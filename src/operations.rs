//! File-level encryption, decryption, and keyfile operations.

use crate::crypto::{self, KdfProfile};
use crate::error::{Error, Result};
use crate::format::{self, Header};
use blake2::{Blake2b512, Digest};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, Write};
use std::path::Component;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use zeroize::Zeroize;

/// Inputs needed for an encryption run.
#[derive(Clone)]
pub struct EncryptOptions {
    /// Wiped from memory when the options are dropped.
    pub password: String,
    pub keyfile_path: Option<PathBuf>,
    pub output_path: PathBuf,
    pub compress: bool,
    /// Argon2id cost profile to record in the header.
    pub kdf_profile: KdfProfile,
    /// Pad the payload so the ciphertext size does not reveal the exact
    /// plaintext size.
    pub pad: bool,
    /// Delete the source once the encrypted file has been written, synced to
    /// disk, and verified by decrypting it again. Off by default.
    pub delete_source: bool,
}

impl EncryptOptions {
    /// Options with the default cost profile, no compression or padding, and
    /// the source left in place.
    pub fn new(password: String, output_path: PathBuf) -> Self {
        Self {
            password,
            keyfile_path: None,
            output_path,
            compress: false,
            kdf_profile: KdfProfile::default(),
            pad: false,
            delete_source: false,
        }
    }
}

impl Drop for EncryptOptions {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl fmt::Debug for EncryptOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptOptions")
            .field("password", &"<redacted>")
            .field("keyfile_path", &self.keyfile_path)
            .field("output_path", &self.output_path)
            .field("compress", &self.compress)
            .field("kdf_profile", &self.kdf_profile)
            .field("pad", &self.pad)
            .field("delete_source", &self.delete_source)
            .finish()
    }
}

/// Inputs needed for a decryption run.
#[derive(Clone)]
pub struct DecryptOptions {
    /// Wiped from memory when the options are dropped.
    pub password: String,
    pub keyfile_path: Option<PathBuf>,
    pub output_dir: PathBuf,
    /// Delete the `.timenc` file once it has been decrypted and the output
    /// synced to disk. Off by default.
    pub delete_source: bool,
}

impl Drop for DecryptOptions {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl fmt::Debug for DecryptOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptOptions")
            .field("password", &"<redacted>")
            .field("keyfile_path", &self.keyfile_path)
            .field("output_dir", &self.output_dir)
            .field("delete_source", &self.delete_source)
            .finish()
    }
}

/// Counts the bytes written to it and discards them.
#[derive(Default)]
struct CountingWriter {
    count: u64,
}

impl Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.count += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Hashes everything written through it, so the payload can be compared with
/// what a later decryption produces.
struct HashingWriter<W: Write> {
    inner: W,
    hasher: Blake2b512,
}

impl<W: Write> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Blake2b512::new(),
        }
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.hasher.update(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Streams the payload - the file itself or a tar archive of the directory,
/// optionally zstd-compressed - into `out`.
///
/// Called twice per encryption: once into a [`CountingWriter`] to learn the
/// exact length the v6 metadata needs up front, then straight into the
/// encryptor. That costs a second read of the source, but no plaintext
/// intermediate (tar archive, compressed copy) is ever written to disk.
fn write_payload<W: Write>(
    input_path: &Path,
    archive_name: &str,
    is_dir: bool,
    compress: bool,
    out: W,
) -> Result<W> {
    if compress {
        let mut encoder = zstd::stream::write::Encoder::new(out, 0)?;
        write_raw_payload(input_path, archive_name, is_dir, &mut encoder)?;
        Ok(encoder.finish()?)
    } else {
        let mut out = out;
        write_raw_payload(input_path, archive_name, is_dir, &mut out)?;
        Ok(out)
    }
}

fn write_raw_payload<W: Write>(
    input_path: &Path,
    archive_name: &str,
    is_dir: bool,
    out: &mut W,
) -> Result<()> {
    if is_dir {
        let mut tar_builder = tar::Builder::new(out);
        // Store symlinks as links instead of archiving whatever they point at,
        // which could be outside the folder the user picked.
        tar_builder.follow_symlinks(false);
        tar_builder.append_dir_all(archive_name, input_path)?;
        tar_builder.finish()?;
    } else {
        let mut file = File::open(input_path)?;
        io::copy(&mut file, out)?;
    }
    Ok(())
}

/// Directory an output file will be created in.
fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// Encrypts a file or directory.
///
/// The output is written to a temporary file next to its destination, synced
/// to disk, and only then moved into place, so a crash never leaves a partial
/// `.timenc` file behind and an existing file is never overwritten. The source
/// is only deleted when [`EncryptOptions::delete_source`] is set, and only
/// after the new file has been decrypted again and compared with the source.
pub fn encrypt(input_path: &Path, options: EncryptOptions) -> Result<PathBuf> {
    if !input_path.exists() {
        return Err(Error::FileNotFound {
            path: input_path.to_string_lossy().to_string(),
        });
    }

    let output_path = options.output_path.clone();
    if output_path.exists() {
        return Err(Error::FileExists {
            path: output_path.to_string_lossy().to_string(),
        });
    }
    let output_dir = parent_dir(&output_path);

    let is_dir = input_path.is_dir();
    let original_name = input_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    // The encrypted file is streamed next to its destination while the folder
    // is being archived, so it must not be part of that folder.
    if is_dir && output_dir.canonicalize()?.starts_with(input_path.canonicalize()?) {
        return Err(Error::OutputInsideInput);
    }

    // v6 records the exact payload length in the encrypted metadata, which is
    // written before the payload, so it is measured in a first pass.
    let payload_len = write_payload(
        input_path,
        &original_name,
        is_dir,
        options.compress,
        CountingWriter::default(),
    )?
    .count;

    let keyfile_bytes = if let Some(ref keyfile_path) = options.keyfile_path {
        Some(zeroize::Zeroizing::new(fs::read(keyfile_path)?))
    } else {
        None
    };

    let salt = crypto::generate_salt();
    let kdf = options.kdf_profile.params();

    // One Argon2id run for the whole file; the metadata and data keys are
    // separate subkeys of its output.
    let keys = format::v6::derive_file_keys(
        options.password.as_bytes(),
        keyfile_bytes.as_ref().map(|bytes| bytes.as_slice()),
        &salt,
        kdf,
    )?;

    let metadata = format::v6::Metadata::new(
        original_name.clone(),
        is_dir,
        options.compress,
        payload_len,
    );

    let temp_file = NamedTempFile::new_in(output_dir)?;
    let encryptor = format::v6::EncryptWriter::new(
        BufWriter::new(temp_file.as_file().try_clone()?),
        salt,
        kdf,
        &metadata,
        &keys,
        options.pad,
    )?;
    let header = encryptor.header().clone();

    let hashing = write_payload(
        input_path,
        &original_name,
        is_dir,
        options.compress,
        HashingWriter::new(encryptor),
    )?;
    let payload_hash = hashing.hasher.finalize();
    hashing
        .inner
        .finish()
        .map_err(|e| match e {
            // The first pass measured a different length: a file in the source
            // grew, shrank, or appeared in between.
            Error::PayloadLengthMismatch { .. } => Error::SourceChanged,
            other => other,
        })?
        .into_inner()
        .map_err(|e| e.into_error())?;

    temp_file.as_file().sync_all()?;

    if options.delete_source {
        verify_encrypted_file(temp_file.path(), &header, &metadata, &keys, &payload_hash)
            .map_err(|e| Error::VerificationFailed(e.to_string()))?;
    }

    persist_new_file(temp_file, &output_path)?;
    sync_dir(output_dir);

    if options.delete_source {
        if is_dir {
            best_effort_secure_delete_dir(input_path)?;
        } else {
            best_effort_secure_delete_file(input_path)?;
        }
    }

    Ok(output_path)
}

/// Re-reads a freshly written v6 file and checks that it decrypts to exactly
/// the payload that was fed into the encryptor.
///
/// Guards against anything between the encryptor and the disk going wrong
/// before the source is deleted. No second Argon2id run is needed: the keys
/// are the ones the file was just written with.
fn verify_encrypted_file(
    path: &Path,
    expected_header: &format::v6::Header,
    expected_metadata: &format::v6::Metadata,
    keys: &format::v6::FileKeys,
    expected_payload_hash: &[u8],
) -> Result<()> {
    let mut file = BufReader::new(File::open(path)?);

    let (header, _) = format::v6::Header::read_from(&mut file)?;
    if header.to_bytes()? != expected_header.to_bytes()? {
        return Err(Error::InvalidFormat);
    }
    header.verify_commitment(keys)?;

    let mut encrypted_metadata = vec![0u8; header.metadata_len as usize];
    file.read_exact(&mut encrypted_metadata)?;
    let metadata = format::v6::decrypt_metadata(&encrypted_metadata, &header, keys)?;
    if &metadata != expected_metadata {
        return Err(Error::InvalidFormat);
    }

    let mut hashing = HashingWriter::new(io::sink());
    format::v6::decrypt_streaming(&mut file, &mut hashing, &header, &metadata, keys)?;
    if hashing.hasher.finalize().as_slice() != expected_payload_hash {
        return Err(Error::DecryptionFailed);
    }

    Ok(())
}

/// Moves a finished temporary file to `target` without replacing anything
/// that may have appeared there in the meantime.
fn persist_new_file(temp_file: NamedTempFile, target: &Path) -> Result<()> {
    let already_exists = || Error::FileExists {
        path: target.to_string_lossy().to_string(),
    };

    match temp_file.persist_noclobber(target) {
        Ok(_) => Ok(()),
        Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => Err(already_exists()),
        // Some filesystems (FAT on USB sticks, some network shares) support
        // neither RENAME_NOREPLACE nor hard links, which persist_noclobber
        // needs. Fall back to checking first and a plain rename.
        Err(e) => {
            if target.exists() {
                return Err(already_exists());
            }
            e.file.persist(target).map_err(|e| Error::from(e.error))?;
            Ok(())
        }
    }
}

/// Flushes a directory entry to disk, so that a rename into it survives a
/// crash. Best-effort, and a no-op where directories cannot be opened.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(dir) = File::open(dir) {
        let _ = dir.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Decrypts a `.timenc` file.
///
/// The encrypted file is only removed when [`DecryptOptions::delete_source`]
/// is set, and only after the decrypted output has been synced to disk.
pub fn decrypt(input_path: &Path, options: DecryptOptions) -> Result<PathBuf> {
    if !input_path.exists() {
        return Err(Error::FileNotFound {
            path: input_path.to_string_lossy().to_string(),
        });
    }

    let mut file = File::open(input_path)?;
    let mut version_bytes = [0u8; 7];
    file.read_exact(&mut version_bytes)?;
    if &version_bytes[0..6] != crypto::MAGIC {
        return Err(Error::InvalidFormat);
    }
    let version = version_bytes[6];
    file.seek(std::io::SeekFrom::Start(0))?;

    let keyfile_bytes = if let Some(ref keyfile_path) = options.keyfile_path {
        Some(zeroize::Zeroizing::new(fs::read(keyfile_path)?))
    } else {
        None
    };
    let keyfile_bytes = keyfile_bytes.as_ref().map(|bytes| bytes.as_slice());

    // The temp file holding the decrypted plaintext must live on the same
    // filesystem as output_dir so it can be moved into place with a rename().
    // Under Flatpak, /tmp is a sandbox-private mount distinct from the host
    // directories exposed to the app, so renaming across them fails with EXDEV
    // ("Invalid cross-device link", os error 18).
    fs::create_dir_all(&options.output_dir)?;

    let result = match version {
        3 => {
            let (header, _header_len) = Header::read_from(&mut file)?;
            let temp_file = NamedTempFile::new_in(&options.output_dir)?;
            let temp_path = temp_file.path().to_path_buf();

            let mut temp_file_handle = File::create(&temp_path)?;
            format::v3::decrypt_streaming(
                &mut file,
                &mut temp_file_handle,
                &header,
                options.password.as_bytes(),
                keyfile_bytes,
            )?;
            temp_file_handle.sync_all()?;

            handle_decrypted_output(
                header.original_name,
                header.is_dir,
                &temp_path,
                &options.output_dir,
            )
        }
        4 | 5 => {
            let (header, _header_len) = format::v4::Header::read_from(&mut file)?;
            let mut encrypted_metadata = vec![0u8; header.metadata_len as usize];
            file.read_exact(&mut encrypted_metadata)?;
            let metadata = format::v4::decrypt_metadata(
                &encrypted_metadata,
                &header,
                options.password.as_bytes(),
                keyfile_bytes,
            )?;

            let temp_file = NamedTempFile::new_in(&options.output_dir)?;
            let temp_path = temp_file.path().to_path_buf();
            let temp_file_handle = File::create(&temp_path)?;
            if metadata.compressed {
                let mut decompressing_writer = zstd::stream::write::Decoder::new(temp_file_handle)?;
                format::v4::decrypt_streaming(
                    &mut file,
                    &mut decompressing_writer,
                    &header,
                    options.password.as_bytes(),
                    keyfile_bytes,
                )?;
                decompressing_writer.flush()?;
                decompressing_writer.into_inner().sync_all()?;
            } else {
                let mut temp_file_handle = temp_file_handle;
                format::v4::decrypt_streaming(
                    &mut file,
                    &mut temp_file_handle,
                    &header,
                    options.password.as_bytes(),
                    keyfile_bytes,
                )?;
                temp_file_handle.sync_all()?;
            }

            handle_decrypted_output(
                metadata.original_name,
                metadata.is_dir,
                &temp_path,
                &options.output_dir,
            )
        }
        6 => {
            let (header, _header_len) = format::v6::Header::read_from(&mut file)?;

            let keys = format::v6::derive_file_keys(
                options.password.as_bytes(),
                keyfile_bytes,
                &header.salt,
                header.kdf,
            )?;
            // Rejects a wrong password or keyfile before any ciphertext is
            // touched, and pins the file to exactly one key.
            header.verify_commitment(&keys)?;

            let mut encrypted_metadata = vec![0u8; header.metadata_len as usize];
            file.read_exact(&mut encrypted_metadata)?;
            let metadata = format::v6::decrypt_metadata(&encrypted_metadata, &header, &keys)?;

            let temp_file = NamedTempFile::new_in(&options.output_dir)?;
            let temp_path = temp_file.path().to_path_buf();
            let temp_file_handle = File::create(&temp_path)?;
            if metadata.compressed {
                let mut decompressing_writer = zstd::stream::write::Decoder::new(temp_file_handle)?;
                format::v6::decrypt_streaming(
                    &mut file,
                    &mut decompressing_writer,
                    &header,
                    &metadata,
                    &keys,
                )?;
                decompressing_writer.flush()?;
                decompressing_writer.into_inner().sync_all()?;
            } else {
                let mut temp_file_handle = temp_file_handle;
                format::v6::decrypt_streaming(
                    &mut file,
                    &mut temp_file_handle,
                    &header,
                    &metadata,
                    &keys,
                )?;
                temp_file_handle.sync_all()?;
            }

            handle_decrypted_output(
                metadata.original_name,
                metadata.is_dir,
                &temp_path,
                &options.output_dir,
            )
        }
        _ => Err(Error::UnsupportedVersion { version }),
    };

    if result.is_ok() && options.delete_source {
        drop(file);
        best_effort_secure_delete_file(input_path)?;
    }

    result
}

/// Writes a new keyfile with random bytes.
pub fn generate_keyfile(output_path: &Path) -> Result<PathBuf> {
    if output_path.exists() {
        return Err(Error::FileExists {
            path: output_path.to_string_lossy().to_string(),
        });
    }

    let keyfile_data = crypto::generate_keyfile_data();
    
    let mut file = fs::File::create(output_path)?;
    file.write_all(&keyfile_data)?;
    file.sync_all()?;

    Ok(output_path.to_path_buf())
}

/// Overwrites every regular file in a directory tree before removing the tree.
///
/// Symlinks are removed, never followed, so nothing outside the directory is
/// touched. Carries the same caveats as [`best_effort_secure_delete_file`].
fn best_effort_secure_delete_dir(path: &Path) -> Result<()> {
    let file_type = fs::symlink_metadata(path)?.file_type();
    if !file_type.is_dir() {
        return if file_type.is_file() {
            best_effort_secure_delete_file(path)
        } else {
            remove_link(path)
        };
    }

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let entry_type = entry.file_type()?;
        if entry_type.is_dir() {
            best_effort_secure_delete_dir(&entry_path)?;
        } else if entry_type.is_file() {
            best_effort_secure_delete_file(&entry_path)?;
        } else {
            remove_link(&entry_path)?;
        }
    }

    fs::remove_dir(path)?;
    Ok(())
}

/// Removes a symlink or other special file without following it.
fn remove_link(path: &Path) -> Result<()> {
    // On Windows a symlink to a directory is itself removed as a directory.
    fs::remove_file(path).or_else(|_| fs::remove_dir(path))?;
    Ok(())
}

/// Overwrites a file with zeros before deleting it.
///
/// This is best-effort only: on SSDs, copy-on-write or journaling file systems,
/// and any storage with wear levelling, overwriting in place does not guarantee
/// the original bytes are gone. It raises the bar against trivial recovery but
/// is not a substitute for full-disk encryption.
fn best_effort_secure_delete_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let len = fs::metadata(path)?.len();
    let mut file = OpenOptions::new().write(true).open(path)?;
    let zeros = [0u8; 64 * 1024];
    let mut remaining = len;

    while remaining > 0 {
        let chunk = remaining.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..chunk])?;
        remaining -= chunk as u64;
    }

    file.flush()?;
    file.sync_all()?;
    drop(file);
    fs::remove_file(path)?;
    Ok(())
}

/// Returns true if an archive entry path could escape the output directory.
///
/// Rejects absolute paths, root or drive prefixes, and `..` segments, and also
/// rejects paths that contain no normal component at all.
fn has_unsafe_path_components(path: &Path) -> bool {
    let mut has_normal = false;

    for component in path.components() {
        match component {
            Component::Normal(_) => has_normal = true,
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return true,
        }
    }

    !has_normal
}

/// Moves decrypted data from the temporary file into the output directory,
/// unpacking the tar archive for directories and rejecting unsafe paths.
fn handle_decrypted_output(
    original_name: String,
    is_dir: bool,
    temp_path: &Path,
    output_dir: &Path,
) -> Result<PathBuf> {
    fs::create_dir_all(output_dir)?;

    if is_dir {
        let tar_file = File::open(temp_path)?;
        let mut tar_archive = tar::Archive::new(tar_file);
        tar_archive.set_overwrite(false);

        let mut extracted_files = Vec::new();
        for entry in tar_archive.entries()? {
            let mut entry = entry?;
            let entry_path = entry.path()?.into_owned();
            if has_unsafe_path_components(&entry_path) {
                return Err(Error::PathTraversal);
            }
            if !entry.unpack_in(output_dir)? {
                return Err(Error::PathTraversal);
            }
            if entry.header().entry_type().is_file() {
                extracted_files.push(output_dir.join(&entry_path));
            }
        }

        // Make sure the extracted files are on disk before the caller may
        // delete the encrypted source. Best-effort: Windows only flushes
        // handles opened for writing, which a read-only file cannot give.
        for extracted in &extracted_files {
            let _ = File::open(extracted).and_then(|file| file.sync_all());
        }

        Ok(output_dir.to_path_buf())
    } else {
        let safe_name = format::sanitize_output_name(&original_name)?;
        let target_path = output_dir.join(safe_name);

        if target_path.exists() {
            return Err(Error::FileExists {
                path: target_path.to_string_lossy().to_string(),
            });
        }

        fs::rename(temp_path, &target_path)?;
        Ok(target_path)
    }
}
