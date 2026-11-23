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

/// Largest keyfile that will be read.
///
/// A keyfile is hashed in full by Argon2id, so an unbounded read would let a
/// wrong path (a device node, a multi-gigabyte video) exhaust memory.
pub const MAX_KEYFILE_BYTES: u64 = 16 * 1024 * 1024;

/// Reads a keyfile, refusing empty and oversized ones.
///
/// An empty keyfile is rejected rather than accepted as "no extra entropy": the
/// user asked for a second factor and would silently get none.
fn read_keyfile(path: &Path) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let file = File::open(path)?;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(MAX_KEYFILE_BYTES + 1).read_to_end(&mut bytes)?;

    if bytes.is_empty() {
        return Err(Error::InvalidKeyfile(format!(
            "{} is empty, so it would add no security",
            path.display()
        )));
    }
    if bytes.len() as u64 > MAX_KEYFILE_BYTES {
        return Err(Error::InvalidKeyfile(format!(
            "{} is larger than {} MiB",
            path.display(),
            MAX_KEYFILE_BYTES / (1024 * 1024)
        )));
    }
    Ok(bytes)
}

/// Reads the format version byte of a `.timenc` file.
pub fn file_format_version(path: &Path) -> Result<u8> {
    let mut prefix = [0u8; 7];
    File::open(path)?
        .read_exact(&mut prefix)
        .map_err(|_| Error::InvalidFormat)?;
    if &prefix[0..6] != crypto::MAGIC {
        return Err(Error::InvalidFormat);
    }
    Ok(prefix[6])
}

/// True for formats that are still readable but lack the guarantees of v6
/// (terminated stream, key commitment). Truncation of such a file at a chunk
/// boundary goes undetected, so frontends should suggest re-encrypting it.
pub fn is_legacy_version(version: u8) -> bool {
    (3..=5).contains(&version)
}

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

/// Size of the blocks handed to the hashing thread.
const HASH_BLOCK: usize = 1024 * 1024;

/// Hashes data on a separate thread, so that hashing (about 1 GB/s for
/// BLAKE2b, slower than the encryption it accompanies) overlaps with the work
/// of the thread that produces the data instead of adding to it.
///
/// A small pool of blocks circulates between the two threads, which bounds the
/// memory used and makes the producer wait if the hasher falls behind.
struct BackgroundHasher {
    full: std::sync::mpsc::SyncSender<Vec<u8>>,
    empty: std::sync::mpsc::Receiver<Vec<u8>>,
    worker: std::thread::JoinHandle<Blake2b512>,
    block: Vec<u8>,
}

impl BackgroundHasher {
    fn new() -> Self {
        use std::sync::mpsc::sync_channel;

        const BLOCKS_IN_FLIGHT: usize = 3;
        let (full_tx, full_rx) = sync_channel::<Vec<u8>>(BLOCKS_IN_FLIGHT);
        let (empty_tx, empty_rx) = sync_channel::<Vec<u8>>(BLOCKS_IN_FLIGHT + 1);
        for _ in 0..BLOCKS_IN_FLIGHT {
            let _ = empty_tx.send(Vec::with_capacity(HASH_BLOCK));
        }

        let worker = std::thread::spawn(move || {
            let mut hasher = Blake2b512::new();
            while let Ok(mut block) = full_rx.recv() {
                hasher.update(&block);
                block.clear();
                let _ = empty_tx.send(block);
            }
            hasher
        });

        Self {
            full: full_tx,
            empty: empty_rx,
            worker,
            block: Vec::with_capacity(HASH_BLOCK),
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let room = HASH_BLOCK - self.block.len();
            let take = room.min(data.len());
            self.block.extend_from_slice(&data[..take]);
            data = &data[take..];

            if self.block.len() == HASH_BLOCK {
                let next = self.empty.recv().unwrap_or_default();
                let full = std::mem::replace(&mut self.block, next);
                // The worker only stops once the sender is dropped.
                let _ = self.full.send(full);
            }
        }
    }

    fn finish(mut self) -> Vec<u8> {
        let _ = self.full.send(std::mem::take(&mut self.block));
        drop(self.full);
        match self.worker.join() {
            Ok(hasher) => hasher.finalize().to_vec(),
            Err(_) => Vec::new(),
        }
    }
}

/// Passes everything through to `inner`, hashing it on the side when asked to
/// so the payload can be compared with what a later decryption produces.
///
/// Hashing is only worth its cost when the result is used (verifying before the
/// source is deleted), so it is off unless requested.
struct HashingWriter<W: Write> {
    inner: W,
    hasher: Option<BackgroundHasher>,
}

impl<W: Write> HashingWriter<W> {
    fn new(inner: W, enabled: bool) -> Self {
        Self {
            inner,
            hasher: enabled.then(BackgroundHasher::new),
        }
    }

    /// Returns the inner writer and, if hashing was on, the digest.
    fn into_parts(self) -> (W, Option<Vec<u8>>) {
        (self.inner, self.hasher.map(BackgroundHasher::finish))
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        if let Some(hasher) = &mut self.hasher {
            hasher.update(&buf[..written]);
        }
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
        // Compression is the slowest stage by far, and it runs twice (once to
        // measure, once for real). With one or more workers zstd produces the
        // same bytes whatever the worker count, run to run and however the
        // input is split into writes, so the two passes always agree on the
        // length. (Without workers the output differs slightly, which is why
        // this is not conditional on the number of cores.)
        encoder.multithread(crypto::worker_threads() as u32)?;
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
        // A large buffer keeps the number of read calls (and, for the
        // encryptor behind `out`, hand-offs) low: io::copy would use 8 KiB.
        let mut buffer = vec![0u8; IO_BUFFER];
        loop {
            let read = match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            out.write_all(&buffer[..read])?;
        }
    }
    Ok(())
}

/// Buffer size for streaming a file into the encryptor and out to disk.
const IO_BUFFER: usize = 1024 * 1024;

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
    //
    // A plain file needs no such pass: its length is its payload length. If it
    // changes while being encrypted the writer notices and reports
    // `SourceChanged`, exactly as it does for the measured case. Anything that
    // is not a regular file (a device, a pipe) still takes the measuring pass,
    // since its reported size means nothing.
    let regular_file = !is_dir && !options.compress && fs::metadata(input_path)?.is_file();
    let payload_len = if regular_file {
        fs::metadata(input_path)?.len()
    } else {
        write_payload(
            input_path,
            &original_name,
            is_dir,
            options.compress,
            CountingWriter::default(),
        )?
        .count
    };

    let keyfile_bytes = match options.keyfile_path {
        Some(ref keyfile_path) => Some(read_keyfile(keyfile_path)?),
        None => None,
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
        BufWriter::with_capacity(IO_BUFFER, temp_file.as_file().try_clone()?),
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
        HashingWriter::new(encryptor, options.delete_source),
    )?;
    let (encryptor, payload_hash) = hashing.into_parts();
    encryptor
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
        let payload_hash = payload_hash.unwrap_or_default();
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
    let mut file = BufReader::with_capacity(IO_BUFFER, File::open(path)?);

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

    let mut hashing = HashingWriter::new(io::sink(), true);
    format::v6::decrypt_streaming(&mut file, &mut hashing, &header, &metadata, keys)?;
    let (_, digest) = hashing.into_parts();
    if digest.as_deref() != Some(expected_payload_hash) {
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

    let keyfile_bytes = match options.keyfile_path {
        Some(ref keyfile_path) => Some(read_keyfile(keyfile_path)?),
        None => None,
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
                options.delete_source,
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
                options.delete_source,
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
                options.delete_source,
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
///
/// The file is created exclusively (an existing file, or a symlink planted at
/// the destination, is an error rather than something to write through) and,
/// on Unix, readable by the owner only: a keyfile is a secret, and the default
/// umask would make it readable by every local user.
pub fn generate_keyfile(output_path: &Path) -> Result<PathBuf> {
    let keyfile_data = zeroize::Zeroizing::new(crypto::generate_keyfile_data());

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(output_path).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            Error::FileExists {
                path: output_path.to_string_lossy().to_string(),
            }
        } else {
            Error::from(e)
        }
    })?;
    file.write_all(&keyfile_data[..])?;
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

/// Accepts only the entry types TimENC itself writes: regular files,
/// directories and symlinks.
///
/// Anything else a hostile archive could carry - hard links (which alias files
/// outside the output directory), FIFOs, character and block devices - is
/// refused rather than recreated on the victim's machine.
fn ensure_supported_entry_type(kind: tar::EntryType) -> Result<()> {
    if kind.is_file() || kind.is_dir() || kind.is_symlink() || kind.is_pax_global_extensions() {
        return Ok(());
    }
    Err(Error::UnsafeArchiveEntry(format!("{kind:?}")))
}

/// Moves decrypted data from the temporary file into the output directory,
/// unpacking the tar archive for directories and rejecting unsafe paths.
///
/// `sync_extracted` makes every extracted file durable before returning. That
/// is one `fsync` per file, which dominates the time for a folder of many small
/// files, so it is only requested when the encrypted source is about to be
/// deleted and the extracted copy becomes the only one.
fn handle_decrypted_output(
    original_name: String,
    is_dir: bool,
    temp_path: &Path,
    output_dir: &Path,
    sync_extracted: bool,
) -> Result<PathBuf> {
    fs::create_dir_all(output_dir)?;

    if is_dir {
        let tar_file = File::open(temp_path)?;
        let mut tar_archive = tar::Archive::new(tar_file);
        tar_archive.set_overwrite(false);

        let mut extracted_files = Vec::new();
        for entry in tar_archive.entries()? {
            let mut entry = entry?;
            ensure_supported_entry_type(entry.header().entry_type())?;
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
        if sync_extracted {
            for extracted in &extracted_files {
                let _ = File::open(extracted).and_then(|file| file.sync_all());
            }
        }

        Ok(output_dir.to_path_buf())
    } else {
        let safe_name = format::sanitize_output_name(&original_name)?;
        let target_path = output_dir.join(safe_name);

        let already_exists = || Error::FileExists {
            path: target_path.to_string_lossy().to_string(),
        };

        // A hard link fails if anything (a file, or a symlink planted in the
        // meantime) already sits at the target, unlike a rename, which would
        // silently replace it between an `exists()` check and the move.
        match fs::hard_link(temp_path, &target_path) {
            Ok(()) => {
                fs::remove_file(temp_path)?;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Err(already_exists()),
            // File systems without hard links (FAT, some network shares):
            // check first and rename.
            Err(_) => {
                if fs::symlink_metadata(&target_path).is_ok() {
                    return Err(already_exists());
                }
                fs::rename(temp_path, &target_path)?;
            }
        }
        Ok(target_path)
    }
}
