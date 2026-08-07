//! File-level encryption, decryption, and keyfile operations.

use crate::crypto::{self, KdfProfile};
use crate::error::{Error, Result};
use crate::format::{self, Header};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::Component;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

/// Inputs needed for an encryption run.
#[derive(Debug, Clone)]
pub struct EncryptOptions {
    pub password: String,
    pub keyfile_path: Option<PathBuf>,
    pub output_path: PathBuf,
    pub compress: bool,
    /// Argon2id cost profile to record in the header.
    pub kdf_profile: KdfProfile,
    /// Pad the payload so the ciphertext size does not reveal the exact
    /// plaintext size.
    pub pad: bool,
}

impl EncryptOptions {
    /// Options with the default cost profile and no compression or padding.
    pub fn new(password: String, output_path: PathBuf) -> Self {
        Self {
            password,
            keyfile_path: None,
            output_path,
            compress: false,
            kdf_profile: KdfProfile::default(),
            pad: false,
        }
    }
}

/// Inputs needed for a decryption run.
#[derive(Debug, Clone)]
pub struct DecryptOptions {
    pub password: String,
    pub keyfile_path: Option<PathBuf>,
    pub output_dir: PathBuf,
}

/// Encrypts a file or directory and removes the original on success.
pub fn encrypt(input_path: &Path, options: EncryptOptions) -> Result<PathBuf> {
    if !input_path.exists() {
        return Err(Error::FileNotFound {
            path: input_path.to_string_lossy().to_string(),
        });
    }

    let is_dir = input_path.is_dir();
    let original_name = input_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    // Holds the tar archive and/or the compressed intermediate. Kept alive
    // until encryption finishes.
    let mut temp_dir = None;

    let mut payload_source = if is_dir {
        let dir = tempfile::tempdir()?;
        let tar_path = dir.path().join(format!("{}.tar", original_name));

        let tar_file = File::create(&tar_path)?;
        let mut tar_builder = tar::Builder::new(tar_file);
        tar_builder.append_dir_all(&original_name, input_path)?;
        tar_builder.finish()?;
        drop(tar_builder);

        temp_dir = Some(dir);
        tar_path
    } else {
        input_path.to_path_buf()
    };

    // v6 records the exact payload length in the encrypted metadata, which is
    // written before the payload. Compression therefore has to happen up front
    // rather than streaming through the encryptor: its output size is not known
    // until it is done.
    if options.compress {
        let dir = match temp_dir {
            Some(dir) => dir,
            None => tempfile::tempdir()?,
        };
        let compressed_path = dir.path().join("payload.zst");

        let mut plain = File::open(&payload_source)?;
        let mut compressed = File::create(&compressed_path)?;
        zstd::stream::copy_encode(&mut plain, &mut compressed, 0)?;
        compressed.flush()?;
        drop(compressed);

        temp_dir = Some(dir);
        payload_source = compressed_path;
    }

    let payload_len = fs::metadata(&payload_source)?.len();

    let keyfile_bytes = if let Some(ref keyfile_path) = options.keyfile_path {
        Some(fs::read(keyfile_path)?)
    } else {
        None
    };

    let salt = crypto::generate_salt();
    let kdf = options.kdf_profile.params();

    // One Argon2id run for the whole file; the metadata and data keys are
    // separate subkeys of its output.
    let keys = format::v6::derive_file_keys(
        options.password.as_bytes(),
        keyfile_bytes.as_deref(),
        &salt,
        kdf,
    )?;

    let metadata = format::v6::Metadata::new(
        original_name.clone(),
        is_dir,
        options.compress,
        payload_len,
    );

    let mut output_file = File::create(&options.output_path)?;
    let mut payload = File::open(&payload_source)?;
    format::v6::encrypt_streaming(
        &mut payload,
        &mut output_file,
        salt,
        kdf,
        &metadata,
        &keys,
        options.pad,
    )?;

    drop(payload);
    output_file.flush()?;
    drop(output_file);
    drop(temp_dir);

    if is_dir {
        fs::remove_dir_all(input_path)?;
    } else {
        best_effort_secure_delete_file(input_path)?;
    }

    Ok(options.output_path.clone())
}

/// Decrypts a `.timenc` file and removes the encrypted source on success.
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
        Some(fs::read(keyfile_path)?)
    } else {
        None
    };

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
                keyfile_bytes.as_deref(),
            )?;

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
                keyfile_bytes.as_deref(),
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
                    keyfile_bytes.as_deref(),
                )?;
                decompressing_writer.flush()?;
            } else {
                let mut temp_file_handle = temp_file_handle;
                format::v4::decrypt_streaming(
                    &mut file,
                    &mut temp_file_handle,
                    &header,
                    options.password.as_bytes(),
                    keyfile_bytes.as_deref(),
                )?;
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
                keyfile_bytes.as_deref(),
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
            } else {
                let mut temp_file_handle = temp_file_handle;
                format::v6::decrypt_streaming(
                    &mut file,
                    &mut temp_file_handle,
                    &header,
                    &metadata,
                    &keys,
                )?;
                temp_file_handle.flush()?;
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

    if result.is_ok() {
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

        for entry in tar_archive.entries()? {
            let mut entry = entry?;
            let entry_path = entry.path()?;
            if has_unsafe_path_components(&entry_path) {
                return Err(Error::PathTraversal);
            }
            if !entry.unpack_in(output_dir)? {
                return Err(Error::PathTraversal);
            }
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
