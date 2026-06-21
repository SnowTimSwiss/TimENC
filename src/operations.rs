//! File-level encryption, decryption, and keyfile operations.

use crate::crypto;
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

    let (input_file, _temp_dir) = if is_dir {
        let temp_dir = tempfile::tempdir()?;
        let tar_path = temp_dir.path().join(format!("{}.tar", original_name));
        
        let tar_file = File::create(&tar_path)?;
        let mut tar_builder = tar::Builder::new(tar_file);
        tar_builder.append_dir_all(&original_name, input_path)?;
        tar_builder.finish()?;
        drop(tar_builder);
        
        (tar_path, Some(temp_dir))
    } else {
        (input_path.to_path_buf(), None)
    };

    let keyfile_bytes = if let Some(ref keyfile_path) = options.keyfile_path {
        Some(fs::read(keyfile_path)?)
    } else {
        None
    };

    let salt = crypto::generate_salt();
    let metadata_nonce = crypto::generate_nonce();
    let data_nonce = crypto::generate_nonce();

    let metadata = format::v4::Metadata::new(original_name.clone(), is_dir, options.compress);
    let metadata_len = (metadata.to_bytes()?.len() + crypto::TAG_SIZE) as u32;
    let header = format::v4::Header::new(metadata_len, salt, metadata_nonce, data_nonce);

    let mut output_file = File::create(&options.output_path)?;

    let plain_input = File::open(&input_file)?;
    if options.compress {
        let mut compressing_reader = zstd::stream::read::Encoder::new(plain_input, 0)?;
        format::v4::encrypt_streaming(
            &mut compressing_reader,
            &mut output_file,
            &header,
            &metadata,
            options.password.as_bytes(),
            keyfile_bytes.as_deref(),
        )?;
    } else {
        let mut input_file_handle = plain_input;
        format::v4::encrypt_streaming(
            &mut input_file_handle,
            &mut output_file,
            &header,
            &metadata,
            options.password.as_bytes(),
            keyfile_bytes.as_deref(),
        )?;
    }

    drop(output_file);

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

    let result = match version {
        3 => {
            let (header, _header_len) = Header::read_from(&mut file)?;
            let temp_file = NamedTempFile::new()?;
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

            let temp_file = NamedTempFile::new()?;
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
