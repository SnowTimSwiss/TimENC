//! High-level encryption/decryption operations

use crate::crypto;
use crate::error::{Error, Result};
use crate::format::{self, Header};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::Component;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

/// Options for encryption
#[derive(Debug, Clone)]
pub struct EncryptOptions {
    pub password: String,
    pub keyfile_path: Option<PathBuf>,
    pub output_path: PathBuf,
    pub delete_source: bool,
}

/// Options for decryption
#[derive(Debug, Clone)]
pub struct DecryptOptions {
    pub password: String,
    pub keyfile_path: Option<PathBuf>,
    pub output_dir: PathBuf,
    pub delete_source: bool,
}

/// Encrypts a file or directory
/// 
/// # Arguments
/// * `input_path` - Path to file or directory to encrypt
/// * `options` - Encryption options
/// 
/// # Returns
/// Path to the encrypted file
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

    // Create temporary TAR archive for directories
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

    // Read keyfile if provided
    let keyfile_bytes = if let Some(ref keyfile_path) = options.keyfile_path {
        Some(fs::read(keyfile_path)?)
    } else {
        None
    };

    // Generate salt and nonce
    let salt = crypto::generate_salt();
    let nonce = crypto::generate_nonce();

    // Create header
    let header = Header::new_v3(original_name.clone(), is_dir, salt, nonce);

    // Create output file
    let mut output_file = File::create(&options.output_path)?;

    // Encrypt using V3 streaming format
    let mut input_file_handle = File::open(&input_file)?;
    format::v3::encrypt_streaming(
        &mut input_file_handle,
        &mut output_file,
        &header,
        options.password.as_bytes(),
        keyfile_bytes.as_deref(),
    )?;

    drop(output_file);

    // Secure cleanup of key material happens automatically via Zeroizing

    // Delete source if requested
    if options.delete_source {
        if is_dir {
            fs::remove_dir_all(input_path)?;
        } else {
            best_effort_secure_delete_file(input_path)?;
        }
    }

    // Temp directory is automatically cleaned up when dropped

    Ok(options.output_path.clone())
}

/// Decrypts a .timenc file
/// 
/// # Arguments
/// * `input_path` - Path to .timenc file
/// * `options` - Decryption options
/// 
/// # Returns
/// Path to the decrypted file or directory
pub fn decrypt(input_path: &Path, options: DecryptOptions) -> Result<PathBuf> {
    if !input_path.exists() {
        return Err(Error::FileNotFound {
            path: input_path.to_string_lossy().to_string(),
        });
    }

    // Read header
    let mut file = File::open(input_path)?;
    let (header, header_len) = Header::read_from(&mut file)?;

    // Read keyfile if provided
    let keyfile_bytes = if let Some(ref keyfile_path) = options.keyfile_path {
        Some(fs::read(keyfile_path)?)
    } else {
        None
    };

    // Create temporary file for decrypted content
    let temp_file = NamedTempFile::new()?;
    let temp_path = temp_file.path().to_path_buf();

    // Decrypt based on version
    match header.version {
        2 => {
            // V2: All ciphertext after header
            let mut header_bytes = Vec::new();
            file.seek(std::io::SeekFrom::Start(0))?;
            file.read_to_end(&mut header_bytes)?;
            let ciphertext = &header_bytes[header_len..];
            let plaintext = format::v2::decrypt(
                ciphertext,
                &header,
                options.password.as_bytes(),
                keyfile_bytes.as_deref(),
            )?;
            let mut temp_file_handle = File::create(&temp_path)?;
            temp_file_handle.write_all(&plaintext)?;
        }
        3 => {
            // V3: Streaming decryption
            let mut temp_file_handle = File::create(&temp_path)?;
            format::v3::decrypt_streaming(
                &mut file,
                &mut temp_file_handle,
                &header,
                options.password.as_bytes(),
                keyfile_bytes.as_deref(),
            )?;
        }
        _ => return Err(Error::UnsupportedVersion { version: header.version }),
    }

    // Create output directory
    fs::create_dir_all(&options.output_dir)?;

    let result_path = if header.is_dir {
        // Extract TAR archive
        let tar_file = File::open(&temp_path)?;
        let mut tar_archive = tar::Archive::new(tar_file);
        tar_archive.set_overwrite(false);
        
        for entry in tar_archive.entries()? {
            let mut entry = entry?;
            let entry_path = entry.path()?;
            if has_unsafe_path_components(&entry_path) {
                return Err(Error::PathTraversal);
            }
            if !entry.unpack_in(&options.output_dir)? {
                return Err(Error::PathTraversal);
            }
        }
        
        options.output_dir.clone()
    } else {
        // Single file
        let safe_name = format::sanitize_output_name(&header.original_name)?;
        let target_path = options.output_dir.join(safe_name);
        
        if target_path.exists() {
            return Err(Error::FileExists {
                path: target_path.to_string_lossy().to_string(),
            });
        }
        
        fs::rename(&temp_path, &target_path)?;
        target_path
    };

    // Delete source .timenc file if requested
    if options.delete_source {
        best_effort_secure_delete_file(input_path)?;
    }

    Ok(result_path)
}

/// Generates a new keyfile
/// 
/// # Arguments
/// * `output_path` - Path where the keyfile should be created
/// 
/// # Returns
/// Path to the created keyfile
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
