//! TIMENC file format handling (v2 and v3)

use crate::crypto::{self, NONCE_SIZE, SALT_SIZE, TAG_SIZE};
use crate::error::{Error, Result};
use std::io::{Read, Write};

/// Chunk size for streaming encryption (64 KiB)
pub const CHUNK_SIZE: usize = 64 * 1024;

/// Encrypted chunk size (plaintext + tag)
pub const ENC_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_SIZE;

/// Header structure for TIMENC files
#[derive(Debug, Clone)]
pub struct Header {
    pub version: u8,
    pub is_dir: bool,
    pub original_name: String,
    pub salt: [u8; SALT_SIZE],
    pub time_cost: u32,
    pub memory_kib: u32,
    pub parallelism: u32,
    pub nonce: [u8; NONCE_SIZE],
}

impl Header {
    /// Serializes the header to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let name_bytes = self.original_name.as_bytes();
        if name_bytes.len() > u16::MAX as usize {
            return Err(Error::FilenameTooLong);
        }

        let mut buf = Vec::with_capacity(6 + 1 + 1 + 2 + name_bytes.len() + SALT_SIZE + 4 + 4 + 1 + NONCE_SIZE);
        
        // Magic
        buf.extend_from_slice(crypto::MAGIC);
        
        // Version
        buf.push(self.version);
        
        // Is directory flag
        buf.push(if self.is_dir { 1 } else { 0 });
        
        // Name length (big-endian u16)
        buf.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        
        // Original name
        buf.extend_from_slice(name_bytes);
        
        // Salt
        buf.extend_from_slice(&self.salt);
        
        // Argon2 parameters
        buf.extend_from_slice(&self.time_cost.to_be_bytes());
        buf.extend_from_slice(&self.memory_kib.to_be_bytes());
        buf.push(self.parallelism as u8);
        
        // Nonce
        buf.extend_from_slice(&self.nonce);

        Ok(buf)
    }

    /// Parses header from bytes
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 6 {
            return Err(Error::InvalidFormat);
        }

        // Magic
        if &data[0..6] != crypto::MAGIC {
            return Err(Error::InvalidFormat);
        }

        let mut offset = 6;

        // Version
        if data.len() <= offset {
            return Err(Error::InvalidFormat);
        }
        let version = data[offset];
        offset += 1;

        // Is directory
        if data.len() <= offset {
            return Err(Error::InvalidFormat);
        }
        let is_dir = data[offset] == 1;
        offset += 1;

        // Name length
        if data.len() < offset + 2 {
            return Err(Error::InvalidFormat);
        }
        let name_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        // Name
        if data.len() < offset + name_len {
            return Err(Error::InvalidFormat);
        }
        let original_name = String::from_utf8(data[offset..offset + name_len].to_vec())?;
        offset += name_len;

        // Salt
        if data.len() < offset + SALT_SIZE {
            return Err(Error::InvalidFormat);
        }
        let salt: [u8; SALT_SIZE] = data[offset..offset + SALT_SIZE].try_into()
            .map_err(|_| Error::InvalidFormat)?;
        offset += SALT_SIZE;

        // Time cost
        if data.len() < offset + 4 {
            return Err(Error::InvalidFormat);
        }
        let time_cost = u32::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]);
        offset += 4;

        // Memory KiB
        if data.len() < offset + 4 {
            return Err(Error::InvalidFormat);
        }
        let memory_kib = u32::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]);
        offset += 4;

        // Parallelism
        if data.len() <= offset {
            return Err(Error::InvalidFormat);
        }
        let parallelism = data[offset] as u32;
        offset += 1;

        // Nonce
        if data.len() < offset + NONCE_SIZE {
            return Err(Error::InvalidFormat);
        }
        let nonce: [u8; NONCE_SIZE] = data[offset..offset + NONCE_SIZE].try_into()
            .map_err(|_| Error::InvalidFormat)?;
        offset += NONCE_SIZE;

        Ok((Header {
            version,
            is_dir,
            original_name,
            salt,
            time_cost,
            memory_kib,
            parallelism,
            nonce,
        }, offset))
    }

    /// Creates a new header for v3 encryption
    pub fn new_v3(original_name: String, is_dir: bool, salt: [u8; SALT_SIZE], nonce: [u8; NONCE_SIZE]) -> Self {
        Header {
            version: 3,
            is_dir,
            original_name,
            salt,
            time_cost: crypto::ARGON2_TIME_COST,
            memory_kib: crypto::ARGON2_MEMORY_KIB,
            parallelism: crypto::ARGON2_PARALLELISM,
            nonce,
        }
    }
}

/// V2 format handler (legacy - single-shot decryption only)
pub mod v2 {
    use super::*;

    /// Encrypts data in V2 format (all in RAM)
    pub fn encrypt(
        plaintext: &[u8],
        header: &Header,
        password: &[u8],
        keyfile_bytes: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let key = crate::crypto::derive_key(password, &header.salt, keyfile_bytes);

        // V2: Encrypt everything
        let ciphertext = crate::crypto::encrypt_chunk(&key, &header.nonce, plaintext)?;

        let mut output = header.to_bytes()?;
        output.extend(ciphertext);
        Ok(output)
    }

    /// Decrypts V2 format (all in RAM)
    pub fn decrypt(
        ciphertext: &[u8],
        header: &Header,
        password: &[u8],
        keyfile_bytes: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let key = crate::crypto::derive_key(password, &header.salt, keyfile_bytes);

        // V2: Decrypt all ciphertext
        let plaintext = crate::crypto::decrypt_chunk(&key, &header.nonce, ciphertext)?;

        Ok(plaintext)
    }
}

/// V3 format handler (streaming)
pub mod v3 {
    use super::*;

    /// Encrypts data in V3 streaming format
    /// 
    /// Writes encrypted chunks to the output writer
    pub fn encrypt_streaming<R: Read, W: Write>(
        input: &mut R,
        output: &mut W,
        header: &Header,
        password: &[u8],
        keyfile_bytes: Option<&[u8]>,
    ) -> Result<()> {
        let key = crate::crypto::derive_key(password, &header.salt, keyfile_bytes);
        let header_bytes = header.to_bytes()?;

        // Write header
        output.write_all(&header_bytes)?;

        // Convert nonce to integer for incrementing (96-bit nonce = 12 bytes)
        // We use big-endian and pad with 4 zero bytes at the front to make 16 bytes (u128)
        let mut nonce_padded = [0u8; 16];
        nonce_padded[4..].copy_from_slice(&header.nonce);
        let nonce_int = u128::from_be_bytes(nonce_padded);

        let mut chunk_counter: u128 = 0;
        let mut buffer = [0u8; CHUNK_SIZE];

        loop {
            let bytes_read = input.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            // Calculate nonce for this chunk
            let current_nonce_int = (nonce_int + chunk_counter) % (2u128.pow(96));
            let current_nonce_bytes = current_nonce_int.to_be_bytes();
            let current_nonce: [u8; NONCE_SIZE] = current_nonce_bytes[4..].try_into()
                .map_err(|_| Error::InvalidFormat)?;

            // Encrypt chunk
            let ciphertext = crate::crypto::encrypt_chunk(&key, &current_nonce, &buffer[..bytes_read])
                .map_err(Error::from)?;
            output.write_all(&ciphertext)?;

            chunk_counter += 1;
        }

        Ok(())
    }

    /// Decrypts V3 streaming format
    /// 
    /// Reads encrypted chunks from input and writes decrypted data to output
    pub fn decrypt_streaming<R: Read, W: Write>(
        input: &mut R,
        output: &mut W,
        header: &Header,
        password: &[u8],
        keyfile_bytes: Option<&[u8]>,
    ) -> Result<()> {
        let key = crate::crypto::derive_key(password, &header.salt, keyfile_bytes);

        // Convert nonce to integer for incrementing (96-bit nonce = 12 bytes)
        let mut nonce_padded = [0u8; 16];
        nonce_padded[4..].copy_from_slice(&header.nonce);
        let nonce_int = u128::from_be_bytes(nonce_padded);

        let mut chunk_counter: u128 = 0;
        let mut encrypted_buffer = [0u8; ENC_CHUNK_SIZE];

        loop {
            let bytes_read = input.read(&mut encrypted_buffer)?;
            if bytes_read == 0 {
                break;
            }

            // Calculate nonce for this chunk
            let current_nonce_int = (nonce_int + chunk_counter) % (2u128.pow(96));
            let current_nonce_bytes = current_nonce_int.to_be_bytes();
            let current_nonce: [u8; NONCE_SIZE] = current_nonce_bytes[4..].try_into()
                .map_err(|_| Error::InvalidFormat)?;

            // Decrypt chunk
            let plaintext = crate::crypto::decrypt_chunk(&key, &current_nonce, &encrypted_buffer[..bytes_read])
                .map_err(|_| Error::DecryptionFailed)?;
            output.write_all(&plaintext)?;

            chunk_counter += 1;
        }

        Ok(())
    }
}
