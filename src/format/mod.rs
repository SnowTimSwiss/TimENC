//! TIMENC file format handling (v2, v3, and v4)

use crate::crypto::{self, NONCE_SIZE, SALT_SIZE, TAG_SIZE};
use crate::error::{Error, Result};
use std::io::{self, Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

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

    /// Reads and parses the header from a reader without buffering the whole file.
    pub fn read_from<R: Read>(reader: &mut R) -> Result<(Self, usize)> {
        let mut fixed = [0u8; 10];
        reader.read_exact(&mut fixed)?;

        if &fixed[0..6] != crypto::MAGIC {
            return Err(Error::InvalidFormat);
        }

        let version = fixed[6];
        let is_dir = fixed[7] == 1;
        let name_len = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;

        let mut variable = vec![0u8; name_len + SALT_SIZE + 4 + 4 + 1 + NONCE_SIZE];
        reader.read_exact(&mut variable)?;

        let original_name = String::from_utf8(variable[0..name_len].to_vec())?;
        let mut offset = name_len;

        let salt: [u8; SALT_SIZE] = variable[offset..offset + SALT_SIZE]
            .try_into()
            .map_err(|_| Error::InvalidFormat)?;
        offset += SALT_SIZE;

        let time_cost = u32::from_be_bytes([
            variable[offset],
            variable[offset + 1],
            variable[offset + 2],
            variable[offset + 3],
        ]);
        offset += 4;

        let memory_kib = u32::from_be_bytes([
            variable[offset],
            variable[offset + 1],
            variable[offset + 2],
            variable[offset + 3],
        ]);
        offset += 4;

        let parallelism = variable[offset] as u32;
        offset += 1;

        let nonce: [u8; NONCE_SIZE] = variable[offset..offset + NONCE_SIZE]
            .try_into()
            .map_err(|_| Error::InvalidFormat)?;

        Ok((
            Header {
                version,
                is_dir,
                original_name,
                salt,
                time_cost,
                memory_kib,
                parallelism,
                nonce,
            },
            fixed.len() + variable.len(),
        ))
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

pub fn sanitize_output_name(name: &str) -> Result<&str> {
    let path = Path::new(name);
    let mut components = path.components();
    match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(component)), None) if !component.is_empty() => {
            Ok(name)
        }
        _ => Err(Error::PathTraversal),
    }
}

/// V4 format handler with encrypted metadata and separated metadata/data contexts.
pub mod v4 {
    use super::*;

    /// Current v4 encryption format version.
    pub const FORMAT_VERSION_V4: u8 = 4;

    /// Stronger v4 Argon2 defaults.
    pub const ARGON2_V4_TIME_COST: u32 = 3;
    pub const ARGON2_V4_MEMORY_KIB: u32 = 262_144; // 256 MiB
    pub const ARGON2_V4_PARALLELISM: u32 = 4;

    /// Encrypted metadata for v4 files.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Metadata {
        pub is_dir: bool,
        pub original_name: String,
    }

    /// Public v4 header. Filename and directory flag live in encrypted metadata.
    #[derive(Debug, Clone)]
    pub struct Header {
        pub version: u8,
        pub salt: [u8; SALT_SIZE],
        pub time_cost: u32,
        pub memory_kib: u32,
        pub parallelism: u32,
        pub metadata_nonce: [u8; NONCE_SIZE],
        pub data_nonce: [u8; NONCE_SIZE],
        pub metadata_len: u32,
    }

    fn build_aad(label: &[u8], header_bytes: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(label.len() + header_bytes.len());
        aad.extend_from_slice(label);
        aad.extend_from_slice(header_bytes);
        aad
    }

    fn read_chunk<R: Read>(input: &mut R, buffer: &mut [u8]) -> io::Result<usize> {
        let mut total = 0;

        while total < buffer.len() {
            match input.read(&mut buffer[total..])? {
                0 => break,
                n => total += n,
            }
        }

        Ok(total)
    }

    impl Metadata {
        pub fn new(original_name: String, is_dir: bool) -> Self {
            Self {
                is_dir,
                original_name,
            }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>> {
            let name_bytes = self.original_name.as_bytes();
            if name_bytes.len() > u16::MAX as usize {
                return Err(Error::FilenameTooLong);
            }

            let mut buf = Vec::with_capacity(1 + 2 + name_bytes.len());
            buf.push(if self.is_dir { 1 } else { 0 });
            buf.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(name_bytes);
            Ok(buf)
        }

        pub fn from_bytes(data: &[u8]) -> Result<Self> {
            if data.len() < 3 {
                return Err(Error::InvalidFormat);
            }

            let is_dir = match data[0] {
                0 => false,
                1 => true,
                _ => return Err(Error::InvalidFormat),
            };

            let name_len = u16::from_be_bytes([data[1], data[2]]) as usize;
            if data.len() < 3 + name_len {
                return Err(Error::InvalidFormat);
            }

            let original_name = String::from_utf8(data[3..3 + name_len].to_vec())?;
            Ok(Self {
                is_dir,
                original_name,
            })
        }
    }

    impl Header {
        pub fn new(
            metadata_len: u32,
            salt: [u8; SALT_SIZE],
            metadata_nonce: [u8; NONCE_SIZE],
            data_nonce: [u8; NONCE_SIZE],
        ) -> Self {
            Self {
                version: FORMAT_VERSION_V4,
                salt,
                time_cost: ARGON2_V4_TIME_COST,
                memory_kib: ARGON2_V4_MEMORY_KIB,
                parallelism: ARGON2_V4_PARALLELISM,
                metadata_nonce,
                data_nonce,
                metadata_len,
            }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>> {
            let mut buf = Vec::with_capacity(
                6 + 1 + SALT_SIZE + 4 + 4 + 4 + NONCE_SIZE + NONCE_SIZE + 4,
            );
            buf.extend_from_slice(crypto::MAGIC);
            buf.push(self.version);
            buf.extend_from_slice(&self.salt);
            buf.extend_from_slice(&self.time_cost.to_be_bytes());
            buf.extend_from_slice(&self.memory_kib.to_be_bytes());
            buf.extend_from_slice(&self.parallelism.to_be_bytes());
            buf.extend_from_slice(&self.metadata_nonce);
            buf.extend_from_slice(&self.data_nonce);
            buf.extend_from_slice(&self.metadata_len.to_be_bytes());
            Ok(buf)
        }

        pub fn from_bytes(data: &[u8]) -> Result<(Self, usize)> {
            let expected_len = 6 + 1 + SALT_SIZE + 4 + 4 + 4 + NONCE_SIZE + NONCE_SIZE + 4;
            if data.len() < expected_len {
                return Err(Error::InvalidFormat);
            }

            if &data[0..6] != crypto::MAGIC {
                return Err(Error::InvalidFormat);
            }

            let mut offset = 6;
            let version = data[offset];
            offset += 1;
            if version != FORMAT_VERSION_V4 {
                return Err(Error::InvalidFormat);
            }

            let salt: [u8; SALT_SIZE] = data[offset..offset + SALT_SIZE]
                .try_into()
                .map_err(|_| Error::InvalidFormat)?;
            offset += SALT_SIZE;

            let time_cost = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            offset += 4;

            let memory_kib = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            offset += 4;

            let parallelism = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            offset += 4;

            let metadata_nonce: [u8; NONCE_SIZE] = data[offset..offset + NONCE_SIZE]
                .try_into()
                .map_err(|_| Error::InvalidFormat)?;
            offset += NONCE_SIZE;

            let data_nonce: [u8; NONCE_SIZE] = data[offset..offset + NONCE_SIZE]
                .try_into()
                .map_err(|_| Error::InvalidFormat)?;
            offset += NONCE_SIZE;

            let metadata_len = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            offset += 4;

            Ok((
                Self {
                    version,
                    salt,
                    time_cost,
                    memory_kib,
                    parallelism,
                    metadata_nonce,
                    data_nonce,
                    metadata_len,
                },
                offset,
            ))
        }

        pub fn read_from<R: Read>(reader: &mut R) -> Result<(Self, usize)> {
            let mut fixed = vec![0u8; 6 + 1 + SALT_SIZE + 4 + 4 + 4 + NONCE_SIZE + NONCE_SIZE + 4];
            reader.read_exact(&mut fixed)?;
            Self::from_bytes(&fixed)
        }
    }

    fn derive_key_v4(
        password: &[u8],
        salt: &[u8],
        keyfile_bytes: Option<&[u8]>,
    ) -> Zeroizing<[u8; crate::crypto::KEY_LEN]> {
        let mut secret = Zeroizing::new(Vec::with_capacity(
            password.len() + keyfile_bytes.map_or(0, |keyfile| keyfile.len()) + 32,
        ));
        secret.extend_from_slice(b"TIMENC-v4|password|");
        secret.extend_from_slice(password);
        if let Some(keyfile) = keyfile_bytes {
            secret.extend_from_slice(b"|keyfile|");
            secret.extend_from_slice(keyfile);
        }

        crate::crypto::derive_key_from_secret(
            &secret,
            salt,
            ARGON2_V4_TIME_COST,
            ARGON2_V4_MEMORY_KIB,
            ARGON2_V4_PARALLELISM,
        )
    }

    pub fn encrypt_metadata(
        metadata: &Metadata,
        header: &Header,
        password: &[u8],
        keyfile_bytes: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let key = derive_key_v4(password, &header.salt, keyfile_bytes);
        let header_bytes = header.to_bytes()?;
        let aad = build_aad(b"TIMENC-v4-metadata", &header_bytes);
        let plaintext = metadata.to_bytes()?;
        crate::crypto::encrypt_chunk(&key, &header.metadata_nonce, &plaintext, &aad).map_err(Error::from)
    }

    pub fn decrypt_metadata(
        encrypted_metadata: &[u8],
        header: &Header,
        password: &[u8],
        keyfile_bytes: Option<&[u8]>,
    ) -> Result<Metadata> {
        let key = derive_key_v4(password, &header.salt, keyfile_bytes);
        let header_bytes = header.to_bytes()?;
        let aad = build_aad(b"TIMENC-v4-metadata", &header_bytes);
        let plaintext = crate::crypto::decrypt_chunk(&key, &header.metadata_nonce, encrypted_metadata, &aad)
            .map_err(|_| Error::DecryptionFailed)?;
        Metadata::from_bytes(&plaintext)
    }

    pub fn encrypt_streaming<R: Read, W: Write>(
        input: &mut R,
        output: &mut W,
        header: &Header,
        metadata: &Metadata,
        password: &[u8],
        keyfile_bytes: Option<&[u8]>,
    ) -> Result<()> {
        let key = derive_key_v4(password, &header.salt, keyfile_bytes);
        let header_bytes = header.to_bytes()?;
        let metadata_aad = build_aad(b"TIMENC-v4-metadata", &header_bytes);
        let data_aad = build_aad(b"TIMENC-v4-data", &header_bytes);

        output.write_all(&header_bytes)?;

        let metadata_bytes = metadata.to_bytes()?;
        let encrypted_metadata = crate::crypto::encrypt_chunk(
            &key,
            &header.metadata_nonce,
            &metadata_bytes,
            &metadata_aad,
        )
        .map_err(Error::from)?;
        output.write_all(&encrypted_metadata)?;

        let mut nonce_padded = [0u8; 16];
        nonce_padded[4..].copy_from_slice(&header.data_nonce);
        let nonce_int = u128::from_be_bytes(nonce_padded);

        let mut chunk_counter: u128 = 0;
        let mut buffer = [0u8; CHUNK_SIZE];

        loop {
            let bytes_read = read_chunk(input, &mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            let current_nonce_int = (nonce_int + chunk_counter) % (2u128.pow(96));
            let current_nonce_bytes = current_nonce_int.to_be_bytes();
            let current_nonce: [u8; NONCE_SIZE] = current_nonce_bytes[4..]
                .try_into()
                .map_err(|_| Error::InvalidFormat)?;

            let ciphertext = crate::crypto::encrypt_chunk(
                &key,
                &current_nonce,
                &buffer[..bytes_read],
                &data_aad,
            )
            .map_err(Error::from)?;
            output.write_all(&ciphertext)?;

            chunk_counter += 1;
        }

        Ok(())
    }

    pub fn decrypt_streaming<R: Read, W: Write>(
        input: &mut R,
        output: &mut W,
        header: &Header,
        password: &[u8],
        keyfile_bytes: Option<&[u8]>,
    ) -> Result<()> {
        let key = derive_key_v4(password, &header.salt, keyfile_bytes);
        let header_bytes = header.to_bytes()?;
        let data_aad = build_aad(b"TIMENC-v4-data", &header_bytes);

        let mut nonce_padded = [0u8; 16];
        nonce_padded[4..].copy_from_slice(&header.data_nonce);
        let nonce_int = u128::from_be_bytes(nonce_padded);

        let mut chunk_counter: u128 = 0;
        let mut encrypted_buffer = [0u8; ENC_CHUNK_SIZE];

        loop {
            let bytes_read = read_chunk(input, &mut encrypted_buffer)?;
            if bytes_read == 0 {
                break;
            }
            if bytes_read < TAG_SIZE {
                return Err(Error::InvalidFormat);
            }

            let current_nonce_int = (nonce_int + chunk_counter) % (2u128.pow(96));
            let current_nonce_bytes = current_nonce_int.to_be_bytes();
            let current_nonce: [u8; NONCE_SIZE] = current_nonce_bytes[4..]
                .try_into()
                .map_err(|_| Error::InvalidFormat)?;

            let plaintext = crate::crypto::decrypt_chunk(
                &key,
                &current_nonce,
                &encrypted_buffer[..bytes_read],
                &data_aad,
            )
            .map_err(|_| Error::DecryptionFailed)?;
            output.write_all(&plaintext)?;

            chunk_counter += 1;
        }

        Ok(())
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
        let key = crate::crypto::derive_key(
            password,
            &header.salt,
            header.time_cost,
            header.memory_kib,
            header.parallelism,
            keyfile_bytes,
        );
        let header_bytes = header.to_bytes()?;

        // V2: Encrypt everything
        let ciphertext = crate::crypto::encrypt_chunk(&key, &header.nonce, plaintext, &header_bytes)?;

        let mut output = header_bytes;
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
        let key = crate::crypto::derive_key(
            password,
            &header.salt,
            header.time_cost,
            header.memory_kib,
            header.parallelism,
            keyfile_bytes,
        );
        let header_bytes = header.to_bytes()?;

        // V2: Decrypt all ciphertext
        let plaintext = crate::crypto::decrypt_chunk(&key, &header.nonce, ciphertext, &header_bytes)?;

        Ok(plaintext)
    }
}

/// V3 format handler (streaming)
pub mod v3 {
    use super::*;

    fn read_chunk<R: Read>(input: &mut R, buffer: &mut [u8]) -> io::Result<usize> {
        let mut total = 0;

        while total < buffer.len() {
            match input.read(&mut buffer[total..])? {
                0 => break,
                n => total += n,
            }
        }

        Ok(total)
    }

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
        let key = crate::crypto::derive_key(
            password,
            &header.salt,
            header.time_cost,
            header.memory_kib,
            header.parallelism,
            keyfile_bytes,
        );
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
            let bytes_read = read_chunk(input, &mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            // Calculate nonce for this chunk
            let current_nonce_int = (nonce_int + chunk_counter) % (2u128.pow(96));
            let current_nonce_bytes = current_nonce_int.to_be_bytes();
            let current_nonce: [u8; NONCE_SIZE] = current_nonce_bytes[4..].try_into()
                .map_err(|_| Error::InvalidFormat)?;

            // Encrypt chunk
            let ciphertext = crate::crypto::encrypt_chunk(&key, &current_nonce, &buffer[..bytes_read], &header_bytes)
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
        let key = crate::crypto::derive_key(
            password,
            &header.salt,
            header.time_cost,
            header.memory_kib,
            header.parallelism,
            keyfile_bytes,
        );
        let header_bytes = header.to_bytes()?;

        // Convert nonce to integer for incrementing (96-bit nonce = 12 bytes)
        let mut nonce_padded = [0u8; 16];
        nonce_padded[4..].copy_from_slice(&header.nonce);
        let nonce_int = u128::from_be_bytes(nonce_padded);

        let mut chunk_counter: u128 = 0;
        let mut encrypted_buffer = [0u8; ENC_CHUNK_SIZE];

        loop {
            let bytes_read = read_chunk(input, &mut encrypted_buffer)?;
            if bytes_read == 0 {
                break;
            }
            if bytes_read < TAG_SIZE {
                return Err(Error::InvalidFormat);
            }

            // Calculate nonce for this chunk
            let current_nonce_int = (nonce_int + chunk_counter) % (2u128.pow(96));
            let current_nonce_bytes = current_nonce_int.to_be_bytes();
            let current_nonce: [u8; NONCE_SIZE] = current_nonce_bytes[4..].try_into()
                .map_err(|_| Error::InvalidFormat)?;

            // Decrypt chunk
            let plaintext = crate::crypto::decrypt_chunk(&key, &current_nonce, &encrypted_buffer[..bytes_read], &header_bytes)
                .map_err(|_| Error::DecryptionFailed)?;
            output.write_all(&plaintext)?;

            chunk_counter += 1;
        }

        Ok(())
    }
}
