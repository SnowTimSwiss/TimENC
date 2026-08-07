//! Binary `.timenc` file formats.

use crate::crypto::{self, NONCE_SIZE, SALT_SIZE, TAG_SIZE};
use crate::error::{Error, Result};
use std::io::{self, Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

/// Plaintext chunk size used by the streaming formats.
pub const CHUNK_SIZE: usize = 64 * 1024;

/// Encrypted chunk size for a full plaintext chunk.
pub const ENC_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_SIZE;

/// Header used by the older v2/v3 formats.
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
    /// Encodes this header as stored bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let name_bytes = self.original_name.as_bytes();
        if name_bytes.len() > u16::MAX as usize {
            return Err(Error::FilenameTooLong);
        }

        let mut buf = Vec::with_capacity(6 + 1 + 1 + 2 + name_bytes.len() + SALT_SIZE + 4 + 4 + 1 + NONCE_SIZE);
        
        buf.extend_from_slice(crypto::MAGIC);
        buf.push(self.version);
        buf.push(if self.is_dir { 1 } else { 0 });
        buf.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.time_cost.to_be_bytes());
        buf.extend_from_slice(&self.memory_kib.to_be_bytes());
        buf.push(self.parallelism as u8);
        buf.extend_from_slice(&self.nonce);

        Ok(buf)
    }

    /// Parses a header from the start of a byte slice.
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 6 {
            return Err(Error::InvalidFormat);
        }

        if &data[0..6] != crypto::MAGIC {
            return Err(Error::InvalidFormat);
        }

        let mut offset = 6;

        if data.len() <= offset {
            return Err(Error::InvalidFormat);
        }
        let version = data[offset];
        offset += 1;

        if data.len() <= offset {
            return Err(Error::InvalidFormat);
        }
        let is_dir = data[offset] == 1;
        offset += 1;

        if data.len() < offset + 2 {
            return Err(Error::InvalidFormat);
        }
        let name_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if data.len() < offset + name_len {
            return Err(Error::InvalidFormat);
        }
        let original_name = String::from_utf8(data[offset..offset + name_len].to_vec())?;
        offset += name_len;

        if data.len() < offset + SALT_SIZE {
            return Err(Error::InvalidFormat);
        }
        let salt: [u8; SALT_SIZE] = data[offset..offset + SALT_SIZE].try_into()
            .map_err(|_| Error::InvalidFormat)?;
        offset += SALT_SIZE;

        if data.len() < offset + 4 {
            return Err(Error::InvalidFormat);
        }
        let time_cost = u32::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]);
        offset += 4;

        if data.len() < offset + 4 {
            return Err(Error::InvalidFormat);
        }
        let memory_kib = u32::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]);
        offset += 4;

        if data.len() <= offset {
            return Err(Error::InvalidFormat);
        }
        let parallelism = data[offset] as u32;
        offset += 1;

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

    /// Builds a v3 header with the standard v3 KDF settings.
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

/// Validates a decrypted file name before it is used as an output path.
///
/// The name must be a single normal path component: anything containing a
/// directory separator, `..`, a root, or a drive prefix is rejected with
/// [`Error::PathTraversal`]. This stops a crafted archive from writing outside
/// the chosen output directory.
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

/// Current format with encrypted metadata and separate metadata/data contexts.
pub mod v4 {
    use super::*;

    /// Legacy encrypted-metadata format version. Still decryptable, but no
    /// longer written: superseded by [`FORMAT_VERSION_V4_5`].
    pub const FORMAT_VERSION_V4: u8 = 4;

    /// Current encrypted-metadata format version. Same on-disk layout and
    /// cryptography as v4 - the only difference is the `compressed` byte in
    /// the metadata block, so this is not a new format generation (no crypto
    /// upgrade), just v4 with one more metadata field. A distinct version byte still matters:
    /// it makes clients built before compression support existed fail loudly
    /// (`UnsupportedVersion`) instead of silently writing out still-compressed
    /// "decrypted" data when they don't know to look at the `compressed` flag.
    pub const FORMAT_VERSION_V4_5: u8 = 5;

    /// Default KDF settings for v4 files.
    pub const ARGON2_V4_TIME_COST: u32 = 3;
    pub const ARGON2_V4_MEMORY_KIB: u32 = 262_144; // 256 MiB
    pub const ARGON2_V4_PARALLELISM: u32 = 4;

    /// Metadata stored inside the encrypted metadata block.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Metadata {
        pub is_dir: bool,
        pub original_name: String,
        pub compressed: bool,
    }

    /// Public v4 header. File name and directory flag are encrypted separately.
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
        pub fn new(original_name: String, is_dir: bool, compressed: bool) -> Self {
            Self {
                is_dir,
                original_name,
                compressed,
            }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>> {
            let name_bytes = self.original_name.as_bytes();
            if name_bytes.len() > u16::MAX as usize {
                return Err(Error::FilenameTooLong);
            }

            let mut buf = Vec::with_capacity(1 + 2 + name_bytes.len() + 1);
            buf.push(if self.is_dir { 1 } else { 0 });
            buf.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(name_bytes);
            buf.push(if self.compressed { 1 } else { 0 });
            Ok(buf)
        }

        /// Parses metadata. The trailing `compressed` byte is optional so that
        /// v4 files written before compression support was added still decrypt
        /// (they default to uncompressed).
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

            let compressed = match data.get(3 + name_len) {
                None => false,
                Some(0) => false,
                Some(1) => true,
                Some(_) => return Err(Error::InvalidFormat),
            };

            Ok(Self {
                is_dir,
                original_name,
                compressed,
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
                version: FORMAT_VERSION_V4_5,
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
            if version != FORMAT_VERSION_V4 && version != FORMAT_VERSION_V4_5 {
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
            if metadata_len > MAX_METADATA_LEN {
                return Err(Error::MetadataTooLarge {
                    len: metadata_len as u64,
                });
            }

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

    /// Largest metadata block this parser will allocate for.
    ///
    /// A v4 metadata block is at most `is_dir + name_len + 64 KiB name +
    /// compressed + tag`, so any larger value in a header is a crafted file
    /// trying to trigger a huge allocation.
    pub const MAX_METADATA_LEN: u32 = 1 + 2 + u16::MAX as u32 + 1 + TAG_SIZE as u32;

    fn derive_key_v4(
        password: &[u8],
        salt: &[u8],
        keyfile_bytes: Option<&[u8]>,
    ) -> Result<Zeroizing<[u8; crate::crypto::KEY_LEN]>> {
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
            crate::crypto::KdfParams::new(
                ARGON2_V4_TIME_COST,
                ARGON2_V4_MEMORY_KIB,
                ARGON2_V4_PARALLELISM,
            ),
        )
    }

    /// Encrypts the metadata block, binding it to the header via AAD.
    pub fn encrypt_metadata(
        metadata: &Metadata,
        header: &Header,
        password: &[u8],
        keyfile_bytes: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let key = derive_key_v4(password, &header.salt, keyfile_bytes)?;
        let header_bytes = header.to_bytes()?;
        let aad = build_aad(b"TIMENC-v4-metadata", &header_bytes);
        let plaintext = metadata.to_bytes()?;
        crate::crypto::encrypt_chunk(&key, &header.metadata_nonce, &plaintext, &aad).map_err(Error::from)
    }

    /// Decrypts and parses the metadata block, verifying it against the header.
    pub fn decrypt_metadata(
        encrypted_metadata: &[u8],
        header: &Header,
        password: &[u8],
        keyfile_bytes: Option<&[u8]>,
    ) -> Result<Metadata> {
        let key = derive_key_v4(password, &header.salt, keyfile_bytes)?;
        let header_bytes = header.to_bytes()?;
        let aad = build_aad(b"TIMENC-v4-metadata", &header_bytes);
        let plaintext = crate::crypto::decrypt_chunk(&key, &header.metadata_nonce, encrypted_metadata, &aad)
            .map_err(|_| Error::DecryptionFailed)?;
        Metadata::from_bytes(&plaintext)
    }

    /// Writes the header, encrypted metadata, and the payload as authenticated
    /// chunks. Each data chunk uses a distinct nonce derived from the base data
    /// nonce plus the chunk index.
    pub fn encrypt_streaming<R: Read, W: Write>(
        input: &mut R,
        output: &mut W,
        header: &Header,
        metadata: &Metadata,
        password: &[u8],
        keyfile_bytes: Option<&[u8]>,
    ) -> Result<()> {
        let key = derive_key_v4(password, &header.salt, keyfile_bytes)?;
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

    /// Decrypts the payload chunks into the writer, reconstructing the per-chunk
    /// nonces. A failed authentication tag aborts with [`Error::DecryptionFailed`].
    pub fn decrypt_streaming<R: Read, W: Write>(
        input: &mut R,
        output: &mut W,
        header: &Header,
        password: &[u8],
        keyfile_bytes: Option<&[u8]>,
    ) -> Result<()> {
        let key = derive_key_v4(password, &header.salt, keyfile_bytes)?;
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

/// Compatibility helpers for the older in-memory v2 format.
pub mod v2 {
    use super::*;

    /// Encrypts a complete v2 payload in memory.
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
        )?;
        let header_bytes = header.to_bytes()?;

        let ciphertext = crate::crypto::encrypt_chunk(&key, &header.nonce, plaintext, &header_bytes)?;

        let mut output = header_bytes;
        output.extend(ciphertext);
        Ok(output)
    }

    /// Decrypts a complete v2 payload in memory.
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
        )?;
        let header_bytes = header.to_bytes()?;

        let plaintext = crate::crypto::decrypt_chunk(&key, &header.nonce, ciphertext, &header_bytes)?;

        Ok(plaintext)
    }
}

/// Compatibility helpers for the older v3 streaming format.
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

    /// Encrypts plaintext as v3 streaming chunks.
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
        )?;
        output.write_all(&header.to_bytes()?)?;

        // Pad the 96-bit nonce so it can be incremented as a u128.
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

            let current_nonce_int = (nonce_int + chunk_counter) % (2u128.pow(96));
            let current_nonce_bytes = current_nonce_int.to_be_bytes();
            let current_nonce: [u8; NONCE_SIZE] = current_nonce_bytes[4..].try_into()
                .map_err(|_| Error::InvalidFormat)?;

            let ciphertext = crate::crypto::encrypt_chunk(&key, &current_nonce, &buffer[..bytes_read], b"")
                .map_err(Error::from)?;
            output.write_all(&ciphertext)?;

            chunk_counter += 1;
        }

        Ok(())
    }

    /// Decrypts v3 streaming chunks into the output writer.
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
        )?;
        // Pad the 96-bit nonce so it can be incremented as a u128.
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

            let current_nonce_int = (nonce_int + chunk_counter) % (2u128.pow(96));
            let current_nonce_bytes = current_nonce_int.to_be_bytes();
            let current_nonce: [u8; NONCE_SIZE] = current_nonce_bytes[4..].try_into()
                .map_err(|_| Error::InvalidFormat)?;

            let plaintext = crate::crypto::decrypt_chunk(&key, &current_nonce, &encrypted_buffer[..bytes_read], b"")
                .map_err(|_| Error::DecryptionFailed)?;
            output.write_all(&plaintext)?;

            chunk_counter += 1;
        }

        Ok(())
    }
}

/// Current format: key-committing, with a terminated chunk stream and optional
/// size padding.
///
/// What changed against [`v4`], and why:
///
/// * **Terminated stream.** Every data chunk authenticates its own index and an
///   `is_final` marker. v4 decrypted until end-of-file, so cutting a v4 file at
///   a chunk boundary produced a shorter plaintext that still authenticated
///   cleanly. v6 rejects that with [`Error::TruncatedFile`].
/// * **Key commitment.** The header carries a commitment to the derived key, so
///   one file cannot be made to decrypt to different valid plaintexts under two
///   different passwords, and a wrong password is rejected straight after key
///   derivation, without any trial decryption.
/// * **Subkey hierarchy.** Metadata and payload use separate keys derived from
///   the Argon2id output, rather than one key separated only by AAD labels.
///   Because each subkey is unique per file, chunk nonces are plain counters
///   starting at zero - no random nonce base and no modular wraparound.
/// * **Honoured KDF parameters.** v4 stored Argon2 costs in the header but
///   derived with hardcoded constants. v6 uses the stored values, bounds-checked
///   against [`crypto::MIN_MEMORY_KIB`] and friends, which is what makes the
///   `Paranoid` profile possible without breaking older files.
/// * **Optional padding.** The true payload length lives in the encrypted
///   metadata, so the ciphertext can be padded to hide the exact plaintext size.
pub mod v6 {
    use super::*;
    use crate::crypto::{KdfParams, KEY_LEN};
    use subtle::ConstantTimeEq;

    /// Version byte of the v6 format.
    ///
    /// Byte 5 was already spent on "v4.5" (see [`v4::FORMAT_VERSION_V4_5`]),
    /// which was a metadata tweak rather than a crypto change. v6 - the first
    /// real cryptographic upgrade since v4 - therefore takes byte 6.
    pub const FORMAT_VERSION_V6: u8 = 6;

    /// Length of the key-commitment tag stored in the header.
    pub const COMMITMENT_SIZE: usize = 32;

    /// Total size of a serialized v6 header. Unlike v2/v3 it is fixed-length.
    pub const HEADER_LEN: usize =
        6 + 1 + SALT_SIZE + 4 + 4 + 4 + 4 + COMMITMENT_SIZE;

    /// Largest metadata block this parser will allocate for.
    pub const MAX_METADATA_LEN: u32 =
        1 + 2 + u16::MAX as u32 + 1 + 8 + TAG_SIZE as u32;

    const SUBKEY_LABEL_METADATA: &[u8] = b"TIMENC-v6 metadata key";
    const SUBKEY_LABEL_DATA: &[u8] = b"TIMENC-v6 data key";
    const SUBKEY_LABEL_COMMITMENT: &[u8] = b"TIMENC-v6 commitment";

    const AAD_LABEL_METADATA: &[u8] = b"TIMENC-v6-metadata";
    const AAD_LABEL_DATA: &[u8] = b"TIMENC-v6-data";

    /// Per-file key material derived from the password and optional keyfile.
    ///
    /// Derived once per operation: the Argon2id run is the expensive part, and
    /// v4 paid for it twice (once for metadata, once for the payload).
    pub struct FileKeys {
        metadata_key: Zeroizing<[u8; KEY_LEN]>,
        data_key: Zeroizing<[u8; KEY_LEN]>,
        commitment: [u8; COMMITMENT_SIZE],
    }

    impl FileKeys {
        /// The commitment tag to store in (or compare against) the header.
        pub fn commitment(&self) -> &[u8; COMMITMENT_SIZE] {
            &self.commitment
        }
    }

    /// Runs Argon2id over the password and keyfile, then splits the result into
    /// the metadata key, the data key, and the commitment tag.
    pub fn derive_file_keys(
        password: &[u8],
        keyfile_bytes: Option<&[u8]>,
        salt: &[u8; SALT_SIZE],
        kdf: KdfParams,
    ) -> Result<FileKeys> {
        let mut secret = Zeroizing::new(Vec::with_capacity(
            password.len() + keyfile_bytes.map_or(0, |keyfile| keyfile.len()) + 32,
        ));
        secret.extend_from_slice(b"TIMENC-v6|password|");
        secret.extend_from_slice(password);
        if let Some(keyfile) = keyfile_bytes {
            secret.extend_from_slice(b"|keyfile|");
            secret.extend_from_slice(keyfile);
        }

        let master = crypto::derive_key_from_secret(&secret, salt, kdf)?;

        let commitment_key = crypto::derive_subkey(&master, SUBKEY_LABEL_COMMITMENT)?;
        let mut commitment = [0u8; COMMITMENT_SIZE];
        commitment.copy_from_slice(&commitment_key[..]);

        Ok(FileKeys {
            metadata_key: crypto::derive_subkey(&master, SUBKEY_LABEL_METADATA)?,
            data_key: crypto::derive_subkey(&master, SUBKEY_LABEL_DATA)?,
            commitment,
        })
    }

    /// Metadata stored inside the encrypted metadata block.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Metadata {
        pub is_dir: bool,
        pub original_name: String,
        pub compressed: bool,
        /// Length of the real payload, before any padding. Everything the data
        /// stream produces beyond this is padding and is discarded.
        pub payload_len: u64,
    }

    impl Metadata {
        pub fn new(
            original_name: String,
            is_dir: bool,
            compressed: bool,
            payload_len: u64,
        ) -> Self {
            Self {
                is_dir,
                original_name,
                compressed,
                payload_len,
            }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>> {
            let name_bytes = self.original_name.as_bytes();
            if name_bytes.len() > u16::MAX as usize {
                return Err(Error::FilenameTooLong);
            }

            let mut buf = Vec::with_capacity(1 + 2 + name_bytes.len() + 1 + 8);
            buf.push(if self.is_dir { 1 } else { 0 });
            buf.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(name_bytes);
            buf.push(if self.compressed { 1 } else { 0 });
            buf.extend_from_slice(&self.payload_len.to_be_bytes());
            Ok(buf)
        }

        /// Parses metadata. Unlike v4 there is no optional tail: v6 metadata is
        /// always written by this crate, so every field is required.
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
            if data.len() != 3 + name_len + 1 + 8 {
                return Err(Error::InvalidFormat);
            }

            let original_name = String::from_utf8(data[3..3 + name_len].to_vec())?;

            let compressed = match data[3 + name_len] {
                0 => false,
                1 => true,
                _ => return Err(Error::InvalidFormat),
            };

            let payload_len = u64::from_be_bytes(
                data[4 + name_len..12 + name_len]
                    .try_into()
                    .map_err(|_| Error::InvalidFormat)?,
            );

            Ok(Self {
                is_dir,
                original_name,
                compressed,
                payload_len,
            })
        }
    }

    /// Public v6 header. Carries no nonces: those are counters derived from the
    /// per-file subkeys.
    #[derive(Debug, Clone)]
    pub struct Header {
        pub version: u8,
        pub salt: [u8; SALT_SIZE],
        pub kdf: KdfParams,
        pub metadata_len: u32,
        pub commitment: [u8; COMMITMENT_SIZE],
    }

    impl Header {
        pub fn new(
            salt: [u8; SALT_SIZE],
            kdf: KdfParams,
            metadata_len: u32,
            commitment: [u8; COMMITMENT_SIZE],
        ) -> Self {
            Self {
                version: FORMAT_VERSION_V6,
                salt,
                kdf,
                metadata_len,
                commitment,
            }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>> {
            let mut buf = Vec::with_capacity(HEADER_LEN);
            buf.extend_from_slice(crypto::MAGIC);
            buf.push(self.version);
            buf.extend_from_slice(&self.salt);
            buf.extend_from_slice(&self.kdf.time_cost.to_be_bytes());
            buf.extend_from_slice(&self.kdf.memory_kib.to_be_bytes());
            buf.extend_from_slice(&self.kdf.parallelism.to_be_bytes());
            buf.extend_from_slice(&self.metadata_len.to_be_bytes());
            buf.extend_from_slice(&self.commitment);
            Ok(buf)
        }

        pub fn from_bytes(data: &[u8]) -> Result<(Self, usize)> {
            if data.len() < HEADER_LEN {
                return Err(Error::InvalidFormat);
            }
            if &data[0..6] != crypto::MAGIC {
                return Err(Error::InvalidFormat);
            }

            let mut offset = 6;
            let version = data[offset];
            offset += 1;
            if version != FORMAT_VERSION_V6 {
                return Err(Error::InvalidFormat);
            }

            let salt: [u8; SALT_SIZE] = data[offset..offset + SALT_SIZE]
                .try_into()
                .map_err(|_| Error::InvalidFormat)?;
            offset += SALT_SIZE;

            let read_u32 = |offset: &mut usize| {
                let value = u32::from_be_bytes([
                    data[*offset],
                    data[*offset + 1],
                    data[*offset + 2],
                    data[*offset + 3],
                ]);
                *offset += 4;
                value
            };

            let time_cost = read_u32(&mut offset);
            let memory_kib = read_u32(&mut offset);
            let parallelism = read_u32(&mut offset);
            let metadata_len = read_u32(&mut offset);

            // Header-supplied costs are honoured, so they must be bounded.
            let kdf = KdfParams::new(time_cost, memory_kib, parallelism);
            kdf.validate()?;

            if metadata_len > MAX_METADATA_LEN {
                return Err(Error::MetadataTooLarge {
                    len: metadata_len as u64,
                });
            }
            if (metadata_len as usize) < TAG_SIZE {
                return Err(Error::InvalidFormat);
            }

            let commitment: [u8; COMMITMENT_SIZE] = data[offset..offset + COMMITMENT_SIZE]
                .try_into()
                .map_err(|_| Error::InvalidFormat)?;
            offset += COMMITMENT_SIZE;

            Ok((
                Self {
                    version,
                    salt,
                    kdf,
                    metadata_len,
                    commitment,
                },
                offset,
            ))
        }

        pub fn read_from<R: Read>(reader: &mut R) -> Result<(Self, usize)> {
            let mut fixed = [0u8; HEADER_LEN];
            reader.read_exact(&mut fixed)?;
            Self::from_bytes(&fixed)
        }

        /// Checks the derived key against the header's commitment tag.
        ///
        /// Call this before touching the ciphertext: it rejects a wrong password
        /// or keyfile immediately, and it is what stops one file from decrypting
        /// to two different valid plaintexts under two different keys.
        pub fn verify_commitment(&self, keys: &FileKeys) -> Result<()> {
            if self.commitment.ct_eq(&keys.commitment).into() {
                Ok(())
            } else {
                Err(Error::DecryptionFailed)
            }
        }
    }

    /// Pads a length using the Padmé scheme.
    ///
    /// Rounds up so that at most `O(log log len)` bits of the true length leak,
    /// with a bounded overhead of about 12% in the worst case and far less for
    /// typical sizes (1000 -> 1024, i.e. 2.4%).
    pub fn padme(len: u64) -> u64 {
        if len < 4 {
            return len;
        }

        let exponent = 63 - len.leading_zeros(); // floor(log2(len))
        let significant = 32 - exponent.leading_zeros(); // floor(log2(exponent)) + 1
        let last_bits = exponent.saturating_sub(significant);
        let mask = (1u64 << last_bits) - 1;

        (len + mask) & !mask
    }

    /// A reader that yields the inner stream, then zero bytes up to a target
    /// length, so that the ciphertext hides the exact plaintext size.
    struct PadReader<'a, R: Read> {
        inner: &'a mut R,
        inner_done: bool,
        inner_len: u64,
        pad_remaining: u64,
    }

    impl<'a, R: Read> PadReader<'a, R> {
        fn new(inner: &'a mut R, pad_bytes: u64) -> Self {
            Self {
                inner,
                inner_done: false,
                inner_len: 0,
                pad_remaining: pad_bytes,
            }
        }
    }

    impl<R: Read> Read for PadReader<'_, R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.inner_done {
                let read = self.inner.read(buf)?;
                if read > 0 {
                    self.inner_len += read as u64;
                    return Ok(read);
                }
                self.inner_done = true;
            }

            let pad = (buf.len() as u64).min(self.pad_remaining) as usize;
            if pad == 0 {
                return Ok(0);
            }
            buf[..pad].fill(0);
            self.pad_remaining -= pad as u64;
            Ok(pad)
        }
    }

    fn metadata_aad(header_bytes: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(AAD_LABEL_METADATA.len() + header_bytes.len());
        aad.extend_from_slice(AAD_LABEL_METADATA);
        aad.extend_from_slice(header_bytes);
        aad
    }

    /// Builds the AAD for one data chunk.
    ///
    /// Binding the chunk index and the `is_final` flag is what makes the stream
    /// tamper-evident as a whole rather than chunk by chunk: reordering,
    /// duplicating, dropping, or appending chunks all change the AAD of some
    /// chunk and fail authentication.
    fn data_aad(header_bytes: &[u8], index: u64, is_final: bool) -> Vec<u8> {
        let mut aad = Vec::with_capacity(AAD_LABEL_DATA.len() + header_bytes.len() + 9);
        aad.extend_from_slice(AAD_LABEL_DATA);
        aad.extend_from_slice(header_bytes);
        aad.extend_from_slice(&index.to_be_bytes());
        aad.push(u8::from(is_final));
        aad
    }

    /// Nonce for the chunk at `index`.
    ///
    /// A plain counter is safe here because the data subkey is unique to this
    /// file: two files never share a key, so they never share a (key, nonce)
    /// pair either.
    fn chunk_nonce(index: u64) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[4..].copy_from_slice(&index.to_be_bytes());
        nonce
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

    /// Encrypts the metadata block on its own.
    ///
    /// Only needed by callers that write the pieces separately; the normal path
    /// is [`encrypt_streaming`], which emits header, metadata, and payload.
    pub fn encrypt_metadata(
        metadata: &Metadata,
        header: &Header,
        keys: &FileKeys,
    ) -> Result<Vec<u8>> {
        let header_bytes = header.to_bytes()?;
        crypto::encrypt_chunk(
            &keys.metadata_key,
            &chunk_nonce(0),
            &metadata.to_bytes()?,
            &metadata_aad(&header_bytes),
        )
        .map_err(Error::from)
    }

    /// Decrypts and parses the metadata block, verifying it against the header.
    pub fn decrypt_metadata(
        encrypted_metadata: &[u8],
        header: &Header,
        keys: &FileKeys,
    ) -> Result<Metadata> {
        let header_bytes = header.to_bytes()?;
        let plaintext = crypto::decrypt_chunk(
            &keys.metadata_key,
            &chunk_nonce(0),
            encrypted_metadata,
            &metadata_aad(&header_bytes),
        )
        .map_err(|_| Error::DecryptionFailed)?;
        Metadata::from_bytes(&plaintext)
    }

    /// Builds the header for a file whose metadata is already known.
    pub fn build_header(
        salt: [u8; SALT_SIZE],
        kdf: KdfParams,
        metadata: &Metadata,
        keys: &FileKeys,
    ) -> Result<Header> {
        let metadata_len = (metadata.to_bytes()?.len() + TAG_SIZE) as u32;
        Ok(Header::new(salt, kdf, metadata_len, *keys.commitment()))
    }

    /// Writes a complete v6 file: header, encrypted metadata, then the payload
    /// as a terminated sequence of authenticated chunks.
    ///
    /// `metadata.payload_len` must equal the exact number of bytes `input`
    /// yields; it is verified once the stream is consumed. When `pad` is set the
    /// stream is extended with zero bytes to a [`padme`] length, which the
    /// decryptor discards.
    ///
    /// Returns the header that was written.
    pub fn encrypt_streaming<R: Read, W: Write>(
        input: &mut R,
        output: &mut W,
        salt: [u8; SALT_SIZE],
        kdf: KdfParams,
        metadata: &Metadata,
        keys: &FileKeys,
        pad: bool,
    ) -> Result<Header> {
        let header = build_header(salt, kdf, metadata, keys)?;
        let header_bytes = header.to_bytes()?;
        output.write_all(&header_bytes)?;

        let encrypted_metadata = encrypt_metadata(metadata, &header, keys)?;
        output.write_all(&encrypted_metadata)?;

        let pad_bytes = if pad {
            padme(metadata.payload_len) - metadata.payload_len
        } else {
            0
        };
        let mut padded = PadReader::new(input, pad_bytes);

        let mut buffer = [0u8; CHUNK_SIZE];
        let mut index: u64 = 0;

        loop {
            let bytes_read = read_chunk(&mut padded, &mut buffer)?;
            // A short read means the padded stream is exhausted. A file whose
            // length is an exact multiple of CHUNK_SIZE therefore ends with an
            // empty final chunk, which is tag-only on disk.
            let is_final = bytes_read < CHUNK_SIZE;

            let ciphertext = crypto::encrypt_chunk(
                &keys.data_key,
                &chunk_nonce(index),
                &buffer[..bytes_read],
                &data_aad(&header_bytes, index, is_final),
            )
            .map_err(Error::from)?;
            output.write_all(&ciphertext)?;

            index += 1;
            if is_final {
                break;
            }
        }

        if padded.inner_len != metadata.payload_len {
            return Err(Error::PayloadLengthMismatch {
                expected: metadata.payload_len,
                actual: padded.inner_len,
            });
        }

        Ok(header)
    }

    /// Decrypts the payload into `output`, writing exactly
    /// `metadata.payload_len` bytes and discarding any padding.
    ///
    /// Fails with [`Error::TruncatedFile`] if the stream ends before the chunk
    /// marked final, [`Error::TrailingData`] if anything follows it, and
    /// [`Error::DecryptionFailed`] if any chunk fails authentication - which
    /// covers reordered, duplicated, and modified chunks.
    pub fn decrypt_streaming<R: Read, W: Write>(
        input: &mut R,
        output: &mut W,
        header: &Header,
        metadata: &Metadata,
        keys: &FileKeys,
    ) -> Result<()> {
        let header_bytes = header.to_bytes()?;

        let mut encrypted_buffer = [0u8; ENC_CHUNK_SIZE];
        let mut index: u64 = 0;
        let mut written: u64 = 0;

        loop {
            let bytes_read = read_chunk(input, &mut encrypted_buffer)?;
            if bytes_read < TAG_SIZE {
                // Either the file was cut at a chunk boundary or the final
                // chunk itself is incomplete. Both mean the stream never
                // reached the chunk that claims to be final.
                return Err(Error::TruncatedFile);
            }

            let is_final = bytes_read < ENC_CHUNK_SIZE;

            let plaintext = crypto::decrypt_chunk(
                &keys.data_key,
                &chunk_nonce(index),
                &encrypted_buffer[..bytes_read],
                &data_aad(&header_bytes, index, is_final),
            )
            .map_err(|_| Error::DecryptionFailed)?;

            // Everything past payload_len is padding and must not be emitted.
            let remaining = metadata.payload_len.saturating_sub(written);
            let keep = (plaintext.len() as u64).min(remaining) as usize;
            output.write_all(&plaintext[..keep])?;
            written += keep as u64;

            index += 1;
            if is_final {
                break;
            }
        }

        // A legitimate final chunk is always shorter than ENC_CHUNK_SIZE, so
        // appended bytes would already have broken its tag. Checked anyway so
        // that the guarantee does not rest on that argument alone.
        if input.read(&mut encrypted_buffer[..1])? != 0 {
            return Err(Error::TrailingData);
        }

        if written != metadata.payload_len {
            return Err(Error::PayloadLengthMismatch {
                expected: metadata.payload_len,
                actual: written,
            });
        }

        Ok(())
    }
}
