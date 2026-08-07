//! Cryptographic constants and helpers used by the file formats.

use crate::error::{Error, Result};
use argon2::{
    Argon2,
    Params,
    Version,
};
use blake2::{
    digest::Mac,
    Blake2bMac512,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

/// ChaCha20-Poly1305 key length in bytes.
pub const KEY_LEN: usize = 32;

/// Argon2 salt length in bytes.
pub const SALT_SIZE: usize = 16;

/// ChaCha20-Poly1305 nonce length in bytes.
pub const NONCE_SIZE: usize = 12;

/// ChaCha20-Poly1305 authentication tag length in bytes.
pub const TAG_SIZE: usize = 16;

/// Default Argon2 parameters for legacy v3 compatibility.
pub const ARGON2_TIME_COST: u32 = 4;
pub const ARGON2_MEMORY_KIB: u32 = 131072; // 128 MiB
pub const ARGON2_PARALLELISM: u32 = 4;

/// Magic bytes at the start of every `.timenc` file.
pub const MAGIC: &[u8; 6] = b"TIMENC";

/// Legacy streaming format version.
pub const FORMAT_VERSION: u8 = 3;

/// Accepted range for the Argon2 time cost read from a file header.
pub const MIN_TIME_COST: u32 = 1;
pub const MAX_TIME_COST: u32 = 64;

/// Accepted range for the Argon2 memory cost read from a file header.
///
/// The upper bound is what makes it safe to honour header-supplied parameters
/// at all: without it, a crafted header could ask for terabytes of memory and
/// turn decryption into an out-of-memory abort.
pub const MIN_MEMORY_KIB: u32 = 8 * 1024; // 8 MiB
pub const MAX_MEMORY_KIB: u32 = 4 * 1024 * 1024; // 4 GiB

/// Accepted range for the Argon2 parallelism read from a file header.
pub const MIN_PARALLELISM: u32 = 1;
pub const MAX_PARALLELISM: u32 = 64;

/// Argon2id cost parameters for one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub time_cost: u32,
    pub memory_kib: u32,
    pub parallelism: u32,
}

impl KdfParams {
    /// Default profile: roughly a second on typical desktop hardware.
    pub const BALANCED: Self = Self {
        time_cost: 3,
        memory_kib: 262_144, // 256 MiB
        parallelism: 4,
    };

    /// High-cost profile for long-term archives.
    pub const PARANOID: Self = Self {
        time_cost: 4,
        memory_kib: 1_048_576, // 1 GiB
        parallelism: 4,
    };

    /// Parameters used by the legacy v3 format.
    pub const LEGACY_V3: Self = Self {
        time_cost: ARGON2_TIME_COST,
        memory_kib: ARGON2_MEMORY_KIB,
        parallelism: ARGON2_PARALLELISM,
    };

    pub fn new(time_cost: u32, memory_kib: u32, parallelism: u32) -> Self {
        Self {
            time_cost,
            memory_kib,
            parallelism,
        }
    }

    /// Rejects parameters outside the accepted ranges.
    ///
    /// Called on every set of parameters that comes from a file, so that a
    /// hostile header cannot force an allocation-based denial of service or a
    /// deliberately weakened derivation.
    pub fn validate(&self) -> Result<()> {
        if !(MIN_TIME_COST..=MAX_TIME_COST).contains(&self.time_cost) {
            return Err(Error::InvalidKdfParameters(format!(
                "time cost {} outside {}..={}",
                self.time_cost, MIN_TIME_COST, MAX_TIME_COST
            )));
        }
        if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib) {
            return Err(Error::InvalidKdfParameters(format!(
                "memory cost {} KiB outside {}..={} KiB",
                self.memory_kib, MIN_MEMORY_KIB, MAX_MEMORY_KIB
            )));
        }
        if !(MIN_PARALLELISM..=MAX_PARALLELISM).contains(&self.parallelism) {
            return Err(Error::InvalidKdfParameters(format!(
                "parallelism {} outside {}..={}",
                self.parallelism, MIN_PARALLELISM, MAX_PARALLELISM
            )));
        }
        Ok(())
    }
}

/// Named cost profiles offered on the command line and in the GUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KdfProfile {
    /// 256 MiB, 3 passes.
    #[default]
    Balanced,
    /// 1 GiB, 4 passes.
    Paranoid,
}

impl KdfProfile {
    pub fn params(self) -> KdfParams {
        match self {
            KdfProfile::Balanced => KdfParams::BALANCED,
            KdfProfile::Paranoid => KdfParams::PARANOID,
        }
    }
}

/// Derives an encryption key from a password and, optionally, keyfile bytes.
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    time_cost: u32,
    memory_kib: u32,
    parallelism: u32,
    keyfile_bytes: Option<&[u8]>,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut combined = Zeroizing::new(Vec::with_capacity(password.len() + 11 + 32));
    combined.extend_from_slice(password);

    if let Some(keyfile) = keyfile_bytes {
        combined.extend_from_slice(b"::KEYFILE::");
        combined.extend_from_slice(keyfile);
    }

    derive_key_from_secret(
        &combined,
        salt,
        KdfParams::new(time_cost, memory_kib, parallelism),
    )
}

/// Derives a key from an already assembled secret using Argon2id.
///
/// Returns an error rather than panicking on unusable parameters: the costs can
/// come from a file header, and the release profile aborts on panic.
pub fn derive_key_from_secret(
    secret: &[u8],
    salt: &[u8],
    kdf: KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    kdf.validate()?;

    let params = Params::new(kdf.memory_kib, kdf.time_cost, kdf.parallelism, Some(KEY_LEN))
        .map_err(|e| Error::InvalidKdfParameters(e.to_string()))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(secret, salt, &mut key[..])
        .map_err(|e| Error::KeyDerivation(e.to_string()))?;

    Ok(key)
}

/// Derives a key using the default TimENC v3 Argon2 parameters.
pub fn derive_key_v3(
    password: &[u8],
    salt: &[u8],
    keyfile_bytes: Option<&[u8]>,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    derive_key(
        password,
        salt,
        ARGON2_TIME_COST,
        ARGON2_MEMORY_KIB,
        ARGON2_PARALLELISM,
        keyfile_bytes,
    )
}

/// Context string prefixed to every subkey label, so that a subkey can never
/// collide with a hash computed for any other purpose.
const SUBKEY_CONTEXT: &[u8] = b"TIMENC subkey v1";

/// Derives a domain-separated subkey from a master key.
///
/// Keyed BLAKE2b is a PRF and fills exactly the role HKDF-Expand fills: given a
/// uniformly random master key, outputs for distinct labels are independent, and
/// seeing one output reveals nothing about the master key or the others. The
/// label is length-prefixed so that no two distinct labels can produce the same
/// input string.
pub fn derive_subkey(master: &[u8; KEY_LEN], label: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut mac = <Blake2bMac512 as Mac>::new_from_slice(master)
        .map_err(|e| Error::KeyDerivation(e.to_string()))?;
    mac.update(SUBKEY_CONTEXT);
    mac.update(&(label.len() as u32).to_be_bytes());
    mac.update(label);

    let mut wide = mac.finalize().into_bytes();
    let mut subkey = Zeroizing::new([0u8; KEY_LEN]);
    subkey.copy_from_slice(&wide[..KEY_LEN]);
    wide.as_mut_slice().zeroize();

    Ok(subkey)
}

/// Generates a random Argon2 salt.
pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Generates a random AEAD nonce.
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Generates random keyfile material.
pub fn generate_keyfile_data() -> [u8; 32] {
    let mut keyfile = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut keyfile);
    keyfile
}

/// Encrypts one authenticated chunk.
pub fn encrypt_chunk(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> std::result::Result<Vec<u8>, chacha20poly1305::Error> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| chacha20poly1305::Error)?;
    cipher.encrypt(nonce.into(), Payload { msg: plaintext, aad })
}

/// Decrypts one authenticated chunk.
pub fn decrypt_chunk(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> std::result::Result<Vec<u8>, chacha20poly1305::Error> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| chacha20poly1305::Error)?;
    cipher.decrypt(nonce.into(), Payload { msg: ciphertext, aad })
}
