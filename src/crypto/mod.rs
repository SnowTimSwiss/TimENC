//! Cryptographic primitives for TimENC

use argon2::{
    Argon2,
    Params,
    Version,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use rand::RngCore;
use zeroize::Zeroizing;

/// Length of the encryption key in bytes
pub const KEY_LEN: usize = 32;

/// Length of the salt in bytes
pub const SALT_SIZE: usize = 16;

/// Length of the nonce in bytes (96 bits)
pub const NONCE_SIZE: usize = 12;

/// Size of the authentication tag in bytes
pub const TAG_SIZE: usize = 16;

/// Default Argon2 parameters (compatible with Python TimENC v3)
pub const ARGON2_TIME_COST: u32 = 4;
pub const ARGON2_MEMORY_KIB: u32 = 131072; // 128 MiB
pub const ARGON2_PARALLELISM: u32 = 4;

/// Magic bytes at the start of every .timenc file
pub const MAGIC: &[u8; 6] = b"TIMENC";

/// Current encryption format version
pub const FORMAT_VERSION: u8 = 3;

/// Derives a key from password and optional keyfile using Argon2id
/// 
/// # Arguments
/// * `password` - The password bytes
/// * `salt` - Random salt (16 bytes)
/// * `keyfile_bytes` - Optional keyfile content
/// 
/// # Returns
/// A 32-byte key for ChaCha20-Poly1305
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    keyfile_bytes: Option<&[u8]>,
) -> Zeroizing<[u8; KEY_LEN]> {
    // Combine password with keyfile if present
    let mut combined = Zeroizing::new(Vec::with_capacity(password.len() + 11 + 32));
    combined.extend_from_slice(password);
    
    if let Some(keyfile) = keyfile_bytes {
        combined.extend_from_slice(b"::KEYFILE::");
        combined.extend_from_slice(keyfile);
    }

    // Create Argon2id instance with v3 parameters
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(KEY_LEN),
    ).expect("Valid Argon2 parameters");

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(&combined, salt, &mut key[..])
        .expect("Key derivation failed");

    key
}

/// Generates a random salt
pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Generates a random nonce
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Generates a random keyfile
pub fn generate_keyfile_data() -> [u8; 32] {
    let mut keyfile = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut keyfile);
    keyfile
}

/// Encrypts a single chunk using ChaCha20-Poly1305
pub fn encrypt_chunk(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| chacha20poly1305::Error)?;
    cipher.encrypt(nonce.into(), Payload { msg: plaintext, aad })
}

/// Decrypts a single chunk using ChaCha20-Poly1305
pub fn decrypt_chunk(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| chacha20poly1305::Error)?;
    cipher.decrypt(nonce.into(), Payload { msg: ciphertext, aad })
}
