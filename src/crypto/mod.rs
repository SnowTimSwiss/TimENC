//! Cryptographic constants and helpers used by the file formats.

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

/// Derives an encryption key from a password and, optionally, keyfile bytes.
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    time_cost: u32,
    memory_kib: u32,
    parallelism: u32,
    keyfile_bytes: Option<&[u8]>,
) -> Zeroizing<[u8; KEY_LEN]> {
    let mut combined = Zeroizing::new(Vec::with_capacity(password.len() + 11 + 32));
    combined.extend_from_slice(password);
    
    if let Some(keyfile) = keyfile_bytes {
        combined.extend_from_slice(b"::KEYFILE::");
        combined.extend_from_slice(keyfile);
    }

    derive_key_from_secret(&combined, salt, time_cost, memory_kib, parallelism)
}

/// Derives a key from an already assembled secret using Argon2id.
pub fn derive_key_from_secret(
    secret: &[u8],
    salt: &[u8],
    time_cost: u32,
    memory_kib: u32,
    parallelism: u32,
) -> Zeroizing<[u8; KEY_LEN]> {

    let params = Params::new(
        memory_kib,
        time_cost,
        parallelism,
        Some(KEY_LEN),
    ).expect("Valid Argon2 parameters");

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(secret, salt, &mut key[..])
        .expect("Key derivation failed");

    key
}

/// Derives a key using the default TimENC v3 Argon2 parameters.
pub fn derive_key_v3(
    password: &[u8],
    salt: &[u8],
    keyfile_bytes: Option<&[u8]>,
) -> Zeroizing<[u8; KEY_LEN]> {
    derive_key(
        password,
        salt,
        ARGON2_TIME_COST,
        ARGON2_MEMORY_KIB,
        ARGON2_PARALLELISM,
        keyfile_bytes,
    )
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
) -> Result<Vec<u8>, chacha20poly1305::Error> {
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
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| chacha20poly1305::Error)?;
    cipher.decrypt(nonce.into(), Payload { msg: ciphertext, aad })
}
