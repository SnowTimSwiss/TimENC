//! TimENC Core Library - Secure encryption with ChaCha20-Poly1305 and Argon2id
//! 
//! This library provides encryption/decryption compatible with TimENC v2 and v3 formats.

pub mod crypto;
pub mod format;
pub mod error;
pub mod operations;

pub use error::{Error, Result};
pub use operations::{encrypt, decrypt, generate_keyfile, EncryptOptions, DecryptOptions};
