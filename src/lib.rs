//! Core encryption library for TimENC.
//!
//! Supports the current encrypted-metadata format and older streaming files.

pub mod crypto;
pub mod format;
pub mod error;
pub mod operations;

pub use error::{Error, Result};
pub use operations::{encrypt, decrypt, generate_keyfile, EncryptOptions, DecryptOptions};
