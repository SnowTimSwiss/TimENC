//! Shared error handling for the core library.

use thiserror::Error;

/// Result type used throughout the library.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by encryption, decryption, archive handling, and keyfile I/O.
#[derive(Error, Debug)]
pub enum Error {
    #[error("File not found: {path}")]
    FileNotFound { path: String },

    #[error("Invalid TIMENC file format")]
    InvalidFormat,

    #[error("Unsupported format version: {version}")]
    UnsupportedVersion { version: u8 },

    #[error("Decryption failed - wrong password/keyfile or tampered file")]
    DecryptionFailed,

    #[error("File already exists: {path}")]
    FileExists { path: String },

    #[error("Filename too long (max 65535 bytes)")]
    FilenameTooLong,

    #[error("Path traversal detected in archive")]
    PathTraversal,

    #[error("IO error: {0}")]
    Io(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("TAR error: {0}")]
    Tar(String),
}

impl From<chacha20poly1305::Error> for Error {
    fn from(e: chacha20poly1305::Error) -> Self {
        Error::Encryption(e.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}
