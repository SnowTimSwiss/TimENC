//! Format tests for TIMENC v2, v3, and v4 compatibility

use std::io::{Cursor, Read};
use timenc::format::{Header, CHUNK_SIZE};
use timenc::crypto;

#[test]
fn test_header_serialization_v3() {
    let salt = crypto::generate_salt();
    let nonce = crypto::generate_nonce();
    
    let header = Header::new_v3(
        "test.txt".to_string(),
        false,
        salt,
        nonce,
    );
    
    let bytes = header.to_bytes().expect("Failed to serialize header");
    let (parsed_header, _) = Header::from_bytes(&bytes).expect("Failed to parse header");
    
    assert_eq!(parsed_header.version, 3);
    assert_eq!(parsed_header.is_dir, false);
    assert_eq!(parsed_header.original_name, "test.txt");
    assert_eq!(parsed_header.salt, salt);
    assert_eq!(parsed_header.nonce, nonce);
    assert_eq!(parsed_header.time_cost, crypto::ARGON2_TIME_COST);
    assert_eq!(parsed_header.memory_kib, crypto::ARGON2_MEMORY_KIB);
    assert_eq!(parsed_header.parallelism, crypto::ARGON2_PARALLELISM);
}

#[test]
fn test_header_with_directory() {
    let salt = crypto::generate_salt();
    let nonce = crypto::generate_nonce();
    
    let header = Header::new_v3(
        "my_folder".to_string(),
        true,
        salt,
        nonce,
    );
    
    let bytes = header.to_bytes().expect("Failed to serialize header");
    let (parsed_header, _) = Header::from_bytes(&bytes).expect("Failed to parse header");
    
    assert_eq!(parsed_header.is_dir, true);
    assert_eq!(parsed_header.original_name, "my_folder");
}

#[test]
fn test_header_with_long_filename() {
    let salt = crypto::generate_salt();
    let nonce = crypto::generate_nonce();
    
    // Max filename length is 65535 bytes
    let long_name = "a".repeat(1000);
    
    let header = Header::new_v3(
        long_name,
        false,
        salt,
        nonce,
    );
    
    let bytes = header.to_bytes().expect("Failed to serialize header");
    let (parsed_header, _) = Header::from_bytes(&bytes).expect("Failed to parse header");
    
    assert_eq!(parsed_header.original_name.len(), 1000);
}

#[test]
fn test_magic_bytes() {
    assert_eq!(crypto::MAGIC, b"TIMENC");
}

#[test]
fn test_chunk_size() {
    // V3 uses 64 KiB chunks
    assert_eq!(CHUNK_SIZE, 64 * 1024);
}

#[test]
fn test_invalid_magic() {
    let invalid_data = b"INVALID";
    let result = Header::from_bytes(invalid_data);
    assert!(result.is_err());
}

#[test]
fn test_read_header_streaming_matches_from_bytes() {
    let salt = crypto::generate_salt();
    let nonce = crypto::generate_nonce();
    let header = Header::new_v3("streamed.txt".to_string(), false, salt, nonce);
    let bytes = header.to_bytes().expect("Failed to serialize header");

    let (parsed_header, header_len) =
        Header::read_from(&mut Cursor::new(bytes.clone())).expect("Failed to read streamed header");

    assert_eq!(header_len, bytes.len());
    assert_eq!(parsed_header.original_name, header.original_name);
    assert_eq!(parsed_header.time_cost, header.time_cost);
    assert_eq!(parsed_header.memory_kib, header.memory_kib);
    assert_eq!(parsed_header.parallelism, header.parallelism);
}

#[test]
fn test_truncated_header() {
    let incomplete_data = b"TIMENC\x03\x00"; // Just magic + version + is_dir
    let result = Header::from_bytes(incomplete_data);
    assert!(result.is_err());
}

#[test]
fn test_sanitize_output_name_rejects_traversal() {
    assert!(timenc::format::sanitize_output_name("../evil.txt").is_err());
    assert!(timenc::format::sanitize_output_name("nested/evil.txt").is_err());
    assert!(timenc::format::sanitize_output_name("/absolute.txt").is_err());
    assert!(timenc::format::sanitize_output_name("safe.txt").is_ok());
}

struct SlowReader {
    inner: Cursor<Vec<u8>>,
    max_chunk: usize,
}

impl SlowReader {
    fn new(data: Vec<u8>, max_chunk: usize) -> Self {
        Self {
            inner: Cursor::new(data),
            max_chunk,
        }
    }
}

impl Read for SlowReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let limit = buf.len().min(self.max_chunk);
        self.inner.read(&mut buf[..limit])
    }
}

#[test]
fn test_v3_streaming_roundtrip_with_fragmented_reads() {
    let salt = crypto::generate_salt();
    let nonce = crypto::generate_nonce();
    let header = Header::new_v3("chunky.bin".to_string(), false, salt, nonce);
    let password = b"password";
    let plaintext = vec![0x42; CHUNK_SIZE * 2 + 123];

    let mut encrypted = Vec::new();
    timenc::format::v3::encrypt_streaming(
        &mut Cursor::new(plaintext.clone()),
        &mut encrypted,
        &header,
        password,
        None,
    )
    .expect("encryption should succeed");

    let header_len = header.to_bytes().expect("header bytes").len();
    let ciphertext = encrypted[header_len..].to_vec();

    let mut decrypted = Vec::new();
    timenc::format::v3::decrypt_streaming(
        &mut SlowReader::new(ciphertext, 17),
        &mut decrypted,
        &header,
        password,
        None,
    )
    .expect("decryption should succeed");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_v3_decrypt_rejects_tampered_ciphertext() {
    let salt = crypto::generate_salt();
    let nonce = crypto::generate_nonce();
    let header = Header::new_v3("original.txt".to_string(), false, salt, nonce);
    let password = b"password";
    let plaintext = b"secret payload";

    let mut encrypted = Vec::new();
    timenc::format::v3::encrypt_streaming(
        &mut Cursor::new(plaintext),
        &mut encrypted,
        &header,
        password,
        None,
    )
    .expect("encryption should succeed");

    let header_len = header.to_bytes().expect("header bytes").len();
    let mut ciphertext = encrypted[header_len..].to_vec();
    ciphertext[0] ^= 0x01;

    let result = timenc::format::v3::decrypt_streaming(
        &mut Cursor::new(ciphertext),
        &mut Vec::new(),
        &header,
        password,
        None,
    );

    assert!(result.is_err());
}

#[test]
fn test_v4_header_serialization_and_metadata_roundtrip() {
    let salt = crypto::generate_salt();
    let metadata_nonce = crypto::generate_nonce();
    let data_nonce = crypto::generate_nonce();
    let metadata = timenc::format::v4::Metadata::new("secret.txt".to_string(), false, false);
    let metadata_len = (metadata.to_bytes().expect("metadata bytes").len() + crypto::TAG_SIZE) as u32;
    let header = timenc::format::v4::Header::new(metadata_len, salt, metadata_nonce, data_nonce);

    let bytes = header.to_bytes().expect("Failed to serialize v4 header");
    let (parsed_header, header_len) = timenc::format::v4::Header::from_bytes(&bytes)
        .expect("Failed to parse v4 header");

    assert_eq!(header_len, bytes.len());
    assert_eq!(parsed_header.version, 5);
    assert_eq!(parsed_header.salt, salt);
    assert_eq!(parsed_header.metadata_nonce, metadata_nonce);
    assert_eq!(parsed_header.data_nonce, data_nonce);
    assert_eq!(parsed_header.metadata_len, metadata_len);
}

#[test]
fn test_v4_streaming_roundtrip_with_fragmented_reads() {
    let salt = crypto::generate_salt();
    let metadata_nonce = crypto::generate_nonce();
    let data_nonce = crypto::generate_nonce();
    let metadata = timenc::format::v4::Metadata::new("chunky.bin".to_string(), false, false);
    let metadata_len = (metadata.to_bytes().expect("metadata bytes").len() + crypto::TAG_SIZE) as u32;
    let header = timenc::format::v4::Header::new(metadata_len, salt, metadata_nonce, data_nonce);
    let password = b"password";
    let plaintext = vec![0x42; CHUNK_SIZE * 2 + 123];

    let mut encrypted = Vec::new();
    timenc::format::v4::encrypt_streaming(
        &mut Cursor::new(plaintext.clone()),
        &mut encrypted,
        &header,
        &metadata,
        password,
        None,
    )
    .expect("encryption should succeed");

    let header_len = header.to_bytes().expect("header bytes").len();
    let metadata_ciphertext = &encrypted[header_len..header_len + header.metadata_len as usize];
    let decrypted_metadata = timenc::format::v4::decrypt_metadata(
        metadata_ciphertext,
        &header,
        password,
        None,
    )
    .expect("metadata decryption should succeed");
    assert_eq!(decrypted_metadata, metadata);

    let ciphertext = encrypted[header_len + header.metadata_len as usize..].to_vec();
    let mut decrypted = Vec::new();
    timenc::format::v4::decrypt_streaming(
        &mut SlowReader::new(ciphertext, 17),
        &mut decrypted,
        &header,
        password,
        None,
    )
    .expect("decryption should succeed");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_v4_metadata_without_compressed_byte_defaults_to_uncompressed() {
    // Pre-compression v4 files only stored is_dir + name_len + name, with no
    // trailing `compressed` byte. Parsing such metadata must still succeed.
    let mut legacy_metadata_bytes = Vec::new();
    legacy_metadata_bytes.push(0u8); // is_dir = false
    let name = b"legacy.txt";
    legacy_metadata_bytes.extend_from_slice(&(name.len() as u16).to_be_bytes());
    legacy_metadata_bytes.extend_from_slice(name);

    let parsed = timenc::format::v4::Metadata::from_bytes(&legacy_metadata_bytes)
        .expect("legacy metadata should parse");
    assert_eq!(parsed.original_name, "legacy.txt");
    assert!(!parsed.is_dir);
    assert!(!parsed.compressed);
}

#[test]
fn test_v4_metadata_roundtrip_with_compressed_flag() {
    let metadata = timenc::format::v4::Metadata::new("data.bin".to_string(), false, true);
    let bytes = metadata.to_bytes().expect("metadata bytes");
    let parsed = timenc::format::v4::Metadata::from_bytes(&bytes).expect("metadata should parse");
    assert_eq!(parsed, metadata);
    assert!(parsed.compressed);
}
