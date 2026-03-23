//! Format tests for TIMENC v2 and v3 compatibility

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
fn test_truncated_header() {
    let incomplete_data = b"TIMENC\x03\x00"; // Just magic + version + is_dir
    let result = Header::from_bytes(incomplete_data);
    assert!(result.is_err());
}
