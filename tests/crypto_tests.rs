//! Core library tests

use timenc::crypto;

#[test]
fn test_key_derivation() {
    let password = b"test_password";
    let salt = [0u8; 16];
    
    let key1 = crypto::derive_key(password, &salt, None);
    let key2 = crypto::derive_key(password, &salt, None);
    
    // Same password + salt should produce same key
    assert_eq!(key1.as_ref(), key2.as_ref());
}

#[test]
fn test_key_derivation_with_keyfile() {
    let password = b"test_password";
    let salt = [0u8; 16];
    let keyfile = b"keyfile_content";
    
    let key1 = crypto::derive_key(password, &salt, None);
    let key2 = crypto::derive_key(password, &salt, Some(keyfile));
    
    // Keyfile should produce different key
    assert_ne!(key1.as_ref(), key2.as_ref());
}

#[test]
fn test_salt_generation() {
    let salt1 = crypto::generate_salt();
    let salt2 = crypto::generate_salt();
    
    // Salts should be unique
    assert_ne!(salt1, salt2);
}

#[test]
fn test_nonce_generation() {
    let nonce1 = crypto::generate_nonce();
    let nonce2 = crypto::generate_nonce();
    
    // Nonces should be unique
    assert_ne!(nonce1, nonce2);
}

#[test]
fn test_keyfile_generation() {
    let keyfile = crypto::generate_keyfile_data();
    
    // Keyfile should be 32 bytes
    assert_eq!(keyfile.len(), 32);
    
    // Keyfiles should be unique
    let keyfile2 = crypto::generate_keyfile_data();
    assert_ne!(keyfile, keyfile2);
}
