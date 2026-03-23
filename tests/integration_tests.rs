//! Integration tests for encrypt/decrypt roundtrip

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use tempfile::TempDir;
use timenc::{encrypt, decrypt, generate_keyfile, EncryptOptions, DecryptOptions};

fn setup_test_file(content: &[u8]) -> (PathBuf, TempDir) {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join("test.txt");
    
    let mut file = fs::File::create(&file_path).expect("Failed to create test file");
    file.write_all(content).expect("Failed to write test content");
    
    (file_path, temp_dir)
}

#[test]
fn test_encrypt_decrypt_file_roundtrip() {
    let original_content = b"Hello, World! This is a secret message.";
    let password = "test_password_123";
    
    let (input_path, _input_temp) = setup_test_file(original_content);
    let encrypt_temp = tempfile::tempdir().expect("Failed to create encrypt temp dir");
    let decrypt_temp = tempfile::tempdir().expect("Failed to create decrypt temp dir");
    
    let output_path = encrypt_temp.path().join("test.timenc");
    
    // Encrypt
    let encrypt_options = EncryptOptions {
        password: password.to_string(),
        keyfile_path: None,
        output_path: output_path.clone(),
        delete_source: false,
    };
    
    encrypt(&input_path, encrypt_options).expect("Encryption failed");
    assert!(output_path.exists());
    
    // Decrypt
    let decrypt_options = DecryptOptions {
        password: password.to_string(),
        keyfile_path: None,
        output_dir: decrypt_temp.path().to_path_buf(),
        delete_source: false,
    };
    
    let result_path = decrypt(&output_path, decrypt_options).expect("Decryption failed");
    assert!(result_path.exists());
    
    // Verify content
    let decrypted_content = fs::read(&result_path).expect("Failed to read decrypted file");
    assert_eq!(original_content, &decrypted_content[..]);
}

#[test]
fn test_encrypt_decrypt_with_keyfile() {
    let original_content = b"Secret content with keyfile protection.";
    let password = "test_password_456";
    
    let (input_path, _input_temp) = setup_test_file(original_content);
    let keyfile_temp = tempfile::tempdir().expect("Failed to create keyfile temp dir");
    let encrypt_temp = tempfile::tempdir().expect("Failed to create encrypt temp dir");
    let decrypt_temp = tempfile::tempdir().expect("Failed to create decrypt temp dir");
    
    // Generate keyfile
    let keyfile_path = keyfile_temp.path().join("test.key");
    generate_keyfile(&keyfile_path).expect("Keyfile generation failed");
    
    let output_path = encrypt_temp.path().join("test.timenc");
    
    // Encrypt with keyfile
    let encrypt_options = EncryptOptions {
        password: password.to_string(),
        keyfile_path: Some(keyfile_path.clone()),
        output_path: output_path.clone(),
        delete_source: false,
    };
    
    encrypt(&input_path, encrypt_options).expect("Encryption failed");
    assert!(output_path.exists());
    
    // Decrypt with keyfile
    let decrypt_options = DecryptOptions {
        password: password.to_string(),
        keyfile_path: Some(keyfile_path),
        output_dir: decrypt_temp.path().to_path_buf(),
        delete_source: false,
    };
    
    let result_path = decrypt(&output_path, decrypt_options).expect("Decryption failed");
    assert!(result_path.exists());
    
    // Verify content
    let decrypted_content = fs::read(&result_path).expect("Failed to read decrypted file");
    assert_eq!(original_content, &decrypted_content[..]);
}

#[test]
fn test_decrypt_wrong_password() {
    let original_content = b"Secret content.";
    let password = "correct_password";
    let wrong_password = "wrong_password";
    
    let (input_path, _input_temp) = setup_test_file(original_content);
    let encrypt_temp = tempfile::tempdir().expect("Failed to create encrypt temp dir");
    let decrypt_temp = tempfile::tempdir().expect("Failed to create decrypt temp dir");
    
    let output_path = encrypt_temp.path().join("test.timenc");
    
    // Encrypt
    let encrypt_options = EncryptOptions {
        password: password.to_string(),
        keyfile_path: None,
        output_path: output_path.clone(),
        delete_source: false,
    };
    
    encrypt(&input_path, encrypt_options).expect("Encryption failed");
    
    // Try to decrypt with wrong password
    let decrypt_options = DecryptOptions {
        password: wrong_password.to_string(),
        keyfile_path: None,
        output_dir: decrypt_temp.path().to_path_buf(),
        delete_source: false,
    };
    
    let result = decrypt(&output_path, decrypt_options);
    assert!(result.is_err());
}

#[test]
fn test_encrypt_decrypt_directory() {
    let password = "test_password_789";
    
    // Create temp directory with files
    let input_temp = tempfile::tempdir().expect("Failed to create input temp dir");
    let input_dir = input_temp.path().join("test_folder");
    fs::create_dir(&input_dir).expect("Failed to create test directory");
    
    // Add files to directory
    fs::write(input_dir.join("file1.txt"), b"Content 1").expect("Failed to write file1");
    fs::write(input_dir.join("file2.txt"), b"Content 2").expect("Failed to write file2");
    
    let encrypt_temp = tempfile::tempdir().expect("Failed to create encrypt temp dir");
    let decrypt_temp = tempfile::tempdir().expect("Failed to create decrypt temp dir");
    
    let output_path = encrypt_temp.path().join("test_folder.timenc");
    
    // Encrypt directory
    let encrypt_options = EncryptOptions {
        password: password.to_string(),
        keyfile_path: None,
        output_path: output_path.clone(),
        delete_source: false,
    };
    
    encrypt(&input_dir, encrypt_options).expect("Encryption failed");
    assert!(output_path.exists());
    
    // Decrypt directory
    let decrypt_options = DecryptOptions {
        password: password.to_string(),
        keyfile_path: None,
        output_dir: decrypt_temp.path().to_path_buf(),
        delete_source: false,
    };
    
    let result_path = decrypt(&output_path, decrypt_options).expect("Decryption failed");
    assert!(result_path.exists());
    
    // Verify files
    let decrypted_dir = result_path.join("test_folder");
    assert!(decrypted_dir.exists());
    assert_eq!(fs::read(decrypted_dir.join("file1.txt")).unwrap(), b"Content 1");
    assert_eq!(fs::read(decrypted_dir.join("file2.txt")).unwrap(), b"Content 2");
}

#[test]
fn test_generate_keyfile() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let keyfile_path = temp_dir.path().join("new_keyfile.key");
    
    let result = generate_keyfile(&keyfile_path);
    assert!(result.is_ok());
    assert!(keyfile_path.exists());
    
    // Verify keyfile size (32 bytes)
    let content = fs::read(&keyfile_path).expect("Failed to read keyfile");
    assert_eq!(content.len(), 32);
}

#[test]
fn test_keyfile_already_exists() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let keyfile_path = temp_dir.path().join("existing.key");
    
    // Create existing file
    fs::write(&keyfile_path, b"existing content").expect("Failed to create existing file");
    
    // Try to generate keyfile at same path
    let result = generate_keyfile(&keyfile_path);
    assert!(result.is_err());
}
