//! Integration tests for encrypt/decrypt roundtrip

use std::fs;
use std::io::Cursor;
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

#[test]
fn test_decrypt_rejects_header_filename_traversal() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let encrypted_path = temp_dir.path().join("evil.timenc");
    let output_dir = temp_dir.path().join("out");

    let salt = timenc::crypto::generate_salt();
    let nonce = timenc::crypto::generate_nonce();
    let header = timenc::format::Header::new_v3("../evil.txt".to_string(), false, salt, nonce);

    let mut encrypted = Vec::new();
    timenc::format::v3::encrypt_streaming(
        &mut Cursor::new(b"payload".to_vec()),
        &mut encrypted,
        &header,
        b"password",
        None,
    )
    .expect("encryption should succeed");

    fs::write(&encrypted_path, encrypted).expect("Failed to write encrypted file");

    let result = decrypt(
        &encrypted_path,
        DecryptOptions {
            password: "password".to_string(),
            keyfile_path: None,
            output_dir: output_dir.clone(),
            delete_source: false,
        },
    );

    assert!(result.is_err());
    assert!(!temp_dir.path().join("evil.txt").exists());
}

#[test]
fn test_decrypt_rejects_tar_traversal_entries() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let tar_path = temp_dir.path().join("payload.tar");
    let encrypted_path = temp_dir.path().join("payload.timenc");
    let output_dir = temp_dir.path().join("out");

    let tar_file = fs::File::create(&tar_path).expect("Failed to create tar");
    let mut builder = tar::Builder::new(tar_file);
    let data = b"owned".to_vec();
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "safe.txt", Cursor::new(data))
        .expect("Failed to append tar data");
    builder.finish().expect("Failed to finish tar");

    let mut tar_bytes = fs::read(&tar_path).expect("Failed to read tar bytes");
    let malicious_name = b"../escape.txt";
    tar_bytes[..100].fill(0);
    tar_bytes[..malicious_name.len()].copy_from_slice(malicious_name);
    tar_bytes[148..156].fill(b' ');
    let checksum: u32 = tar_bytes[..512].iter().map(|&byte| byte as u32).sum();
    let checksum_octal = format!("{checksum:06o}\0 ");
    tar_bytes[148..156].copy_from_slice(checksum_octal.as_bytes());
    fs::write(&tar_path, tar_bytes).expect("Failed to rewrite tar bytes");

    let salt = timenc::crypto::generate_salt();
    let nonce = timenc::crypto::generate_nonce();
    let header = timenc::format::Header::new_v3("archive".to_string(), true, salt, nonce);

    let mut encrypted = Vec::new();
    timenc::format::v3::encrypt_streaming(
        &mut fs::File::open(&tar_path).expect("Failed to open tar"),
        &mut encrypted,
        &header,
        b"password",
        None,
    )
    .expect("encryption should succeed");

    fs::write(&encrypted_path, encrypted).expect("Failed to write encrypted file");

    let result = decrypt(
        &encrypted_path,
        DecryptOptions {
            password: "password".to_string(),
            keyfile_path: None,
            output_dir: output_dir.clone(),
            delete_source: false,
        },
    );

    assert!(result.is_err());
    assert!(!temp_dir.path().join("escape.txt").exists());
}

#[test]
fn test_decrypt_uses_header_argon2_parameters() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let encrypted_path = temp_dir.path().join("custom.timenc");
    let output_dir = temp_dir.path().join("out");

    let mut header = timenc::format::Header::new_v3(
        "custom.txt".to_string(),
        false,
        timenc::crypto::generate_salt(),
        timenc::crypto::generate_nonce(),
    );
    header.time_cost = 2;
    header.memory_kib = 32 * 1024;
    header.parallelism = 1;

    let mut encrypted = Vec::new();
    timenc::format::v3::encrypt_streaming(
        &mut Cursor::new(b"custom-params".to_vec()),
        &mut encrypted,
        &header,
        b"password",
        None,
    )
    .expect("encryption should succeed");

    fs::write(&encrypted_path, encrypted).expect("Failed to write encrypted file");

    let result_path = decrypt(
        &encrypted_path,
        DecryptOptions {
            password: "password".to_string(),
            keyfile_path: None,
            output_dir,
            delete_source: false,
        },
    )
    .expect("decryption should succeed");

    let decrypted = fs::read(result_path).expect("Failed to read decrypted file");
    assert_eq!(decrypted, b"custom-params");
}
