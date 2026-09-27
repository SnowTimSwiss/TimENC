//! Tests for the file-handling guarantees of encrypt/decrypt: the source is
//! only deleted on request, existing files are never overwritten, and nothing
//! is left behind on failure.

use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use timenc::format::v6::{self, EncryptWriter, Metadata};
use timenc::format::CHUNK_SIZE;
use timenc::{decrypt, encrypt, DecryptOptions, EncryptOptions, Error, KdfParams};

/// Cheapest parameters the header validation accepts, to keep tests fast.
const FAST_KDF: KdfParams = KdfParams {
    time_cost: 1,
    memory_kib: 8 * 1024,
    parallelism: 1,
};

fn encrypt_options(output_path: PathBuf, delete_source: bool) -> EncryptOptions {
    let mut options = EncryptOptions::new("correct horse".to_string(), output_path);
    options.delete_source = delete_source;
    options
}

fn decrypt_options(output_dir: &Path, delete_source: bool) -> DecryptOptions {
    DecryptOptions {
        password: "correct horse".to_string(),
        keyfile_path: None,
        output_dir: output_dir.to_path_buf(),
        delete_source,
    }
}

fn dir_entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn test_source_file_is_kept_by_default() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("keep.txt");
    fs::write(&input, b"keep me").unwrap();
    let output = temp.path().join("keep.timenc");

    encrypt(&input, encrypt_options(output.clone(), false)).unwrap();

    assert_eq!(fs::read(&input).unwrap(), b"keep me");
    assert!(output.exists());
}

#[test]
fn test_source_file_is_deleted_on_request() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("secret.txt");
    fs::write(&input, b"secret").unwrap();
    let output = temp.path().join("secret.timenc");

    encrypt(&input, encrypt_options(output.clone(), true)).unwrap();
    assert!(!input.exists());

    let out_dir = temp.path().join("out");
    let restored = decrypt(&output, decrypt_options(&out_dir, false)).unwrap();
    assert_eq!(fs::read(restored).unwrap(), b"secret");
}

#[test]
fn test_source_directory_is_kept_by_default() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("folder");
    fs::create_dir_all(input.join("sub")).unwrap();
    fs::write(input.join("sub/a.txt"), b"a").unwrap();
    let output = temp.path().join("folder.timenc");

    let mut options = encrypt_options(output.clone(), false);
    options.compress = true;
    encrypt(&input, options).unwrap();

    assert_eq!(fs::read(input.join("sub/a.txt")).unwrap(), b"a");
}

#[test]
fn test_source_directory_is_deleted_on_request() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("folder");
    fs::create_dir_all(input.join("sub")).unwrap();
    fs::write(input.join("sub/a.txt"), b"a").unwrap();
    fs::write(input.join("b.txt"), vec![7u8; 3 * CHUNK_SIZE + 5]).unwrap();
    let output = temp.path().join("folder.timenc");

    encrypt(&input, encrypt_options(output.clone(), true)).unwrap();
    assert!(!input.exists());

    let out_dir = temp.path().join("out");
    decrypt(&output, decrypt_options(&out_dir, false)).unwrap();
    assert_eq!(fs::read(out_dir.join("folder/sub/a.txt")).unwrap(), b"a");
    assert_eq!(
        fs::read(out_dir.join("folder/b.txt")).unwrap(),
        vec![7u8; 3 * CHUNK_SIZE + 5]
    );
}

#[test]
fn test_encrypted_file_is_kept_after_decrypt_by_default() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("data.bin");
    fs::write(&input, b"payload").unwrap();
    let output = temp.path().join("data.timenc");
    encrypt(&input, encrypt_options(output.clone(), true)).unwrap();

    let out_dir = temp.path().join("out");
    decrypt(&output, decrypt_options(&out_dir, false)).unwrap();
    assert!(output.exists());
}

#[test]
fn test_encrypted_file_is_deleted_after_decrypt_on_request() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("data.bin");
    fs::write(&input, b"payload").unwrap();
    let output = temp.path().join("data.timenc");
    encrypt(&input, encrypt_options(output.clone(), true)).unwrap();

    let out_dir = temp.path().join("out");
    let restored = decrypt(&output, decrypt_options(&out_dir, true)).unwrap();
    assert!(!output.exists());
    assert_eq!(fs::read(restored).unwrap(), b"payload");
}

#[test]
fn test_encrypt_refuses_to_overwrite_existing_output() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("new.txt");
    fs::write(&input, b"new").unwrap();
    let output = temp.path().join("existing.timenc");
    fs::write(&output, b"do not touch").unwrap();

    let result = encrypt(&input, encrypt_options(output.clone(), true));

    assert!(matches!(result, Err(Error::FileExists { .. })));
    assert_eq!(fs::read(&output).unwrap(), b"do not touch");
    assert_eq!(fs::read(&input).unwrap(), b"new");
    assert_eq!(dir_entries(temp.path()), vec!["existing.timenc", "new.txt"]);
}

#[test]
fn test_failed_encrypt_leaves_no_partial_output() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("in.txt");
    fs::write(&input, b"data").unwrap();
    let output = temp.path().join("in.timenc");

    let mut options = encrypt_options(output.clone(), true);
    options.keyfile_path = Some(temp.path().join("missing.key"));
    assert!(encrypt(&input, options).is_err());

    assert!(input.exists());
    assert_eq!(dir_entries(temp.path()), vec!["in.txt"]);
}

#[test]
fn test_encrypt_rejects_output_inside_input_directory() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("folder");
    fs::create_dir(&input).unwrap();
    fs::write(input.join("a.txt"), b"a").unwrap();

    let result = encrypt(&input, encrypt_options(input.join("folder.timenc"), true));

    assert!(matches!(result, Err(Error::OutputInsideInput)));
    assert_eq!(dir_entries(&input), vec!["a.txt"]);
}

#[cfg(unix)]
#[test]
fn test_directory_symlinks_are_archived_as_links_not_followed() {
    let temp = tempfile::tempdir().unwrap();
    let outside = temp.path().join("outside.txt");
    fs::write(&outside, b"outside the folder").unwrap();

    let input = temp.path().join("folder");
    fs::create_dir(&input).unwrap();
    fs::write(input.join("inside.txt"), b"inside").unwrap();
    std::os::unix::fs::symlink(&outside, input.join("link.txt")).unwrap();

    let output = temp.path().join("folder.timenc");
    encrypt(&input, encrypt_options(output.clone(), true)).unwrap();

    // Deleting the source removed the link, not the file it points to.
    assert!(!input.exists());
    assert_eq!(fs::read(&outside).unwrap(), b"outside the folder");

    let out_dir = temp.path().join("out");
    decrypt(&output, decrypt_options(&out_dir, false)).unwrap();
    let restored_link = out_dir.join("folder/link.txt");
    assert!(fs::symlink_metadata(&restored_link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read_link(&restored_link).unwrap(), outside);
}

#[test]
fn test_options_debug_output_redacts_password() {
    let encrypt_debug = format!("{:?}", encrypt_options(PathBuf::from("x"), false));
    let decrypt_debug = format!("{:?}", decrypt_options(Path::new("x"), false));
    assert!(!encrypt_debug.contains("correct horse"));
    assert!(!decrypt_debug.contains("correct horse"));
}

/// The push-style writer must produce byte-for-byte the same file as the
/// reader-based encryptor, however the payload is split into writes.
#[test]
fn test_encrypt_writer_matches_encrypt_streaming() {
    let salt = [3u8; 16];
    let keys = v6::derive_file_keys(b"pw", None, &salt, FAST_KDF).unwrap();

    for len in [0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 2 * CHUNK_SIZE, 70_000] {
        let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        for pad in [false, true] {
            let metadata = Metadata::new("f".to_string(), false, false, len as u64);

            let mut expected = Vec::new();
            v6::encrypt_streaming(
                &mut Cursor::new(&payload),
                &mut expected,
                salt,
                FAST_KDF,
                &metadata,
                &keys,
                pad,
            )
            .unwrap();

            let mut writer =
                EncryptWriter::new(Vec::new(), salt, FAST_KDF, &metadata, &keys, pad).unwrap();
            for piece in payload.chunks(1000) {
                writer.write_all(piece).unwrap();
            }
            let actual = writer.finish().unwrap();

            assert_eq!(actual, expected, "len {} pad {}", len, pad);
        }
    }
}

#[test]
fn test_encrypt_writer_rejects_wrong_length() {
    let salt = [4u8; 16];
    let keys = v6::derive_file_keys(b"pw", None, &salt, FAST_KDF).unwrap();
    let metadata = Metadata::new("f".to_string(), false, false, 10);

    let mut writer = EncryptWriter::new(Vec::new(), salt, FAST_KDF, &metadata, &keys, false).unwrap();
    writer.write_all(b"too short").unwrap();

    assert!(matches!(
        writer.finish(),
        Err(Error::PayloadLengthMismatch { expected: 10, actual: 9 })
    ));
}
