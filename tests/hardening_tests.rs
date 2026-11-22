//! Regression tests from the security audit: hostile archives, keyfile
//! handling, and robustness against corrupted files.
//!
//! Files are built through the format API with the cheapest legal Argon2
//! parameters, so the tests exercise the file-level code paths without paying
//! for a full key derivation each time.

use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use tempfile::tempdir;
use timenc::crypto::{self, KdfParams};
use timenc::format::v6;
use timenc::{decrypt, generate_keyfile, DecryptOptions, Error};

const PASSWORD: &str = "correct horse battery staple";

fn cheap_kdf() -> KdfParams {
    KdfParams::new(1, crypto::MIN_MEMORY_KIB, 1)
}

/// Builds a complete v6 file around `payload`.
fn build_v6(payload: &[u8], name: &str, is_dir: bool) -> Vec<u8> {
    let salt = crypto::generate_salt();
    let keys = v6::derive_file_keys(PASSWORD.as_bytes(), None, &salt, cheap_kdf()).unwrap();
    let metadata = v6::Metadata::new(name.to_string(), is_dir, false, payload.len() as u64);
    let mut out = Vec::new();
    v6::encrypt_streaming(
        &mut Cursor::new(payload),
        &mut out,
        salt,
        cheap_kdf(),
        &metadata,
        &keys,
        false,
    )
    .unwrap();
    out
}

fn options(output_dir: &Path) -> DecryptOptions {
    DecryptOptions {
        password: PASSWORD.to_string(),
        keyfile_path: None,
        output_dir: output_dir.to_path_buf(),
        delete_source: false,
    }
}

fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

// ---------------------------------------------------------------------------
// Hostile archives. These need the right password, i.e. they model a malicious
// sender who shares a `.timenc` file together with its password.
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn symlink_entry(builder: &mut tar::Builder<Vec<u8>>, path: &str, target: &Path) {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_mode(0o777);
    header.set_path(path).unwrap();
    header.set_link_name(target).unwrap();
    header.set_cksum();
    builder.append(&header, std::io::empty()).unwrap();
}

fn file_entry(builder: &mut tar::Builder<Vec<u8>>, path: &str, contents: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(contents.len() as u64);
    header.set_mode(0o644);
    header.set_path(path).unwrap();
    header.set_cksum();
    builder.append(&header, contents).unwrap();
}

#[cfg(unix)]
#[test]
fn archive_cannot_write_through_a_symlink_it_planted() {
    let work = tempdir().unwrap();
    let outside = work.path().join("outside");
    fs::create_dir(&outside).unwrap();

    // evil -> <outside>, then evil/pwned.txt: if the extractor follows the
    // link it writes into `outside`.
    let mut builder = tar::Builder::new(Vec::new());
    symlink_entry(&mut builder, "dir/evil", &outside);
    file_entry(&mut builder, "dir/evil/pwned.txt", b"owned");
    let tar_bytes = builder.into_inner().unwrap();

    let file = write_file(work.path(), "evil.timenc", &build_v6(&tar_bytes, "dir", true));
    let out = work.path().join("out");

    let _ = decrypt(&file, options(&out));

    assert!(
        !outside.join("pwned.txt").exists(),
        "extraction followed a planted symlink out of the output directory"
    );
}

#[cfg(unix)]
#[test]
fn archive_cannot_overwrite_an_outside_file_through_a_hardlink() {
    let work = tempdir().unwrap();
    let victim = work.path().join("victim.txt");
    fs::write(&victim, b"precious").unwrap();

    // dir/loot is a hard link to the victim file, then a regular entry with
    // the same name tries to write through it.
    let mut builder = tar::Builder::new(Vec::new());
    let mut link = tar::Header::new_gnu();
    link.set_entry_type(tar::EntryType::Link);
    link.set_size(0);
    link.set_mode(0o644);
    link.set_path("dir/loot").unwrap();
    link.set_link_name(&victim).unwrap();
    link.set_cksum();
    builder.append(&link, std::io::empty()).unwrap();
    file_entry(&mut builder, "dir/loot", b"overwritten");
    let tar_bytes = builder.into_inner().unwrap();

    let file = write_file(work.path(), "evil.timenc", &build_v6(&tar_bytes, "dir", true));
    let out = work.path().join("out");

    let _ = decrypt(&file, options(&out));

    assert_eq!(
        fs::read(&victim).unwrap(),
        b"precious",
        "a hard link in the archive let it overwrite a file outside the output directory"
    );
    assert!(
        !out.join("dir/loot").exists() || fs::read(out.join("dir/loot")).unwrap() != b"precious",
        "a hard link in the archive exposed a file from outside the output directory"
    );
}

#[test]
fn archive_with_special_files_is_rejected() {
    let work = tempdir().unwrap();

    let mut builder = tar::Builder::new(Vec::new());
    let mut fifo = tar::Header::new_gnu();
    fifo.set_entry_type(tar::EntryType::Fifo);
    fifo.set_size(0);
    fifo.set_mode(0o644);
    fifo.set_path("dir/pipe").unwrap();
    fifo.set_cksum();
    builder.append(&fifo, std::io::empty()).unwrap();
    let tar_bytes = builder.into_inner().unwrap();

    let file = write_file(work.path(), "evil.timenc", &build_v6(&tar_bytes, "dir", true));
    let out = work.path().join("out");

    let result = decrypt(&file, options(&out));
    assert!(result.is_err(), "device/fifo entries must not be extracted");
    assert!(!out.join("dir/pipe").exists());
}

#[test]
fn extraction_failure_leaves_no_plaintext_temp_file_behind() {
    let work = tempdir().unwrap();

    let mut builder = tar::Builder::new(Vec::new());
    file_entry(&mut builder, "dir/ok.txt", b"secret contents");
    let mut tar_bytes = builder.into_inner().unwrap();
    // Corrupt the archive so extraction fails after decryption succeeded.
    tar_bytes[0] ^= 0xFF;

    let file = write_file(work.path(), "bad.timenc", &build_v6(&tar_bytes, "dir", true));
    let out = work.path().join("out");

    assert!(decrypt(&file, options(&out)).is_err());

    let leftovers: Vec<_> = fs::read_dir(&out)
        .map(|entries| entries.filter_map(|e| e.ok()).collect())
        .unwrap_or_default();
    assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
}

// ---------------------------------------------------------------------------
// Keyfiles
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn generated_keyfile_is_private_to_the_owner() {
    use std::os::unix::fs::PermissionsExt;

    let work = tempdir().unwrap();
    let path = work.path().join("secret.key");
    generate_keyfile(&path).unwrap();

    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "keyfile must not be readable by other users");
}

#[cfg(unix)]
#[test]
fn generate_keyfile_does_not_follow_a_symlink() {
    let work = tempdir().unwrap();
    let target = work.path().join("target.txt");
    fs::write(&target, b"keep me").unwrap();
    let link = work.path().join("link.key");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    assert!(generate_keyfile(&link).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"keep me");
}

#[test]
fn empty_keyfile_is_refused() {
    let work = tempdir().unwrap();
    let keyfile = write_file(work.path(), "empty.key", b"");
    let input = write_file(work.path(), "data.txt", b"hello");

    let mut opts = timenc::EncryptOptions::new(PASSWORD.to_string(), work.path().join("out.timenc"));
    opts.keyfile_path = Some(keyfile);
    let err = timenc::encrypt(&input, opts).unwrap_err();
    assert!(matches!(err, Error::InvalidKeyfile(_)), "got {err:?}");
}

#[test]
fn oversized_keyfile_is_refused_without_reading_it_all() {
    let work = tempdir().unwrap();
    let keyfile = work.path().join("huge.key");
    // Sparse file: costs no disk, but a naive fs::read would allocate it all.
    let file = fs::File::create(&keyfile).unwrap();
    file.set_len(timenc::operations::MAX_KEYFILE_BYTES + 1).unwrap();
    let input = write_file(work.path(), "data.txt", b"hello");

    let mut opts = timenc::EncryptOptions::new(PASSWORD.to_string(), work.path().join("out.timenc"));
    opts.keyfile_path = Some(keyfile);
    let err = timenc::encrypt(&input, opts).unwrap_err();
    assert!(matches!(err, Error::InvalidKeyfile(_)), "got {err:?}");
}

// ---------------------------------------------------------------------------
// Corruption robustness
// ---------------------------------------------------------------------------

/// Flipping any single byte of a v6 file must be detected. The release build
/// aborts on panic, so "returns an error" is the only acceptable outcome.
#[test]
fn every_single_byte_flip_in_a_v6_file_is_rejected() {
    let work = tempdir().unwrap();
    let original = build_v6(b"some payload that spans a few bytes", "f.txt", false);

    for i in 0..original.len() {
        let mut corrupted = original.clone();
        corrupted[i] ^= 0x01;
        let file = write_file(work.path(), "c.timenc", &corrupted);
        let out = work.path().join(format!("out-{i}"));
        let result = decrypt(&file, options(&out));
        assert!(result.is_err(), "flip at byte {i} was accepted");
    }
}

#[test]
fn every_truncation_of_a_v6_file_is_rejected() {
    let work = tempdir().unwrap();
    let original = build_v6(&vec![7u8; 3 * crypto::KEY_LEN * 2048], "f.bin", false);

    // Every length up to the end of the first chunk, then every chunk edge.
    let mut cut_points: Vec<usize> = (0..400).collect();
    cut_points.extend((400..original.len()).step_by(v6::HEADER_LEN + 997));
    for len in cut_points {
        let file = write_file(work.path(), "t.timenc", &original[..len]);
        let out = work.path().join(format!("out-{len}"));
        assert!(decrypt(&file, options(&out)).is_err(), "truncation to {len} bytes accepted");
    }
}

#[test]
fn appending_bytes_to_a_v6_file_is_rejected() {
    let work = tempdir().unwrap();
    let mut file_bytes = build_v6(b"abc", "f.txt", false);
    file_bytes.extend_from_slice(&[0u8; 5]);
    let file = write_file(work.path(), "a.timenc", &file_bytes);
    assert!(decrypt(&file, options(&work.path().join("out"))).is_err());
}

/// A failed decryption must not leave the plaintext prefix behind as a
/// stray file in the output directory.
#[test]
fn failed_decryption_leaves_no_files_in_the_output_directory() {
    let work = tempdir().unwrap();
    let mut bytes = build_v6(&vec![1u8; 200_000], "big.bin", false);
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF; // break the final chunk's tag, after earlier chunks were written

    let file = write_file(work.path(), "big.timenc", &bytes);
    let out = work.path().join("out");
    assert!(decrypt(&file, options(&out)).is_err());

    let leftovers: Vec<_> = fs::read_dir(&out)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
}

// ---------------------------------------------------------------------------
// Legacy formats
// ---------------------------------------------------------------------------

#[test]
fn legacy_format_versions_are_reported_for_a_warning() {
    let work = tempdir().unwrap();

    let v6_file = write_file(work.path(), "new.timenc", &build_v6(b"x", "f", false));
    assert_eq!(timenc::operations::file_format_version(&v6_file).unwrap(), 6);
    assert!(!timenc::operations::is_legacy_version(6));
    for legacy in [3u8, 4, 5] {
        assert!(timenc::operations::is_legacy_version(legacy));
    }

    let junk = write_file(work.path(), "junk.timenc", b"not a timenc file at all");
    assert!(timenc::operations::file_format_version(&junk).is_err());

    // Prevent an unused-import warning on platforms where no test above needs it.
    let _ = Write::flush(&mut std::io::sink());
}

// ---------------------------------------------------------------------------
// Process hardening
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn core_dumps_can_be_disabled() {
    timenc::hardening::disable_core_dumps();

    let mut limit = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) };
    assert_eq!(rc, 0);
    assert_eq!(limit.rlim_cur, 0);
    assert_eq!(limit.rlim_max, 0);
}

#[cfg(target_os = "linux")]
#[test]
fn memory_inspection_can_be_disabled() {
    timenc::hardening::disable_memory_inspection();
    let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
    assert_eq!(dumpable, 0);
}

// ---------------------------------------------------------------------------
// Output file names
// ---------------------------------------------------------------------------

#[test]
fn output_names_must_be_exactly_one_plain_component() {
    use timenc::format::sanitize_output_name;

    for good in ["report.pdf", "a b", ".hidden", "...", "ünï.txt"] {
        assert_eq!(sanitize_output_name(good).unwrap(), good);
    }
    // `Path` normalises several of these to a single component, so the check
    // has to compare against the whole string.
    for bad in ["", ".", "..", "a/", "a/.", "a//", "/a", "a/b", "../a", "a/..", "a\0b"] {
        assert!(sanitize_output_name(bad).is_err(), "{bad:?} was accepted");
    }
}

// ---------------------------------------------------------------------------
// Compression determinism
// ---------------------------------------------------------------------------

/// Compressed payloads are measured in one pass and encrypted in a second one;
/// the two must agree on the compressed length or encryption fails with
/// `SourceChanged`. Multithreaded zstd is deterministic, and this keeps it so.
#[test]
fn compressed_encryption_never_reports_a_changed_source() {
    let work = tempdir().unwrap();

    // Compressible, and large enough to span several multithreaded zstd jobs.
    let mut text = String::new();
    let mut state = 7u64;
    while text.len() < 24 * 1024 * 1024 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        text.push_str(&format!("line {} of some fairly repetitive text\n", (state >> 40) % 5000));
    }
    let input = write_file(work.path(), "text.txt", text.as_bytes());

    for round in 0..4 {
        let output = work.path().join(format!("out-{round}.timenc"));
        let mut opts = timenc::EncryptOptions::new(PASSWORD.to_string(), output.clone());
        opts.compress = true;
        opts.kdf_profile = timenc::KdfProfile::Balanced;
        timenc::encrypt(&input, opts).unwrap_or_else(|e| panic!("round {round}: {e}"));

        let restored = work.path().join(format!("restored-{round}"));
        decrypt(&output, options(&restored)).unwrap();
        assert!(fs::read(restored.join("text.txt")).unwrap() == text.as_bytes());
    }
}
