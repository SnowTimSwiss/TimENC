//! Wraps arbitrary bytes as the *payload of a directory archive* inside a valid
//! v6 file, then runs the real `decrypt` on it.
//!
//! This models a malicious sender who knows the password: the archive is
//! authentic, so everything depends on the extraction code. Nothing may panic
//! and nothing may appear outside the output directory.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;
use std::fs;
use std::io::Cursor;
use timenc::crypto::{self, KdfParams};
use timenc::format::v6;
use timenc::{decrypt, DecryptOptions};

const PASSWORD: &str = "fuzz password";

fuzz_target!(|tar_bytes: &[u8]| {
    let kdf = KdfParams::new(1, crypto::MIN_MEMORY_KIB, 1);
    let salt = [3u8; 16];
    let keys = v6::derive_file_keys(PASSWORD.as_bytes(), None, &salt, kdf).unwrap();
    let metadata = v6::Metadata::new("d".into(), true, false, tar_bytes.len() as u64);

    let mut file = Vec::new();
    v6::encrypt_streaming(&mut Cursor::new(tar_bytes), &mut file, salt, kdf, &metadata, &keys, false)
        .unwrap();

    let sandbox = tempfile::tempdir().unwrap();
    let input = sandbox.path().join("in.timenc");
    let out = sandbox.path().join("out");
    fs::write(&input, &file).unwrap();

    let _ = decrypt(
        &input,
        DecryptOptions {
            password: PASSWORD.to_string(),
            keyfile_path: None,
            output_dir: out,
            delete_source: false,
        },
    );

    let names: BTreeSet<String> = fs::read_dir(sandbox.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    let expected: BTreeSet<String> = ["in.timenc", "out"].iter().map(|s| s.to_string()).collect();
    assert!(
        names.is_subset(&expected),
        "extraction wrote outside the output directory: {names:?}"
    );
});
