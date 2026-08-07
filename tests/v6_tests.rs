//! Tests for the v6 format: stream termination, key commitment, the subkey
//! schedule, honoured KDF parameters, and size padding.

use std::io::Cursor;
use timenc::crypto::{self, KdfParams, KdfProfile};
use timenc::error::Error;
use timenc::format::v6;
use timenc::format::{CHUNK_SIZE, ENC_CHUNK_SIZE};

/// Deliberately cheap parameters: these tests exercise the format, not Argon2.
fn test_kdf() -> KdfParams {
    KdfParams::new(1, crypto::MIN_MEMORY_KIB, 1)
}

fn keys_for(salt: &[u8; 16], password: &[u8]) -> v6::FileKeys {
    v6::derive_file_keys(password, None, salt, test_kdf()).expect("derivation should succeed")
}

/// Encrypts `plaintext` as a complete v6 file and returns the bytes.
fn encrypt_v6(plaintext: &[u8], password: &[u8], pad: bool) -> (Vec<u8>, v6::Header, v6::Metadata) {
    let salt = crypto::generate_salt();
    let keys = keys_for(&salt, password);
    let metadata = v6::Metadata::new("payload.bin".to_string(), false, false, plaintext.len() as u64);

    let mut output = Vec::new();
    let header = v6::encrypt_streaming(
        &mut Cursor::new(plaintext),
        &mut output,
        salt,
        test_kdf(),
        &metadata,
        &keys,
        pad,
    )
    .expect("v6 encryption should succeed");

    (output, header, metadata)
}

/// Splits a v6 file into its header, encrypted metadata, and payload chunks.
fn split_v6(file: &[u8]) -> (v6::Header, &[u8], &[u8]) {
    let (header, header_len) = v6::Header::from_bytes(file).expect("header should parse");
    let metadata_end = header_len + header.metadata_len as usize;
    (header, &file[header_len..metadata_end], &file[metadata_end..])
}

/// Decrypts the payload of a v6 file, re-reading metadata from the file itself.
fn decrypt_v6(file: &[u8], password: &[u8]) -> Result<Vec<u8>, Error> {
    let (header, encrypted_metadata, payload) = split_v6(file);
    let keys = v6::derive_file_keys(password, None, &header.salt, header.kdf)?;
    header.verify_commitment(&keys)?;
    let metadata = v6::decrypt_metadata(encrypted_metadata, &header, &keys)?;

    let mut plaintext = Vec::new();
    v6::decrypt_streaming(
        &mut Cursor::new(payload),
        &mut plaintext,
        &header,
        &metadata,
        &keys,
    )?;
    Ok(plaintext)
}

// ---------------------------------------------------------------------------
// Header and metadata
// ---------------------------------------------------------------------------

#[test]
fn test_v6_header_roundtrip() {
    let salt = crypto::generate_salt();
    let keys = keys_for(&salt, b"password");
    let metadata = v6::Metadata::new("secret.txt".to_string(), false, true, 1234);

    let header = v6::build_header(salt, test_kdf(), &metadata, &keys).expect("header");
    let bytes = header.to_bytes().expect("serialization");
    assert_eq!(bytes.len(), v6::HEADER_LEN);

    let (parsed, len) = v6::Header::from_bytes(&bytes).expect("parsing");
    assert_eq!(len, v6::HEADER_LEN);
    assert_eq!(parsed.version, v6::FORMAT_VERSION_V6);
    assert_eq!(parsed.salt, salt);
    assert_eq!(parsed.kdf, test_kdf());
    assert_eq!(parsed.metadata_len, header.metadata_len);
    assert_eq!(&parsed.commitment, keys.commitment());
}

#[test]
fn test_v6_metadata_roundtrip() {
    let metadata = v6::Metadata::new("dir name".to_string(), true, true, u64::MAX);
    let bytes = metadata.to_bytes().expect("serialization");
    assert_eq!(v6::Metadata::from_bytes(&bytes).expect("parsing"), metadata);
}

#[test]
fn test_v6_metadata_rejects_trailing_bytes() {
    let metadata = v6::Metadata::new("x".to_string(), false, false, 1);
    let mut bytes = metadata.to_bytes().expect("serialization");
    bytes.push(0);
    assert!(matches!(
        v6::Metadata::from_bytes(&bytes),
        Err(Error::InvalidFormat)
    ));
}

#[test]
fn test_v6_header_rejects_v4_version_byte() {
    let salt = crypto::generate_salt();
    let keys = keys_for(&salt, b"password");
    let metadata = v6::Metadata::new("x".to_string(), false, false, 0);
    let header = v6::build_header(salt, test_kdf(), &metadata, &keys).expect("header");

    let mut bytes = header.to_bytes().expect("serialization");
    bytes[6] = 5; // v4.5
    assert!(matches!(
        v6::Header::from_bytes(&bytes),
        Err(Error::InvalidFormat)
    ));
}

// ---------------------------------------------------------------------------
// A4: header-supplied Argon2 parameters are used, and bounded
// ---------------------------------------------------------------------------

#[test]
fn test_v6_rejects_absurd_memory_cost_in_header() {
    let salt = crypto::generate_salt();
    let keys = keys_for(&salt, b"password");
    let metadata = v6::Metadata::new("x".to_string(), false, false, 0);
    let header = v6::build_header(salt, test_kdf(), &metadata, &keys).expect("header");

    let mut bytes = header.to_bytes().expect("serialization");
    // memory_kib sits right after magic + version + salt.
    let offset = 6 + 1 + 16 + 4;
    bytes[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());

    // Without the bound this would ask Argon2 for four terabytes of memory.
    assert!(matches!(
        v6::Header::from_bytes(&bytes),
        Err(Error::InvalidKdfParameters(_))
    ));
}

#[test]
fn test_v6_rejects_absurd_metadata_length_in_header() {
    let salt = crypto::generate_salt();
    let keys = keys_for(&salt, b"password");
    let metadata = v6::Metadata::new("x".to_string(), false, false, 0);
    let header = v6::build_header(salt, test_kdf(), &metadata, &keys).expect("header");

    let mut bytes = header.to_bytes().expect("serialization");
    let offset = 6 + 1 + 16 + 4 + 4 + 4;
    bytes[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());

    assert!(matches!(
        v6::Header::from_bytes(&bytes),
        Err(Error::MetadataTooLarge { .. })
    ));
}

#[test]
fn test_kdf_parameter_bounds() {
    assert!(KdfParams::BALANCED.validate().is_ok());
    assert!(KdfParams::PARANOID.validate().is_ok());
    assert!(KdfParams::LEGACY_V3.validate().is_ok());

    assert!(KdfParams::new(0, 262_144, 4).validate().is_err());
    assert!(KdfParams::new(3, 1024, 4).validate().is_err());
    assert!(KdfParams::new(3, u32::MAX, 4).validate().is_err());
    assert!(KdfParams::new(3, 262_144, 0).validate().is_err());
}

#[test]
fn test_kdf_profiles_differ_and_are_recorded() {
    assert_eq!(KdfProfile::default(), KdfProfile::Balanced);
    assert_eq!(KdfProfile::Balanced.params(), KdfParams::BALANCED);
    assert_eq!(KdfProfile::Paranoid.params(), KdfParams::PARANOID);
    assert!(KdfProfile::Paranoid.params().memory_kib > KdfProfile::Balanced.params().memory_kib);

    // The chosen profile must survive into the header, otherwise picking
    // "paranoid" would silently do nothing (the v4 bug).
    let salt = crypto::generate_salt();
    let keys = v6::derive_file_keys(b"password", None, &salt, KdfParams::PARANOID)
        .expect("derivation should succeed");
    let metadata = v6::Metadata::new("x".to_string(), false, false, 0);
    let header = v6::build_header(salt, KdfParams::PARANOID, &metadata, &keys).expect("header");
    let bytes = header.to_bytes().expect("serialization");
    let (parsed, _) = v6::Header::from_bytes(&bytes).expect("parsing");
    assert_eq!(parsed.kdf, KdfParams::PARANOID);
}

// ---------------------------------------------------------------------------
// A3: subkey schedule
// ---------------------------------------------------------------------------

#[test]
fn test_subkeys_are_domain_separated() {
    let master = [7u8; 32];
    let a = crypto::derive_subkey(&master, b"label a").expect("subkey");
    let b = crypto::derive_subkey(&master, b"label b").expect("subkey");
    let a_again = crypto::derive_subkey(&master, b"label a").expect("subkey");

    assert_ne!(a.as_ref(), b.as_ref());
    assert_eq!(a.as_ref(), a_again.as_ref());
    assert_ne!(a.as_ref(), &master);
}

#[test]
fn test_subkey_labels_cannot_collide_by_concatenation() {
    // Length-prefixing the label is what stops "ab" + "c" from colliding with
    // "a" + "bc" once the context string is prepended.
    let master = [9u8; 32];
    let first = crypto::derive_subkey(&master, b"abc").expect("subkey");
    let second = crypto::derive_subkey(&master, b"ab").expect("subkey");
    assert_ne!(first.as_ref(), second.as_ref());
}

// ---------------------------------------------------------------------------
// A2: key commitment
// ---------------------------------------------------------------------------

#[test]
fn test_v6_commitment_rejects_wrong_password() {
    let (file, _, _) = encrypt_v6(b"committed payload", b"right password", false);

    assert!(matches!(
        decrypt_v6(&file, b"wrong password"),
        Err(Error::DecryptionFailed)
    ));
    assert!(decrypt_v6(&file, b"right password").is_ok());
}

#[test]
fn test_v6_commitment_is_checked_before_the_ciphertext() {
    // A wrong password must be rejected by the commitment alone, without any
    // trial decryption: that is what makes the file bound to exactly one key.
    let (file, header, _) = encrypt_v6(b"payload", b"right password", false);

    let wrong_keys = v6::derive_file_keys(b"wrong password", None, &header.salt, header.kdf)
        .expect("derivation should succeed");
    assert!(matches!(
        header.verify_commitment(&wrong_keys),
        Err(Error::DecryptionFailed)
    ));

    let right_keys = v6::derive_file_keys(b"right password", None, &header.salt, header.kdf)
        .expect("derivation should succeed");
    assert!(header.verify_commitment(&right_keys).is_ok());
    assert_eq!(file[6], v6::FORMAT_VERSION_V6);
}

#[test]
fn test_v6_tampered_commitment_is_detected() {
    let (mut file, _, _) = encrypt_v6(b"payload", b"password", false);

    // Flip a bit in the commitment tag at the end of the header.
    let commitment_start = v6::HEADER_LEN - v6::COMMITMENT_SIZE;
    file[commitment_start] ^= 0x01;

    assert!(matches!(
        decrypt_v6(&file, b"password"),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn test_v6_keyfile_changes_the_key() {
    let salt = crypto::generate_salt();
    let without = v6::derive_file_keys(b"password", None, &salt, test_kdf()).expect("keys");
    let with = v6::derive_file_keys(b"password", Some(b"keyfile"), &salt, test_kdf()).expect("keys");
    assert_ne!(without.commitment(), with.commitment());
}

// ---------------------------------------------------------------------------
// Roundtrips
// ---------------------------------------------------------------------------

#[test]
fn test_v6_streaming_roundtrip() {
    let plaintext: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let (file, _, _) = encrypt_v6(&plaintext, b"password", false);
    assert_eq!(decrypt_v6(&file, b"password").expect("decryption"), plaintext);
}

#[test]
fn test_v6_roundtrip_at_exact_chunk_boundaries() {
    // A payload that is an exact multiple of CHUNK_SIZE ends with an empty
    // final chunk, which is tag-only on disk. Easy case to get wrong.
    for chunks in [0usize, 1, 2] {
        let plaintext = vec![0xABu8; chunks * CHUNK_SIZE];
        let (file, _, _) = encrypt_v6(&plaintext, b"password", false);
        assert_eq!(
            decrypt_v6(&file, b"password").expect("decryption"),
            plaintext,
            "roundtrip failed for {chunks} full chunks"
        );
    }
}

#[test]
fn test_v6_roundtrip_with_fragmented_reads() {
    /// A reader that never returns more than a few bytes at a time.
    struct Trickle<'a> {
        data: &'a [u8],
        position: usize,
    }

    impl std::io::Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.position >= self.data.len() {
                return Ok(0);
            }
            let take = buf.len().min(7).min(self.data.len() - self.position);
            buf[..take].copy_from_slice(&self.data[self.position..self.position + take]);
            self.position += take;
            Ok(take)
        }
    }

    let plaintext: Vec<u8> = (0..100_000u32).map(|i| (i % 97) as u8).collect();
    let salt = crypto::generate_salt();
    let keys = keys_for(&salt, b"password");
    let metadata =
        v6::Metadata::new("trickle.bin".to_string(), false, false, plaintext.len() as u64);

    let mut file = Vec::new();
    let header = v6::encrypt_streaming(
        &mut Trickle {
            data: &plaintext,
            position: 0,
        },
        &mut file,
        salt,
        test_kdf(),
        &metadata,
        &keys,
        false,
    )
    .expect("encryption should succeed");

    let payload = &file[v6::HEADER_LEN + header.metadata_len as usize..];
    let mut decrypted = Vec::new();
    v6::decrypt_streaming(
        &mut Trickle {
            data: payload,
            position: 0,
        },
        &mut decrypted,
        &header,
        &metadata,
        &keys,
    )
    .expect("decryption should succeed");

    assert_eq!(decrypted, plaintext);
}

// ---------------------------------------------------------------------------
// A1: stream termination
// ---------------------------------------------------------------------------

#[test]
fn test_v4_silently_accepts_truncation_at_a_chunk_boundary() {
    // Documents the weakness v6 fixes. v4 decrypts until end-of-file, so
    // dropping whole chunks from the end leaves every remaining tag valid and
    // yields a shorter "successfully decrypted" plaintext.
    let plaintext = vec![0x5Au8; 3 * CHUNK_SIZE];
    let salt = crypto::generate_salt();
    let metadata = timenc::format::v4::Metadata::new("victim.bin".to_string(), false, false);
    let metadata_len = (metadata.to_bytes().expect("metadata").len() + crypto::TAG_SIZE) as u32;
    let header = timenc::format::v4::Header::new(
        metadata_len,
        salt,
        crypto::generate_nonce(),
        crypto::generate_nonce(),
    );

    let mut file = Vec::new();
    timenc::format::v4::encrypt_streaming(
        &mut Cursor::new(&plaintext),
        &mut file,
        &header,
        &metadata,
        b"password",
        None,
    )
    .expect("v4 encryption should succeed");

    // v4 writes no terminator, so a 3-chunk payload is exactly 3 chunks.
    let payload_start = header.to_bytes().expect("header").len() + metadata_len as usize;
    assert_eq!(file.len() - payload_start, 3 * ENC_CHUNK_SIZE);

    // Drop the last chunk, cutting exactly on a chunk boundary.
    let truncated_payload = &file[payload_start..file.len() - ENC_CHUNK_SIZE];

    let mut decrypted = Vec::new();
    let result = timenc::format::v4::decrypt_streaming(
        &mut Cursor::new(truncated_payload),
        &mut decrypted,
        &header,
        b"password",
        None,
    );

    assert!(
        result.is_ok(),
        "this test documents that v4 accepts the truncation"
    );
    assert_eq!(
        decrypted.len(),
        2 * CHUNK_SIZE,
        "v4 returned a silently shortened plaintext"
    );
}

#[test]
fn test_v6_rejects_truncation_at_a_chunk_boundary() {
    // 3 full chunks plus a partial final chunk.
    let plaintext = vec![0x5Au8; 3 * CHUNK_SIZE + 1000];
    let (file, header, _) = encrypt_v6(&plaintext, b"password", false);

    let payload_start = v6::HEADER_LEN + header.metadata_len as usize;
    let final_chunk_len = 1000 + crypto::TAG_SIZE;
    assert_eq!(
        file.len() - payload_start,
        3 * ENC_CHUNK_SIZE + final_chunk_len
    );

    // The same attack as the v4 test above: drop the final chunk, leaving a cut
    // exactly on a chunk boundary with every remaining tag still valid.
    let truncated = &file[..file.len() - final_chunk_len];

    assert!(
        matches!(decrypt_v6(truncated, b"password"), Err(Error::TruncatedFile)),
        "truncation at a chunk boundary must be rejected"
    );
}

#[test]
fn test_v6_rejects_truncation_of_the_terminator_chunk() {
    // A payload that is an exact multiple of CHUNK_SIZE ends in a tag-only
    // terminator chunk. Removing just that terminator must also be caught.
    let plaintext = vec![0x5Au8; 2 * CHUNK_SIZE];
    let (file, header, _) = encrypt_v6(&plaintext, b"password", false);

    let payload_start = v6::HEADER_LEN + header.metadata_len as usize;
    assert_eq!(
        file.len() - payload_start,
        2 * ENC_CHUNK_SIZE + crypto::TAG_SIZE
    );

    let truncated = &file[..file.len() - crypto::TAG_SIZE];
    assert!(matches!(
        decrypt_v6(truncated, b"password"),
        Err(Error::TruncatedFile)
    ));
}

#[test]
fn test_v6_rejects_dropping_every_data_chunk() {
    let plaintext = vec![1u8; 10_000];
    let (file, header, _) = encrypt_v6(&plaintext, b"password", false);
    let header_and_metadata = &file[..v6::HEADER_LEN + header.metadata_len as usize];

    assert!(matches!(
        decrypt_v6(header_and_metadata, b"password"),
        Err(Error::TruncatedFile)
    ));
}

#[test]
fn test_v6_rejects_a_truncated_final_chunk() {
    let plaintext = vec![0x33u8; 100_000];
    let (file, _, _) = encrypt_v6(&plaintext, b"password", false);
    let truncated = &file[..file.len() - 5];

    assert!(matches!(
        decrypt_v6(truncated, b"password"),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn test_v6_rejects_swapped_chunks() {
    let plaintext: Vec<u8> = (0..3 * CHUNK_SIZE).map(|i| (i % 256) as u8).collect();
    let (file, header, _) = encrypt_v6(&plaintext, b"password", false);

    let payload_start = v6::HEADER_LEN + header.metadata_len as usize;
    let mut tampered = file.clone();
    let (first, second) = (payload_start, payload_start + ENC_CHUNK_SIZE);
    for i in 0..ENC_CHUNK_SIZE {
        tampered.swap(first + i, second + i);
    }

    assert!(matches!(
        decrypt_v6(&tampered, b"password"),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn test_v6_rejects_duplicated_chunk() {
    let plaintext = vec![0x77u8; 2 * CHUNK_SIZE + 100];
    let (file, header, _) = encrypt_v6(&plaintext, b"password", false);

    let payload_start = v6::HEADER_LEN + header.metadata_len as usize;
    let first_chunk = file[payload_start..payload_start + ENC_CHUNK_SIZE].to_vec();

    // Replace the second chunk with a copy of the first.
    let mut tampered = file.clone();
    tampered[payload_start + ENC_CHUNK_SIZE..payload_start + 2 * ENC_CHUNK_SIZE]
        .copy_from_slice(&first_chunk);

    assert!(matches!(
        decrypt_v6(&tampered, b"password"),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn test_v6_rejects_appended_data() {
    let plaintext = vec![0x11u8; 1000];
    let (mut file, _, _) = encrypt_v6(&plaintext, b"password", false);
    file.extend_from_slice(&[0u8; 64]);

    assert!(
        decrypt_v6(&file, b"password").is_err(),
        "data appended after the final chunk must be rejected"
    );
}

#[test]
fn test_v6_rejects_tampered_payload_byte() {
    let plaintext = vec![0x22u8; 5000];
    let (mut file, _, _) = encrypt_v6(&plaintext, b"password", false);
    let last = file.len() - 1;
    file[last] ^= 0x01;

    assert!(matches!(
        decrypt_v6(&file, b"password"),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn test_v6_header_is_bound_to_the_payload() {
    // The whole header is AAD for every chunk, so editing any header field
    // that survives parsing still breaks authentication.
    let plaintext = vec![0x44u8; 5000];
    let (mut file, _, _) = encrypt_v6(&plaintext, b"password", false);
    file[7] ^= 0x01; // first salt byte

    assert!(
        decrypt_v6(&file, b"password").is_err(),
        "a modified salt must not yield a successful decryption"
    );
}

// ---------------------------------------------------------------------------
// A6: size padding
// ---------------------------------------------------------------------------

#[test]
fn test_padme_matches_reference_values() {
    // Small inputs are left alone; there is nothing to hide.
    assert_eq!(v6::padme(0), 0);
    assert_eq!(v6::padme(1), 1);
    assert_eq!(v6::padme(2), 2);

    // The worked example from the Padmé paper.
    assert_eq!(v6::padme(1000), 1024);

    // Powers of two are already fixed points.
    for exponent in 3..40 {
        let value = 1u64 << exponent;
        assert_eq!(v6::padme(value), value, "2^{exponent} should not be padded");
    }
}

#[test]
fn test_padme_overhead_is_bounded() {
    for len in [5u64, 100, 1_001, 65_537, 1_000_000, 1 << 32] {
        let padded = v6::padme(len);
        assert!(padded >= len);
        let overhead = (padded - len) as f64 / len as f64;
        assert!(
            overhead <= 0.12,
            "padding {len} -> {padded} is {:.1}% overhead",
            overhead * 100.0
        );
    }
}

#[test]
fn test_v6_padding_hides_the_exact_size() {
    // Two different plaintext sizes that land in the same Padmé bucket must
    // produce ciphertexts of identical length.
    let a = vec![0u8; 1000];
    let b = vec![0u8; 1010];
    assert_eq!(v6::padme(1000), v6::padme(1010));

    let (file_a, _, _) = encrypt_v6(&a, b"password", true);
    let (file_b, _, _) = encrypt_v6(&b, b"password", true);
    assert_eq!(file_a.len(), file_b.len());

    // Without padding the sizes differ, which is the leak being closed.
    let (plain_a, _, _) = encrypt_v6(&a, b"password", false);
    let (plain_b, _, _) = encrypt_v6(&b, b"password", false);
    assert_ne!(plain_a.len(), plain_b.len());
}

#[test]
fn test_v6_padding_roundtrips_exactly() {
    for len in [0usize, 1, 999, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 150_000] {
        let plaintext: Vec<u8> = (0..len).map(|i| (i % 253) as u8).collect();
        let (file, _, _) = encrypt_v6(&plaintext, b"password", true);
        let decrypted = decrypt_v6(&file, b"password").expect("decryption should succeed");
        assert_eq!(decrypted, plaintext, "padded roundtrip failed for len {len}");
    }
}

#[test]
fn test_v6_padding_survives_truncation_check() {
    // Padding must not weaken the termination guarantee.
    let plaintext = vec![0x66u8; 3 * CHUNK_SIZE];
    let (file, _, _) = encrypt_v6(&plaintext, b"password", true);
    let truncated = &file[..file.len() - ENC_CHUNK_SIZE];
    assert!(decrypt_v6(truncated, b"password").is_err());
}

// ---------------------------------------------------------------------------
// Payload length bookkeeping
// ---------------------------------------------------------------------------

#[test]
fn test_v6_encrypt_rejects_wrong_declared_payload_length() {
    let salt = crypto::generate_salt();
    let keys = keys_for(&salt, b"password");
    // Claims 10 bytes but the reader yields 5.
    let metadata = v6::Metadata::new("liar.bin".to_string(), false, false, 10);

    let mut output = Vec::new();
    let result = v6::encrypt_streaming(
        &mut Cursor::new(b"12345"),
        &mut output,
        salt,
        test_kdf(),
        &metadata,
        &keys,
        false,
    );

    assert!(matches!(
        result,
        Err(Error::PayloadLengthMismatch {
            expected: 10,
            actual: 5
        })
    ));
}

#[test]
fn test_v6_decrypt_rejects_payload_shorter_than_metadata_claims() {
    let plaintext = vec![0x88u8; 500];
    let salt = crypto::generate_salt();
    let keys = keys_for(&salt, b"password");
    let metadata = v6::Metadata::new("x.bin".to_string(), false, false, 500);

    let mut file = Vec::new();
    let header = v6::encrypt_streaming(
        &mut Cursor::new(&plaintext),
        &mut file,
        salt,
        test_kdf(),
        &metadata,
        &keys,
        false,
    )
    .expect("encryption");

    // Decrypt the same stream while claiming a longer payload.
    let lying_metadata = v6::Metadata::new("x.bin".to_string(), false, false, 900);
    let payload = &file[v6::HEADER_LEN + header.metadata_len as usize..];
    let mut out = Vec::new();
    let result = v6::decrypt_streaming(
        &mut Cursor::new(payload),
        &mut out,
        &header,
        &lying_metadata,
        &keys,
    );

    assert!(matches!(
        result,
        Err(Error::PayloadLengthMismatch {
            expected: 900,
            actual: 500
        })
    ));
}
