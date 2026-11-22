//! The v6 stream encryptor and decryptor work on batches of chunks across
//! several threads. These tests check that this changes nothing on disk: the
//! output must be byte-for-byte what a plain one-chunk-at-a-time implementation
//! of the format produces, for every thread count and at every batch edge.
//!
//! Everything here shares the `TIMENC_THREADS` environment variable, so the
//! checks run inside single test functions instead of separate parallel tests.

use std::io::Cursor;
use timenc::crypto::{self, KdfParams, KEY_LEN, TAG_SIZE};
use timenc::error::Error;
use timenc::format::v6;
use timenc::format::{CHUNK_SIZE, ENC_CHUNK_SIZE};

const PASSWORD: &[u8] = b"parallel test password";
const BATCH_CHUNKS: usize = 64; // mirrors the private constant in the library
const BATCH_BYTES: usize = BATCH_CHUNKS * CHUNK_SIZE;

fn kdf() -> KdfParams {
    KdfParams::new(1, crypto::MIN_MEMORY_KIB, 1)
}

/// Deterministic, non-repeating-looking test data.
fn payload(len: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// The data key, derived from the format description alone rather than through
/// the library's private `FileKeys`.
fn data_key(salt: &[u8; 16]) -> [u8; KEY_LEN] {
    let mut secret = b"TIMENC-v6|password|".to_vec();
    secret.extend_from_slice(PASSWORD);
    let master = crypto::derive_key_from_secret(&secret, salt, kdf()).unwrap();
    *crypto::derive_subkey(&master, b"TIMENC-v6 data key").unwrap()
}

/// A plain, sequential implementation of the v6 payload layout.
fn reference_file(plaintext: &[u8], pad: bool, salt: [u8; 16]) -> Vec<u8> {
    let keys = v6::derive_file_keys(PASSWORD, None, &salt, kdf()).unwrap();
    let metadata = v6::Metadata::new("ref.bin".into(), false, false, plaintext.len() as u64);
    let header = v6::build_header(salt, kdf(), &metadata, &keys).unwrap();
    let header_bytes = header.to_bytes().unwrap();

    let mut file = header_bytes.clone();
    file.extend(v6::encrypt_metadata(&metadata, &header, &keys).unwrap());

    let mut body = plaintext.to_vec();
    if pad {
        body.resize(v6::padme(plaintext.len() as u64) as usize, 0);
    }

    let key = data_key(&salt);
    let mut pieces: Vec<&[u8]> = body.chunks(CHUNK_SIZE).collect();
    if body.len() % CHUNK_SIZE == 0 {
        pieces.push(&[]); // an empty final chunk follows a whole number of chunks
    }
    let last = pieces.len() - 1;
    for (index, piece) in pieces.iter().enumerate() {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&(index as u64).to_be_bytes());
        let mut aad = b"TIMENC-v6-data".to_vec();
        aad.extend_from_slice(&header_bytes);
        aad.extend_from_slice(&(index as u64).to_be_bytes());
        aad.push(u8::from(index == last));
        file.extend(crypto::encrypt_chunk(&key, &nonce, piece, &aad).unwrap());
    }
    file
}

fn encrypt(plaintext: &[u8], pad: bool, salt: [u8; 16]) -> Vec<u8> {
    let keys = v6::derive_file_keys(PASSWORD, None, &salt, kdf()).unwrap();
    let metadata = v6::Metadata::new("ref.bin".into(), false, false, plaintext.len() as u64);
    let mut out = Vec::new();
    v6::encrypt_streaming(&mut Cursor::new(plaintext), &mut out, salt, kdf(), &metadata, &keys, pad)
        .unwrap();
    out
}

fn decrypt(file: &[u8]) -> (Vec<u8>, Result<(), Error>) {
    let (header, header_len) = v6::Header::from_bytes(file).unwrap();
    let keys = v6::derive_file_keys(PASSWORD, None, &header.salt, header.kdf).unwrap();
    header.verify_commitment(&keys).unwrap();
    let metadata_end = header_len + header.metadata_len as usize;
    let metadata = v6::decrypt_metadata(&file[header_len..metadata_end], &header, &keys).unwrap();

    let mut out = Vec::new();
    let result = v6::decrypt_streaming(
        &mut Cursor::new(&file[metadata_end..]),
        &mut out,
        &header,
        &metadata,
        &keys,
    );
    (out, result)
}

/// Sizes that sit on, just before and just after every kind of edge.
fn edge_sizes() -> Vec<usize> {
    let mut sizes = vec![0, 1, 15, 16, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1];
    sizes.push(2 * CHUNK_SIZE);
    sizes.push((BATCH_CHUNKS - 1) * CHUNK_SIZE);
    for delta in [-1i64, 0, 1] {
        sizes.push((BATCH_BYTES as i64 + delta) as usize);
        sizes.push((2 * BATCH_BYTES as i64 + delta) as usize);
    }
    sizes.push(2 * BATCH_BYTES + CHUNK_SIZE + 7);
    sizes.push(3 * BATCH_BYTES + 12_345);
    sizes
}

#[test]
fn output_is_identical_to_a_sequential_implementation_at_every_edge_and_thread_count() {
    let salt = [0x42u8; 16];
    for size in edge_sizes() {
        let data = payload(size);
        // Padding changes the stream length, not the batching logic, so a
        // padded run for the small and medium sizes is enough.
        let pads: &[bool] = if size <= 2 * BATCH_BYTES { &[false, true] } else { &[false] };
        for &pad in pads {
            let expected = reference_file(&data, pad, salt);
            for threads in ["1", "3", "8"] {
                std::env::set_var("TIMENC_THREADS", threads);
                let actual = encrypt(&data, pad, salt);
                assert!(
                    actual == expected,
                    "ciphertext differs from the reference (threads={threads}, size={size}, pad={pad})"
                );

                let (plain, result) = decrypt(&actual);
                result.unwrap_or_else(|e| panic!("decrypt failed (threads={threads}, size={size}): {e}"));
                assert!(plain == data, "round trip differs (threads={threads}, size={size}, pad={pad})");
            }
        }
    }
    std::env::remove_var("TIMENC_THREADS");
}

/// Offset of chunk `n` within the payload part of a file.
fn payload_start(file: &[u8]) -> usize {
    let (header, header_len) = v6::Header::from_bytes(file).unwrap();
    header_len + header.metadata_len as usize
}

#[test]
fn tampering_is_caught_across_batch_boundaries_and_output_stops_at_the_failure() {
    let salt = [7u8; 16];
    let data = payload(2 * BATCH_BYTES + 5 * CHUNK_SIZE + 99);
    let file = encrypt(&data, false, salt);
    let start = payload_start(&file);

    for threads in ["1", "4"] {
        std::env::set_var("TIMENC_THREADS", threads);

        // Corrupt one byte in chunk k: the chunks before it are still
        // delivered, nothing at or after it is.
        for k in [0usize, 1, BATCH_CHUNKS - 1, BATCH_CHUNKS, BATCH_CHUNKS + 1, 2 * BATCH_CHUNKS - 1, 2 * BATCH_CHUNKS, 2 * BATCH_CHUNKS + 5] {
            let mut bad = file.clone();
            bad[start + k * ENC_CHUNK_SIZE + 3] ^= 0x10;
            let (out, result) = decrypt(&bad);
            assert!(matches!(result, Err(Error::DecryptionFailed)), "k={k} threads={threads}: {result:?}");
            assert_eq!(out.len(), k * CHUNK_SIZE, "k={k} threads={threads}");
            assert!(out == data[..k * CHUNK_SIZE]);
        }

        // Cut on a chunk boundary around the batch edges.
        for k in [1usize, BATCH_CHUNKS - 1, BATCH_CHUNKS, BATCH_CHUNKS + 1, 2 * BATCH_CHUNKS] {
            let cut = &file[..start + k * ENC_CHUNK_SIZE];
            let (out, result) = decrypt(cut);
            assert!(matches!(result, Err(Error::TruncatedFile)), "k={k} threads={threads}: {result:?}");
            assert!(out == data[..k * CHUNK_SIZE], "chunks before the cut must still be delivered");
        }

        // Cut inside a chunk.
        let cut = &file[..start + BATCH_CHUNKS * ENC_CHUNK_SIZE + 100];
        assert!(decrypt(cut).1.is_err());
        let cut = &file[..start + BATCH_CHUNKS * ENC_CHUNK_SIZE + TAG_SIZE - 1];
        assert!(matches!(decrypt(cut).1, Err(Error::TruncatedFile)));

        // Swap two chunks that sit in different batches.
        let mut swapped = file.clone();
        let a = start + 3 * ENC_CHUNK_SIZE;
        let b = start + (BATCH_CHUNKS + 3) * ENC_CHUNK_SIZE;
        for i in 0..ENC_CHUNK_SIZE {
            swapped.swap(a + i, b + i);
        }
        assert!(matches!(decrypt(&swapped).1, Err(Error::DecryptionFailed)));

        // Duplicate a chunk and append garbage.
        let mut dup = file.clone();
        let chunk = file[start..start + ENC_CHUNK_SIZE].to_vec();
        dup.splice(start..start, chunk);
        assert!(decrypt(&dup).1.is_err());
        let mut extended = file.clone();
        extended.extend_from_slice(&[0u8; 3]);
        assert!(decrypt(&extended).1.is_err());
    }
    std::env::remove_var("TIMENC_THREADS");
}

#[test]
fn writer_refuses_more_payload_than_declared() {
    use std::io::Write;

    let salt = [1u8; 16];
    let keys = v6::derive_file_keys(PASSWORD, None, &salt, kdf()).unwrap();
    let metadata = v6::Metadata::new("x".into(), false, false, 10);
    let mut sink = Vec::new();
    let mut writer = v6::EncryptWriter::new(&mut sink, salt, kdf(), &metadata, &keys, false).unwrap();

    writer.write_all(&[0u8; 10]).unwrap();
    let error = writer.write_all(&[0u8; 1]).unwrap_err();
    assert!(matches!(Error::from(error), Error::SourceChanged));
}

#[test]
fn small_writes_in_odd_sizes_produce_the_same_file_as_one_big_write() {
    use std::io::Write;

    let salt = [9u8; 16];
    let data = payload(BATCH_BYTES + 3 * CHUNK_SIZE + 1);
    let expected = encrypt(&data, false, salt);

    let keys = v6::derive_file_keys(PASSWORD, None, &salt, kdf()).unwrap();
    let metadata = v6::Metadata::new("ref.bin".into(), false, false, data.len() as u64);
    let mut out = Vec::new();
    let mut writer = v6::EncryptWriter::new(&mut out, salt, kdf(), &metadata, &keys, false).unwrap();
    let mut rest = &data[..];
    let mut step = 1usize;
    while !rest.is_empty() {
        let take = step.min(rest.len());
        writer.write_all(&rest[..take]).unwrap();
        rest = &rest[take..];
        step = step * 3 + 1; // 1, 4, 13, 40 ... crosses chunk and batch edges unevenly
    }
    writer.finish().unwrap();
    assert!(out == expected);
}
