//! Round-trips arbitrary payloads through the v6 stream, then corrupts the
//! ciphertext and checks the corruption is always caught.
//!
//! Run with a large `-max_len` (for example 300000) so inputs cross the
//! 64 KiB chunk boundaries, where the final-chunk logic lives.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use std::sync::OnceLock;
use timenc::crypto::{self, KdfParams};
use timenc::format::v6;

struct Fixture {
    salt: [u8; 16],
    kdf: KdfParams,
    keys: v6::FileKeys,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let salt = [7u8; 16];
        let kdf = KdfParams::new(1, crypto::MIN_MEMORY_KIB, 1);
        let keys = v6::derive_file_keys(b"fuzz password", None, &salt, kdf).unwrap();
        Fixture { salt, kdf, keys }
    })
}

fuzz_target!(|input: &[u8]| {
    let Some((&control, rest)) = input.split_first() else {
        return;
    };
    let pad = control & 1 == 1;
    let (position_bytes, payload) = rest.split_at(rest.len().min(4));
    let fx = fixture();

    let metadata = v6::Metadata::new("f".into(), false, false, payload.len() as u64);
    let mut file = Vec::new();
    v6::encrypt_streaming(
        &mut Cursor::new(payload),
        &mut file,
        fx.salt,
        fx.kdf,
        &metadata,
        &fx.keys,
        pad,
    )
    .unwrap();

    let decrypt = |bytes: &[u8]| -> Result<Vec<u8>, timenc::Error> {
        let (header, header_len) = v6::Header::from_bytes(bytes)?;
        header.verify_commitment(&fx.keys)?;
        let metadata_end = header_len + header.metadata_len as usize;
        let metadata = v6::decrypt_metadata(
            bytes.get(header_len..metadata_end).ok_or(timenc::Error::InvalidFormat)?,
            &header,
            &fx.keys,
        )?;
        let mut out = Vec::new();
        v6::decrypt_streaming(
            &mut Cursor::new(&bytes[metadata_end..]),
            &mut out,
            &header,
            &metadata,
            &fx.keys,
        )?;
        Ok(out)
    };

    assert_eq!(decrypt(&file).as_deref().ok(), Some(payload), "round trip");

    // Flip one bit somewhere in the file.
    let mut seed = [0u8; 4];
    seed[..position_bytes.len()].copy_from_slice(position_bytes);
    let at = u32::from_le_bytes(seed) as usize % file.len();
    let mut corrupted = file.clone();
    corrupted[at] ^= 1 << (control >> 5);
    assert!(decrypt(&corrupted).is_err(), "bit flip at {at} accepted");

    // Cut the file short.
    assert!(decrypt(&file[..at]).is_err(), "truncation to {at} accepted");

    // Append a byte.
    let mut extended = file.clone();
    extended.push(control);
    assert!(decrypt(&extended).is_err(), "trailing byte accepted");
});
