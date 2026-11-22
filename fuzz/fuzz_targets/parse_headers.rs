//! Feeds arbitrary bytes to every header and metadata parser.
//!
//! The parsers run on untrusted input before any key is derived, so they must
//! never panic (the release profile aborts on panic) and must never allocate
//! based on an unchecked length.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use timenc::format::{self, v4, v6};

fuzz_target!(|data: &[u8]| {
    // v2/v3 header, both parsers. They must agree on anything both accept.
    let slice_parse = format::Header::from_bytes(data);
    let reader_parse = format::Header::read_from(&mut Cursor::new(data));
    if let (Ok((a, a_len)), Ok((b, b_len))) = (&slice_parse, &reader_parse) {
        assert_eq!(a_len, b_len);
        assert_eq!(a.to_bytes().unwrap(), b.to_bytes().unwrap());
    }

    // v4/v5 header and metadata.
    let _ = v4::Header::from_bytes(data);
    let _ = v4::Header::read_from(&mut Cursor::new(data));
    let _ = v4::Metadata::from_bytes(data);

    // v6 header: anything accepted must re-serialise to exactly the bytes that
    // were parsed, i.e. there is one canonical encoding.
    if let Ok((header, len)) = v6::Header::from_bytes(data) {
        assert_eq!(header.to_bytes().unwrap(), data[..len]);
        assert!(header.kdf.validate().is_ok());
        assert!(header.metadata_len <= v6::MAX_METADATA_LEN);
    }
    let _ = v6::Header::read_from(&mut Cursor::new(data));

    // v6 metadata likewise has a single encoding.
    if let Ok(metadata) = v6::Metadata::from_bytes(data) {
        assert_eq!(metadata.to_bytes().unwrap(), data);
    }

    // Whatever the name parser accepts is a single plain path component.
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(name) = format::sanitize_output_name(text) {
            assert!(!name.contains('/'));
            assert_ne!(name, "..");
            assert_ne!(name, ".");
        }
    }
});
