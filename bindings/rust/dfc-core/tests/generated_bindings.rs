use std::{collections::BTreeMap, fs, path::Path};

const READER_STATUSES: [(&str, u32); 8] = [
    ("DFC_FFI_READER_OK", 0),
    ("DFC_FFI_READER_PENDING", 1),
    ("DFC_FFI_READER_INVALID", 2),
    ("DFC_FFI_READER_BUFFER_TOO_SMALL", 3),
    ("DFC_FFI_READER_PROTOCOL_ERROR", 4),
    ("DFC_FFI_READER_INTEGRITY_ERROR", 5),
    ("DFC_FFI_READER_CARD_ERROR", 6),
    ("DFC_FFI_READER_UNSUPPORTED", 7),
];

fn parse_header(path: &Path) -> BTreeMap<String, u32> {
    let source = fs::read_to_string(path).expect("read dfc_ffi.h");
    source
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            if fields.next()? != "#define" {
                return None;
            }
            let name = fields.next()?;
            if !name.starts_with("DFC_FFI_READER_")
                || name == "DFC_FFI_READER_MAX_CLEAR_HEADER_LENGTH"
            {
                return None;
            }
            let value = fields
                .next()?
                .parse()
                .unwrap_or_else(|_| panic!("{name} must have an integer value"));
            Some((name.to_owned(), value))
        })
        .collect()
}

fn parse_rust_bindings(path: &Path) -> BTreeMap<String, u32> {
    let source = fs::read_to_string(path).expect("read checked-in Rust bindings");
    source
        .lines()
        .filter_map(|line| {
            let line = line.strip_prefix("pub const DFC_FFI_READER_")?;
            let (suffix, value) = line.split_once(": u32 = ")?;
            if suffix == "MAX_CLEAR_HEADER_LENGTH" {
                return None;
            }
            let value = value
                .strip_suffix(';')?
                .parse()
                .unwrap_or_else(|_| panic!("DFC_FFI_READER_{suffix} must have an integer value"));
            Some((format!("DFC_FFI_READER_{suffix}"), value))
        })
        .collect()
}

#[test]
fn checked_in_reader_status_bindings_match_the_c_header() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo = crate_dir.join("../../..");
    let expected = READER_STATUSES
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect::<BTreeMap<_, _>>();

    let header = parse_header(&repo.join("ffi/dfc_ffi.h"));
    let bindings = parse_rust_bindings(&repo.join("bindings/rust/dfc-core-sys/src/bindings.rs"));

    assert_eq!(header, expected, "reader status contract changed");
    assert_eq!(bindings, header, "regenerate the checked-in Rust bindings");
}
