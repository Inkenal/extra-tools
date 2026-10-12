//! Small decoding helpers for the registry-facing output. Deliberately
//! thin: everything non-trivial (what the bytes mean) was resolved in the
//! `cm` module; this just turns proven byte layouts into readable Rust
//! types.

/// Decodes a UTF-16LE byte slice (not null-terminated; length is exact,
/// per the recovered spec) to a `String`, using the standard lossy
/// replacement for any unpaired surrogates rather than failing -- this is
/// a forensic tool and a best-effort string beats an aborted parse.
pub fn decode_utf16le_lossy(bytes: &[u8]) -> String {
    let u16s: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
}

/// Best-effort registry type name for the well-known `REG_*` values.
/// Falls back to a numeric label for anything unrecognized -- this
/// mapping is standard public Windows API knowledge (winnt.h), not
/// something recovered from the binary, so treat it as reference
/// convenience rather than reverse-engineering evidence.
pub fn registry_type_name(value: Option<u32>) -> String {
    match value {
        None => "unknown".to_string(),
        Some(0) => "REG_NONE".to_string(),
        Some(1) => "REG_SZ".to_string(),
        Some(2) => "REG_EXPAND_SZ".to_string(),
        Some(3) => "REG_BINARY".to_string(),
        Some(4) => "REG_DWORD".to_string(),
        Some(5) => "REG_DWORD_BIG_ENDIAN".to_string(),
        Some(6) => "REG_LINK".to_string(),
        Some(7) => "REG_MULTI_SZ".to_string(),
        Some(11) => "REG_QWORD".to_string(),
        Some(other) => format!("REG_UNKNOWN({})", other),
    }
}
