//! Configuration Manager TxR record parsing.
//!
//! This module consumes a CLFS record's *payload* bytes only -- it has no
//! knowledge of CLFS blocks, sectors, or LSNs beyond what's already been
//! resolved by the `clfs` module. This mirrors the proven handoff boundary
//! found in `ClfsReadLogRecord`/`ClfsReadNextLogRecord`: CLFS returns a raw
//! pointer + length and understands nothing about what's inside.
//!
//! Field offsets recovered from `ntoskrnl.exe` Configuration Manager code
//! (`FUN_140a07d18` and its callees), across several rounds of tracing.

pub const COMMON_HEADER_LEN: usize = 0x24;

/// Bit forced into the subtype field (offset 0x0C) to mark a fragmented
/// payload. Proven in the CM fragment-writer (`FUN_140a085d0`).
pub const FRAGMENT_BIT: u32 = 0x8000_0000;

#[derive(Debug, Clone, Copy)]
pub struct CmCommonHeader {
    /// 0x00. Checksum over the record buffer (algorithm not verified by
    /// this reader -- see project scope, CRC validation intentionally
    /// skipped throughout).
    pub checksum: u32,
    /// 0x04. Total record buffer length as CM allocated it.
    pub record_length: u32,
    /// 0x08. Observed constant `1` in every traced producer. Preserved,
    /// not assumed to always be 1.
    pub version: u32,
    /// 0x0C. Operation subtype, MAY have `FRAGMENT_BIT` set. Use
    /// `subtype_value()` for the masked value.
    pub subtype_raw: u32,
    /// 0x10. Proven to exist (u64); role never confirmed by code (only
    /// copied verbatim, never independently dereferenced or compared).
    /// Preserved exactly, per project instructions -- do not invent a name
    /// beyond "unknown_1".
    pub unknown_1: u64,
    /// 0x18. Same status as `unknown_1`.
    pub unknown_2: u64,
    /// 0x20. Length, in bytes, of the UTF-16LE key path that follows the
    /// subtype-specific header region.
    pub key_path_length: u16,
    /// 0x22. Proven to exist; role unproven.
    pub unknown_3: u16,
}

#[derive(Debug)]
pub enum CmParseError {
    TooShortForCommonHeader,
    UnknownSubtypeHeaderSize(u32),
    TooShortForSubtypeHeader,
    KeyPathOutOfBounds,
    DataOutOfBounds,
}

impl CmCommonHeader {
    pub fn parse(data: &[u8]) -> Result<CmCommonHeader, CmParseError> {
        if data.len() < COMMON_HEADER_LEN {
            return Err(CmParseError::TooShortForCommonHeader);
        }
        Ok(CmCommonHeader {
            checksum: u32::from_le_bytes(data[0x00..0x04].try_into().unwrap()),
            record_length: u32::from_le_bytes(data[0x04..0x08].try_into().unwrap()),
            version: u32::from_le_bytes(data[0x08..0x0C].try_into().unwrap()),
            subtype_raw: u32::from_le_bytes(data[0x0C..0x10].try_into().unwrap()),
            unknown_1: u64::from_le_bytes(data[0x10..0x18].try_into().unwrap()),
            unknown_2: u64::from_le_bytes(data[0x18..0x20].try_into().unwrap()),
            key_path_length: u16::from_le_bytes(data[0x20..0x22].try_into().unwrap()),
            unknown_3: u16::from_le_bytes(data[0x22..0x24].try_into().unwrap()),
        })
    }

    /// Subtype value with the fragment marker bit masked off.
    pub fn subtype_value(&self) -> u32 {
        self.subtype_raw & !FRAGMENT_BIT
    }

    pub fn is_fragment(&self) -> bool {
        self.subtype_raw & FRAGMENT_BIT != 0
    }
}

/// Header size (bytes, including the common header) for a given on-disk
/// subtype value.
///
/// VERIFIED against a real `.regtrans-ms` sample by brute-forcing the
/// offset at which the `\REGISTRY` key-path prefix appears for each
/// subtype seen in the file:
///   - subtype 1 -> 0x40   (verified)
///   - subtype 2 -> 0x40   (verified)
///   - subtype 3 -> 0x50   (verified)
///   - subtype 4 -> 0x50   (verified)
///   - subtype 5 -> 0x50   (verified)
/// The on-disk subtype is a small remapped integer, not the raw CM
/// op-code, so the originally-handed spec's op-code-keyed table did not
/// apply. Subtypes 0/6/7/8/9 were not present in the available sample and
/// are left unmapped (records with those subtypes are skipped rather than
/// mis-parsed at a guessed size).
pub fn header_size_for_subtype(subtype: u32) -> Option<usize> {
    match subtype {
        1 => Some(0x40),
        2 => Some(0x40),
        3 => Some(0x50),
        4 => Some(0x50),
        5 => Some(0x50),
        _ => None,
    }
}

#[derive(Debug)]
pub struct CmRecord<'a> {
    pub common: CmCommonHeader,
    pub header_size: usize,
    /// Raw UTF-16LE bytes of the key path. Length = `common.key_path_length`.
    pub key_path_utf16le: &'a [u8],
    /// Raw UTF-16LE bytes of the value name. For 0x50-header records the
    /// length comes from the header field at 0x30 (confirmed against a real
    /// sample); otherwise from NUL-splitting. May be empty.
    pub value_name_utf16le: &'a [u8],
    /// The value data bytes. For 0x50-header records the length comes from
    /// the header field at 0x44 (confirmed against a real sample).
    pub value_data: &'a [u8],
    /// Registry type (REG_SZ etc.), from CM header offset 0x40. Confirmed
    /// against a real sample for subtype 3 (1=REG_SZ matched string data,
    /// 4=REG_DWORD matched 4-byte data). `None` for smaller-header subtypes
    /// where the field's location isn't confirmed.
    pub registry_type: Option<u16>,
    /// Value name length in bytes, from CM header offset 0x30 (when present).
    pub value_name_length: Option<usize>,
    /// Value data length in bytes, from CM header offset 0x44 (when present).
    pub value_data_length: Option<usize>,
}


/// Parses a single CM record from a CLFS payload slice. Does not attempt
/// fragment reassembly -- see `cm::fragment` for that, which operates on
/// possibly-multiple `CmRecord`s.
pub fn parse_cm_record(payload: &[u8]) -> Result<CmRecord<'_>, CmParseError> {
    let common = CmCommonHeader::parse(payload)?;
    let header_size = header_size_for_subtype(common.subtype_value())
        .ok_or(CmParseError::UnknownSubtypeHeaderSize(common.subtype_value()))?;

    if payload.len() < header_size {
        return Err(CmParseError::TooShortForSubtypeHeader);
    }

    let key_path_len = common.key_path_length as usize;
    let key_path_end = header_size
        .checked_add(key_path_len)
        .ok_or(CmParseError::KeyPathOutOfBounds)?;
    if key_path_end > payload.len() {
        return Err(CmParseError::KeyPathOutOfBounds);
    }

    let key_path_utf16le = &payload[header_size..key_path_end];

    // CORRECTED against real sample. For the 0x50-header subtypes (3, and
    // by structure 4/5/6), the CM header carries explicit length/type
    // fields that make the trailing region unambiguous -- far better than
    // NUL-splitting, which fails on value names containing no separator:
    //   0x30 u16  value_name_length (bytes)   [confirmed subtype 3]
    //   0x40 u16  registry_type                [confirmed subtype 3: 1=REG_SZ, 4=REG_DWORD]
    //   0x44 u16  value_data_length (bytes)    [confirmed subtype 3]
    // These offsets only exist within the 0x50 header; smaller headers
    // (0x40, 0x38) don't have them, so we fall back to NUL-splitting there.
    let rest = &payload[key_path_end..];

    let (value_name_utf16le, value_data, registry_type, value_name_length, value_data_length) =
        if header_size >= 0x50 && payload.len() >= 0x46 {
            let vn_len = u16::from_le_bytes(payload[0x30..0x32].try_into().unwrap()) as usize;
            let reg_type = u16::from_le_bytes(payload[0x40..0x42].try_into().unwrap());
            let vd_len = u16::from_le_bytes(payload[0x44..0x46].try_into().unwrap()) as usize;

            let vn_end = vn_len.min(rest.len());
            let vn = &rest[..vn_end];
            let data_region = &rest[vn_end..];
            let vd_end = vd_len.min(data_region.len());
            let vd = &data_region[..vd_end];
            (vn, vd, Some(reg_type), Some(vn_len), Some(vd_len))
        } else {
            let (vn, vd) = split_value_name(rest);
            (vn, vd, None, None, None)
        };

    Ok(CmRecord {
        common,
        header_size,
        key_path_utf16le,
        value_name_utf16le,
        value_data,
        registry_type,
        value_name_length,
        value_data_length,
    })
}

/// Splits a trailing region into (value_name_utf16le, value_data) on the
/// first UTF-16LE NUL (0x0000) code unit. If no NUL is found, the whole
/// region is treated as the value name and data is empty -- observed in
/// real "key-level" records (subtype 4) whose trailing region is just the
/// leaf name with no separate data.
fn split_value_name(rest: &[u8]) -> (&[u8], &[u8]) {
    let mut i = 0;
    while i + 1 < rest.len() {
        if rest[i] == 0 && rest[i + 1] == 0 {
            return (&rest[..i], &rest[i + 2..]);
        }
        i += 2;
    }
    (rest, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_header_parses_known_layout() {
        // Minimal synthetic subtype-3 payload: 0x50 header, key path "\A"
        // (UTF-16LE, 4 bytes), value name "V" (2 bytes), REG_SZ, 2 data bytes.
        let mut p = vec![0u8; 0x50 + 4 + 2 + 2];
        p[0x0C..0x10].copy_from_slice(&3u32.to_le_bytes()); // subtype 3
        p[0x20..0x22].copy_from_slice(&4u16.to_le_bytes()); // key path len = 4 bytes
        p[0x30..0x32].copy_from_slice(&2u16.to_le_bytes()); // value name len = 2 bytes
        p[0x40..0x42].copy_from_slice(&1u16.to_le_bytes()); // REG_SZ
        p[0x44..0x46].copy_from_slice(&2u16.to_le_bytes()); // data len = 2 bytes
        // key path "\A"
        p[0x50..0x54].copy_from_slice(&[0x5C, 0x00, 0x41, 0x00]);
        // value name "V"
        p[0x54..0x56].copy_from_slice(&[0x56, 0x00]);
        // data
        p[0x56..0x58].copy_from_slice(&[0x21, 0x00]);

        let rec = parse_cm_record(&p).expect("should parse");
        assert_eq!(rec.common.subtype_value(), 3);
        assert_eq!(rec.header_size, 0x50);
        assert_eq!(rec.key_path_utf16le, &[0x5C, 0x00, 0x41, 0x00]);
        assert_eq!(rec.value_name_utf16le, &[0x56, 0x00]);
        assert_eq!(rec.value_data, &[0x21, 0x00]);
        assert_eq!(rec.registry_type, Some(1));
    }

    #[test]
    fn header_sizes_match_verified_sample() {
        assert_eq!(header_size_for_subtype(1), Some(0x40));
        assert_eq!(header_size_for_subtype(2), Some(0x40));
        assert_eq!(header_size_for_subtype(3), Some(0x50));
        assert_eq!(header_size_for_subtype(4), Some(0x50));
        assert_eq!(header_size_for_subtype(5), Some(0x50));
        assert_eq!(header_size_for_subtype(99), None);
    }
}
