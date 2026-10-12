//! Top-level CM parsing entry point. Consumes raw CLFS payload byte
//! slices (as produced by `clfs::record::ClfsRecord::payload`) and
//! produces fully decoded registry transaction operations. Knows nothing
//! about CLFS blocks, sectors, or LSNs -- only about CM's own record
//! format, per the proven CLFS/CM boundary.

use super::fragment::{self, FragmentReassembler};
use super::txr::{self, CmParseError};
use crate::registry::decoder;

#[derive(Debug)]
pub struct DecodedOperation {
    pub subtype: u32,
    pub key_path: String,
    /// Value name (UTF-16LE), length-delimited via the CM header field at
    /// 0x30 for 0x50-header records. May be empty.
    pub value_name: String,
    /// Registry type (REG_SZ etc.) from CM header offset 0x40, confirmed
    /// against a real sample for subtype 3. `None` when not available.
    pub registry_type: Option<u16>,
    /// Raw value-data bytes, length-delimited via the CM header field at
    /// 0x44 for 0x50-header records.
    pub value_data: Vec<u8>,
    pub was_reassembled_from_fragments: bool,
}

/// Feed CLFS payloads in here one at a time (in the order CLFS yielded
/// them). Non-fragmented records are decoded immediately; fragmented ones
/// are buffered internally and emitted once complete.
#[derive(Default)]
pub struct CmParser {
    reassembler: FragmentReassembler,
}

impl CmParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Processes one CLFS payload. Returns zero or more decoded operations
    /// (zero if this payload was a not-yet-complete fragment piece).
    pub fn process_payload(&mut self, payload: &[u8]) -> Vec<DecodedOperation> {
        let mut out = Vec::new();

        if fragment::payload_is_fragment(payload) {
            self.reassembler.add(payload);
            for (header, data) in self.reassembler.take_complete() {
                let rebuilt = fragment::rebuild_payload(&header, &data);
                if let Ok(rec) = txr::parse_cm_record(&rebuilt) {
                    out.push(decode(&rec, true));
                }
            }
            return out;
        }

        match txr::parse_cm_record(payload) {
            Ok(rec) => out.push(decode(&rec, false)),
            Err(_e) => {
                // Corruption-tolerant: skip this record, keep going.
            }
        }
        out
    }

    /// Call after all records have been fed in. Reports how many fragment
    /// groups never completed (missing pieces / truncated file) --
    /// forensic visibility rather than silent data loss.
    pub fn incomplete_fragment_groups(&self) -> usize {
        self.reassembler.incomplete_groups()
    }
}

fn decode(rec: &txr::CmRecord<'_>, was_reassembled: bool) -> DecodedOperation {
    let key_path = decoder::decode_utf16le_lossy(rec.key_path_utf16le);
    let value_name = decoder::decode_utf16le_lossy(rec.value_name_utf16le);

    DecodedOperation {
        subtype: rec.common.subtype_value(),
        key_path,
        value_name,
        registry_type: rec.registry_type,
        value_data: rec.value_data.to_vec(),
        was_reassembled_from_fragments: was_reassembled,
    }
}

impl CmParseError {
    pub fn describe(&self) -> &'static str {
        match self {
            CmParseError::TooShortForCommonHeader => "payload too short for common header",
            CmParseError::UnknownSubtypeHeaderSize(_) => "unrecognized subtype",
            CmParseError::TooShortForSubtypeHeader => "payload too short for subtype header",
            CmParseError::KeyPathOutOfBounds => "key path length exceeds payload",
            CmParseError::DataOutOfBounds => "data region exceeds payload",
        }
    }
}
