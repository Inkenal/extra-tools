//! CM record fragment reassembly.
//!
//! Recovered from the CM fragment *writer* (`FUN_140a085d0`,
//! `ntoskrnl.exe`). CLFS itself has no awareness of fragmentation -- every
//! fragment is a completely ordinary, independent CLFS record whose
//! *client payload* happens to carry these extra bookkeeping fields. That
//! makes this purely a CM-layer concern, consistent with the proven
//! CLFS/CM handoff boundary.
//!
//! No CLFS-side or CM-side *reader* function implementing reassembly was
//! ever found during the investigation -- this module's algorithm is
//! reconstructed from the writer's layout (strong evidence, not directly
//! observed reader code).

use std::collections::HashMap;

use super::txr::{CmCommonHeader, FRAGMENT_BIT};

pub const FRAGMENT_HEADER_LEN: usize = 0x40;

// Cap allocations from malformed fragment metadata in untrusted log files.
const MAX_FRAGMENTS_PER_GROUP: u32 = 4096;

#[derive(Debug, Clone, Copy)]
pub struct FragmentInfo {
    pub fragment_count: u32,
    pub fragment_index: u32,
    pub fragment_chunk_length: u32,
}

impl FragmentInfo {
    /// Parses the fragment-specific fields from a CM payload known to have
    /// `FRAGMENT_BIT` set in its subtype field. `payload` is the full CM
    /// payload (same base as the common header), not an offset slice.
    pub fn parse(payload: &[u8]) -> Option<FragmentInfo> {
        if payload.len() < FRAGMENT_HEADER_LEN {
            return None;
        }
        Some(FragmentInfo {
            fragment_count: u32::from_le_bytes(payload[0x30..0x34].try_into().ok()?),
            fragment_index: u32::from_le_bytes(payload[0x34..0x38].try_into().ok()?),
            fragment_chunk_length: u32::from_le_bytes(payload[0x38..0x3C].try_into().ok()?),
        })
    }
}

/// Grouping key: the first 0x30 bytes of the fragment's CM payload, with
/// the fragment marker bit at offset 0x0C masked off (it's forced-set
/// identically on every fragment of the same group, so it doesn't
/// distinguish groups, but masking it keeps the key equal to what the
/// original unfragmented record's header would have been).
fn group_key(payload: &[u8]) -> Option<[u8; 0x30]> {
    if payload.len() < 0x30 {
        return None;
    }
    let mut key = [0u8; 0x30];
    key.copy_from_slice(&payload[0..0x30]);
    // clear the fragment bit within the subtype field (bytes 0x0C..0x10, LE)
    let subtype = u32::from_le_bytes(key[0x0C..0x10].try_into().unwrap());
    let cleared = subtype & !FRAGMENT_BIT;
    key[0x0C..0x10].copy_from_slice(&cleared.to_le_bytes());
    Some(key)
}

/// Accumulates fragments across however many CLFS records they were
/// spread over, and reassembles complete ones on demand.
///
/// Usage: feed every CM payload that has `is_fragment() == true` into
/// `add`; call `take_complete` periodically (or at the end) to drain any
/// groups that now have all their pieces.
#[derive(Default)]
pub struct FragmentReassembler {
    groups: HashMap<[u8; 0x30], Vec<Option<Vec<u8>>>>,
}

impl FragmentReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one fragment's raw CM payload bytes in. Corruption-tolerant:
    /// malformed fragment metadata is silently dropped (the record is
    /// lost, but scanning continues) rather than erroring the whole file.
    pub fn add(&mut self, payload: &[u8]) {
        let Some(info) = FragmentInfo::parse(payload) else {
            return;
        };
        let Some(key) = group_key(payload) else {
            return;
        };
        if info.fragment_count == 0
            || info.fragment_count > MAX_FRAGMENTS_PER_GROUP
            || info.fragment_index >= info.fragment_count
        {
            return;
        }
        let Some(end) = FRAGMENT_HEADER_LEN.checked_add(info.fragment_chunk_length as usize) else {
            return;
        };
        let Some(chunk) = payload.get(FRAGMENT_HEADER_LEN..end) else {
            return;
        };
        let chunk = chunk.to_vec();

        let slots = self
            .groups
            .entry(key)
            .or_insert_with(|| vec![None; info.fragment_count as usize]);
        // Defend against a corrupt/conflicting fragment_count across
        // fragments claiming the same group: keep the first size seen.
        if (info.fragment_index as usize) < slots.len() {
            slots[info.fragment_index as usize] = Some(chunk);
        }
    }

    /// Drains and returns every group that currently has all its
    /// fragments, as reassembled `(header_bytes, data)` pairs where
    /// `header_bytes` is the original 0x30-byte header (fragment bit
    /// cleared) and `data` is the concatenated payload data in index
    /// order. Groups still missing pieces are left in place.
    pub fn take_complete(&mut self) -> Vec<([u8; 0x30], Vec<u8>)> {
        let mut done_keys = Vec::new();
        for (key, slots) in self.groups.iter() {
            if slots.iter().all(|s| s.is_some()) {
                done_keys.push(*key);
            }
        }

        let mut out = Vec::new();
        for key in done_keys {
            if let Some(slots) = self.groups.remove(&key) {
                let mut data = Vec::new();
                for slot in slots {
                    if let Some(chunk) = slot {
                        data.extend_from_slice(&chunk);
                    }
                }
                out.push((key, data));
            }
        }
        out
    }

    /// Any groups still incomplete when the file has been fully scanned
    /// (truncated file, missing records, etc.) -- surfaced for forensic
    /// visibility rather than silently discarded.
    pub fn incomplete_groups(&self) -> usize {
        self.groups.len()
    }
}

/// Rebuilds a full, non-fragmented CM payload buffer from a reassembled
/// `(header, data)` pair so it can be parsed with the ordinary
/// `txr::parse_cm_record` path.
pub fn rebuild_payload(header: &[u8; 0x30], data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(header.len() + data.len());
    buf.extend_from_slice(header);
    buf.extend_from_slice(data);
    // Fix up record_length (offset 0x04) to reflect the reassembled size,
    // since the original per-fragment record_length only described that
    // fragment's own (small) buffer.
    let new_len = buf.len() as u32;
    buf[0x04..0x08].copy_from_slice(&new_len.to_le_bytes());
    buf
}

/// Convenience check mirroring `CmCommonHeader::is_fragment()` without
/// needing a fully parsed header first (used to decide whether to route a
/// payload to the reassembler at all).
pub fn payload_is_fragment(payload: &[u8]) -> bool {
    CmCommonHeader::parse(payload)
        .map(|h| h.is_fragment())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fragment(count: u32, index: u32, bytes: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; FRAGMENT_HEADER_LEN];
        p[0x0C..0x10].copy_from_slice(&(FRAGMENT_BIT | 3).to_le_bytes());
        p[0x30..0x34].copy_from_slice(&count.to_le_bytes());
        p[0x34..0x38].copy_from_slice(&index.to_le_bytes());
        p[0x38..0x3C].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        p.extend_from_slice(bytes);
        p
    }

    #[test]
    fn rejects_unreasonably_large_fragment_count() {
        let mut r = FragmentReassembler::new();
        r.add(&fragment(u32::MAX, 0, b"test"));
        assert_eq!(r.incomplete_groups(), 0);
    }

    #[test]
    fn reassembles_small_fragment_group() {
        let mut r = FragmentReassembler::new();
        r.add(&fragment(2, 0, b"ab"));
        r.add(&fragment(2, 1, b"cd"));
        let complete = r.take_complete();
        assert_eq!(complete.len(), 1);
        assert_eq!(complete[0].1, b"abcd");
        assert_eq!(r.incomplete_groups(), 0);
    }
}
