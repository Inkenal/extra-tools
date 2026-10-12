//! CLFS client record header + sequential record enumeration.
//!
//! Field offsets proven via decompile (`ClfsReadLogRecord`,
//! `ClfsReadNextLogRecord`, `FUN_1400598ec`, `FUN_14005a264`,
//! `FUN_140007c80`) AND cross-confirmed via raw x86-64 disassembly of a
//! real binary (clfs.sys 10.0.19041.6157) -- the header layout and the
//! payload-offset formula are the most independently-confirmed facts in
//! the whole investigation (5+ separate call sites).
//!
//! Per project scope: hash-bucket-based lookup is intentionally NOT used
//! here. Enumeration is purely sequential from the first record.

use super::block::BlockHeader;

pub const RECORD_HEADER_LEN: usize = 0x28; // minimum; HeaderLength may exceed this

/// Hard safety cap on records visited per block. Recovered from
/// `FUN_140007c80`'s specific "find last record" loop (0x1FE = 510). Note:
/// this cap was proven present in that one function, NOT confirmed as a
/// universal property enforced by every record-walk in clfs.sys. It's
/// applied here as a defensive guard against infinite loops on corrupt or
/// adversarial input, consistent with how a forensic reader should behave,
/// not as a claim that Windows itself always enforces it everywhere.
pub const MAX_RECORDS_PER_BLOCK: u32 = 510;

#[derive(Debug, Clone, Copy)]
pub struct ClfsRecordHeader {
    /// record+0x00. Proven: this record's LSN.
    pub current_lsn: u64,
    /// record+0x08. Proven to exist and be this size; role unproven.
    /// Preserved verbatim, not renamed.
    pub unknown_1: u64,
    /// record+0x10. Same as above.
    pub unknown_2: u64,
    /// record+0x18. Proven: total record size including header.
    pub record_length: u32,
    /// record+0x22. Proven: offset from record start to client payload.
    /// Minimum observed value 0x28.
    pub header_length: u16,
    /// record+0x24. Proven bitmask; only bit 0x20 (last-record-in-block)
    /// has a proven meaning. Other bits (0x3F must be nonzero, 0xC0 must
    /// be zero, for a record to be considered valid) are validation-only,
    /// not individually attributed.
    pub flags: u32,
}

#[derive(Debug)]
pub enum RecordError {
    TooShortForHeader,
    InvalidSequence,
    InvalidFlags,
    HeaderLengthTooSmall,
    HeaderLengthExceedsRecordLength,
    RecordLeavesBlock,
}

impl ClfsRecordHeader {
    /// Parses a record header at the start of `data`. Does not validate;
    /// call `validate` separately (kept apart so callers can inspect a
    /// header even when validation fails, useful for forensic triage of
    /// corrupt records).
    pub fn parse(data: &[u8]) -> Result<ClfsRecordHeader, RecordError> {
        if data.len() < RECORD_HEADER_LEN {
            return Err(RecordError::TooShortForHeader);
        }
        Ok(ClfsRecordHeader {
            current_lsn: u64::from_le_bytes(data[0x00..0x08].try_into().unwrap()),
            unknown_1: u64::from_le_bytes(data[0x08..0x10].try_into().unwrap()),
            unknown_2: u64::from_le_bytes(data[0x10..0x18].try_into().unwrap()),
            record_length: u32::from_le_bytes(data[0x18..0x1C].try_into().unwrap()),
            header_length: u16::from_le_bytes(data[0x22..0x24].try_into().unwrap()),
            flags: u32::from_le_bytes(data[0x24..0x28].try_into().unwrap()),
        })
    }

    /// Validation gates recovered from `FUN_1400085d0` / the inline checks
    /// in `FUN_1400598ec`, `FUN_14005a264`, `FUN_140007c80` (identical
    /// across all sites).
    pub fn validate(&self, offset_in_block: usize, block_size: usize) -> Result<(), RecordError> {
        let sequence = self.current_lsn & 0x1FF;
        if sequence >= 0x1FF {
            return Err(RecordError::InvalidSequence);
        }
        if self.flags & 0x3F == 0 {
            return Err(RecordError::InvalidFlags);
        }
        if self.flags & 0xC0 != 0 {
            return Err(RecordError::InvalidFlags);
        }
        if self.header_length < 0x28 {
            return Err(RecordError::HeaderLengthTooSmall);
        }
        if (self.header_length as u32) > self.record_length {
            return Err(RecordError::HeaderLengthExceedsRecordLength);
        }
        let end = offset_in_block.saturating_add(self.record_length as usize);
        if end > block_size {
            return Err(RecordError::RecordLeavesBlock);
        }
        Ok(())
    }

    /// Proven: bit 0x20 marks the last record in the block.
    pub fn is_last_in_block(&self) -> bool {
        self.flags & 0x20 != 0
    }

    /// Proven formula: payload = record + HeaderLength.
    pub fn payload_offset(&self) -> usize {
        self.header_length as usize
    }

    /// Proven formula: payload length = RecordLength - HeaderLength.
    pub fn payload_length(&self) -> usize {
        (self.record_length as usize).saturating_sub(self.header_length as usize)
    }
}

/// A single enumerated CLFS record: header plus a borrowed slice of its
/// client payload (the bytes that get handed to Configuration Manager).
#[derive(Debug)]
pub struct ClfsRecord<'a> {
    pub header: ClfsRecordHeader,
    pub offset_in_block: usize,
    pub payload: &'a [u8],
    /// Set when this record failed validation but is still being surfaced
    /// for forensic best-effort purposes (e.g. corrupt tail record). When
    /// `Some`, `payload` may be truncated or unreliable.
    pub validation_error: Option<String>,
}

/// Sequentially enumerates records in a single, already-fixed-up block.
///
/// `block` must be the full block buffer (post `restore_sector_signatures`).
/// Per project scope, this deliberately ignores the hash-bucket table and
/// walks from the first record via `align8(RecordLength)` stepping only.
pub struct RecordIter<'a> {
    block: &'a [u8],
    block_size: usize,
    cursor: Option<usize>,
    records_visited: u32,
    done: bool,
}

impl<'a> RecordIter<'a> {
    /// `first_record_offset`: where to start. Callers should try
    /// `BlockHeader::first_record_offset()` first and fall back to a
    /// linear probe (see `find_first_record_offset`) if that's `None`.
    pub fn new(block: &'a [u8], header: &BlockHeader, first_record_offset: usize) -> Self {
        RecordIter {
            block,
            block_size: header.block_size_bytes().min(block.len()),
            cursor: Some(first_record_offset),
            records_visited: 0,
            done: false,
        }
    }
}

impl<'a> Iterator for RecordIter<'a> {
    type Item = ClfsRecord<'a>;

    fn next(&mut self) -> Option<ClfsRecord<'a>> {
        if self.done {
            return None;
        }
        let offset = self.cursor?;

        if self.records_visited >= MAX_RECORDS_PER_BLOCK {
            self.done = true;
            return None;
        }

        if offset >= self.block_size || offset + RECORD_HEADER_LEN > self.block.len() {
            self.done = true;
            return None;
        }

        let header = match ClfsRecordHeader::parse(&self.block[offset..]) {
            Ok(h) => h,
            Err(_) => {
                self.done = true;
                return None;
            }
        };

        self.records_visited += 1;

        let validation_error = header.validate(offset, self.block_size).err();

        if validation_error.is_some() {
            // Stop enumeration after surfacing the failing record --
            // per the recovered spec, a validation failure is treated as
            // block corruption, not "end of valid data" in the original
            // code. We still yield this last record for forensic
            // visibility rather than silently dropping it.
            self.done = true;
            let payload_start = offset + header.payload_offset().min(self.block.len() - offset);
            let payload = &self.block[payload_start.min(self.block.len())..];
            return Some(ClfsRecord {
                header,
                offset_in_block: offset,
                payload,
                validation_error: validation_error.map(|e| format!("{:?}", e)),
            });
        }

        let payload_start = offset + header.payload_offset();
        let payload_end = offset + header.record_length as usize;
        let payload = &self.block[payload_start.min(self.block.len())..payload_end.min(self.block.len())];

        let is_last = header.is_last_in_block();

        if is_last {
            self.done = true;
        } else {
            let step = align8(header.record_length as usize);
            self.cursor = Some(offset + step);
        }

        Some(ClfsRecord {
            header,
            offset_in_block: offset,
            payload,
            validation_error: None,
        })
    }
}

/// `(len + 7) & !7` -- proven 8-byte alignment for record stepping.
pub fn align8(len: usize) -> usize {
    (len + 7) & !7
}

/// Fallback for when `BlockHeader::first_record_offset()` returns `None`
/// (empty/unreliable hash bucket 0): linearly probe from just past the
/// fixed header region for the first offset that parses and validates as
/// a record. This is a pragmatic reader-side strategy, not something
/// proven to be what Windows itself does.
pub fn find_first_record_offset(block: &[u8], header: &BlockHeader) -> Option<usize> {
    let block_size = header.block_size_bytes().min(block.len());
    let start = 0x68 + 2 * header.sector_count as usize; // just past header + sig array
    let start = align8(start);
    let mut offset = start;
    while offset + RECORD_HEADER_LEN <= block_size {
        if let Ok(h) = ClfsRecordHeader::parse(&block[offset..]) {
            if h.validate(offset, block_size).is_ok() {
                return Some(offset);
            }
        }
        offset += 8;
    }
    None
}
