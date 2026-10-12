//! Minimal CLFS reader: just enough to enumerate records and hand their
//! payloads to the CM layer. Deliberately does NOT implement: writing,
//! restart-area management, container management, reservations, log
//! growth, client contexts, management APIs, or runtime recovery.
//!
//! # Block discovery strategy
//!
//! Investigation of `clfs.sys` found no reliable block-to-block chaining
//! mechanism (no "next block" pointer, no directory) reachable from the
//! normal read path -- block location is normally either LSN-arithmetic
//! (`ContainerId`/`BlockOffset` decomposed from an LSN) or via the restart
//! area, neither of which this offline reader implements (out of scope).
//!
//! So: this reader does a **physical scan** of the container file for
//! valid block-start magics (`0x15 0x00`) at 512-byte-aligned candidate
//! offsets, parses each candidate's header to get its real size
//! (`SectorCount << 9`), and resumes scanning after that block. This is a
//! pragmatic reader-side strategy, not a description of CLFS's own
//! behavior -- flagged as such rather than presented as proven.

pub mod block;
pub mod fixup;
pub mod record;

use block::{BlockHeader, SECTOR_SIZE};

#[derive(Debug)]
pub struct FoundBlock {
    pub file_offset: u64,
    pub header: BlockHeader,
    /// Owned, sector-fixed-up copy of the block's bytes.
    pub data: Vec<u8>,
    pub fixup_note: Option<String>,
}

/// Scans `container` (the full bytes of a `.regtrans-ms` file) for valid
/// CLFS blocks, applying sector fixup to each one found.
///
/// Corruption tolerance: a block that fails header parsing or fixup is
/// skipped (scan resumes at the next 512-byte boundary) rather than
/// aborting the whole scan, per project scope ("tolerate corruption
/// wherever possible and continue").
pub fn scan_blocks(container: &[u8]) -> Vec<FoundBlock> {
    let mut found = Vec::new();
    let mut pos: usize = 0;

    while pos + block::BLOCK_HEADER_MIN_LEN <= container.len() {
        if !block::looks_like_block_start(&container[pos..]) {
            pos += SECTOR_SIZE;
            continue;
        }

        match try_read_block_at(container, pos) {
            Ok(fb) => {
                let advance = fb.header.block_size_bytes().max(SECTOR_SIZE);
                found.push(fb);
                pos += advance;
            }
            Err(_) => {
                // Magic matched but header/fixup failed -- likely a false
                // positive or a genuinely corrupt block. Move on one
                // sector at a time rather than giving up on the file.
                pos += SECTOR_SIZE;
            }
        }
    }

    found
}

fn try_read_block_at(container: &[u8], pos: usize) -> Result<FoundBlock, String> {
    let header = block::BlockHeader::parse(&container[pos..])
        .map_err(|e| format!("header parse failed: {:?}", e))?;

    let block_size = header.block_size_bytes();
    if pos + block_size > container.len() {
        return Err("block extends past end of file".into());
    }

    let mut data = container[pos..pos + block_size].to_vec();

    let fixup_note = match fixup::restore_sector_signatures(&mut data, &header) {
        Ok(fixup::FixupOutcome::Ok) => None,
        Ok(fixup::FixupOutcome::StoppedEarly { at_sector }) => {
            Some(format!("fixup stopped early at sector {}", at_sector))
        }
        Err(e) => return Err(format!("sector signature mismatch at sector {}", e.sector)),
    };

    Ok(FoundBlock {
        file_offset: pos as u64,
        header,
        data,
        fixup_note,
    })
}

impl FoundBlock {
    /// Convenience: get a sequential record iterator over this block,
    /// starting from the proven hash-bucket[0] shortcut and falling back
    /// to a linear probe if that slot is empty/invalid.
    pub fn records(&self) -> record::RecordIter<'_> {
        let first = self
            .header
            .first_record_offset()
            .or_else(|| record::find_first_record_offset(&self.data, &self.header));

        match first {
            Some(off) => record::RecordIter::new(&self.data, &self.header, off),
            None => record::RecordIter::new(&self.data, &self.header, self.data.len()), // yields nothing
        }
    }
}
