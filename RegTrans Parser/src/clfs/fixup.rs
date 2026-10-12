//! CLFS sector-signature restoration ("update sequence"-equivalent).
//!
//! Recovered from `FUN_140004100` (clfs.sys decompile). At write time,
//! Windows overwrites the last 2 bytes of every 512-byte sector with a
//! signature value, stashing the real 2 bytes in a per-sector array at
//! block+0x68. On read, every sector's tail must match the block's
//! signature byte (block+0x02) or the block is considered torn; if it
//! matches, the real bytes are swapped back in before the block's contents
//! (including any record header/payload that straddles a sector boundary)
//! can be trusted.
//!
//! This is a two-part check, not a single one:
//!   - the tail's *high* byte having its sign bit set means "sector never
//!     wholly written" and stops restoration without an error (this is the
//!     observed behavior in the traced code -- it `break`s, it does not
//!     return an error code)
//!   - the tail's *low* byte must equal the block's signature byte, or the
//!     block is torn (hard error)

use super::block::{BlockHeader, SECTOR_SIZE};

#[derive(Debug, PartialEq, Eq)]
pub enum FixupOutcome {
    /// All present sectors matched and were restored.
    Ok,
    /// Restoration stopped early because a sector's tail looked
    /// uninitialized (high byte sign bit set). Sectors below this point
    /// were restored; sectors at/after it were left untouched. This is NOT
    /// necessarily corruption -- it's the observed non-error stop condition
    /// in the original code, typically meaning the block was not fully
    /// written (e.g. this is the log's current/active block).
    StoppedEarly { at_sector: u16 },
}

#[derive(Debug)]
pub struct SignatureMismatch {
    pub sector: u16,
}

/// Restores sector tails in `block` (which must be exactly
/// `header.block_size_bytes()` long) in place.
///
/// Walks sectors from the *last* to the *first*, matching the order
/// observed in the decompiled loop (`for sector = sector_count downto 1`).
pub fn restore_sector_signatures(
    block: &mut [u8],
    header: &BlockHeader,
) -> Result<FixupOutcome, SignatureMismatch> {
    let block_size = header.block_size_bytes();
    debug_assert!(block.len() >= block_size);

    let sig_array_off = header.sig_array_offset as usize;

    for sector in (1..=header.sector_count).rev() {
        let sector_idx = (sector - 1) as usize;
        let tail_off = sector_idx * SECTOR_SIZE + (SECTOR_SIZE - 2); // +0x1FE within the sector

        if tail_off + 2 > block.len() {
            // Truncated buffer -- can't safely check this sector at all.
            // Treat as an early stop rather than panicking.
            return Ok(FixupOutcome::StoppedEarly { at_sector: sector });
        }

        let hi_byte = block[tail_off];
        let lo_byte = block[tail_off + 1];

        // Soft stop: high byte's sign bit set -> sector not fully written.
        if hi_byte & 0x80 != 0 {
            return Ok(FixupOutcome::StoppedEarly { at_sector: sector });
        }

        // Hard error: low byte must match the block's signature byte.
        if lo_byte != header.signature_byte {
            return Err(SignatureMismatch { sector });
        }

        // Restore real data from the replacement array.
        let repl_off = sig_array_off + sector_idx * 2;
        if repl_off + 2 > block.len() {
            return Ok(FixupOutcome::StoppedEarly { at_sector: sector });
        }
        // Read the replacement bytes before overwriting the sector tail.
        let real_bytes = [block[repl_off], block[repl_off + 1]];
        block[tail_off] = real_bytes[0];
        block[tail_off + 1] = real_bytes[1];
    }

    Ok(FixupOutcome::Ok)
}
