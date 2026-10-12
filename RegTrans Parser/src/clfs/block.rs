//! CLFS log block header.
//!
//! Recovered by static analysis of `clfs.sys` (decompile + raw disassembly,
//! two builds: an unlabeled decompile and 10.0.19041.6157). Only the fields
//! actually used by a read-only enumerator are modeled here. Everything else
//! is preserved as raw bytes rather than invented.

pub const SECTOR_SIZE: usize = 512;
pub const BLOCK_HEADER_MIN_LEN: usize = 0x68 + 4; // through the sig-array-base field

/// Magic bytes proven at block+0x00 / block+0x01.
pub const BLOCK_MAGIC_0: u8 = 0x15;
pub const BLOCK_MAGIC_1: u8 = 0x00;

#[derive(Debug)]
pub enum BlockError {
    TooShort,
    BadMagic { at: usize },
    SectorCountZero,
    BlockLargerThanBuffer { need: usize, have: usize },
}

/// A parsed (but not yet sector-fixed-up) CLFS block header.
///
/// Field offsets are all `Proven` per the recovered spec, except where noted.
#[derive(Debug, Clone, Copy)]
pub struct BlockHeader {
    /// block+0x02, single byte. Compared against each sector's tail low byte
    /// during fixup.
    pub signature_byte: u8,
    /// block+0x04, u16. Block size in bytes = sector_count << 9.
    pub sector_count: u16,
    /// block+0x0C, u32. CRC-32-shaped checksum. Intentionally unverified by
    /// this reader (skip CRC validation, per scope).
    pub checksum: u32,
    /// block+0x10, u32. Flags; bit 0x1 reportedly gates whether fixup is
    /// needed. This reader always performs fixup regardless (safe no-op on
    /// already-correct data), so this field is informational only.
    pub flags: u32,
    /// block+0x28..0x67, 16 x u32. Record-lookup hash bucket table.
    /// bucket[0] is proven to equal the byte offset (from block start) of
    /// the first record in a well-formed block. Not required for a purely
    /// sequential reader (which can instead probe from just past the
    /// header), but exposed here since it's essentially free to read and
    /// matches what Windows itself uses as its first-record shortcut.
    pub hash_buckets: [u32; 16],
    /// block+0x68, u32. Byte offset (from block start) of the per-sector
    /// signature replacement array (2 bytes per sector).
    pub sig_array_offset: u32,
}

impl BlockHeader {
    /// Parses a block header from `data`, which must be at least
    /// `BLOCK_HEADER_MIN_LEN` bytes and start at a candidate block boundary.
    ///
    /// Does NOT perform sector fixup and does NOT validate the CRC -- this
    /// is purely the fixed-position header fields, all proven offsets.
    pub fn parse(data: &[u8]) -> Result<BlockHeader, BlockError> {
        if data.len() < BLOCK_HEADER_MIN_LEN {
            return Err(BlockError::TooShort);
        }
        if data[0x00] != BLOCK_MAGIC_0 {
            return Err(BlockError::BadMagic { at: 0x00 });
        }
        if data[0x01] != BLOCK_MAGIC_1 {
            return Err(BlockError::BadMagic { at: 0x01 });
        }

        let signature_byte = data[0x02];
        let sector_count = u16::from_le_bytes([data[0x04], data[0x05]]);
        if sector_count == 0 {
            return Err(BlockError::SectorCountZero);
        }
        let checksum = u32::from_le_bytes(data[0x0C..0x10].try_into().unwrap());
        let flags = u32::from_le_bytes(data[0x10..0x14].try_into().unwrap());

        let mut hash_buckets = [0u32; 16];
        for (i, chunk) in data[0x28..0x68].chunks_exact(4).enumerate() {
            hash_buckets[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        let sig_array_offset = u32::from_le_bytes(data[0x68..0x6C].try_into().unwrap());

        let block_size = block_size_bytes(sector_count);
        if data.len() < block_size {
            return Err(BlockError::BlockLargerThanBuffer {
                need: block_size,
                have: data.len(),
            });
        }

        Ok(BlockHeader {
            signature_byte,
            sector_count,
            checksum,
            flags,
            hash_buckets,
            sig_array_offset,
        })
    }

    /// The proven "first record" shortcut: `block_base + hash_buckets[0]`.
    /// Returns `None` if the slot is empty or clearly out of range -- caller
    /// should fall back to linear probing in that case.
    pub fn first_record_offset(&self) -> Option<usize> {
        let off = self.hash_buckets[0] as usize;
        let size = self.block_size_bytes();
        if off == 0 || off >= size {
            None
        } else {
            Some(off)
        }
    }

    pub fn block_size_bytes(&self) -> usize {
        block_size_bytes(self.sector_count)
    }
}

/// SectorCount << 9. Proven at 3+ independent sites across two builds.
pub fn block_size_bytes(sector_count: u16) -> usize {
    (sector_count as usize) << 9
}

/// Quick magic-only check, useful for physically scanning a file for block
/// boundaries when no reliable chaining/restart-area info is used (see
/// module-level docs in `main.rs` for why this is the chosen strategy).
pub fn looks_like_block_start(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == BLOCK_MAGIC_0 && data[1] == BLOCK_MAGIC_1
}
