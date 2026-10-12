#![allow(dead_code)] // some parser API surface is exposed for library use / future subtypes
//! Offline `.regtrans-ms` parser.
//!
//! Usage: regtrans_parser <path-to-file>
//!
//! Pipeline: physical block scan -> sector fixup -> sequential record
//! enumeration -> CM payload parsing (with fragment reassembly) ->
//! printed operation/key path/type/data.
//!
//! Deliberately does not implement: CLFS writing, restart-area
//! management, container management, reservations, log growth, client
//! contexts, management APIs, or runtime recovery. See module-level docs
//! in `clfs/mod.rs` and `cm/fragment.rs` for what's proven vs. inferred.

mod clfs;
mod cm;
mod registry;

use std::env;
use std::fs;
use std::process::ExitCode;

use cm::parser::CmParser;
use registry::decoder::registry_type_name;

/// Best-effort, NOT independently proven, labels for on-disk subtype
/// values. Refined against a real sample where subtype 3 carried a value
/// name + data (SetValue-like) and subtype 4 carried only a leaf value
/// name (key-level op). The exact op-code -> English-name mapping was
/// never proven from code, so these remain informational.
fn tentative_subtype_label(subtype: u32) -> &'static str {
    match subtype {
        2 => "binary value data (observed: SearchRoots entries)",
        3 => "SetValue-like: key path + value name + data (observed)",
        4 => "key-level op: leaf value name, no data (observed)",
        0 | 1 | 5 | 6 | 7 | 8 | 9 => "unverified (not seen in available sample)",
        other => {
            let _ = other;
            "unrecognized"
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: {} <path-to-.regtrans-ms>", args[0]);
        return ExitCode::FAILURE;
    }

    let data = match fs::read(&args[1]) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("failed to read {}: {}", args[1], e);
            return ExitCode::FAILURE;
        }
    };

    let blocks = clfs::scan_blocks(&data);
    eprintln!("found {} valid block(s)", blocks.len());

    let mut parser = CmParser::new();
    let mut op_count = 0usize;
    let mut record_count = 0usize;
    let mut corrupt_record_count = 0usize;

    for block in &blocks {
        if let Some(note) = &block.fixup_note {
            eprintln!(
                "  block @ file offset 0x{:X}: {}",
                block.file_offset, note
            );
        }

        for record in block.records() {
            record_count += 1;
            if record.validation_error.is_some() {
                corrupt_record_count += 1;
                eprintln!(
                    "  record @ block offset 0x{:X}: validation failed: {:?} (still attempting payload extraction)",
                    record.offset_in_block, record.validation_error
                );
            }

            for op in parser.process_payload(record.payload) {
                op_count += 1;
                print_operation(&op);
            }
        }
    }

    let incomplete = parser.incomplete_fragment_groups();
    if incomplete > 0 {
        eprintln!(
            "warning: {} fragment group(s) never completed (truncated file or missing records)",
            incomplete
        );
    }

    eprintln!(
        "done: {} block(s), {} CLFS record(s) ({} failed validation), {} CM operation(s) decoded",
        blocks.len(),
        record_count,
        corrupt_record_count,
        op_count
    );

    ExitCode::SUCCESS
}

fn print_operation(op: &cm::parser::DecodedOperation) {
    println!("---");
    println!(
        "operation:    subtype {} ({})",
        op.subtype,
        tentative_subtype_label(op.subtype)
    );
    println!("key path:     {}", op.key_path);
    if !op.value_name.is_empty() {
        println!("value name:   {}", op.value_name);
    }
    if let Some(t) = op.registry_type {
        println!("registry type: {}", registry_type_name(Some(t as u32)));
    }
    println!("data length:  {} byte(s)", op.value_data.len());
    if !op.value_data.is_empty() {
        println!(
            "data (hex, first 64 bytes): {}",
            hex_preview(&op.value_data, 64)
        );
        // Best-effort: if the data looks like a UTF-16LE string, show it.
        if let Some(s) = try_utf16le_string(&op.value_data) {
            println!("data (as UTF-16LE string): {}", s);
        }
    }
    if op.was_reassembled_from_fragments {
        println!("(reassembled from multiple CLFS records)");
    }
}

/// Heuristic: if the data is an even number of bytes and decodes to mostly
/// printable UTF-16LE, return it. Purely a display convenience -- the raw
/// bytes remain authoritative.
fn try_utf16le_string(data: &[u8]) -> Option<String> {
    if data.is_empty() || data.len() % 2 != 0 {
        return None;
    }
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let s = String::from_utf16_lossy(&u16s);
    let printable = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\0')
        .count();
    let trimmed = s.trim_end_matches('\0').to_string();
    if !trimmed.is_empty() && printable as f64 / s.chars().count().max(1) as f64 > 0.8 {
        Some(trimmed)
    } else {
        None
    }
}

fn hex_preview(data: &[u8], max: usize) -> String {
    let n = data.len().min(max);
    let mut s = String::with_capacity(n * 2);
    for b in &data[..n] {
        s.push_str(&format!("{:02x}", b));
    }
    if data.len() > n {
        s.push_str("...");
    }
    s
}
