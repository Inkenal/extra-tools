# regtrans_parser

Offline forensic parser for Windows Registry Transaction Log
(`.regtrans-ms`) files. Reads a container from disk and extracts, per
transaction record: **operation subtype, registry key path, value name,
registry type, and value data**.

## Status

Tested against a Windows 11 24H2 transaction log during development.
The sample is not included in this repository. This is a best-effort reader,
not a complete implementation of CLFS or registry transaction recovery.

## What was reverse engineered vs. verified against real data

The CLFS block/record format and the CM TxR payload format were recovered
by static analysis of `clfs.sys`, `tm.sys`, and the Configuration Manager
in `ntoskrnl.exe`. Several details from that phase were **corrected once a
real sample was available** -- notably:

- Blocks begin at file offset 0x1000 (after a container header), at a
  9-sector (0x1200-byte) stride. The reader physically scans for block
  magics rather than relying on restart-area/container metadata.
- The on-disk record subtype is a small remapped integer (1..5 observed),
  not the raw CM op-code. Verified header sizes: subtype 1->0x40, 2->0x40,
  3->0x50, 4->0x50, 5->0x50.
- For 0x50-header records the CM header carries explicit fields:
  0x30 = value-name length, 0x40 = registry type, 0x44 = value-data
  length. (An earlier inference that offset 0x30 was the registry type was
  disproven by real data and removed.)
- The record's "name" is the full key path; the value name follows it,
  and value data follows that -- all length-delimited by header fields.

Anything not confirmed against the sample is commented as such in-source
rather than presented as fact. Subtypes 0/6/7/8/9 were not present in the
sample and are intentionally not mapped (such records are skipped, not
guessed).

## Layout

```
src/
  clfs/   block.rs, fixup.rs, record.rs, mod.rs   -- minimal CLFS reader
  cm/     txr.rs, fragment.rs, parser.rs, mod.rs  -- CM TxR payload parsing
  registry/ decoder.rs, mod.rs                    -- UTF-16 / type decoding
  main.rs                                          -- CLI
tests/    real_sample.rs                           -- optional sample integration test
```

## Usage

```
cargo run --release -- <path-to-.regtrans-ms>
```

Operations print to stdout; block/record/validation summary to stderr.

To build or run the test suite:

```sh
cargo build --release --locked
cargo test --locked
```

The integration test can optionally parse a local sample by setting
`REGTRANS_TEST_SAMPLE` to the file path. The sample is never packaged.

**Evidence handling:** Registry paths and value data can include personal
information. Treat parser output and input log files as case evidence. Don't
commit them to the repository.

## Scope (intentionally NOT implemented)

CLFS writing, restart-area management, container management, reservations,
log growth, client contexts, management APIs, runtime recovery, and CRC
validation. A malformed block may be skipped; output is best-effort and may
be incomplete.
