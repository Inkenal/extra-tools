//! Integration test against a real .regtrans-ms sample, if present.
//! Set REGTRANS_TEST_SAMPLE to a local sample file to enable this test.
//! It is skipped when no sample path is supplied.

use std::path::Path;
use std::env;
use std::process::Command;

#[test]
fn parses_real_sample_if_present() {
    let Ok(path) = env::var("REGTRANS_TEST_SAMPLE") else {
        eprintln!("REGTRANS_TEST_SAMPLE not set; skipping optional integration test");
        return;
    };
    assert!(Path::new(&path).is_file(), "REGTRANS_TEST_SAMPLE must point to an existing file");

    let out = Command::new(env!("CARGO_BIN_EXE_regtrans_parser"))
        .arg(&path)
        .output()
        .expect("run parser");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // Every emitted key path must start with the registry root -- this is
    // the strongest cheap correctness signal (a wrong header size shifts
    // the path and breaks this).
    let mut key_paths = 0usize;
    for line in stdout.lines() {
        if let Some(kp) = line.strip_prefix("key path:") {
            key_paths += 1;
            let kp = kp.trim();
            assert!(
                kp.starts_with("\\REGISTRY"),
                "malformed key path (likely wrong header size): {:?}",
                kp
            );
        }
    }
    assert!(key_paths > 0, "expected to decode at least one operation");

    // No CLFS record should fail validation on a healthy sample.
    assert!(
        stderr.contains("0 failed validation"),
        "unexpected CLFS validation failures: {}",
        stderr
    );
}
