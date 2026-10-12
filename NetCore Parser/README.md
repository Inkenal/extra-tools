# NetCore Forensics

A command-line parser for Windows `NetCore.etl` traces. It uses the native ETW reader to export event headers and payloads, with limited decoding for known networking diagnostic formats.

**Status:** pre-release (`1.0.0rc12`). Tested with Python 3.11+; native ETL input requires 64-bit Python on Windows. Validation across different Windows builds is still limited.

## Install

```powershell
py -3 -m pip install .
```

The package uses Python's standard library and Windows system APIs. It does not require PowerShell scripts or a network service.

## Parse an ETL

Work from a stable copy of the ETL. `C:\Windows\System32\LogFiles\WMI\NetCore.etl` is normally a live, circular trace; copying it while it is being written may produce inconsistent evidence.

```powershell
py -3 -m netcore_forensics parse "D:\Evidence\NetCore.etl" -o "D:\Cases\NetCore01"
```

An omitted input path defaults to the system NetCore ETL, but a stable copy is recommended. The output directory must be empty or nonexistent. A failed or interrupted export retains an `INCOMPLETE` file.

The case directory contains:

| File | Contents |
|---|---|
| `events.jsonl` | Every native event, including recognized trace headers and raw payloads |
| `timeline.csv` | One row per event; excludes trace headers by default |
| `Summary.csv` | Counts matching timeline rows and retains their first observed UTC timestamp |
| `case.json` | Source SHA-256, counts, classifications and decoding coverage |
| `report.md` | Compact case report |
| `attribution.json` | Binary GUID matches for unclassified event families |

`Summary.csv` groups the **visible timeline columns**, not the full raw payload. Events with different binary payloads can share one summary row. Refer to `events.jsonl` when payload identity matters.

## Search and verify

```powershell
py -3 -m netcore_forensics search "D:\Cases\NetCore01\events.jsonl" --pid 1234
py -3 -m netcore_forensics search "D:\Cases\NetCore01\events.jsonl" --decode-status opaque_payload
py -3 -m netcore_forensics info "D:\Cases\NetCore01"
py -3 -m netcore_forensics verify "D:\Cases\NetCore01"
```

`verify` compares the current source file against the SHA-256 saved when the case was created; it is not a chain-of-custody check. Use `--help` for all filters and options.

To process an older JSONL export instead of an ETL:

```powershell
py -3 -m netcore_forensics import-native "D:\Evidence\native.jsonl" -o "D:\Cases\Imported"
```

## Unrecognized GUIDs

On Windows, an ETL parse checks a fixed list of 13 networking DLLs when it encounters an unclassified provider or message GUID. It does not scan directories recursively. Results are recorded in `attribution.json` and do not change event classifications or decoding status.

The default lookup uses DLLs from the **analysis computer**. If the ETL came from another PC, those DLLs may not match the source. Use `--windows-dir "E:\Windows"` only when a suitable copy of the source Windows directory is available. A GUID found in a DLL is a reference, not proof that the DLL emitted an event.

## Scope and limitations

- Source payload bytes, timestamps, identifiers and event metadata are preserved. Layout interpretation is partial unless a verified decoder applies.
- NetCore captures Windows connectivity diagnostics. It is **not** a complete history of websites, remote endpoints or which executables opened sockets.
- Circular retention, trace configuration and missing WPP metadata limit the evidence available. Absence of an event does not prove an activity did not happen.
- ETLs and exports may contain usernames, local addresses, hostnames, device identifiers and installed software information. **Do not publish case files or real ETL captures to GitHub without reviewing and sanitizing them.**

For the field definitions and attribution approach, see [methodology](docs/METHODOLOGY.md) and [binary attribution](docs/ATTRIBUTION.md).

## Development

```bash
python -m pip install -e . pytest
python -m pytest -q
python -m compileall -q src
```

CI runs the unit tests on Windows and Linux. A genuine Windows ETL integration test remains necessary before a stable release.

## License

MIT. Windows DLLs and tracing symbols are not included.
