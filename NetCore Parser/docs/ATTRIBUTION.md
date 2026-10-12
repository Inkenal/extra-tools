# GUID attribution

The parser ships with a reviewed map of diagnostic GUIDs and candidate Windows components. The mappings describe likely **diagnostic families**, not the meaning of an event's payload or the program responsible for network activity.

For an unknown GUID, the parser optionally looks for its 16-byte little-endian representation in 13 named networking DLLs under `System32`. It reads each DLL at most once per case, searches at most 256 unknown GUIDs and skips DLLs above 64 MiB. The search is read-only and never expands to a recursive system scan.

`attribution.json` records the DLL name, file offset, SHA-256 and whether the lookup used the analysis computer or an explicitly supplied Windows directory. A match is a candidate association, not verified provenance. No match does not invalidate an event.

The bundled classifications are based on matching GUIDs to reviewed Windows binaries and examining diagnostic payloads. They can vary with Windows build. In particular, a WPP message GUID is not necessarily the provider control GUID. Interpreting WPP payloads may require symbols or matching trace-format metadata.

Relevant Microsoft documentation:

- [WPP control GUIDs](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/control-guid)
- [Trace message format files](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/trace-message-format-file)
