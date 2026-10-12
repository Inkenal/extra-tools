# Forensic methodology and data quality

## Ingestion

`parse` consumes offline ETLs through the Windows ETW API. It does not search
for guessed WPP records in unused circular-buffer space. `EVENT_RECORD` gives
us header and payload in one callback: capture those fields together. Output
order is callback delivery order; `sequence_index` is an analysis index, **not**
a Windows EventRecordID.

`import-native` consumes an existing native JSONL export. It can only preserve
fields present in that export. A missing binary payload cannot be inferred.

## Trace-session metadata versus investigative events

The `EventTrace_Header` event class (event type 0) contains ETW session
configuration in a `TRACE_LOGFILE_HEADER` payload. The native reader can
return the header even when Get-WinEvent omits it. Header identification
requires the known trace-control GUID, type/opcode 0, and plausible
documented fixed fields (including buffer size and pointer size). Do not
interpret every event ID 0 or every record from that provider as a header.

All callbacks remain in `events.jsonl` with their original payload and
`sequence_index`. Identified headers have `record_kind=trace_session_header`
and `trace_session_metadata`. Ordinary `timeline.csv` omits those rows unless
requested. `case.json` differentiates `native_records_total`,
`trace_session_headers`, and `windows_comparable_events`.

Independent reference counts must come from the exact same stable ETL.
`--reference-event-count` records that count and the difference; it does
not query or otherwise validate Get-WinEvent itself. A zero count difference
is only one of several required validation checks.

## Compact timeline summary

`timeline.csv` is the unmodified per-event investigative view (trace-session
headers are omitted by default). `Summary.csv` keeps the other timeline columns,
replaces `sequence_index` with `Counter`, and renames `timestamp_utc` to
`First seen` (UTC). Only the **visible columns** are compared: `sequence_index` and `timestamp_utc` are excluded
from the grouping key, and the first observed UTC timestamp appears under `First seen`.
All other visible fields, including PID, TID, GUIDs, classification,
message ID, and payload length, remain part of the grouping key. The sum
of `Counter` must equal the number of rows in `timeline.csv`. This
same aggregation supplies `summary_rows` and `summary_occurrences` in
`case.json`. The other case-level counters group more broadly (by class or
message type) and cannot recover the detailed timeline field combinations.

This grouping is not proof of equal raw payload bytes or equal event
semantics: fields not exposed in the timeline cannot be compared by this
summary. Investigators must use `events.jsonl` for complete original payload
information. SQLite temporary storage keeps memory usage bounded and is
removed after the summary has been committed.

## Source identity

SHA-256 is computed before and after reading. If the source changes, the case
stays marked `INCOMPLETE`. These checks demonstrate which bytes were analyzed;
they do not establish acquisition provenance, tool validation, operator identity,
chain of custody, or integrity of every other copy.

## Event meaning

The same network interface GUID can recur across sessions and logs. It is a
correlation key, not proof of a connection to a remote host. `event_id` is an
ETW descriptor identifier; WPP message IDs require additional metadata and
may not equal it. An absent or zero ETW provider GUID does not imply the
original WPP message GUID was zero.

- **Confirmed**: event timestamp from ETW, provider ID, PID, TID, descriptor,
  original payload byte sequence and available TDH property values.
- **Observed**: readable byte strings, candidate identifiers, fixed-size data.
- **Inferred**: module candidate from DLL/GUID research, known function names
  reconstructed from observed formats.
- **Unknown**: unformatted/opaque fields; no semantics asserted.

The project does not invent process names or correlate PIDs to executable
images unless separately acquired process creation/termination evidence is
available. PID reuse is common.

## Data loss and coverage

Circular traces retain only a rolling window. ETW buffers can be lost or an
AutoLogger may be configured at levels that omit useful event types. A
negative result is not proof of non-execution or non-communication.

## Known limitations

- Public Microsoft WPP TMFs may not exist for the target Windows build.
- WPP TraceGuid extraction through TDH may fail; events remain in the case.
- The old raw-carver is deliberately not part of 1.0 production ingestion.
- The native `ctypes` reader/header logic was count-reconciled on one Windows 11
  snapshot, but still requires broader Windows regression validation before 1.0.0.
- No automatic IP/port attribution, malicious verdicts, YARA signatures, or
  remote lookups are included.

## Reference API documentation

- https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nc-evntrace-pevent_record_callback
- https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilew
- https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_record
- https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracew
- https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace
- https://learn.microsoft.com/en-us/windows/win32/etw/using-tdhformatproperty-to-consume-event-data
