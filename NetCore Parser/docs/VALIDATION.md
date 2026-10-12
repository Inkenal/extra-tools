# Validation

The native ETW reader was count-reconciled against `Get-WinEvent` on a stable Windows 11 NetCore snapshot. The native callback returned one additional trace-session header; the comparable-event count matched Windows after that header was identified by its structure.

Unit tests cover ETW structure layouts, trace-header recognition, conservative payload extraction, source hashing, CSV aggregation, unknown GUID attribution and CLI errors. The tests do **not** independently validate every inferred payload field or every Windows version.

Before calling this a stable release:

1. Parse stable ETLs on several supported Windows builds and compare event counts with `Get-WinEvent` on the exact same file.
2. Validate representative decoded fields against independently known event meanings and recorded raw bytes.
3. Check round-trip case exports, source hashing and interruption recovery.
4. Measure runtime and peak memory on slower Windows PCs.
5. Review any new sample data for private information before publishing it.

The repository contains synthetic test fixtures, not raw user ETL files.
