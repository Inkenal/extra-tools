# Changelog

## 1.0.0rc12

- Review and simplify the repository documentation and generated case report.
- Reject malformed JSONL payload types and payload lengths with a clear error.
- Handle invalid timestamp values in the search command without a traceback.
- Replace machine-specific test payload identifiers with synthetic fixtures.
- Keep native ETL acquisition, payload decoders and case export formats unchanged.

## 1.0.0rc11

- Add bounded, read-only GUID lookup in selected Windows networking DLLs.
- Keep lookup results in `attribution.json`, separate from event classification.

## Earlier candidates

- Native ETL ingestion, source hashing, trace-header recognition, CSV exports, event classification and decoding-coverage reporting.
