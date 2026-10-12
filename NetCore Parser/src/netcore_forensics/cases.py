"""Streaming case exports with source-byte integrity checks."""

from __future__ import annotations

import csv
import hashlib
import json
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Iterable

from . import __version__
from .attribution import scan_unknown_guids
from .decoding import annotate, extract_observed_strings, module_map

TIMELINE_FIELDS = [
    'sequence_index', 'timestamp_utc', 'pid', 'tid', 'provider_guid', 'wpp_guid', 'event_id',
    'message_id', 'record_kind', 'classification', 'emitter_module_candidate',
    'interpretation', 'decode_status', 'payload_length',
]

# The first occurrence supplies timestamp_utc; event identity is defined by
# the other visible timeline fields. Summary replaces sequence_index with Counter
# and renames timestamp_utc to First seen (timestamps remain UTC).
SUMMARY_IDENTITY_FIELDS = [
    field for field in TIMELINE_FIELDS if field not in ('sequence_index', 'timestamp_utc')
]
SUMMARY_FIELDS = ['Counter', 'First seen', *TIMELINE_FIELDS[2:]]


def write_summary_csv(source: Path, output: Path) -> tuple[int, int]:
    """Aggregate visible timeline rows with bounded RAM and no hash collisions.

    Unlike a Python Counter of all rows, an on-disk SQLite index scales to
    large traces without retaining the entire timeline in process memory.
    The regular timeline remains unchanged; each summary row records the
    first observed UTC timestamp and how many matching timeline rows occurred.
    Returns (distinct patterns, total occurrences) for case.json reporting.
    """
    with TemporaryDirectory(prefix='.summary_', dir=output.parent) as temporary:
        work = Path(temporary)
        database = sqlite3.connect(work / 'counts.sqlite3')
        try:
            database.execute('PRAGMA cache_size = -8192')  # ~8 MiB SQLite page cache
            database.execute('''
                CREATE TABLE events (
                    identity TEXT PRIMARY KEY,
                    first_timestamp TEXT NOT NULL,
                    first_sequence INTEGER NOT NULL,
                    occurrences INTEGER NOT NULL
                ) WITHOUT ROWID
            ''')
            with source.open('r', encoding='utf-8', newline='') as fp:
                reader = csv.DictReader(fp)
                if reader.fieldnames != TIMELINE_FIELDS:
                    raise ValueError('Timeline CSV columns do not match the expected schema')
                for sequence, row in enumerate(reader):
                    # JSON encoding is unambiguous even if CSV fields contain
                    # delimiters, quotes, newlines, or non-ASCII strings.
                    identity = json.dumps(
                        [row[field] for field in SUMMARY_IDENTITY_FIELDS],
                        ensure_ascii=False, separators=(',', ':'),
                    )
                    database.execute('''
                        INSERT INTO events (identity, first_timestamp, first_sequence, occurrences)
                        VALUES (?, ?, ?, 1)
                        ON CONFLICT(identity) DO UPDATE SET occurrences = occurrences + 1
                    ''', (identity, row['timestamp_utc'], sequence))
            database.commit()
            rows_written = 0
            total_occurrences = 0
            temporary_csv = work / 'Summary.csv'
            with temporary_csv.open('w', encoding='utf-8', newline='', buffering=1024 * 1024) as fp:
                writer = csv.DictWriter(fp, fieldnames=SUMMARY_FIELDS)
                writer.writeheader()
                # This gives stable first-seen order rather than arbitrary
                # grouping order, which is useful for forensic review.
                for identity, first_timestamp, occurrences in database.execute('''
                    SELECT identity, first_timestamp, occurrences
                    FROM events ORDER BY first_sequence
                '''):
                    values = json.loads(identity)
                    row = dict(zip(SUMMARY_IDENTITY_FIELDS, values))
                    row['First seen'] = first_timestamp
                    row['Counter'] = occurrences
                    writer.writerow(row)
                    rows_written += 1
                    total_occurrences += occurrences
            temporary_csv.replace(output)
            return rows_written, total_occurrences
        finally:
            database.close()


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as fp:
        for block in iter(lambda: fp.read(4 * 1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def native_jsonl(path: Path) -> Iterable[dict]:
    """Read previous native exports without inferring missing payloads."""
    with path.open(encoding='utf-8-sig') as fp:
        for lineno, line in enumerate(fp, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f'{path}:{lineno}: invalid JSON: {exc}') from exc
            if not isinstance(event, dict):
                raise ValueError(f'{path}:{lineno}: expected JSON object')
            payload_hex = event.get('payload_hex')
            if payload_hex is not None and not isinstance(payload_hex, str):
                raise ValueError(f'{path}:{lineno}: payload_hex must be a string')
            if 'payload_length' not in event:
                event['payload_length'] = len(payload_hex or '') // 2
            if (not isinstance(event['payload_length'], int)
                    or isinstance(event['payload_length'], bool)
                    or event['payload_length'] < 0):
                raise ValueError(f'{path}:{lineno}: payload_length must be a nonnegative integer')
            event.setdefault('event_id', event.get('message_id'))
            event.setdefault('extraction_method', 'imported_native_jsonl')
            yield event


def _top(counter: Counter, n: int = 40) -> list[dict]:
    return [{'value': str(value), 'count': count} for value, count in counter.most_common(n)]


# Event-family coverage groups by the same (WPP message GUID if available,
# otherwise ETW provider GUID, event ID) key used by top_message_types.
# These statuses represent parsing coverage, not verified forensic semantics.
DECODE_STATUSES = (
    'partial_layout', 'empty_payload', 'opaque_payload',
    'tdh_fields_only', 'trace_metadata', 'payload_error',
)


def message_type_coverage(messages: Counter, statuses: Counter,
                          first_opaque: dict) -> list[dict]:
    """Summarize all observed message types using bounded aggregate counters.

    No additional pass over events.jsonl and no payload retention is required.
    The result includes *every* message type, ordered by observed frequency.
    """
    # Index each aggregate once; avoid scanning all types for every type.
    unexpected = {}
    for (guid, event_id, status), count in statuses.items():
        if status not in DECODE_STATUSES:
            unexpected.setdefault((guid, event_id), {})[status] = count
    results = []
    for (guid, event_id), total in messages.most_common():
        by_status = {
            status: statuses.get((guid, event_id, status), 0)
            for status in DECODE_STATUSES
        }
        other_statuses = unexpected.get((guid, event_id), {})
        result = {'guid': guid, 'event_id': event_id, 'total': total,
                  **by_status, 'opaque_percent': round(100 * by_status['opaque_payload'] / total, 2),
                  'first_opaque_sequence_index': first_opaque.get((guid, event_id))}
        if other_statuses:
            result['other_statuses'] = other_statuses
        results.append(result)
    return results


def normalize_reader_stats(stats: dict | None) -> dict | None:
    """Don't report a zero buffer count as an observed fact after reading events.

    Older reader output supplied zero for EVENT_TRACE_LOGFILEW.BuffersRead on
    successful captures. We retain the raw API field but mark the measurement
    unavailable; we do *not* infer buffer loss or change the native ETW reader.
    """
    if stats is None:
        return None
    normalized = dict(stats)
    value = normalized.get('buffers_read')
    if value == 0 and normalized.get('events_read', 0) > 0:
        normalized['buffers_read_raw'] = 0
        normalized['buffers_read'] = None
        normalized['buffers_read_status'] = 'unavailable_zero_with_events'
    elif isinstance(value, int) and value > 0:
        normalized['buffers_read_status'] = 'reported_by_windows_api_unverified'
    else:
        normalized['buffers_read_status'] = 'unavailable'
    return normalized


class CaseWriter:
    """Write once, stream every event, close before manifest is committed."""

    def __init__(self, source: Path, output: Path, source_kind: str, no_payload: bool = False,
                 include_trace_metadata_in_timeline: bool = False,
                 reference_event_count: int | None = None,
                 extract_strings: bool = True,
                 attribution_windows_dir: Path | None = None,
                 attribution_origin: str = 'not_configured'):
        self.source = source
        self.output = output
        self.source_kind = source_kind
        self.no_payload = no_payload
        self.extract_strings = extract_strings
        self.attribution_windows_dir = attribution_windows_dir
        self.attribution_origin = attribution_origin
        self.include_trace_metadata_in_timeline = include_trace_metadata_in_timeline
        if reference_event_count is not None and reference_event_count < 0:
            raise ValueError('Reference event count cannot be negative')
        self.reference_event_count = reference_event_count
        self.before_hash = file_hash(source)
        self.sources = module_map()
        self.stats: Counter = Counter()
        self.providers: Counter = Counter()
        self.classes: Counter = Counter()
        self.decode_statuses: Counter = Counter()
        self.unknown_providers: Counter = Counter()
        self.unknown_guids: Counter = Counter()
        self.messages: Counter = Counter()
        self.message_decode_statuses: Counter = Counter()
        self.first_opaque_message_index: dict[tuple[str, int | None], int] = {}
        self.first: str | None = None
        self.last: str | None = None
        self._closed = False
        self._committed = False

    def __enter__(self) -> 'CaseWriter':
        self.output.mkdir(parents=True, exist_ok=True)
        (self.output / 'INCOMPLETE').write_text(
            'Export did not finish. Treat outputs as partial until this marker disappears.\n',
            encoding='utf-8',
        )
        self.json_file = (self.output / 'events.jsonl').open('w', encoding='utf-8', newline='\n', buffering=1024 * 1024)
        self.csv_file = (self.output / 'timeline.csv').open('w', encoding='utf-8', newline='', buffering=1024 * 1024)
        self.timeline = csv.DictWriter(self.csv_file, fieldnames=TIMELINE_FIELDS,
                                       extrasaction='ignore')
        self.timeline.writeheader()
        return self

    def append(self, event: dict) -> None:
        if self._closed:
            raise RuntimeError('case writer already closed')
        event['sequence_index'] = self.stats['events']
        # Parse hexadecimal bytes once per record, and only when a consumer
        # needs them. Full payload hex is still preserved in the evidence file.
        payload_hex = event.get('payload_hex')
        payload = None
        if payload_hex:
            if self.no_payload and not event.get('wpp_guid'):
                # No decoder uses this payload and it will not be exported.
                payload = None
            else:
                try:
                    payload = bytes.fromhex(payload_hex)
                except ValueError:
                    event['payload_error'] = 'not_valid_hex'
        event = annotate(event, self.sources, payload=payload)
        if payload_hex:
            # Count source payloads independently of optional export settings.
            self.stats['with_raw_payload'] += 1
        if payload is not None:
            event['observed_strings'] = (extract_observed_strings(payload)
                                         if self.extract_strings else [])
        else:
            # For payloads deliberately omitted, do not scan large hex strings.
            event['observed_strings'] = []
        if self.no_payload:
            for field in ('payload_hex', 'native_event_xml', 'extended_data'):
                event.pop(field, None)
        self.json_file.write(json.dumps(event, ensure_ascii=False, separators=(',', ':')) + '\n')
        is_header = event['record_kind'] == 'trace_session_header'
        if not is_header or self.include_trace_metadata_in_timeline:
            self.timeline.writerow(event)
            self.stats['timeline_records'] += 1
        self.stats['trace_session_headers'] += is_header
        self.stats['events'] += 1
        self.stats['with_wpp_guid'] += bool(event.get('wpp_guid'))
        self.stats['partially_decoded'] += bool(event.get('decoded_fields'))
        self.providers[event.get('provider_guid') or '(missing)'] += 1
        self.classes[event['classification']] += 1
        self.decode_statuses[event['decode_status']] += 1
        if event['classification'] == 'unclassified_etw_event':
            self.unknown_providers[event.get('provider_guid') or '(missing)'] += 1
            # WPP message and ETW provider GUIDs can differ; inspect each once.
            self.unknown_guids.update({
                guid: 1 for guid in (event.get('wpp_guid'), event.get('provider_guid'))
                if guid
            })
        message_key = (event.get('wpp_guid') or event.get('provider_guid') or '',
                       event.get('event_id'))
        self.messages[message_key] += 1
        status = event['decode_status']
        self.message_decode_statuses[(*message_key, status)] += 1
        if status == 'opaque_payload':
            self.first_opaque_message_index.setdefault(message_key, event['sequence_index'])
        stamp = event.get('timestamp_utc')
        if stamp is not None:
            if not isinstance(stamp, str):
                raise ValueError('timestamp_utc must be an ISO-8601 string')
            self.first = stamp if self.first is None or stamp < self.first else self.first
            self.last = stamp if self.last is None or stamp > self.last else self.last
        if self.stats['events'] % 50_000 == 0:
            print(f'[progress] {self.stats["events"]:,} events', flush=True)

    def finish(self, reader_stats: dict | None = None) -> dict:
        self._close()
        after_hash = file_hash(self.source)
        if self.before_hash != after_hash:
            raise RuntimeError(
                'Input changed during extraction. Preserve a stable copy of the ETL or JSONL '
                'and rerun; current outputs are marked INCOMPLETE.'
            )
        # Build the compact view after the append-only evidentiary exports have
        # closed. This never changes event acquisition or original timeline data.
        try:
            summary_rows, summary_occurrences = write_summary_csv(
                self.output / 'timeline.csv', self.output / 'Summary.csv'
            )
            if summary_occurrences != self.stats['timeline_records']:
                raise RuntimeError('Summary occurrence count differs from the source timeline')
        except sqlite3.Error as exc:
            raise RuntimeError(f'Unable to build Summary.csv: {exc}') from exc
        coverage = message_type_coverage(
            self.messages, self.message_decode_statuses, self.first_opaque_message_index,
        )
        opaque_priorities = sorted(
            (item for item in coverage if item['opaque_payload']),
            key=lambda item: (-item['opaque_payload'], -item['total'], item['guid'],
                              -1 if item['event_id'] is None else item['event_id']),
        )
        # Run attribution after closing append-only evidence exports. It does
        # not change event classification, payload bytes or timeline fields.
        attribution = scan_unknown_guids(
            self.unknown_guids, self.attribution_windows_dir,
            origin=self.attribution_origin,
        )
        summary = {
            'tool': 'netcore-forensics', 'version': __version__,
            'generated_utc': datetime.now(timezone.utc).isoformat(),
            'source': {
                'path_at_analysis': str(self.source.resolve()),
                'type': self.source_kind,
                'bytes': self.source.stat().st_size,
                'sha256': self.before_hash,
            },
            'events': self.stats['events'],  # backward-compatible with RC1
            'native_records_total': self.stats['events'],
            'trace_session_headers': self.stats['trace_session_headers'],
            'windows_comparable_events': (
                self.stats['events'] - self.stats['trace_session_headers']
            ),
            'timeline_records': self.stats['timeline_records'],
            'summary_rows': summary_rows,
            'summary_occurrences': summary_occurrences,
            'timeline_trace_metadata_included': self.include_trace_metadata_in_timeline,
            'first_timestamp_utc': self.first, 'last_timestamp_utc': self.last,
            'with_wpp_guid': self.stats['with_wpp_guid'],
            'partially_decoded': self.stats['partially_decoded'],
            'with_raw_payload': self.stats['with_raw_payload'],
            'observed_strings_extracted': self.extract_strings,
            'native_reader_stats': normalize_reader_stats(reader_stats),
            'top_providers': _top(self.providers), 'classes': _top(self.classes),
            'decode_statuses': _top(self.decode_statuses),
            'top_unclassified_providers': _top(self.unknown_providers, 20),
            'unknown_guid_attribution': {
                'file': 'attribution.json',
                'status': attribution['status'],
                'binary_origin': attribution['binary_origin'],
                'unknown_guid_count': attribution['unknown_guid_count'],
                'matched_guid_count': attribution['matched_guid_count'],
                'unresolved_guid_count': attribution['unresolved_guid_count'],
                'unscanned_guid_count': attribution['unscanned_guid_count'],
            },
            'top_message_types': [
                {'guid': guid, 'event_id': event_id, 'count': count}
                for (guid, event_id), count in self.messages.most_common(100)
            ],
            'decoding_coverage_by_message_type': coverage,
            'top_opaque_message_types': opaque_priorities[:30],
            'limitations': [
                'Family classifications do not establish individual network connections.',
                'Opaque WPP payloads may require provider-specific format metadata.',
                'Summary.csv groups timeline fields, not the complete binary payload.',
                'A GUID match in a DLL is an association, not proof of event origin.',
                'Circular retention and provider settings can limit the recorded history.',
            ],
        }
        if self.reference_event_count is not None:
            summary['reference_event_count'] = self.reference_event_count
            summary['count_difference'] = (
                summary['windows_comparable_events'] - self.reference_event_count
            )
        (self.output / 'attribution.json').write_text(
            json.dumps(attribution, indent=2, ensure_ascii=False) + '\n', encoding='utf-8'
        )
        (self.output / 'case.json').write_text(
            json.dumps(summary, indent=2, ensure_ascii=False) + '\n', encoding='utf-8'
        )
        (self.output / 'README.txt').write_text(
            'Read-only forensic export. Verify source SHA-256 and preserve the original.\n'
            'events.jsonl preserves every callback, including trace-session headers.\n'
            'timeline.csv excludes trace-session headers by default.\n'
            'Summary.csv groups matching visible timeline fields; Counter gives\n'
            'occurrences and First seen is the first observed UTC timestamp. It does not\n'
            'prove that unexported payload bytes are identical.\n'
            'decode_status is independent of event classification.\n'
            'case.json documents coverage by GUID/event ID, interpretation limits, and timestamps.\n'
            'attribution.json lists binary GUID matches for unresolved providers.\n',
            encoding='utf-8',
        )
        self._write_report(summary)
        (self.output / 'INCOMPLETE').unlink()
        self._committed = True
        return summary

    def _write_report(self, summary: dict) -> None:
        lines = [
            '# NetCore forensic case summary', '',
            f"Analysis tool: netcore-forensics {summary['version']}",
            f"Source: `{summary['source']['path_at_analysis']}`",
            f"Source SHA-256: `{summary['source']['sha256']}`",
            f"Analysis time (UTC): {summary['generated_utc']}",
            f"Native records consumed: {summary['native_records_total']:,}",
            f"Recognized trace-session headers: {summary['trace_session_headers']:,}",
            f"Windows-comparable events: {summary['windows_comparable_events']:,}",
            f"Timeline rows: {summary['timeline_records']:,}",
            f"Summary.csv distinct rows: {summary['summary_rows']:,}",
            f"Summary.csv total occurrences: {summary['summary_occurrences']:,}",
            f"First event UTC: {summary['first_timestamp_utc'] or 'not available'}",
            f"Last event UTC: {summary['last_timestamp_utc'] or 'not available'}",
            f"Events with raw payload: {summary['with_raw_payload']:,}",
            f"Events with a candidate WPP GUID: {summary['with_wpp_guid']:,}",
            f"Events with a partial interpretation: {summary['partially_decoded']:,}",
            '', '## Decoding coverage', '',
        ]
        lines.extend(f"- {item['value']}: {item['count']:,}" for item in summary['decode_statuses'])
        lines.extend(['', '## Event-type decoding coverage (most frequent)', '',
                      'Event-type key: candidate WPP GUID if present, otherwise ETW provider GUID, plus event ID.',
                      'The status columns report extraction coverage, not the semantic accuracy of a decoded layout.',
                      '',
                      '| GUID | ID | Total | Partial | Empty | Opaque | TDH-only | Errors |',
                      '|---|---:|---:|---:|---:|---:|---:|---:|'])
        for item in summary['decoding_coverage_by_message_type'][:12]:
            lines.append(
                f"| `{item['guid']}` | {item['event_id']} | {item['total']:,} | "
                f"{item['partial_layout']:,} | {item['empty_payload']:,} | "
                f"{item['opaque_payload']:,} | {item['tdh_fields_only']:,} | "
                f"{item['payload_error']:,} |"
            )
        if not summary['decoding_coverage_by_message_type']:
            lines.append('| *(no records)* | | | | | | | |')
        lines.extend(['', '## Priority opaque message types (largest first)', '',
                      'Counts of records whose payload fields are not decoded.',
                      'The sequence index identifies a raw example in `events.jsonl`.', '',
                      '| GUID | ID | Opaque | Total | Opaque % | First opaque sequence index |',
                      '|---|---:|---:|---:|---:|---:|'])
        for item in summary['top_opaque_message_types'][:12]:
            lines.append(
                f"| `{item['guid']}` | {item['event_id']} | "
                f"{item['opaque_payload']:,} | {item['total']:,} | "
                f"{item['opaque_percent']:.2f}% | {item['first_opaque_sequence_index']} |"
            )
        if not summary['top_opaque_message_types']:
            lines.append('| *(no opaque payloads)* | | | | | |')
        lines.extend(['', '## Native buffer statistics', ''])
        reader_stats = summary['native_reader_stats']
        if reader_stats is None:
            lines.append('Not available for imported JSONL (no native ETL reader was used).')
        else:
            buffer_count = reader_stats.get('buffers_read')
            lines.append('Buffers read: ' + (str(buffer_count) if buffer_count is not None
                                             else 'unavailable (zero returned despite events)'))
            if 'buffers_read_raw' in reader_stats:
                lines.append(f"Raw Windows API BuffersRead field: {reader_stats['buffers_read_raw']}")
            lines.append('Buffer and loss fields are not independent completeness checks.')
        attr = summary['unknown_guid_attribution']
        if attr['unknown_guid_count']:
            lines.extend(['', '## Unknown-GUID source-binary attribution', '',
                          f"Status: {attr['status']}",
                          f"Binary origin: {attr['binary_origin']}",
                          f"Unclassified GUIDs: {attr['unknown_guid_count']:,}",
                          f"GUIDs with binary hits: {attr['matched_guid_count']:,}",
                          f"GUIDs without allowlist matches: {attr['unresolved_guid_count']:,}",
                          f"GUIDs not scanned: {attr['unscanned_guid_count']:,}"])
        lines.extend(['', '## Event classification', ''])
        if 'reference_event_count' in summary:
            lines.extend([
                f"Independent reference count: {summary['reference_event_count']:,}",
                f"Comparable events minus reference: {summary['count_difference']:+,}",
            ])
        for item in summary['classes']:
            lines.append(f"- {item['value']}: {item['count']:,}")
        if summary['top_unclassified_providers']:
            lines.extend(['', '## Unclassified providers', ''])
            lines.extend(
                f"- {item['value']}: {item['count']:,}"
                for item in summary['top_unclassified_providers']
            )
        lines.append('')
        (self.output / 'report.md').write_text('\n'.join(lines), encoding='utf-8')

    def _close(self) -> None:
        if not self._closed:
            self.json_file.close()
            self.csv_file.close()
            self._closed = True

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self._close()


def verify_source(case_dir: Path) -> bool:
    data = json.loads((case_dir / 'case.json').read_text(encoding='utf-8'))
    source = Path(data['source']['path_at_analysis'])
    if not source.exists():
        raise FileNotFoundError(f'Source no longer at recorded path: {source}')
    return file_hash(source) == data['source']['sha256']
