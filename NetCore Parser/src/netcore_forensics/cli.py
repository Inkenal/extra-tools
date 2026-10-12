"""Command line interface for NetCore ETW evidence analysis."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from .cases import CaseWriter, native_jsonl, verify_source

DEFAULT_NETCORE_ETL = Path(r'C:\Windows\System32\LogFiles\WMI\NetCore.etl')


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='netcore-forensics', description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for cmd, label in [('parse', 'Read an ETL using native Windows ETW APIs'),
                       ('import-native', 'Import previously exported native JSONL')]:
        operation = sub.add_parser(cmd, help=label)
        if cmd == 'parse':
            operation.add_argument('source', nargs='?', type=Path, default=DEFAULT_NETCORE_ETL,
                                   help='ETL snapshot; defaults to live Windows NetCore.etl '
                                        '(copy it first for reliable hashing)')
        else:
            operation.add_argument('source', type=Path)
        operation.add_argument('-o', '--output', required=True, type=Path,
                               help='New case directory, must not contain existing results')
        operation.add_argument('--skip-strings', action='store_true',
                               help='Skip heuristic printable-string scanning for faster analysis; raw payloads remain available')
        operation.add_argument('--without-payload', action='store_true',
                               help='Omit raw payload bytes (not recommended for forensic cases)')
        operation.add_argument('--include-trace-metadata-in-timeline', action='store_true',
                               help='Include ETW trace-session headers in timeline.csv')
        operation.add_argument('--windows-dir', type=Path,
                               help='Windows directory from the traced PC (e.g. E:\\Windows); '
                                    'used for bounded binary association')
        operation.add_argument('--reference-event-count', type=int,
                               help='Independent Get-WinEvent event count from the SAME stable ETL')
        if cmd == 'parse':
            operation.add_argument('--skip-tdh', action='store_true',
                                   help='Skip optional Windows TDH property lookups for speed')
    search = sub.add_parser('search', help='Search an existing case without loading it into RAM')
    search.add_argument('events', type=Path, help='events.jsonl')
    search.add_argument('--pid', type=int)
    search.add_argument('--guid', help='WPP message or ETW provider GUID')
    search.add_argument('--event-id', type=int)
    search.add_argument('--classification')
    search.add_argument('--decode-status', help='Filter independently reported decoding coverage')
    search.add_argument('--record-kind', choices=('event', 'trace_session_header'))
    search.add_argument('--module', help='Exact candidate emitter module')
    search.add_argument('--full', action='store_true', help='Print complete JSONL records')
    search.add_argument('--text', help='Case-insensitive substring across decoded fields')
    search.add_argument('--since', help='Inclusive UTC ISO-8601 timestamp')
    search.add_argument('--until', help='Inclusive UTC ISO-8601 timestamp')
    search.add_argument('--limit', type=int, default=50)
    verify = sub.add_parser('verify', help='Verify source SHA-256 from case.json')
    verify.add_argument('case_directory', type=Path)
    info = sub.add_parser('info', help='Print case.json')
    info.add_argument('case_directory', type=Path)
    return parser


def _prepare_output(output: Path, source: Path) -> None:
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise FileExistsError(f'Output directory is not empty: {output}')
    if output.resolve() == source.resolve():
        raise ValueError('Output cannot equal source')


def _parse_etl(path: Path, case: CaseWriter, use_tdh: bool) -> dict:
    """Direct callback, no custom worker threads or event reconstruction."""
    from .etw import consume_etl

    source_map = case.sources

    def on_record(event: dict) -> None:
        # Provider and WPP message GUIDs are distinct identifiers in many ETW
        # sessions. Treat this as a candidate only when directly mapped.
        guid = event['provider_guid'].lower()
        event['wpp_guid'] = event.get('wpp_guid') or (guid if guid in source_map else None)
        case.append(event)

    return consume_etl(path, on_record, use_tdh=use_tdh)


def _utc_timestamp(value: str) -> datetime:
    try:
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError(f'Invalid ISO-8601 timestamp: {value!r}') from exc
    if stamp.tzinfo is None:
        raise ValueError(f'Timestamp requires a UTC offset or Z: {value}')
    return stamp.astimezone(timezone.utc)


def _search(args: argparse.Namespace) -> int:
    if args.limit < 1:
        raise ValueError('--limit must be positive')
    since = _utc_timestamp(args.since) if args.since else None
    until = _utc_timestamp(args.until) if args.until else None
    if since and until and since > until:
        raise ValueError('--since must not exceed --until')
    count = 0
    with args.events.open('r', encoding='utf-8') as fp:
        for line in fp:
            if not line.strip():
                continue
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError('Search input must contain JSON objects')
            if args.pid is not None and event.get('pid') != args.pid:
                continue
            if args.guid and args.guid.strip('{}').lower() not in {
                (event.get('wpp_guid') or '').lower(),
                (event.get('provider_guid') or '').strip('{}').lower(),
            }:
                continue
            if args.event_id is not None and event.get('event_id') != args.event_id:
                continue
            if args.classification and event.get('classification') != args.classification:
                continue
            if args.decode_status and event.get('decode_status') != args.decode_status:
                continue
            if args.record_kind and event.get('record_kind', 'event') != args.record_kind:
                continue
            if args.module and (event.get('emitter_module_candidate') or '').lower() != args.module.lower():
                continue
            if since or until:
                text_stamp = event.get('timestamp_utc')
                if not text_stamp:
                    continue
                stamp = _utc_timestamp(text_stamp)
                if since and stamp < since:
                    continue
                if until and stamp > until:
                    continue
            if args.text:
                # Large raw-hex fields are not meaningful free-text search targets.
                searchable = {key: value for key, value in event.items()
                              if key not in {'payload_hex', 'native_event_xml', 'extended_data'}}
                if args.text.casefold() not in json.dumps(searchable, ensure_ascii=False).casefold():
                    continue
            if not args.full:
                event = {k: event.get(k) for k in (
                    'sequence_index', 'timestamp_utc', 'pid', 'tid', 'provider_guid',
                    'wpp_guid', 'event_id', 'classification', 'decode_status', 'emitter_module_candidate',
                    'event_data', 'decoded_fields', 'observed_strings', 'payload_length'
                ) if event.get(k) is not None}
            print(json.dumps(event, ensure_ascii=False))
            count += 1
            if count >= args.limit:
                break
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command in {'parse', 'import-native'}:
            if not args.source.is_file():
                raise FileNotFoundError(args.source)
            _prepare_output(args.output, args.source)
            source_kind = 'etl' if args.command == 'parse' else 'previously_exported_native_jsonl'
            if args.command == 'parse' and args.source.suffix.lower() != '.etl':
                raise ValueError('Expected an .etl file')
            # The default local lookup describes the analysis computer. A
            # copied ETL may originate elsewhere, so provenance remains clear.
            if args.windows_dir is not None:
                windows_dir = args.windows_dir
                attribution_origin = 'investigator_supplied_windows_directory'
                if not (windows_dir / 'System32').is_dir():
                    raise ValueError('--windows-dir must contain a System32 directory')
            elif args.command == 'parse' and sys.platform == 'win32':
                windows_dir = Path(os.environ.get('SystemRoot', r'C:\Windows'))
                attribution_origin = 'analysis_computer_not_proven_trace_source'
            else:
                windows_dir = None
                attribution_origin = 'not_available_without_explicit_windows_directory'
            with CaseWriter(
                args.source, args.output, source_kind,
                no_payload=args.without_payload,
                include_trace_metadata_in_timeline=args.include_trace_metadata_in_timeline,
                reference_event_count=args.reference_event_count,
                extract_strings=not args.skip_strings,
                attribution_windows_dir=windows_dir,
                attribution_origin=attribution_origin,
            ) as case:
                if args.command == 'parse':
                    stats = _parse_etl(args.source, case, use_tdh=not args.skip_tdh)
                else:
                    for event in native_jsonl(args.source):
                        case.append(event)
                    stats = None
                summary = case.finish(reader_stats=stats)
            result = {
                'native_records_total': summary['native_records_total'],
                'trace_session_headers': summary['trace_session_headers'],
                'windows_comparable_events': summary['windows_comparable_events'],
                'output': str(args.output),
                'source_sha256': summary['source']['sha256'],
            }
            if 'reference_event_count' in summary:
                result['reference_event_count'] = summary['reference_event_count']
                result['count_difference'] = summary['count_difference']
            print(json.dumps(result, indent=2))
            return 0
        if args.command == 'search':
            return _search(args)
        if args.command == 'verify':
            match = verify_source(args.case_directory)
            print('MATCH' if match else 'MISMATCH')
            return 0 if match else 2
        if args.command == 'info':
            print((args.case_directory / 'case.json').read_text(encoding='utf-8'))
            return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    return 1
