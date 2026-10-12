"""Synthetic ETW session-header regression fixtures."""

import csv
import json
import struct
from pathlib import Path

from netcore_forensics.cli import DEFAULT_NETCORE_ETL, build_parser, main
from netcore_forensics.decoding import annotate, module_map
from netcore_forensics.trace_metadata import EVENT_TRACE_CONTROL_GUID, parse_session_header

# Synthetic EventTrace_Header prefix; no captured machine bytes are included.
_HEADER_PREFIX = struct.pack(
    '<IIIIQIIIIII', 131072, 0x0501000A, 19045, 4, 0,
    156250, 16, 0x22, 0, 1, 8,
)


def session_record() -> dict:
    payload = _HEADER_PREFIX + bytes(386 - len(_HEADER_PREFIX))
    return {
        'timestamp_utc': '2025-01-02T09:59:28.000000Z',
        'timestamp_filetime_100ns': 133803719680000000,
        'provider_guid': EVENT_TRACE_CONTROL_GUID,
        'event_id': 0, 'message_id': 0, 'opcode': 0, 'event_version': 2,
        'pid': 4, 'tid': 348, 'header_flags': '0x0340',
        'payload_hex': payload.hex(), 'payload_length': 386,
    }


def first_windows_record() -> dict:
    return {
        'timestamp_utc': '2025-01-02T09:59:28.000000Z',
        'timestamp_filetime_100ns': 133803719680000000,
        'provider_guid': EVENT_TRACE_CONTROL_GUID,
        'event_id': 0, 'message_id': 0, 'opcode': 80, 'event_version': 2,
        'pid': 4, 'tid': 348, 'header_flags': '0x0340',
        'payload_hex': bytes(48).hex(), 'payload_length': 48,
    }


def test_trace_header_detection_requires_structural_evidence():
    header = session_record()
    parsed = parse_session_header(header)
    assert parsed['buffer_size_bytes'] == 131072
    assert parsed['pointer_size_bytes'] == 8
    assert parsed['maximum_file_size_mb'] == 16
    assert parsed['log_file_mode'] == '0x00000022'
    assert parsed['provider_version'] == 19045
    assert parsed['number_of_processors'] == 4
    classified = annotate(header, module_map())
    assert classified['classification'] == 'trace_session_header'
    assert classified['record_kind'] == 'trace_session_header'
    assert classified['interpretation'] == 'trace_session_metadata'

    # The first Windows event is NOT the omitted header, despite the same GUID.
    record = first_windows_record()
    assert parse_session_header(record) is None
    assert annotate(record, module_map())['record_kind'] == 'event'

    # Never classify based on event index, GUID, opcode, or length alone.
    invalid = session_record()
    invalid['payload_hex'] = bytes(386).hex()
    assert parse_session_header(invalid) is None
    invalid = session_record()
    invalid['provider_guid'] = '00000000-0000-0000-0000-000000000000'
    assert parse_session_header(invalid) is None
    invalid = session_record()
    invalid['payload_hex'] = ''
    assert parse_session_header(invalid) is None
    invalid = session_record()
    invalid['event_id'] = 27
    assert parse_session_header(invalid) is None


def test_three_records_produce_two_comparable_events(tmp_path: Path, capsys):
    source = tmp_path / 'captured_native.jsonl'
    third = first_windows_record()
    third.update({'provider_guid': 'c8dbf506-e3d3-4822-930d-84c557eb6247',
                  'event_id': 2005, 'message_id': 2005, 'opcode': 0})
    source.write_text(''.join(json.dumps(item) + '\n'
                              for item in [session_record(), first_windows_record(), third]))
    out = tmp_path / 'case'
    assert main(['import-native', str(source), '-o', str(out),
                 '--reference-event-count', '2']) == 0
    case = json.loads((out / 'case.json').read_text(encoding='utf-8'))
    assert case['events'] == case['native_records_total'] == 3
    assert case['trace_session_headers'] == 1
    assert case['windows_comparable_events'] == 2
    assert case['timeline_records'] == 2
    assert case['reference_event_count'] == 2
    assert case['count_difference'] == 0
    assert 'INCOMPLETE' not in [f.name for f in out.iterdir()]
    with (out / 'timeline.csv').open(newline='', encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 2
    assert rows[0]['record_kind'] == 'event'
    events = [json.loads(x) for x in (out / 'events.jsonl').read_text().splitlines()]
    assert len(events) == 3
    assert events[0]['record_kind'] == 'trace_session_header'
    assert events[0]['payload_hex'] == session_record()['payload_hex']
    assert events[1]['record_kind'] == 'event'
    assert main(['verify', str(out)]) == 0
    assert main(['search', str(out / 'events.jsonl'),
                 '--record-kind', 'trace_session_header']) == 0
    assert 'trace_session_header' in capsys.readouterr().out


def test_optional_header_in_timeline_and_absent_reference(tmp_path):
    source = tmp_path / 'native.jsonl'
    source.write_text(json.dumps(session_record()) + '\n')
    out = tmp_path / 'case'
    assert main(['import-native', str(source), '-o', str(out),
                 '--include-trace-metadata-in-timeline']) == 0
    case = json.loads((out / 'case.json').read_text())
    assert case['timeline_records'] == 1
    assert case['windows_comparable_events'] == 0
    assert 'reference_event_count' not in case
    assert 'count_difference' not in case


def test_parse_default_path_does_not_apply_to_json_import():
    parser = build_parser()
    args = parser.parse_args(['parse', '-o', 'sample'])
    assert args.source == DEFAULT_NETCORE_ETL
    assert str(args.source) == r'C:\Windows\System32\LogFiles\WMI\NetCore.etl'
    args = parser.parse_args(['parse', r'D:\Evidence\Snapshot.etl', '-o', 'sample'])
    assert str(args.source) == r'D:\Evidence\Snapshot.etl'
