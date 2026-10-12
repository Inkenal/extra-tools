"""Deduplicated timeline must never alter the ordinary evidentiary timeline."""

import csv
import json

from netcore_forensics.cases import SUMMARY_FIELDS, TIMELINE_FIELDS
from netcore_forensics.cli import main


def _read_rows(path):
    with path.open(encoding='utf-8', newline='') as fp:
        return list(csv.DictReader(fp))


def test_deduplicate_identical_timeline_fields_across_timestamps(tmp_path):
    source = tmp_path / 'source.jsonl'
    events = [
        {'timestamp_utc': '2025-01-02T09:00:00Z', 'pid': 1, 'tid': 2,
         'provider_guid': '00000000-0000-0000-0000-000000000000',
         'event_id': 7, 'message_id': 7, 'payload_hex': 'abcd'},
        {'timestamp_utc': '2025-01-02T09:00:01Z', 'pid': 1, 'tid': 2,
         'provider_guid': '00000000-0000-0000-0000-000000000000',
         'event_id': 7, 'message_id': 7, 'payload_hex': 'abcd'},
        {'timestamp_utc': '2025-01-02T09:00:02Z', 'pid': 3, 'tid': 2,
         'provider_guid': '00000000-0000-0000-0000-000000000000',
         'event_id': 7, 'message_id': 7, 'payload_hex': 'abcd'},
        {'timestamp_utc': '2025-01-02T09:00:03Z', 'pid': 1, 'tid': 2,
         'provider_guid': '00000000-0000-0000-0000-000000000000',
         'event_id': 7, 'message_id': 7, 'payload_hex': 'abcd'},
        {'timestamp_utc': '2025-01-02T09:00:04Z', 'pid': 1, 'tid': 2,
         'provider_guid': '00000000-0000-0000-0000-000000000000',
         'event_id': 7, 'message_id': 7, 'payload_hex': 'abcdef'},
    ]
    source.write_text(''.join(json.dumps(event)+'\n' for event in events), encoding='utf-8')
    output = tmp_path / 'out'
    assert main(['import-native', str(source), '-o', str(output)]) == 0

    normal = _read_rows(output / 'timeline.csv')
    dedup = _read_rows(output / 'Summary.csv')
    with (output / 'timeline.csv').open(encoding='utf-8', newline='') as fp:
        assert csv.DictReader(fp).fieldnames == TIMELINE_FIELDS
    with (output / 'Summary.csv').open(encoding='utf-8', newline='') as fp:
        assert csv.DictReader(fp).fieldnames == SUMMARY_FIELDS
    assert not (output / 'timeline_deduplicated.csv').exists()
    assert len(normal) == 5
    assert [x['sequence_index'] for x in normal] == ['0', '1', '2', '3', '4']
    assert len(dedup) == 3
    assert [x['Counter'] for x in dedup] == ['3', '1', '1']
    assert [x['First seen'] for x in dedup] == [
        '2025-01-02T09:00:00Z', '2025-01-02T09:00:02Z', '2025-01-02T09:00:04Z',
    ]
    assert [x['pid'] for x in dedup] == ['1', '3', '1']
    assert [x['payload_length'] for x in dedup] == ['2', '2', '3']
    assert sum(int(x['Counter']) for x in dedup) == len(normal)
    assert 'timestamp_utc' not in dedup[0]
    assert 'sequence_index' not in dedup[0]
    assert len((output / 'events.jsonl').read_text().splitlines()) == 5
    case = json.loads((output / 'case.json').read_text())
    assert case['timeline_records'] == 5
    assert case['summary_rows'] == 3
    assert case['summary_occurrences'] == 5
    assert sum(row['count'] for row in case['classes']) == 5
    assert len(case['classes']) < len(dedup)  # class counts cannot replace detailed grouping
    assert not (output / 'INCOMPLETE').exists()
    assert not any('.summary_' in x.name for x in output.iterdir())


def test_empty_timeline_has_only_header(tmp_path):
    source = tmp_path / 'empty.jsonl'
    source.write_text('', encoding='utf-8')
    output = tmp_path / 'out'
    assert main(['import-native', str(source), '-o', str(output)]) == 0
    assert _read_rows(output / 'Summary.csv') == []
    summary = json.loads((output / 'case.json').read_text())
    assert summary['summary_rows'] == 0
    assert summary['summary_occurrences'] == 0


def test_multiline_csv_fields_do_not_break_deduplication(tmp_path):
    """Test CSV-special characters without imposing any event-decoder interpretation."""
    from netcore_forensics.cases import write_summary_csv

    path = tmp_path / 'timeline.csv'
    with path.open('w', encoding='utf-8', newline='') as fp:
        writer = csv.DictWriter(fp, fieldnames=TIMELINE_FIELDS)
        writer.writeheader()
        for i in range(3):
            row = {field: '' for field in TIMELINE_FIELDS}
            row.update(sequence_index=i, timestamp_utc=f'time{i}',
                       emitter_module_candidate='quotes " and newline\n and comma,',
                       interpretation='привет,مرحبا')
            writer.writerow(row)
    rows, occurrences = write_summary_csv(path, tmp_path / 'grouped.csv')
    assert rows == 1
    assert occurrences == 3
    grouped = _read_rows(tmp_path / 'grouped.csv')
    assert grouped[0]['Counter'] == '3'
    assert grouped[0]['First seen'] == 'time0'
    assert grouped[0]['emitter_module_candidate'] == 'quotes " and newline\n and comma,'
    assert grouped[0]['interpretation'] == 'привет,مرحبا'
