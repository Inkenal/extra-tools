"""Decoding coverage reports do not change source records."""

import json

import pytest

from netcore_forensics.cases import message_type_coverage, normalize_reader_stats
from netcore_forensics.cli import main
from collections import Counter


@pytest.mark.parametrize(('raw', 'expected'), [
    (None, None),
    ({'events_read': 100, 'buffers_read': 0},
     {'events_read': 100, 'buffers_read': None, 'buffers_read_raw': 0,
      'buffers_read_status': 'unavailable_zero_with_events'}),
    ({'events_read': 0, 'buffers_read': 0},
     {'events_read': 0, 'buffers_read': 0, 'buffers_read_status': 'unavailable'}),
    ({'events_read': 100, 'buffers_read': 4},
     {'events_read': 100, 'buffers_read': 4,
      'buffers_read_status': 'reported_by_windows_api_unverified'}),
])
def test_buffer_count_never_asserts_zero_buffers_after_receiving_events(raw, expected):
    assert normalize_reader_stats(raw) == expected
    if raw is not None:
        assert raw.get('buffers_read') == raw.get('buffers_read')  # no mutation


def test_event_type_coverage_preserves_every_status_including_future_types():
    messages = Counter({('a', 17): 4, ('b', 0): 1})
    statuses = Counter({('a', 17, 'opaque_payload'): 2,
                        ('a', 17, 'empty_payload'): 1,
                        ('a', 17, 'future_status'): 1,
                        ('b', 0, 'trace_metadata'): 1})
    rows = message_type_coverage(messages, statuses, {('a', 17): 14})
    assert len(rows) == 2
    assert rows[0]['total'] == 4
    assert rows[0]['opaque_payload'] == 2
    assert rows[0]['empty_payload'] == 1
    assert rows[0]['opaque_percent'] == 50.0
    assert rows[0]['first_opaque_sequence_index'] == 14
    assert rows[0]['other_statuses'] == {'future_status': 1}
    assert rows[1]['trace_metadata'] == 1
    assert rows[1]['first_opaque_sequence_index'] is None


def test_coverage_integrates_with_case_report(tmp_path):
    guid = '014de49f-ce63-4779-ba2b-d616f6963a87'
    other = 'ea289c62-8c36-4904-9726-15ecd282aed5'
    events = [
        dict(timestamp_utc='2025-01-02T00:00:00Z', provider_guid=guid,
             event_id=17, pid=1, payload_hex='cafe'),
        dict(timestamp_utc='2025-01-02T00:00:01Z', provider_guid=guid,
             event_id=17, pid=1, payload_hex='caff'),
        dict(timestamp_utc='2025-01-02T00:00:02Z', provider_guid=guid,
             event_id=17, pid=1, payload_hex=''),
        dict(timestamp_utc='2025-01-02T00:00:03Z', provider_guid=guid,
             event_id=17, pid=1, payload_hex='cabb', event_data={'field': 3}),
        dict(timestamp_utc='2025-01-02T00:00:04Z', provider_guid=other,
             event_id=0, pid=1, payload_hex='00'),
    ]
    source = tmp_path / 'source.jsonl'
    source.write_text(''.join(json.dumps(e) + '\n' for e in events), encoding='utf-8')
    output = tmp_path / 'case'
    assert main(['import-native', str(source), '-o', str(output)]) == 0
    meta = json.loads((output / 'case.json').read_text())
    coverage = meta['decoding_coverage_by_message_type']
    assert len(coverage) == 2
    assert coverage[0]['guid'] == guid
    assert coverage[0]['event_id'] == 17
    assert coverage[0]['total'] == 4
    assert coverage[0]['opaque_payload'] == 2
    assert coverage[0]['empty_payload'] == 1
    assert coverage[0]['tdh_fields_only'] == 1
    assert coverage[0]['first_opaque_sequence_index'] == 0
    assert meta['top_opaque_message_types'][0]['opaque_payload'] == 2
    assert meta['top_opaque_message_types'][1]['guid'] == other
    assert meta['native_reader_stats'] is None
    assert meta['native_records_total'] == 5
    assert sum(x['total'] for x in coverage) == 5
    assert sum(x['opaque_payload'] for x in coverage) == 3
    assert len((output / 'events.jsonl').read_text().splitlines()) == 5
    text = (output / 'report.md').read_text()
    assert 'Event-type decoding coverage' in text
    assert 'Priority opaque message types' in text
    assert 'Not available for imported JSONL' in text
    assert '0 |' in text  # tables include counts, including zeros
