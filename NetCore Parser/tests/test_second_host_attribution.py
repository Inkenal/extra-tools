"""Known GUID families must not be treated as decoded payloads."""

import json

import pytest

from netcore_forensics.cli import main
from netcore_forensics.decoding import annotate, classify_event, module_map


# Synthetic payloads: family attribution does not decode unknown fields.
SAMPLES = [
    ('d5981b96-2d24-303d-1369-fe0f937ae543', 12,
     '4100000064006e0073002e006d007300660074006e006300730069002e0063006f006d0000000000000c800006000b000000',
     'network_connectivity_diagnostic'),
    ('d5981b96-2d24-303d-1369-fe0f937ae543', 12,
     '4100000064006e0073002e006d007300660074006e006300730069002e0063006f006d0000000000000b8000060012000000',
     'network_connectivity_diagnostic'),
    ('d5981b96-2d24-303d-1369-fe0f937ae543', 13,
     '64006e0073002e006d007300660074006e006300730069002e0063006f006d000000b4050000b4050000',
     'network_connectivity_diagnostic'),
    ('847dcc45-f34e-342b-882a-d45f241cb5f6', 27,
     '00112233445566778899aabbccddeeff',
     'connection_manager_diagnostic'),
    ('847dcc45-f34e-342b-882a-d45f241cb5f6', 27,
     '102132435465768798a9babbdcddedef',
     'connection_manager_diagnostic'),
    ('847dcc45-f34e-342b-882a-d45f241cb5f6', 27,
     '00112233445566778899aabbccddeeff',
     'connection_manager_diagnostic'),
    ('8b88784e-3ccd-3410-27a7-600f51db5fb9', 78,
     '57636d53636d4e6f74696669636174696f6e48616e646c657200',
     'connection_manager_diagnostic'),
    ('8b88784e-3ccd-3410-27a7-600f51db5fb9', 79,
     '0400000000000000',
     'connection_manager_diagnostic'),
    ('8b88784e-3ccd-3410-27a7-600f51db5fb9', 86,
     '57636d53636d4e6f74696669636174696f6e48616e646c65720078000000',
     'connection_manager_diagnostic'),
]


@pytest.mark.parametrize('provider,event_id,payload_hex,family', SAMPLES)
def test_second_host_family_does_not_decode_unverified_bytes(
    provider, event_id, payload_hex, family,
):
    event = {
        'provider_guid': provider,
        'event_id': event_id, 'payload_hex': payload_hex,
        'payload_length': len(payload_hex) // 2,
    }
    record = annotate(event, module_map())
    assert record['classification'] == family
    assert record['payload_hex'] == payload_hex
    assert record['decode_status'] == 'opaque_payload'
    assert record['decoded_fields'] is None
    assert record['socket_connection_evidence'] == 'not_established'


def test_unknown_guids_remain_unclassified():
    record = {
        'provider_guid': '8b88784e-3ccd-3410-27a7-600f51db5fb8',
        'record_kind': 'event', 'wpp_guid': None,
        'emitter_module_candidate': None, 'decoded_fields': None,
    }
    assert classify_event(record) == 'unclassified_etw_event'


def test_second_host_case_reconciliation(tmp_path, capsys):
    source = tmp_path / 'native.jsonl'
    rows = []
    for seq, (provider, event_id, payload_hex, family) in enumerate(SAMPLES):
        rows.append({
            'timestamp_utc': f'2025-01-02T20:15:{seq:02d}Z',
            'provider_guid': provider, 'pid': 4, 'tid': 10,
            'event_id': event_id,
            'payload_hex': payload_hex, 'payload_length': len(payload_hex) // 2,
        })
    source.write_text(''.join(json.dumps(x) + '\n' for x in rows), encoding='utf-8')
    out = tmp_path / 'case'
    assert main(['import-native', str(source), '-o', str(out)]) == 0
    summary = json.loads((out / 'case.json').read_text())
    assert summary['native_records_total'] == len(SAMPLES)
    assert summary['windows_comparable_events'] == len(SAMPLES)
    assert summary['summary_occurrences'] == len(SAMPLES)
    assert summary['top_unclassified_providers'] == []
    assert dict((x['value'], x['count']) for x in summary['classes']) == {
        'network_connectivity_diagnostic': 3,
        'connection_manager_diagnostic': 6,
    }
    assert summary['decode_statuses'][0]['count'] == len(SAMPLES)
    assert summary['decode_statuses'][0]['value'] == 'opaque_payload'
    originals = [json.loads(line) for line in (out / 'events.jsonl').read_text().splitlines()]
    assert [x['payload_hex'] for x in originals] == [x['payload_hex'] for x in rows]
    capsys.readouterr()
