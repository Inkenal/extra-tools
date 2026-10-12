"""Known-source classification does not imply full payload decoding."""

import csv
import json

import pytest

from netcore_forensics.cli import main
from netcore_forensics.decoding import annotate, classify_event, decode_status, module_map


@pytest.mark.parametrize(('provider', 'wpp_guid', 'module', 'decoded', 'expected'), [
    ('014de49f-ce63-4779-ba2b-d616f6963a87', None, None, None,
     'network_connectivity_status_diagnostic'),
    ('68fdd900-4a3e-11d1-84f4-0000f80464e3', None, None, None,
     'trace_control_event'),
    ('00000000-0000-0000-0000-000000000000',
     '7ac5404b-0acd-3d12-3291-2bdf0dea9484', None, None,
     'network_connectivity_api_diagnostic'),
    ('00000000-0000-0000-0000-000000000000',
     '8ae0ccb2-d1f7-3880-d1d9-09f791e673db', None, None,
     'network_connectivity_api_diagnostic'),
    ('00000000-0000-0000-0000-000000000000', None, 'wcmcsp.dll', None,
     'connection_manager_diagnostic'),
    ('00000000-0000-0000-0000-000000000000', None, 'wcmapi.dll', None,
     'connection_manager_diagnostic'),
    ('00000000-0000-0000-0000-000000000000', None,
     'Windows.Networking.Connectivity.dll', None,
     'network_connectivity_api_diagnostic'),
    ('00000000-0000-0000-0000-000000000000', None,
     'OnDemandConnRouteHelper.dll', None, 'connection_routing_diagnostic'),
    ('00000000-0000-0000-0000-000000000000',
     'f3678906-e82d-358d-81de-92bc83cd5ad3', None,
     {'kind': 'identifier_16'}, 'network_interface_layout_observed'),
    ('00000000-0000-0000-0000-000000000000',
     '24453f6e-f0f9-3f0a-c888-f4d3af4fe751', None,
     {'kind': 'compound_interface_record'}, 'network_interface_layout_observed'),
    ('00000000-0000-0000-0000-000000000000',
     'f3678906-e82d-358d-81de-92bc83cd5ad3', None,
     {'kind': 'u32_value'}, 'unclassified_etw_event'),
    ('ea289c62-8c36-4904-9726-15ecd282aed5', None, None, None,
     'network_profile_diagnostic'),
    ('1701c7dc-045c-45c0-8cd6-4d42e3bbf387', None, None, None,
     'network_connectivity_diagnostic'),
])
def test_classification_is_conservative(provider, wpp_guid, module, decoded, expected):
    record = dict(provider_guid=provider, wpp_guid=wpp_guid,
                  emitter_module_candidate=module, decoded_fields=decoded,
                  record_kind='event')
    assert classify_event(record) == expected


@pytest.mark.parametrize(('record', 'expected'), [
    ({'record_kind': 'trace_session_header'}, 'trace_metadata'),
    ({'record_kind': 'event', 'decoded_fields': {'kind': 'empty_event'}}, 'partial_layout'),
    ({'record_kind': 'event', 'event_data': {'_HR': 0}}, 'tdh_fields_only'),
    ({'record_kind': 'event', 'payload_length': 22}, 'opaque_payload'),
    ({'record_kind': 'event', 'payload_length': 0}, 'empty_payload'),
    ({'record_kind': 'event', 'decode_error': 'bad', 'payload_length': 1}, 'payload_error'),
])
def test_decode_status(record, expected):
    assert decode_status(record) == expected


def test_unknown_provider_does_not_get_fictitious_decoding():
    record = annotate({'provider_guid': 'ea289c62-8c36-4904-9726-15ecd282aed5',
                       'wpp_guid': None, 'event_id': 0, 'payload_hex': 'ab12',
                       'payload_length': 2}, module_map())
    assert record['classification'] == 'network_profile_diagnostic'
    assert record['decode_status'] == 'opaque_payload'
    assert record['decoded_fields'] is None
    assert record['socket_connection_evidence'] == 'not_established'


def test_case_exports_coverage_and_keeps_evidence(tmp_path, capsys):
    source = tmp_path / 'events.jsonl'
    original = [
        {'timestamp_utc': '2025-01-02T09:00:00Z', 'pid': 42, 'tid': 3,
         'event_id': 1, 'provider_guid': '014de49f-ce63-4779-ba2b-d616f6963a87',
         'payload_hex': 'abcd', 'payload_length': 2},
        {'timestamp_utc': '2025-01-02T09:00:01Z', 'pid': 42, 'tid': 3,
         'event_id': 1, 'provider_guid': '014de49f-ce63-4779-ba2b-d616f6963a87',
         'payload_hex': 'abce', 'payload_length': 2},
        {'timestamp_utc': '2025-01-02T09:00:02Z', 'pid': 9, 'tid': 3,
         'event_id': 2, 'provider_guid': 'ea289c62-8c36-4904-9726-15ecd282aed5',
         'payload_hex': '', 'payload_length': 0},
    ]
    source.write_text(''.join(json.dumps(x)+'\n' for x in original), encoding='utf-8')
    output = tmp_path / 'case'
    assert main(['import-native', str(source), '-o', str(output)]) == 0
    assert len((output / 'events.jsonl').read_text().splitlines()) == 3
    with (output / 'timeline.csv').open(encoding='utf-8', newline='') as fp:
        timeline = list(csv.DictReader(fp))
    with (output / 'Summary.csv').open(encoding='utf-8', newline='') as fp:
        summary_csv = list(csv.DictReader(fp))
    assert len(timeline) == 3
    assert 'decode_status' in timeline[0]
    assert len(summary_csv) == 2
    assert [x['Counter'] for x in summary_csv] == ['2', '1']
    assert [x['First seen'] for x in summary_csv] == [
        '2025-01-02T09:00:00Z', '2025-01-02T09:00:02Z',
    ]
    assert summary_csv[0]['decode_status'] == 'opaque_payload'
    case = json.loads((output / 'case.json').read_text())
    assert case['native_records_total'] == 3
    assert case['summary_occurrences'] == 3
    assert case['summary_rows'] == 2
    assert dict((x['value'], x['count']) for x in case['decode_statuses']) == {
        'opaque_payload': 2, 'empty_payload': 1,
    }
    assert case['top_unclassified_providers'] == []
    assert 'Decoding coverage' in (output / 'report.md').read_text()
    capsys.readouterr()  # discard the pretty-printed parse summary
    assert main(['search', str(output / 'events.jsonl'), '--decode-status', 'empty_payload']) == 0
    hits = [json.loads(x) for x in capsys.readouterr().out.splitlines() if x.startswith('{')]
    assert hits[-1]['decode_status'] == 'empty_payload'

@pytest.mark.parametrize(('guid', 'family'), [
    ('ea289c62-8c36-4904-9726-15ecd282aed5', 'network_profile_diagnostic'),
    ('1701c7dc-045c-45c0-8cd6-4d42e3bbf387', 'network_connectivity_diagnostic'),
    ('afa03ad9-e63c-59d0-754c-f5a51b7fe33c', 'data_usage_service_diagnostic'),
    ('f3678906-e82d-358d-81de-92bc83cd5ad3', 'network_connectivity_api_diagnostic'),
    ('24453f6e-f0f9-3f0a-c888-f4d3af4fe751', 'network_connectivity_api_diagnostic'),
    ('0616f7dd-722a-4df1-b87a-414fa870d8b7', 'connection_manager_diagnostic'),
])
def test_binary_associated_family_without_fictional_decoding(guid, family):
    raw = {
        'provider_guid': guid, 'wpp_guid': None, 'event_id': 0,
        'payload_hex': 'cafe1234', 'payload_length': 4,
    }
    record = annotate(raw, module_map())
    assert record['classification'] == family
    assert record['decode_status'] == 'opaque_payload'
    assert record['decoded_fields'] is None
    assert record['socket_connection_evidence'] == 'not_established'
    assert record['payload_hex'] == 'cafe1234'


def test_unrelated_provider_stays_unknown():
    record = annotate({
        'provider_guid': '44444444-4444-4444-4444-444444444444',
        'wpp_guid': None, 'event_id': 0, 'payload_hex': 'cafe', 'payload_length': 2,
    }, module_map())
    assert record['classification'] == 'unclassified_etw_event'
    assert record['decode_status'] == 'opaque_payload'


def test_validated_interface_layout_has_priority_over_binary_hint():
    rec = {'provider_guid': 'f3678906-e82d-358d-81de-92bc83cd5ad3',
           'wpp_guid': 'f3678906-e82d-358d-81de-92bc83cd5ad3',
           'decoded_fields': {'kind': 'identifier_16'}, 'record_kind': 'event'}
    assert classify_event(rec) == 'network_interface_layout_observed'
