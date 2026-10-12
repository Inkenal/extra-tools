"""Binary association is bounded and independent of decoding."""

import hashlib
import json
from collections import Counter
from uuid import UUID

from netcore_forensics.attribution import MAX_GUIDS, NETWORK_DLLS, scan_unknown_guids
from netcore_forensics.cli import build_parser, main


NCSI = 'd5981b96-2d24-303d-1369-fe0f937ae543'
WCM = '847dcc45-f34e-342b-882a-d45f241cb5f6'
UNKNOWN = '8b88784e-3ccd-3410-27a7-600f51db5fb8'


def make_windows(tmp_path):
    system32 = tmp_path / 'Windows' / 'System32'
    system32.mkdir(parents=True)
    return system32


def test_exact_windows_guid_bytes_and_sha256(tmp_path):
    system32 = make_windows(tmp_path)
    data = b'prefix' + UUID(NCSI).bytes_le + b'footer'
    (system32 / 'ncsi.dll').write_bytes(data)
    result = scan_unknown_guids(Counter({NCSI: 216}), system32.parent,
                                origin='supplied_source_windows')
    assert result['status'] == 'completed'
    assert result['dlls_read'] == 1
    assert result['matched_guid_count'] == 1
    assert result['unresolved_guid_count'] == 0
    entry = result['results'][0]
    assert entry['occurrences'] == 216
    assert entry['status'] == 'binary_match'
    assert entry['candidate_family_unverified'] == 'network_connectivity_diagnostic'
    assert entry['matches'] == [{
        'dll': 'ncsi.dll', 'offset_hex': '0x6',
        'dll_sha256': hashlib.sha256(data).hexdigest(), 'dll_bytes': len(data),
    }]


def test_multiple_matches_and_unresolved_are_not_hidden(tmp_path):
    system32 = make_windows(tmp_path)
    (system32 / 'wcmsvc.dll').write_bytes(UUID(WCM).bytes_le + b'\xff')
    (system32 / 'wcmapi.dll').write_bytes(b'x' + UUID(WCM).bytes_le)
    (system32 / 'irrelevant.dll').write_bytes(UUID(UNKNOWN).bytes_le)
    result = scan_unknown_guids(Counter({WCM: 108, UNKNOWN: 3}),
                                system32.parent, origin='analysis_computer')
    assert result['matched_guid_count'] == 1
    assert result['unresolved_guid_count'] == 1
    assert [hit['dll'] for hit in result['results'][0]['matches']] == ['wcmsvc.dll', 'wcmapi.dll']
    assert result['results'][0]['candidate_family_unverified'] == 'connection_manager_diagnostic'
    assert result['results'][1]['status'] == 'no_match_in_allowlist'
    assert result['dlls_read'] == 2


def test_binary_big_endian_never_claimed_as_windows_guid_match(tmp_path):
    system32 = make_windows(tmp_path)
    (system32 / 'ncsi.dll').write_bytes(UUID(NCSI).bytes)
    result = scan_unknown_guids(Counter({NCSI: 1}), system32.parent,
                                origin='supplied_source_windows')
    assert result['matched_guid_count'] == 0
    assert result['unresolved_guid_count'] == 1


def test_no_unknowns_does_not_scan_dlls(tmp_path):
    result = scan_unknown_guids(Counter(), tmp_path / 'nonexistent', origin='analysis_computer')
    assert result['status'] == 'no_unknown_guids'
    assert result['dlls_read'] == 0


def test_scan_is_bounded_by_number_of_guids_and_dll_bytes(tmp_path):
    system32 = make_windows(tmp_path)
    (system32 / 'ncsi.dll').write_bytes(b'x' * 10)
    counts = Counter({str(UUID(int=i+1)): 300-i for i in range(MAX_GUIDS+1)})
    result = scan_unknown_guids(counts, system32.parent, origin='source_windows')
    assert result['scanned_guid_count'] == MAX_GUIDS
    assert result['unscanned_guid_count'] == 1
    assert result['results'][-1]['status'] == 'not_scanned'
    assert len(result['results']) == MAX_GUIDS+1


def test_import_with_explicit_windows_folder_adds_sidecar_not_decoding(tmp_path, capsys):
    system32 = make_windows(tmp_path)
    payload = '4100000064006e0073002e006d007300660074006e006300730069002e0063006f006d0000000000000c800006000b000000'
    (system32 / 'ncsi.dll').write_bytes(b'header' + UUID(UNKNOWN).bytes_le)
    data = [
        {'timestamp_utc': '2025-01-02T20:00:00Z', 'provider_guid': UNKNOWN,
         'event_id': 12, 'pid': 10, 'tid': 5, 'payload_hex': payload,
         'payload_length': len(payload)//2},
        {'timestamp_utc': '2025-01-02T20:00:01Z', 'provider_guid': UNKNOWN,
         'event_id': 12, 'pid': 10, 'tid': 5, 'payload_hex': payload,
         'payload_length': len(payload)//2},
    ]
    source = tmp_path/'source.jsonl'
    source.write_text(''.join(json.dumps(row) + '\n' for row in data))
    output = tmp_path/'case'
    assert main(['import-native', str(source), '-o', str(output),
                 '--windows-dir', str(system32.parent)]) == 0
    summary = json.loads((output/'case.json').read_text())
    attr = json.loads((output/'attribution.json').read_text())
    assert attr['matched_guid_count'] == 1
    assert attr['results'][0]['occurrences'] == 2
    assert attr['results'][0]['matches'][0]['dll'] == 'ncsi.dll'
    assert summary['unknown_guid_attribution']['matched_guid_count'] == 1
    assert summary['classes'] == [{'value': 'unclassified_etw_event', 'count': 2}]
    assert summary['decode_statuses'] == [{'value': 'opaque_payload', 'count': 2}]
    events = [json.loads(line) for line in (output/'events.jsonl').read_text().splitlines()]
    assert [event['payload_hex'] for event in events] == [payload, payload]
    assert all(event['classification'] == 'unclassified_etw_event' for event in events)
    assert 'attribution.json' in (output/'README.txt').read_text()
    assert 'Unknown-GUID source-binary attribution' in (output/'report.md').read_text()
    capsys.readouterr()


def test_import_without_explicit_source_does_not_search_analysis_host(tmp_path, capsys):
    source = tmp_path/'source.jsonl'
    source.write_text(json.dumps({'provider_guid': UNKNOWN, 'event_id': 27,
                                  'payload_hex': '00000000', 'payload_length': 4})+'\n')
    output = tmp_path/'case'
    assert main(['import-native', str(source), '-o', str(output)]) == 0
    attr = json.loads((output/'attribution.json').read_text())
    assert attr['status'] == 'no_windows_directory_available'
    assert attr['unscanned_guid_count'] == 1
    assert attr['matched_guid_count'] == 0
    capsys.readouterr()


def test_invalid_windows_dir_fails_before_creating_case(tmp_path):
    source=tmp_path/'native.jsonl'
    source.write_text('{}\n')
    case=tmp_path/'case'
    assert main(['import-native', str(source), '-o', str(case),
                 '--windows-dir', str(tmp_path/'missing')]) != 0
    assert not case.exists()


def test_no_deep_scan_cli_option():
    parser=build_parser()
    assert '--windows-dir' in parser.format_help() or '--windows-dir' in parser._subparsers._group_actions[0].choices['parse'].format_help()
    assert not any('deep' in x for x in NETWORK_DLLS)
