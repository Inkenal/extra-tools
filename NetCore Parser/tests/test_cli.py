import json
from pathlib import Path

from netcore_forensics.cli import main


def test_import_search_and_verify(tmp_path, capsys):
    source = tmp_path / 'native.jsonl'
    rows = [
        {'timestamp_utc': '2025-01-02T09:00:00Z', 'pid': 50, 'tid': 11,
         'provider_guid': '{c8dbf506-e3d3-4822-930d-84c557eb6247}',
         'message_id': 2005, 'event_data': {'_FunctionName': 'JetSeek', '_HR': -1601},
         'wpp_guid': None},
        {'timestamp_utc': '2025-01-02T09:00:01Z', 'pid': 123, 'tid': 5,
         'provider_guid': '{00000000-0000-0000-0000-000000000000}',
         'message_id': 17, 'wpp_guid': '39029d0f-1cab-3381-7bfa-38f3a8fd428e',
         'payload_hex': (b'\0' * 28 + b'PathStateCanConnectTooNew\0').hex()},
    ]
    source.write_text(''.join(json.dumps(r) + '\n' for r in rows), encoding='utf-8')
    out = tmp_path / 'case'
    assert main(['import-native', str(source), '-o', str(out)]) == 0
    case = json.loads((out / 'case.json').read_text())
    assert case['events'] == 2
    assert case['with_wpp_guid'] == 1
    assert case['partially_decoded'] == 1
    assert case['source']['sha256']
    assert main(['verify', str(out)]) == 0
    assert main(['search', str(out / 'events.jsonl'), '--text', 'PathStateCanConnectTooNew']) == 0
    output = capsys.readouterr().out
    assert 'PathStateCanConnectTooNew' in output
    assert main(['import-native', str(source), '-o', str(out)]) == 1
    source.write_text(source.read_text() + '{}\n', encoding='utf-8')
    assert main(['verify', str(out)]) == 2


def test_reject_nonobject_json(tmp_path):
    source = tmp_path / 'bad.jsonl'
    source.write_text('[]\n', encoding='utf-8')
    assert main(['import-native', str(source), '-o', str(tmp_path / 'case')]) == 1


def test_parse_requires_windows(tmp_path):
    import os
    if os.name == 'nt':
        return
    etl = tmp_path / 'sample.etl'
    etl.write_bytes(b'bad')
    assert main(['parse', str(etl), '-o', str(tmp_path / 'case')]) == 1


def test_timestamp_filter_requires_timezone(tmp_path):
    p = tmp_path / 'events.jsonl'
    p.write_text(json.dumps({'timestamp_utc': '2025-01-02T11:00:00.000000Z',
                             'pid': 1, 'event_id': 1}) + '\n', encoding='utf-8')
    assert main(['search', str(p), '--since', '2025-01-02T11:00:00Z']) == 0
    assert main(['search', str(p), '--since', '2025-01-02T11:00:00']) == 1
    assert main(['search', str(p), '--since', '2025-01-02T11:00:00+03:00',
                 '--until', '2025-01-02T10:59:59Z']) == 0


def test_invalid_import_payload_type_is_a_clean_error(tmp_path, capsys):
    source = tmp_path / 'bad_payload.jsonl'
    source.write_text(json.dumps({'payload_hex': 1234}) + '\n', encoding='utf-8')
    assert main(['import-native', str(source), '-o', str(tmp_path / 'case')]) == 1
    assert 'payload_hex must be a string' in capsys.readouterr().err


def test_invalid_import_payload_length_is_a_clean_error(tmp_path, capsys):
    source = tmp_path / 'bad_length.jsonl'
    source.write_text(json.dumps({'payload_hex': '00', 'payload_length': -1}) + '\n', encoding='utf-8')
    assert main(['import-native', str(source), '-o', str(tmp_path / 'case')]) == 1
    assert 'payload_length must be a nonnegative integer' in capsys.readouterr().err


def test_invalid_record_timestamp_is_a_clean_error(tmp_path, capsys):
    source = tmp_path / 'bad_timestamp.jsonl'
    source.write_text(json.dumps({'timestamp_utc': 1234}) + '\n', encoding='utf-8')
    assert main(['search', str(source), '--since', '2025-01-02T00:00:00Z']) == 1
    assert 'Invalid ISO-8601 timestamp' in capsys.readouterr().err


def test_search_rejects_nonobject_jsonl(tmp_path, capsys):
    source = tmp_path / 'bad_search.jsonl'
    source.write_text('[]\n', encoding='utf-8')
    assert main(['search', str(source)]) == 1
    assert 'Search input must contain JSON objects' in capsys.readouterr().err
