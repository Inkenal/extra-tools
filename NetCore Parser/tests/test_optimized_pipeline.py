"""Optimization regressions: ordinary scans retain all enrichment."""

import json

import pytest

from netcore_forensics.cli import build_parser, main
from netcore_forensics.decoding import normalize_guid, module_map


def test_fast_is_removed_from_both_ingest_commands():
    parser = build_parser()
    for command in ('parse', 'import-native'):
        with pytest.raises(SystemExit) as exc:
            parser.parse_args([command, 'capture.etl', '-o', 'case', '--fast'])
        assert exc.value.code == 2


def test_default_extraction_preserves_raw_payload_and_observed_strings(tmp_path):
    source = tmp_path / 'input.jsonl'
    payload = b'hello evidence world'
    source.write_text(json.dumps({
        'timestamp_utc': '2025-01-02T00:00:00Z',
        'provider_guid': '00000000-0000-0000-0000-000000000000',
        'wpp_guid': '39029d0f-1cab-3381-7bfa-38f3a8fd428e',
        'message_id': 77, 'payload_hex': payload.hex(),
    }) + '\n', encoding='utf-8')
    output = tmp_path / 'case'
    assert main(['import-native', str(source), '-o', str(output)]) == 0
    event = json.loads((output / 'events.jsonl').read_text())
    summary = json.loads((output / 'case.json').read_text())
    assert event['payload_hex'] == payload.hex()
    assert event['observed_strings']
    assert summary['with_raw_payload'] == 1
    assert summary['observed_strings_extracted'] is True


def test_guid_normalization_preserves_existing_behavior():
    assert normalize_guid('{39029D0F-1CAB-3381-7BFA-38F3A8FD428E}') == (
        '39029d0f-1cab-3381-7bfa-38f3a8fd428e')
    assert normalize_guid('39029d0f-1cab-3381-7bfa-38f3a8fd428e') == (
        '39029d0f-1cab-3381-7bfa-38f3a8fd428e')
    assert normalize_guid('invalid') is None
    assert normalize_guid(None) is None
    assert normalize_guid({}) is None
    for _ in range(20):
        assert normalize_guid('39029d0f-1cab-3381-7bfa-38f3a8fd428e') == (
            '39029d0f-1cab-3381-7bfa-38f3a8fd428e')


def test_module_map_still_available():
    assert module_map()['39029d0f-1cab-3381-7bfa-38f3a8fd428e'] == 'ncsi.dll'
