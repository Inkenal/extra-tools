"""Conservative interpretations of observed NetCore event payloads."""

from __future__ import annotations

import csv
from functools import lru_cache
from importlib.resources import files
from uuid import UUID

from .trace_metadata import parse_session_header

from .legacy_layouts import (
    ADDITIONAL_GUIDS, CONNECTIVITY_GUID, NCSI,
    decode_additional, decode_connectivity, decode_ncsi, decode_rare,
    printable_runs,
)

ZERO_GUID = '00000000-0000-0000-0000-000000000000'
SRUM_GUID = 'c8dbf506-e3d3-4822-930d-84c557eb6247'
EVENT_TRACE_GUID = '68fdd900-4a3e-11d1-84f4-0000f80464e3'
NETWORK_CONNECTIVITY_STATUS_GUID = '014de49f-ce63-4779-ba2b-d616f6963a87'
WINRT_CONNECTIVITY_GUID = '8ae0ccb2-d1f7-3880-d1d9-09f791e673db'
OBSERVED_INTERFACE_LAYOUT_GUIDS = frozenset({
    'f3678906-e82d-358d-81de-92bc83cd5ad3',
    '24453f6e-f0f9-3f0a-c888-f4d3af4fe751',
})
INTERFACE_LAYOUT_KINDS = frozenset({
    'identifier_16', 'two_identifiers_16', 'interface_identifier_and_name',
    'compound_interface_record', 'identifier_plus_u32',
})

# GUID-to-family mappings are based on exact binary references and diagnostic
# evidence. They do not establish the precise emitter or payload semantics.
# See docs/ATTRIBUTION.md for the attribution method.
BINARY_ASSOCIATED_PROVIDER_FAMILIES = {
    'ea289c62-8c36-4904-9726-15ecd282aed5': 'network_profile_diagnostic',
    '1701c7dc-045c-45c0-8cd6-4d42e3bbf387': 'network_connectivity_diagnostic',
    'afa03ad9-e63c-59d0-754c-f5a51b7fe33c': 'data_usage_service_diagnostic',
    '0616f7dd-722a-4df1-b87a-414fa870d8b7': 'connection_manager_diagnostic',
    'f3678906-e82d-358d-81de-92bc83cd5ad3': 'network_connectivity_api_diagnostic',
    '24453f6e-f0f9-3f0a-c888-f4d3af4fe751': 'network_connectivity_api_diagnostic',
    'd5981b96-2d24-303d-1369-fe0f937ae543': 'network_connectivity_diagnostic',
    '847dcc45-f34e-342b-882a-d45f241cb5f6': 'connection_manager_diagnostic',
    '8b88784e-3ccd-3410-27a7-600f51db5fb9': 'connection_manager_diagnostic',
}



@lru_cache(maxsize=512)
def _normalize_guid_text(value: str) -> str | None:
    # Provider and WPP GUIDs repeat heavily within a single ETL trace.
    # Bounded memoization avoids reparsing the same UUID for every event.
    try:
        return str(UUID(value.strip('{}')))
    except ValueError:
        return None


def normalize_guid(value: str | None) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return _normalize_guid_text(value)


def module_map() -> dict[str, str]:
    with files('netcore_forensics').joinpath('module_map.csv').open('r', encoding='utf-8-sig') as fp:
        return {row['wpp_message_guid'].lower(): row['module'] for row in csv.DictReader(fp)}


def decode_payload(guid: str | None, message_id: int | None, payload: bytes) -> dict | None:
    """Only interpret payloads for a verified message GUID and message ID.

    A matching identifier alone is not proof of network traffic or executable
    activity. Opaque trailing bytes are preserved in the event's payload_hex.
    """
    if not guid or message_id is None:
        return None
    if guid == NCSI:
        return decode_ncsi(message_id, payload)
    if guid == CONNECTIVITY_GUID:
        return decode_connectivity(message_id, payload)
    if guid in ADDITIONAL_GUIDS:
        return decode_additional(guid, message_id, payload)
    return decode_rare(guid, message_id, payload)


def extract_observed_strings(payload: bytes) -> list[dict]:
    """Return candidate printable strings, never authoritative field names."""
    return printable_runs(payload)


def classify_event(record: dict) -> str:
    """Classify an observed *diagnostic family*, never a proven socket connection.

    Mapping a source family does not imply that the event schema is known.
    Unknown identifiers stay unclassified.
    """
    provider = (record.get('provider_guid') or '').strip('{}').lower()
    guid = (record.get('wpp_guid') or '').strip('{}').lower()
    message_id = record.get('event_id', record.get('message_id'))
    if record.get('record_kind') == 'trace_session_header':
        return 'trace_session_header'
    if provider == EVENT_TRACE_GUID:
        return 'trace_control_event'
    if provider == SRUM_GUID:
        if message_id in (2010, 2011, 2012):
            return 'srum_network_aggregation'
        return 'srum_service_diagnostic'
    if provider == NETWORK_CONNECTIVITY_STATUS_GUID:
        return 'network_connectivity_status_diagnostic'
    if guid == NCSI:
        return 'network_connectivity_diagnostic'
    module = (record.get('emitter_module_candidate') or '').lower()
    if module == 'ncsi.dll':
        return 'network_connectivity_diagnostic'
    if module in {'netprofm.dll', 'netprofmsvc.dll'}:
        return 'network_profile_diagnostic'
    if module in {'wcmsvc.dll', 'wcmapi.dll', 'wcmcsp.dll'}:
        return 'connection_manager_diagnostic'
    if module == 'ondemandconnroutehelper.dll':
        return 'connection_routing_diagnostic'
    if module == 'windows.networking.connectivity.dll':
        return 'network_connectivity_api_diagnostic'
    # These two WPP GUIDs are recognized by payload/function-name research,
    # but they aren't assigned to a source DLL in module_map.csv.
    if guid in {CONNECTIVITY_GUID, WINRT_CONNECTIVITY_GUID}:
        return 'network_connectivity_api_diagnostic'
    # GUID-sized fields alone don't establish their semantic role. Only
    # classify the family when a validated layout contains the identifier.
    decoded = record.get('decoded_fields')
    if (guid in OBSERVED_INTERFACE_LAYOUT_GUIDS and isinstance(decoded, dict)
            and decoded.get('kind') in INTERFACE_LAYOUT_KINDS):
        return 'network_interface_layout_observed'
    # Conservative fallback: a source-family hint from reviewed binary GUID
    # presence. Never invent event-specific semantics or payload decoding.
    binary_family = BINARY_ASSOCIATED_PROVIDER_FAMILIES.get(provider)
    if binary_family is not None:
        return binary_family
    return 'unclassified_etw_event'


def decode_status(record: dict) -> str:
    """Distinguish successful layout extraction from source attribution.

    No payload decoder means neither corruption nor a missing DLL. In
    particular, a known provider without its manifest/TMF remains opaque.
    """
    if record.get('record_kind') == 'trace_session_header':
        return 'trace_metadata'
    if record.get('decode_error') or record.get('payload_error'):
        return 'payload_error'
    if record.get('decoded_fields'):
        return 'partial_layout'
    if record.get('event_data'):
        return 'tdh_fields_only'
    if record.get('payload_length', 0):
        return 'opaque_payload'
    if record.get('payload_hex'):
        return 'opaque_payload'
    return 'empty_payload'


def annotate(record: dict, sources: dict[str, str], payload: bytes | None = None) -> dict:
    """Normalize fields and add hints without inventing network connections."""
    guid = normalize_guid(record.get('wpp_guid'))
    provider_guid = normalize_guid(record.get('provider_guid'))
    record['wpp_guid'] = guid
    record['provider_guid'] = provider_guid
    session = parse_session_header(record)
    record['record_kind'] = 'trace_session_header' if session is not None else 'event'
    if session is not None:
        record['trace_session_metadata'] = session
    record['emitter_module_candidate'] = sources.get(guid) if guid else None
    message_id = record.get('message_id', record.get('event_id'))
    payload_hex = record.get('payload_hex')
    decoded = None
    if payload_hex is not None and guid and message_id is not None:
        try:
            decoded = decode_payload(guid, int(message_id), payload if payload is not None else bytes.fromhex(payload_hex))
        except (ValueError, TypeError):
            record['decode_error'] = 'Invalid hexadecimal payload or message ID'
    record['decoded_fields'] = decoded
    record['classification'] = classify_event(record)
    record['decode_status'] = decode_status(record)
    record['interpretation'] = (
        'trace_session_metadata' if session is not None else
        'partial_observed_layout' if decoded else 'raw_or_metadata_only'
    )
    record['socket_connection_evidence'] = 'not_established'
    return record
