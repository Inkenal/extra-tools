import struct

from netcore_forensics.decoding import annotate, classify_event, decode_payload, module_map
from netcore_forensics.etw import (
    EventDescriptor, EventHeader, EventRecord, EventTrace, EventTraceLogfileW,
    TraceLogfileHeader, windows_filetime,
)
import ctypes


def test_windows_ctypes_struct_layouts():
    assert ctypes.sizeof(EventDescriptor) == 16
    assert ctypes.sizeof(EventHeader) == 80
    assert ctypes.sizeof(EventRecord) == 112
    assert ctypes.sizeof(EventTrace) == 88
    assert ctypes.sizeof(TraceLogfileHeader) == 280
    assert ctypes.sizeof(EventTraceLogfileW) == 448


def test_filetime_utc():
    assert windows_filetime(116444736000000000) == '1970-01-01T00:00:00.000000Z'
    assert windows_filetime(0) is None


def test_known_mapping_ncsi():
    assert module_map()['39029d0f-1cab-3381-7bfa-38f3a8fd428e'] == 'ncsi.dll'


def test_ncsi_state_decoding():
    guid = '39029d0f-1cab-3381-7bfa-38f3a8fd428e'
    payload = b'\0' * 28 + b'PathStateCanConnectTooOld\0'
    d = decode_payload(guid, 17, payload)
    assert d['kind'] == 'ncsi_path_state_diagnostic'
    assert d['state_label'] == 'PathStateCanConnectTooOld'
    assert decode_payload(guid, 17, b'other') is None


def test_rare_four_byte_layout_unknown_semantics():
    d = decode_payload('53533f3c-7588-3bc3-9ead-1e6c10b4b917', 11, struct.pack('<I', 1))
    assert d['value'] == 1
    assert 'unverified' in d['confidence']


def test_no_source_guesses():
    d = annotate({'provider_guid': '{00000000-0000-0000-0000-000000000000}',
                  'wpp_guid': None, 'event_id': 17, 'payload_hex': '01020304'}, module_map())
    assert d['decoded_fields'] is None
    assert d['socket_connection_evidence'] == 'not_established'


def test_srum_classification():
    assert classify_event({'provider_guid': 'c8dbf506-e3d3-4822-930d-84c557eb6247',
                           'event_id': 2010}) == 'srum_network_aggregation'
    assert classify_event({'provider_guid': 'c8dbf506-e3d3-4822-930d-84c557eb6247',
                           'event_id': 2005}) == 'srum_service_diagnostic'


def test_event_record_keeps_timestamp_and_payload_together():
    import uuid
    from netcore_forensics.etw import EventRecord, read_event, EVENT_HEADER_FLAG_TRACE_MESSAGE

    raw = ctypes.create_string_buffer(b'TEST\0PAYLOAD', 12)
    record = EventRecord()
    record.EventHeader.TimeStamp = 116444736000000000
    record.EventHeader.ProcessId = 1234
    record.EventHeader.ThreadId = 4321
    record.EventHeader.ProviderId = type(record.EventHeader.ProviderId).from_buffer_copy(
        uuid.UUID('c8dbf506-e3d3-4822-930d-84c557eb6247').bytes_le
    )
    record.EventHeader.Flags = EVENT_HEADER_FLAG_TRACE_MESSAGE
    record.EventHeader.EventDescriptor.Id = 2005
    record.UserDataLength = 12
    record.UserData = ctypes.cast(raw, ctypes.c_void_p).value
    extracted = read_event(record)
    assert extracted['timestamp_utc'] == '1970-01-01T00:00:00.000000Z'
    assert extracted['pid'] == 1234
    assert extracted['tid'] == 4321
    assert extracted['provider_guid'] == 'c8dbf506-e3d3-4822-930d-84c557eb6247'
    assert extracted['event_id'] == 2005
    assert extracted['payload_hex'] == b'TEST\0PAYLOAD'.hex()
    assert extracted['wpp_trace_message']
