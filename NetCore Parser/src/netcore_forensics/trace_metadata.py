"""Recognize the ETW EventTrace_Header session record without dropping evidence.

ETW's first trace-header callback is an EventTrace_Header record with event
class type 0 and a TRACE_LOGFILE_HEADER payload. Windows Event Log's
Get-WinEvent generally omits this record, while ProcessTrace exposes it.

The trace-control GUID and opcode alone are insufficient: the event must have
plausible fixed fields from the documented TRACE_LOGFILE_HEADER structure.
The original UserData remains in payload_hex.
"""

from __future__ import annotations

import struct

EVENT_TRACE_CONTROL_GUID = '68fdd900-4a3e-11d1-84f4-0000f80464e3'

# The fixed prefix of the MOF EventTrace_Header event. The full payload has
# varying-length timezone, logger name and log-file path information.
# Reference: Microsoft EventTrace_Header event class (EventType 0).
_HEADER_PREFIX = struct.Struct('<IIIIQIIIIII')
# offsets: BufferSize=0, Version=4, ProviderVersion=8, Processors=12,
# EndTime=16, TimerResolution=24, MaxFileSize=28, Mode=32, Buffers=36,
# StartBuffers=40, PointerSize=44.


def parse_session_header(record: dict) -> dict | None:
    """Return session metadata only when the record is unambiguously a header.

    No assumptions are made about the event's sequence_index or timestamp.
    Incomplete imports without the native payload stay unclassified.
    """
    provider = (record.get('provider_guid') or '').strip('{}').lower()
    if provider != EVENT_TRACE_CONTROL_GUID:
        return None
    try:
        event_id = int(record.get('event_id', -1))
        opcode = int(record.get('opcode', -1))
    except (ValueError, TypeError):
        return None
    if event_id != 0 or opcode != 0:
        return None
    hex_payload = record.get('payload_hex')
    if not isinstance(hex_payload, str) or len(hex_payload) < _HEADER_PREFIX.size * 2:
        return None
    try:
        # Parse only the fixed fields. Do not scan stale padding for a filename
        # or assume a stable layout for strings on every Windows version.
        payload = bytes.fromhex(hex_payload[:_HEADER_PREFIX.size * 2])
        (buffer_size, version, provider_version, processors, end_time,
         timer_resolution, max_file_mb, log_file_mode, buffers_written,
         start_buffers, pointer_size) = _HEADER_PREFIX.unpack(payload)
    except (ValueError, struct.error):
        return None

    # Sanity checks distinguish EventTrace_Header from ordinary legacy ETW
    # events that share the control provider and event ID.
    if not (1024 <= buffer_size <= 16 * 1024 * 1024 and buffer_size % 1024 == 0):
        return None
    if version == 0 or not (1 <= processors <= 4096):
        return None
    if pointer_size not in (4, 8):
        return None
    if not (0 < timer_resolution <= 100_000_000):
        return None

    return {
        'buffer_size_bytes': buffer_size,
        'trace_version_raw': f'0x{version:08x}',
        'provider_version': provider_version,
        'number_of_processors': processors,
        'timer_resolution_100ns': timer_resolution,
        'maximum_file_size_mb': max_file_mb,
        'log_file_mode': f'0x{log_file_mode:08x}',
        'buffers_written_at_capture': buffers_written,
        'start_buffers': start_buffers,
        'pointer_size_bytes': pointer_size,
    }
