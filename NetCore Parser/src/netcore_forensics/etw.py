"""Windows ETW file consumer, implemented with Python ctypes.

The EVENT_RECORD callback provides the event header and UserData together.
No byte carving, process-name guesswork, or event-position joins are used.

Windows x64 is currently the only supported native-reader target. The
structure declarations mirror the published evntcons.h / evntrace.h ABI.
"""

from __future__ import annotations

import ctypes as C
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from .trace_metadata import parse_session_header

# Windows uses UTF-16 wchar_t. Keep these definitions importable on Linux so
# the normalization and decoder code can be tested there.
U8 = C.c_ubyte
U16 = C.c_ushort
U32 = C.c_uint32
U64 = C.c_uint64
I64 = C.c_int64
PTR = C.c_void_p
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
EVENT_HEADER_FLAG_TRACE_MESSAGE = 0x0008
EVENT_HEADER_FLAG_STRING_ONLY = 0x0004
TRACE_MESSAGE_GUID = '00000000-0000-0000-0000-000000000000'
SRUM_PROVIDER_GUID = 'c8dbf506-e3d3-4822-930d-84c557eb6247'
EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


class GUID(C.Structure):
    _fields_ = [('Data1', U32), ('Data2', U16), ('Data3', U16), ('Data4', U8 * 8)]

    def text(self) -> str:
        return str(uuid.UUID(bytes_le=bytes(self)))


class EventDescriptor(C.Structure):
    _fields_ = [
        ('Id', U16), ('Version', U8), ('Channel', U8), ('Level', U8),
        ('Opcode', U8), ('Task', U16), ('Keyword', U64),
    ]


class EventHeader(C.Structure):
    _fields_ = [
        ('Size', U16), ('HeaderType', U16), ('Flags', U16), ('EventProperty', U16),
        ('ThreadId', U32), ('ProcessId', U32), ('TimeStamp', I64),
        ('ProviderId', GUID), ('EventDescriptor', EventDescriptor),
        ('ProcessorTime', U64), ('ActivityId', GUID),
    ]


class EtwBufferContext(C.Structure):
    _fields_ = [('ProcessorIndex', U16), ('LoggerId', U16)]


class ExtendedDataItem(C.Structure):
    _fields_ = [
        ('Reserved1', U16), ('ExtType', U16), ('Linkage', U16),
        ('DataSize', U16), ('DataPtr', U64),
    ]


class EventRecord(C.Structure):
    _fields_ = [
        ('EventHeader', EventHeader), ('BufferContext', EtwBufferContext),
        ('ExtendedDataCount', U16), ('UserDataLength', U16),
        ('ExtendedData', C.POINTER(ExtendedDataItem)),
        ('UserData', PTR), ('UserContext', PTR),
    ]


class EventTraceHeader(C.Structure):
    _fields_ = [
        ('Size', U16), ('FieldTypeFlags', U16), ('Version', U32),
        ('ThreadId', U32), ('ProcessId', U32), ('TimeStamp', I64),
        ('Guid', GUID), ('ProcessorTime', U64),
    ]


class EventTrace(C.Structure):
    _fields_ = [
        ('Header', EventTraceHeader), ('InstanceId', U32), ('ParentInstanceId', U32),
        ('ParentGuid', GUID), ('MofData', PTR), ('MofLength', U32),
        ('ClientContext', U32),
    ]


class TraceLogfileHeader(C.Structure):
    _fields_ = [
        ('BufferSize', U32), ('Version', U32), ('ProviderVersion', U32),
        ('NumberOfProcessors', U32), ('EndTime', I64),
        ('TimerResolution', U32), ('MaximumFileSize', U32),
        ('LogFileMode', U32), ('BuffersWritten', U32),
        ('LogInstanceGuid', GUID), ('LoggerName', PTR), ('LogFileName', PTR),
        ('TimeZoneInformation', U8 * 172),
        ('BootTime', I64), ('PerfFreq', I64), ('StartTime', I64),
        ('ReservedFlags', U32), ('BuffersLost', U32),
    ]


class EventTraceLogfileW(C.Structure):
    _fields_ = [
        ('LogFileName', PTR), ('LoggerName', PTR), ('CurrentTime', I64),
        ('BuffersRead', U32), ('ProcessTraceMode', U32),
        ('CurrentEvent', EventTrace), ('LogfileHeader', TraceLogfileHeader),
        ('BufferCallback', PTR), ('BufferSize', U32), ('Filled', U32),
        ('EventsLost', U32), ('EventRecordCallback', PTR),
        ('IsKernelTrace', U32), ('Context', PTR),
    ]


def check_abi() -> None:
    """Fail before calling native code if the ctypes layout isn't Windows x64."""
    expected = {
        'GUID': (GUID, 16), 'EventDescriptor': (EventDescriptor, 16),
        'EventHeader': (EventHeader, 80), 'EventTraceHeader': (EventTraceHeader, 48),
        'EventTrace': (EventTrace, 88), 'EventRecord': (EventRecord, 112),
        'TraceLogfileHeader': (TraceLogfileHeader, 280),
        'EventTraceLogfileW': (EventTraceLogfileW, 448),
    }
    if os.name != 'nt' or C.sizeof(PTR) != 8:
        raise OSError('Native ETL ingestion requires 64-bit Python on Windows')
    for name, (klass, size) in expected.items():
        if C.sizeof(klass) != size:
            raise RuntimeError(f'ABI mismatch for {name}: {C.sizeof(klass)}, expected {size}')


def windows_filetime(value: int) -> str | None:
    if not value:
        return None
    try:
        # Integer arithmetic preserves 100 ns increments to the nearest microsecond.
        stamp = EPOCH + timedelta(microseconds=value // 10)
    except (OverflowError, ValueError):
        return None
    return stamp.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def read_event(record: EventRecord) -> dict:
    """Make a Python-owned copy before the ETW callback returns."""
    header = record.EventHeader
    length = int(record.UserDataLength)
    payload = C.string_at(record.UserData, length) if length and record.UserData else b''
    extended = []
    if record.ExtendedData and record.ExtendedDataCount:
        for item in record.ExtendedData[:record.ExtendedDataCount]:
            entry = {'type': int(item.ExtType), 'size': int(item.DataSize)}
            if item.DataPtr and item.DataSize:
                entry['hex'] = C.string_at(item.DataPtr, item.DataSize).hex()
            extended.append(entry)
    desc = header.EventDescriptor
    provider = header.ProviderId.text()
    return {
        'timestamp_utc': windows_filetime(int(header.TimeStamp)),
        'timestamp_filetime_100ns': int(header.TimeStamp),
        'pid': int(header.ProcessId), 'tid': int(header.ThreadId),
        'provider_guid': provider, 'event_id': int(desc.Id),
        'message_id': int(desc.Id),
        'level': int(desc.Level), 'opcode': int(desc.Opcode),
        'task': int(desc.Task), 'keywords': f'0x{int(desc.Keyword):016x}',
        'event_version': int(desc.Version), 'channel': int(desc.Channel),
        'header_flags': f'0x{int(header.Flags):04x}',
        'activity_id': header.ActivityId.text(),
        'cpu_index': int(record.BufferContext.ProcessorIndex),
        'payload_hex': payload.hex(), 'payload_length': length,
        'extended_data': extended,
        'wpp_trace_message': bool(header.Flags & EVENT_HEADER_FLAG_TRACE_MESSAGE),
        'extraction_method': 'windows_event_record_callback',
    }


def consume_etl(path: Path, callback: Callable[[dict], None], use_tdh: bool = True) -> dict:
    """Stream records through Windows ProcessTrace; no event is dropped by design.

    The caller must raise for I/O failure. Exceptions cannot propagate directly
    across a ctypes callback; we store the first and raise it after ProcessTrace.
    """
    check_abi()
    dll = C.WinDLL('advapi32', use_last_error=True)
    dll.OpenTraceW.argtypes = [C.POINTER(EventTraceLogfileW)]
    dll.OpenTraceW.restype = U64
    dll.ProcessTrace.argtypes = [C.POINTER(U64), U32, PTR, PTR]
    dll.ProcessTrace.restype = U32
    dll.CloseTrace.argtypes = [U64]
    dll.CloseTrace.restype = U32

    on_record_type = C.WINFUNCTYPE(None, C.POINTER(EventRecord))
    errors: list[Exception] = []
    count = 0
    if use_tdh:
        from .tdh import Tdh
        tdh = Tdh()
    else:
        tdh = None

    def on_record(pointer: C.POINTER(EventRecord)) -> None:
        nonlocal count
        if errors:
            return
        try:
            event = read_event(pointer.contents)
            if (tdh is not None
                    and (event['wpp_trace_message'] or event['provider_guid'] == SRUM_PROVIDER_GUID)
                    and parse_session_header(event) is None):
                event.update(tdh.describe(C.cast(pointer, PTR), event['provider_guid'],
                                          event['wpp_trace_message']))
            callback(event)
            count += 1
        except Exception as exc:
            errors.append(exc)

    handler = on_record_type(on_record)
    logfile = EventTraceLogfileW()
    filepath = C.create_unicode_buffer(str(path.resolve()))
    logfile.LogFileName = C.cast(filepath, PTR)
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD
    logfile.EventRecordCallback = C.cast(handler, PTR)

    handle = dll.OpenTraceW(C.byref(logfile))
    invalid = (1 << (8 * C.sizeof(PTR))) - 1
    if handle == invalid:
        raise OSError(C.get_last_error(), f'OpenTraceW failed for {path}')
    try:
        handles = (U64 * 1)(handle)
        status = dll.ProcessTrace(handles, 1, None, None)
    finally:
        dll.CloseTrace(handle)
    if errors:
        raise RuntimeError('ETW callback failed') from errors[0]
    if status:
        raise OSError(status, f'ProcessTrace failed with Windows status {status}')
    return {
        'events_read': count,
        'tdh_attempted': use_tdh,
        'buffers_read': int(logfile.BuffersRead),
        'events_lost_reported': int(logfile.EventsLost),
        'file_mode': int(logfile.LogfileHeader.LogFileMode),
        'buffers_lost_reported': int(logfile.LogfileHeader.BuffersLost),
    }
