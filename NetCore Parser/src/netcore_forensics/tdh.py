"""Read optional WPP and SruMon properties from Windows TDH metadata.

Failures are expected when Microsoft has not shipped TMFs or manifest data.
The original UserData remains available regardless of TDH results.
"""

from __future__ import annotations

import ctypes as C
import uuid


class PropertyDataDescriptor(C.Structure):
    _fields_ = [
        ('PropertyName', C.c_uint64),
        ('ArrayIndex', C.c_uint32),
        ('Reserved', C.c_uint32),
    ]


class Tdh:
    def __init__(self) -> None:
        self.dll = C.WinDLL('tdh.dll')
        self.dll.TdhGetPropertySize.argtypes = [
            C.c_void_p, C.c_uint32, C.c_void_p, C.c_uint32,
            C.POINTER(PropertyDataDescriptor), C.POINTER(C.c_uint32),
        ]
        self.dll.TdhGetPropertySize.restype = C.c_uint32
        self.dll.TdhGetProperty.argtypes = [
            C.c_void_p, C.c_uint32, C.c_void_p, C.c_uint32,
            C.POINTER(PropertyDataDescriptor), C.c_uint32, C.c_void_p,
        ]
        self.dll.TdhGetProperty.restype = C.c_uint32

    def get(self, event_pointer: C.c_void_p, name: str) -> bytes | None:
        text = C.create_unicode_buffer(name)
        desc = PropertyDataDescriptor(C.cast(text, C.c_void_p).value, 0, 0)
        length = C.c_uint32()
        status = self.dll.TdhGetPropertySize(event_pointer, 0, None, 1,
                                              C.byref(desc), C.byref(length))
        if status or length.value > 64 * 1024:
            return None
        if length.value == 0:
            return b''
        buf = C.create_string_buffer(length.value)
        status = self.dll.TdhGetProperty(event_pointer, 0, None, 1, C.byref(desc),
                                         length.value, C.cast(buf, C.c_void_p))
        return bytes(buf) if status == 0 else None

    def describe(self, event_pointer: C.c_void_p, provider: str, is_wpp: bool) -> dict:
        fields: dict = {}
        if is_wpp:
            guid = self.get(event_pointer, 'TraceGuid')
            if guid and len(guid) == 16:
                fields['wpp_guid'] = str(uuid.UUID(bytes_le=guid))
            name = self.get(event_pointer, 'GuidName')
            if name:
                fields['tdh_module_name'] = name.decode('utf-16le', errors='replace').rstrip('\0')
            # FormattedString requires WPP TMF symbols. If not available, avoid
            # guessing from arbitrary binary data and retain the raw payload.
        if provider == 'c8dbf506-e3d3-4822-930d-84c557eb6247':
            function = self.get(event_pointer, '_FunctionName')
            if function:
                fields['event_data'] = {
                    '_FunctionName': function.decode('utf-16le', errors='replace').rstrip('\0')
                }
                for key in ('_Status', '_HR'):
                    value = self.get(event_pointer, key)
                    if value and len(value) == 4:
                        fields['event_data'][key] = int.from_bytes(value, 'little', signed=True)
        return fields
