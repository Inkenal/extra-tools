"""Observed NetCore layouts from the v5 research series.

These functions parse structural features. They are not Microsoft WPP TMFs and
must not be presented as proof of a network connection. Their inputs are event
payload bodies, *not* arbitrary bytes carved from an ETL file.
"""
import ipaddress
import re
import struct
import uuid

CONNECTIVITY_GUID = "7ac5404b-0acd-3d12-3291-2bdf0dea9484"
NCSI = "39029d0f-1cab-3381-7bfa-38f3a8fd428e"
ADDITIONAL_GUIDS = {
 "f3678906-e82d-358d-81de-92bc83cd5ad3",
 "24453f6e-f0f9-3f0a-c888-f4d3af4fe751",
 "8ae0ccb2-d1f7-3880-d1d9-09f791e673db",
 "24b76497-5f5d-36a6-0ef4-a9feba7d0550",
 "acbb59b9-c830-3de7-bfff-ef0115061b17",
}
GUID_CONNECTIVITY = "53533f3c-7588-3bc3-9ead-1e6c10b4b917"
GUID_NCSI_A = "2cec06c4-4a63-3e3f-7c35-57ceb565f029"
GUID_NCSI_B = "44cb5004-0beb-36f6-6980-3df7edb26194"
IDENTIFIER_TEXT = re.compile(r"^\{[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\}$")

def printable_runs(payload):
    # Show only unambiguously printable strings. Offsets are payload-relative.
    a = []
    for m in re.finditer(rb'[\x20-\x7e]{5,}', payload):
        a.append({'offset': m.start(), 'encoding': 'ascii', 'value': m.group().decode('ascii')[:200]})
    # Matching pairs of low ASCII/zero can occur at either byte alignment.
    for align in (0, 1):
        seq = rb'(?:[\x20-\x7e]\x00){4,}'
        for m in re.finditer(seq, payload[align:]):
            a.append({'offset': align+m.start(), 'encoding': 'utf-16le',
                      'value': m.group().decode('utf-16le')[:200]})
    a.sort(key=lambda x: (x['offset'], x['encoding']))
    # Identical overlapping candidates add noise and inflate large JSONL files.
    unique = []
    seen = set()
    for item in a:
        key = (item['offset'], item['encoding'], item['value'])
        if key not in seen:
            seen.add(key)
            unique.append(item)
            if len(unique) == 30:
                break
    return unique


def describe_payload(payload):
    n = len(payload)
    result = {'size': n, 'strings': printable_runs(payload)}
    if n in (4, 8, 12):
        result['u32_le'] = list(struct.unpack('<'+'I'*(n//4), payload))
    if n >= 16 and n % 4 == 0 and n <= 32:
        result['first_four_u32_le'] = list(struct.unpack('<IIII', payload[:16]))
        if n == 16:
            # Candidate GUID interpretation only; not an asserted field type.
            result['candidate_guid'] = str(uuid.UUID(bytes_le=payload))
    return result


def decode_connectivity(mid, payload):
    """Decode only fields directly supported by DLL logging helpers and observed payloads.

    This does not identify socket destinations, initiating EXEs, or user intent.
    """
    n = len(payload)
    data = {'message_id': mid, 'confidence': 'payload-and-static-analysis'}
    if mid in (20, 23, 25, 27, 32, 42) and n == 16:
        data.update(kind='16_byte_identifier', candidate_interface_guid=str(uuid.UUID(bytes_le=payload)))
    elif mid == 30 and n >= 22:
        try:
            name_raw = payload[16:-4]
            if len(name_raw) % 2 != 0:
                return None
            name = name_raw.decode('utf-16le').rstrip('\x00')
            data.update(kind='interface_name_record', candidate_interface_guid=str(uuid.UUID(bytes_le=payload[:16])),
                        network_name=name, trailing_u32=struct.unpack('<I', payload[-4:])[0])
        except UnicodeDecodeError:
            return None
    elif mid in (33, 39) and n == 0:
        data.update(kind='empty_event')
    elif mid in (41, 50, 95) and n == 4:
        data.update(kind='u32_value', value=struct.unpack('<I',payload)[0])
    elif mid in (96, 97, 98, 99):
        function_raw, sep, remainder = payload.partition(b'\x00')
        if not sep:
            return None
        if len(remainder) != (0 if mid in (96, 98) else 4):
            return None
        try:
            function = function_raw.decode('ascii')
        except UnicodeDecodeError:
            return None
        if not function.startswith('long __cdecl Windows::Networking::Connectivity::'):
            return None
        k = 'function_entry' if mid in (96, 98) else 'function_result'
        data.update(kind=k, function_signature=function)
        m = re.search(r'::([A-Za-z_][A-Za-z_0-9]*)\(',function)
        if m:
            data['method_name'] = m.group(1)
        if remainder:
            result = struct.unpack('<i', remainder)[0]
            data['hresult_signed'] = result
            data['hresult_hex'] = f'0x{result & 0xffffffff:08X}'
            data['succeeded'] = result >= 0
    else:
        return None
    return data


def decode_additional(guid, mid, payload):
    """Conservative format extraction for 5 additional GUID families.

    Interpretation reflects observed binary layouts, NOT vendor WPP message semantics.
    Unknown layouts return None, not an invented event meaning.
    """
    n = len(payload)
    result = {'kind': None, 'confidence': 'observed-structure-only'}
    guidsingle = lambda b: str(uuid.UUID(bytes_le=b))
    if guid == 'f3678906-e82d-358d-81de-92bc83cd5ad3':
        if mid == 17 and n == 16:
            result.update(kind='identifier_16', candidate_interface_guid=guidsingle(payload))
        elif mid == 23 and n == 32:
            result.update(kind='two_identifiers_16', values=[guidsingle(payload[:16]), guidsingle(payload[16:])])
        elif mid == 25 and n == 4:
            result.update(kind='u32_value', value=struct.unpack('<I',payload)[0])
        elif mid == 27 and n > 18 and (n-16)%2 == 0:
            try:
                name=payload[16:].decode('utf-16le').rstrip('\x00')
                if not name or any(ord(c)<32 for c in name):return None
            except UnicodeDecodeError:return None
            result.update(kind='interface_identifier_and_name', candidate_interface_guid=guidsingle(payload[:16]), network_name=name)
        elif mid == 28 and n == 0:
            result.update(kind='empty_event')
    elif guid == '24453f6e-f0f9-3f0a-c888-f4d3af4fe751':
        if mid == 16 and n >= 20:
            # This variable layout includes a 16-byte identifier, null terminated UTF16
            # interface name, another UTF16 string, ASCII media tag and trailing opaque data.
            try:
                rest=payload[16:]
                end=next(i for i in range(0,len(rest)-1,2) if rest[i:i+2] == b'\x00\x00')
                name=rest[:end].decode('utf-16le')
                if not name or not name.isprintable():return None
                result.update(kind='compound_interface_record', candidate_interface_guid=guidsingle(payload[:16]), network_name=name,
                              remaining_payload_hex=rest[end+2:].hex(), remaining_fields_unresolved=True)
            except (StopIteration,UnicodeDecodeError):return None
        elif mid == 17 and n == 16:
            result.update(kind='identifier_16', candidate_interface_guid=guidsingle(payload))
        elif mid == 63 and n == 20:
            result.update(kind='identifier_plus_u32', candidate_interface_guid=guidsingle(payload[:16]), value=struct.unpack('<I',payload[16:])[0])
        elif mid in (65,66) and n == 4:
            result.update(kind='u32_value',value=struct.unpack('<I',payload)[0])
        elif mid in (20,43,47) and n == 0:
            result.update(kind='empty_event')
    elif guid == '8ae0ccb2-d1f7-3880-d1d9-09f791e673db':
        if mid == 11 and n >= 4 and n%2 == 0:
            try:
                name=payload.decode('utf-16le').rstrip('\x00')
                if not name.startswith('Windows.Networking.Connectivity.') or not name.isprintable():return None
            except UnicodeDecodeError:return None
            result.update(kind='winrt_type_name', class_name=name)
        elif mid in (12,14,16) and n == 4:
            result.update(kind='u32_value',value=struct.unpack('<I',payload)[0])
        elif mid == 13 and n == 0:
            result.update(kind='empty_event')
        elif mid == 15 and n == 32:
            result.update(kind='two_identifiers_16',values=[guidsingle(payload[:16]),guidsingle(payload[16:])], semantics_unconfirmed=True)
    elif guid == '24b76497-5f5d-36a6-0ef4-a9feba7d0550' and mid in (25,26,27,28,29,30) and n == 0:
        result.update(kind='empty_event')
    elif guid == 'acbb59b9-c830-3de7-bfff-ef0115061b17' and mid in (10,11) and n == 0:
        result.update(kind='empty_event')
    return result if result['kind'] else None


def decode_ncsi(mid,payload):
 """Conservative, observed content only; does NOT assign destination/connection semantics."""
 if mid in (17,18):
  prefix=28 if mid==17 else 52
  if len(payload)<=prefix:return None
  s=payload[prefix:].split(b'\0',1)[0]
  if not s.startswith(b'PathState') or not all(32<=x<127 for x in s): return None
  value={'kind':'ncsi_path_state_diagnostic','state_label':s.decode('ascii'),'prefix_hex':payload[:prefix].hex(),
         'confidence':'validated payload string; prefix field semantics unknown'}
  try:
   if mid==17: value['address_bytes_candidate_ipv4']=str(ipaddress.IPv4Address(payload[8:12]))
   else: value['address_bytes_candidate_ipv6']=str(ipaddress.IPv6Address(payload[8:24]))
  except (ValueError,ipaddress.AddressValueError):pass
  return value
 if mid==10 and len(payload)>9:
  s=payload[8:].split(b'\0',1)[0]
  if s.startswith(b'Nl') and all(32<=x<127 for x in s):
   return {'kind':'ncsi_object_name','object_label':s.decode('ascii'),'prefix_hex':payload[:8].hex(),'confidence':'observed payload string'}
 if mid in (15,16):
  txt=describe_payload(payload)['strings']
  return {'kind':'ncsi_reachability_diagnostic','printable_fields':txt, 'confidence':'strings only; address roles unknown'} if txt else None
 return None


def decode_rare(guid, message_id, payload):
    guid = (guid or '').lower()
    n = len(payload)
    if guid == GUID_CONNECTIVITY and message_id == 11 and n == 4:
        return {'kind': 'observed_u32', 'value': struct.unpack('<I', payload)[0],
                'confidence': 'observed field width; semantics unverified'}
    if guid == GUID_NCSI_A:
        if message_id == 13 and n == 0:
            return {'kind': 'empty_event', 'confidence': 'observed exact empty payload'}
        if message_id in (14, 15) and n == 12:
            return {'kind': 'observed_three_u32', 'values_le': list(struct.unpack('<III', payload)),
                    'confidence': 'observed field widths; semantics unverified'}
    if guid == GUID_NCSI_B:
        if message_id == 30 and n == 0:
            return {'kind': 'empty_event', 'confidence': 'observed exact empty payload'}
        if message_id == 11 and n == 8:
            return {'kind': 'observed_two_u32', 'values_le': list(struct.unpack('<II', payload)),
                    'confidence': 'observed field widths; semantics unverified'}
        if message_id == 13 and n >= 78:
            try:
                candidate = payload[:76].decode('utf-16le')
            except UnicodeDecodeError:
                return None
            if not IDENTIFIER_TEXT.fullmatch(candidate) or payload[76:78] != b'\x00\x00':
                return None
            interface_id = str(uuid.UUID(candidate[1:-1]))
            return {'kind': 'text_guid_plus_opaque_suffix',
                    'candidate_interface_guid': interface_id,
                    'text_guid': candidate,
                    'opaque_suffix_hex': payload[78:].hex(),
                    'opaque_suffix_bytes': n - 78,
                    'confidence': 'validated UTF-16LE GUID text; suffix fields not decoded'}
    return None
