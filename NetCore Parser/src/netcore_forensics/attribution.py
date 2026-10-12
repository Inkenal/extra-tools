"""Read-only, bounded binary GUID lookup for previously unclassified events.

Binary presence establishes an association, *not* the origin or meaning of an
ETW event. Results are reported separately from the original evidence files.
"""

from __future__ import annotations

import hashlib
import mmap
from collections import Counter
from pathlib import Path
from uuid import UUID

# Fixed, intentionally narrow allowlist. No directory walking or deep scan.
NETWORK_DLLS = (
    'ncsi.dll', 'nlasvc.dll', 'netprofm.dll', 'netprofmsvc.dll',
    'wcmsvc.dll', 'wcmcsp.dll', 'wcmapi.dll',
    'Windows.Networking.Connectivity.dll', 'OnDemandConnRouteHelper.dll',
    'dnsapi.dll', 'dusmsvc.dll', 'netman.dll', 'nlaapi.dll',
)
# These are *candidate* diagnostic families for explanatory sidecar output.
# They never become classifications without separate event-level evidence.
DLL_FAMILY_HINTS = {
    'ncsi.dll': 'network_connectivity_diagnostic',
    'netprofm.dll': 'network_profile_diagnostic',
    'netprofmsvc.dll': 'network_profile_diagnostic',
    'wcmsvc.dll': 'connection_manager_diagnostic',
    'wcmcsp.dll': 'connection_manager_diagnostic',
    'wcmapi.dll': 'connection_manager_diagnostic',
    'Windows.Networking.Connectivity.dll': 'network_connectivity_api_diagnostic',
    'OnDemandConnRouteHelper.dll': 'connection_routing_diagnostic',
    'dusmsvc.dll': 'data_usage_service_diagnostic',
}
MAX_GUIDS = 256
MAX_DLL_BYTES = 64 * 1024 * 1024


def _valid_guid(text: str) -> bool:
    try:
        return str(UUID(text)) == text
    except (ValueError, AttributeError, TypeError):
        return False


def scan_unknown_guids(
    occurrences: Counter[str], windows_dir: Path | None, *, origin: str,
) -> dict:
    """Search fixed System32 DLL filenames only, at most once per case.

    Every match is an untrusted *binary association*. In particular, no match
    can change an event's classification, decode_status, or raw binary payload.
    An automatic local scan describes the *analysis* computer, not necessarily
    the computer that produced a copied ETL.
    """
    counts = occurrences.most_common()
    result = {
        'status': 'no_unknown_guids' if not counts else 'not_scanned',
        'binary_origin': origin,
        'windows_directory': str(windows_dir) if windows_dir is not None else None,
        'method': 'exact_guid_le_bytes_in_allowlisted_system32_dlls',
        'interpretation': 'binary_association_only_not_proof_of_emitter_or_event_meaning',
        'unknown_guid_count': len(counts),
        'candidate_limit': MAX_GUIDS,
        'scanned_guid_count': 0,
        'matched_guid_count': 0,
        'unresolved_guid_count': 0,
        'unscanned_guid_count': 0,
        'dlls_read': 0,
        'dlls_missing': [],
        'dlls_unreadable': [],
        'dlls_skipped': [],
        'results': [],
    }
    if not counts:
        return result
    if windows_dir is None:
        result['status'] = 'no_windows_directory_available'
        result['unscanned_guid_count'] = len(counts)
        result['results'] = [{'guid': guid, 'occurrences': count,
                              'status': 'not_scanned', 'matches': []}
                             for guid, count in counts]
        return result

    targets = [(guid, count) for guid, count in counts if _valid_guid(guid)][:MAX_GUIDS]
    # Invalid identifiers are kept in the unresolved/omitted counts, not silently
    # converted to arbitrary GUIDs.
    target_guids = {guid: [] for guid, _ in targets}
    needles = [(guid, UUID(guid).bytes_le) for guid, _ in targets]
    result['scanned_guid_count'] = len(targets)
    result['unscanned_guid_count'] = len(counts) - len(targets)
    result['status'] = 'completed'

    for filename in NETWORK_DLLS:
        path = windows_dir / 'System32' / filename
        try:
            stat = path.stat()
            if not path.is_file():
                raise OSError('not a regular file')
        except FileNotFoundError:
            result['dlls_missing'].append(filename)
            continue
        except OSError as exc:
            result['dlls_unreadable'].append({'dll': filename, 'error': type(exc).__name__})
            continue
        if not (0 < stat.st_size <= MAX_DLL_BYTES):
            result['dlls_skipped'].append({'dll': filename, 'reason': 'size_outside_limit'})
            continue
        try:
            with path.open('rb') as fp:
                with mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ) as binary:
                    result['dlls_read'] += 1
                    hits = [(guid, binary.find(needle)) for guid, needle in needles]
                    hits = [(guid, offset) for guid, offset in hits if offset >= 0]
                    if hits:
                        digest = hashlib.sha256(binary).hexdigest()
                        for guid, offset in hits:
                            target_guids[guid].append({
                                'dll': filename,
                                'offset_hex': f'0x{offset:X}',
                                'dll_sha256': digest,
                                'dll_bytes': stat.st_size,
                            })
        except (OSError, ValueError) as exc:
            result['dlls_unreadable'].append({'dll': filename, 'error': type(exc).__name__})

    for guid, count in counts:
        if guid not in target_guids:
            result['results'].append({'guid': guid, 'occurrences': count,
                                      'status': 'not_scanned', 'matches': []})
            continue
        matches = target_guids[guid]
        families = {DLL_FAMILY_HINTS.get(item['dll']) for item in matches}
        # Even a unique family hint is only a lead: the DLL might merely
        # reference the GUID. Mixed/unknown families are left ambiguous.
        candidate_family = next(iter(families)) if len(families) == 1 else None
        result['results'].append({
            'guid': guid, 'occurrences': count,
            'status': 'binary_match' if matches else 'no_match_in_allowlist',
            'candidate_family_unverified': candidate_family,
            'matches': matches,
        })
        if matches:
            result['matched_guid_count'] += 1
        else:
            result['unresolved_guid_count'] += 1
    if result['dlls_unreadable'] or result['dlls_skipped'] or result['unscanned_guid_count']:
        result['status'] = 'partial_scan'
    if result['dlls_read'] == 0:
        result['status'] = 'no_readable_allowlisted_dlls'
    return result
