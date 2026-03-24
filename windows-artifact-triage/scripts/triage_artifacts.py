#!/usr/bin/env python3
"""
Windows Artifact Triage Engine
Parses EZTools CSV, Chainsaw JSON, Hayabusa CSV, and produces correlated forensic analysis.
Part of the DFIR Skills Suite for Claude.
"""

import argparse
import csv
import json
import sys
import os
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from io import StringIO

# Try pandas for performance, fall back to csv module
try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False
    print("[!] pandas not available, using csv module (slower for large files)", file=sys.stderr)


# ─── Timestamp Helpers ───────────────────────────────────────────────────────

def parse_ts(ts_str):
    """Parse various timestamp formats to datetime. Returns None on failure."""
    if not ts_str or ts_str in ('', 'N/A', 'null', 'None'):
        return None
    ts_str = str(ts_str).strip()
    formats = [
        '%Y-%m-%d %H:%M:%S.%f',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%S.%fZ',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%SZ',
        '%m/%d/%Y %H:%M:%S',
        '%m/%d/%Y %I:%M:%S %p',
        '%d/%m/%Y %H:%M:%S',
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts_str[:len(ts_str)], fmt)
        except (ValueError, TypeError):
            continue
    return None


def ts_to_iso(dt):
    """Convert datetime to ISO format string."""
    if dt:
        return dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    return ''


# ─── Suspicious Path Detection ───────────────────────────────────────────────

SUSPICIOUS_PATHS = [
    r'\Users\Public\\',
    r'\AppData\Local\Temp\\',
    r'\AppData\Roaming\\',
    r'\ProgramData\\',
    r'\Windows\Temp\\',
    r'\Recycle',
    r'\$Recycle',
    r'C:\Temp\\',
    r'C:\tmp\\',
    r'\Downloads\\',
    r'\perflogs\\',
]

SUSPICIOUS_EXES = [
    'psexec', 'psexesvc', 'mimikatz', 'procdump', 'lazagne',
    'sharphound', 'bloodhound', 'rubeus', 'certutil',
    'bitsadmin', 'mshta', 'regsvr32', 'rundll32', 'wscript',
    'cscript', 'powershell', 'pwsh', 'cmd',
    'whoami', 'nltest', 'dsquery', 'net1', 'netsh',
    'rar', '7z', 'rclone', 'megasync',  # Exfil tools
    'nc', 'ncat', 'socat', 'chisel', 'plink',  # Tunneling
]

PERSISTENCE_REG_PATHS = [
    r'CurrentVersion\Run',
    r'CurrentVersion\RunOnce',
    r'CurrentVersion\RunServices',
    r'CurrentVersion\Explorer\Shell Folders',
    r'CurrentVersion\Explorer\User Shell Folders',
    r'CurrentVersion\Winlogon',
    r'CurrentVersion\Image File Execution Options',
    r'CurrentVersion\Windows\AppInit_DLLs',
    r'Control\SafeBoot',
    r'Environment\UserInitMprLogonScript',
    r'Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
]


def is_suspicious_path(path):
    """Check if a file path is in a suspicious location."""
    if not path:
        return False
    path_lower = path.lower()
    return any(sp.lower() in path_lower for sp in SUSPICIOUS_PATHS)


def is_suspicious_exe(name):
    """Check if an executable name matches known offensive tools."""
    if not name:
        return False
    name_lower = name.lower().replace('.exe', '').replace('.com', '').replace('.bat', '')
    return name_lower in SUSPICIOUS_EXES


# ─── CSV Parsers (one per artifact type) ─────────────────────────────────────

def read_csv_robust(filepath, encoding='utf-8'):
    """Read CSV handling encoding issues and BOM."""
    encodings = [encoding, 'utf-8-sig', 'utf-16', 'latin-1', 'cp1252']
    for enc in encodings:
        try:
            if HAS_PANDAS:
                df = pd.read_csv(filepath, encoding=enc, low_memory=False)
                return df.to_dict('records')
            else:
                with open(filepath, 'r', encoding=enc, errors='replace') as f:
                    reader = csv.DictReader(f)
                    return list(reader)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return []


def parse_prefetch(filepath):
    """Parse PECmd CSV output → evidence of execution."""
    records = read_csv_robust(filepath)
    results = []
    for r in records:
        exe_name = r.get('ExecutableName', r.get('SourceFilename', ''))
        if not exe_name:
            continue
        entry = {
            'source': 'prefetch',
            'executable': exe_name,
            'run_count': int(r.get('RunCount', 0) or 0),
            'last_run': r.get('LastRun', ''),
            'previous_runs': [r.get(f'PreviousRun{i}', '') for i in range(7)
                              if r.get(f'PreviousRun{i}', '')],
            'source_path': r.get('SourceFilename', ''),
            'suspicious_path': is_suspicious_path(r.get('SourceFilename', '')),
            'suspicious_exe': is_suspicious_exe(exe_name),
            'volume_info': r.get('VolumeInformation', ''),
        }
        # Parse all timestamps for timeline
        ts = parse_ts(r.get('LastRun', ''))
        if ts:
            entry['timestamp'] = ts_to_iso(ts)
        results.append(entry)
    return results


def parse_amcache(filepath):
    """Parse AmcacheParser CSV → evidence of execution + hashes."""
    records = read_csv_robust(filepath)
    results = []
    for r in records:
        name = r.get('Name', r.get('ProgramName', ''))
        path = r.get('FullPath', r.get('FilePath', ''))
        sha1 = r.get('SHA1', r.get('FileId', ''))
        if sha1 and sha1.startswith('0000'):
            sha1 = sha1[4:]  # Amcache SHA1 prefix removal
        entry = {
            'source': 'amcache',
            'executable': name,
            'full_path': path,
            'sha1': sha1,
            'publisher': r.get('Publisher', ''),
            'version': r.get('Version', r.get('BinFileVersion', '')),
            'timestamp': r.get('FileKeyLastWriteTimestamp',
                              r.get('LastWriteTimestamp', '')),
            'suspicious_path': is_suspicious_path(path),
            'suspicious_exe': is_suspicious_exe(name),
        }
        results.append(entry)
    return results


def parse_shimcache(filepath):
    """Parse AppCompatCacheParser CSV → evidence of execution."""
    records = read_csv_robust(filepath)
    results = []
    for r in records:
        path = r.get('Path', r.get('CachePath', ''))
        entry = {
            'source': 'shimcache',
            'full_path': path,
            'executable': os.path.basename(path) if path else '',
            'last_modified': r.get('LastModifiedTimeUTC', r.get('LastModified', '')),
            'cache_position': int(r.get('CacheEntryPosition', r.get('ControlSet', 0)) or 0),
            'suspicious_path': is_suspicious_path(path),
            'suspicious_exe': is_suspicious_exe(os.path.basename(path) if path else ''),
        }
        ts = parse_ts(r.get('LastModifiedTimeUTC', r.get('LastModified', '')))
        if ts:
            entry['timestamp'] = ts_to_iso(ts)
        results.append(entry)
    return results


def parse_evtx(filepath):
    """Parse EvtxECmd CSV → security events with categorization."""
    records = read_csv_robust(filepath)
    results = {
        'logons': [],
        'failed_logons': [],
        'process_creation': [],
        'service_installs': [],
        'scheduled_tasks': [],
        'account_changes': [],
        'log_cleared': [],
        'other_notable': [],
    }

    for r in records:
        eid = str(r.get('EventId', r.get('EventID', '')))
        ts_str = r.get('TimeCreated', r.get('SystemTime', ''))
        channel = r.get('Channel', '')
        computer = r.get('Computer', '')
        map_desc = r.get('MapDescription', '')

        base = {
            'timestamp': ts_str,
            'event_id': eid,
            'channel': channel,
            'computer': computer,
            'map_description': map_desc,
            'payload': {f'PayloadData{i}': r.get(f'PayloadData{i}', '')
                       for i in range(1, 7) if r.get(f'PayloadData{i}', '')},
        }

        if eid == '4624':
            base['logon_type'] = _extract_payload_field(r, 'LogonType', 'PayloadData3')
            base['source_ip'] = _extract_payload_field(r, 'IpAddress', 'PayloadData5')
            base['target_user'] = _extract_payload_field(r, 'TargetUserName', 'PayloadData1')
            results['logons'].append(base)
        elif eid == '4625':
            base['logon_type'] = _extract_payload_field(r, 'LogonType', 'PayloadData3')
            base['source_ip'] = _extract_payload_field(r, 'IpAddress', 'PayloadData5')
            base['target_user'] = _extract_payload_field(r, 'TargetUserName', 'PayloadData1')
            base['failure_reason'] = _extract_payload_field(r, 'FailureReason', 'PayloadData2')
            results['failed_logons'].append(base)
        elif eid in ('4688', '1'):  # Process creation / Sysmon Event 1
            base['process'] = _extract_payload_field(r, 'NewProcessName', 'PayloadData1')
            base['command_line'] = _extract_payload_field(r, 'CommandLine', 'PayloadData2')
            base['parent_process'] = _extract_payload_field(r, 'ParentProcessName', 'PayloadData4')
            base['user'] = _extract_payload_field(r, 'SubjectUserName', 'PayloadData3')
            results['process_creation'].append(base)
        elif eid in ('7045', '4697'):
            base['service_name'] = _extract_payload_field(r, 'ServiceName', 'PayloadData1')
            base['service_path'] = _extract_payload_field(r, 'ImagePath', 'PayloadData2')
            base['service_type'] = _extract_payload_field(r, 'ServiceType', 'PayloadData3')
            base['service_start'] = _extract_payload_field(r, 'StartType', 'PayloadData4')
            results['service_installs'].append(base)
        elif eid == '4698':
            base['task_name'] = _extract_payload_field(r, 'TaskName', 'PayloadData1')
            base['task_content'] = _extract_payload_field(r, 'TaskContent', 'PayloadData2')
            results['scheduled_tasks'].append(base)
        elif eid in ('4720', '4722', '4723', '4724', '4725', '4726', '4728', '4732', '4756'):
            base['target_account'] = _extract_payload_field(r, 'TargetUserName', 'PayloadData1')
            base['group_name'] = _extract_payload_field(r, 'GroupName', 'PayloadData2')
            results['account_changes'].append(base)
        elif eid == '1102':
            results['log_cleared'].append(base)
        elif eid in ('4672', '4648', '5140', '5145', '5857', '5860', '5861'):
            results['other_notable'].append(base)

    return results


def _extract_payload_field(record, field_name, fallback_payload):
    """Extract a field from EvtxECmd record, trying named field first, then PayloadData."""
    val = record.get(field_name, '')
    if not val:
        val = record.get(fallback_payload, '')
    return val or ''


def parse_mft(filepath):
    """Parse MFTECmd CSV → file system activity with timestomping detection."""
    records = read_csv_robust(filepath)
    results = []
    timestomped = []

    for r in records:
        filename = r.get('FileName', '')
        parent = r.get('ParentPath', '')
        full_path = f"{parent}\\{filename}" if parent and filename else filename

        si_created = parse_ts(r.get('Created0x10', ''))
        fn_created = parse_ts(r.get('Created0x30', ''))
        si_modified = parse_ts(r.get('LastModified0x10', ''))

        entry = {
            'source': 'mft',
            'filename': filename,
            'parent_path': parent,
            'full_path': full_path,
            'si_created': ts_to_iso(si_created),
            'fn_created': ts_to_iso(fn_created),
            'si_modified': ts_to_iso(si_modified),
            'is_directory': r.get('IsDirectory', 'False') == 'True',
            'file_size': r.get('FileSize', ''),
            'in_use': r.get('InUse', 'True') == 'True',
        }

        # Timestomping detection
        if si_created and fn_created:
            if si_created < fn_created:
                entry['timestomped'] = True
                entry['timestomp_type'] = 'SI_before_FN'
                entry['time_delta_seconds'] = abs((fn_created - si_created).total_seconds())
                timestomped.append(entry)
            # Check for identical timestamps (tool artifact)
            si_all_same = (r.get('Created0x10', '') == r.get('LastModified0x10', '') ==
                          r.get('LastRecordChange0x10', '') == r.get('LastAccess0x10', ''))
            if si_all_same and r.get('Created0x10', ''):
                entry['timestomped'] = True
                entry['timestomp_type'] = 'all_SI_identical'
                if entry not in timestomped:
                    timestomped.append(entry)

        results.append(entry)

    return results, timestomped


def parse_usn_journal(filepath):
    """Parse MFTECmd $J output → file change events."""
    records = read_csv_robust(filepath)
    results = []
    for r in records:
        reasons = r.get('UpdateReasons', '')
        entry = {
            'source': 'usn_journal',
            'timestamp': r.get('UpdateTimestamp', ''),
            'filename': r.get('Name', ''),
            'parent_path': r.get('ParentPath', ''),
            'update_reasons': reasons,
            'is_file_create': 'FileCreate' in reasons,
            'is_file_delete': 'FileDelete' in reasons or 'Close' in reasons,
            'is_data_change': 'DataExtend' in reasons or 'DataOverwrite' in reasons,
            'is_rename': 'RenameNewName' in reasons,
        }
        results.append(entry)
    return results


def parse_chainsaw(filepath):
    """Parse Chainsaw JSON output → sigma detections."""
    with open(filepath, 'r') as f:
        data = json.load(f)

    results = []
    items = data if isinstance(data, list) else data.get('detections', data.get('results', []))
    for d in items:
        entry = {
            'source': 'chainsaw',
            'rule_name': d.get('name', d.get('title', '')),
            'level': d.get('level', d.get('severity', '')),
            'status': d.get('status', ''),
            'timestamp': d.get('timestamp', d.get('system', {}).get('timestamp', '')),
            'sigma_id': d.get('sigma', {}).get('id', '') if isinstance(d.get('sigma'), dict) else '',
            'authors': d.get('authors', []),
            'tags': d.get('tags', []),
            'document': d.get('document', {}),
        }
        results.append(entry)
    return results


def parse_hayabusa(filepath):
    """Parse Hayabusa CSV or JSONL output → detection timeline."""
    results = []

    # Try CSV first
    try:
        records = read_csv_robust(filepath)
        if records and 'Timestamp' in records[0]:
            for r in records:
                entry = {
                    'source': 'hayabusa',
                    'timestamp': r.get('Timestamp', ''),
                    'rule_title': r.get('RuleTitle', r.get('Title', '')),
                    'level': r.get('Level', ''),
                    'computer': r.get('Computer', ''),
                    'channel': r.get('Channel', ''),
                    'event_id': r.get('EventID', r.get('EventId', '')),
                    'details': r.get('Details', r.get('RecordInformation', '')),
                    'mitre_attack': r.get('MitreAttack', r.get('Tags', '')),
                    'rule_file': r.get('RuleFile', ''),
                }
                results.append(entry)
            return results
    except Exception:
        pass

    # Try JSONL
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    d = json.loads(line)
                    entry = {
                        'source': 'hayabusa',
                        'timestamp': d.get('Timestamp', ''),
                        'rule_title': d.get('RuleTitle', ''),
                        'level': d.get('Level', ''),
                        'computer': d.get('Computer', ''),
                        'channel': d.get('Channel', ''),
                        'event_id': str(d.get('EventID', '')),
                        'details': json.dumps(d.get('Details', {})) if isinstance(d.get('Details'), dict) else str(d.get('Details', '')),
                        'mitre_attack': d.get('MitreAttack', ''),
                    }
                    results.append(entry)
    except (json.JSONDecodeError, FileNotFoundError):
        pass

    return results


# ─── Analysis Functions ──────────────────────────────────────────────────────

def analyze_execution(prefetch_data, amcache_data, shimcache_data):
    """Cross-correlate execution evidence across artifact sources."""
    exe_map = defaultdict(lambda: {
        'sources': set(), 'first_seen': None, 'last_seen': None,
        'paths': set(), 'hashes': set(), 'run_count': 0,
        'suspicious': False, 'reasons': [],
    })

    for p in prefetch_data:
        name = p['executable'].lower()
        exe_map[name]['sources'].add('prefetch')
        exe_map[name]['run_count'] = max(exe_map[name]['run_count'], p.get('run_count', 0))
        if p.get('source_path'):
            exe_map[name]['paths'].add(p['source_path'])
        ts = parse_ts(p.get('timestamp', p.get('last_run', '')))
        if ts:
            if not exe_map[name]['last_seen'] or ts > exe_map[name]['last_seen']:
                exe_map[name]['last_seen'] = ts
        if p.get('suspicious_path'):
            exe_map[name]['suspicious'] = True
            exe_map[name]['reasons'].append('suspicious_path')
        if p.get('suspicious_exe'):
            exe_map[name]['suspicious'] = True
            exe_map[name]['reasons'].append('known_tool')

    for a in amcache_data:
        name = a['executable'].lower()
        exe_map[name]['sources'].add('amcache')
        if a.get('full_path'):
            exe_map[name]['paths'].add(a['full_path'])
        if a.get('sha1'):
            exe_map[name]['hashes'].add(a['sha1'])
        if a.get('suspicious_path'):
            exe_map[name]['suspicious'] = True
            exe_map[name]['reasons'].append('suspicious_path')

    for s in shimcache_data:
        name = s['executable'].lower()
        exe_map[name]['sources'].add('shimcache')
        if s.get('full_path'):
            exe_map[name]['paths'].add(s['full_path'])

    # Convert sets to lists for JSON serialization
    output = []
    for exe_name, data in sorted(exe_map.items()):
        data['executable'] = exe_name
        data['sources'] = sorted(data['sources'])
        data['paths'] = sorted(data['paths'])
        data['hashes'] = sorted(data['hashes'])
        data['first_seen'] = ts_to_iso(data['first_seen']) if data['first_seen'] else ''
        data['last_seen'] = ts_to_iso(data['last_seen']) if data['last_seen'] else ''
        data['reasons'] = sorted(set(data['reasons']))
        output.append(data)

    # Sort: suspicious first, then by last_seen descending
    output.sort(key=lambda x: (not x['suspicious'], x.get('last_seen', '') or ''), reverse=False)
    return output


def analyze_persistence(evtx_data, registry_data=None):
    """Identify persistence mechanisms from events and registry."""
    persistence = []

    # Service installations
    for svc in evtx_data.get('service_installs', []):
        entry = {
            'type': 'service_install',
            'timestamp': svc['timestamp'],
            'name': svc.get('service_name', ''),
            'path': svc.get('service_path', ''),
            'suspicious': is_suspicious_path(svc.get('service_path', '')),
            'event_id': svc['event_id'],
        }
        # Check for known malicious service patterns
        path = svc.get('service_path', '').lower()
        if any(x in path for x in ['powershell', 'cmd /c', 'mshta', 'certutil', 'bitsadmin',
                                     '%comspec%', 'psexesvc']):
            entry['suspicious'] = True
            entry['reason'] = 'suspicious_command_in_service_path'
        persistence.append(entry)

    # Scheduled tasks
    for task in evtx_data.get('scheduled_tasks', []):
        persistence.append({
            'type': 'scheduled_task',
            'timestamp': task['timestamp'],
            'name': task.get('task_name', ''),
            'content': task.get('task_content', '')[:500],  # Truncate
            'event_id': task['event_id'],
            'suspicious': True,  # All runtime-created tasks are notable
        })

    return persistence


def analyze_lateral_movement(evtx_data):
    """Detect lateral movement indicators from event logs."""
    lateral = {
        'rdp_sessions': [],
        'network_logons': [],
        'psexec_indicators': [],
        'wmi_activity': [],
        'summary': {},
    }

    # Type 10 = RDP, Type 3 = Network
    for logon in evtx_data.get('logons', []):
        logon_type = str(logon.get('logon_type', ''))
        if logon_type == '10':
            lateral['rdp_sessions'].append({
                'timestamp': logon['timestamp'],
                'source_ip': logon.get('source_ip', ''),
                'target_user': logon.get('target_user', ''),
                'computer': logon.get('computer', ''),
            })
        elif logon_type == '3':
            lateral['network_logons'].append({
                'timestamp': logon['timestamp'],
                'source_ip': logon.get('source_ip', ''),
                'target_user': logon.get('target_user', ''),
                'computer': logon.get('computer', ''),
            })

    # PsExec detection via service installs
    for svc in evtx_data.get('service_installs', []):
        if 'psexe' in svc.get('service_name', '').lower() or 'psexe' in svc.get('service_path', '').lower():
            lateral['psexec_indicators'].append({
                'timestamp': svc['timestamp'],
                'service_name': svc.get('service_name', ''),
                'service_path': svc.get('service_path', ''),
            })

    # WMI from notable events
    for evt in evtx_data.get('other_notable', []):
        if evt['event_id'] in ('5857', '5860', '5861'):
            lateral['wmi_activity'].append(evt)

    lateral['summary'] = {
        'rdp_sessions': len(lateral['rdp_sessions']),
        'network_logons': len(lateral['network_logons']),
        'psexec_indicators': len(lateral['psexec_indicators']),
        'wmi_events': len(lateral['wmi_activity']),
        'unique_source_ips': len(set(
            l.get('source_ip', '') for l in
            lateral['rdp_sessions'] + lateral['network_logons']
            if l.get('source_ip', '') and l['source_ip'] not in ('', '-', '::1', '127.0.0.1')
        )),
    }

    return lateral


def analyze_bruteforce(evtx_data, window_minutes=10, threshold=5):
    """Detect brute force and password spray patterns."""
    findings = []
    failed = evtx_data.get('failed_logons', [])

    # Group by source IP
    by_ip = defaultdict(list)
    for f in failed:
        ip = f.get('source_ip', '')
        if ip and ip not in ('', '-', '::1', '127.0.0.1'):
            ts = parse_ts(f['timestamp'])
            if ts:
                by_ip[ip].append({'ts': ts, 'user': f.get('target_user', ''), 'record': f})

    for ip, attempts in by_ip.items():
        attempts.sort(key=lambda x: x['ts'])
        # Sliding window
        for i, start in enumerate(attempts):
            window_end = start['ts'] + timedelta(minutes=window_minutes)
            window_attempts = [a for a in attempts[i:] if a['ts'] <= window_end]

            if len(window_attempts) >= threshold:
                unique_users = set(a['user'] for a in window_attempts)
                finding = {
                    'source_ip': ip,
                    'start_time': ts_to_iso(start['ts']),
                    'end_time': ts_to_iso(window_attempts[-1]['ts']),
                    'total_attempts': len(window_attempts),
                    'unique_users': len(unique_users),
                    'users_targeted': sorted(unique_users),
                }
                if len(unique_users) > 3:
                    finding['attack_type'] = 'password_spray'
                else:
                    finding['attack_type'] = 'brute_force'

                findings.append(finding)
                break  # One finding per IP

    return findings


def build_timeline(all_data, time_range=None):
    """Build unified timeline from all parsed artifacts."""
    timeline = []

    def add_entry(ts_str, source, event_type, description, details=None):
        ts = parse_ts(ts_str)
        if not ts:
            return
        if time_range:
            start, end = time_range
            if ts < start or ts > end:
                return
        timeline.append({
            'timestamp': ts_to_iso(ts),
            'source': source,
            'event_type': event_type,
            'description': description,
            'details': details or {},
            '_sort_key': ts,
        })

    # Add prefetch
    for p in all_data.get('prefetch', []):
        add_entry(p.get('timestamp', p.get('last_run', '')), 'prefetch', 'execution',
                  f"Executed: {p['executable']} (run count: {p.get('run_count', '?')})",
                  {'path': p.get('source_path', ''), 'suspicious': p.get('suspicious_path', False)})

    # Add evtx events
    for category, events in all_data.get('evtx', {}).items():
        for e in events:
            desc = e.get('map_description', f"Event {e['event_id']}")
            add_entry(e['timestamp'], f'evtx/{e.get("channel", "")}', category, desc, e.get('payload', {}))

    # Add hayabusa detections
    for h in all_data.get('hayabusa', []):
        add_entry(h['timestamp'], 'hayabusa', f"detection/{h.get('level', '')}",
                  f"[{h.get('level', '')}] {h.get('rule_title', '')}",
                  {'channel': h.get('channel', ''), 'event_id': h.get('event_id', ''),
                   'mitre': h.get('mitre_attack', '')})

    # Add chainsaw
    for c in all_data.get('chainsaw', []):
        add_entry(c['timestamp'], 'chainsaw', f"detection/{c.get('level', '')}",
                  f"[{c.get('level', '')}] {c.get('rule_name', '')}",
                  {'sigma_id': c.get('sigma_id', ''), 'tags': c.get('tags', [])})

    # Sort by timestamp
    timeline.sort(key=lambda x: x.get('_sort_key', datetime.min))
    for t in timeline:
        del t['_sort_key']

    return timeline


def generate_summary(all_data, execution, persistence, lateral, bruteforce, timestomped):
    """Generate human-readable triage summary."""
    lines = [
        '# Windows Artifact Triage Summary',
        '',
        f'**Generated**: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}',
        '',
        '## Quick Stats',
        '',
    ]

    # Execution
    suspicious_exes = [e for e in execution if e.get('suspicious')]
    lines.append(f'- **Total unique executables**: {len(execution)}')
    lines.append(f'- **Suspicious executables**: {len(suspicious_exes)}')
    if suspicious_exes:
        for s in suspicious_exes[:10]:
            lines.append(f'  - `{s["executable"]}` — sources: {", ".join(s["sources"])} — reasons: {", ".join(s["reasons"])}')

    # Persistence
    lines.append(f'- **Persistence mechanisms found**: {len(persistence)}')
    suspicious_persist = [p for p in persistence if p.get('suspicious')]
    if suspicious_persist:
        lines.append(f'- **Suspicious persistence**: {len(suspicious_persist)}')
        for p in suspicious_persist[:5]:
            lines.append(f'  - [{p["type"]}] {p.get("name", "")} → `{p.get("path", "")[:100]}`')

    # Lateral movement
    if lateral.get('summary'):
        s = lateral['summary']
        lines.append(f'- **RDP sessions**: {s.get("rdp_sessions", 0)}')
        lines.append(f'- **Network logons**: {s.get("network_logons", 0)}')
        lines.append(f'- **PsExec indicators**: {s.get("psexec_indicators", 0)}')
        lines.append(f'- **Unique source IPs**: {s.get("unique_source_ips", 0)}')

    # Brute force
    if bruteforce:
        lines.append(f'- **Brute force/spray attacks detected**: {len(bruteforce)}')
        for bf in bruteforce[:3]:
            lines.append(f'  - {bf["attack_type"]} from {bf["source_ip"]}: '
                        f'{bf["total_attempts"]} attempts against {bf["unique_users"]} users')

    # Timestomping
    if timestomped:
        lines.append(f'- **Timestomped files detected**: {len(timestomped)}')
        for t in timestomped[:5]:
            lines.append(f'  - `{t.get("full_path", t.get("filename", ""))}`'
                        f' ({t.get("timestomp_type", "")})')

    # Log clearing
    if all_data.get('evtx', {}).get('log_cleared'):
        lines.append(f'- **ALERT: Audit log cleared {len(all_data["evtx"]["log_cleared"])} time(s)**')

    return '\n'.join(lines)


# ─── Auto-detect artifact files ─────────────────────────────────────────────

def auto_detect_artifacts(input_dir):
    """Scan a directory for recognizable forensic artifact files."""
    detected = {}
    input_path = Path(input_dir)

    for f in input_path.rglob('*.csv'):
        name_lower = f.name.lower()
        # Read first line to check headers
        try:
            with open(f, 'r', encoding='utf-8-sig', errors='replace') as fh:
                header = fh.readline().lower()
        except Exception:
            continue

        if 'executablename' in header or 'runcount' in header or 'prefetch' in name_lower:
            detected['prefetch'] = str(f)
        elif 'sha1' in header and ('amcache' in name_lower or 'fullpath' in header):
            detected['amcache'] = str(f)
        elif 'cacheentryposition' in header or 'shimcache' in name_lower or 'appcompat' in name_lower:
            detected['shimcache'] = str(f)
        elif 'eventid' in header and ('timecreated' in header or 'systemtime' in header):
            detected.setdefault('evtx', []).append(str(f)) if isinstance(detected.get('evtx'), list) else detected.update({'evtx': [str(f)]})
        elif 'created0x10' in header or 'created0x30' in header:
            detected['mft'] = str(f)
        elif 'updatereasons' in header and 'updatetimestamp' in header:
            detected['usn'] = str(f)
        elif 'ruletitle' in header or ('timestamp' in header and 'level' in header and 'channel' in header):
            detected['hayabusa'] = str(f)

    for f in input_path.rglob('*.json'):
        try:
            with open(f, 'r') as fh:
                data = json.load(fh)
            if isinstance(data, list) and data and any(k in data[0] for k in ('name', 'level', 'sigma')):
                detected['chainsaw'] = str(f)
        except (json.JSONDecodeError, IndexError, KeyError):
            pass

    for f in input_path.rglob('*.jsonl'):
        detected['hayabusa'] = str(f)

    return detected


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Windows Artifact Triage Engine')
    parser.add_argument('--input-dir', help='Directory containing artifact CSVs (auto-detects)')
    parser.add_argument('--output-dir', default='./triage_output', help='Output directory')
    parser.add_argument('--prefetch', help='PECmd CSV file')
    parser.add_argument('--amcache', help='AmcacheParser CSV file')
    parser.add_argument('--shimcache', help='AppCompatCacheParser CSV file')
    parser.add_argument('--evtx', nargs='+', help='EvtxECmd CSV file(s)')
    parser.add_argument('--mft', help='MFTECmd $MFT CSV file')
    parser.add_argument('--usn', help='MFTECmd $J CSV file')
    parser.add_argument('--chainsaw', help='Chainsaw JSON output')
    parser.add_argument('--hayabusa', help='Hayabusa CSV/JSONL output')
    parser.add_argument('--focus', choices=['execution', 'persistence', 'lateral', 'filesystem',
                                            'accounts', 'all'], default='all')
    parser.add_argument('--timerange', help='UTC time range: "start,end" in ISO format')
    parser.add_argument('--format', choices=['json', 'csv', 'markdown'], default='json')

    args = parser.parse_args()

    # Auto-detect if input dir provided
    artifact_files = {}
    if args.input_dir:
        print(f"[*] Scanning {args.input_dir} for artifacts...", file=sys.stderr)
        artifact_files = auto_detect_artifacts(args.input_dir)
        print(f"[+] Detected: {', '.join(artifact_files.keys())}", file=sys.stderr)

    # Override with explicit paths
    if args.prefetch: artifact_files['prefetch'] = args.prefetch
    if args.amcache: artifact_files['amcache'] = args.amcache
    if args.shimcache: artifact_files['shimcache'] = args.shimcache
    if args.evtx: artifact_files['evtx'] = args.evtx
    if args.mft: artifact_files['mft'] = args.mft
    if args.usn: artifact_files['usn'] = args.usn
    if args.chainsaw: artifact_files['chainsaw'] = args.chainsaw
    if args.hayabusa: artifact_files['hayabusa'] = args.hayabusa

    if not artifact_files:
        print("[!] No artifacts found. Use --input-dir or specify files directly.", file=sys.stderr)
        sys.exit(1)

    # Parse time range
    time_range = None
    if args.timerange:
        parts = args.timerange.split(',')
        if len(parts) == 2:
            time_range = (parse_ts(parts[0].strip()), parse_ts(parts[1].strip()))

    # Parse all artifacts
    all_data = {}

    if 'prefetch' in artifact_files:
        print(f"[*] Parsing prefetch: {artifact_files['prefetch']}", file=sys.stderr)
        all_data['prefetch'] = parse_prefetch(artifact_files['prefetch'])
        print(f"    → {len(all_data['prefetch'])} entries", file=sys.stderr)

    if 'amcache' in artifact_files:
        print(f"[*] Parsing amcache: {artifact_files['amcache']}", file=sys.stderr)
        all_data['amcache'] = parse_amcache(artifact_files['amcache'])
        print(f"    → {len(all_data['amcache'])} entries", file=sys.stderr)

    if 'shimcache' in artifact_files:
        print(f"[*] Parsing shimcache: {artifact_files['shimcache']}", file=sys.stderr)
        all_data['shimcache'] = parse_shimcache(artifact_files['shimcache'])
        print(f"    → {len(all_data['shimcache'])} entries", file=sys.stderr)

    if 'evtx' in artifact_files:
        evtx_files = artifact_files['evtx'] if isinstance(artifact_files['evtx'], list) else [artifact_files['evtx']]
        all_evtx = {'logons': [], 'failed_logons': [], 'process_creation': [],
                    'service_installs': [], 'scheduled_tasks': [], 'account_changes': [],
                    'log_cleared': [], 'other_notable': []}
        for ef in evtx_files:
            print(f"[*] Parsing evtx: {ef}", file=sys.stderr)
            parsed = parse_evtx(ef)
            for k, v in parsed.items():
                all_evtx[k].extend(v)
        all_data['evtx'] = all_evtx
        total_events = sum(len(v) for v in all_evtx.values())
        print(f"    → {total_events} categorized events", file=sys.stderr)

    if 'mft' in artifact_files:
        print(f"[*] Parsing MFT: {artifact_files['mft']}", file=sys.stderr)
        mft_data, timestomped = parse_mft(artifact_files['mft'])
        all_data['mft'] = mft_data
        all_data['timestomped'] = timestomped
        print(f"    → {len(mft_data)} entries, {len(timestomped)} timestomped", file=sys.stderr)

    if 'usn' in artifact_files:
        print(f"[*] Parsing USN journal: {artifact_files['usn']}", file=sys.stderr)
        all_data['usn'] = parse_usn_journal(artifact_files['usn'])
        print(f"    → {len(all_data['usn'])} entries", file=sys.stderr)

    if 'chainsaw' in artifact_files:
        print(f"[*] Parsing Chainsaw: {artifact_files['chainsaw']}", file=sys.stderr)
        all_data['chainsaw'] = parse_chainsaw(artifact_files['chainsaw'])
        print(f"    → {len(all_data['chainsaw'])} detections", file=sys.stderr)

    if 'hayabusa' in artifact_files:
        print(f"[*] Parsing Hayabusa: {artifact_files['hayabusa']}", file=sys.stderr)
        all_data['hayabusa'] = parse_hayabusa(artifact_files['hayabusa'])
        print(f"    → {len(all_data['hayabusa'])} detections", file=sys.stderr)

    # Analyze
    print("[*] Running analysis...", file=sys.stderr)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    execution = analyze_execution(
        all_data.get('prefetch', []),
        all_data.get('amcache', []),
        all_data.get('shimcache', []),
    )
    persistence = analyze_persistence(all_data.get('evtx', {}))
    lateral = analyze_lateral_movement(all_data.get('evtx', {}))
    bruteforce = analyze_bruteforce(all_data.get('evtx', {}))
    timestomped = all_data.get('timestomped', [])

    # Build timeline
    timeline = build_timeline(all_data, time_range)

    # Write outputs
    with open(output_dir / 'execution_evidence.json', 'w') as f:
        json.dump(execution, f, indent=2, default=str)

    with open(output_dir / 'persistence_mechanisms.json', 'w') as f:
        json.dump(persistence, f, indent=2, default=str)

    with open(output_dir / 'lateral_movement.json', 'w') as f:
        json.dump(lateral, f, indent=2, default=str)

    with open(output_dir / 'bruteforce_detection.json', 'w') as f:
        json.dump(bruteforce, f, indent=2, default=str)

    if timestomped:
        with open(output_dir / 'timestomping.json', 'w') as f:
            json.dump(timestomped, f, indent=2, default=str)

    # Timeline as CSV
    if timeline:
        with open(output_dir / 'timeline.csv', 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['timestamp', 'source', 'event_type', 'description', 'details'])
            writer.writeheader()
            for t in timeline:
                row = dict(t)
                row['details'] = json.dumps(row['details']) if isinstance(row['details'], dict) else str(row['details'])
                writer.writerow(row)

    # Summary
    summary = generate_summary(all_data, execution, persistence, lateral, bruteforce, timestomped)
    with open(output_dir / 'triage_summary.md', 'w') as f:
        f.write(summary)

    # Extract hashes for IOC enrichment
    all_hashes = set()
    for e in all_data.get('amcache', []):
        if e.get('sha1'):
            all_hashes.add(e['sha1'])
    if all_hashes:
        with open(output_dir / 'extracted_hashes.txt', 'w') as f:
            f.write('\n'.join(sorted(all_hashes)))
        print(f"[+] Extracted {len(all_hashes)} SHA1 hashes for enrichment", file=sys.stderr)

    print(f"\n[+] Triage complete. Results in {output_dir}/", file=sys.stderr)
    print(f"    - execution_evidence.json ({len(execution)} executables)", file=sys.stderr)
    print(f"    - persistence_mechanisms.json ({len(persistence)} mechanisms)", file=sys.stderr)
    print(f"    - lateral_movement.json ({lateral['summary']})", file=sys.stderr)
    print(f"    - timeline.csv ({len(timeline)} events)", file=sys.stderr)
    print(f"    - triage_summary.md", file=sys.stderr)

    # Print summary to stdout
    print(summary)


if __name__ == '__main__':
    main()
