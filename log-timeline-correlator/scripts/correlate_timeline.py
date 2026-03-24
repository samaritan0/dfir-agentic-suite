#!/usr/bin/env python3
"""
Log Analyzer & Timeline Correlator
Merges, normalizes, and correlates forensic timelines from multiple sources.
Part of the DFIR Skills Suite for Claude.
"""

import argparse
import csv
import json
import re
import sys
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from dateutil import parser as dateutil_parser
    HAS_DATEUTIL = True
except ImportError:
    HAS_DATEUTIL = False

csv.field_size_limit(10 * 1024 * 1024)  # 10MB field limit for large log entries

# ─── Timestamp Parsing ───────────────────────────────────────────────────────

TIMESTAMP_FORMATS = [
    '%Y-%m-%dT%H:%M:%S.%fZ',
    '%Y-%m-%dT%H:%M:%SZ',
    '%Y-%m-%dT%H:%M:%S.%f',
    '%Y-%m-%dT%H:%M:%S',
    '%Y-%m-%d %H:%M:%S.%f',
    '%Y-%m-%d %H:%M:%S',
    '%m/%d/%Y %H:%M:%S',
    '%m/%d/%Y %I:%M:%S %p',
    '%b %d %H:%M:%S',       # syslog (no year)
    '%b  %d %H:%M:%S',      # syslog with double space
]

SYSLOG_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<process>[^:\[]+)(?:\[(?P<pid>\d+)\])?\s*:\s*(?P<message>.*)'
)

COMMON_TS_FIELDS = [
    'timestamp', 'Timestamp', 'TimeCreated', 'datetime', 'eventTime',
    'time', 'date', '@timestamp', 'createdDateTime', 'published',
    'UpdateTimestamp', 'SystemTime', 'ts',
]


def parse_timestamp(ts_str, year_hint=None):
    """Parse timestamp string to UTC datetime. Returns None on failure."""
    if not ts_str or ts_str in ('', 'N/A', 'null', 'None'):
        return None
    ts_str = str(ts_str).strip()

    # Try dateutil first (most flexible)
    if HAS_DATEUTIL:
        try:
            dt = dateutil_parser.parse(ts_str)
            if dt.tzinfo:
                return dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        except (ValueError, OverflowError):
            pass

    # Manual format matching
    for fmt in TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(ts_str[:30], fmt)
            # Syslog: add current year if missing
            if dt.year == 1900 and year_hint:
                dt = dt.replace(year=year_hint)
            elif dt.year == 1900:
                dt = dt.replace(year=datetime.utcnow().year)
            return dt
        except (ValueError, TypeError):
            continue

    # Epoch seconds/milliseconds
    try:
        val = float(ts_str)
        if val > 1e12:  # milliseconds
            return datetime.utcfromtimestamp(val / 1000)
        elif val > 1e9:  # seconds
            return datetime.utcfromtimestamp(val)
    except (ValueError, OverflowError, OSError):
        pass

    return None


def ts_iso(dt):
    """Format datetime to ISO string."""
    return dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ') if dt else ''


# ─── Input Parsers ───────────────────────────────────────────────────────────

class TimelineEvent:
    """Normalized timeline event."""
    __slots__ = ['timestamp', 'source', 'source_type', 'event_type', 'host',
                 'user', 'description', 'details', 'severity', 'mitre', 'raw']

    def __init__(self, **kwargs):
        for s in self.__slots__:
            setattr(self, s, kwargs.get(s, ''))
        if not self.details:
            self.details = {}
        if not self.raw:
            self.raw = {}

    def to_dict(self):
        return {s: getattr(self, s) for s in self.__slots__
                if s != 'raw'}  # Exclude raw to save space

    def to_csv_row(self):
        d = self.to_dict()
        d['details'] = json.dumps(d['details']) if isinstance(d['details'], dict) else str(d['details'])
        return d


def detect_format(filepath):
    """Auto-detect log file format."""
    path = Path(filepath)
    ext = path.suffix.lower()

    if ext == '.jsonl':
        return 'jsonl'

    try:
        with open(filepath, 'r', encoding='utf-8-sig', errors='replace') as f:
            first_line = f.readline().strip()
            second_line = f.readline().strip()
    except Exception:
        return 'unknown'

    # l2tcsv
    if first_line.startswith('date,time,') or 'MACB' in first_line:
        return 'l2tcsv'

    # Hayabusa CSV
    if 'Timestamp' in first_line and 'RuleTitle' in first_line and 'Level' in first_line:
        return 'hayabusa_csv'

    # EvtxECmd CSV
    if 'EventId' in first_line and ('TimeCreated' in first_line or 'SystemTime' in first_line):
        return 'evtx_csv'

    # Generic CSV
    if ext == '.csv' and ',' in first_line:
        return 'generic_csv'

    # JSON array
    if first_line.startswith('['):
        return 'json_array'

    # JSONL (one JSON object per line)
    if first_line.startswith('{'):
        try:
            json.loads(first_line)
            return 'jsonl'
        except json.JSONDecodeError:
            pass

    # Syslog
    if SYSLOG_RE.match(first_line):
        return 'syslog'

    # auth.log (same format as syslog typically)
    if 'sshd' in first_line or 'pam_unix' in first_line or 'sudo' in first_line:
        return 'syslog'

    return 'unknown'


def parse_l2tcsv(filepath):
    """Parse Plaso l2tcsv format."""
    events = []
    with open(filepath, 'r', encoding='utf-8-sig', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts_str = f"{row.get('date', '')} {row.get('time', '')}"
            ts = parse_timestamp(ts_str)
            if not ts:
                continue
            events.append(TimelineEvent(
                timestamp=ts,
                source='plaso',
                source_type=row.get('source', ''),
                event_type=row.get('type', row.get('MACB', '')),
                host=row.get('host', ''),
                user=row.get('user', ''),
                description=row.get('short', row.get('desc', '')),
                severity='info',
                details={
                    'filename': row.get('filename', ''),
                    'sourcetype': row.get('sourcetype', ''),
                    'extra': row.get('extra', ''),
                    'inode': row.get('inode', ''),
                },
            ))
    return events


def parse_hayabusa_csv(filepath):
    """Parse Hayabusa CSV timeline."""
    events = []
    with open(filepath, 'r', encoding='utf-8-sig', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts = parse_timestamp(row.get('Timestamp', ''))
            if not ts:
                continue
            level = row.get('Level', 'info').lower()
            events.append(TimelineEvent(
                timestamp=ts,
                source='hayabusa',
                source_type=row.get('Channel', ''),
                event_type=f"detection/{level}",
                host=row.get('Computer', ''),
                user='',
                description=row.get('RuleTitle', row.get('Title', '')),
                severity=level,
                mitre=row.get('MitreAttack', row.get('Tags', '')),
                details={
                    'event_id': row.get('EventID', row.get('EventId', '')),
                    'details': row.get('Details', row.get('RecordInformation', '')),
                    'rule_file': row.get('RuleFile', ''),
                },
            ))
    return events


def parse_evtx_csv(filepath):
    """Parse EvtxECmd CSV output."""
    events = []
    with open(filepath, 'r', encoding='utf-8-sig', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts = parse_timestamp(row.get('TimeCreated', row.get('SystemTime', '')))
            if not ts:
                continue
            eid = row.get('EventId', row.get('EventID', ''))
            events.append(TimelineEvent(
                timestamp=ts,
                source='evtx',
                source_type=row.get('Channel', ''),
                event_type=f"event_{eid}",
                host=row.get('Computer', ''),
                user='',
                description=row.get('MapDescription', f'Event {eid}'),
                severity='info',
                details={f'PayloadData{i}': row.get(f'PayloadData{i}', '')
                        for i in range(1, 7) if row.get(f'PayloadData{i}', '')},
            ))
    return events


def parse_jsonl(filepath):
    """Parse JSONL files (Plaso json_line, Hayabusa json, generic)."""
    events = []
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Find timestamp
            ts = None
            for field in COMMON_TS_FIELDS:
                if field in obj:
                    ts = parse_timestamp(str(obj[field]))
                    if ts:
                        break

            if not ts:
                continue

            # Detect source type
            if 'RuleTitle' in obj:  # Hayabusa
                events.append(TimelineEvent(
                    timestamp=ts,
                    source='hayabusa',
                    source_type=obj.get('Channel', ''),
                    event_type=f"detection/{obj.get('Level', 'info').lower()}",
                    host=obj.get('Computer', ''),
                    description=obj.get('RuleTitle', ''),
                    severity=obj.get('Level', 'info').lower(),
                    mitre=obj.get('MitreAttack', ''),
                    details=obj,
                ))
            elif 'message' in obj and 'source_short' in obj:  # Plaso
                events.append(TimelineEvent(
                    timestamp=ts,
                    source='plaso',
                    source_type=obj.get('source_short', ''),
                    event_type=obj.get('timestamp_desc', ''),
                    host=obj.get('hostname', ''),
                    user=obj.get('username', ''),
                    description=obj.get('message', ''),
                    severity='info',
                    details={'filename': obj.get('filename', ''), 'display_name': obj.get('display_name', '')},
                ))
            else:  # Generic JSON (CloudTrail, Okta, etc.)
                # Try to extract meaningful fields
                desc = (obj.get('eventName', '') or obj.get('displayMessage', '') or
                        obj.get('message', '') or obj.get('summary', '') or
                        json.dumps(obj)[:200])
                events.append(TimelineEvent(
                    timestamp=ts,
                    source='json_log',
                    source_type=obj.get('eventSource', obj.get('eventType', 'generic')),
                    event_type=obj.get('eventName', obj.get('action', {}).get('objectType', '')),
                    host=obj.get('sourceIPAddress', obj.get('client', {}).get('ipAddress', '')),
                    user=(obj.get('userIdentity', {}).get('arn', '') or
                          obj.get('actor', {}).get('displayName', '')),
                    description=desc,
                    severity=obj.get('severity', 'info'),
                    details=obj,
                ))
    return events


def parse_json_array(filepath):
    """Parse JSON array files (Chainsaw output)."""
    events = []
    with open(filepath, 'r') as f:
        data = json.load(f)

    if not isinstance(data, list):
        data = data.get('detections', data.get('results', []))

    for obj in data:
        ts = None
        for field in COMMON_TS_FIELDS:
            if field in obj:
                ts = parse_timestamp(str(obj[field]))
                if ts:
                    break

        if not ts:
            # Chainsaw nests timestamp
            sys_ts = obj.get('system', {}).get('timestamp', '')
            ts = parse_timestamp(sys_ts)

        if not ts:
            continue

        events.append(TimelineEvent(
            timestamp=ts,
            source='chainsaw',
            source_type='sigma_detection',
            event_type=f"detection/{obj.get('level', 'info')}",
            host=obj.get('system', {}).get('computer', ''),
            description=obj.get('name', obj.get('title', '')),
            severity=obj.get('level', 'info'),
            mitre=','.join(obj.get('tags', [])),
            details={'sigma_id': obj.get('sigma', {}).get('id', '') if isinstance(obj.get('sigma'), dict) else ''},
        ))
    return events


def parse_syslog(filepath):
    """Parse syslog/auth.log format."""
    events = []
    year = datetime.utcnow().year

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            m = SYSLOG_RE.match(line)
            if m:
                ts_str = f"{m.group('month')} {m.group('day')} {m.group('time')}"
                ts = parse_timestamp(ts_str, year_hint=year)
                if not ts:
                    continue

                process = m.group('process').strip()
                message = m.group('message')

                # Determine severity from content
                severity = 'info'
                msg_lower = message.lower()
                if 'failed' in msg_lower or 'error' in msg_lower or 'denied' in msg_lower:
                    severity = 'warning'
                if 'invalid' in msg_lower or 'attack' in msg_lower or 'breach' in msg_lower:
                    severity = 'high'

                events.append(TimelineEvent(
                    timestamp=ts,
                    source='syslog',
                    source_type=process,
                    event_type='syslog',
                    host=m.group('host'),
                    description=message,
                    severity=severity,
                    details={'pid': m.group('pid') or '', 'process': process},
                ))
            else:
                # Try to parse as generic timestamped line
                ts = parse_timestamp(line[:30])
                if ts:
                    events.append(TimelineEvent(
                        timestamp=ts,
                        source='log',
                        source_type='generic',
                        event_type='log_entry',
                        description=line[30:].strip(),
                        severity='info',
                    ))
    return events


# ─── Correlation Engine ──────────────────────────────────────────────────────

def correlate_events(events, window_seconds=300):
    """Group events into correlation clusters based on temporal proximity."""
    if not events:
        return []

    events.sort(key=lambda e: e.timestamp)
    clusters = []
    current_cluster = [events[0]]

    for i in range(1, len(events)):
        delta = (events[i].timestamp - events[i-1].timestamp).total_seconds()
        if delta <= window_seconds:
            current_cluster.append(events[i])
        else:
            if len(current_cluster) >= 2:  # Only keep clusters with 2+ events
                clusters.append({
                    'start': ts_iso(current_cluster[0].timestamp),
                    'end': ts_iso(current_cluster[-1].timestamp),
                    'duration_seconds': (current_cluster[-1].timestamp - current_cluster[0].timestamp).total_seconds(),
                    'event_count': len(current_cluster),
                    'sources': sorted(set(e.source for e in current_cluster)),
                    'max_severity': max((e.severity for e in current_cluster),
                                       key=lambda s: {'info': 0, 'low': 1, 'medium': 2, 'warning': 2,
                                                       'high': 3, 'critical': 4}.get(s, 0)),
                    'events': [e.to_dict() for e in current_cluster],
                })
            current_cluster = [events[i]]

    # Don't forget last cluster
    if len(current_cluster) >= 2:
        clusters.append({
            'start': ts_iso(current_cluster[0].timestamp),
            'end': ts_iso(current_cluster[-1].timestamp),
            'duration_seconds': (current_cluster[-1].timestamp - current_cluster[0].timestamp).total_seconds(),
            'event_count': len(current_cluster),
            'sources': sorted(set(e.source for e in current_cluster)),
            'max_severity': max((e.severity for e in current_cluster),
                               key=lambda s: {'info': 0, 'low': 1, 'medium': 2, 'warning': 2,
                                               'high': 3, 'critical': 4}.get(s, 0)),
            'events': [e.to_dict() for e in current_cluster],
        })

    return clusters


# ─── Attack Sequence Detection ───────────────────────────────────────────────

ATTACK_PHASE_INDICATORS = {
    'reconnaissance': {
        'keywords': ['scan', 'enum', 'discovery', 'whoami', 'ipconfig', 'systeminfo',
                     'net user', 'net group', 'nltest', 'dsquery', 'nslookup', 'arp'],
        'event_ids': ['4625'],  # Failed logons as recon
        'mitre_tactics': ['TA0043', 'TA0007'],
    },
    'initial_access': {
        'keywords': ['logon success', 'authenticated', 'session opened'],
        'event_ids': ['4624', '4648'],
        'mitre_tactics': ['TA0001'],
    },
    'execution': {
        'keywords': ['powershell', 'cmd.exe', 'wscript', 'cscript', 'mshta',
                     'process create', 'script block'],
        'event_ids': ['4688', '1'],  # Process creation + Sysmon
        'mitre_tactics': ['TA0002'],
    },
    'persistence': {
        'keywords': ['service install', 'scheduled task', 'registry', 'run key',
                     'startup', 'autorun', 'account created'],
        'event_ids': ['7045', '4697', '4698', '4720', '13'],
        'mitre_tactics': ['TA0003'],
    },
    'lateral_movement': {
        'keywords': ['rdp', 'psexec', 'wmi', 'winrm', 'remote', 'logon type 3',
                     'logon type 10', 'admin$', 'ipc$'],
        'event_ids': ['4624'],  # with specific logon types
        'mitre_tactics': ['TA0008'],
    },
    'collection_staging': {
        'keywords': ['archive', 'compress', 'rar', '7z', 'zip', 'staging', 'copy'],
        'mitre_tactics': ['TA0009'],
    },
    'exfiltration': {
        'keywords': ['upload', 'exfil', 'rclone', 'mega', 'cloud', 'transfer',
                     'dns tunnel', 'large transfer'],
        'mitre_tactics': ['TA0010'],
    },
}


def detect_attack_sequence(events):
    """Detect attack phase progression in the timeline."""
    phases_found = defaultdict(list)

    for event in events:
        desc_lower = (event.description or '').lower()
        eid = str(event.details.get('event_id', '')) if isinstance(event.details, dict) else ''
        mitre = (event.mitre or '').upper()

        for phase, indicators in ATTACK_PHASE_INDICATORS.items():
            matched = False

            # Keyword match
            if any(kw in desc_lower for kw in indicators.get('keywords', [])):
                matched = True

            # Event ID match
            if eid in indicators.get('event_ids', []):
                matched = True

            # MITRE tactic match
            if any(tactic in mitre for tactic in indicators.get('mitre_tactics', [])):
                matched = True

            if matched:
                phases_found[phase].append({
                    'timestamp': ts_iso(event.timestamp),
                    'source': event.source,
                    'description': event.description[:200],
                    'severity': event.severity,
                    'mitre': event.mitre,
                })

    # Build sequence
    phase_order = ['reconnaissance', 'initial_access', 'execution', 'persistence',
                   'lateral_movement', 'collection_staging', 'exfiltration']

    sequence = []
    for phase in phase_order:
        if phase in phases_found:
            events_in_phase = phases_found[phase]
            events_in_phase.sort(key=lambda x: x['timestamp'])
            sequence.append({
                'phase': phase,
                'mitre_tactic': ATTACK_PHASE_INDICATORS[phase].get('mitre_tactics', []),
                'first_seen': events_in_phase[0]['timestamp'],
                'last_seen': events_in_phase[-1]['timestamp'],
                'event_count': len(events_in_phase),
                'sample_events': events_in_phase[:5],
            })

    return {
        'phases_detected': len(sequence),
        'total_phases': len(phase_order),
        'sequence': sequence,
        'attack_progression_complete': len(sequence) >= 3,
    }


# ─── Gap Analysis ────────────────────────────────────────────────────────────

def analyze_gaps(events, max_gap_minutes=60):
    """Find suspicious gaps in the timeline."""
    if len(events) < 2:
        return []

    events_sorted = sorted(events, key=lambda e: e.timestamp)
    gaps = []

    # Calculate median inter-event time for context
    deltas = []
    for i in range(1, min(len(events_sorted), 1000)):
        d = (events_sorted[i].timestamp - events_sorted[i-1].timestamp).total_seconds()
        if d > 0:
            deltas.append(d)
    median_delta = sorted(deltas)[len(deltas)//2] if deltas else 60

    for i in range(1, len(events_sorted)):
        delta = (events_sorted[i].timestamp - events_sorted[i-1].timestamp).total_seconds()
        if delta > max_gap_minutes * 60:
            gaps.append({
                'gap_start': ts_iso(events_sorted[i-1].timestamp),
                'gap_end': ts_iso(events_sorted[i].timestamp),
                'gap_seconds': delta,
                'gap_human': f"{delta/3600:.1f} hours" if delta > 3600 else f"{delta/60:.0f} minutes",
                'before_event': events_sorted[i-1].to_dict(),
                'after_event': events_sorted[i].to_dict(),
                'suspicious': delta > median_delta * 100,  # 100x median gap
            })

    # Check for log clearing events
    for e in events_sorted:
        eid = str(e.details.get('event_id', '')) if isinstance(e.details, dict) else ''
        if eid in ('1102', '104') or 'log clear' in (e.description or '').lower():
            gaps.append({
                'gap_start': ts_iso(e.timestamp),
                'gap_end': ts_iso(e.timestamp),
                'gap_seconds': 0,
                'gap_human': 'LOG CLEARED',
                'event': e.to_dict(),
                'suspicious': True,
                'type': 'log_clearing',
            })

    return gaps


# ─── Entity Pivoting ─────────────────────────────────────────────────────────

def pivot_on_entity(events, entity):
    """Filter timeline to events involving a specific entity (IP, user, host)."""
    entity_lower = entity.lower()
    matching = []

    for e in events:
        searchable = ' '.join([
            str(e.host or ''), str(e.user or ''), str(e.description or ''),
            json.dumps(e.details) if isinstance(e.details, dict) else str(e.details or ''),
        ]).lower()

        if entity_lower in searchable:
            matching.append(e)

    return matching


# ─── Report Generation ───────────────────────────────────────────────────────

def generate_report(events, clusters, attack_seq, gaps, pivot_entity=None):
    """Generate Markdown analysis report."""
    lines = [
        '# Timeline Analysis Report',
        '',
        f'**Generated**: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}',
        f'**Total events**: {len(events)}',
        '',
    ]

    if events:
        lines.append(f'**Time range**: {ts_iso(min(e.timestamp for e in events))} → {ts_iso(max(e.timestamp for e in events))}')

    # Source breakdown
    source_counts = defaultdict(int)
    for e in events:
        source_counts[e.source] += 1
    lines.append('')
    lines.append('## Source Breakdown')
    lines.append('')
    for src, count in sorted(source_counts.items(), key=lambda x: -x[1]):
        lines.append(f'- **{src}**: {count} events')

    # Severity distribution
    sev_counts = defaultdict(int)
    for e in events:
        sev_counts[e.severity] += 1
    lines.append('')
    lines.append('## Severity Distribution')
    lines.append('')
    for sev in ['critical', 'high', 'warning', 'medium', 'low', 'info']:
        if sev in sev_counts:
            lines.append(f'- **{sev}**: {sev_counts[sev]}')

    # Attack sequence
    if attack_seq and attack_seq.get('phases_detected', 0) > 0:
        lines.append('')
        lines.append('## Attack Sequence Analysis')
        lines.append('')
        lines.append(f'**Phases detected**: {attack_seq["phases_detected"]}/{attack_seq["total_phases"]}')
        if attack_seq.get('attack_progression_complete'):
            lines.append('**⚠️ Multi-phase attack progression detected**')
        lines.append('')
        for phase in attack_seq.get('sequence', []):
            lines.append(f'### {phase["phase"].replace("_", " ").title()}')
            lines.append(f'- First seen: {phase["first_seen"]}')
            lines.append(f'- Events: {phase["event_count"]}')
            lines.append(f'- MITRE: {", ".join(phase["mitre_tactic"])}')
            if phase.get('sample_events'):
                lines.append(f'- Sample: {phase["sample_events"][0]["description"][:100]}')
            lines.append('')

    # Correlation clusters (top 10 by severity)
    if clusters:
        lines.append('## Notable Event Clusters')
        lines.append('')
        notable = sorted(clusters,
                        key=lambda c: {'info': 0, 'low': 1, 'medium': 2, 'warning': 2,
                                       'high': 3, 'critical': 4}.get(c['max_severity'], 0),
                        reverse=True)[:10]
        for i, c in enumerate(notable, 1):
            lines.append(f'### Cluster {i} ({c["max_severity"]})')
            lines.append(f'- Time: {c["start"]} → {c["end"]} ({c["duration_seconds"]:.0f}s)')
            lines.append(f'- Events: {c["event_count"]} from {", ".join(c["sources"])}')
            lines.append('')

    # Gaps
    suspicious_gaps = [g for g in gaps if g.get('suspicious')]
    if suspicious_gaps:
        lines.append('## Suspicious Timeline Gaps')
        lines.append('')
        for g in suspicious_gaps[:10]:
            if g.get('type') == 'log_clearing':
                lines.append(f'- **LOG CLEARED** at {g["gap_start"]}')
            else:
                lines.append(f'- Gap of {g["gap_human"]} from {g["gap_start"]} to {g["gap_end"]}')
        lines.append('')

    if pivot_entity:
        lines.append(f'## Entity Pivot: {pivot_entity}')
        lines.append('')
        lines.append(f'See entity_timeline.csv for all events involving this entity.')

    return '\n'.join(lines)


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Log Analyzer & Timeline Correlator')
    parser.add_argument('--inputs', nargs='+', required=True, help='Input files (auto-detected format)')
    parser.add_argument('--output-dir', default='./correlated', help='Output directory')
    parser.add_argument('--timerange', help='UTC time range: "start,end" in ISO format')
    parser.add_argument('--window', type=int, default=300, help='Correlation window in seconds (default: 300)')
    parser.add_argument('--pivot-entity', help='IP, user, or hostname to pivot on')
    parser.add_argument('--attack-sequence', action='store_true', help='Enable attack sequence detection')
    parser.add_argument('--gap-threshold', type=int, default=60, help='Gap threshold in minutes (default: 60)')

    args = parser.parse_args()

    # Parse time range
    time_range = None
    if args.timerange:
        parts = args.timerange.split(',')
        if len(parts) == 2:
            start = parse_timestamp(parts[0].strip())
            end = parse_timestamp(parts[1].strip())
            if start and end:
                time_range = (start, end)

    # Parse all inputs
    all_events = []
    for input_file in args.inputs:
        if not os.path.exists(input_file):
            print(f"[!] File not found: {input_file}", file=sys.stderr)
            continue

        fmt = detect_format(input_file)
        print(f"[*] Parsing {input_file} (detected: {fmt})", file=sys.stderr)

        parsers = {
            'l2tcsv': parse_l2tcsv,
            'hayabusa_csv': parse_hayabusa_csv,
            'evtx_csv': parse_evtx_csv,
            'jsonl': parse_jsonl,
            'json_array': parse_json_array,
            'syslog': parse_syslog,
            'generic_csv': parse_evtx_csv,  # Try as generic CSV
        }

        parse_fn = parsers.get(fmt)
        if parse_fn:
            try:
                events = parse_fn(input_file)
                print(f"    → {len(events)} events", file=sys.stderr)
                all_events.extend(events)
            except Exception as e:
                print(f"[!] Error parsing {input_file}: {e}", file=sys.stderr)
        else:
            print(f"[!] Unknown format for {input_file}, skipping", file=sys.stderr)

    if not all_events:
        print("[!] No events parsed from any input.", file=sys.stderr)
        sys.exit(1)

    # Filter by time range
    if time_range:
        before = len(all_events)
        all_events = [e for e in all_events
                     if time_range[0] <= e.timestamp <= time_range[1]]
        print(f"[*] Time filter: {before} → {len(all_events)} events", file=sys.stderr)

    # Sort all events
    all_events.sort(key=lambda e: e.timestamp)
    print(f"[+] Total merged events: {len(all_events)}", file=sys.stderr)

    # Correlate
    print("[*] Running correlation analysis...", file=sys.stderr)
    clusters = correlate_events(all_events, window_seconds=args.window)
    print(f"    → {len(clusters)} correlation clusters", file=sys.stderr)

    # Attack sequence detection
    attack_seq = {}
    if args.attack_sequence:
        print("[*] Detecting attack sequences...", file=sys.stderr)
        attack_seq = detect_attack_sequence(all_events)
        print(f"    → {attack_seq.get('phases_detected', 0)} phases detected", file=sys.stderr)

    # Gap analysis
    print("[*] Analyzing timeline gaps...", file=sys.stderr)
    gaps = analyze_gaps(all_events, max_gap_minutes=args.gap_threshold)
    print(f"    → {len(gaps)} gaps found, {len([g for g in gaps if g.get('suspicious')])} suspicious", file=sys.stderr)

    # Entity pivot
    pivot_events = []
    if args.pivot_entity:
        print(f"[*] Pivoting on entity: {args.pivot_entity}", file=sys.stderr)
        pivot_events = pivot_on_entity(all_events, args.pivot_entity)
        print(f"    → {len(pivot_events)} matching events", file=sys.stderr)

    # Write outputs
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Merged timeline CSV
    with open(output_dir / 'merged_timeline.csv', 'w', newline='') as f:
        fields = ['timestamp', 'source', 'source_type', 'event_type', 'host',
                  'user', 'description', 'severity', 'mitre', 'details']
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for e in all_events:
            writer.writerow(e.to_csv_row())

    # Clusters
    with open(output_dir / 'correlation_clusters.json', 'w') as f:
        json.dump(clusters, f, indent=2, default=str)

    # Attack sequence
    if attack_seq:
        with open(output_dir / 'attack_sequence.json', 'w') as f:
            json.dump(attack_seq, f, indent=2, default=str)

    # Gaps
    with open(output_dir / 'gap_analysis.json', 'w') as f:
        json.dump(gaps, f, indent=2, default=str)

    # Entity pivot
    if pivot_events:
        with open(output_dir / 'entity_timeline.csv', 'w', newline='') as f:
            fields = ['timestamp', 'source', 'source_type', 'event_type', 'host',
                      'user', 'description', 'severity', 'mitre', 'details']
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for e in pivot_events:
                writer.writerow(e.to_csv_row())

    # Report
    report = generate_report(all_events, clusters, attack_seq, gaps, args.pivot_entity)
    with open(output_dir / 'analysis_report.md', 'w') as f:
        f.write(report)

    print(f"\n[+] Analysis complete. Results in {output_dir}/", file=sys.stderr)
    print(report)


if __name__ == '__main__':
    main()
