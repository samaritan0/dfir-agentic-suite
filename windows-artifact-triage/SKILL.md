---
name: windows-artifact-triage
description: "Parse and correlate Windows forensic artifacts from EZTools (Eric Zimmerman), KAPE, Chainsaw, Hayabusa, and raw event logs. Handles CSV output from EvtxECmd, MFTECmd, PECmd (Prefetch), AmcacheParser, AppCompatCacheParser, SBECmd (ShellBags), LECmd (LNK files), JLECmd (Jump Lists), and RECmd (Registry). Also parses Chainsaw JSON and Hayabusa CSV/JSONL timelines. Use this skill whenever the user mentions Windows forensics, EZTools, KAPE output, event logs, prefetch, amcache, shimcache, MFT, USN journal, registry forensics, shellbags, Chainsaw, Hayabusa, or asks to 'parse these artifacts', 'triage this Windows system', 'correlate these events', 'what executed on this system', 'find persistence', or 'build a timeline from KAPE'. Also triggers for lateral movement analysis, evidence of execution, and timestomping detection."
---

# Windows Artifact Triage

## What this skill does

Parses CSV/JSON output from the most common Windows DFIR tools and produces:
1. **Evidence of Execution** — programs that ran, when, how many times
2. **Persistence Mechanisms** — registry Run keys, services, scheduled tasks, WMI
3. **Lateral Movement** — RDP, PsExec, WMI, WinRM, SMB indicators
4. **File System Activity** — file creation, deletion, renaming, timestomping
5. **Account Activity** — logons, logon failures, privilege escalation
6. **Correlated Timeline** — unified UTC timeline across all artifact types

## Supported artifact formats

### EZTools CSV outputs

Each tool produces CSV with specific columns. The parsing script handles all of them:

| Tool | Key Columns | Forensic Value |
|---|---|---|
| **EvtxECmd** | TimeCreated, EventId, Channel, Provider, MapDescription, PayloadData1-6 | Event log analysis with Maps normalization |
| **MFTECmd** ($MFT) | EntryNumber, ParentPath, FileName, Created0x10, Created0x30, IsDirectory | File system + timestomping ($SI vs $FN) |
| **MFTECmd** ($J/USN) | UpdateTimestamp, Name, UpdateReasons, ParentPath | File changes: create/delete/rename/data_extend |
| **PECmd** (Prefetch) | SourceFilename, ExecutableName, RunCount, LastRun, PreviousRun0-6 | Evidence of execution with timestamps |
| **AmcacheParser** | SHA1, FullPath, FileKeyLastWriteTimestamp, Name | Program execution + SHA1 for VT lookup |
| **AppCompatCacheParser** | LastModifiedTimeUTC, Path, CacheEntryPosition | Shimcache execution evidence |
| **SBECmd** (ShellBags) | AbsolutePath, LastWriteTime, ShellType | User folder browsing history |
| **LECmd** (LNK) | SourceFile, TargetCreated, TargetModified, TargetPath, Arguments, WorkingDirectory | Shortcut analysis |
| **JLECmd** (Jump Lists) | SourceFile, TargetCreated, TargetPath, Arguments | Recent/pinned program activity |
| **RECmd** (Registry) | HivePath, Key, ValueName, ValueData, LastWriteTimestamp | Registry analysis (persistence, config) |

### Detection tool outputs

| Tool | Format | Key Fields |
|---|---|---|
| **Chainsaw** | JSON (array of detections) | name, level, status, timestamp, authors, sigma references |
| **Hayabusa** | CSV or JSONL | Timestamp, RuleTitle, Level, Computer, Channel, EventID, Details |

## How to use this skill

### Step 1: Identify what artifacts are available

Ask the user or check uploaded files. Common KAPE output structure:
```
<case>/
├── C/
│   ├── Windows/System32/winevt/logs/  → raw .evtx
│   └── Windows/Prefetch/              → raw .pf
└── Module_Output/
    ├── EvtxECmd/                      → CSVs per log
    ├── PECmd/                         → Prefetch CSV
    ├── AmcacheParser/                 → Amcache CSV
    ├── MFTECmd/                       → $MFT, $J CSVs
    └── AppCompatCacheParser/          → Shimcache CSV
```

### Step 2: Run the triage script

```bash
python3 /path/to/skills/windows-artifact-triage/scripts/triage_artifacts.py \
    --input-dir <kape_output_dir> \
    --output-dir <results_dir> \
    [--focus execution|persistence|lateral|filesystem|accounts|all] \
    [--timerange "2024-01-15T00:00:00,2024-01-16T23:59:59"] \
    [--format json|csv|markdown]
```

Or parse individual files:
```bash
python3 scripts/triage_artifacts.py --prefetch prefetch_output.csv --evtx evtx_output.csv --focus execution
```

### Step 3: Analyze the output

The script produces:
- `execution_evidence.json` — All programs that ran, sources, timestamps
- `persistence_mechanisms.json` — Registry, services, tasks, WMI persistence
- `lateral_movement.json` — RDP, PsExec, WMI, WinRM indicators
- `timeline.csv` — Unified timeline sorted by UTC timestamp
- `triage_summary.md` — Human-readable executive summary
- `suspicious_findings.json` — Items flagged as anomalous by heuristics

## Key analysis heuristics

The skill applies these detection heuristics automatically:

### Evidence of Execution
- Cross-reference Prefetch executables against known-good baselines
- Flag executables in unusual paths: `\Users\*\AppData\`, `\ProgramData\`, `\Temp\`, `\Recycle`
- Detect renamed system tools (cmd.exe hash in non-standard path)
- Amcache SHA1 extraction for bulk VT lookup (chain to ioc-extractor skill)

### Persistence Detection
- Registry Run/RunOnce keys (HKLM and HKCU)
- Service installations (Event 7045, Event 4697)
- Scheduled task creation (Event 4698, schtasks in command lines)
- WMI event subscriptions (Event 5861)
- Startup folder additions via ShellBags/LNK analysis
- DLL search order hijack indicators (DLLs in writable paths)

### Timestomping Detection
- Compare $STANDARD_INFORMATION (0x10) vs $FILE_NAME (0x30) timestamps from MFT
- Flag when $SI Created < $FN Created (impossible without manipulation)
- Flag when $SI timestamps are all identical (bulk timestamp modification)
- Nanosecond analysis: legitimate files have random nanoseconds; tools often zero them

### Lateral Movement
- Event 4624 Type 3 (network) + Type 10 (RDP) with source IP
- PsExec indicators: PSEXESVC service installation (Event 7045), prefetch for psexec
- WMI: Event 5857/5860/5861, wmiprvse.exe child processes
- WinRM: Event 6 (WSMan), powershell remoting sessions
- SMB: Event 5140/5145 (share access), admin$ and C$ access

### Account Anomalies
- Brute force: >5 Event 4625 from same source in 10 minutes
- Spray: >5 Event 4625 against different accounts from same source
- Kerberos: Event 4769 with RC4 encryption (overpass-the-hash)
- Privilege escalation: Event 4672 (special privileges), Event 4728 (added to admin group)

## Event log quick reference

Critical Windows Event IDs the skill prioritizes:

| Event ID | Log | Meaning |
|---|---|---|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4648 | Security | Explicit credential logon |
| 4672 | Security | Special privileges assigned |
| 4688 | Security | Process creation (with command line if enabled) |
| 4697/7045 | Security/System | Service installed |
| 4698 | Security | Scheduled task created |
| 4720 | Security | User account created |
| 4728/4732 | Security | Member added to global/local group |
| 4769 | Security | Kerberos service ticket requested |
| 1 | Sysmon | Process creation |
| 3 | Sysmon | Network connection |
| 7 | Sysmon | Image loaded |
| 11 | Sysmon | File created |
| 13 | Sysmon | Registry value set |
| 1102 | Security | Audit log cleared |

## Integration with other skills

- **ioc-extractor**: Feed Amcache SHA1 hashes, extracted IPs from event logs, and domains from command lines into IOC enrichment
- **log-timeline-correlator**: The timeline.csv output is designed to merge with plaso supertimelines
- **yara-rule-generator**: Use extracted file paths and behavioral patterns to generate targeted YARA rules

## Script dependencies

```bash
pip install pandas --break-system-packages
```

Pandas is the only hard dependency. The script handles CSV parsing, timestamp normalization, and correlation. For very large datasets (>1GB CSV), consider using `--chunk-size` to process in batches.
