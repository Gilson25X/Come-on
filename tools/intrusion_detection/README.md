# Intrusion Detection System (IDS) — Host-Based Defensive Monitoring

A pure-Python host-based intrusion detection system that monitors system logs, file integrity, and network connections to detect unauthorized access and suspicious activity. Designed for security professionals and system administrators.

## Features

### Log Monitor
- **Brute-force detection** — tracks failed login attempts per source IP and alerts when thresholds are exceeded (5+ attempts = alert)
- **Privilege escalation tracking** — monitors sudo commands and su sessions, flags suspicious commands (shell spawns, firewall flushes, security service disabling)
- **Account change detection** — alerts on user creation, modification, group changes, and password changes
- **Syslog anomaly detection** — monitors for kernel exploits (segfaults), OOM kills, promiscuous mode, SYN floods, SELinux/AppArmor denials

### File Integrity Monitor (FIM)
- **SHA-256 baseline** — creates and verifies cryptographic baselines of critical system files
- **Change detection** — detects modified, created, and deleted files against the baseline
- **Permission monitoring** — flags SUID bit additions, world-writable permissions, ownership changes
- **Critical file awareness** — higher severity for changes to `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, SSH config, PAM configuration
- **System binary monitoring** — watches `/usr/bin`, `/sbin`, `/usr/local/bin` for unauthorized additions

### Network Monitor
- **Port scan detection** — identifies sources connecting to 10+ unique ports (possible reconnaissance)
- **Data exfiltration indicators** — flags non-browser processes with many external connections, DNS tunneling indicators
- **Suspicious listener detection** — alerts on services listening on known C2/backdoor ports (4444, 31337, 12345, etc.)
- **Connection anomalies** — processes connecting from temp directories, connections to bogon/reserved IP ranges
- **Efficient inode mapping** — builds PID-to-socket map once for fast process correlation

### Alert Engine
- **Unified alert format** — consolidates alerts from all modules with unique IDs, severity levels, and timestamps
- **Threat level assessment** — overall CLEAN/LOW/MEDIUM/HIGH/CRITICAL threat classification
- **JSON export** — structured report output for integration with SIEM or other tools
- **Severity prioritization** — alerts sorted by criticality for efficient triage

## Usage

```bash
cd tools/intrusion_detection

# Full scan (all modules)
python -m ids.cli

# Run specific modules
python -m ids.cli --logs              # Log analysis only
python -m ids.cli --fim               # File integrity check only
python -m ids.cli --network           # Network monitoring only
python -m ids.cli --logs --network    # Combine modules

# File Integrity Monitor
python -m ids.cli --fim --init-baseline           # Create initial baseline
python -m ids.cli --fim                            # Check against baseline
python -m ids.cli --fim --update-baseline          # Update after legit changes
python -m ids.cli --fim --watch-paths /opt /srv    # Monitor additional paths

# Export results
python -m ids.cli --all -o report.json

# Options
python -m ids.cli --help
```

### Options

| Flag | Description |
|------|-------------|
| `--all`, `-a` | Run all monitoring modules (default) |
| `--logs`, `-l` | Analyze system and authentication logs |
| `--fim`, `-f` | Run file integrity monitor |
| `--network`, `-n` | Run network traffic monitor |
| `--init-baseline` | Create or reset the FIM baseline |
| `--update-baseline` | Update baseline to current state |
| `--baseline-path FILE` | Custom baseline file path |
| `--watch-paths PATH...` | Additional paths to monitor with FIM |
| `--output`, `-o` | Export alert report to JSON |
| `--no-color` | Disable colored output |
| `--quiet`, `-q` | Only show alerts |

### Exit Codes

- `0` — No critical or warning alerts
- `1` — Critical or warning alerts detected

## Requirements

- **Python 3.10+**
- **No external dependencies** — uses only the Python standard library
- **Linux** — full functionality (log parsing, `/proc` network analysis, FIM on system paths)
- **macOS / Windows** — FIM works on user-specified paths; log and network modules have limited support

## Architecture

```
ids/
  __init__.py          # Package init
  cli.py               # CLI entry point and report formatting
  log_monitor.py       # Auth/syslog parsing, brute-force detection
  file_integrity.py    # FIM baseline creation and verification
  network_monitor.py   # Connection analysis and anomaly detection
  alert_engine.py      # Alert aggregation, prioritization, and export
```

## FIM Workflow

1. **Create baseline:** `python -m ids.cli --fim --init-baseline`
   - Snapshots SHA-256 hashes, permissions, and ownership of all monitored system files
   - Saves to `~/.ids_baseline.json`

2. **Run checks:** `python -m ids.cli --fim`
   - Compares current state against baseline
   - Reports modified, created, and deleted files

3. **After updates:** `python -m ids.cli --fim --update-baseline`
   - Refreshes baseline after legitimate system updates (e.g., `apt upgrade`)

## Monitored Paths (FIM)

By default, the FIM monitors:
- System binaries: `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/local/bin`
- Critical configs: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`
- Init/services: `/etc/systemd/system`, `/etc/init.d`, `/etc/rc.local`
- Network config: `/etc/resolv.conf`, `/etc/hosts`, `/etc/network`
- Security: `/etc/pam.d`, `/etc/security`, kernel module dirs

Add custom paths with `--watch-paths`.

## Integration

The JSON export (`-o report.json`) produces a structured format suitable for:
- SIEM ingestion (Splunk, ELK, Wazuh)
- Custom dashboards
- Automated alerting pipelines
- Compliance reporting
