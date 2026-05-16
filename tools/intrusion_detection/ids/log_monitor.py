"""
Log Monitor Module

Analyzes system and authentication logs for intrusion indicators:
- Failed login attempts (brute-force detection)
- Successful logins from unusual sources
- Privilege escalation events (su/sudo usage)
- SSH session anomalies
- Suspicious command execution in logs
- Account creation/modification events
"""

import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


@dataclass
class LogEvent:
    """A parsed log event."""
    timestamp: str
    source_file: str
    line_number: int
    raw_line: str
    event_type: str  # "failed_login", "successful_login", "privilege_escalation", etc.
    severity: str  # "info", "warning", "critical"
    details: dict[str, str] = field(default_factory=dict)
    source_ip: Optional[str] = None
    username: Optional[str] = None


@dataclass
class BruteForceAlert:
    """Alert for detected brute-force activity."""
    source_ip: str
    target_user: Optional[str]
    attempt_count: int
    time_window_seconds: int
    first_attempt: str
    last_attempt: str
    source_file: str

    @property
    def severity(self) -> str:
        if self.attempt_count >= 20:
            return "CRITICAL"
        if self.attempt_count >= 10:
            return "HIGH"
        if self.attempt_count >= 5:
            return "MEDIUM"
        return "LOW"


@dataclass
class LogMonitorResult:
    """Aggregated result from log monitoring."""
    events: list[LogEvent] = field(default_factory=list)
    brute_force_alerts: list[BruteForceAlert] = field(default_factory=list)
    privilege_escalations: list[LogEvent] = field(default_factory=list)
    suspicious_commands: list[LogEvent] = field(default_factory=list)
    account_changes: list[LogEvent] = field(default_factory=list)
    total_lines_analyzed: int = 0
    files_analyzed: list[str] = field(default_factory=list)

    @property
    def total_alerts(self) -> int:
        return (
            len(self.brute_force_alerts)
            + len(self.privilege_escalations)
            + len(self.suspicious_commands)
            + len(self.account_changes)
        )


# Patterns for parsing auth logs
AUTH_PATTERNS: dict[str, re.Pattern[str]] = {
    "failed_password": re.compile(
        r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)"
    ),
    "accepted_password": re.compile(
        r"Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)"
    ),
    "invalid_user": re.compile(
        r"Invalid user (\S+) from (\S+)"
    ),
    "sudo_command": re.compile(
        r"(\S+) : TTY=\S+ ; PWD=\S+ ; USER=(\S+) ; COMMAND=(.*)"
    ),
    "sudo_failed": re.compile(
        r"(\S+) : .*authentication failure.*"
    ),
    "su_session": re.compile(
        r"su(?:\[\d+\])?: (?:Successful|FAILED) su for (\S+) by (\S+)"
    ),
    "session_opened": re.compile(
        r"session opened for user (\S+)(?: by (?:uid=\d+|\(uid=\d+\)|(\S+)))?"
    ),
    "session_closed": re.compile(
        r"session closed for user (\S+)"
    ),
    "user_added": re.compile(
        r"new user: name=(\S+).*"
    ),
    "user_modified": re.compile(
        r"usermod.*: change user '(\S+)'"
    ),
    "group_added": re.compile(
        r"new group: name=(\S+).*"
    ),
    "password_changed": re.compile(
        r"password changed for (\S+)"
    ),
}

# Suspicious commands in sudo/su logs
SUSPICIOUS_SUDO_COMMANDS: list[tuple[str, str]] = [
    (r"/bin/(?:ba)?sh", "Shell spawned via sudo"),
    (r"chmod\s+[0-7]*[2367][0-7]*\s+/", "Chmod with world-writable permissions on system path"),
    (r"(?:useradd|adduser)", "User account created via sudo"),
    (r"(?:passwd\s+root|chpasswd)", "Root password change"),
    (r"(?:visudo|/etc/sudoers)", "Sudoers file modification"),
    (r"/etc/shadow", "Direct shadow file access"),
    (r"(?:iptables|nftables|ufw).*(?:-F|-X|flush|delete)", "Firewall rules flushed"),
    (r"(?:systemctl|service).*(?:stop|disable).*(?:fail2ban|sshguard|firewall|auditd)",
     "Security service disabled"),
    (r"(?:curl|wget).*\|\s*(?:ba)?sh", "Pipe-to-shell download via sudo"),
    (r"nc\s+-[elp]|ncat\s+-|socat\s+", "Netcat/reverse shell via sudo"),
    (r"crontab", "Crontab modification via sudo"),
]

# Log files to monitor
LOG_FILES: dict[str, str] = {
    "/var/log/auth.log": "auth",
    "/var/log/secure": "auth",
    "/var/log/syslog": "syslog",
    "/var/log/messages": "syslog",
    "/var/log/faillog": "faillog",
    "/var/log/lastlog": "lastlog",
    "/var/log/kern.log": "kernel",
    "/var/log/daemon.log": "daemon",
}

# Syslog timestamp pattern
SYSLOG_TIMESTAMP = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
)

# ISO timestamp pattern
ISO_TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
)


def _extract_timestamp(line: str) -> str:
    """Extract timestamp from a log line."""
    match = SYSLOG_TIMESTAMP.match(line)
    if match:
        return match.group(1)
    match = ISO_TIMESTAMP.match(line)
    if match:
        return match.group(1)
    return ""


def analyze_auth_log(
    log_path: str,
    max_lines: int = 50000,
) -> LogMonitorResult:
    """
    Analyze an authentication log file for intrusion indicators.

    Args:
        log_path: Path to the auth log file.
        max_lines: Maximum number of lines to analyze (reads from end).

    Returns:
        LogMonitorResult with categorized events.
    """
    result = LogMonitorResult()
    result.files_analyzed.append(log_path)

    try:
        with open(log_path, "r", errors="replace") as f:
            lines = f.readlines()
    except (OSError, PermissionError):
        return result

    # Analyze the most recent lines
    lines = lines[-max_lines:]
    result.total_lines_analyzed = len(lines)

    failed_logins: dict[str, list[tuple[str, Optional[str]]]] = defaultdict(list)

    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue

        timestamp = _extract_timestamp(line)

        # Failed password
        match = AUTH_PATTERNS["failed_password"].search(line)
        if match:
            user, ip, port = match.groups()
            event = LogEvent(
                timestamp=timestamp,
                source_file=log_path,
                line_number=line_num,
                raw_line=line,
                event_type="failed_login",
                severity="warning",
                source_ip=ip,
                username=user,
                details={"port": port},
            )
            result.events.append(event)
            failed_logins[ip].append((timestamp, user))
            continue

        # Invalid user attempt
        match = AUTH_PATTERNS["invalid_user"].search(line)
        if match:
            user, ip = match.groups()
            event = LogEvent(
                timestamp=timestamp,
                source_file=log_path,
                line_number=line_num,
                raw_line=line,
                event_type="invalid_user",
                severity="warning",
                source_ip=ip,
                username=user,
            )
            result.events.append(event)
            failed_logins[ip].append((timestamp, user))
            continue

        # Accepted login
        match = AUTH_PATTERNS["accepted_password"].search(line)
        if match:
            user, ip, port = match.groups()
            event = LogEvent(
                timestamp=timestamp,
                source_file=log_path,
                line_number=line_num,
                raw_line=line,
                event_type="successful_login",
                severity="info",
                source_ip=ip,
                username=user,
                details={"port": port},
            )
            result.events.append(event)
            continue

        # Sudo command
        match = AUTH_PATTERNS["sudo_command"].search(line)
        if match:
            user, target_user, command = match.groups()
            event = LogEvent(
                timestamp=timestamp,
                source_file=log_path,
                line_number=line_num,
                raw_line=line,
                event_type="sudo_command",
                severity="info",
                username=user,
                details={"target_user": target_user, "command": command.strip()},
            )
            result.privilege_escalations.append(event)

            # Check if the sudo command is suspicious
            cmd = command.strip()
            for pattern, reason in SUSPICIOUS_SUDO_COMMANDS:
                if re.search(pattern, cmd, re.IGNORECASE):
                    suspicious_event = LogEvent(
                        timestamp=timestamp,
                        source_file=log_path,
                        line_number=line_num,
                        raw_line=line,
                        event_type="suspicious_command",
                        severity="critical",
                        username=user,
                        details={
                            "command": cmd,
                            "reason": reason,
                            "target_user": target_user,
                        },
                    )
                    result.suspicious_commands.append(suspicious_event)
                    break
            continue

        # Sudo authentication failure
        match = AUTH_PATTERNS["sudo_failed"].search(line)
        if match:
            user = match.group(1)
            event = LogEvent(
                timestamp=timestamp,
                source_file=log_path,
                line_number=line_num,
                raw_line=line,
                event_type="sudo_failed",
                severity="warning",
                username=user,
            )
            result.privilege_escalations.append(event)
            continue

        # User/account changes
        for pattern_name in ("user_added", "user_modified", "group_added", "password_changed"):
            match = AUTH_PATTERNS[pattern_name].search(line)
            if match:
                user = match.group(1)
                event = LogEvent(
                    timestamp=timestamp,
                    source_file=log_path,
                    line_number=line_num,
                    raw_line=line,
                    event_type=pattern_name,
                    severity="warning",
                    username=user,
                )
                result.account_changes.append(event)
                break

    # Detect brute-force patterns
    for ip, attempts in failed_logins.items():
        if len(attempts) >= 5:
            target_users = set(user for _, user in attempts if user)
            alert = BruteForceAlert(
                source_ip=ip,
                target_user=", ".join(target_users) if target_users else None,
                attempt_count=len(attempts),
                time_window_seconds=0,
                first_attempt=attempts[0][0],
                last_attempt=attempts[-1][0],
                source_file=log_path,
            )
            result.brute_force_alerts.append(alert)

    return result


def analyze_syslog(
    log_path: str,
    max_lines: int = 50000,
) -> LogMonitorResult:
    """
    Analyze syslog/messages for suspicious kernel and daemon events.
    """
    result = LogMonitorResult()
    result.files_analyzed.append(log_path)

    try:
        with open(log_path, "r", errors="replace") as f:
            lines = f.readlines()
    except (OSError, PermissionError):
        return result

    lines = lines[-max_lines:]
    result.total_lines_analyzed = len(lines)

    suspicious_syslog_patterns: list[tuple[re.Pattern[str], str, str]] = [
        (re.compile(r"segfault at", re.IGNORECASE),
         "Segmentation fault (possible exploit attempt)", "warning"),
        (re.compile(r"Out of memory: Kill", re.IGNORECASE),
         "OOM killer invoked (possible resource exhaustion attack)", "critical"),
        (re.compile(r"promiscuous mode", re.IGNORECASE),
         "Network interface in promiscuous mode (possible sniffing)", "critical"),
        (re.compile(r"TCP: Possible SYN flooding", re.IGNORECASE),
         "SYN flood detected", "critical"),
        (re.compile(r"kernel:.*nf_conntrack: table full", re.IGNORECASE),
         "Connection tracking table full (possible DoS)", "critical"),
        (re.compile(r"COMMAND=/bin/(?:ba)?sh", re.IGNORECASE),
         "Shell spawned via privilege escalation", "warning"),
        (re.compile(r"UFW BLOCK", re.IGNORECASE),
         "Firewall blocked connection", "info"),
        (re.compile(r"apparmor=\"DENIED\"", re.IGNORECASE),
         "AppArmor denied access", "warning"),
        (re.compile(r"audit.*avc:\s+denied", re.IGNORECASE),
         "SELinux denied access", "warning"),
    ]

    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue

        timestamp = _extract_timestamp(line)

        for pattern, reason, severity in suspicious_syslog_patterns:
            if pattern.search(line):
                event = LogEvent(
                    timestamp=timestamp,
                    source_file=log_path,
                    line_number=line_num,
                    raw_line=line,
                    event_type="syslog_anomaly",
                    severity=severity,
                    details={"reason": reason},
                )
                result.suspicious_commands.append(event)
                break

    return result


def scan_all_logs() -> LogMonitorResult:
    """
    Scan all available system logs and combine results.
    """
    combined = LogMonitorResult()

    for log_path, log_type in LOG_FILES.items():
        if not Path(log_path).exists():
            continue

        if log_type == "auth":
            result = analyze_auth_log(log_path)
        elif log_type in ("syslog", "kernel", "daemon"):
            result = analyze_syslog(log_path)
        else:
            continue

        combined.events.extend(result.events)
        combined.brute_force_alerts.extend(result.brute_force_alerts)
        combined.privilege_escalations.extend(result.privilege_escalations)
        combined.suspicious_commands.extend(result.suspicious_commands)
        combined.account_changes.extend(result.account_changes)
        combined.total_lines_analyzed += result.total_lines_analyzed
        combined.files_analyzed.extend(result.files_analyzed)

    return combined
