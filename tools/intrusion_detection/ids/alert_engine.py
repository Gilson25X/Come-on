"""
Alert Engine Module

Provides a rule-based alert system that:
- Aggregates alerts from all IDS modules
- Categorizes and prioritizes alerts by severity
- Supports configurable alert rules and thresholds
- Generates consolidated alert reports
- Provides alert history tracking
"""

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ids.log_monitor import LogMonitorResult, BruteForceAlert, LogEvent
from ids.file_integrity import FIMResult, FileChange
from ids.network_monitor import NetworkMonitorResult, NetworkAlert


@dataclass
class Alert:
    """A unified alert from any IDS module."""
    alert_id: str
    timestamp: str
    module: str  # "log_monitor", "file_integrity", "network_monitor"
    alert_type: str
    severity: str  # "info", "warning", "critical"
    title: str
    description: str
    details: dict = field(default_factory=dict)

    @property
    def severity_rank(self) -> int:
        ranks = {"critical": 3, "warning": 2, "info": 1}
        return ranks.get(self.severity, 0)


@dataclass
class AlertSummary:
    """Summary of all alerts from an IDS scan."""
    alerts: list[Alert] = field(default_factory=list)
    scan_timestamp: str = ""
    scan_duration_seconds: float = 0.0
    modules_run: list[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for a in self.alerts if a.severity == "critical")

    @property
    def warning_count(self) -> int:
        return sum(1 for a in self.alerts if a.severity == "warning")

    @property
    def info_count(self) -> int:
        return sum(1 for a in self.alerts if a.severity == "info")

    @property
    def total_count(self) -> int:
        return len(self.alerts)

    @property
    def threat_level(self) -> str:
        if self.critical_count >= 3:
            return "CRITICAL"
        if self.critical_count >= 1:
            return "HIGH"
        if self.warning_count >= 5:
            return "MEDIUM"
        if self.warning_count >= 1:
            return "LOW"
        return "CLEAN"


def _generate_alert_id(module: str, alert_type: str, index: int) -> str:
    """Generate a unique alert ID."""
    ts = int(time.time())
    return f"{module[:3].upper()}-{alert_type[:8].upper()}-{ts}-{index:03d}"


def process_log_alerts(log_result: LogMonitorResult) -> list[Alert]:
    """Convert log monitor results into unified alerts."""
    alerts: list[Alert] = []
    idx = 0

    # Brute force alerts
    for bf in log_result.brute_force_alerts:
        idx += 1
        alerts.append(Alert(
            alert_id=_generate_alert_id("log", "bruteforce", idx),
            timestamp=bf.last_attempt or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            module="log_monitor",
            alert_type="brute_force",
            severity=bf.severity.lower(),
            title=f"Brute-force attack from {bf.source_ip}",
            description=(
                f"{bf.attempt_count} failed login attempts from {bf.source_ip} "
                f"targeting user(s): {bf.target_user or 'multiple'}"
            ),
            details={
                "source_ip": bf.source_ip,
                "target_user": bf.target_user,
                "attempt_count": bf.attempt_count,
                "first_attempt": bf.first_attempt,
                "last_attempt": bf.last_attempt,
                "source_file": bf.source_file,
            },
        ))

    # Suspicious commands
    for event in log_result.suspicious_commands:
        idx += 1
        alerts.append(Alert(
            alert_id=_generate_alert_id("log", "suscmd", idx),
            timestamp=event.timestamp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            module="log_monitor",
            alert_type="suspicious_command",
            severity=event.severity,
            title=f"Suspicious command by {event.username or 'unknown'}",
            description=event.details.get("reason", "Suspicious command executed"),
            details={
                "username": event.username,
                "command": event.details.get("command", ""),
                "reason": event.details.get("reason", ""),
                "source_file": event.source_file,
                "line": event.line_number,
            },
        ))

    # Account changes
    for event in log_result.account_changes:
        idx += 1
        alerts.append(Alert(
            alert_id=_generate_alert_id("log", "acctchg", idx),
            timestamp=event.timestamp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            module="log_monitor",
            alert_type="account_change",
            severity="warning",
            title=f"Account change: {event.event_type} ({event.username})",
            description=f"Account modification detected: {event.event_type} for user {event.username}",
            details={
                "event_type": event.event_type,
                "username": event.username,
                "source_file": event.source_file,
                "line": event.line_number,
            },
        ))

    # Privilege escalation (sudo failures)
    sudo_failures = [e for e in log_result.privilege_escalations if e.event_type == "sudo_failed"]
    if len(sudo_failures) >= 3:
        idx += 1
        alerts.append(Alert(
            alert_id=_generate_alert_id("log", "sudofail", idx),
            timestamp=sudo_failures[-1].timestamp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            module="log_monitor",
            alert_type="privilege_escalation_failure",
            severity="warning",
            title=f"{len(sudo_failures)} sudo authentication failures",
            description=(
                f"Multiple sudo authentication failures detected "
                f"({len(sudo_failures)} total)"
            ),
            details={
                "failure_count": len(sudo_failures),
                "users": list(set(e.username for e in sudo_failures if e.username)),
            },
        ))

    return alerts


def process_fim_alerts(fim_result: FIMResult) -> list[Alert]:
    """Convert file integrity results into unified alerts."""
    alerts: list[Alert] = []
    idx = 0

    if fim_result.is_baseline_new:
        idx += 1
        alerts.append(Alert(
            alert_id=_generate_alert_id("fim", "baseline", idx),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            module="file_integrity",
            alert_type="baseline_created",
            severity="info",
            title="FIM baseline created",
            description=(
                f"New baseline created with {fim_result.files_checked} files. "
                f"Subsequent scans will compare against this baseline."
            ),
            details={
                "files_checked": fim_result.files_checked,
                "baseline_file": fim_result.baseline_file,
            },
        ))
        return alerts

    for change in fim_result.changes:
        idx += 1
        alerts.append(Alert(
            alert_id=_generate_alert_id("fim", change.change_type, idx),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            module="file_integrity",
            alert_type=f"file_{change.change_type}",
            severity=change.severity,
            title=f"File {change.change_type}: {change.path}",
            description="; ".join(change.details),
            details={
                "path": change.path,
                "change_type": change.change_type,
                "changes": change.details,
            },
        ))

    return alerts


def process_network_alerts(net_result: NetworkMonitorResult) -> list[Alert]:
    """Convert network monitor results into unified alerts."""
    alerts: list[Alert] = []
    idx = 0

    for net_alert in net_result.alerts:
        idx += 1
        alerts.append(Alert(
            alert_id=_generate_alert_id("net", net_alert.alert_type, idx),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            module="network_monitor",
            alert_type=net_alert.alert_type,
            severity=net_alert.severity,
            title=f"Network: {net_alert.alert_type.replace('_', ' ').title()}",
            description=net_alert.details,
            details={
                "source_ip": net_alert.source_ip,
                "destination_ip": net_alert.destination_ip,
                "connections_involved": len(net_alert.related_connections),
            },
        ))

    return alerts


def generate_alert_summary(
    log_result: Optional[LogMonitorResult] = None,
    fim_result: Optional[FIMResult] = None,
    net_result: Optional[NetworkMonitorResult] = None,
    scan_duration: float = 0.0,
) -> AlertSummary:
    """
    Generate a consolidated alert summary from all IDS module results.

    Args:
        log_result: Results from log monitoring.
        fim_result: Results from file integrity checking.
        net_result: Results from network monitoring.
        scan_duration: How long the scan took.

    Returns:
        AlertSummary with all alerts sorted by severity.
    """
    summary = AlertSummary(
        scan_timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        scan_duration_seconds=scan_duration,
    )

    if log_result:
        summary.modules_run.append("log_monitor")
        summary.alerts.extend(process_log_alerts(log_result))

    if fim_result:
        summary.modules_run.append("file_integrity")
        summary.alerts.extend(process_fim_alerts(fim_result))

    if net_result:
        summary.modules_run.append("network_monitor")
        summary.alerts.extend(process_network_alerts(net_result))

    # Sort by severity (critical first)
    summary.alerts.sort(key=lambda a: a.severity_rank, reverse=True)

    return summary


def export_alerts_json(summary: AlertSummary, output_path: str) -> None:
    """Export alert summary to a JSON file."""
    data = {
        "scan_timestamp": summary.scan_timestamp,
        "scan_duration_seconds": summary.scan_duration_seconds,
        "modules_run": summary.modules_run,
        "threat_level": summary.threat_level,
        "counts": {
            "critical": summary.critical_count,
            "warning": summary.warning_count,
            "info": summary.info_count,
            "total": summary.total_count,
        },
        "alerts": [
            {
                "id": a.alert_id,
                "timestamp": a.timestamp,
                "module": a.module,
                "type": a.alert_type,
                "severity": a.severity,
                "title": a.title,
                "description": a.description,
                "details": a.details,
            }
            for a in summary.alerts
        ],
    }

    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
