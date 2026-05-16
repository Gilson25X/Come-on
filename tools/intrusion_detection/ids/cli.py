"""
Intrusion Detection System CLI — Host-based defensive monitoring tool.

Usage:
    python -m ids.cli [OPTIONS]

Runs log monitoring, file integrity checking, and network traffic analysis,
then prints a consolidated alert report.
"""

import argparse
import sys
import time

from ids.log_monitor import scan_all_logs, LogMonitorResult
from ids.file_integrity import (
    check_integrity,
    create_baseline,
    update_baseline,
    FIMResult,
    DEFAULT_BASELINE_PATH,
)
from ids.network_monitor import run_network_monitor, NetworkMonitorResult
from ids.alert_engine import (
    generate_alert_summary,
    export_alerts_json,
    AlertSummary,
    Alert,
)


class Colors:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls) -> None:
        cls.RED = cls.YELLOW = cls.GREEN = cls.CYAN = ""
        cls.BLUE = cls.BOLD = cls.DIM = cls.RESET = ""


def _severity_color(severity: str) -> str:
    if severity == "critical":
        return Colors.RED + Colors.BOLD
    if severity == "warning":
        return Colors.YELLOW
    return Colors.DIM


def _threat_color(level: str) -> str:
    if level in ("CRITICAL", "HIGH"):
        return Colors.RED + Colors.BOLD
    if level == "MEDIUM":
        return Colors.YELLOW
    if level == "LOW":
        return Colors.DIM
    return Colors.GREEN


def print_banner() -> None:
    banner = f"""{Colors.CYAN}{Colors.BOLD}
  ___ ____  ____
 |_ _|  _ \\/ ___|
  | || | | \\___ \\
  | || |_| |___) |
 |___|____/|____/

 Intrusion Detection System v1.0.0
 Host-Based Defensive Monitoring
{Colors.RESET}"""
    print(banner)


def print_section(title: str) -> None:
    width = 70
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'=' * width}")
    print(f"  {title}")
    print(f"{'=' * width}{Colors.RESET}")


def print_log_results(result: LogMonitorResult) -> None:
    """Print log monitoring results."""
    print_section("LOG MONITOR RESULTS")

    print(f"\n  Files analyzed: {', '.join(result.files_analyzed) or 'none found'}")
    print(f"  Total lines analyzed: {result.total_lines_analyzed:,}")

    # Brute force alerts
    if result.brute_force_alerts:
        print(f"\n  {Colors.RED}--- Brute-Force Attacks ({len(result.brute_force_alerts)}) ---{Colors.RESET}")
        for bf in sorted(result.brute_force_alerts, key=lambda x: x.attempt_count, reverse=True):
            color = _severity_color(bf.severity.lower())
            print(f"\n  {color}[{bf.severity}]{Colors.RESET} {bf.source_ip}")
            print(f"    Attempts: {bf.attempt_count}")
            print(f"    Target user(s): {bf.target_user or 'multiple'}")
            print(f"    Window: {bf.first_attempt} -> {bf.last_attempt}")
            print(f"    Source: {bf.source_file}")

    # Privilege escalations
    sudo_events = [e for e in result.privilege_escalations if e.event_type == "sudo_command"]
    sudo_fails = [e for e in result.privilege_escalations if e.event_type == "sudo_failed"]
    if sudo_events or sudo_fails:
        total = len(sudo_events) + len(sudo_fails)
        print(f"\n  --- Privilege Escalation Events ({total}) ---")
        print(f"    Sudo commands: {len(sudo_events)}")
        print(f"    Sudo failures: {len(sudo_fails)}")

    # Suspicious commands
    if result.suspicious_commands:
        print(f"\n  {Colors.RED}--- Suspicious Commands ({len(result.suspicious_commands)}) ---{Colors.RESET}")
        for event in result.suspicious_commands:
            color = _severity_color(event.severity)
            print(f"\n  {color}[{event.severity.upper()}]{Colors.RESET} {event.details.get('reason', '')}")
            if event.username:
                print(f"    User: {event.username}")
            cmd = event.details.get("command", "")
            if cmd:
                cmd_display = cmd[:120] + ("..." if len(cmd) > 120 else "")
                print(f"    Command: {cmd_display}")
            print(f"    Time: {event.timestamp}")

    # Account changes
    if result.account_changes:
        print(f"\n  {Colors.YELLOW}--- Account Changes ({len(result.account_changes)}) ---{Colors.RESET}")
        for event in result.account_changes:
            print(f"    [{event.event_type}] {event.username} ({event.timestamp})")

    if not result.brute_force_alerts and not result.suspicious_commands and not result.account_changes:
        print(f"\n  {Colors.GREEN}No suspicious log events detected.{Colors.RESET}")


def print_fim_results(result: FIMResult) -> None:
    """Print file integrity monitoring results."""
    print_section("FILE INTEGRITY MONITOR")

    print(f"\n  Files checked: {result.files_checked}")
    print(f"  Baseline: {result.baseline_file}")

    if result.is_baseline_new:
        print(f"\n  {Colors.CYAN}New baseline created with {result.files_checked} files.{Colors.RESET}")
        print(f"  Run the IDS again to detect changes against this baseline.")
        return

    if not result.changes:
        print(f"\n  {Colors.GREEN}No file integrity changes detected.{Colors.RESET}")
        return

    # Group changes by type
    by_type: dict[str, list] = {}
    for change in result.changes:
        by_type.setdefault(change.change_type, []).append(change)

    for change_type, changes in by_type.items():
        label = change_type.upper()
        print(f"\n  --- {label} Files ({len(changes)}) ---")
        for change in sorted(changes, key=lambda c: c.severity == "critical", reverse=True):
            color = _severity_color(change.severity)
            print(f"\n  {color}[{change.severity.upper()}]{Colors.RESET} {change.path}")
            for detail in change.details:
                print(f"    {Colors.YELLOW}! {detail}{Colors.RESET}")


def print_network_results(result: NetworkMonitorResult) -> None:
    """Print network monitoring results."""
    print_section("NETWORK MONITOR")

    print(f"\n  Total connections: {result.total_connections}")
    print(f"  Listening services: {len(result.listening_services)}")
    print(f"  Established connections: {len(result.established_connections)}")

    if result.connection_summary:
        print(f"\n  Connection states:")
        for state, count in sorted(result.connection_summary.items()):
            print(f"    {state}: {count}")

    if result.alerts:
        print(f"\n  {Colors.RED}--- Network Alerts ({len(result.alerts)}) ---{Colors.RESET}")
        for alert in sorted(result.alerts, key=lambda a: {"critical": 0, "warning": 1, "info": 2}.get(a.severity, 3)):
            color = _severity_color(alert.severity)
            print(f"\n  {color}[{alert.severity.upper()}]{Colors.RESET} {alert.alert_type.replace('_', ' ').title()}")
            print(f"    {alert.details}")
            if alert.source_ip:
                print(f"    Source: {alert.source_ip}")
            if alert.destination_ip:
                print(f"    Destination: {alert.destination_ip}")
    else:
        print(f"\n  {Colors.GREEN}No network anomalies detected.{Colors.RESET}")


def print_alert_summary(summary: AlertSummary) -> None:
    """Print the consolidated alert summary."""
    print_section("ALERT SUMMARY")

    color = _threat_color(summary.threat_level)
    print(f"\n  Threat Level: {color}{summary.threat_level}{Colors.RESET}")
    print(f"  Scan Duration: {summary.scan_duration_seconds:.1f} seconds")
    print(f"  Modules Run: {', '.join(summary.modules_run)}")
    print()
    print(f"  {Colors.RED}Critical: {summary.critical_count}{Colors.RESET}")
    print(f"  {Colors.YELLOW}Warning:  {summary.warning_count}{Colors.RESET}")
    print(f"  {Colors.DIM}Info:     {summary.info_count}{Colors.RESET}")
    print(f"  {'─' * 30}")
    print(f"  Total:    {summary.total_count}")
    print()

    if summary.total_count == 0:
        print(f"  {Colors.GREEN}{Colors.BOLD}No intrusion indicators detected.{Colors.RESET}")
    else:
        # Show top alerts
        critical_alerts = [a for a in summary.alerts if a.severity == "critical"]
        if critical_alerts:
            print(f"  {Colors.RED}{Colors.BOLD}Top Critical Alerts:{Colors.RESET}")
            for alert in critical_alerts[:5]:
                print(f"    [{alert.alert_id}] {alert.title}")
                desc_display = alert.description[:100] + ("..." if len(alert.description) > 100 else "")
                print(f"      {desc_display}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Intrusion Detection System - Host-based defensive monitoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s                         Run all monitors
  %(prog)s --logs --network        Monitor logs and network only
  %(prog)s --fim                   File integrity check only
  %(prog)s --fim --init-baseline   Create/reset FIM baseline
  %(prog)s --all -o report.json    Full scan with JSON export
""",
    )

    # Module selection
    module_group = parser.add_argument_group("Monitoring modules")
    module_group.add_argument(
        "--all", "-a",
        action="store_true",
        help="Run all monitoring modules (default)",
    )
    module_group.add_argument(
        "--logs", "-l",
        action="store_true",
        help="Analyze system and authentication logs",
    )
    module_group.add_argument(
        "--fim", "-f",
        action="store_true",
        help="Run file integrity monitor",
    )
    module_group.add_argument(
        "--network", "-n",
        action="store_true",
        help="Run network traffic monitor",
    )

    # FIM options
    fim_group = parser.add_argument_group("File Integrity options")
    fim_group.add_argument(
        "--init-baseline",
        action="store_true",
        help="Create or reset the FIM baseline",
    )
    fim_group.add_argument(
        "--update-baseline",
        action="store_true",
        help="Update baseline to current state (after legitimate changes)",
    )
    fim_group.add_argument(
        "--baseline-path",
        metavar="FILE",
        default=DEFAULT_BASELINE_PATH,
        help=f"Path to the FIM baseline file (default: {DEFAULT_BASELINE_PATH})",
    )
    fim_group.add_argument(
        "--watch-paths",
        nargs="+",
        metavar="PATH",
        help="Additional paths to monitor with FIM",
    )

    # Output options
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Export alert report to JSON file",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Only show alerts (suppress clean module results)",
    )

    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        Colors.disable()

    # Determine which modules to run
    any_module = args.logs or args.fim or args.network
    run_all = args.all or not any_module

    print_banner()

    start_time = time.time()

    log_result: LogMonitorResult | None = None
    fim_result: FIMResult | None = None
    net_result: NetworkMonitorResult | None = None

    # LOG MONITORING
    if run_all or args.logs:
        print(f"\n  {Colors.CYAN}Scanning system logs...{Colors.RESET}")
        log_result = scan_all_logs()
        print_log_results(log_result)

    # FILE INTEGRITY MONITORING
    if run_all or args.fim:
        if args.init_baseline:
            print(f"\n  {Colors.CYAN}Creating FIM baseline...{Colors.RESET}")
            fim_result = create_baseline(
                paths=args.watch_paths,
                baseline_path=args.baseline_path,
            )
        elif args.update_baseline:
            print(f"\n  {Colors.CYAN}Updating FIM baseline...{Colors.RESET}")
            fim_result = update_baseline(
                baseline_path=args.baseline_path,
                paths=args.watch_paths,
            )
        else:
            print(f"\n  {Colors.CYAN}Checking file integrity...{Colors.RESET}")
            fim_result = check_integrity(
                paths=args.watch_paths,
                baseline_path=args.baseline_path,
            )
        print_fim_results(fim_result)

    # NETWORK MONITORING
    if run_all or args.network:
        print(f"\n  {Colors.CYAN}Monitoring network connections...{Colors.RESET}")
        net_result = run_network_monitor()
        print_network_results(net_result)

    elapsed = time.time() - start_time

    # Generate consolidated alert summary
    summary = generate_alert_summary(
        log_result=log_result,
        fim_result=fim_result,
        net_result=net_result,
        scan_duration=elapsed,
    )

    print_alert_summary(summary)

    # JSON export
    if args.output:
        export_alerts_json(summary, args.output)
        print(f"  {Colors.CYAN}Report exported to: {args.output}{Colors.RESET}\n")

    # Exit code: 0 if clean, 1 if alerts found
    sys.exit(1 if summary.critical_count > 0 or summary.warning_count > 0 else 0)


if __name__ == "__main__":
    main()
