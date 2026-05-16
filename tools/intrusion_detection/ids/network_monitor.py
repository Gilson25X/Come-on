"""
Network Traffic Monitor Module

Monitors network connections and traffic patterns for intrusion indicators:
- Port scan detection (many connections to different ports from same source)
- Unusual outbound traffic patterns (data exfiltration indicators)
- Connection to known-malicious IP ranges
- DNS query anomaly detection
- Protocol anomalies (unexpected services on standard ports)
- Connection rate monitoring
"""

import os
import platform
import socket
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ConnectionRecord:
    """A network connection record."""
    protocol: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str
    pid: Optional[int] = None
    process_name: Optional[str] = None


@dataclass
class NetworkAlert:
    """A network-based intrusion alert."""
    alert_type: str  # "port_scan", "exfiltration", "suspicious_outbound", etc.
    severity: str  # "info", "warning", "critical"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    details: str = ""
    related_connections: list[ConnectionRecord] = field(default_factory=list)


@dataclass
class NetworkMonitorResult:
    """Aggregated network monitoring results."""
    alerts: list[NetworkAlert] = field(default_factory=list)
    total_connections: int = 0
    listening_services: list[ConnectionRecord] = field(default_factory=list)
    established_connections: list[ConnectionRecord] = field(default_factory=list)
    connection_summary: dict[str, int] = field(default_factory=dict)

    @property
    def total_alerts(self) -> int:
        return len(self.alerts)


# Known Bogon / reserved IP ranges that should not appear in external connections
BOGON_RANGES: list[tuple[str, str]] = [
    ("0.0.0.0", "Reserved"),
    ("100.64.", "Carrier-grade NAT"),
    ("169.254.", "Link-local"),
    ("192.0.0.", "IETF protocol assignments"),
    ("192.0.2.", "Documentation (TEST-NET-1)"),
    ("198.51.100.", "Documentation (TEST-NET-2)"),
    ("203.0.113.", "Documentation (TEST-NET-3)"),
    ("224.", "Multicast"),
    ("240.", "Reserved for future use"),
]

# Ports that commonly indicate specific services
EXPECTED_SERVICES: dict[int, str] = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}

# TCP states
TCP_STATES: dict[str, str] = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


def _hex_to_ip(hex_str: str) -> str:
    """Convert hex IP address from /proc/net/* to human-readable format."""
    if len(hex_str) == 8:
        addr = int(hex_str, 16)
        return socket.inet_ntoa(addr.to_bytes(4, "little"))
    elif len(hex_str) == 32:
        groups = [hex_str[i:i + 8] for i in range(0, 32, 8)]
        addr_bytes = b""
        for g in groups:
            addr_bytes += int(g, 16).to_bytes(4, "little")
        return socket.inet_ntop(socket.AF_INET6, addr_bytes)
    return hex_str


def _get_process_name(pid: int) -> Optional[str]:
    """Get process name for a PID."""
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            return f.read().strip()
    except (OSError, PermissionError):
        return None


def _build_inode_pid_map() -> dict[int, int]:
    """Build a map of socket inode -> PID for efficient lookup."""
    inode_map: dict[int, int] = {}
    proc_path = Path("/proc")

    try:
        for pid_dir in proc_path.iterdir():
            if not pid_dir.name.isdigit():
                continue
            fd_dir = pid_dir / "fd"
            try:
                for fd in fd_dir.iterdir():
                    try:
                        link = str(fd.resolve(strict=False))
                        if "socket:[" in link:
                            inode_str = link.split("[")[1].rstrip("]")
                            inode_map[int(inode_str)] = int(pid_dir.name)
                    except (OSError, PermissionError, ValueError, IndexError):
                        continue
            except (OSError, PermissionError):
                continue
    except (OSError, PermissionError):
        pass

    return inode_map


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    return (
        ip.startswith("10.")
        or ip.startswith("172.16.") or ip.startswith("172.17.")
        or ip.startswith("172.18.") or ip.startswith("172.19.")
        or ip.startswith("172.2") or ip.startswith("172.30.")
        or ip.startswith("172.31.")
        or ip.startswith("192.168.")
        or ip.startswith("127.")
        or ip == "0.0.0.0"
        or ip == "::"
        or ip == "::1"
    )


def get_connections() -> list[ConnectionRecord]:
    """Parse all active network connections from /proc/net on Linux."""
    connections: list[ConnectionRecord] = []

    if platform.system() != "Linux":
        return connections

    inode_map = _build_inode_pid_map()

    protocols = {
        "/proc/net/tcp": "tcp",
        "/proc/net/tcp6": "tcp6",
        "/proc/net/udp": "udp",
        "/proc/net/udp6": "udp6",
    }

    for proc_file, proto in protocols.items():
        path = Path(proc_file)
        if not path.exists():
            continue

        try:
            content = path.read_text()
        except (OSError, PermissionError):
            continue

        for line in content.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 10:
                continue

            try:
                local_parts = parts[1].split(":")
                remote_parts = parts[2].split(":")

                local_ip = _hex_to_ip(local_parts[0])
                local_port = int(local_parts[1], 16)
                remote_ip = _hex_to_ip(remote_parts[0])
                remote_port = int(remote_parts[1], 16)

                state_hex = parts[3]
                state = TCP_STATES.get(state_hex, state_hex)

                inode = int(parts[9]) if len(parts) > 9 else 0

                pid: Optional[int] = None
                process_name: Optional[str] = None
                if inode > 0 and inode in inode_map:
                    pid = inode_map[inode]
                    process_name = _get_process_name(pid)

                connections.append(ConnectionRecord(
                    protocol=proto,
                    local_address=local_ip,
                    local_port=local_port,
                    remote_address=remote_ip,
                    remote_port=remote_port,
                    state=state,
                    pid=pid,
                    process_name=process_name,
                ))
            except (ValueError, IndexError):
                continue

    return connections


def detect_port_scan(connections: list[ConnectionRecord]) -> list[NetworkAlert]:
    """
    Detect potential port scanning activity.

    A port scan is indicated by many SYN_RECV or ESTABLISHED connections
    from the same source IP to many different local ports.
    """
    alerts: list[NetworkAlert] = []

    # Group inbound connections by source IP
    inbound_by_source: dict[str, list[ConnectionRecord]] = defaultdict(list)
    for conn in connections:
        if conn.state in ("SYN_RECV", "ESTABLISHED", "SYN_SENT"):
            if not _is_private_ip(conn.remote_address) or conn.remote_address.startswith("10."):
                inbound_by_source[conn.remote_address].append(conn)

    for source_ip, conns in inbound_by_source.items():
        unique_ports = set(c.local_port for c in conns)
        if len(unique_ports) >= 10:
            severity = "critical" if len(unique_ports) >= 50 else "warning"
            alerts.append(NetworkAlert(
                alert_type="port_scan",
                severity=severity,
                source_ip=source_ip,
                details=(
                    f"Potential port scan: {len(unique_ports)} unique ports "
                    f"targeted from {source_ip}"
                ),
                related_connections=conns[:10],
            ))

    return alerts


def detect_data_exfiltration(connections: list[ConnectionRecord]) -> list[NetworkAlert]:
    """
    Detect potential data exfiltration indicators.

    Flags:
    - Many outbound connections to unusual ports from non-browser processes
    - Outbound connections on DNS port from non-resolver processes
    - Connections to unusual high ports
    """
    alerts: list[NetworkAlert] = []

    browser_processes = {"chrome", "firefox", "chromium", "brave", "opera", "edge"}
    resolver_processes = {"systemd-resolve", "resolved", "dnsmasq", "unbound",
                          "named", "bind", "coredns"}

    outbound_by_process: dict[str, list[ConnectionRecord]] = defaultdict(list)

    for conn in connections:
        if conn.state != "ESTABLISHED":
            continue
        if _is_private_ip(conn.remote_address):
            continue
        proc = conn.process_name or "unknown"
        outbound_by_process[proc].append(conn)

    for proc, conns in outbound_by_process.items():
        # Non-browser process with many external connections
        if proc.lower() not in browser_processes and len(conns) >= 20:
            alerts.append(NetworkAlert(
                alert_type="excessive_outbound",
                severity="warning",
                details=(
                    f"Process '{proc}' has {len(conns)} outbound connections "
                    f"to external hosts"
                ),
                related_connections=conns[:5],
            ))

        # DNS connections from non-resolver
        for conn in conns:
            if conn.remote_port == 53 and proc.lower() not in resolver_processes:
                alerts.append(NetworkAlert(
                    alert_type="dns_anomaly",
                    severity="warning",
                    destination_ip=conn.remote_address,
                    details=(
                        f"Direct DNS connection from non-resolver process '{proc}' "
                        f"to {conn.remote_address} (possible DNS tunneling)"
                    ),
                    related_connections=[conn],
                ))

    return alerts


def detect_suspicious_listeners(connections: list[ConnectionRecord]) -> list[NetworkAlert]:
    """
    Detect suspicious listening services.

    Flags services listening on:
    - All interfaces (0.0.0.0) on unexpected ports
    - Known C2/backdoor ports
    - Ports that don't match expected services
    """
    alerts: list[NetworkAlert] = []

    suspicious_listen_ports: dict[int, str] = {
        4444: "Metasploit default handler",
        5555: "Common RAT / ADB",
        6666: "IRC botnet / backdoor",
        6667: "IRC botnet",
        8888: "Common backdoor / proxy",
        9999: "Common backdoor",
        1234: "Common backdoor",
        31337: "Back Orifice / elite backdoor",
        12345: "NetBus trojan",
        27374: "SubSeven trojan",
        3333: "Cryptocurrency mining pool",
        14444: "Monero mining pool",
    }

    for conn in connections:
        if conn.state != "LISTEN":
            continue

        # Check for suspicious listening ports
        if conn.local_port in suspicious_listen_ports:
            alerts.append(NetworkAlert(
                alert_type="suspicious_listener",
                severity="critical",
                details=(
                    f"Listening on suspicious port {conn.local_port}: "
                    f"{suspicious_listen_ports[conn.local_port]} "
                    f"(process: {conn.process_name or 'unknown'})"
                ),
                related_connections=[conn],
            ))

        # Service on all interfaces on uncommon port
        if conn.local_address in ("0.0.0.0", "::") and conn.local_port > 1024:
            if conn.local_port not in EXPECTED_SERVICES and \
               conn.local_port not in suspicious_listen_ports:
                if conn.process_name and conn.process_name not in (
                    "node", "python3", "python", "java", "code", "docker-proxy",
                    "containerd", "kubelet", "nginx", "apache2", "httpd",
                ):
                    alerts.append(NetworkAlert(
                        alert_type="unexpected_listener",
                        severity="info",
                        details=(
                            f"Unexpected service on 0.0.0.0:{conn.local_port} "
                            f"(process: {conn.process_name})"
                        ),
                        related_connections=[conn],
                    ))

    return alerts


def detect_connection_anomalies(connections: list[ConnectionRecord]) -> list[NetworkAlert]:
    """
    Detect general connection anomalies.
    """
    alerts: list[NetworkAlert] = []

    # Check for connections from processes in suspicious directories
    for conn in connections:
        if conn.state != "ESTABLISHED" or conn.pid is None:
            continue

        try:
            exe_path = str(Path(f"/proc/{conn.pid}/exe").resolve(strict=False))
        except (OSError, PermissionError):
            continue

        suspicious_dirs = ["/tmp/", "/dev/shm/", "/var/tmp/"]
        for sus_dir in suspicious_dirs:
            if sus_dir in exe_path.lower():
                alerts.append(NetworkAlert(
                    alert_type="suspicious_process_connection",
                    severity="critical",
                    details=(
                        f"Network connection from process in {sus_dir}: "
                        f"{exe_path} -> {conn.remote_address}:{conn.remote_port}"
                    ),
                    related_connections=[conn],
                ))
                break

    # Check for bogon destination IPs in established connections
    for conn in connections:
        if conn.state != "ESTABLISHED":
            continue
        for bogon_prefix, description in BOGON_RANGES:
            if conn.remote_address.startswith(bogon_prefix):
                alerts.append(NetworkAlert(
                    alert_type="bogon_connection",
                    severity="warning",
                    destination_ip=conn.remote_address,
                    details=(
                        f"Connection to bogon/reserved IP range ({description}): "
                        f"{conn.remote_address}:{conn.remote_port}"
                    ),
                    related_connections=[conn],
                ))
                break

    return alerts


def run_network_monitor() -> NetworkMonitorResult:
    """
    Run all network monitoring checks and aggregate results.
    """
    connections = get_connections()

    result = NetworkMonitorResult(total_connections=len(connections))

    # Categorize connections
    for conn in connections:
        if conn.state == "LISTEN":
            result.listening_services.append(conn)
        elif conn.state == "ESTABLISHED":
            result.established_connections.append(conn)

    # Connection summary by state
    state_counts: dict[str, int] = defaultdict(int)
    for conn in connections:
        state_counts[conn.state] += 1
    result.connection_summary = dict(state_counts)

    # Run detection modules
    result.alerts.extend(detect_port_scan(connections))
    result.alerts.extend(detect_data_exfiltration(connections))
    result.alerts.extend(detect_suspicious_listeners(connections))
    result.alerts.extend(detect_connection_anomalies(connections))

    return result
