"""
File Integrity Monitor (FIM) Module

Monitors critical system files and directories for unauthorized changes:
- Creates and verifies SHA-256 hash baselines of critical files
- Detects new, modified, and deleted files
- Monitors permission and ownership changes
- Watches sensitive configuration files and binaries
"""

import hashlib
import json
import os
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class FileState:
    """Snapshot of a file's state at a point in time."""
    path: str
    sha256: str
    size: int
    mode: int
    uid: int
    gid: int
    mtime: float
    is_symlink: bool = False

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
            "mtime": self.mtime,
            "is_symlink": self.is_symlink,
        }

    @staticmethod
    def from_dict(d: dict) -> "FileState":
        return FileState(
            path=d["path"],
            sha256=d["sha256"],
            size=d["size"],
            mode=d["mode"],
            uid=d["uid"],
            gid=d["gid"],
            mtime=d["mtime"],
            is_symlink=d.get("is_symlink", False),
        )


@dataclass
class FileChange:
    """A detected change to a monitored file."""
    path: str
    change_type: str  # "modified", "created", "deleted", "permissions", "ownership"
    severity: str  # "info", "warning", "critical"
    details: list[str] = field(default_factory=list)
    old_state: Optional[FileState] = None
    new_state: Optional[FileState] = None


@dataclass
class FIMResult:
    """Result from file integrity check."""
    changes: list[FileChange] = field(default_factory=list)
    files_checked: int = 0
    baseline_file: Optional[str] = None
    is_baseline_new: bool = False

    @property
    def total_changes(self) -> int:
        return len(self.changes)

    @property
    def critical_changes(self) -> int:
        return sum(1 for c in self.changes if c.severity == "critical")


# Critical system directories and files to monitor
CRITICAL_PATHS: list[str] = [
    # System binaries
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/bin",
    "/sbin",
    # Configuration
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/hosts",
    "/etc/hosts.allow",
    "/etc/hosts.deny",
    "/etc/crontab",
    "/etc/pam.d",
    "/etc/security",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    # Init / services
    "/etc/systemd/system",
    "/etc/init.d",
    "/etc/rc.local",
    # Kernel modules
    "/lib/modules",
    "/etc/modprobe.d",
    # Network configuration
    "/etc/resolv.conf",
    "/etc/nsswitch.conf",
    "/etc/network",
    "/etc/netplan",
]

# Files that are CRITICAL if modified (higher severity)
CRITICAL_FILES: set[str] = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/hosts",
    "/etc/ld.so.conf",
    "/etc/rc.local",
    "/etc/crontab",
    "/etc/pam.d/common-auth",
    "/etc/pam.d/sshd",
}

DEFAULT_BASELINE_PATH = os.path.expanduser("~/.ids_baseline.json")


def _compute_sha256(file_path: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
    except (OSError, PermissionError):
        return "ERROR_READING_FILE"
    return h.hexdigest()


def _get_file_state(file_path: str) -> Optional[FileState]:
    """Get the current state of a file."""
    path = Path(file_path)
    try:
        is_symlink = path.is_symlink()
        st = path.stat()
        sha256 = _compute_sha256(file_path) if path.is_file() and not is_symlink else ""
        return FileState(
            path=file_path,
            sha256=sha256,
            size=st.st_size,
            mode=st.st_mode,
            uid=st.st_uid,
            gid=st.st_gid,
            mtime=st.st_mtime,
            is_symlink=is_symlink,
        )
    except (OSError, PermissionError):
        return None


def _collect_file_states(paths: list[str], max_depth: int = 2) -> dict[str, FileState]:
    """Collect file states for all monitored paths."""
    states: dict[str, FileState] = {}

    for path_str in paths:
        path = Path(path_str)

        if not path.exists():
            continue

        if path.is_file():
            state = _get_file_state(path_str)
            if state:
                states[path_str] = state
        elif path.is_dir():
            try:
                for root, dirs, files in os.walk(path_str):
                    # Limit depth
                    depth = root.replace(path_str, "").count(os.sep)
                    if depth >= max_depth:
                        dirs.clear()
                        continue

                    for filename in files:
                        fp = os.path.join(root, filename)
                        state = _get_file_state(fp)
                        if state:
                            states[fp] = state
            except (OSError, PermissionError):
                continue

    return states


def create_baseline(
    paths: Optional[list[str]] = None,
    baseline_path: str = DEFAULT_BASELINE_PATH,
    max_depth: int = 2,
) -> FIMResult:
    """
    Create a baseline snapshot of monitored files.

    Args:
        paths: List of paths to monitor (default: CRITICAL_PATHS).
        baseline_path: Where to save the baseline JSON.
        max_depth: Maximum directory traversal depth.

    Returns:
        FIMResult indicating baseline creation status.
    """
    monitored_paths = paths or CRITICAL_PATHS
    states = _collect_file_states(monitored_paths, max_depth)

    baseline_data = {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "monitored_paths": monitored_paths,
        "files": {path: state.to_dict() for path, state in states.items()},
    }

    with open(baseline_path, "w") as f:
        json.dump(baseline_data, f, indent=2)

    result = FIMResult(
        files_checked=len(states),
        baseline_file=baseline_path,
        is_baseline_new=True,
    )
    return result


def check_integrity(
    paths: Optional[list[str]] = None,
    baseline_path: str = DEFAULT_BASELINE_PATH,
    max_depth: int = 2,
) -> FIMResult:
    """
    Check current file states against the baseline.

    If no baseline exists, creates one and returns with is_baseline_new=True.

    Args:
        paths: List of paths to check (default: CRITICAL_PATHS).
        baseline_path: Path to the baseline JSON file.
        max_depth: Maximum directory traversal depth.

    Returns:
        FIMResult with all detected changes.
    """
    if not Path(baseline_path).exists():
        return create_baseline(paths, baseline_path, max_depth)

    try:
        with open(baseline_path, "r") as f:
            baseline_data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return create_baseline(paths, baseline_path, max_depth)

    baseline_files: dict[str, FileState] = {}
    for path, state_dict in baseline_data.get("files", {}).items():
        baseline_files[path] = FileState.from_dict(state_dict)

    monitored_paths = paths or baseline_data.get("monitored_paths", CRITICAL_PATHS)
    current_states = _collect_file_states(monitored_paths, max_depth)

    result = FIMResult(
        files_checked=len(current_states),
        baseline_file=baseline_path,
    )

    # Check for modified and deleted files
    for path, baseline_state in baseline_files.items():
        current_state = current_states.get(path)

        if current_state is None:
            # File was deleted
            severity = "critical" if path in CRITICAL_FILES else "warning"
            result.changes.append(FileChange(
                path=path,
                change_type="deleted",
                severity=severity,
                details=[f"File no longer exists (was {baseline_state.size} bytes)"],
                old_state=baseline_state,
            ))
            continue

        changes: list[str] = []

        # Content change
        if baseline_state.sha256 and current_state.sha256:
            if baseline_state.sha256 != current_state.sha256:
                changes.append(
                    f"Content modified (hash changed from "
                    f"{baseline_state.sha256[:16]}... to {current_state.sha256[:16]}...)"
                )

        # Size change
        if baseline_state.size != current_state.size:
            changes.append(
                f"Size changed from {baseline_state.size} to {current_state.size} bytes"
            )

        # Permission change
        if baseline_state.mode != current_state.mode:
            old_perms = stat.filemode(baseline_state.mode)
            new_perms = stat.filemode(current_state.mode)
            changes.append(f"Permissions changed from {old_perms} to {new_perms}")

            # Check for dangerous permission changes
            if (current_state.mode & stat.S_ISUID) and not (baseline_state.mode & stat.S_ISUID):
                changes.append("SUID bit was added")
            if (current_state.mode & stat.S_IWOTH) and not (baseline_state.mode & stat.S_IWOTH):
                changes.append("World-writable permission was added")

        # Ownership change
        if baseline_state.uid != current_state.uid or baseline_state.gid != current_state.gid:
            changes.append(
                f"Ownership changed from {baseline_state.uid}:{baseline_state.gid} "
                f"to {current_state.uid}:{current_state.gid}"
            )

        if changes:
            severity = "critical" if path in CRITICAL_FILES else "warning"
            result.changes.append(FileChange(
                path=path,
                change_type="modified",
                severity=severity,
                details=changes,
                old_state=baseline_state,
                new_state=current_state,
            ))

    # Check for new files
    for path, current_state in current_states.items():
        if path not in baseline_files:
            severity = "warning"
            details = [f"New file detected ({current_state.size} bytes)"]

            # New executables in system dirs are more suspicious
            if current_state.mode & stat.S_IXUSR:
                parent = str(Path(path).parent)
                if any(parent.startswith(d) for d in ("/usr/bin", "/usr/sbin",
                                                       "/bin", "/sbin",
                                                       "/usr/local/bin")):
                    severity = "critical"
                    details.append("New executable in system binary directory")

            # New SUID binaries are critical
            if current_state.mode & stat.S_ISUID:
                severity = "critical"
                details.append("New SUID binary detected")

            result.changes.append(FileChange(
                path=path,
                change_type="created",
                severity=severity,
                details=details,
                new_state=current_state,
            ))

    return result


def update_baseline(
    baseline_path: str = DEFAULT_BASELINE_PATH,
    paths: Optional[list[str]] = None,
    max_depth: int = 2,
) -> FIMResult:
    """
    Update the baseline to reflect current file states.
    Useful after legitimate system updates.
    """
    return create_baseline(paths, baseline_path, max_depth)
