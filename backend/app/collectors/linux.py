"""
Linux configuration collector.

READ-ONLY: reads only files and runs only read-only system commands
that any non-root user can safely call on a Linux system.

No arbitrary shell execution from API input.
No changes to system state.
Not available on Windows — returns an explicit error evidence dict.

Normalised evidence structure (for linux.json rules):
  {
    "_source": "linux_live:<hostname>",
    "sshd": {
        "protocol": str | None,
        "permit_root_login": str | None
    },
    "pam": {
        "password_hash": str | None
    },
    "firewall": {
        "active": bool
    },
    "services": {
        "cron_active": bool
    }
  }
"""
from __future__ import annotations

import logging
import platform
import re
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

_COLLECTION_ERROR_SOURCE = "linux_live:collection_error"


def _run(cmd: list[str], timeout: int = 5) -> str | None:
    """Run a read-only command and return stdout, or None on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception as exc:  # noqa: BLE001
        logger.debug("Command %s failed: %s", cmd, exc)
        return None


def _read_file(path: str) -> str | None:
    """Read a file, returning None if missing or unreadable."""
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:  # noqa: BLE001
        return None


def _collect_sshd() -> dict:
    sshd_config = _read_file("/etc/ssh/sshd_config")
    protocol: str | None = None
    permit_root: str | None = None

    if sshd_config:
        for line in sshd_config.splitlines():
            line = line.strip()
            if line.startswith("#"):
                continue
            if re.match(r"^Protocol\s+", line, re.IGNORECASE):
                protocol = line.split()[-1]
            if re.match(r"^PermitRootLogin\s+", line, re.IGNORECASE):
                permit_root = line.split()[-1].lower()

    return {"protocol": protocol, "permit_root_login": permit_root}


def _collect_pam() -> dict:
    pam_config = _read_file("/etc/pam.d/common-password")
    password_hash: str | None = None

    if pam_config:
        for line in pam_config.splitlines():
            if "pam_unix.so" in line and not line.strip().startswith("#"):
                # e.g. "password [success=1 default=ignore] pam_unix.so obscure sha512"
                password_hash = line
                break

    return {"password_hash": password_hash}


def _collect_firewall() -> dict:
    """Check if ufw or iptables is active."""
    active = False

    # Try ufw
    if shutil.which("ufw"):
        out = _run(["ufw", "status"])
        if out and "active" in out.lower():
            active = True

    # Fallback: iptables (check for non-empty filter table)
    if not active and shutil.which("iptables"):
        out = _run(["iptables", "-L", "-n"])
        if out and "Chain INPUT" in out:
            # Has rules if there's anything beyond the default "policy ACCEPT"
            lines = [ln for ln in out.splitlines() if ln.strip() and not ln.startswith("Chain") and not ln.startswith("target")]
            active = len(lines) > 0

    return {"active": active}


def _collect_services() -> dict:
    """Check if cron is running via systemctl."""
    cron_active = False
    if shutil.which("systemctl"):
        for unit in ("cron", "crond"):
            out = _run(["systemctl", "is-active", unit])
            if out and out.strip() == "active":
                cron_active = True
                break

    return {"cron_active": cron_active}


def collect() -> dict:
    """
    Collect Linux security configuration facts from the current host.

    Only runs on Linux. Returns an error evidence dict on Windows/macOS
    or if collection fails — the ERROR evidence will produce ERROR findings,
    never false PASSes.

    Returns:
        Normalised evidence dict with '_source' key.
    """
    if platform.system() != "Linux":
        logger.warning(
            "Linux collector called on non-Linux platform (%s). Returning error evidence.",
            platform.system()
        )
        return {
            "_source": _COLLECTION_ERROR_SOURCE,
            "_error": f"Linux collector not available on {platform.system()}",
        }

    import socket
    hostname = socket.gethostname()

    try:
        evidence: dict = {
            "_source": f"linux_live:{hostname}",
            "sshd": _collect_sshd(),
            "pam": _collect_pam(),
            "firewall": _collect_firewall(),
            "services": _collect_services(),
        }
        logger.info("Linux evidence collected from %s", hostname)
        return evidence

    except Exception as exc:  # noqa: BLE001
        logger.exception("Linux collector failed: %s", exc)
        return {
            "_source": _COLLECTION_ERROR_SOURCE,
            "_error": str(exc),
        }
