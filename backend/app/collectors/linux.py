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
        "permit_root_login": str | None,
        "permit_empty_passwords": str | None,
        "password_authentication": str | None
    },
    "pam": {
        "password_hash": str | None
    },
    "firewall": {
        "active": bool,
        "installed": bool,
        "ufw_installed": bool,
        "ufw_active": bool,
        "iptables_installed": bool,
        "iptables_has_rules": bool,
        "effective_policy": str | None
    },
    "services": {
        "cron_active": bool
    },
    "sysctl": {
        "ip_forward": str | None,
        "icmp_echo_ignore_broadcasts": str | None
    }
  }
"""
from __future__ import annotations

import glob
import logging
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

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
        p = Path(path)
        if not p.is_file():
            return None
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:  # noqa: BLE001
        return None


def _collect_sshd() -> dict[str, str | None]:
    """
    Collect OpenSSH server settings.
    Checks effective runtime configuration (sshd -T) if possible,
    and falls back to parsing /etc/ssh/sshd_config including Include directives
    and /etc/ssh/sshd_config.d/*.conf.
    """
    protocol: str | None = None
    permit_root: str | None = None
    permit_empty_pw: str | None = None
    password_auth: str | None = None

    # 1. Try effective runtime config if sshd is executable
    if shutil.which("sshd"):
        effective = _run(["sshd", "-T"], timeout=3)
        if effective:
            for line in effective.splitlines():
                line = line.strip().lower()
                if line.startswith("permitrootlogin "):
                    permit_root = line.split(maxsplit=1)[1].strip()
                elif line.startswith("permitemptypasswords "):
                    permit_empty_pw = line.split(maxsplit=1)[1].strip()
                elif line.startswith("passwordauthentication "):
                    password_auth = line.split(maxsplit=1)[1].strip()
                elif line.startswith("protocol "):
                    protocol = line.split(maxsplit=1)[1].strip()

    # 2. If any key is still None, inspect configuration files
    if None in (permit_root, permit_empty_pw, password_auth, protocol):
        config_files: list[str] = []
        main_config = "/etc/ssh/sshd_config"
        main_text = _read_file(main_config)
        if main_text:
            config_files.append(main_config)
            # Check for Include directives
            for line in main_text.splitlines():
                line = line.strip()
                if line.startswith("#"):
                    continue
                m = re.match(r"^Include\s+(.+)$", line, re.IGNORECASE)
                if m:
                    pattern = m.group(1).strip()
                    if not pattern.startswith("/"):
                        pattern = f"/etc/ssh/{pattern}"
                    for inc_path in sorted(glob.glob(pattern)):
                        if inc_path not in config_files and Path(inc_path).is_file():
                            config_files.append(inc_path)

        # Default drop-in dir if not explicitly included
        dropin_files = sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf"))
        for d_file in dropin_files:
            if d_file not in config_files and Path(d_file).is_file():
                config_files.append(d_file)

        # In OpenSSH, first specification of an option wins
        for cfg_path in config_files:
            text = _read_file(cfg_path)
            if not text:
                continue
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(maxsplit=1)
                if len(parts) < 2:
                    continue
                keyword = parts[0].lower()
                val = parts[1].strip()

                if keyword == "permitrootlogin" and permit_root is None:
                    permit_root = val.lower()
                elif keyword == "permitemptypasswords" and permit_empty_pw is None:
                    permit_empty_pw = val.lower()
                elif keyword == "passwordauthentication" and password_auth is None:
                    password_auth = val.lower()
                elif keyword == "protocol" and protocol is None:
                    protocol = val.lower()

    return {
        "protocol": protocol,
        "permit_root_login": permit_root,
        "permit_empty_passwords": permit_empty_pw,
        "password_authentication": password_auth,
    }


def _collect_pam() -> dict[str, str | None]:
    """Collect PAM password policy settings."""
    pam_config = _read_file("/etc/pam.d/common-password")
    password_hash: str | None = None

    if pam_config:
        for line in pam_config.splitlines():
            if "pam_unix.so" in line and not line.strip().startswith("#"):
                password_hash = line.strip()
                break

    return {"password_hash": password_hash}


def _collect_firewall() -> dict[str, Any]:
    """
    Check firewall status and configuration.
    Distinguishes installed, active, configured rules, and policy.
    Never marks active=True without concrete evidence of filtering rules.
    """
    ufw_installed = shutil.which("ufw") is not None
    iptables_installed = shutil.which("iptables") is not None
    ufw_active = False
    iptables_has_rules = False
    effective_policy: str | None = None

    # Check ufw
    if ufw_installed:
        out = _run(["ufw", "status"])
        if out and re.search(r"Status:\s*active", out, re.IGNORECASE):
            ufw_active = True
            effective_policy = "active"

    # Check iptables
    if iptables_installed:
        out = _run(["iptables", "-L", "-n"])
        if out and "Chain " in out:
            # Check for non-default drop/reject policy or actual filtering rules
            input_chain_has_rules = False
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("Chain INPUT") and "policy DROP" in line:
                    input_chain_has_rules = True
                    effective_policy = effective_policy or "DROP"
                elif (
                    not line.startswith("Chain")
                    and not line.startswith("target")
                    and not line.startswith("pkts")
                    and re.match(r"^(ACCEPT|DROP|REJECT|LOG|[A-Z_]+)\s+", line)
                ):
                    # Actual iptables rule line
                    input_chain_has_rules = True
            iptables_has_rules = input_chain_has_rules

    is_active = ufw_active or (iptables_installed and iptables_has_rules)

    return {
        "active": is_active,
        "installed": ufw_installed or iptables_installed,
        "ufw_installed": ufw_installed,
        "ufw_active": ufw_active,
        "iptables_installed": iptables_installed,
        "iptables_has_rules": iptables_has_rules,
        "effective_policy": effective_policy,
    }


def _collect_services() -> dict[str, bool]:
    """Check if scheduled task daemons (cron / crond) are active."""
    cron_active = False
    if shutil.which("systemctl"):
        for unit in ("cron", "crond"):
            out = _run(["systemctl", "is-active", unit])
            if out and out.strip() == "active":
                cron_active = True
                break

    return {"cron_active": cron_active}


def _collect_sysctl() -> dict[str, str | None]:
    """Collect key security kernel parameters in a read-only manner."""
    ip_fwd = _read_file("/proc/sys/net/ipv4/ip_forward")
    icmp_echo = _read_file("/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts")

    return {
        "ip_forward": ip_fwd.strip() if ip_fwd else None,
        "icmp_echo_ignore_broadcasts": icmp_echo.strip() if icmp_echo else None,
    }


def collect() -> dict[str, Any]:
    """
    Collect Linux security configuration facts from the current host.

    Only runs on Linux. Returns an error evidence dict on Windows/macOS
    or if collection fails — the ERROR evidence will produce ERROR findings,
    never false PASSes.
    """
    if platform.system() != "Linux":
        logger.warning(
            "Linux collector called on non-Linux platform (%s). Returning error evidence.",
            platform.system(),
        )
        return {
            "_source": _COLLECTION_ERROR_SOURCE,
            "_error": f"Linux collector not available on {platform.system()}",
        }

    import socket
    hostname = socket.gethostname()

    try:
        evidence: dict[str, Any] = {
            "_source": f"linux_live:{hostname}",
            "sshd": _collect_sshd(),
            "pam": _collect_pam(),
            "firewall": _collect_firewall(),
            "services": _collect_services(),
            "sysctl": _collect_sysctl(),
        }
        logger.info("Linux evidence collected from %s", hostname)
        return evidence

    except Exception as exc:  # noqa: BLE001
        logger.exception("Linux collector failed: %s", exc)
        return {
            "_source": _COLLECTION_ERROR_SOURCE,
            "_error": str(exc),
        }


def collect_from_dict(data: dict[str, Any], source_label: str = "linux_fixture:inline") -> dict[str, Any]:
    """Load Linux evidence from an in-memory dictionary (useful for simulated tests)."""
    result = dict(data)
    result["_source"] = source_label
    return result


def collect_from_file(path: str | Path, source_label: str | None = None) -> dict[str, Any]:
    """Load Linux evidence from a JSON file (offline / simulated mode)."""
    import json
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Linux evidence file not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    label = source_label or f"linux_fixture:{p.stem}"
    data["_source"] = label
    return data
