"""Windows PowerShell-based evidence collector for CIS Compliance Auditor.

Supports:
  - Live collection via PowerShell / Registry (Windows only)
  - Offline mode from a pre-collected JSON file
  - Inline dict injection (for testing / fixtures)

All operations are READ-ONLY; no system state is modified.
"""
from __future__ import annotations

import json
import logging
import platform
import subprocess
import socket
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------
Evidence = dict[str, Any]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run_ps(command: str, timeout: int = 20) -> str | None:
    """Run a PowerShell command and return its stdout, or None on any error."""
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            return None
        return result.stdout.strip() or None
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired, Exception):
        return None


def _parse_json(raw: str | None) -> Any:
    """Safely parse a JSON string; returns None if raw is None or invalid."""
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Sub-collectors (each returns a dict with None values on failure)
# ---------------------------------------------------------------------------

def _collect_os() -> dict[str, str | None]:
    """Collect OS information via CIM/WMI or Registry fallback."""
    defaults: dict[str, str | None] = {
        "caption": None,
        "version": None,
        "build_number": None,
    }
    try:
        raw = _run_ps(
            "Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue "
            "| Select-Object Caption, Version, BuildNumber | ConvertTo-Json"
        )
        data = _parse_json(raw)
        if isinstance(data, dict) and data.get("Caption"):
            return {
                "caption": data.get("Caption"),
                "version": data.get("Version"),
                "build_number": str(data["BuildNumber"]) if data.get("BuildNumber") is not None else None,
            }

        # Fallback to Registry & Environment for non-elevated user access
        caption = _run_ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -ErrorAction SilentlyContinue).ProductName")
        build = _run_ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -ErrorAction SilentlyContinue).CurrentBuild")
        version = _run_ps("[System.Environment]::OSVersion.Version.ToString()")
        return {
            "caption": caption.strip() if caption else None,
            "version": version.strip() if version else None,
            "build_number": build.strip() if build else None,
        }
    except Exception:  # noqa: BLE001
        return defaults


def _collect_firewall() -> dict[str, bool | None]:
    """Collect Windows Firewall profile states via NetFirewallProfile or Registry."""
    defaults: dict[str, bool | None] = {
        "domain_enabled": None,
        "private_enabled": None,
        "public_enabled": None,
    }
    try:
        raw = _run_ps(
            "Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name, Enabled | ConvertTo-Json"
        )
        data = _parse_json(raw)
        if data is not None:
            profiles: list[dict] = data if isinstance(data, list) else [data]
            result = dict(defaults)
            for profile in profiles:
                name = str(profile.get("Name", "")).lower()
                enabled = profile.get("Enabled")
                if name == "domain":
                    result["domain_enabled"] = bool(enabled) if enabled is not None else None
                elif name == "private":
                    result["private_enabled"] = bool(enabled) if enabled is not None else None
                elif name == "public":
                    result["public_enabled"] = bool(enabled) if enabled is not None else None
            if any(v is not None for v in result.values()):
                return result

        # Fallback to Registry: SharedAccess Parameters FirewallPolicy
        domain_raw = _run_ps("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile' -ErrorAction SilentlyContinue).EnableFirewall")
        private_raw = _run_ps("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile' -ErrorAction SilentlyContinue).EnableFirewall")
        public_raw = _run_ps("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile' -ErrorAction SilentlyContinue).EnableFirewall")

        def _to_b(v):
            return (int(v.strip()) == 1) if v and v.strip().isdigit() else None

        return {
            "domain_enabled": _to_b(domain_raw),
            "private_enabled": _to_b(private_raw),
            "public_enabled": _to_b(public_raw),
        }
    except Exception:  # noqa: BLE001
        return defaults


def _collect_defender() -> dict[str, bool | None]:
    """Collect Windows Defender status."""
    defaults: dict[str, bool | None] = {
        "antivirus_enabled": None,
        "real_time_protection": None,
    }
    try:
        raw = _run_ps(
            "Get-MpComputerStatus -ErrorAction SilentlyContinue "
            "| Select-Object AntivirusEnabled, RealTimeProtectionEnabled | ConvertTo-Json"
        )
        data = _parse_json(raw)
        if isinstance(data, dict):
            av = data.get("AntivirusEnabled")
            rtp = data.get("RealTimeProtectionEnabled")
            return {
                "antivirus_enabled": bool(av) if av is not None else None,
                "real_time_protection": bool(rtp) if rtp is not None else None,
            }

        # Fallback: check Windows Defender service (WinDefend)
        svc_state = _run_ps("(Get-Service WinDefend -ErrorAction SilentlyContinue).Status")
        if svc_state:
            is_running = "running" in svc_state.lower()
            return {"antivirus_enabled": is_running, "real_time_protection": is_running}

        return defaults
    except Exception:  # noqa: BLE001
        return defaults


def _collect_accounts() -> dict[str, bool | None]:
    """Collect local account security settings (Guest, built-in Administrator)."""
    defaults: dict[str, bool | None] = {
        "guest_enabled": None,
        "administrator_renamed": None,
    }
    try:
        # Guest account
        guest_raw = _run_ps(
            "Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue | Select-Object Enabled | ConvertTo-Json"
        )
        guest_data = _parse_json(guest_raw)
        guest_enabled: bool | None = None
        if isinstance(guest_data, dict):
            val = guest_data.get("Enabled")
            guest_enabled = bool(val) if val is not None else None

        # Built-in Administrator (SID ends in -500)
        admin_raw = _run_ps(
            "Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID -like '*-500' } "
            "| Select-Object Name | ConvertTo-Json"
        )
        admin_data = _parse_json(admin_raw)
        administrator_renamed: bool | None = None
        if isinstance(admin_data, dict):
            name = admin_data.get("Name", "")
            administrator_renamed = name.lower() != "administrator"
        elif isinstance(admin_data, list) and admin_data:
            name = admin_data[0].get("Name", "")
            administrator_renamed = name.lower() != "administrator"

        return {
            "guest_enabled": guest_enabled,
            "administrator_renamed": administrator_renamed,
        }
    except Exception:  # noqa: BLE001
        return defaults


def _collect_password_policy() -> dict[str, int | bool | None]:
    """Parse password policy from 'net accounts' output."""
    defaults: dict[str, int | bool | None] = {
        "min_length": None,
        "max_age_days": None,
        "complexity_enabled": None,
        "lockout_threshold": None,
    }
    try:
        raw = _run_ps("net accounts")
        if raw is None:
            return defaults

        result: dict[str, int | bool | None] = dict(defaults)
        for line in raw.splitlines():
            lower = line.lower()
            if "minimum password length" in lower:
                parts = line.split(":")
                if len(parts) >= 2:
                    val = parts[-1].strip()
                    try:
                        result["min_length"] = int(val)
                    except ValueError:
                        result["min_length"] = None
            elif "maximum password age" in lower:
                parts = line.split(":")
                if len(parts) >= 2:
                    val = parts[-1].strip().split()[0]
                    try:
                        result["max_age_days"] = int(val)
                    except ValueError:
                        result["max_age_days"] = None
            elif "lockout threshold" in lower:
                parts = line.split(":")
                if len(parts) >= 2:
                    val = parts[-1].strip().split()[0]
                    try:
                        result["lockout_threshold"] = int(val)
                    except ValueError:
                        result["lockout_threshold"] = None

        return result
    except Exception:  # noqa: BLE001
        return defaults


def _collect_audit_policy() -> dict[str, str | None]:
    """Parse audit policy from auditpol CSV output."""
    defaults: dict[str, str | None] = {
        "logon_events": None,
        "account_logon": None,
    }
    try:
        raw = _run_ps('auditpol /get /subcategory:"Logon","Account Logon" /r')
        if raw is None:
            return defaults

        result: dict[str, str | None] = dict(defaults)
        lines = raw.splitlines()
        for line in lines[1:]:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 5:
                continue
            subcategory = parts[2].lower()
            setting = parts[4] if len(parts) > 4 else None
            if "logon" in subcategory and "account logon" not in subcategory:
                result["logon_events"] = setting
            elif "account logon" in subcategory:
                result["account_logon"] = setting

        return result
    except Exception:  # noqa: BLE001
        return defaults


def _collect_smb() -> dict[str, bool | None]:
    """Collect SMB server configuration (SMBv1 status)."""
    defaults: dict[str, bool | None] = {"smb1_enabled": None}
    try:
        raw = _run_ps(
            "Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object EnableSMB1Protocol | ConvertTo-Json"
        )
        data = _parse_json(raw)
        if isinstance(data, dict) and data.get("EnableSMB1Protocol") is not None:
            return {"smb1_enabled": bool(data.get("EnableSMB1Protocol"))}

        # Fallback to Registry: LanmanServer Parameters SMB1
        smb1_raw = _run_ps("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name SMB1 -ErrorAction SilentlyContinue).SMB1")
        if smb1_raw is not None and smb1_raw.strip().isdigit():
            return {"smb1_enabled": int(smb1_raw.strip()) == 1}

        # On modern Windows (Windows 10/11), SMB1 is disabled by default if parameter is absent
        return {"smb1_enabled": False}
    except Exception:  # noqa: BLE001
        return defaults


def _collect_rdp() -> dict[str, bool | None]:
    """Collect RDP enabled/disabled state and NLA requirement via registry."""
    defaults: dict[str, bool | None] = {
        "enabled": None,
        "nla_required": None,
    }
    try:
        # fDenyTSConnections == 0 means RDP is ENABLED
        rdp_raw = _run_ps(
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' "
            "-Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections"
        )
        rdp_enabled: bool | None = None
        if rdp_raw is not None:
            try:
                rdp_enabled = int(rdp_raw.strip()) == 0
            except ValueError:
                rdp_enabled = None

        # UserAuthentication == 1 means NLA is required
        nla_raw = _run_ps(
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
            "\\WinStations\\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication"
        )
        nla_required: bool | None = None
        if nla_raw is not None:
            try:
                nla_required = int(nla_raw.strip()) == 1
            except ValueError:
                nla_required = None

        return {"enabled": rdp_enabled, "nla_required": nla_required}
    except Exception:  # noqa: BLE001
        return defaults


def _collect_bitlocker() -> dict[str, bool | None]:
    """Collect BitLocker protection status for the OS drive (C:)."""
    defaults: dict[str, bool | None] = {"os_drive_protected": None}
    try:
        raw = _run_ps(
            "Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue "
            "| Select-Object ProtectionStatus | ConvertTo-Json"
        )
        data = _parse_json(raw)
        if not isinstance(data, dict):
            return defaults
        val = data.get("ProtectionStatus")
        protected: bool | None = None
        if val is not None:
            try:
                protected = int(val) == 1
            except (ValueError, TypeError):
                protected = None
        return {"os_drive_protected": protected}
    except Exception:  # noqa: BLE001
        return defaults


def _collect_services() -> dict[str, bool | None]:
    """Collect optional Windows feature states (Telnet client)."""
    defaults: dict[str, bool | None] = {"telnet_installed": None}
    try:
        raw = _run_ps(
            "Get-WindowsOptionalFeature -Online -FeatureName TelnetClient -ErrorAction SilentlyContinue "
            "| Select-Object State | ConvertTo-Json"
        )
        data = _parse_json(raw)
        if not isinstance(data, dict):
            return defaults
        state = str(data.get("State", "")).lower()
        if state in ("enabled", "disabled"):
            return {"telnet_installed": state == "enabled"}
        return defaults
    except Exception:  # noqa: BLE001
        return defaults


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def collect() -> Evidence:
    """Perform live evidence collection on the local Windows system."""
    current_platform = platform.system()
    if current_platform != "Windows":
        return {
            "_source": "windows_live:collection_error",
            "_error": f"Windows collector not available on {current_platform}",
        }

    try:
        hostname = socket.gethostname()
        source = f"windows_live:{hostname}"

        evidence: Evidence = {
            "_source": source,
            "os": _collect_os(),
            "firewall": _collect_firewall(),
            "defender": _collect_defender(),
            "accounts": _collect_accounts(),
            "password_policy": _collect_password_policy(),
            "audit_policy": _collect_audit_policy(),
            "smb": _collect_smb(),
            "rdp": _collect_rdp(),
            "bitlocker": _collect_bitlocker(),
            "services": _collect_services(),
        }
        return evidence

    except Exception as exc:  # noqa: BLE001
        return {
            "_source": "windows_live:collection_error",
            "_error": str(exc),
        }


def collect_from_file(path: str | Path, source_label: str | None = None) -> Evidence:
    """Load pre-collected evidence from a JSON file (offline / air-gapped mode)."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    try:
        with file_path.open("r", encoding="utf-8-sig") as fh:
            data: Any = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError(f"Failed to load evidence file '{file_path}': {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(
            f"Evidence file must contain a JSON object (dict), got {type(data).__name__}"
        )

    label = source_label or f"windows_fixture:{file_path.stem}"
    data["_source"] = label
    return data


def collect_from_dict(data: dict[str, Any], source_label: str = "windows_fixture:inline") -> Evidence:
    """Accept a pre-built evidence dict (e.g. for unit testing)."""
    result: Evidence = dict(data)
    result["_source"] = source_label
    return result
