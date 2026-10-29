"""
Cisco IOS configuration collector / parser.

Parses a Cisco IOS-style 'show running-config' text file (or string)
into a normalised evidence dictionary that the rule evaluator understands.

IMPORTANT: This is a READ-ONLY, OFFLINE parser.
- It only reads text files — no live device connections.
- All fixture-based audits must be marked is_simulated=True.
- Do NOT extend this to run arbitrary commands on network devices.

Normalised evidence structure (for network.json rules):
  {
    "_source": "<path or label>",
    "services": {
        "ssh_enabled": bool,
        "telnet_enabled": bool
    },
    "logging": {
        "remote_host": str | None
    },
    "acls": {
        "mgmt_acl_present": bool
    },
    "banner": {
        "login_banner": str | None
    },
    "snmp": {
        "default_community": bool   # True if 'public' or 'private' are present
    }
  }
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)


def _parse_config(text: str) -> dict:
    """
    Parse Cisco IOS running-config text into a normalised evidence dict.

    Parsing is line-by-line regex matching — deterministic and read-only.
    """
    lines = [ln.rstrip() for ln in text.splitlines()]

    # ── SSH ─────────────────────────────────────────────────────────────
    ssh_enabled = any(
        re.search(r"^\s*ip\s+ssh\s+version\s+2", ln, re.IGNORECASE)
        for ln in lines
    )

    # ── Telnet on VTY lines ──────────────────────────────────────────────
    # Consider telnet enabled if any VTY line has 'transport input telnet'
    # or 'transport input all'
    telnet_enabled = any(
        re.search(r"^\s*transport\s+input\s+(telnet|all)\b", ln, re.IGNORECASE)
        for ln in lines
    )

    # ── Remote logging host ──────────────────────────────────────────────
    logging_match = None
    for ln in lines:
        m = re.match(r"^\s*logging\s+host\s+(\S+)", ln, re.IGNORECASE)
        if m:
            logging_match = m.group(1)
            break

    # ── Management ACL applied to VTY ───────────────────────────────────
    # Look for 'access-class <name> in' on a VTY line
    mgmt_acl_present = any(
        re.search(r"^\s*access-class\s+\S+\s+in\b", ln, re.IGNORECASE)
        for ln in lines
    )

    # ── Login banner ─────────────────────────────────────────────────────
    login_banner: str | None = None
    in_banner = False
    banner_lines: list[str] = []
    for ln in lines:
        if re.match(r"^\s*banner\s+login\s+\^C", ln, re.IGNORECASE):
            in_banner = True
            continue
        if in_banner:
            if "^C" in ln:
                in_banner = False
                break
            banner_lines.append(ln)
    if banner_lines:
        login_banner = "\n".join(banner_lines).strip()

    # ── Default SNMP community strings ───────────────────────────────────
    # True if 'public' or 'private' community strings are configured
    # and NOT removed via 'no snmp-server community public/private'
    active_communities: set[str] = set()
    for ln in lines:
        m = re.match(r"^\s*snmp-server\s+community\s+(\S+)", ln, re.IGNORECASE)
        if m:
            active_communities.add(m.group(1).lower())
        m_no = re.match(r"^\s*no\s+snmp-server\s+community\s+(\S+)", ln, re.IGNORECASE)
        if m_no:
            active_communities.discard(m_no.group(1).lower())

    default_community = bool(active_communities & {"public", "private"})

    return {
        "services": {
            "ssh_enabled": ssh_enabled,
            "telnet_enabled": telnet_enabled,
        },
        "logging": {
            "remote_host": logging_match,
        },
        "acls": {
            "mgmt_acl_present": mgmt_acl_present,
        },
        "banner": {
            "login_banner": login_banner,
        },
        "snmp": {
            "default_community": default_community,
        },
    }


def collect_from_file(config_path: str | Path, source_label: str | None = None) -> dict:
    """
    Load a Cisco IOS running-config from a text file and return
    normalised evidence. Raises FileNotFoundError if the file is missing.

    Args:
        config_path:  Path to the .txt config file.
        source_label: Optional label for the '_source' field.
                      Defaults to the file path string.

    Returns:
        Normalised evidence dict with a '_source' key.
    """
    config_path = Path(config_path)
    if not config_path.exists():
        raise FileNotFoundError(f"Cisco config file not found: {config_path}")

    text = config_path.read_text(encoding="utf-8")
    logger.info("Parsing Cisco config from %s (%d chars)", config_path, len(text))

    evidence = _parse_config(text)
    evidence["_source"] = source_label or f"cisco_fixture:{config_path}"
    return evidence


def collect_from_text(config_text: str, source_label: str = "cisco_fixture:inline") -> dict:
    """
    Parse Cisco IOS running-config from a raw string.
    Useful for testing without a file on disk.
    """
    evidence = _parse_config(config_text)
    evidence["_source"] = source_label
    return evidence
