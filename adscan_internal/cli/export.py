"""Basic session export to TXT and JSON.

Exports session findings (credentials, hosts, vulnerabilities, attack paths)
to TXT and JSON formats for offline use and external reporting.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any

from adscan_internal import print_error, print_info, print_success


def handle_export(shell, args: str) -> None:
    """Export current session data to TXT/JSON.

    Usage:
        export              - Export all to JSON
        export txt          - Export to TXT (human-readable)
        export json         - Export to JSON
        export --output FILE - Export to specific file
    """
    fmt = "json"
    output_file = None

    parts = args.strip().split() if args else []
    i = 0
    while i < len(parts):
        part = parts[i]
        if part in ("txt", "json"):
            fmt = part
        elif part == "--output" and i + 1 < len(parts):
            i += 1
            output_file = parts[i]
        i += 1

    data = _collect_session_data(shell)

    if not data.get("domains"):
        print_info("No session data to export. Run some scans first.")
        return

    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        workspace_dir = getattr(shell, "workspace_dir", ".")
        output_file = os.path.join(
            workspace_dir, f"adscan_export_{timestamp}.{fmt}"
        )

    try:
        if fmt == "json":
            _export_json(data, output_file)
        else:
            _export_txt(data, output_file)
        print_success(f"Exported to: {output_file}")
    except OSError as exc:
        print_error(f"Failed to write export: {exc}")


def _collect_session_data(shell) -> dict[str, Any]:
    """Collect all exportable data from the current session."""
    data: dict[str, Any] = {
        "export_timestamp": datetime.now().isoformat(),
        "domains": {},
        "credentials": {},
    }

    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return data

    for domain, ddata in domains_data.items():
        if not isinstance(ddata, dict):
            continue

        domain_str = str(domain)
        domain_export: dict[str, Any] = {}

        # Basic domain info
        for key in ("dc", "pdc", "dns_ip", "domain_sid"):
            val = ddata.get(key)
            if val is not None:
                domain_export[key] = str(val)

        # Credentials
        creds = ddata.get("credentials")
        if isinstance(creds, dict) and creds:
            data["credentials"][domain_str] = {
                str(u): str(c) for u, c in creds.items()
            }

        # Vulnerabilities
        vulns = ddata.get("vulnerabilities")
        if isinstance(vulns, dict) and vulns:
            domain_export["vulnerabilities"] = {}
            for vname, vdata in vulns.items():
                if isinstance(vdata, dict):
                    domain_export["vulnerabilities"][str(vname)] = {
                        str(k): str(v) for k, v in vdata.items()
                        if k != "_evidence"
                    }
                elif vdata is True:
                    domain_export["vulnerabilities"][str(vname)] = True

        # Attack paths
        paths = ddata.get("attack_paths")
        if isinstance(paths, list) and paths:
            domain_export["attack_paths"] = []
            for p in paths:
                if isinstance(p, dict):
                    domain_export["attack_paths"].append({
                        "name": str(p.get("name") or p.get("title") or ""),
                        "status": str(p.get("status") or ""),
                        "steps": len(p.get("relations", [])),
                    })

        if domain_export:
            data["domains"][domain_str] = domain_export

    return data


def _export_json(data: dict[str, Any], path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def _export_txt(data: dict[str, Any], path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    lines: list[str] = [
        f"ADscan Export - {data['export_timestamp']}",
        "=" * 60,
        "",
    ]

    for domain, ddata in data.get("domains", {}).items():
        lines.append(f"Domain: {domain}")
        lines.append("-" * 40)
        for k, v in ddata.items():
            if k in ("vulnerabilities", "attack_paths"):
                continue
            lines.append(f"  {k}: {v}")
        lines.append("")

    if data.get("credentials"):
        lines.append("Credentials")
        lines.append("-" * 40)
        for domain, creds in data["credentials"].items():
            for user, cred in creds.items():
                lines.append(f"  {domain}\\{user}: {cred}")
        lines.append("")

    for domain, ddata in data.get("domains", {}).items():
        vulns = ddata.get("vulnerabilities", {})
        if vulns:
            lines.append(f"Vulnerabilities ({domain})")
            lines.append("-" * 40)
            for vname, vdata in vulns.items():
                if isinstance(vdata, dict):
                    lines.append(f"  {vname}")
                    for k, v in vdata.items():
                        lines.append(f"    {k}: {v}")
                else:
                    lines.append(f"  {vname}: {vdata}")
            lines.append("")

        paths = ddata.get("attack_paths", [])
        if paths:
            lines.append(f"Attack Paths ({domain})")
            lines.append("-" * 40)
            for p in paths:
                name = p.get("name", "unnamed")
                status = p.get("status", "")
                steps = p.get("steps", 0)
                lines.append(f"  {name} [{status}] ({steps} steps)")
            lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
