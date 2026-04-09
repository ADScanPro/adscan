"""ADCS CLI orchestration helpers."""

from __future__ import annotations

from typing import Any
from datetime import UTC, datetime

from adscan_internal import (
    print_error,
    print_exception,
    print_instruction,
    print_info_debug,
    print_info_verbose,
    print_operation_header,
    print_success,
    telemetry,
)
from adscan_internal.integrations.netexec.parsers import parse_adcs_detection_output
from adscan_internal.cli.common import build_lab_event_fields
from adscan_internal.rich_output import mark_sensitive, print_panel
from adscan_internal.services import CredentialStoreService
from adscan_internal.workspaces import domain_relpath


def _set_adcs_detection_state(
    shell: Any,
    *,
    domain: str,
    detected: bool | None,
    via: str,
    reason: str,
    source_context: str | None = None,
) -> None:
    """Persist ADCS detection state with basic traceability fields."""
    domain_data = shell.domains_data.get(domain, {}) if hasattr(shell, "domains_data") else {}
    if not isinstance(domain_data, dict):
        domain_data = {}
    if detected is None:
        domain_data.pop("adcs_detected", None)
    else:
        domain_data["adcs_detected"] = detected
    domain_data["adcs_detected_via"] = via
    domain_data["adcs_detected_reason"] = reason
    domain_data["adcs_detected_checked_at"] = datetime.now(UTC).isoformat()
    if source_context:
        domain_data["adcs_detected_source_context"] = source_context
    shell.domains_data[domain] = domain_data


def _is_inconclusive_adcs_reason(reason: str) -> bool:
    """Return True when the detection outcome should not be cached as negative."""
    normalized = str(reason or "").strip().lower()
    if normalized == "missing_credentials":
        return True
    if normalized.startswith("auth_"):
        return True
    return False


def _resolve_adcs_credentials(
    shell: Any,
    target_domain: str,
) -> tuple[str, str, str] | None:
    """Resolve credentials to use for ADCS detection.

    The resolution order is:
    1. Credentials configured for the target domain itself.
    2. Credentials configured for the shell's primary domain (``shell.domain``),
       when present.

    Args:
        shell: Shell object that owns ``domains_data`` and optional ``domain``.
        target_domain: Domain we are detecting ADCS on.

    Returns:
        Tuple of (username, password, auth_domain) or None if no credentials
        could be found.
    """

    # First try credentials for the target domain
    domain_data = shell.domains_data.get(target_domain, {}) or {}
    username = domain_data.get("username")
    password = domain_data.get("password")
    if username and password:
        return username, password, target_domain

    # Then fall back to the primary domain configured in the shell (if any)
    primary_domain = getattr(shell, "domain", None)
    if primary_domain:
        primary_data = shell.domains_data.get(primary_domain, {}) or {}
        primary_username = primary_data.get("username")
        primary_password = primary_data.get("password")
        if primary_username and primary_password:
            return primary_username, primary_password, primary_domain

    return None


def detect_adcs(
    shell: Any,
    *,
    domain: str,
    silent: bool = False,
    emit_telemetry: bool = True,
    force: bool = False,
    source_context: str | None = None,
) -> bool:
    """Detect whether ADCS is implemented in the given domain.

    This preserves the existing behaviour from `adscan.py`:
    - caches `adcs_detected` unless `force=True`
    - stores `adcs` (enrollment server) and `ca` (CA name) in `domains_data`
    - optionally emits telemetry events
    """
    try:
        domain_data = shell.domains_data.get(domain, {})
        if not domain_data:
            if not silent:
                marked_domain = mark_sensitive(domain, "domain")
                print_error(
                    f"Domain {marked_domain} is not initialized. Cannot detect ADCS."
                )
            return False

        if not force and "adcs_detected" in domain_data:
            return bool(domain_data["adcs_detected"])

        domain_data.setdefault("adcs", None)
        domain_data.setdefault("ca", None)

        pdc_hostname = domain_data["pdc_hostname"]
        pdc_fqdn = f"{pdc_hostname}.{domain}"

        creds = CredentialStoreService.resolve_auth_credentials(
            shell.domains_data,
            target_domain=domain,
            primary_domain=getattr(shell, "domain", None),
        )
        if not creds:
            if not silent:
                marked_domain = mark_sensitive(domain, "domain")
                print_error(
                    "No credentials found for ADCS detection. "
                    f"Configure credentials for domain {marked_domain} or for the primary domain."
                )
            missing_credentials_reason = "missing_credentials"
            _set_adcs_detection_state(
                shell,
                domain=domain,
                detected=None
                if _is_inconclusive_adcs_reason(missing_credentials_reason)
                else False,
                via="ldap",
                reason=missing_credentials_reason,
                source_context=source_context,
            )
            return False

        username, password, auth_domain = creds
        use_kerberos = False
        if hasattr(shell, "do_sync_clock_with_pdc"):
            use_kerberos = bool(
                shell.do_sync_clock_with_pdc(domain, verbose=not silent)
            )
        if use_kerberos and not silent:
            marked_username = mark_sensitive(username, "user")
            marked_domain = mark_sensitive(auth_domain, "domain")
            print_info_verbose(
                f"Using Kerberos authentication for ADCS detection as "
                f"{marked_username}@{marked_domain}"
            )

        auth = shell.build_auth_nxc(
            username,
            password,
            auth_domain,
            kerberos=use_kerberos,
        )

        marked_pdc_fqdn = mark_sensitive(pdc_fqdn, "hostname")
        log_path = domain_relpath(shell.domains_dir, domain, shell.ldap_dir, "adcs.log")
        command = (
            f"{shell.netexec_path} ldap {marked_pdc_fqdn} {auth} "
            f"--log {log_path} -M adcs"
        )

        if not silent:
            print_operation_header(
                "ADCS Detection",
                details={
                    "Domain": domain,
                    "PDC": pdc_fqdn,
                    "Username": username,
                    "Protocol": "LDAP",
                    "Auth Type": "Kerberos" if use_kerberos else "NTLM",
                    "Scan Target": "PKI Enrollment Server & Certificate Authority",
                },
                icon="🔐",
            )
            print_info_debug(f"Command: {command}")

        completed_process = shell._run_netexec(
            command,
            domain=domain,
            timeout=900,
            operation_kind="adcs_detection",
            service="ldap",
        )
        if completed_process is None:
            if emit_telemetry:
                _capture_adcs_not_discovered(shell, domain_data, error=True)
            _set_adcs_detection_state(
                shell,
                domain=domain,
                detected=False,
                via="ldap",
                reason="runner_returned_none",
                source_context=source_context,
            )
            return False

        output = completed_process.stdout or ""
        errors = completed_process.stderr or ""

        if completed_process.returncode != 0:
            if not silent:
                marked_domain = mark_sensitive(domain, "domain")
                print_error(f"Error searching for ADCS in domain {marked_domain}")
                if errors:
                    print_error(errors.strip())
            if emit_telemetry:
                _capture_adcs_not_discovered(shell, domain_data, error=True)
            _set_adcs_detection_state(
                shell,
                domain=domain,
                detected=False,
                via="ldap",
                reason=f"netexec_nonzero:{completed_process.returncode}",
                source_context=source_context,
            )
            return False

        enrollment_server, ca_name = parse_adcs_detection_output(output)
        adcs_found = bool(enrollment_server or ca_name)

        if enrollment_server:
            domain_data["adcs"] = enrollment_server
            if not silent:
                print_success(f"ADCS Enrollment Server found: {enrollment_server}")
        if ca_name:
            domain_data["ca"] = ca_name
            if not silent:
                print_success(f"Certificate Authority found: {ca_name}")

        if adcs_found:
            if not silent:
                marked_domain = mark_sensitive(domain, "domain")
                print_info_verbose(f"ADCS is implemented in the domain {marked_domain}")
            if emit_telemetry:
                _capture_adcs_discovered(shell, domain_data, enrollment_server, ca_name)
        else:
            if not silent:
                marked_domain = mark_sensitive(domain, "domain")
                print_error(f"ADCS not found in domain {marked_domain}")
            if emit_telemetry:
                _capture_adcs_not_discovered(shell, domain_data, error=False)

        _set_adcs_detection_state(
            shell,
            domain=domain,
            detected=adcs_found,
            via="ldap",
            reason="enrollment_server_or_ca_found" if adcs_found else "ldap_detection_empty",
            source_context=source_context,
        )
        domain_data = shell.domains_data.get(domain, {}) if hasattr(shell, "domains_data") else {}
        if isinstance(domain_data, dict):
            if enrollment_server:
                domain_data["adcs"] = enrollment_server
            if ca_name:
                domain_data["ca"] = ca_name
            shell.domains_data[domain] = domain_data
        return adcs_found
    except Exception as exc:
        if emit_telemetry:
            telemetry.capture_exception(exc)
        if not silent:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(
                f"Error executing ADCS detection for domain {marked_domain}: {exc}"
            )
        if domain in shell.domains_data:
            _set_adcs_detection_state(
                shell,
                domain=domain,
                detected=False,
                via="ldap",
                reason=f"exception:{type(exc).__name__}",
                source_context=source_context,
            )
        return False


def detect_adcs_from_bloodhound(
    shell: Any,
    *,
    domain: str,
    silent: bool = False,
) -> tuple[str | None, str | None]:
    """Try to resolve ADCS metadata (host + CA) from BloodHound CE."""
    try:
        if not hasattr(shell, "_get_bloodhound_service"):
            if not silent:
                print_info_debug("[adcs-bh] BloodHound service unavailable.")
            return None, None

        service = shell._get_bloodhound_service()  # type: ignore[attr-defined]
        client = getattr(service, "client", None)
        execute_rows = getattr(client, "execute_query_rows", None)
        execute_graph = getattr(client, "execute_query_with_relationships", None)
        if not callable(execute_rows) and not callable(execute_graph):
            if not silent:
                print_info_debug(
                    "[adcs-bh] BloodHound client has no rows/graph query methods."
                )
            return None, None

        domain_clean = str(domain or "").strip().lower()
        query = f"""
        MATCH p=()-[:HostsCAService]->(ca:EnterpriseCA)
        WHERE toLower(ca.name) ENDS WITH "@{domain_clean}"
        RETURN p
        """
        if not silent:
            print_info_debug(f"[adcs-bh] Using query: {query.strip()}")
        adcs_host: str | None = None
        ca_name: str | None = None

        def _normalize_ca(value: str | None) -> str | None:
            if not value:
                return None
            cleaned = str(value).strip()
            if "@" in cleaned:
                cleaned = cleaned.split("@", 1)[0].strip()
            return cleaned or None

        def _extract_from_graph(graph: dict[str, Any]) -> tuple[str | None, str | None]:
            try:
                nodes_map = graph.get("nodes")
                edges = graph.get("edges")
                if not isinstance(nodes_map, dict) or not isinstance(edges, list):
                    return None, None
                if not silent:
                    print_info_debug(
                        "[adcs-bh] HostsCAService graph: "
                        f"nodes={len(nodes_map)}, edges={len(edges)}"
                    )
                    if edges:
                        sample_edge = edges[0]
                        if isinstance(sample_edge, dict):
                            print_info_debug(
                                "[adcs-bh] HostsCAService edge sample keys: "
                                f"{list(sample_edge.keys())}"
                            )
                    if nodes_map:
                        sample_node = next(iter(nodes_map.values()), None)
                        if isinstance(sample_node, dict):
                            print_info_debug(
                                "[adcs-bh] HostsCAService node sample keys: "
                                f"{list(sample_node.keys())}"
                            )
                for edge in edges:
                    if not isinstance(edge, dict):
                        continue
                    edge_label = str(edge.get("label") or "").strip()
                    edge_kind = str(edge.get("kind") or "").strip()
                    if not silent:
                        print_info_debug(
                            "[adcs-bh] HostsCAService edge: "
                            f"label={edge_label!r} kind={edge_kind!r} "
                            f"source={edge.get('source')!r} target={edge.get('target')!r} "
                            f"from={edge.get('from')!r} to={edge.get('to')!r}"
                        )
                    if (edge_label or edge_kind) != "HostsCAService":
                        continue
                    source_id = str(edge.get("source") or edge.get("from") or "")
                    target_id = str(edge.get("target") or edge.get("to") or "")

                    def _resolve_node(node_id: str) -> dict[str, Any] | None:
                        if not node_id:
                            return None
                        node = nodes_map.get(node_id)
                        if isinstance(node, dict):
                            return node
                        try:
                            node_int = int(node_id)
                        except ValueError:
                            node_int = None
                        if node_int is not None:
                            node = nodes_map.get(node_int)
                            if isinstance(node, dict):
                                return node
                        node = nodes_map.get(f"name:{node_id}")
                        if isinstance(node, dict):
                            return node
                        return None

                    source_node = _resolve_node(source_id)
                    target_node = _resolve_node(target_id)
                    if not silent:
                        print_info_debug(
                            "[adcs-bh] HostsCAService nodes: "
                            f"source_id={source_id!r} target_id={target_id!r} "
                            f"source_kind={str(source_node.get('kind') or '') if isinstance(source_node, dict) else None!r} "
                            f"target_kind={str(target_node.get('kind') or '') if isinstance(target_node, dict) else None!r} "
                            f"source_label={str(source_node.get('label') or '') if isinstance(source_node, dict) else None!r} "
                            f"target_label={str(target_node.get('label') or '') if isinstance(target_node, dict) else None!r}"
                        )
                    adcs = None
                    ca = None
                    if isinstance(source_node, dict):
                        if str(source_node.get("kind") or "").lower() == "computer":
                            adcs = str(source_node.get("label") or "").strip() or None
                        if (
                            str(source_node.get("kind") or "").lower()
                            == "enterpriseca"
                        ):
                            ca = _normalize_ca(
                                str(
                                    source_node.get("caname")
                                    or source_node.get("caName")
                                    or source_node.get("label")
                                    or ""
                                ).strip()
                            )
                    if isinstance(target_node, dict):
                        if (
                            str(target_node.get("kind") or "").lower()
                            == "enterpriseca"
                        ):
                            ca = _normalize_ca(
                                str(
                                    target_node.get("caname")
                                    or target_node.get("caName")
                                    or target_node.get("label")
                                    or ""
                                ).strip()
                            )
                        if str(target_node.get("kind") or "").lower() == "computer":
                            adcs = str(target_node.get("label") or "").strip() or adcs
                    if adcs or ca:
                        return adcs, ca
                return None, None
            except Exception as exc:  # noqa: BLE001
                if not silent:
                    print_info_debug(
                        f"[adcs-bh] HostsCAService graph parse error: {exc}"
                    )
                    print_exception(exception=exc)
                return None, None

        # Try relationship query first (best for path outputs).
        if callable(execute_graph):
            graph = execute_graph(query)
            if isinstance(graph, dict):
                if not silent:
                    print_info_debug(
                        "[adcs-bh] HostsCAService graph keys: "
                        f"{list(graph.keys())}"
                    )
                adcs_host, ca_name = _extract_from_graph(graph)
                if not silent and not (adcs_host or ca_name):
                    print_info_debug("[adcs-bh] HostsCAService graph empty.")

        rows: list[Any] = []

        # Fallback to rows query.
        if not adcs_host and not ca_name and callable(execute_rows):
            rows = execute_rows(query)
            if not isinstance(rows, list) or not rows:
                if not silent:
                    marked_domain = mark_sensitive(domain, "domain")
                    print_info_debug(
                        f"[adcs-bh] No HostsCAService rows for {marked_domain}."
                    )
                return None, None

            sample_row = rows[0]
            if not silent:
                print_info_debug(
                    "[adcs-bh] HostsCAService row sample: "
                    f"type={type(sample_row).__name__}, keys={list(sample_row.keys()) if isinstance(sample_row, dict) else 'N/A'}"
                )

        def _extract_node_props(node: object) -> dict[str, Any] | None:
            if isinstance(node, dict):
                props = node.get("properties")
                if isinstance(props, dict) and props:
                    return props
                return node
            return None

        def _extract_nodes_from_path(path_obj: object) -> list[dict[str, Any]]:
            if isinstance(path_obj, dict):
                nodes = path_obj.get("nodes")
                if isinstance(nodes, list):
                    return [
                        props
                        for props in (
                            _extract_node_props(node) for node in nodes
                        )
                        if isinstance(props, dict)
                    ]
                segments = path_obj.get("segments")
                if isinstance(segments, list):
                    collected: list[dict[str, Any]] = []
                    for segment in segments:
                        if not isinstance(segment, dict):
                            continue
                        for key in ("start", "end"):
                            props = _extract_node_props(segment.get(key))
                            if isinstance(props, dict):
                                collected.append(props)
                    return collected
            if isinstance(path_obj, list):
                return [
                    props
                    for props in (_extract_node_props(node) for node in path_obj)
                    if isinstance(props, dict)
                ]
            return []

        if not adcs_host and not ca_name:
            if not rows:
                return None, None
            for row in rows:
                path_obj = row.get("p") if isinstance(row, dict) else row
                nodes = _extract_nodes_from_path(path_obj)
                if not nodes:
                    continue
                for node in nodes:
                    labels = node.get("labels")
                    label_list = (
                        [str(label).lower() for label in labels]
                        if isinstance(labels, list)
                        else []
                    )
                    if "enterpriseca" in label_list or node.get("caname") or node.get(
                        "caName"
                    ):
                        ca_name = _normalize_ca(
                            str(
                                node.get("caname")
                                or node.get("caName")
                                or node.get("name")
                                or ""
                            ).strip()
                        ) or ca_name
                    if "computer" in label_list or node.get("dnshostname"):
                        adcs_host = (
                            str(
                                node.get("dnshostname")
                                or node.get("dnsHostname")
                                or node.get("name")
                                or ""
                            ).strip()
                            or adcs_host
                        )

                if adcs_host or ca_name:
                    break

        if not silent:
            marked_domain = mark_sensitive(domain, "domain")
            print_info_debug(
                f"[adcs-bh] Resolved for {marked_domain}: "
                f"adcs={adcs_host!r}, ca={ca_name!r}"
            )

        return adcs_host, ca_name
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        if not silent:
            print_exception(exception=exc)
        return None, None


def ensure_adcs_metadata(
    shell: Any,
    *,
    domain: str,
    silent: bool = False,
    emit_telemetry: bool = True,
    force: bool = False,
    allow_ldap_fallback: bool = True,
    source_context: str | None = None,
) -> bool:
    """Ensure ADCS metadata (adcs + ca) is populated using BH → LDAP fallback."""
    domain_data = shell.domains_data.get(domain, {}) if hasattr(shell, "domains_data") else {}
    if not domain_data:
        if not silent:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(
                f"Domain {marked_domain} is not initialized. Cannot resolve ADCS."
            )
        return False

    if not force and domain_data.get("adcs") and domain_data.get("ca"):
        if not silent:
            marked_domain = mark_sensitive(domain, "domain")
            print_info_debug(f"[adcs] Using cached ADCS metadata for {marked_domain}.")
        return True
    if not force and domain_data.get("adcs_detected") is False:
        if not silent:
            marked_domain = mark_sensitive(domain, "domain")
            cached_reason = str(domain_data.get("adcs_detected_reason") or "unknown").strip() or "unknown"
            cached_checked_at = str(domain_data.get("adcs_detected_checked_at") or "").strip() or "unknown"
            cached_via = str(domain_data.get("adcs_detected_via") or "unknown").strip() or "unknown"
            cached_source_context = (
                str(domain_data.get("adcs_detected_source_context") or "").strip() or "unknown"
            )
            print_info_debug(
                f"[adcs] Cached negative ADCS detection for {marked_domain}; skipping lookup. "
                f"via={cached_via!r} reason={cached_reason!r} "
                f"source_context={cached_source_context!r} checked_at={cached_checked_at!r}"
            )
        return False

    adcs_host, ca_name = detect_adcs_from_bloodhound(
        shell, domain=domain, silent=silent
    )
    if adcs_host:
        domain_data["adcs"] = adcs_host
    if ca_name:
        domain_data["ca"] = ca_name

    if domain_data.get("adcs") and domain_data.get("ca"):
        _set_adcs_detection_state(
            shell,
            domain=domain,
            detected=True,
            via="bloodhound",
            reason="bloodhound_metadata_resolved",
            source_context=source_context,
        )
        domain_data = shell.domains_data.get(domain, {}) if hasattr(shell, "domains_data") else {}
        if not silent:
            marked_domain = mark_sensitive(domain, "domain")
            print_success(
                f"ADCS metadata resolved from BloodHound for {marked_domain}."
            )
        if emit_telemetry:
            _capture_adcs_discovered(
                shell,
                domain_data,
                domain_data.get("adcs"),
                domain_data.get("ca"),
            )
        return True

    if allow_ldap_fallback:
        if not silent:
            marked_domain = mark_sensitive(domain, "domain")
            print_info_debug(
                f"[adcs] Falling back to LDAP detection for {marked_domain}."
            )
        found = detect_adcs(
            shell,
            domain=domain,
            silent=silent,
            emit_telemetry=emit_telemetry,
            force=True,
            source_context=source_context,
        )
        if found:
            domain_data = shell.domains_data.get(domain, {}) if hasattr(shell, "domains_data") else {}
            if isinstance(domain_data, dict):
                domain_data["adcs_detected_via"] = "ldap"
                if source_context:
                    domain_data["adcs_detected_source_context"] = source_context
                shell.domains_data[domain] = domain_data
            if not silent:
                marked_domain = mark_sensitive(domain, "domain")
                print_success(
                    f"ADCS metadata resolved via LDAP for {marked_domain}."
                )
        return found

    _set_adcs_detection_state(
        shell,
        domain=domain,
        detected=False,
        via="bloodhound",
        reason="bloodhound_and_ldap_not_found" if allow_ldap_fallback else "bloodhound_not_found",
        source_context=source_context,
    )
    return False

def _capture_adcs_discovered(
    shell: Any,
    domain_data: dict,
    enrollment_server: str | None,
    ca_name: str | None,
) -> None:
    try:
        properties: dict[str, object] = {
            "scan_mode": getattr(shell, "scan_mode", None),
            "auth_type": domain_data.get("auth", "unknown"),
            "workspace_type": shell.type,
            "auto_mode": shell.auto,
            "has_enrollment_server": enrollment_server is not None,
            "has_ca": ca_name is not None,
        }
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture("adcs_discovered", properties)
    except Exception as telemetry_error:
        telemetry.capture_exception(telemetry_error)


def _capture_adcs_not_discovered(shell: Any, domain_data: dict, *, error: bool) -> None:
    try:
        properties: dict[str, object] = {
            "scan_mode": getattr(shell, "scan_mode", None),
            "auth_type": domain_data.get("auth", "unknown"),
            "workspace_type": shell.type,
            "auto_mode": shell.auto,
            "error": error,
        }
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture("adcs_not_discovered", properties)
    except Exception as telemetry_error:
        telemetry.capture_exception(telemetry_error)


def ask_for_search_adcs(shell: Any, domain: str) -> None:
    """Prompt user to search for Active Directory Certificate Services."""
    do_search_adcs(shell, domain)


def do_search_adcs(shell: Any, domain: str) -> None:
    """
    Searches for ADCS in the domain.

    Usage: search_adcs <domain>

    Performs a search for ADCS in the domain.

    Requires that the domain's PDC is defined in the domains list and that a username
    and password have been specified for authentication.

    If an error occurs while executing the command, an error message is displayed and
    it continues with the next domain.
    """
    detect_adcs(
        shell,
        domain=domain,
        silent=False,
        emit_telemetry=True,
        force=True,
        source_context="manual_search_adcs",
    )


def do_show_adcs_cache(shell: Any, domain: str) -> None:
    """Show the cached ADCS detection state for a domain.

    Usage:
        show_adcs_cache [domain]

    When ``domain`` is omitted, the current shell domain is used.
    """
    requested_domain = str(domain or "").strip()
    target_domain = requested_domain or str(getattr(shell, "domain", "") or "").strip()
    if not target_domain:
        print_instruction("Usage: show_adcs_cache <domain>")
        return

    domain_data = shell.domains_data.get(target_domain, {}) if hasattr(shell, "domains_data") else {}
    if not isinstance(domain_data, dict) or not domain_data:
        marked_domain = mark_sensitive(target_domain, "domain")
        print_error(f"Domain {marked_domain} is not initialized.")
        return

    marked_domain = mark_sensitive(target_domain, "domain")
    panel_lines = [
        f"[bold]Domain:[/bold] {marked_domain}",
        f"[bold]ADCS Host:[/bold] {mark_sensitive(str(domain_data.get('adcs') or 'unknown'), 'hostname')}",
        f"[bold]CA:[/bold] {mark_sensitive(str(domain_data.get('ca') or 'unknown'), 'text')}",
        f"[bold]Detected:[/bold] {domain_data.get('adcs_detected')!r}",
        f"[bold]Via:[/bold] {str(domain_data.get('adcs_detected_via') or 'unknown')}",
        f"[bold]Reason:[/bold] {str(domain_data.get('adcs_detected_reason') or 'unknown')}",
        (
            "[bold]Source Context:[/bold] "
            f"{str(domain_data.get('adcs_detected_source_context') or 'unknown')}"
        ),
        (
            "[bold]Checked At:[/bold] "
            f"{str(domain_data.get('adcs_detected_checked_at') or 'unknown')}"
        ),
    ]
    print_panel(
        "\n".join(panel_lines),
        title="[bold]ADCS Cache[/bold]",
        border_style="cyan",
        padding=(1, 2),
    )


def ask_for_adcs_esc(
    shell: Any,
    *,
    domain: str,
    esc: str,
    username: str,
    password: str,
    template: str | None = None,
) -> None:
    """Prompt for exploiting a specific ADCS ESC{X} vulnerability and dispatch."""
    from rich.prompt import Confirm

    marked_username = mark_sensitive(username, "user")
    if template:
        respuesta = Confirm.ask(
            f"Do you want to exploit vulnerability ESC{esc} as user {marked_username} for template {template}?"
        )
    else:
        respuesta = Confirm.ask(
            f"Do you want to exploit vulnerability ESC{esc} for user {marked_username}?"
        )

    if not respuesta:
        return

    method_name = f"adcs_esc{esc}"
    try:
        method = getattr(shell, method_name)
        if template:
            method(domain, username, password, template)
        else:
            method(domain, username, password)
    except AttributeError as exc:
        telemetry.capture_exception(exc)
        print_error(f"Function to exploit ESC{esc} not implemented")
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error executing ESC.")
        print_exception(show_locals=False, exception=exc)
