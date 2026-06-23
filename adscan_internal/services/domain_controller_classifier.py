"""Domain controller role helpers.

Centralizes the distinction between writable domain controllers and read-only
domain controllers (RODCs) for both attack-path target classification and
post-exploitation UX decisions.

The canonical detection signals on a Computer node, in order of strength:

1. ``primaryGroupID``
   Active Directory schema imposes ``primaryGroupID == 516`` for writable DCs
   and ``primaryGroupID == 521`` for RODCs.  This is an attribute of the
   object itself, populated by the LDAP collector — it does not require
   enumerating group memberships externally (which RODCs may block).

2. ``serviceprincipalnames`` containing ``krbtgt/<host>``
   Only RODCs have a local krbtgt account; writable DCs share the single
   domain-wide krbtgt user.  Any SPN matching ``krbtgt/<anything>`` on a
   Computer is a definitive RODC fingerprint.

3. ``userAccountControl & 0x04000000`` (``UF_PARTIAL_SECRETS_ACCOUNT``)
   The dedicated UAC bit for RODC machine accounts.

4. Explicit ``msDS-isRODC`` / ``isRODC`` flags (BloodHound CE / native
   collector legacy).

Membership-based detection (RID 516 / 521 via memberships.json) is kept as
a downstream fallback in callers, but it is NOT used here because RODCs by
design restrict membership enumeration in many environments.

This module is the single source of truth for the question "is this target a
domain controller?".  Two public entry points answer the two distinct flavours
of that question:

- :func:`classify_computer_node_role` / :func:`node_is_rodc_computer` —
  graph-node-based classification of a single collected Computer object.
- :func:`is_dc_host` — alias-aware "is this *target host* a DC?" used by the
  attack-path runtime to drive service selection (ldap vs cifs).  It resolves
  the host to its Computer node when graph nodes are available and otherwise
  matches against the domain's canonical DC identifiers with the same
  alias-aware (IP ↔ short ↔ FQDN ↔ ``HOST$``) host matcher used everywhere
  else (``credential_store_service.hosts_match``) — never a naive string
  compare, which silently misclassifies a DC supplied as an FQDN.
"""

from __future__ import annotations

from typing import Any, Iterable, Literal


RID_DOMAIN_CONTROLLERS = 516
RID_READ_ONLY_DOMAIN_CONTROLLERS = 521
RODC_TARGET_PRIORITY_RANK = 25

# UAC bit reserved for RODC machine accounts (MS-ADTS 2.2.16.1).
UF_PARTIAL_SECRETS_ACCOUNT = 0x04000000


DCRole = Literal["writable_dc", "rodc"]


def _coerce_boolish(value: object) -> bool:
    """Return True when *value* clearly represents a boolean true."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return False


def _node_kind_matches_computer(node: dict[str, Any]) -> bool:
    """Return True when the node's ``kind`` field marks it as a Computer."""
    kind = node.get("kind") or ""
    kind_values = kind if isinstance(kind, list) else [kind]
    return any(str(value or "").strip() == "Computer" for value in kind_values)


def _node_properties(node: dict[str, Any]) -> dict[str, Any]:
    """Return the ``properties`` sub-dict of a node, defaulting to empty."""
    props = node.get("properties")
    return props if isinstance(props, dict) else {}


def _read_int_attr(props: dict[str, Any], *keys: str) -> int | None:
    """Return the first present property under *keys* as an int, else None."""
    for key in keys:
        if key not in props:
            continue
        raw = props[key]
        if raw is None:
            continue
        try:
            return int(raw)
        except (TypeError, ValueError):
            continue
    return None


def _hostname_stem(value: object) -> str:
    """Return the lowercase hostname stem (no ``$``, no domain suffix)."""
    token = str(value or "").strip()
    if not token:
        return ""
    if token.endswith("$"):
        token = token[:-1]
    if "." in token:
        token = token.split(".", 1)[0]
    if "@" in token:
        token = token.split("@", 1)[0]
    return token.strip().lower()


def _spn_targets_local_krbtgt(props: dict[str, Any]) -> bool:
    """Return True when any SPN on the node is ``krbtgt/<host-or-fqdn>``.

    Only RODCs publish such an SPN — writable DCs share the single
    domain-wide ``krbtgt`` user account.  Pattern is robust against
    case differences and FQDN/short variants.
    """
    spns = props.get("serviceprincipalnames")
    if not isinstance(spns, (list, tuple)):
        return False
    samaccount = _hostname_stem(props.get("samaccountname"))
    dns_host_stem = _hostname_stem(props.get("dnshostname"))
    name_stem = _hostname_stem(props.get("name"))
    own_stems = {stem for stem in (samaccount, dns_host_stem, name_stem) if stem}
    for raw in spns:
        token = str(raw or "").strip().lower()
        if not token.startswith("krbtgt/"):
            continue
        spn_stem = _hostname_stem(token.split("/", 1)[1])
        if not spn_stem:
            continue
        if not own_stems or spn_stem in own_stems:
            return True
    return False


def classify_computer_node_role(node: dict[str, Any]) -> DCRole | None:
    """Classify a Computer node as ``writable_dc``, ``rodc``, or unknown.

    Reads node properties (``primaryGroupID``, SPNs, ``userAccountControl``,
    explicit RODC flags) and returns the canonical role label, or ``None``
    when the available signals do not uniquely identify the role.

    The function never raises; missing fields simply lower confidence.
    """
    if not isinstance(node, dict):
        return None
    if not _node_kind_matches_computer(node):
        return None

    props = _node_properties(node)

    # 1. primaryGroupID — definitive per AD schema.
    primary_gid = _read_int_attr(props, "primarygroupid", "primaryGroupID", "primary_group_id")
    if primary_gid == RID_READ_ONLY_DOMAIN_CONTROLLERS:
        return "rodc"
    if primary_gid == RID_DOMAIN_CONTROLLERS:
        return "writable_dc"

    # 2. Local krbtgt SPN — definitive RODC.
    if _spn_targets_local_krbtgt(props):
        return "rodc"

    # 3. UAC bit — definitive RODC.
    uac = _read_int_attr(props, "useraccountcontrol", "userAccountControl")
    if uac is not None and (uac & UF_PARTIAL_SECRETS_ACCOUNT):
        return "rodc"

    # 4. Explicit BloodHound/collector RODC flags.
    for key in ("msDS-isRODC", "msds-isrodc", "isRODC", "isrodc"):
        if _coerce_boolish(node.get(key)) or _coerce_boolish(props.get(key)):
            return "rodc"

    return None


def node_is_rodc_computer(node: dict[str, Any]) -> bool:
    """Return True when an attack-graph node represents an RODC computer.

    Thin wrapper over :func:`classify_computer_node_role` for legacy callers
    that only need the boolean.
    """
    return classify_computer_node_role(node) == "rodc"


# ---------------------------------------------------------------------------
# Alias-aware "is this target a DC?" — single source of truth
# ---------------------------------------------------------------------------


def _node_identities(node: dict[str, Any]) -> list[str]:
    """Return the identity tokens of a Computer node usable for host matching.

    Pulls every name-like attribute the collector may have populated
    (``samaccountname``, ``dnshostname``, ``name``) plus the node ``name``
    field, so an alias-aware match can find the node from any of IP / short /
    FQDN / ``HOST$`` the caller supplies.
    """
    props = _node_properties(node)
    tokens: list[str] = []
    for source in (
        node.get("name"),
        props.get("name"),
        props.get("samaccountname"),
        props.get("samAccountName"),
        props.get("dnshostname"),
        props.get("dNSHostName"),
    ):
        text = str(source or "").strip()
        if text:
            tokens.append(text)
    return tokens


def expand_host_aliases(
    host: str,
    *,
    ip_hostname_inventory: dict[str, Any] | None,
) -> set[str]:
    """Return the alias-comparison keys for *host*, widened via the inventory.

    Bridges the IP ↔ hostname gap: when *host* is an IP that the workspace
    inventory maps to one or more hostnames (or vice versa), the returned key
    set includes the aliased identifiers so a DC supplied as an IP still
    matches a DC identifier stored as an FQDN, and conversely.

    Canonical alias expander reused by :func:`is_dc_host` and other call sites
    (e.g. the MSSQL S4U2self SPN-ownership gate) that must answer "does this
    host token refer to the same machine as that identifier?" over the
    workspace's resolved IP <-> hostname map. ``host_match_keys`` alone is
    deliberately string-only (IPs kept verbatim); this helper layers the
    DNS/inventory bridge on top.
    """
    from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
        host_match_keys,
    )

    keys: set[str] = set(host_match_keys(host))
    if not keys or not isinstance(ip_hostname_inventory, dict):
        return keys

    raw = str(host or "").strip().rstrip(".").rstrip("$").lower()
    # host is an IP -> add its mapped hostnames' keys.
    for ip, hostnames in ip_hostname_inventory.items():
        ip_norm = str(ip or "").strip().lower()
        host_list = hostnames if isinstance(hostnames, (list, tuple, set)) else [hostnames]
        host_keys = {h for entry in host_list for h in host_match_keys(str(entry or ""))}
        if ip_norm and ip_norm == raw:
            keys |= host_keys
        elif keys & host_keys:
            # host is a hostname mapped to this IP -> add the IP key too.
            keys |= host_match_keys(ip_norm)
    return keys



# Backward-compatible private alias (kept for existing call sites/imports).
_expand_host_aliases = expand_host_aliases


def is_dc_host(
    *,
    host: str | None,
    domains_data: dict[str, Any] | None,
    domain: str,
    computer_nodes: Iterable[dict[str, Any]] | None = None,
    ip_hostname_inventory: dict[str, Any] | None = None,
) -> bool:
    """Return True when *host* is a domain controller (writable DC or RODC).

    This is the alias-aware answer to "is this attack-path target a DC?".  It
    drives downstream service selection (a DC needs an ``ldap`` altservice for
    DCSync; a member server does not).  The naive ``target_host == kdc_ip``
    string compare it replaces silently misclassified any DC supplied as an
    FQDN or short name, because an FQDN never string-equals an IP.

    Resolution order (strongest signal first):

    1. **Graph node** — when *computer_nodes* are provided, find the Computer
       node whose identity aliases *host* and apply
       :func:`classify_computer_node_role`.  A ``writable_dc`` / ``rodc`` verdict
       is returned immediately; a matched-but-not-DC node short-circuits to
       ``False`` (the collector saw the object and it is a member server).
    2. **Domain DC identifiers** — alias-aware compare *host* against the
       domain's canonical DC identifiers (``resolve_dc_ip``,
       ``resolve_dc_fqdn``, ``pdc``, ``pdc_hostname``, and every entry in
       ``dcs``) using the shared :func:`hosts_match` semantics, with the
       IP ↔ hostname bridge from the workspace inventory.

    Args:
        host: Target host as an IP, short name, FQDN, or ``HOST$``.
        domains_data: Full ``domains_data`` mapping (or just the per-domain
            entry — both are accepted; the per-domain entry is resolved below).
        domain: The domain whose DC identifiers to compare against.
        computer_nodes: Optional iterable of collected Computer nodes
            (attack-graph / BloodHound shape).  When supplied, enables the
            strongest, role-accurate classification path.
        ip_hostname_inventory: Optional ``{ip: [hostname, …]}`` map
            (``load_workspace_ip_hostname_inventory``) used to bridge IP and
            hostname forms during comparison.

    Returns:
        ``True`` for a writable DC or an RODC; ``False`` otherwise.  Never
        raises — any internal failure degrades to ``False``.
    """
    host_text = str(host or "").strip()
    if not host_text:
        return False

    try:
        from adscan_internal.models.domain import (  # noqa: PLC0415
            resolve_dc_fqdn,
            resolve_dc_ip,
        )
        from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
            host_match_keys,
        )
    except Exception:  # noqa: BLE001 - degrade safely if imports fail
        return False

    # Accept either the full domains_data or a single per-domain entry.
    domain_data: dict[str, Any] = {}
    if isinstance(domains_data, dict):
        candidate = domains_data.get(domain)
        if isinstance(candidate, dict):
            domain_data = candidate
        else:
            # Caller passed the per-domain entry directly.
            domain_data = domains_data

    host_keys = expand_host_aliases(
        host_text, ip_hostname_inventory=ip_hostname_inventory
    )

    # 1. Graph-node classification — strongest, role-accurate.
    if computer_nodes is not None:
        for node in computer_nodes:
            if not isinstance(node, dict):
                continue
            node_keys: set[str] = set()
            for identity in _node_identities(node):
                node_keys |= host_match_keys(identity)
            if not node_keys or not (node_keys & host_keys):
                continue
            role = classify_computer_node_role(node)
            if role in ("writable_dc", "rodc"):
                return True
            # Matched the node and it is not a DC -> definitively not a DC.
            return False

    # 2. Domain DC identifiers — alias-aware fallback (the bug fix).
    identifiers: list[str] = []
    try:
        dc_ip = resolve_dc_ip(domain_data)
        if dc_ip:
            identifiers.append(dc_ip)
    except Exception:  # noqa: BLE001
        pass
    try:
        dc_fqdn = resolve_dc_fqdn(
            domain_data,
            target_domain=domain,
            ip_hostname_inventory=ip_hostname_inventory,
        )
        if dc_fqdn:
            identifiers.append(dc_fqdn)
    except Exception:  # noqa: BLE001
        pass
    for key in ("pdc", "pdc_hostname", "pdc_hostname_fqdn", "pdc_fqdn", "dc_fqdn"):
        value = str(domain_data.get(key) or "").strip()
        if value:
            identifiers.append(value)
    dcs = domain_data.get("dcs")
    if isinstance(dcs, (list, tuple)):
        identifiers.extend(str(entry).strip() for entry in dcs if str(entry or "").strip())

    for identifier in identifiers:
        identifier_keys = expand_host_aliases(
            identifier, ip_hostname_inventory=ip_hostname_inventory
        )
        if host_keys & identifier_keys:
            return True

    return False


def dc_aware_mint_services(*, is_dc: bool) -> list[str]:
    """Return the altservices to mint a service ticket for, by DC-ness.

    Single source of the "the altservice set differs for a DC" rule:

    - **DC** → ``["cifs", "http", "ldap"]``.  ``ldap`` is required so a follow-up
      DCSync (MS-DRSR) can authenticate; ``cifs``/``http`` cover SMB/WinRM.
    - **non-DC** → ``["cifs", "http"]``.  ``cifs`` covers DumpLSA / SMB-backed
      post-ex; ``http`` covers WinRM.  A member server is never a DCSync target,
      so ``ldap`` is omitted.
    """
    if is_dc:
        return ["cifs", "http", "ldap"]
    return ["cifs", "http"]
