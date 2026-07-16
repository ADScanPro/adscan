"""Pure graph-node classification of a Computer's domain-controller role.

This module is the native-stack-free core of the DC-role question: given a
collected Computer node (BloodHound / native-collector shape), is it a writable
domain controller, a read-only domain controller (RODC), or neither?  It reads
only the node's own attributes and imports nothing from the engine / native
stack — so it is safe to bundle into the readable appliance web backend
(``adscan_web``), which needs the role verdict to grade a target's Privilege
Tier but must never ship the credential/Kerberos runtime.

The canonical detection signals on a Computer node, in order of strength:

1. ``primaryGroupID``
   Active Directory schema imposes ``primaryGroupID == 516`` for writable DCs
   and ``primaryGroupID == 521`` for RODCs.  This is an attribute of the object
   itself, populated by the LDAP collector — it does not require enumerating
   group memberships externally (which RODCs may block).

2. ``serviceprincipalnames`` containing ``krbtgt/<host>``
   Only RODCs have a local krbtgt account; writable DCs share the single
   domain-wide krbtgt user.  Any SPN matching ``krbtgt/<anything>`` on a
   Computer is a definitive RODC fingerprint.

3. ``userAccountControl & 0x04000000`` (``UF_PARTIAL_SECRETS_ACCOUNT``)
   The dedicated UAC bit for RODC machine accounts.

4. Explicit ``msDS-isRODC`` / ``isRODC`` flags (BloodHound CE / native
   collector legacy).

The alias-aware "is this *target host* a DC?" runtime resolver (``is_dc_host``),
and the host-alias helpers it depends on, live in
:mod:`adscan_internal.services.domain_controller_classifier`, which re-exports
:func:`classify_computer_node_role` / :func:`node_is_rodc_computer` from here so
existing call sites keep their import path.
"""

from __future__ import annotations

from typing import Any, Literal


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
