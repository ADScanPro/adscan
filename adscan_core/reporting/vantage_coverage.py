"""Vantage coverage: a proven privilege the assessment could not exercise.

Some privileges are read out of the directory and then exercised over a
protocol whose ports the assessment's network position cannot reach. Directory
replication is the canonical case: the permission is a pair of extended rights
on the domain object, readable over LDAP, but exercising it means speaking
MS-DRSR, which is TCP only and runs on a port the endpoint mapper assigns out
of the high dynamic range. From a segmented audit position or a restricted VPN,
port 135 answers and the dynamic range does not.

Two wrong ways to report that, and the second is the one that ships quietly:

* **``closed_by_configuration`` is forbidden here.** That status is reserved
  for a configuration close ADscan observed WITH CERTAINTY. What ADscan
  observed is its OWN reachability, and it cannot tell a host firewall on the
  domain controller (real hardening, worth crediting) apart from a filtered
  network path from this position (the VPN and segmented-audit case). Crediting
  a control nobody observed is the false negative the Exposure-Validation
  doctrine forbids. This block rides on the existing ``attempted`` status and
  adds no new status token.
* **A bare ``attempted`` is wrong too, because the error runs the other way.**
  The principal HELD the privilege; that is why the step was offered, and the
  finding stands on the directory read rather than on the attempt. A client who
  reads "the replication attempt did not complete" reasonably concludes they
  are fine. They are not: the privilege is present and the exposure is real.
  Only the TEST of that avenue was impossible from where the assessment stood.

So the client-facing statement carries three things, and the third is where the
value is: the privilege is present and who holds it; the assessment could not
exercise it from this position, naming the ports the protocol needs and what
did answer; and what that does and does not mean, with the native command that
settles it from inside the client's own network.

This module is the SSOT for both halves, mirroring
:mod:`adscan_core.reporting.cracking_coverage` and
:mod:`adscan_core.reporting.host_enrichment_coverage`:

* :func:`build_vantage_coverage` turns the observed entries into the block
  persisted by
  :func:`adscan_core.reporting.technical_report.record_vantage_coverage`; and
* :func:`vantage_coverage_view` turns that persisted block back into the small
  render-ready shape the PDF report and the paid web platform both consume, so
  the two surfaces cannot word the same gap differently.

The generalisation is deliberately ONE level wide: the condition is "a proven
privilege ADscan could not exercise because a required port or path was
unreachable from the assessment position". A second instance (another
TCP-dynamic-RPC technique) is a new entry in :data:`VANTAGE_PROTOCOLS`, not a
new block. It is not a general-purpose network-reachability register.

Pure logic: no IO, no console, no network. Safe to import from ``adscan_core``,
the LITE runtime, the PRO report renderer and the web backend alike.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

#: Per-domain key this block is stamped under, in ``technical_report.json`` and
#: in the renderer's ``report_data``. One name, so the writer, the PDF and the
#: web platform cannot drift apart on where the record lives.
VANTAGE_COVERAGE_KEY = "vantage_coverage"

#: Directory replication (MS-DRSR). The only protocol registered today.
PROTOCOL_DRSUAPI = "drsuapi"

#: Canonical fill-in tokens for a command whose object the record did not carry.
#: An obvious placeholder, never a fictional but real-looking object name a
#: client would paste and run (see the remediation-placeholder contract).
_DOMAIN_DN_TOKEN = "<DOMAIN-DN>"
_HOLDER_TOKEN = "<ACCOUNT>"
_DC_TOKEN = "<DOMAIN-CONTROLLER>"

#: One protocol whose reach the assessment can observe but not control.
#:
#: ``privilege_label`` names the permission in the client's own vocabulary.
#: ``protocol_label`` names the protocol the privilege is exercised over.
#: ``port_requirement`` states what that protocol needs, in prose.
#: ``consequence`` states what the privilege permits from a position that has
#: those ports, so the reader is never left thinking the limitation is the
#: finding.
#: ``verify`` is an ordered tuple of ``(caption, windows_command)`` pairs the
#: CLIENT runs from inside their network to settle it. Native Microsoft and
#: built-in OS commands only: an offensive tool has no place in a deliverable,
#: and the client is the one running these.
VANTAGE_PROTOCOLS: dict[str, dict[str, Any]] = {
    PROTOCOL_DRSUAPI: {
        "privilege_label": (
            "directory replication rights (Replicating Directory Changes and "
            "Replicating Directory Changes All)"
        ),
        "protocol_label": "the directory replication protocol (MS-DRSR)",
        "port_requirement": (
            "it runs over TCP only, on a port assigned on request out of the "
            "dynamic range 49152-65535 by the endpoint mapper on port 135"
        ),
        "consequence": (
            "From any position where that port range is open, the same "
            "permission allows an attacker to read the password material of "
            "every account in the domain, including the account that signs "
            "Kerberos tickets."
        ),
        "verify": (
            (
                "Confirm the replication rights on the domain object",
                "(Get-Acl \"AD:{domain_dn}\").Access | "
                "Where-Object { $_.ObjectType -in "
                "'1131f6ad-9c07-11d1-f79f-00c04fd3d2d9',"
                "'1131f6aa-9c07-11d1-f79f-00c04fd3d2d9' } | "
                "Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType",
            ),
            (
                "Read the dynamic port range in force on the domain controller",
                "netsh int ipv4 show dynamicport tcp",
            ),
            (
                "Read the inbound rules that admit replication traffic to it",
                "Get-NetFirewallRule -Enabled True -Direction Inbound | "
                "Where-Object { $_.DisplayName -like '*RPC*' } | "
                "Select-Object DisplayName, Profile, Action",
            ),
        ),
    },
}


def _text(value: Any) -> str:
    """Return *value* as a stripped string, or ``""``."""
    return str(value or "").strip()


def _render_verify(
    protocol: Mapping[str, Any], *, domain_dn: str
) -> list[dict[str, str]]:
    """Fill the protocol's verification commands with the recorded identifiers.

    A command in a deliverable is meant to be RUN, so an object the record did
    not carry degrades to an obvious ``<...>`` fill-in rather than to a
    plausible-looking literal.

    Substitution is a literal replace, NOT ``str.format``: a PowerShell command
    legitimately contains ``{ ... }`` script blocks, which ``format`` reads as
    fields and rejects, silently leaving the placeholder in the command a client
    is meant to paste.
    """
    rendered: list[dict[str, str]] = []
    for caption, command in protocol.get("verify") or ():
        filled = str(command).replace(
            "{domain_dn}", domain_dn or _DOMAIN_DN_TOKEN
        )
        rendered.append({"caption": str(caption), "command": filled})
    return rendered


def _statement_for_entry(entry: Mapping[str, Any]) -> str:
    """Render the client-facing sentences for one unexercised privilege.

    Three movements, in this order, because the order is the whole point: the
    privilege is real, the test was not possible from here, and here is what
    that means and how you settle it. Reversing them turns a live exposure into
    an apology about the network.
    """
    protocol = VANTAGE_PROTOCOLS.get(_text(entry.get("protocol")))
    if not protocol:
        return ""
    holder = _text(entry.get("holder")) or _HOLDER_TOKEN
    target = _text(entry.get("target")) or "the domain"
    answered = _text(entry.get("reachable_ports"))
    silent = _text(entry.get("unreachable_ports"))

    present = (
        f"{holder} holds, directly or through its group membership, "
        f"{protocol['privilege_label']} on {target}. That permission was read "
        "from the directory, so this finding does not rest on the attempt "
        "described next."
    )

    not_exercised = (
        "The assessment could not exercise it from the network position it ran "
        f"from. The privilege is exercised over {protocol['protocol_label']}, and "
        f"{protocol['port_requirement']}."
    )
    if answered and silent:
        not_exercised += (
            f" Port {answered} answered from the assessment host; no port in the "
            f"{silent} range answered within the time allowed."
        )
    elif silent:
        not_exercised += (
            f" No port in the {silent} range answered from the assessment host "
            "within the time allowed."
        )

    meaning = (
        "This describes the route between the assessment host and the domain "
        "controller, and it is not evidence that the domain controller refuses "
        "replication: what was measured is the assessment's own reach, not a "
        f"filtering decision on your side. {protocol['consequence']} "
        "The checks below settle both halves from inside your own network."
    )
    return f"{present} {not_exercised} {meaning}"


def _clean_entry(entry: Any) -> dict[str, Any] | None:
    """Normalize one recorded entry, or ``None`` when it carries no protocol.

    An unrecognised protocol is dropped rather than rendered: a malformed value
    must never manufacture a coverage declaration nobody observed.
    """
    if not isinstance(entry, Mapping):
        return None
    protocol_key = _text(entry.get("protocol")).lower()
    protocol = VANTAGE_PROTOCOLS.get(protocol_key)
    if not protocol:
        return None
    domain_dn = _text(entry.get("domain_dn"))
    cleaned: dict[str, Any] = {
        "protocol": protocol_key,
        "privilege_label": str(protocol["privilege_label"]),
        "protocol_label": str(protocol["protocol_label"]),
        "holder": _text(entry.get("holder")) or _HOLDER_TOKEN,
        "target": _text(entry.get("target")) or "the domain",
        "host": _text(entry.get("host")) or _DC_TOKEN,
        "domain_dn": domain_dn,
        "reachable_ports": _text(entry.get("reachable_ports")),
        "unreachable_ports": _text(entry.get("unreachable_ports")),
        "verify": _render_verify(protocol, domain_dn=domain_dn),
    }
    cleaned["statement"] = _statement_for_entry(cleaned)
    return cleaned


def _clean_entries(entries: Any) -> list[dict[str, Any]]:
    """Normalize and de-duplicate recorded entries, order preserved."""
    cleaned: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for raw in entries or ():
        item = _clean_entry(raw)
        if item is None:
            continue
        key = (item["protocol"], item["holder"].lower(), item["target"].lower())
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(item)
    return cleaned


def build_vantage_coverage(*, entries: Iterable[Any] = ()) -> dict[str, Any]:
    """Build the ``vantage_coverage`` block for one domain.

    Args:
        entries: One mapping per proven privilege the assessment could not
            exercise for reachability. Each needs ``protocol`` (a key of
            :data:`VANTAGE_PROTOCOLS`) and, to read well, ``holder`` (the object
            that holds the privilege, already humanized by the caller),
            ``target`` (what it holds it over), ``host`` (the host the attempt
            went to), ``domain_dn`` (so the verification command names a real
            object), ``reachable_ports`` and ``unreachable_ports``.

    Returns:
        The block to hand to ``record_vantage_coverage``. Always carries
        ``statement`` so the recorder accepts it; ``complete`` is ``True`` when
        nothing was left unexercised, and the statement is then empty rather
        than an affirmation: unlike a corpus or a host sweep there is no
        "everything was exercised" claim to make, because the set of privileges
        a given assessment exercises is not a fixed denominator.
    """
    cleaned = _clean_entries(entries)
    statements = [e["statement"] for e in cleaned if e["statement"]]
    return {
        "complete": not cleaned,
        "entries": cleaned,
        "protocols": sorted({e["protocol"] for e in cleaned}),
        "statement": " ".join(statements),
    }


def vantage_coverage_view(coverage: Any) -> dict[str, Any]:
    """Return the render-ready view of a persisted ``vantage_coverage`` block.

    The one shape the PDF report and the web platform both read, so the
    limitation is worded identically wherever a client meets it.

    Returns a mapping with:
      * ``has_gap`` --- whether to surface the declaration at all;
      * ``statement`` --- the joined client-facing sentences (empty when there
        is nothing to declare);
      * ``entries`` --- one record per unexercised privilege, each carrying its
        own ``statement`` plus the ``verify`` command list, so a surface can
        render them individually instead of as one paragraph;
      * ``protocols`` --- the protocol keys involved, for a machine consumer.

    An absent or unreadable block yields ``has_gap=False``: a scan predating
    this record must render exactly as it did before rather than grow a notice
    nobody observed.
    """
    if not isinstance(coverage, Mapping):
        return {
            "has_gap": False,
            "statement": "",
            "entries": [],
            "protocols": [],
        }
    entries = _clean_entries(coverage.get("entries"))
    # Honour the statement that was RECORDED: the wording persisted at scan time
    # is what that assessment reported, and re-deriving it would let a later
    # change to this module silently rewrite an already-delivered finding. Only
    # a block with no recorded statement falls back to the derivation.
    statement = _text(coverage.get("statement")) or " ".join(
        e["statement"] for e in entries if e["statement"]
    )
    complete = bool(coverage.get("complete", not entries))
    has_gap = bool(not complete and entries and statement)
    return {
        "has_gap": has_gap,
        "statement": statement if has_gap else "",
        "entries": entries if has_gap else [],
        "protocols": sorted({e["protocol"] for e in entries}) if has_gap else [],
    }


def merge_vantage_coverage(domain_entries: Any) -> dict[str, Any]:
    """Fold every domain's recorded coverage into one report-wide view.

    Unlike the corpus and host-sweep mergers this one is a UNION of records, not
    a fold of counters: each entry names its own holder and target, so two
    domains that each left a privilege unexercised produce two declarations, and
    neither may absorb the other.

    ``domain_entries`` is any iterable of per-domain mappings (the renderer
    passes ``report_data.values()``); non-mapping entries and the reserved
    non-domain blocks that ride alongside are skipped. No recorded coverage
    anywhere yields ``has_gap=False`` --- the pre-existing render, unchanged.
    """
    merged: list[dict[str, Any]] = []
    for entry in domain_entries or ():
        if not isinstance(entry, Mapping):
            continue
        view = vantage_coverage_view(entry.get(VANTAGE_COVERAGE_KEY))
        if not view["has_gap"]:
            continue
        merged.extend(view["entries"])
    if not merged:
        return vantage_coverage_view(None)
    return vantage_coverage_view(build_vantage_coverage(entries=merged))


__all__ = [
    "PROTOCOL_DRSUAPI",
    "VANTAGE_COVERAGE_KEY",
    "VANTAGE_PROTOCOLS",
    "build_vantage_coverage",
    "merge_vantage_coverage",
    "vantage_coverage_view",
]
