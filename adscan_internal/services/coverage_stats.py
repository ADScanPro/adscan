"""Single source of truth for ADscan coverage headline figures.

This module computes the canonical counts that describe ADscan's coverage — the
number of Active Directory attack techniques, the number of reported finding
types, and the ADCS ESC class span — directly from the live product catalogs.
Every surface that quotes these numbers (the public README, the marketing site,
the coverage-matrix PDF, the docs) must derive them from here so they can never
drift apart.

Design notes:
- Like ``attack_step_catalog``, this module has **no top-level dependency on the
  ``pro`` package**. ``ATTACK_STEP_CATALOG`` is a shared service with no ``pro``
  imports; ``VULN_CATALOG`` lives under ``pro`` and is imported lazily inside
  :func:`build_technique_stats` and :func:`build_finding_inventory`, so the
  module stays importable in contexts where ``pro`` is not needed.
- The exclusion rule (``context`` category entries are attack-graph plumbing, not
  customer-facing techniques) is defined ONCE here as ``STEP_CATEGORY_EXCLUDE``
  and re-used by ``scripts/export_coverage_matrix.py``.
- The counts come in pairs with the inventories that enumerate them:
  :func:`build_technique_inventory` enumerates what ``technique_count`` counts
  (what ADscan looks for) and :func:`build_finding_inventory` enumerates what
  ``finding_count`` counts (what lands in the report). Each inventory applies
  exactly the filter its count applies, so a published page can never state one
  figure and list a different number of rows.
"""

from __future__ import annotations

import re
from typing import Any

from adscan_internal.services.attack_step_catalog import ATTACK_STEP_CATALOG

# ``context`` entries are pure attack-graph pivots (membership / credential-reuse
# plumbing), not a detect/exploit technique a customer sees as coverage. This is
# the single definition of the exclusion rule; other modules import it from here.
STEP_CATEGORY_EXCLUDE = {"context"}

# ESC keys look like ``adcsesc1`` … ``adcsesc16a`` — pull the leading integer.
_ESC_KEY_PREFIX = "adcsesc"


def _adcs_esc_numbers(step_catalog: dict[str, Any]) -> list[int]:
    """Return the sorted, de-duplicated ESC class numbers present in the catalog.

    ADCS templates are catalog keys of the form ``adcsesc<N>[<variant>]``
    (e.g. ``adcsesc1``, ``adcsesc6a``). Variants collapse to their integer class.
    """
    numbers: set[int] = set()
    for key, entry in step_catalog.items():
        if getattr(entry, "category", None) in STEP_CATEGORY_EXCLUDE:
            continue
        if not key.startswith(_ESC_KEY_PREFIX):
            continue
        m = re.match(r"(\d+)", key[len(_ESC_KEY_PREFIX):])
        if m:
            numbers.add(int(m.group(1)))
    return sorted(numbers)


def _adcs_esc_span(step_catalog: dict[str, Any]) -> str:
    """Compute the ADCS ESC span string (e.g. ``ESC1–ESC17``) from the catalog.

    The span is ``ESC<min>–ESC<max>`` using an en-dash, matching the register the
    site and reports already use. Empty string when no ESC techniques exist.
    """
    numbers = _adcs_esc_numbers(step_catalog)
    if not numbers:
        return ""
    return f"ESC{numbers[0]}–ESC{numbers[-1]}"


# Human-facing labels for the catalog's internal category keys. Only the keys
# that do not read well when title-cased need an entry; ``_category_label``
# falls back to a title-cased key for anything missing, so a new category never
# breaks generation — it just renders less prettily until it is added here.
CATEGORY_LABELS: dict[str, str] = {
    "acl_ace": "ACL / ACE Abuse",
    "adcs": "AD CS — Certificate Services",
    "coercion": "Authentication Coercion",
    "collection": "Collection",
    "credential_access": "Credential Access",
    "cve": "Known CVEs",
    "delegation": "Delegation Abuse",
    "entry_vector": "Initial Access",
    "execution": "Execution",
    "kerberos": "Kerberos Attacks",
    "lateral_movement": "Lateral Movement",
    "ntlm": "NTLM Weaknesses",
    "ntlm_relay": "NTLM Relay",
    "privilege": "Privilege Escalation",
    "trust": "Trust Abuse",
}

# Short display names for catalog relations whose key does not title-case into
# something a reader recognises. Anything absent falls back to the title-cased
# key, so this map only has to grow when a new relation reads badly.
DISPLAY_NAME_OVERRIDES: dict[str, str] = {
    "kerberoasting": "Kerberoasting",
    "addmember": "Add Member to Group",
    "addself": "Add Self to Group",
    "domainpassreuse": "Domain Password Reuse",
    "localcredtodomainreuse": "Local-to-Domain Credential Reuse",
    "addkeycredentiallink": "Shadow Credentials (Key Credential Link)",
    "adminto": "Local Admin Rights",
    "allextendedrights": "All Extended Rights",
    "allowedtoact": "Resource-Based Constrained Delegation (inbound)",
    "allowedtodelegate": "Constrained Delegation",
    # ESC5's public name is the ACL weakness, not the MITRE technique title
    # (T1649 belongs in the MITRE field). The exploitation ADscan carries for it
    # is CA-object takeover → CA private-key theft → offline certificate forgery.
    "adcsesc5": "AD CS ESC5 — Vulnerable PKI Object Access Control",
    "asreproasting": "AS-REP Roasting",
    "backupoperatorescalation": "Backup Operators Escalation",
    "blankpassword": "Blank Password",
    "canpsremote": "PowerShell Remoting Access",
    "canrdp": "RDP Access",
    "certighost": "Certighost (AD CS Chase-Fallback DC Impersonation)",
    "coerceandrelayntlmtoadcs": "Coerce and Relay NTLM to AD CS (ESC8)",
    "computerpre2k": "Pre-Windows 2000 Computer Account",
    "crackntlmv1": "NetNTLMv1 Offline Recovery",
    "dcsync": "DCSync",
    "dfscoerce": "DFSCoerce",
    "dnsadminabuse": "DnsAdmins Abuse",
    "dumpdpapi": "DPAPI Secret Extraction",
    "dumplsa": "LSA Secrets Extraction",
    "dumplsass": "LSASS Credential Extraction",
    "dumpsam": "SAM Database Extraction",
    "executedcom": "DCOM Execution",
    "extractrodckrbtgtsecret": "RODC krbtgt Secret Extraction",
    "forcechangepassword": "Force Change Password",
    "forgerodcgoldenticket": "RODC Golden Ticket",
    "fullcontrolshare": "Full Control Share",
    "genericall": "GenericAll",
    "genericwrite": "GenericWrite",
    "getchanges": "DS-Replication-Get-Changes",
    "getchangesall": "DS-Replication-Get-Changes-All",
    "getchangesinfilteredset": "DS-Replication-Get-Changes-In-Filtered-Set",
    "gpppassword": "Group Policy Preferences Password",
    "guestsession": "Guest Session",
    "hasshadowcredentials": "Shadow Credentials Present",
    "hassession": "Privileged Session Abuse",
    "kerberoskeylist": "Kerberos Key List (RODC)",
    "ldapanonymousbind": "Anonymous LDAP Bind",
    "localadminpassreuse": "Local Admin Password Reuse",
    "managerodcprp": "RODC Password Replication Policy Control",
    "memberof": "Group Membership",
    "ms17-010": "MS17-010 (EternalBlue)",
    "mseven": "MS14-068 / Kerberos PAC Forgery",
    "mssql_impersonate_login": "MSSQL Login Impersonation",
    "mssql_linked_server_lateral": "MSSQL Linked Server Lateral Movement",
    "mssql_ntlmv2_theft": "MSSQL NetNTLMv2 Theft",
    "mssql_openrowset_bulk_read": "MSSQL OPENROWSET Bulk Read",
    "mssql_seimpersonate_escalation": "MSSQL SeImpersonate Escalation",
    "mssql_token_theft_escalation": "MSSQL Token Theft Escalation",
    "mssql_trustworthy_db_escalation": "MSSQL TRUSTWORTHY Database Escalation",
    "nopac": "noPac (CVE-2021-42278/42287)",
    "ntlmv1enabled": "NetNTLMv1 Enabled",
    "ntlmv1relayrbcd": "NetNTLMv1 Relay to RBCD",
    "ntlmv1relayshadowcreds": "NetNTLMv1 Relay to Shadow Credentials",
    "owns": "Object Ownership",
    "passwordinfile": "Password in File",
    "passwordinshare": "Password in Share",
    "passwordspray": "Password Spraying",
    "petitpotam": "PetitPotam",
    "poisoncapturentlmv2crack": "LLMNR/NBT-NS Poisoning and NetNTLMv2 Recovery",
    "preparerodccredentialcaching": "RODC Credential Caching",
    "printerbug": "PrinterBug (MS-RPRN)",
    "printnightmare": "PrintNightmare",
    "printoperatorabuse": "Print Operators Abuse",
    "privilegedgroupcontrol": "Privileged Group Control",
    "readgmsapassword": "Read gMSA Password",
    "crossorgtgtdelegation": "Cross-Forest TGT Delegation",
    "raisechild": "Child-to-Forest-Root Escalation",
    "readlapspassword": "Read LAPS Password",
    "readshare": "Readable Share",
    "scheduledtask": "Scheduled Task Execution",
    "spnjack": "SPN-Jacking",
    "sqlaccess": "MSSQL Access",
    "sqladmin": "MSSQL Sysadmin",
    "synclapspassword": "Sync LAPS Password",
    "timeroasting": "Timeroasting",
    "unconstraineddelegation": "Unconstrained Delegation",
    "useraspass": "Username as Password",
    "userdescription": "Credentials in User Description",
    "writeaccountrestrictions": "Write Account Restrictions",
    "writedacl": "WriteDACL",
    "writelogonscript": "Write Logon Script",
    "writeowner": "WriteOwner",
    "writeshare": "Writable Share",
    "writesmbpath": "Writable SMB Path",
    "writespn": "Write SPN",
    "xp_cmdshell": "xp_cmdshell Execution",
    "zerologon": "Zerologon (CVE-2020-1472)",
}

# How ``support_kind`` is presented to a reader. ADscan's Exposure-Validation
# doctrine requires these to stay honest: "Executed" means ADscan runs the
# technique end to end; "Detected" means it is identified and mapped but not
# executed; the safety label states that ADscan deliberately refuses to run a
# destructive technique. Never relabel a non-execution as a defensive block.
SUPPORT_KIND_LABELS: dict[str, str] = {
    "supported": "Executed",
    "unsupported": "Detected",
    "policy_blocked": "Detected · not executed (safety)",
    # A condition or pivot ADscan observes and chains into an attack path
    # (credential reuse, NTLMv1 enabled, a writable staging path) rather than a
    # standalone step it runs. "Observed" keeps that distinct from "Detected",
    # which implies a discrete technique that was identified but not executed.
    "context": "Observed (attack-path pivot)",
}


def _category_label(category: str) -> str:
    return CATEGORY_LABELS.get(category, category.replace("_", " ").title())


def _display_name(relation: str) -> str:
    """Reader-facing name for a catalog relation key.

    Order: explicit override, then the ``adcsesc<N>[<variant>]`` family rule (18
    keys that would otherwise render as ``Adcsesc1``), then a title-cased key.
    """
    override = DISPLAY_NAME_OVERRIDES.get(relation)
    if override:
        return override
    esc = re.fullmatch(rf"{_ESC_KEY_PREFIX}(\d+)([a-z]?)", relation)
    if esc:
        variant = esc.group(2).upper()
        return f"AD CS ESC{esc.group(1)}{variant}"
    return relation.replace("_", " ").title()


def build_technique_inventory() -> list[dict[str, Any]]:
    """Return one row per customer-facing technique, for generated coverage docs.

    Applies exactly the same ``STEP_CATEGORY_EXCLUDE`` rule as
    :func:`build_technique_stats`, so the published list and the published count
    are computed from one filter and can never disagree. A unit test locks that
    invariant (``len(inventory) == technique_count``).

    Returns:
        Rows sorted by category label then display name, each containing the
        catalog ``relation`` key, a human ``display_name``, the raw ``category``
        and its ``category_label``, the catalog ``description``, the MITRE
        ATT&CK id/name, the raw ``support_kind`` plus its reader-facing
        ``support_label``, the linked ``vuln_key`` when the technique maps to
        a reported finding, and the ``detection_event_ids`` the technique
        declares (empty when it leaves no event of its own).

        ``detection_event_ids`` is exported so a published surface can DERIVE
        its detection figures instead of transcribing them. The public
        detection-events page had its counts written by hand from a snapshot,
        and went stale the same day the catalog gained a technique: the page
        said 106 while the catalog said 107, and the missing technique was
        simply absent from a table that claims to be exhaustive.
    """
    rows: list[dict[str, Any]] = []
    for relation, entry in ATTACK_STEP_CATALOG.items():
        category = getattr(entry, "category", None)
        if not category or category in STEP_CATEGORY_EXCLUDE:
            continue
        support_kind = getattr(entry, "support_kind", None) or ""
        rows.append(
            {
                "relation": relation,
                "display_name": _display_name(relation),
                "category": category,
                "category_label": _category_label(category),
                "description": (getattr(entry, "description", None) or "").strip(),
                "mitre_technique_id": getattr(entry, "mitre_technique_id", None) or "",
                "mitre_technique_name": getattr(entry, "mitre_technique_name", None)
                or "",
                "support_kind": support_kind,
                "support_label": SUPPORT_KIND_LABELS.get(support_kind, "Detected"),
                "vuln_key": getattr(entry, "vuln_key", None) or "",
                "detection_event_ids": [
                    str(event_id)
                    for event_id in (getattr(entry, "detection_event_ids", None) or ())
                ],
            }
        )
    rows.sort(key=lambda r: (r["category_label"], r["display_name"]))
    return rows


# The severity ladder the published inventory is ordered by, worst first. The
# catalog stores ``severity`` as a lowercase word and ``cvss`` as a string, and
# both are carried through VERBATIM: a severity and a CVSS score are claims
# about a client's risk, so nothing here rounds, re-derives or substitutes one.
# The rank is the only derived field, and it exists so a published surface can
# order and group by severity without keeping a ladder of its own, which is how
# two surfaces end up disagreeing about whether "high" outranks "medium".
#
# A severity the catalog uses and this tuple does not carry would silently sort
# last; ``tests/unit/services/test_coverage_finding_inventory.py`` fails instead
# and names it.
FINDING_SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")


def _finding_severity_rank(severity: str) -> int:
    """Position of ``severity`` on :data:`FINDING_SEVERITY_ORDER`, worst first.

    An unrecognised severity sorts after every known one rather than raising:
    generation must never be the thing that breaks when the catalog gains a
    word. The test above is what makes the omission loud.
    """
    try:
        return FINDING_SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(FINDING_SEVERITY_ORDER)


# A CVE identifier named anywhere on a finding: its title or its reference
# list. Used to give a finding an EXTERNAL anchor an auditor can check, which is
# a fact about the finding and not a claim about its score. See the long note in
# build_finding_inventory about why those are different things here.
_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _cve_ids_for_entry(entry: dict[str, Any]) -> list[str]:
    """Return the CVE ids the catalog entry names, de-duplicated and sorted."""
    haystack = " ".join(
        [str(entry.get("title") or "")]
        + [str(ref) for ref in (entry.get("references") or ())]
    )
    return sorted({m.group(0).upper() for m in _CVE_ID_RE.finditer(haystack)})


# Findings whose authored ``cvss`` in ``VULN_CATALOG`` DISAGREES with the score
# its own stored CVSS Base vector computes, measured 2026-10-09. This is a
# DECLARED, OPEN defect, not an accepted state: it is listed so a NEW
# disagreement fails the guard loudly instead of joining a silent majority.
#
# Shrinking this set is the fix (reconcile the number to the vector, or author
# the vector the number was meant to express). Do NOT add a key here to make a
# test pass. Full entry, with what an auditor can ask, in BACKLOG.md.
CVSS_CATALOG_VECTOR_DISAGREEMENTS: frozenset[str] = frozenset(
    {
        "asreproast",
        "credential_in_ldap_attribute",
        "dcsync",
        "gmsa_readable",
        "gpp_autologin",
        "gpp_passwords",
        "kerberoast",
        "laps_readable",
        "ldap_anonymous",
        "ldap_security_posture",
        "password_not_req",
        "smb_guest_shares",
        "smb_null_domain",
        "smb_share_secrets",
    }
)


def _base_vector_for_finding(key: str) -> tuple[str, float | None]:
    """Return the finding's CVSS Base vector and the score computed FROM it.

    The score is the vector's own ``formal_score``, never the catalog number, so
    the pair is internally consistent by construction: a consumer that renders
    both is showing a score and the thing that reproduces it. Best-effort, since
    the severity engine lives in ``adscan_core`` and a finding simply may not
    have a vector; a failure yields ``("", None)``, which every consumer must
    treat as "no CVSS Base may be presented for this finding".
    """
    try:
        from adscan_core.cvss import compute_base_cvss_result  # noqa: PLC0415

        result = compute_base_cvss_result(key)
    except Exception:  # noqa: BLE001 - generation must not fail on one finding
        return "", None
    vector = str(getattr(result, "vector", None) or "").strip()
    if not vector:
        return "", None
    formal = getattr(result, "formal_score", None)
    return vector, (float(formal) if formal is not None else None)


# ---------------------------------------------------------------------------
# The severity model, exported per finding
# ---------------------------------------------------------------------------
#
# ADscan rates a finding with a catalog BASELINE plus a CONTEXTUAL overlay that
# raises it according to what the assessment observed. Both halves live in
# ``adscan_core.cvss``; this section does not re-implement either, it DRIVES
# them (``compute_finding_severity`` with one synthesised context per option) so
# an exported option is by construction the number the engine would produce.
# Transcribing the rule table instead is how a published method stops matching
# the method that ran.
#
# ONLY THE TIER AXIS IS PUBLISHED, and that is a correctness decision rather
# than a staging one. The overlay also keys on confirmed exploitation and on a
# confirmed relay endpoint, and those are properties of ONE assessment's
# evidence rather than of the finding type, so a catalog-level export has no
# honest value to state for them. Publishing an axis the product does not
# resolve from the catalog alone would be publishing a method we do not run,
# which is the defect the no-CVSS decision exists to prevent. A second axis is
# an ADDITION to ``axes`` once there is something true to put in it, never a
# migration of this shape.

#: The axis id and its reader-facing label. The label is the only new
#: client-facing string this export introduces; each option's ``reason`` is
#: carried from the catalog verbatim.
_TIER_AXIS_ID = "affected_asset_tier"
_TIER_AXIS_LABEL = "Privilege tier of the affected assets"


def _tier_axis_tokens() -> tuple[str, ...]:
    """The tier tokens an affected asset can carry, worst first.

    Read from the tier SSOT's own token order rather than written out here, so a
    tier added there flows through. The ``ungraded`` token is dropped: it is the
    declared ABSENCE of a grade, so there is no overlay outcome to state for it.
    """
    from adscan_core.reporting.privilege_tier_labels import (  # noqa: PLC0415
        PRIVILEGE_TIER_TOKEN_ORDER,
        TIER_TOKEN_UNGRADED,
    )

    return tuple(t for t in PRIVILEGE_TIER_TOKEN_ORDER if t != TIER_TOKEN_UNGRADED)


def _severity_model_for_finding(key: str) -> dict[str, Any] | None:
    """Return the published severity model for one finding, or ``None``.

    ``None`` means the finding's rating does not move with any published axis,
    and a consumer shows the baseline alone. Two distinct cases collapse into it
    on purpose:

    * the finding carries no tier-keyed elevation rule, so the tier of the
      affected assets is not an input to its rating;
    * it carries one, but the rule cannot raise the baseline (the baseline
      already sits at or above the rule's score, as it does for the two findings
      that start at 9.8). An axis whose every option equals the baseline is an
      inert control, and shipping one claims the rating responds to context when
      it does not.

    Best-effort: a failure on one finding yields ``None`` rather than failing
    generation, matching :func:`_base_vector_for_finding`.
    """
    try:
        from adscan_core.cvss.calculator import (  # noqa: PLC0415
            compute_finding_severity,
        )
        from adscan_core.cvss.models import CvssContext  # noqa: PLC0415
        from adscan_core.reporting.privilege_tier_labels import (  # noqa: PLC0415
            token_is_tier0,
        )
        from adscan_internal.services.compromise_class import (  # noqa: PLC0415
            PrivilegeTier,
            privilege_tier_label,
        )

        baseline = compute_finding_severity(key, CvssContext.empty())

        options: list[dict[str, Any]] = []
        for token in _tier_axis_tokens():
            # The overlay's tier condition IS the Tier 0 containment boundary,
            # so both Tier 0 tokens set it and Tier 1 / Tier 2 do not. That is
            # the engine's own reading (a membership-derived Tier 0 counts), and
            # it is why two options legitimately carry the same outcome.
            result = compute_finding_severity(
                key,
                CvssContext(has_tier_zero_targets=token_is_tier0(token)),
            )
            options.append(
                {
                    "value": token,
                    "label": privilege_tier_label(PrivilegeTier(token)),
                    "score": round(float(result.display_score), 1),
                    "band": result.display_severity,
                    "elevated": bool(result.adscan.is_elevated),
                    "reason": result.adscan.reason or "",
                }
            )
    except Exception:  # noqa: BLE001 - one finding must not fail generation
        return None

    if not any(opt["elevated"] for opt in options):
        return None

    return {
        "baseline": {
            "score": round(float(baseline.display_score), 1),
            "band": baseline.display_severity,
        },
        "axes": [
            {
                "id": _TIER_AXIS_ID,
                "label": _TIER_AXIS_LABEL,
                "options": options,
            }
        ],
    }


def build_severity_model_meta() -> dict[str, Any]:
    """Return the model-level facts a consumer needs in order to read the axes.

    The band table comes from the severity mapper's own published table, the
    same thresholds that produced every ``band`` in the export, so a published
    scale cannot disagree with the grades shown against it. ``version`` is the
    overlay's own methodology version, read off a real result rather than
    written here.
    """
    from adscan_core.cvss.calculator import (  # noqa: PLC0415
        compute_adscan_priority_result,
    )
    from adscan_core.cvss.models import CvssContext  # noqa: PLC0415
    from adscan_core.cvss.severity_mapper import severity_bands  # noqa: PLC0415

    probe = compute_adscan_priority_result("kerberoast", CvssContext.empty())
    return {
        "version": probe.version,
        "bands": [{"label": label, "range": span} for label, span in severity_bands()],
        "axes": [{"id": _TIER_AXIS_ID, "label": _TIER_AXIS_LABEL}],
    }


def build_finding_inventory() -> list[dict[str, Any]]:
    """Return one row per customer-facing reported finding type.

    The companion of :func:`build_technique_inventory` on the other half of the
    product: that one is what ADscan LOOKS FOR, this one is what LANDS IN THE
    REPORT. ``VULN_CATALOG`` is the whole customer-facing finding set with no
    exclusions, which is exactly the filter :func:`build_technique_stats` counts
    for ``finding_count``, so ``len(inventory) == finding_count`` holds by
    construction and a unit test locks it. Publishing a count next to a list
    derived by a different rule is how a page ends up stating one figure and
    enumerating another.

    Severity and CVSS are carried VERBATIM from the catalog. They are claims
    about a client's risk, and a surface that rounds "8.5" or promotes a
    "medium" is making a claim the assessment did not.

    THE CATALOG CVSS NUMBER IS EXPORTED BUT MUST NOT BE PUBLISHED AS A SCORE,
    and the export carries the evidence of why. ``VULN_CATALOG`` gives a
    ``cvss`` to all 93 findings, but only 17 carry a Base VECTOR in
    :mod:`adscan_core.cvss`, and in 14 of those 17 the catalog number
    CONTRADICTS the score its own vector computes (kerberoasting 5.3 against
    4.3, AS-REP roasting 6.9 against 5.3, DCSync 9.8 against 8.8). So for 76
    findings the number is unsourced and for 14 more it disagrees with ADscan's
    own stored vector. A score without a reproducible vector looks computed and
    cannot be checked, and this product's buyer hands the result to an auditor
    whose first question is where 8.5 came from.

    ``severity`` carries no such promise: it is ADscan's own rating, stated as
    ADscan's rating, and it is what the report and the web platform already lead
    with. That is the field a public surface should grade a finding by.

    A reference to NVD does NOT make the number citable either, and the catalog
    proves it from the inside: ``ms17-010`` and ``smb_v1_enabled`` both cite
    CVE-2017-0144 and carry 8.1 and 7.5. One CVE cannot determine two different
    scores, so the reference list is reading material for the finding, not
    attribution for the number. The external anchor exported here is therefore
    ``cve_ids``, which is a checkable fact about the finding; 10 of the 93 name
    one.

    All three stay in the export because the data layer should be FAITHFUL and
    because exporting the vector alongside the number is what makes the
    disagreement visible to the next reader instead of hiding it. The editorial
    decision belongs at the point of publication, not here. Tracked as open in
    BACKLOG.md.

    The MITRE mapping is carried as the catalog's own list, not flattened to a
    primary: fourteen findings map to more than one ATT&CK technique, and
    picking one would drop the rest with nothing saying so. Eight findings carry
    no mapping at all (directory hygiene with no ATT&CK equivalent, such as
    stale computer accounts) and come back with an empty list, which a consumer
    renders as absent rather than guessing an id.

    Returns:
        Rows ordered by severity (worst first), then descending CVSS, then
        title, each containing the catalog ``key``, the reader-facing ``title``,
        the ``severity`` word plus its ``severity_rank``, the ``cvss`` string,
        the ``category`` the catalog files it under, its ``cwe``, the ``mitre``
        list of ``{id, name}`` mappings, the ``cvss_vector`` and the
        ``cvss_vector_score`` computed from it when ADscan stores one (empty and
        ``None`` for the 76 that have neither), the ``cve_ids`` the entry names
        (empty for the 83 that name none), the ``step_relation`` linking it
        back to the technique inventory when the catalog declares one, and the
        ``severity_model`` describing how the finding's RATING responds to the
        privilege tier of the affected assets (``None`` when no published axis
        moves it).
    """
    # Lazy import, for the same reason build_technique_stats does it: this
    # module must stay importable where the ``pro`` package is not installed.
    from adscan_internal.pro.reporting.vuln_catalog import (  # noqa: PLC0415
        VULN_CATALOG,
    )

    rows: list[dict[str, Any]] = []
    for key, entry in VULN_CATALOG.items():
        severity = str(entry.get("severity") or "").strip().lower()
        vector, vector_score = _base_vector_for_finding(key)
        rows.append(
            {
                "key": key,
                "title": (entry.get("title") or "").strip(),
                "severity": severity,
                "severity_rank": _finding_severity_rank(severity),
                "cvss": str(entry.get("cvss") or "").strip(),
                "category": (entry.get("category") or "").strip(),
                "cwe": (entry.get("cwe") or "").strip(),
                "mitre": [
                    {
                        "id": str(m.get("id") or "").strip(),
                        "name": str(m.get("name") or "").strip(),
                    }
                    for m in (entry.get("mitre") or ())
                    if str(m.get("id") or "").strip()
                ],
                # The reproducible half, when ADscan actually has one. Empty
                # vector means no CVSS Base may be presented for the finding at
                # all, which is the rule adscan_core.cvss states itself.
                "cvss_vector": vector,
                "cvss_vector_score": vector_score,
                "cve_ids": _cve_ids_for_entry(entry),
                "step_relation": (entry.get("step_relation") or "").strip(),
                # How this finding's RATING responds to what the assessment
                # observed, driven from the live severity engine. ``None`` for a
                # finding whose rating no published axis moves. See
                # _severity_model_for_finding.
                "severity_model": _severity_model_for_finding(key),
            }
        )

    def _cvss_desc(row: dict[str, Any]) -> float:
        """Sort key only. A malformed score sorts last; it is never rewritten."""
        try:
            return -float(row["cvss"])
        except ValueError:
            return 1.0

    rows.sort(key=lambda r: (r["severity_rank"], _cvss_desc(r), r["title"]))
    return rows


def build_technique_stats() -> dict[str, Any]:
    """Assemble the canonical coverage figures from the live catalogs.

    Returns:
        A dict with:
          - ``technique_count``: number of attack-step techniques excluding the
            ``context`` category.
          - ``finding_count``: number of reported finding types (``VULN_CATALOG``).
          - ``by_category``: technique count per (non-excluded) category, sorted
            by category name for deterministic output.
          - ``adcs_esc_span``: ``ESC<min>–ESC<max>`` computed from the catalog.
    """
    # Lazy import: keeps the module free of a top-level ``pro`` dependency.
    from adscan_internal.pro.reporting.vuln_catalog import (  # noqa: PLC0415
        VULN_CATALOG,
    )

    by_category: dict[str, int] = {}
    supported_count = 0
    for entry in ATTACK_STEP_CATALOG.values():
        cat = getattr(entry, "category", None)
        if not cat or cat in STEP_CATEGORY_EXCLUDE:
            continue
        by_category[cat] = by_category.get(cat, 0) + 1
        # "supported" = ADscan executes the technique end to end (as opposed to
        # unsupported / policy_blocked, which are detected/mapped but not run).
        # This is the "supported AD techniques" figure the platform pages quote,
        # distinct from the total technique count.
        if getattr(entry, "support_kind", None) == "supported":
            supported_count += 1

    by_category = dict(sorted(by_category.items()))
    technique_count = sum(by_category.values())
    finding_count = len(VULN_CATALOG)
    adcs_esc_span = _adcs_esc_span(ATTACK_STEP_CATALOG)

    return {
        "technique_count": technique_count,
        "supported_technique_count": supported_count,
        "finding_count": finding_count,
        "by_category": by_category,
        "adcs_esc_span": adcs_esc_span,
    }


if __name__ == "__main__":  # pragma: no cover - manual inspection helper
    import json

    print(json.dumps(build_technique_stats(), indent=2, ensure_ascii=False))
