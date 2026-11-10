"""Per-host endpoint capability, credential hardening and validated outcome.

Three observed facts about one host, and the one rule that binds them: none of
them is a protection GRADE. Founder decision 2026-11-03
(``adscan-obsidian/business/decisiones-paridad-web-informe-2026-11-03.md``,
section "Proteccion de endpoints").

Capability class (axis 1, an observed fact)
-------------------------------------------
Which kinds of product were ACTIVE on the host: ``none_detected``,
``av_only``, ``edr`` or ``av_and_edr``. It is computed from active products
only. An installed product that is not running is listed separately
(``inactive_protection_label``), because it is protection the client believes
it has, which is a finding in its own right and must never be counted as the
capability the host has.

What this class must NEVER become is "high / medium / low protection". A host
running endpoint detection and response is not thereby well protected: on a
measured engagement the extraction completed on hosts with EDR active. The only
scale the deliverable shows is axis 2.

Validated outcome (axis 2, the only scale)
------------------------------------------
What the assessment PROVED on the host, from the attempts it actually ran:

``gap_proven``       A credential extraction completed while a product was
                     confirmed active on the host.
``held_under_test``  Every realistic low-footprint extraction source was
                     attempted and every one was stopped. The positive control
                     the Exposure-Validation doctrine allows, and never on one
                     method alone (see ``REQUIRED_CREDENTIAL_SOURCES``).
``inconclusive``     Attempts ran with a product active, none completed, but
                     not every realistic source was stopped. Reported as what
                     it is, because calling it "not tested" would erase an
                     interruption the client's SOC can verify, and calling it
                     "held" would credit a control off one method.
``not_tested``       No extraction ran on the host while a product was active.

What feeds ``held_under_test``: the dump seams record an interruption for the
registry reads (SAM, LSA secrets) when the in-place read was cut off on every
retry, and for the LSASS memory read only when EVERY realistic low-footprint
method was attempted with a product active and each was interrupted at the
LSASS open or read (``lsass_orchestrator.lsass_interrupted_on_every_low_footprint_method``).
A caught noisy method (comsvcs, ProcDump) alone never counts, and neither does
a cascade the operator stopped early.

Credential hardening (context, never a score)
---------------------------------------------
LSA protection (``RunAsPPL``) and Credential Guard, each read from the registry
and reported in three states. "Not checked" when the read did not happen, never
"off". Credential Guard is reported as CONFIGURED (a setting turns it on), never
as running: the running state needs a WMI query this assessment does not make.

Both guard credential material in LSASS memory. Neither protects the SAM or the
LSA secrets in the registry, so the "protection was enabled and the read
completed anyway" sentence is only ever stated about an LSASS memory read.

Pure logic: no IO. Imported by :mod:`adscan_core.reporting.endpoint_defense`,
which is why it cannot import that module back; the posture and outcome tokens
it reads are mirrored here and a test asserts they never diverge.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

# ── Mirrored tokens (locked by test against endpoint_defense) ──────────────
_POSTURE_ACTIVE = "active"
_POSTURE_INSTALLED_INACTIVE = "installed_inactive"
_POSTURE_NONE_DETECTED = "none_detected"
#: The postures where the host WAS examined and the result is known, so a
#: capability class can be stated. ``undetermined`` and ``not_assessed`` carry
#: no class at all: "no active product" would be a claim about a host nobody
#: measured.
_ASSESSED_POSTURES = frozenset(
    {_POSTURE_ACTIVE, _POSTURE_INSTALLED_INACTIVE, _POSTURE_NONE_DETECTED}
)
_OUTCOME_COMPLETED = "completed"
_OUTCOME_INTERRUPTED = "interrupted"

# ── Product categories (from the catalog) ──────────────────────────────────
CATEGORY_AV = "av"
CATEGORY_EDR = "edr"

# ── Axis 1: capability class ───────────────────────────────────────────────
CAPABILITY_NONE_DETECTED = "none_detected"
CAPABILITY_AV_ONLY = "av_only"
CAPABILITY_EDR = "edr"
CAPABILITY_AV_AND_EDR = "av_and_edr"
#: An active product whose category the catalog does not carry. Rare, and
#: stated as such rather than guessed into one of the four.
CAPABILITY_UNCLASSIFIED = "unclassified"

CAPABILITY_CLASSES = (
    CAPABILITY_AV_AND_EDR,
    CAPABILITY_EDR,
    CAPABILITY_AV_ONLY,
    CAPABILITY_NONE_DETECTED,
    CAPABILITY_UNCLASSIFIED,
)

#: Client-facing names. Deliberately the product TYPE and nothing more: no word
#: here may grade the protection (a test greps for the grading vocabulary).
CAPABILITY_LABELS: dict[str, str] = {
    CAPABILITY_NONE_DETECTED: "No active product",
    CAPABILITY_AV_ONLY: "Antivirus only",
    CAPABILITY_EDR: "EDR",
    CAPABILITY_AV_AND_EDR: "Antivirus and EDR",
    CAPABILITY_UNCLASSIFIED: "Active product, type not identified",
}

#: What each class means, stated as what was observed and nothing more.
CAPABILITY_MEANINGS: dict[str, str] = {
    CAPABILITY_AV_AND_EDR: (
        "An antivirus and an endpoint detection and response product were both running."
    ),
    CAPABILITY_EDR: (
        "An endpoint detection and response product was running, with no "
        "separate antivirus observed active."
    ),
    CAPABILITY_AV_ONLY: (
        "An antivirus was running and no endpoint detection and response "
        "product was observed active."
    ),
    CAPABILITY_NONE_DETECTED: (
        "No product was observed active. A product installed there but idle is "
        "counted on its own row."
    ),
    CAPABILITY_UNCLASSIFIED: (
        "A product was running whose type this assessment does not identify."
    ),
}

#: The limit of the class, said wherever the class is shown.
CAPABILITY_SCOPE_NOTE = (
    "This names the type of product observed and nothing more. It is not a "
    "measure of how well a host is protected, which only a test can show."
)

#: Why an idle product is its own row and never part of the class.
INACTIVE_PROTECTION_MEANING = (
    "Installed on the host but not running, or running with real-time "
    "protection off. Worth treating as a finding, because it is protection the "
    "host appears to have and does not."
)

#: Said beside ``av_only`` when every active antivirus on the host belongs to a
#: suite that sells endpoint detection and response as a licence on the same
#: agent. The service names the check reads are the same either way, so the
#: class cannot tell the two apart, and a recommendation to "deploy EDR" on a
#: host already running it would be wrong in a way a sysadmin disproves in a
#: minute.
EDR_MODULE_UNCONFIRMED_NOTE = (
    "This product can include an endpoint detection and response component "
    "that this check cannot tell apart from the antivirus, so whether one is "
    "enabled was not confirmed."
)


def product_activity_unconfirmed(product: Mapping[str, Any]) -> bool:
    """Whether a product was seen but its protection state was NOT read.

    The probe treats a Defender real-time-protection state it could not read
    as "on" when it picks a technique, which is the safe choice there and an
    assumption everywhere else. Such a product is neither observed active nor
    observed inactive: the host's protection is undetermined. Before this
    existed, an assumed "on" read as "observed active" in the report and
    could green the anti-malware control.
    """
    if bool(product.get("activity_unconfirmed")):
        return True
    return product.get("realtime_protection_confirmed") is False


def product_is_active(product: Mapping[str, Any]) -> bool:
    """Whether one product entry reads as actively protecting the host.

    Prefers the runtime's own derived ``active``. Falls back to the same rule
    the runtime applies (``DetectedProduct.active``): process-running AND
    real-time protection on, where running is either observed directly or
    implied by an auto-start service. The SSOT for this rule:
    ``endpoint_defense.classify_host_posture`` reads it from here. A product
    whose protection state was assumed rather than read is never active here
    (see :func:`product_activity_unconfirmed`).
    """
    if product_activity_unconfirmed(product):
        return False
    if "active" in product:
        return bool(product.get("active"))
    running = bool(product.get("running"))
    installed = bool(product.get("installed"))
    try:
        svc_start = int(product.get("svc_start"))
    except (TypeError, ValueError):
        svc_start = -1
    process_running = running or (installed and svc_start in (0, 1, 2))
    return process_running and bool(product.get("realtime_protection", True))


def _rows(products: Any) -> list[Mapping[str, Any]]:
    return [p for p in (products or ()) if isinstance(p, Mapping)]


def _category(product: Mapping[str, Any]) -> str:
    return str(product.get("category") or "").strip().lower()


def _names(products: Iterable[Mapping[str, Any]]) -> list[str]:
    names: list[str] = []
    for product in products:
        name = str(product.get("name") or "").strip()
        if name and name not in names:
            names.append(name)
    return names


def active_products(products: Any) -> list[Mapping[str, Any]]:
    """The product entries that were active on the host."""
    return [p for p in _rows(products) if product_is_active(p)]


def inactive_products(products: Any) -> list[Mapping[str, Any]]:
    """The product entries OBSERVED present on the host and not active.

    A product whose protection state could not be read is neither active nor
    inactive, so it is not listed here.
    """
    return [
        p
        for p in _rows(products)
        if not product_is_active(p) and not product_activity_unconfirmed(p)
    ]


def unconfirmed_products(products: Any) -> list[Mapping[str, Any]]:
    """The product entries seen on the host whose protection state was not read."""
    return [p for p in _rows(products) if product_activity_unconfirmed(p)]


def classify_host_capability(products: Any, posture: Any) -> str:
    """The capability class of one host, from its ACTIVE products only.

    Returns ``""`` when the host's posture was not determined, because no class
    can be stated about a host nobody measured.
    """
    if str(posture or "") not in _ASSESSED_POSTURES:
        return ""
    categories = {_category(p) for p in active_products(products)}
    has_av = CATEGORY_AV in categories
    has_edr = CATEGORY_EDR in categories
    if has_av and has_edr:
        return CAPABILITY_AV_AND_EDR
    if has_edr:
        return CAPABILITY_EDR
    if has_av:
        return CAPABILITY_AV_ONLY
    if categories:
        return CAPABILITY_UNCLASSIFIED
    return CAPABILITY_NONE_DETECTED


def capability_label(token: Any) -> str:
    """The client-facing name for a capability token, ``""`` for none."""
    return CAPABILITY_LABELS.get(str(token or ""), "")


def edr_module_unconfirmed(products: Any, capability: Any) -> bool:
    """Whether an ``av_only`` reading may be hiding an EDR licence.

    True only when the host reads ``av_only`` and EVERY active antivirus on it
    is flagged by the catalog as a suite whose EDR component this check cannot
    see. One plainly antivirus-only product among them is enough to keep the
    reading as stated.
    """
    if str(capability or "") != CAPABILITY_AV_ONLY:
        return False
    avs = [p for p in active_products(products) if _category(p) == CATEGORY_AV]
    return bool(avs) and all(bool(p.get("edr_module_indistinguishable")) for p in avs)


def _class_phrase(categories: set[str]) -> str:
    has_av = CATEGORY_AV in categories
    has_edr = CATEGORY_EDR in categories
    if has_av and has_edr:
        return "Antivirus and EDR"
    if has_edr:
        return "EDR"
    if has_av:
        return "Antivirus"
    return "Product"


def inactive_protection_label(products: Any) -> str:
    """What is installed on the host but not active, by class, or ``""``.

    "EDR installed, not active" is the reading the founder asked for in so many
    words: it is protection the client believes the host has, and it is listed
    apart from the capability class so that class never counts it.
    """
    idle = inactive_products(products)
    if not idle:
        return ""
    return f"{_class_phrase({_category(p) for p in idle})} installed, not active"


def inactive_classes(products: Any) -> list[str]:
    """The catalog categories present on the host but not active."""
    seen: list[str] = []
    for product in inactive_products(products):
        category = _category(product)
        if category in (CATEGORY_AV, CATEGORY_EDR) and category not in seen:
            seen.append(category)
    return seen


def capability_rows(counts: Mapping[str, int]) -> list[dict[str, Any]]:
    """Render-ready class rows (label, meaning, hosts), in a stable order.

    The one builder every surface reads, so no renderer keeps a label map.
    """
    return [
        {
            "capability_class": token,
            "label": capability_label(token),
            "meaning": CAPABILITY_MEANINGS.get(token, ""),
            "hosts": int(counts[token]),
        }
        for token in CAPABILITY_CLASSES
        if counts.get(token)
    ]


def inactive_rows(counts: Mapping[str, int]) -> list[dict[str, Any]]:
    """Render-ready rows for what sits installed but not active, EDR first."""
    return [
        {
            "category": category,
            "label": f"{_class_phrase({category})} installed, not active",
            "meaning": INACTIVE_PROTECTION_MEANING,
            "hosts": int(counts[category]),
        }
        for category in (CATEGORY_EDR, CATEGORY_AV)
        if counts.get(category)
    ]


def product_names(products: Any) -> tuple[list[str], list[str]]:
    """``(active names, inactive names)`` for a host, order preserved."""
    return _names(active_products(products)), _names(inactive_products(products))


# ── Credential hardening ───────────────────────────────────────────────────
HARDENING_NOT_CHECKED = "not_checked"
LSA_PROTECTION_ENABLED = "enabled"
LSA_PROTECTION_NOT_ENABLED = "not_enabled"
CREDENTIAL_GUARD_CONFIGURED = "configured"
CREDENTIAL_GUARD_NOT_CONFIGURED = "not_configured"

LSA_PROTECTION_STATES = (
    LSA_PROTECTION_ENABLED,
    LSA_PROTECTION_NOT_ENABLED,
    HARDENING_NOT_CHECKED,
)
CREDENTIAL_GUARD_STATES = (
    CREDENTIAL_GUARD_CONFIGURED,
    CREDENTIAL_GUARD_NOT_CONFIGURED,
    HARDENING_NOT_CHECKED,
)

LSA_PROTECTION_LABELS: dict[str, str] = {
    LSA_PROTECTION_ENABLED: "Enabled",
    LSA_PROTECTION_NOT_ENABLED: "Not enabled",
    HARDENING_NOT_CHECKED: "Not checked",
}
CREDENTIAL_GUARD_LABELS: dict[str, str] = {
    CREDENTIAL_GUARD_CONFIGURED: "Configured",
    CREDENTIAL_GUARD_NOT_CONFIGURED: "Not configured",
    HARDENING_NOT_CHECKED: "Not checked",
}

#: The limit of the Credential Guard reading, carried WITH the data so no
#: surface can show the state without it. Authored once, read verbatim.
CREDENTIAL_GUARD_SCOPE_NOTE = (
    "Credential Guard is read from its registry configuration. Configured "
    "means a setting turns it on. Whether it was running on the host was not "
    "checked, and recent Windows editions can turn it on by default on "
    "eligible hardware without either setting, so not configured does not "
    "mean it is off."
)

#: Why the hardening states sit beside the outcome and never change it.
HARDENING_SCOPE_NOTE = (
    "LSA protection and Credential Guard guard the credentials held in memory. "
    "Neither protects the SAM or the LSA secrets stored in the registry, so "
    "they are context for a memory read and say nothing about a registry read."
)

_STATE_PRESENT = "present"
_STATE_ABSENT = "absent"


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def lsa_protection_from_registry(state: Any, value: Any) -> str:
    """LSA protection from the collector's ``RunAsPPL`` read.

    Mirrors the ``lsa_protection_disabled`` finding exactly (absent or 0 reads
    not enabled), so the per-host state and the finding cannot disagree about
    the same host. A failed or skipped read is ``not_checked``, never "not
    enabled".
    """
    token = str(state or "").strip().lower()
    if token == _STATE_PRESENT:
        number = _int_or_none(value)
        return (
            LSA_PROTECTION_ENABLED
            if number is not None and number > 0
            else LSA_PROTECTION_NOT_ENABLED
        )
    if token == _STATE_ABSENT:
        return LSA_PROTECTION_NOT_ENABLED
    return HARDENING_NOT_CHECKED


def credential_guard_from_registry(
    *,
    lsa_state: Any,
    lsa_value: Any,
    policy_state: Any,
    policy_value: Any,
) -> str:
    """Credential Guard CONFIGURATION from the two places it is set.

    ``HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LsaCfgFlags`` (set directly)
    and ``HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard\\LsaCfgFlags``
    (set by Group Policy). 1 turns it on with a UEFI lock, 2 without one.

    ``configured`` as soon as either location turns it on. ``not_configured``
    only when BOTH locations were read and neither does, because an unread
    location may be the one that turns it on. Never "running", see
    :data:`CREDENTIAL_GUARD_SCOPE_NOTE`.
    """
    observed = 0
    for state, value in ((lsa_state, lsa_value), (policy_state, policy_value)):
        token = str(state or "").strip().lower()
        if token == _STATE_PRESENT:
            observed += 1
            if (_int_or_none(value) or 0) in (1, 2):
                return CREDENTIAL_GUARD_CONFIGURED
        elif token == _STATE_ABSENT:
            observed += 1
    if observed == 2:
        return CREDENTIAL_GUARD_NOT_CONFIGURED
    return HARDENING_NOT_CHECKED


def normalize_lsa_protection(value: Any, *, ppl_enabled: Any = None) -> str:
    """A persisted LSA protection token, with the legacy ``ppl_enabled`` fallback.

    The legacy boolean only ever upgrades to ``enabled``: a ``False`` there was
    written both for a value of 0 and for a read that failed, so it cannot
    support "not enabled" and reads ``not_checked``.
    """
    token = str(value or "").strip().lower()
    if token in LSA_PROTECTION_STATES:
        return token
    if ppl_enabled is True:
        return LSA_PROTECTION_ENABLED
    return HARDENING_NOT_CHECKED


def normalize_credential_guard(value: Any) -> str:
    token = str(value or "").strip().lower()
    return token if token in CREDENTIAL_GUARD_STATES else HARDENING_NOT_CHECKED


# ── Axis 2: validated outcome ──────────────────────────────────────────────
VALIDATED_GAP_PROVEN = "gap_proven"
VALIDATED_HELD_UNDER_TEST = "held_under_test"
VALIDATED_INCONCLUSIVE = "inconclusive"
VALIDATED_NOT_TESTED = "not_tested"

#: Worst reading first: the order a host list is read in.
VALIDATED_OUTCOMES = (
    VALIDATED_GAP_PROVEN,
    VALIDATED_INCONCLUSIVE,
    VALIDATED_HELD_UNDER_TEST,
    VALIDATED_NOT_TESTED,
)

VALIDATED_OUTCOME_LABELS: dict[str, str] = {
    VALIDATED_GAP_PROVEN: "Gap proven",
    VALIDATED_HELD_UNDER_TEST: "Held under test",
    VALIDATED_INCONCLUSIVE: "Interrupted, not every method tried",
    VALIDATED_NOT_TESTED: "Not tested",
}

VALIDATED_OUTCOME_MEANINGS: dict[str, str] = {
    VALIDATED_GAP_PROVEN: (
        "Credential material was extracted from this host while an endpoint "
        "product was confirmed active."
    ),
    VALIDATED_HELD_UNDER_TEST: (
        "Every realistic low-footprint way of reading credential material was "
        "attempted on this host, and every one was interrupted."
    ),
    VALIDATED_INCONCLUSIVE: (
        "Extraction was attempted with a product active and did not complete, "
        "but not every realistic method was tried, so this is not a verdict "
        "that the host held."
    ),
    VALIDATED_NOT_TESTED: (
        "No credential extraction ran on this host while a product was active, "
        "so its protection was observed but not tested."
    ),
}

#: Where credential material lives on a Windows host, by the technique that
#: reads it. Every one must be stopped before a host may read as held: a real
#: attacker who loses the registry read moves on to memory.
_SOURCE_SAM = "sam"
_SOURCE_LSA_SECRETS = "lsa_secrets"
_SOURCE_LSASS_MEMORY = "lsass_memory"
REQUIRED_CREDENTIAL_SOURCES = frozenset(
    {_SOURCE_SAM, _SOURCE_LSA_SECRETS, _SOURCE_LSASS_MEMORY}
)
TECHNIQUE_CREDENTIAL_SOURCES: dict[str, tuple[str, ...]] = {
    "dumpsam": (_SOURCE_SAM,),
    "dumplsa": (_SOURCE_LSA_SECRETS,),
    "backupoperatordump": (_SOURCE_SAM, _SOURCE_LSA_SECRETS),
    "dumplsass": (_SOURCE_LSASS_MEMORY,),
}

#: The one technique whose result LSA protection and Credential Guard bear on.
LSASS_MEMORY_TECHNIQUE = "dumplsass"


def _pair_completed(pair: Mapping[str, Any]) -> bool:
    if str(pair.get("outcome") or "") == _OUTCOME_COMPLETED:
        return True
    try:
        return int(pair.get(_OUTCOME_COMPLETED) or 0) > 0
    except (TypeError, ValueError):
        return False


def derive_validated_outcome(pairs: Iterable[Any], host_posture: Any = None) -> str:
    """The validated outcome for ONE host, from its technique-host rows.

    Args:
        pairs: The host's folded technique rows (``technique``, ``outcome``,
            ``posture``), one per technique.
        host_posture: The host's posture from the inventory, when it has one.
            A host whose inventory says no product was active cannot have a
            product test, whatever the attempts recorded.
    """
    if host_posture is not None and str(host_posture) != _POSTURE_ACTIVE:
        return VALIDATED_NOT_TESTED
    tested = [
        p
        for p in (pairs or ())
        if isinstance(p, Mapping) and str(p.get("posture") or "") == _POSTURE_ACTIVE
    ]
    if not tested:
        return VALIDATED_NOT_TESTED
    if any(_pair_completed(p) for p in tested):
        return VALIDATED_GAP_PROVEN
    stopped: set[str] = set()
    for pair in tested:
        if str(pair.get("outcome") or "") != _OUTCOME_INTERRUPTED:
            continue
        technique = str(pair.get("technique") or "").strip().lower()
        stopped.update(TECHNIQUE_CREDENTIAL_SOURCES.get(technique, ()))
    if REQUIRED_CREDENTIAL_SOURCES <= stopped:
        return VALIDATED_HELD_UNDER_TEST
    return VALIDATED_INCONCLUSIVE


def validated_outcome_label(token: Any) -> str:
    return VALIDATED_OUTCOME_LABELS.get(str(token or ""), "")


def validated_outcome_rank(token: Any) -> int:
    text = str(token or "")
    return (
        VALIDATED_OUTCOMES.index(text)
        if text in VALIDATED_OUTCOMES
        else len(VALIDATED_OUTCOMES)
    )


# ── Tier 0 coverage recommendation ─────────────────────────────────────────
#: The classes that put a Tier 0 host in the recommendation. A host running
#: EDR (alone or beside an antivirus) is out of it, and so is an
#: ``unclassified`` one, because a recommendation to deploy something the host
#: may already run is wrong.
_RECOMMEND_CLASSES = frozenset({CAPABILITY_AV_ONLY, CAPABILITY_NONE_DETECTED})


def _host_action(row: Mapping[str, Any]) -> str:
    if CATEGORY_EDR in (row.get("inactive_classes") or ()):
        return (
            "An endpoint detection and response product is installed on this "
            "host but not active. Restore it."
        )
    if row.get("edr_module_unconfirmed"):
        products = ", ".join(str(n) for n in (row.get("active_products") or ()))
        subject = (
            f"the endpoint detection and response component of {products}"
            if products
            else "the suite's endpoint detection and response component"
        )
        return (
            f"Confirm that {subject} is licensed and enabled on this host. If it "
            "is not, deploy one."
        )
    if str(row.get("capability_class") or "") == CAPABILITY_AV_ONLY:
        return (
            "Deploy an endpoint detection and response product on this host, "
            "alongside the antivirus."
        )
    return "Deploy an endpoint detection and response product on this host."


def recommendation_text(count: int, tier0_examined: int) -> str:
    """The recommendation sentence, worded as a recommendation and never a verdict."""
    if count <= 0:
        return ""
    if tier0_examined == 1:
        lead = "The one Tier 0 host examined showed"
    else:
        lead = f"{count:,} of the {tier0_examined:,} Tier 0 hosts examined showed"
    return (
        "We recommend running endpoint detection and response on every Tier 0 "
        "host, because those hosts control the domain's identity. "
        f"{lead} no active EDR product. This is a recommendation about the type of "
        "product observed, not a measure of how well those hosts are protected."
    )


def build_tier0_edr_recommendation(
    host_rows: Iterable[Any], *, is_tier0: Any
) -> dict[str, Any]:
    """The Tier 0 coverage recommendation over a block's host rows.

    Args:
        host_rows: Rows carrying ``privilege_tier``, ``capability_class``,
            ``edr_module_unconfirmed``, ``inactive_classes`` and the labels.
        is_tier0: The tier predicate, injected so this module keeps no second
            copy of the Tier 0 tokens.
    """
    tier0_examined = 0
    hosts: list[dict[str, Any]] = []
    for row in host_rows or ():
        if not isinstance(row, Mapping) or not is_tier0(row.get("privilege_tier")):
            continue
        capability = str(row.get("capability_class") or "")
        if not capability:
            continue
        tier0_examined += 1
        if capability not in _RECOMMEND_CLASSES:
            continue
        hosts.append(
            {
                "host": str(row.get("host") or ""),
                "privilege_tier": str(row.get("privilege_tier") or ""),
                "privilege_tier_label": str(row.get("privilege_tier_label") or ""),
                "capability_class": capability,
                "capability_label": capability_label(capability),
                "edr_module_unconfirmed": bool(row.get("edr_module_unconfirmed")),
                "action": _host_action(row),
            }
        )
    return {
        "hosts": hosts,
        "count": len(hosts),
        "tier0_examined": tier0_examined,
        "text": recommendation_text(len(hosts), tier0_examined),
    }


def empty_recommendation() -> dict[str, Any]:
    return {"hosts": [], "count": 0, "tier0_examined": 0, "text": ""}


__all__ = [
    "CAPABILITY_AV_AND_EDR",
    "CAPABILITY_AV_ONLY",
    "CAPABILITY_CLASSES",
    "CAPABILITY_EDR",
    "CAPABILITY_LABELS",
    "CAPABILITY_MEANINGS",
    "CAPABILITY_SCOPE_NOTE",
    "CAPABILITY_NONE_DETECTED",
    "CAPABILITY_UNCLASSIFIED",
    "CATEGORY_AV",
    "CATEGORY_EDR",
    "CREDENTIAL_GUARD_CONFIGURED",
    "CREDENTIAL_GUARD_LABELS",
    "CREDENTIAL_GUARD_NOT_CONFIGURED",
    "CREDENTIAL_GUARD_SCOPE_NOTE",
    "CREDENTIAL_GUARD_STATES",
    "EDR_MODULE_UNCONFIRMED_NOTE",
    "HARDENING_NOT_CHECKED",
    "HARDENING_SCOPE_NOTE",
    "INACTIVE_PROTECTION_MEANING",
    "LSASS_MEMORY_TECHNIQUE",
    "LSA_PROTECTION_ENABLED",
    "LSA_PROTECTION_LABELS",
    "LSA_PROTECTION_NOT_ENABLED",
    "LSA_PROTECTION_STATES",
    "REQUIRED_CREDENTIAL_SOURCES",
    "TECHNIQUE_CREDENTIAL_SOURCES",
    "VALIDATED_GAP_PROVEN",
    "VALIDATED_HELD_UNDER_TEST",
    "VALIDATED_INCONCLUSIVE",
    "VALIDATED_NOT_TESTED",
    "VALIDATED_OUTCOMES",
    "VALIDATED_OUTCOME_LABELS",
    "VALIDATED_OUTCOME_MEANINGS",
    "active_products",
    "build_tier0_edr_recommendation",
    "capability_label",
    "capability_rows",
    "classify_host_capability",
    "credential_guard_from_registry",
    "derive_validated_outcome",
    "edr_module_unconfirmed",
    "empty_recommendation",
    "inactive_classes",
    "inactive_products",
    "inactive_protection_label",
    "inactive_rows",
    "lsa_protection_from_registry",
    "normalize_credential_guard",
    "normalize_lsa_protection",
    "product_is_active",
    "product_names",
    "recommendation_text",
    "validated_outcome_label",
    "validated_outcome_rank",
]
