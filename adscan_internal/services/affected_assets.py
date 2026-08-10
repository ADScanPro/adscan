"""Resolve which objects a finding is about — shared by both report tiers.

This is a RESOLUTION pass over data the workspace already holds: given a
finding's key and its persisted ``details``, it decides which accounts, hosts,
shares, certificate templates, issuing authorities and artifacts the finding
affects, and normalises them into display strings a reader can act on. It
decides WHICH OBJECT a finding is about — never what to tell the client about
it. The remediation prose, the compliance mapping and the bonus documents stay
paid; this does not.

It lives under ``adscan_internal/services`` (LITE-safe) rather than
``adscan_internal/pro`` because the free exposure report
(:mod:`adscan_internal.services.lite_html_report`) is the only artifact most
readers ever see, and a finding that names no object is one the reader cannot
act on. Both tiers resolve assets through this one implementation, so the free
report and the paid kit can never name different objects for the same finding.

The prose that USES these assets — the per-instance "specifics" sentence woven
into a finding's narrative and remediation — is product knowledge and stays in
``adscan_internal/pro/reporting/finding_specifics.py``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import re
from typing import Any

from adscan_core.reporting.vuln_catalog_meta import VULN_CATALOG_STEP_RELATIONS
from adscan_internal.services.adcs_path_display import extract_adcs_template_names
from adscan_internal.services.affected_asset_rules import (
    AssetRule,
    Extra,
    Scope,
    SourceMode,
    TargetMode,
    extract_adcs_ca_names,
    rule_for,
)
from adscan_internal.services.compromise_class import is_direct_domain_breaker_target

#: Reserved key under a finding's ``details`` carrying the engine's typed,
#: correlation-ready affected-asset entities. Declared here — the base module —
#: so the flat resolution and the structured one cannot disagree about where
#: they live; :data:`affected_assets_struct.SERIALIZED_KEY` is its alias, and
#: that is the name the platform contract is documented under.
SERIALIZED_ENTITIES_KEY = "_affected_assets_struct"

#: The flat, client-facing type name for each structured entity type. The typed
#: vocabulary the platform correlates on says ``computer``; every flat surface
#: (the appendix CSV column, the asset-type counts, the priority ladder) has
#: always said ``host``, so the translation happens here rather than by
#: renaming a column the client's GRC import already maps.
_FLAT_TYPE_BY_ENTITY_TYPE: dict[str, str] = {
    "computer": "host",
    "user": "user",
    "group": "group",
    "domain": "domain",
    "template": "template",
    "ca": "ca",
    "share": "share",
    "artifact": "artifact",
    "credential": "credential",
}

#: Entity types whose flat string carries a ``Template: ``-style prefix that
#: :func:`classify_asset_type` already reads. Indexing their bare names would
#: risk a collision — a template called ``Administrator`` would then re-type the
#: account of the same name — so only principal entities go in the index.
_PREFIXED_ENTITY_TYPES: frozenset[str] = frozenset(
    {"template", "ca", "share", "artifact", "credential"}
)

_DIRECT_ASSET_KEYS: tuple[str, ...] = (
    "admin_users",
    "priv_users",
    "general_users",
    "all_users",
    "users",
    "all_computers",
    "computers",
    "hosts",
    "hostnames",
    "affected_assets",
    "affected_hosts",
    "affected_computers",
    "vulnerable_hosts",
    "vulnerable_computers",
    "dcs",
    "non_dcs",
    "servers",
    "workstations",
    "sample",
)

_IGNORED_KEYS: tuple[str, ...] = (
    "_affected_assets",
    "_evidence",
    "attack_graph_edges",
    "count",
    "status",
    "value",
)

_SOURCE_RELEVANT_RELATIONS: tuple[str, ...] = ("hassession",)

_ADCS_RELATIONS: tuple[str, ...] = (
    "adcsesc1",
    "adcsesc2",
    "adcsesc3",
    "adcsesc4",
    "adcsesc5",
    "adcsesc6",
    "adcsesc7",
    "adcsesc8",
    "adcsesc9",
    "adcsesc10",
    "adcsesc11",
    "adcsesc13",
    "adcsesc14",
    "adcsesc15",
    "adcsesc16",
    "adcsesc17",
)

_CONTEXT_DETAIL_KEYS_BY_RELATION: dict[str, tuple[str, ...]] = {
    "passwordinshare": (
        "host",
        "hostname",
        "hosts",
        "hosts_list",
        "share",
        "shares",
        "shares_list",
        "artifact",
    ),
    "passwordinfile": (
        "host",
        "hostname",
        "artifact",
    ),
    "gpppassword": (
        "artifact",
        "source_xml",
    ),
}

# Maximum number of affected assets rendered inline in any deliverable PDF
# (executive report, AD Hardening Playbook). Above this, the PDF shows the top
# INLINE_AFFECTED_ASSETS_CAP prioritized assets plus a single overflow line that
# points the reader at the bundled machine-readable appendix. Tune here only —
# this is the one knob every render path reads. Kept generous enough that small
# and mid-size findings still list every asset, but bounded so a posture finding
# with thousands of affected hosts can never bloat the PDF or the render path.
INLINE_AFFECTED_ASSETS_CAP = 25

# Filename of the bundled complete affected-asset record, referenced verbatim by
# the overflow line so the reader knows exactly where the untruncated list lives.
AFFECTED_ASSETS_APPENDIX_FILENAME = "affected_assets_appendix.csv"


def _is_non_empty_string(value: Any) -> bool:
    """Return True when value is a meaningful non-empty string."""
    return isinstance(value, str) and bool(value.strip()) and value != "NS"


def _extend_unique(target: list[str], values: Iterable[str]) -> None:
    """Append string values preserving order and uniqueness."""
    seen = set(target)
    for value in values:
        normalized = value.strip()
        if not normalized or normalized in seen:
            continue
        target.append(normalized)
        seen.add(normalized)


def _extract_strings(value: Any) -> list[str]:
    """Extract string leaves from a nested list-like value."""
    if _is_non_empty_string(value):
        return [str(value).strip()]
    if isinstance(value, list):
        results: list[str] = []
        for item in value:
            _extend_unique(results, _extract_strings(item))
        return results
    if isinstance(value, tuple):
        results = []
        for item in value:
            _extend_unique(results, _extract_strings(item))
        return results
    return []


#: ``details`` keys that can carry the share a secret was recovered from, most
#: precise first. ``secret_locations`` is the per-hit record the share-secret
#: scan persists (it carries the full UNC path of the file); the rest are the
#: bare share names the collector / attack-graph edges carry.
SECRET_LOCATION_KEY = "secret_locations"
_SHARE_NAME_KEYS: tuple[str, ...] = (
    "share_path",
    "share",
    "shares",
    "shares_list",
    "share_name",
)


def _split_joined_display_tokens(value: str) -> list[str]:
    """Split a human comma-joined token (``"DEV, HR, SYSVOL"``) into its parts.

    Attack-graph edge notes carry a share list twice: ``shares_list`` (the real
    list) and ``shares`` (the same list pre-joined for display). Reading both
    produced a bogus affected asset whose identifier was the whole joined
    string. Splitting here means either form yields the same tokens.

    A path-like value is returned untouched — a file name may legally contain a
    comma, and splitting a UNC locator would corrupt it.
    """
    text = str(value or "").strip()
    if not text:
        return []
    if "," not in text or "\\" in text or "/" in text:
        return [text]
    return [part for part in (part.strip() for part in text.split(",")) if part]


def extract_share_locations(details: Any) -> list[str]:
    """Return where a share-borne secret actually lives, most precise first.

    Prefers the per-hit UNC path the share-secret scan persists under
    ``details.secret_locations[].unc`` (``\\\\host\\share\\dir\\file.ext``) — that
    is the locator an operator opens to clear the file. Falls back to the bare
    share name(s) only when no path was resolved, and never returns the
    comma-joined display form of a share list.
    """
    view = details if isinstance(details, dict) else {}
    if not view:
        return []

    locations: list[str] = []
    raw_locations = view.get(SECRET_LOCATION_KEY)
    if isinstance(raw_locations, list):
        for entry in raw_locations:
            if not isinstance(entry, dict):
                _extend_unique(locations, _extract_strings(entry))
                continue
            for key in ("unc", "path", "share"):
                value = entry.get(key)
                if _is_non_empty_string(value):
                    _extend_unique(locations, [str(value).strip()])
                    break
    if locations:
        return locations

    for key in _SHARE_NAME_KEYS:
        for value in _extract_strings(view.get(key)):
            _extend_unique(locations, _split_joined_display_tokens(value))
    return locations


def _is_direct_domain_breaker_asset(asset: str) -> bool:
    """Return True when *asset* names a direct domain-breaker target.

    Attack-path/edge extraction picks up the path terminal, which for an
    escalation finding (ADCS ESC1, etc.) is the destination principal — e.g.
    ``DOMAIN ADMINS@ESSOS.LOCAL``, ``Enterprise Admins``, ``krbtgt`` or a DC.
    Those destinations are not the *affected* asset of the finding (the
    vulnerable object + source principals are); they are merely where the path
    ends, so they must be dropped from the affected-assets list.

    Delegates the name resolution (including the ``@domain`` strip) to the
    nomenclature SSOT :func:`is_direct_domain_breaker_target`. A bare domain
    object name (``ESSOS.LOCAL``) is NOT a breaker principal here, so it is
    preserved — domain-wide findings (DCSync) keep the domain as affected.
    """
    text = str(asset or "").strip()
    if not text:
        return False
    return is_direct_domain_breaker_target({"name": text})


def _drop_direct_domain_breaker_assets(assets: Iterable[str]) -> list[str]:
    """Filter out direct domain-breaker targets, keeping every other asset."""
    return [asset for asset in assets if not _is_direct_domain_breaker_asset(asset)]


#: Tokens that are container/realm placeholders, never a concrete principal.
PLACEHOLDER_ASSET_TOKENS = frozenset({"(domain)", "domain", "n/a", "ns", "-", ""})

#: Separator between a principal and the part of it that is affected, e.g.
#: ``david.orelious · description``. Shared by the flat and structured sides so
#: the PDF and the platform render the same label.
ACCOUNT_QUALIFIER_SEPARATOR = " · "

_ACCOUNT_CONTAINER_KEYS: tuple[str, ...] = ("accounts", "hosts")
_ACCOUNT_NAME_KEYS: tuple[str, ...] = (
    "samaccountname",
    "sAMAccountName",
    "name",
    "hostname",
)


def _format_record_qualifier(entry: Mapping[str, Any], qualifier_key: str) -> str:
    """Return the qualifier text for one record, joining a list value.

    A qualifier may be a scalar (the LDAP attribute holding a secret) or a list
    (every HTTP SPN a principal publishes). A list is joined rather than
    stringified, so the reader gets ``CASTELBLACK$ · HTTP/web01.corp.local``
    instead of a Python repr.
    """
    if not qualifier_key:
        return ""
    raw = entry.get(qualifier_key)
    if isinstance(raw, (list, tuple)):
        return ", ".join(_extract_strings(list(raw)))
    return str(raw or "").strip()


def format_account_display(name: str, qualifier: str = "") -> str:
    """Return the display label for one affected principal record."""
    base = str(name or "").strip()
    detail = str(qualifier or "").strip()
    if base and detail:
        return f"{base}{ACCOUNT_QUALIFIER_SEPARATOR}{detail}"
    return base


def iter_account_records(
    details: Any,
    *,
    rule: AssetRule | None = None,
) -> list[tuple[str, str, str]]:
    """Return ``(name, object_sid, qualifier)`` for each principal a finding carries.

    Host- and account-scoped findings (SMB signing, SMBv1, password-not-required,
    stale passwords, secrets in a directory attribute) carry their affected
    principals as a list of dicts, keyed by ``samaccountname`` with an
    ``object_id`` companion. The generic extractor only understands string leaves
    and flat lists, so these dicts are skipped and the bare-domain fallback fires
    — this is the single walker that recovers them, shared by the flat display
    list and the structured entities so the two can never disagree.

    Beyond the conventional ``accounts`` / ``hosts`` containers it reads the
    detector-specific containers the finding's :class:`AssetRule` declares, and
    carries that rule's qualifier field (e.g. the LDAP attribute holding the
    secret) alongside each principal. A rule may also declare which field NAMES
    the record, for a detector that keys its records on its own vocabulary (a
    trust names its counterpart ``partner``).
    """
    if not isinstance(details, dict):
        return []
    containers = list(_ACCOUNT_CONTAINER_KEYS)
    qualifier_key = ""
    name_keys = list(_ACCOUNT_NAME_KEYS)
    if rule is not None:
        containers.extend(rule.record_containers)
        qualifier_key = rule.record_qualifier
        if rule.record_name_field:
            name_keys.insert(0, rule.record_name_field)

    records: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for container_key in containers:
        container = details.get(container_key)
        # A detector that observes exactly one principal persists it as a bare
        # string (``captured_user``), not a list. Read it as a one-entry
        # container so a rule can name it without a second vocabulary.
        if _is_non_empty_string(container):
            container = [container]
        if not isinstance(container, list):
            continue
        for entry in container:
            if not isinstance(entry, dict):
                for value in _extract_strings(entry):
                    key = (value.strip().lower(), "")
                    if value.strip().lower() in PLACEHOLDER_ASSET_TOKENS or key in seen:
                        continue
                    seen.add(key)
                    records.append((value.strip(), "", ""))
                continue
            name = ""
            for name_key in name_keys:
                value = entry.get(name_key)
                if _is_non_empty_string(value):
                    name = str(value).strip()
                    break
            if not name or name.lower() in PLACEHOLDER_ASSET_TOKENS:
                continue
            sid = str(entry.get("object_id") or entry.get("sid") or "").strip()
            qualifier = _format_record_qualifier(entry, qualifier_key)
            key = (name.lower(), qualifier.lower())
            if key in seen:
                continue
            seen.add(key)
            records.append((name, sid, qualifier))
    return _drop_subsumed_records(records)


def _drop_subsumed_records(
    records: list[tuple[str, str, str]],
) -> list[tuple[str, str, str]]:
    """Drop a bare record that a richer record for the same principal covers.

    A finding can carry the same principal through two containers written by two
    detectors, at different fidelity. Two shapes recur, and both read to a client
    as two affected objects when they are one:

    * ``jdoe`` alongside ``jdoe · description`` — one detector says WHICH
      attribute holds the secret, the other does not. The qualified record is
      strictly more informative, so the bare one goes.
    * ``MEEREEN`` alongside ``MEEREEN$`` — one detector persists a plain host
      list, the other the machine account with its SID. Only the record carrying
      the SID names a directory object, so the bare hostname goes.

    The second fold is deliberately narrow: it applies only when the bare record
    has no SID of its own and a ``$``-suffixed record for the same base name
    does, which is exactly the plain-host-list case and not a user who happens to
    share a name with a computer account.
    """
    qualified = {
        name.strip().lower() for name, _sid, qualifier in records if qualifier.strip()
    }
    identified = {
        name.strip().lower().rstrip("$") for name, sid, _q in records if sid.strip()
    }
    if not qualified and not identified:
        return records
    kept: list[tuple[str, str, str]] = []
    for name, sid, qualifier in records:
        lowered = name.strip().lower()
        if not qualifier.strip() and lowered in qualified:
            continue
        if not sid.strip() and lowered.rstrip("$") in identified:
            continue
        kept.append((name, sid, qualifier))
    return kept


def _extract_account_assets(details: Any, *, rule: AssetRule | None = None) -> list[str]:
    """Return the display labels for the principals a finding carries itself."""
    assets: list[str] = []
    for name, _sid, qualifier in iter_account_records(details, rule=rule):
        _extend_unique(assets, [format_account_display(name, qualifier)])
    return assets


def _looks_like_artifact(value: str) -> bool:
    """Return True when a value looks like a file/share artifact."""
    lower = value.lower()
    if "/" in value or "\\" in value:
        return True
    return lower.endswith(
        (
            ".xml",
            ".txt",
            ".log",
            ".csv",
            ".json",
            ".ini",
            ".conf",
            ".config",
            ".bak",
            ".zip",
            ".ps1",
            ".bat",
            ".doc",
            ".docx",
            ".xlsx",
        )
    )


def classify_asset_type(value: str) -> str:
    """Guess an asset's type from its display string alone.

    The FALLBACK, for a finding the engine never stamped with typed entities.
    Prefer :func:`resolve_asset_type`, which reads the type the engine resolved
    against the directory.

    A name on its own does not say what kind of object it is, and this function
    is where that showed: ``khal.drogo`` has a dot so it read as a host,
    ``BRAAVOS.ESSOS.LOCAL (192.168.180.23)`` has a space so it read as a user,
    ``sql_svc`` starts with ``sql`` so it read as a host, and every group read
    as a user. Those guesses are only ever right by coincidence; they are kept
    for artifacts that predate the typed entities, where a guess beats nothing.
    """
    text = str(value or "").strip()
    lower = text.lower()
    if not text:
        return "other"
    if lower.startswith("template: "):
        return "template"
    if lower.startswith("ca: "):
        return "ca"
    if lower.startswith("share: "):
        return "share"
    if lower.startswith("artifact: "):
        return "artifact"
    if _looks_like_artifact(text):
        return "artifact"
    if lower.endswith("$"):
        return "host"
    if "@" in text and "/" not in text and "\\" not in text:
        return "user"
    if "." in text and " " not in text:
        return "host"
    if re.match(r"^(dc|srv|sql|fs|ca|pki|wkst|ws|pc|host)[-_0-9a-z]", lower):
        return "host"
    return "user"


def build_asset_type_index(vuln_data: Any) -> dict[str, str]:
    """Map a finding's flat asset strings to the type the engine RESOLVED.

    Built from the typed entities the finalization pass stamped into the
    finding's ``details``, keyed by the same display string the flat extractor
    emits, so a renderer holding only a list of strings can still answer "what
    kind of object is this" from the directory rather than from the name.

    Returns ``{}`` for a finding with no stamped entities; callers then fall
    back to :func:`classify_asset_type`.
    """
    view = _details_view(vuln_data) if isinstance(vuln_data, dict) else {}
    raw = view.get(SERIALIZED_ENTITIES_KEY)
    if not isinstance(raw, list):
        return {}
    index: dict[str, str] = {}
    for entity in raw:
        if not isinstance(entity, dict):
            continue
        entity_type = str(entity.get("type") or "").strip().lower()
        if entity_type in _PREFIXED_ENTITY_TYPES:
            continue
        flat_type = _FLAT_TYPE_BY_ENTITY_TYPE.get(entity_type)
        if not flat_type:
            continue
        for token in (entity.get("display"), entity.get("identifier")):
            text = str(token or "").strip()
            if text:
                index.setdefault(text.casefold(), flat_type)
    return index


def resolve_asset_type(
    asset: str, type_index: Mapping[str, str] | None = None
) -> str:
    """Return an asset's type, preferring what the engine resolved over a guess.

    ``type_index`` comes from :func:`build_asset_type_index`. When the asset is
    in it the answer is the directory's, which is the whole point: the CSV
    appendix exists to be imported into a GRC tool and filtered by type, so a
    column filled by string heuristics is worse than no column at all.
    """
    if type_index:
        resolved = type_index.get(str(asset or "").strip().casefold())
        if resolved:
            return resolved
    return classify_asset_type(asset)


def _asset_priority(asset: str, asset_type: str) -> tuple[int, str]:
    """Return a priority tuple where smaller values are more critical."""
    lower = asset.lower()
    if asset_type == "host":
        if re.search(r"(^|[-_.])(dc|domaincontroller)([-_.]|$)", lower):
            return 0, lower
        if any(token in lower for token in ("pki", "ca", "adcs", "aia", "cert")):
            return 1, lower
        if any(
            token in lower
            for token in ("sql", "mssql", "exchange", "fs", "file", "hyper", "vcenter")
        ):
            return 2, lower
        if any(token in lower for token in ("srv", "server")):
            return 3, lower
        if any(token in lower for token in ("wkst", "ws", "laptop", "desktop", "pc")):
            return 5, lower
        return 4, lower
    if asset_type in ("user", "group"):
        # Groups keep the account ladder they were sorted by when every group
        # was mis-typed as a user, so naming them correctly does not silently
        # reorder which assets a capped inline list shows.
        if lower in {"administrator", "krbtgt"} or "domain admin" in lower:
            return 1, lower
        if any(token in lower for token in ("admin", "svc", "sql", "backup")):
            return 3, lower
        return 6, lower
    if asset_type == "domain":
        # The domain object is the whole directory. It only ever appears alone
        # (a domain-wide finding names nothing else), so it keeps the mid-table
        # slot the host heuristic used to give it.
        return 4, lower
    if asset_type == "ca":
        return 1, lower
    if asset_type == "template":
        return 2, lower
    if asset_type == "share":
        return 6, lower
    if asset_type == "artifact":
        if "sysvol" in lower or "/policies/" in lower or "\\policies\\" in lower:
            return 2, lower
        return 7, lower
    return 8, lower


def _normalize_relation(value: Any) -> str:
    """Return a normalized relation token."""
    return str(value or "").strip().lower().replace(" ", "")


def _template_cn_from_dn(value: Any) -> str:
    """Return the template CN from a distinguished name or a bare name."""
    text = str(value or "").strip()
    if not text:
        return ""
    if "=" in text and "," in text:
        # CN=VulnTemplate,CN=Certificate Templates,...
        first = text.split(",", 1)[0]
        if "=" in first:
            return first.split("=", 1)[1].strip()
    return text


def _adcs_template_names(details: Mapping[str, Any] | None) -> list[str]:
    """Return abused certificate template names via the SSOT extractor.

    Delegates to :func:`adcs_path_display.extract_adcs_template_names` (the
    single source of truth, which understands ``template`` / ``templates`` /
    ``vulnerable_resources`` / ``templates_summary``) and then drops any name
    that is actually an Enterprise CA — the SSOT appends every
    ``vulnerable_resources[].name`` regardless of ``kind``, so a CA would
    otherwise be mislabelled as a template.

    Also recovers the two dominant ESC keys the SSOT does NOT read —
    ``template_dn`` (a distinguished name; the CN is taken) and
    ``template_used_for_run`` (the template name used in the executed run) — so
    findings that only carry those still surface their template.
    """
    template_names = list(extract_adcs_template_names(details))
    if isinstance(details, Mapping):
        cn = _template_cn_from_dn(details.get("template_dn"))
        if cn:
            template_names.append(cn)
        used = str(details.get("template_used_for_run") or "").strip()
        if used:
            template_names.append(used)

    if not template_names:
        return []

    ca_names = {name.strip().lower() for name in extract_adcs_ca_names(details)}
    result: list[str] = []
    seen: set[str] = set()
    for name in template_names:
        key = name.strip().lower()
        if not key or key in ca_names or key in seen:
            continue
        seen.add(key)
        result.append(name.strip())
    return result


def _adcs_template_and_ca_assets(details: Mapping[str, Any] | None) -> list[str]:
    """Return typed ``Template: ...`` / ``CA: ...`` assets from ADCS details."""
    assets: list[str] = []
    _extend_unique(
        assets, [f"Template: {template}" for template in _adcs_template_names(details)]
    )
    _extend_unique(assets, [f"CA: {ca}" for ca in extract_adcs_ca_names(details)])
    return assets


def _extract_adcs_template_assets(step: dict[str, Any]) -> list[str]:
    """Return template/CA-focused affected assets for ADCS findings when available."""
    details = step.get("details") if isinstance(step.get("details"), dict) else {}
    relation = _normalize_relation(step.get("action") or step.get("relation"))
    if relation not in _ADCS_RELATIONS:
        return []

    assets: list[str] = []
    for key in (
        "from",
        "source",
        "source_user",
        "source_username",
        "user",
        "username",
        "credential_username",
    ):
        _extend_unique(assets, _extract_strings(details.get(key)))

    template_assets = _adcs_template_and_ca_assets(details)

    if relation == "adcsesc4" and not template_assets:
        # ESC4 abuses write-access to a template; when no template name is
        # carried in the notes, the target label often IS the template name.
        target_label = str(details.get("to") or details.get("target") or "").strip()
        if target_label:
            candidate = target_label
            if "@" in candidate:
                candidate = candidate.split("@", 1)[0].strip()
            if (
                candidate
                and "." not in candidate
                and "\\" not in candidate
                and "/" not in candidate
            ):
                template_assets = [f"Template: {candidate}"]

    _extend_unique(assets, template_assets)
    return assets


#: Memoized inversion of ``ATTACK_STEP_CATALOG`` (relation -> finding key).
_RELATIONS_BY_VULN_KEY: dict[str, set[str]] | None = None


def _relations_by_vuln_key() -> dict[str, set[str]]:
    """Return ``{vuln_key: {relation, ...}}`` from the attack-step catalog.

    ``ATTACK_STEP_CATALOG`` is keyed by graph relation and each entry declares
    the finding it belongs to, so inverting it recovers every relation a finding
    can appear as. That matters because ``VULN_CATALOG.step_relation`` names at
    most one, and several findings ship under a relation that does not resemble
    their key at all — ``ntlmv1_crack`` edges carry ``CrackNTLMv1``,
    ``laps_readable`` also covers ``SyncLAPSPassword``. Without the inversion the
    edge is filtered out and the finding lists no asset.

    Computed once and memoized; the catalog is a module-level constant.
    """
    global _RELATIONS_BY_VULN_KEY
    if _RELATIONS_BY_VULN_KEY is not None:
        return _RELATIONS_BY_VULN_KEY
    mapping: dict[str, set[str]] = {}
    try:
        from adscan_internal.services.attack_step_catalog import ATTACK_STEP_CATALOG

        for relation, entry in ATTACK_STEP_CATALOG.items():
            vuln_key = (
                entry.get("vuln_key")
                if isinstance(entry, dict)
                else getattr(entry, "vuln_key", None)
            )
            key = str(vuln_key or "").strip().lower()
            alias = _normalize_relation(relation)
            if key and alias:
                mapping.setdefault(key, set()).add(alias)
    except Exception:  # noqa: BLE001 - alias enrichment is never fatal
        mapping = {}
    _RELATIONS_BY_VULN_KEY = mapping
    return mapping


def _relation_aliases_for_vulnerability(vuln_name: str) -> set[str]:
    """Return possible graph relation names associated with a finding key.

    Reads ``step_relation`` from the LITE-safe catalog slice, not the full PRO
    ``VULN_CATALOG``: a graph relation name is a structural join key, not
    product knowledge, and both tiers must resolve the same aliases or the free
    report and the paid kit would name different objects for the same finding.
    """
    key = str(vuln_name or "").strip().lower()
    aliases = {_normalize_relation(vuln_name)}
    step_relation = VULN_CATALOG_STEP_RELATIONS.get(vuln_name)
    if step_relation:
        aliases.add(_normalize_relation(step_relation))
    aliases.update(_relations_by_vuln_key().get(key, set()))
    return {alias for alias in aliases if alias}


def _extract_assets_from_attack_graph_edges(
    target: list[str],
    vuln_name: str,
    attack_graph_edges: Any,
) -> None:
    """Extract correlated assets from attack graph edges."""
    if not isinstance(attack_graph_edges, list):
        return

    relation_aliases = _relation_aliases_for_vulnerability(vuln_name)
    matches: list[str] = []
    for edge in attack_graph_edges:
        if not isinstance(edge, dict):
            continue
        relation = _normalize_relation(edge.get("relation"))
        if relation and relation not in relation_aliases:
            continue
        notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
        if relation in _ADCS_RELATIONS:
            _extend_unique(matches, _extract_strings(edge.get("source")))
            _extend_unique(matches, _extract_strings(edge.get("from")))
            adcs_assets = _adcs_template_and_ca_assets(notes)
            _extend_unique(matches, adcs_assets)
            if adcs_assets:
                continue
            # ADCS edge with no template parsed: fall through to target/to, but
            # drop the direct domain-breaker destination (Domain Admins, etc.).
            # The bare domain object is preserved by the filter.
            edge_terminals = _extract_strings(edge.get("target"))
            _extend_unique(edge_terminals, _extract_strings(edge.get("to")))
            _extend_unique(matches, _drop_direct_domain_breaker_assets(edge_terminals))
            continue
        _extend_unique(matches, _extract_strings(edge.get("target")))
        _extend_unique(matches, _extract_strings(edge.get("to")))

    _extend_unique(target, matches)


def _path_relation_tokens(path: dict[str, Any]) -> set[str]:
    """Return every normalized relation token a path carries.

    Reads both places the engine records a step's relation: the flat
    ``relations`` list and the per-step ``action``/``relation`` field. Extracted
    from :func:`_path_matches_vulnerability` so the *one* definition of "which
    relations does this path use" is shared by the per-finding predicate and by
    :func:`count_findings_on_paths`, which needs it once per path rather than
    once per (finding, path) pair.
    """
    tokens: set[str] = set()

    relations = path.get("relations")
    if isinstance(relations, list):
        for relation in relations:
            token = _normalize_relation(relation)
            if token:
                tokens.add(token)

    steps = path.get("steps")
    if isinstance(steps, list):
        for step in steps:
            if not isinstance(step, dict):
                continue
            token = _normalize_relation(step.get("action") or step.get("relation"))
            if token:
                tokens.add(token)

    return tokens


def _path_matches_vulnerability(path: dict[str, Any], vuln_name: str) -> bool:
    """Return True when a path contains a step tied to the vulnerability."""
    relation_aliases = _relation_aliases_for_vulnerability(vuln_name)
    if not relation_aliases:
        return False
    return bool(_path_relation_tokens(path) & relation_aliases)


def count_findings_on_paths(
    finding_keys: Iterable[Any],
    paths: Iterable[Any],
) -> tuple[int, int]:
    """Count how many findings sit on at least one attack path.

    The topological counterpart to the finding list: a finding that appears on
    no complete path reaches nothing on its own, and the share of findings in
    that state is the field figure this exists to measure. Both halves are
    returned as raw counts and NEVER as a ratio — a percentage cannot be
    re-aggregated across audits, whereas two counts can be summed.

    "On a path" is decided by exactly the same relation-alias join
    :func:`_path_matches_vulnerability` applies (a finding key resolves to the
    graph relations it can appear as, via ``VULN_CATALOG.step_relation`` plus
    the inverted attack-step catalog). Each path's relation tokens are read
    once, so the cost is linear in paths plus one set intersection per finding
    rather than a full re-scan of the path list for every finding.

    Args:
        finding_keys: The finding/vulnerability keys to test, one per finding
            the report counts. Every entry counts toward the denominator —
            including a key with no relation mapping (a posture finding such as
            ``smb_signing_disabled`` has no graph edge and legitimately sits on
            no path) and a blank key — so the denominator matches the finding
            inventory the caller passed in rather than a filtered subset.
        paths: Attack-path dicts (the engine's summary shape). Non-dict entries
            are ignored.

    Returns:
        ``(findings_on_path, findings_total)``. A finding that matches several
        paths counts once.
    """
    path_tokens = [
        _path_relation_tokens(path) for path in paths if isinstance(path, dict)
    ]
    path_tokens = [tokens for tokens in path_tokens if tokens]

    findings_total = 0
    findings_on_path = 0
    for key in finding_keys:
        findings_total += 1
        aliases = _relation_aliases_for_vulnerability(str(key or ""))
        if not aliases:
            continue
        if any(tokens & aliases for tokens in path_tokens):
            findings_on_path += 1

    return findings_on_path, findings_total


def _extract_assets_from_matching_step(step: dict[str, Any]) -> list[str]:
    """Extract target-like assets from a matching attack step."""
    details = step.get("details") if isinstance(step.get("details"), dict) else {}
    assets: list[str] = []
    relation = _normalize_relation(step.get("action") or step.get("relation"))
    adcs_assets = _extract_adcs_template_assets(step)
    if adcs_assets:
        return adcs_assets
    target_like: list[str] = []
    for key in (
        "to",
        "target",
        "target_host",
        "target_hostname",
        "target_user",
        "target_username",
        "hostname",
        "computer",
        "host",
        "user",
        "username",
        "hosts",
        "hosts_list",
    ):
        _extend_unique(target_like, _extract_strings(details.get(key)))

    # Drop the path TERMINAL when it is a direct domain-breaker destination
    # (e.g. Domain Admins / Enterprise Admins / krbtgt / a DC). That is where
    # the escalation lands, not the asset the finding affects. The bare domain
    # object survives the filter (DCSync / domain-wide).
    _extend_unique(assets, _drop_direct_domain_breaker_assets(target_like))

    if relation in _SOURCE_RELEVANT_RELATIONS:
        for key in (
            "from",
            "source",
            "source_user",
            "source_username",
            "user",
            "username",
            "credential_username",
        ):
            _extend_unique(assets, _extract_strings(details.get(key)))

    _SHARE_KEYS = {"share", "shares", "shares_list"}
    _ARTIFACT_KEYS = {"artifact", "source_xml"}
    for key in _CONTEXT_DETAIL_KEYS_BY_RELATION.get(relation, ()):
        values = _extract_strings(details.get(key))
        if not values:
            continue
        if key in _SHARE_KEYS:
            # A share edge carries the list twice — ``shares_list`` and the
            # pre-joined ``shares`` display string — so split the joined form
            # instead of emitting "DEV, HR, SYSVOL" as one asset.
            tokens: list[str] = []
            for value in values:
                _extend_unique(tokens, _split_joined_display_tokens(value))
            _extend_unique(assets, [f"Share: {token}" for token in tokens])
        elif key in _ARTIFACT_KEYS:
            _extend_unique(assets, [f"Artifact: {value}" for value in values])
        else:
            _extend_unique(assets, values)

    return assets


def _extract_assets_from_attack_paths(
    target: list[str],
    vuln_name: str,
    attack_paths: Any,
) -> None:
    """Extract affected assets from attack paths correlated to the finding."""
    if not isinstance(attack_paths, list):
        return

    relation_aliases = _relation_aliases_for_vulnerability(vuln_name)
    if not relation_aliases:
        return

    matches: list[str] = []
    for path in attack_paths:
        if not isinstance(path, dict) or not _path_matches_vulnerability(
            path, vuln_name
        ):
            continue

        matched_step_assets: list[str] = []
        steps = path.get("steps")
        if isinstance(steps, list):
            for step in steps:
                if not isinstance(step, dict):
                    continue
                relation = step.get("action") or step.get("relation")
                if _normalize_relation(relation) not in relation_aliases:
                    continue
                _extend_unique(
                    matched_step_assets, _extract_assets_from_matching_step(step)
                )

        if matched_step_assets:
            _extend_unique(matches, matched_step_assets)
            continue

        # The path-level target fallback is the terminal; drop it when it is a
        # direct domain-breaker destination (keep the bare domain object).
        _extend_unique(
            matches,
            _drop_direct_domain_breaker_assets(_extract_strings(path.get("target"))),
        )

    _extend_unique(target, matches)


def _details_view(vuln_data: Any) -> dict[str, Any]:
    """Return the details mapping for a finding.

    ``vuln_data`` may already BE the flattened details dict (the report-builder /
    HTML path) or may carry a nested ``details`` sub-dict (the technical-report
    path). This merges both views so extractors find the keys either way.
    """
    if not isinstance(vuln_data, dict):
        return {}
    nested = vuln_data.get("details")
    if isinstance(nested, dict):
        merged = dict(vuln_data)
        merged.update(nested)
        return merged
    return vuln_data


def _password_redacted_assets(details: Mapping[str, Any]) -> list[str]:
    """Return a single redacted-password marker when a secret is present.

    The actual secret is never emitted as an affected asset; presence is shown
    via a fixed marker so the report can state that credential material was
    recovered without exposing it.
    """
    for key in ("password", "secret", "plaintext", "cleartext", "value"):
        value = details.get(key)
        if _is_non_empty_string(value):
            return ["Password: [redacted]"]
    return []


_SOURCE_PRINCIPAL_KEYS: tuple[str, ...] = (
    "from",
    "source",
    "source_user",
    "source_username",
    "user",
    "username",
    "credential_username",
)


def _extract_registry_extras_from_details(vuln_name: str, vuln_data: Any) -> list[str]:
    """Pull the rule's source principals + typed extras from the finding details.

    Used on the direct (no-attack_path) path where ``vuln_data`` is/contains the
    flattened ``details`` dict. Source principals and target are governed by the
    finding-key rule in ``affected_asset_rules``; the relation-driven path/edge
    extractors handle the same axes when a correlated attack path is in scope.
    """
    details = _details_view(vuln_data)
    if not details:
        return []
    rule = rule_for(vuln_name)

    assets: list[str] = []

    if rule.source is SourceMode.PRINCIPALS:
        for key in _SOURCE_PRINCIPAL_KEYS:
            _extend_unique(assets, _extract_strings(details.get(key)))

    if rule.target is TargetMode.KEEP:
        target_like: list[str] = []
        for key in ("to", "target", "target_user", "target_username", "target_host"):
            _extend_unique(target_like, _extract_strings(details.get(key)))
        _extend_unique(assets, _drop_direct_domain_breaker_assets(target_like))
    elif rule.target is TargetMode.DROP_BREAKER:
        target_like = []
        for key in ("to", "target"):
            _extend_unique(target_like, _extract_strings(details.get(key)))
        _extend_unique(assets, _drop_direct_domain_breaker_assets(target_like))

    if not rule.extras:
        return assets
    if Extra.TEMPLATES in rule.extras:
        _extend_unique(
            assets,
            [f"Template: {template}" for template in _adcs_template_names(details)],
        )
    if Extra.CA in rule.extras:
        _extend_unique(assets, [f"CA: {ca}" for ca in extract_adcs_ca_names(details)])
    if Extra.HOST in rule.extras:
        for key in ("host", "hostname", "hosts", "hosts_list"):
            _extend_unique(assets, _extract_strings(details.get(key)))
    if Extra.SHARE_PATH in rule.extras:
        _extend_unique(
            assets,
            [f"Share: {location}" for location in extract_share_locations(details)],
        )
    if Extra.ARTIFACT in rule.extras:
        for key in ("artifact", "source_xml"):
            values = _extract_strings(details.get(key))
            _extend_unique(assets, [f"Artifact: {value}" for value in values])
    if Extra.PASSWORD_REDACTED in rule.extras:
        _extend_unique(assets, _password_redacted_assets(details))
    return assets


def _flat_assets_from_structured_entities(vuln_data: Any) -> list[str]:
    """Lift serialized structured entities into flat, typed display strings.

    Reads ``_affected_assets_struct`` (the engine's standardized entity list,
    when present) and returns the flat strings the PDF/appendix renderers expect.
    Hosts keep their rich ``display`` (FQDN + IP). Template / CA / share /
    artifact entities are re-prefixed (``Template: …`` etc.) so the existing
    ``classify_asset_type`` keeps working. Returns ``[]`` when no structured
    entities are present so the legacy extraction path runs unchanged.
    """
    view = _details_view(vuln_data) if isinstance(vuln_data, dict) else {}
    raw = view.get("_affected_assets_struct")
    if not isinstance(raw, list) or not raw:
        return []
    prefix_by_type = {
        "template": "Template: ",
        "ca": "CA: ",
        "share": "Share: ",
        "artifact": "Artifact: ",
    }
    out: list[str] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        asset_type = str(entry.get("type") or "").strip().lower()
        display = str(entry.get("display") or entry.get("identifier") or "").strip()
        if not display:
            continue
        prefix = prefix_by_type.get(asset_type, "")
        if prefix:
            # Re-prefix using the stable identifier (the bare template/CA name),
            # not the host-style display, so classification stays correct.
            name = str(entry.get("identifier") or display).strip()
            _extend_unique(out, [f"{prefix}{name}"])
        elif asset_type == "credential":
            _extend_unique(out, ["Password: [redacted]"])
        else:
            _extend_unique(out, [display])
    return out


def is_precise_share_locator(value: str) -> bool:
    """Return True when a share asset names a file, not just the share."""
    text = str(value or "")
    if text.lower().startswith("share: "):
        text = text[len("share: ") :]
    return "\\" in text or "/" in text


def prefer_precise_share_locators(assets: Iterable[str]) -> list[str]:
    """Drop bare share names once the exact secret-bearing files are known.

    A share-secret finding can learn its shares twice: the per-hit file paths the
    scan recorded, and the coarser share list an attack-graph edge carries (which
    is the scan's SCOPE, not where the secret was). Listing both puts shares the
    secret is not in next to the file it is in. When any locator names a file,
    the coarse names are noise.
    """
    values = list(assets)
    share_values = [value for value in values if classify_asset_type(value) == "share"]
    if not any(is_precise_share_locator(value) for value in share_values):
        return values
    return [
        value
        for value in values
        if classify_asset_type(value) != "share" or is_precise_share_locator(value)
    ]


def extract_affected_assets(
    vuln_name: str,
    vuln_data: Any,
    *,
    domain_name: str | None = None,
    attack_paths: list[dict[str, Any]] | None = None,
) -> list[str]:
    """Return a normalized list of affected assets for a finding.

    The report pipeline mixes legacy values, summarized values, and technical
    report details. This helper prefers explicit asset keys but also handles
    summarized lists stored under ``sample``.
    """
    return prefer_precise_share_locators(
        _extract_affected_assets_raw(
            vuln_name,
            vuln_data,
            domain_name=domain_name,
            attack_paths=attack_paths,
        )
    )


def _drop_machine_account_shadows(assets: list[str]) -> list[str]:
    """Drop a bare hostname when the same host's machine account is listed.

    One finding can reach this list through two containers written by two
    detectors: a plain host list (``MEEREEN``) and a per-account record carrying
    the machine account (``MEEREEN$``). They are the same computer, and listing
    both names one host twice — visible to the client as two affected objects.
    The machine account is the directory object, so it is the one kept.
    """
    machine_accounts = {
        asset.strip().lower()[:-1] for asset in assets if asset.strip().endswith("$")
    }
    if not machine_accounts:
        return assets
    return [
        asset
        for asset in assets
        if asset.strip().endswith("$") or asset.strip().lower() not in machine_accounts
    ]


def _extract_affected_assets_raw(
    vuln_name: str,
    vuln_data: Any,
    *,
    domain_name: str | None = None,
    attack_paths: list[dict[str, Any]] | None = None,
) -> list[str]:
    """Collect the affected assets before the precision preference is applied."""
    if isinstance(vuln_data, list):
        return _extract_strings(vuln_data)

    if not isinstance(vuln_data, dict):
        return [domain_name] if _is_non_empty_string(domain_name) and vuln_data else []

    assets: list[str] = []

    precomputed_assets = vuln_data.get("_affected_assets")
    if isinstance(precomputed_assets, list):
        _extend_unique(assets, _extract_strings(precomputed_assets))
        if assets:
            return assets

    # The engine's standardized, structured entities (when serialized into the
    # finding details by the report finalization pass) are the richest source:
    # their host ``display`` already carries BOTH FQDN and IP
    # (``MEEREEN.ESSOS.LOCAL (192.168.180.12)``). Lift them into flat display
    # strings here so the PDF main report AND the bonus appendices — which both
    # route through this extractor — render the SAME IP+FQDN host strings the
    # web shows. The typed prefixes (Template:/CA:/Share:/Artifact:) are
    # reconstructed so downstream classification stays consistent.
    structured_assets = _flat_assets_from_structured_entities(vuln_data)
    if structured_assets:
        _extend_unique(assets, structured_assets)
        return assets

    rule = rule_for(vuln_name)

    # Attack-graph correlation only applies to per-principal attack-step
    # findings. A host / account / domain-scoped finding names its OWN affected
    # principals, so correlating it to an edge would list the same thing twice
    # in two different spellings — and the structured side already gates this
    # way, so gating here is what keeps the PDF and the platform identical.
    if rule.scope is Scope.PER_PRINCIPAL:
        _extract_assets_from_attack_graph_edges(
            assets,
            vuln_name,
            vuln_data.get("attack_graph_edges"),
        )

    for key in _DIRECT_ASSET_KEYS:
        if key not in vuln_data:
            continue
        _extend_unique(assets, _extract_strings(vuln_data.get(key)))

    if rule.scope is Scope.PER_PRINCIPAL:
        _extract_assets_from_attack_paths(assets, vuln_name, attack_paths)

    # Registry-driven typed extras pulled directly from the finding details.
    # The report pipeline often hands us the flattened ``details`` dict as
    # ``vuln_data`` (no attack_paths in scope), so the ESC templates/CA, the
    # share path/host, and the GPP artifact must surface from the details too —
    # not only from a correlated attack path. Composition (which extras apply)
    # is declared per finding-key in ``affected_asset_rules``.
    _extend_unique(assets, _extract_registry_extras_from_details(vuln_name, vuln_data))

    # Host/account-scoped findings (SMB signing, SMBv1, password-not-required,
    # stale passwords, a secret in a directory attribute) carry their affected
    # principals as list-of-dicts under ``details.accounts`` / ``details.hosts``
    # or the detector-specific container their rule declares. The generic list
    # scan below only handles flat lists, so without this the bare-domain
    # fallback would fire.
    _extend_unique(
        assets, _extract_account_assets(vuln_data.get("details"), rule=rule)
    )
    _extend_unique(assets, _extract_account_assets(vuln_data, rule=rule))

    assets = _drop_machine_account_shadows(assets)

    if assets:
        return assets

    # Last resort: treat ANY list in the details as affected assets. Opt-in per
    # rule and off by default — this is what once rendered a credential
    # detector's rule names ("CMD ConvertTo-SecureString") as the affected
    # assets of a client finding. A finding with no declared locator falls
    # through to the domain below instead: vague, but never wrong.
    if rule.scan_details_lists:
        for key, value in vuln_data.items():
            if key in _IGNORED_KEYS:
                continue
            if isinstance(value, list):
                _extend_unique(assets, _extract_strings(value))

        if assets:
            return assets

    return [domain_name] if _is_non_empty_string(domain_name) and vuln_data else []


def summarize_affected_assets(
    vuln_name: str,
    vuln_data: Any,
    *,
    domain_name: str | None = None,
    attack_paths: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return a structured summary of affected assets for display and exports."""
    assets = extract_affected_assets(
        vuln_name,
        vuln_data,
        domain_name=domain_name,
        attack_paths=attack_paths,
    )
    type_index = build_asset_type_index(vuln_data)
    asset_types = {asset: resolve_asset_type(asset, type_index) for asset in assets}
    asset_type_counts = {
        "host": 0,
        "user": 0,
        "group": 0,
        "domain": 0,
        "template": 0,
        "ca": 0,
        "share": 0,
        "artifact": 0,
        "credential": 0,
        "other": 0,
    }
    for asset_type in asset_types.values():
        if asset_type not in asset_type_counts:
            asset_type_counts["other"] += 1
            continue
        asset_type_counts[asset_type] += 1

    domain_controller_count = 0
    non_dc_count = 0
    privileged_user_count = 0
    general_user_count = 0
    if isinstance(vuln_data, dict):
        dcs = vuln_data.get("dcs")
        non_dcs = vuln_data.get("non_dcs")
        admin_users = vuln_data.get("admin_users")
        priv_users = vuln_data.get("priv_users")
        general_users = vuln_data.get("general_users")
        if isinstance(dcs, list):
            domain_controller_count = len(_extract_strings(dcs))
        if isinstance(non_dcs, list):
            non_dc_count = len(_extract_strings(non_dcs))
        if isinstance(admin_users, list):
            privileged_user_count += len(_extract_strings(admin_users))
        if isinstance(priv_users, list):
            privileged_user_count += len(_extract_strings(priv_users))
        if isinstance(general_users, list):
            general_user_count = len(_extract_strings(general_users))

    prioritized_assets = sorted(
        assets,
        key=lambda asset: _asset_priority(asset, asset_types[asset]),
    )
    return {
        "total_assets": len(assets),
        "assets": assets,
        "asset_types": asset_types,
        "asset_type_counts": asset_type_counts,
        "domain_controller_count": domain_controller_count,
        "non_dc_count": non_dc_count,
        "privileged_user_count": privileged_user_count,
        "general_user_count": general_user_count,
        "prioritized_assets": prioritized_assets,
    }


def affected_assets_overflow_line(remaining: int) -> str:
    """Return the overflow line shown when a finding's asset list is truncated.

    ``remaining`` is the number of affected assets not shown inline. The line
    points the reader at the bundled complete record so the truncation is never
    a dead end. Single source of truth for the wording across every PDF.
    """
    asset_word = "asset" if remaining == 1 else "assets"
    return (
        f"… and {remaining} more {asset_word} — "
        f"full list in {AFFECTED_ASSETS_APPENDIX_FILENAME}"
    )


def _source_principal_names(vuln_name: str, vuln_data: Any) -> set[str]:
    """Return the lowercased source-principal names for role classification.

    The merged affected-asset list is flat, but the appendix wants a ``role``
    per asset (``source`` / ``target`` / ``affected``). The only axis the SSOT
    distinguishes structurally is the source principals — surfaced when the
    finding's rule sets ``source=PRINCIPALS`` (ESC enrolling principals,
    hassession sources, roastable principals, …). This recovers that set from
    the finding details using the same source-key list the extractor uses, so
    the appendix's role labels stay consistent with the extraction logic and
    cannot drift. Anything not in this set is reported as ``affected`` — the
    honest default for a posture/host/domain-wide finding.
    """
    details = _details_view(vuln_data)
    if not details:
        return set()
    rule = rule_for(vuln_name)
    if rule.source is not SourceMode.PRINCIPALS:
        return set()
    names: list[str] = []
    for key in _SOURCE_PRINCIPAL_KEYS:
        _extend_unique(names, _extract_strings(details.get(key)))
    return {name.strip().lower() for name in names if name.strip()}


def build_affected_asset_records(
    vuln_name: str,
    vuln_data: Any,
    *,
    domain_name: str | None = None,
    attack_paths: list[dict[str, Any]] | None = None,
) -> list[dict[str, str]]:
    """Return the COMPLETE, untruncated affected-asset records for a finding.

    Each record is ``{"asset": str, "asset_type": str, "role": str}`` where
    ``role`` is ``"source"`` (a source principal of the finding), ``"target"``
    (a typed delegation/path target), or ``"affected"`` (the default — the
    vulnerable resource itself, a posture host, or a domain-wide object).
    Records are returned in priority order (most critical first), matching the
    inline display ordering, so the appendix and the PDF agree on what the
    "top N" are.

    This is the SSOT the machine-readable appendix iterates. It shares the exact
    extraction path with :func:`summarize_affected_assets` /
    :func:`build_affected_assets_display_entries`, so the appendix can never
    diverge from the PDF's inline list.
    """
    summary = summarize_affected_assets(
        vuln_name,
        vuln_data,
        domain_name=domain_name,
        attack_paths=attack_paths,
    )
    prioritized_assets = list(summary["prioritized_assets"])
    asset_types = summary.get("asset_types") or {}
    source_names = _source_principal_names(vuln_name, vuln_data)

    records: list[dict[str, str]] = []
    for asset in prioritized_assets:
        asset_type = asset_types.get(asset) or classify_asset_type(asset)
        # Source principals are the only axis the SSOT distinguishes
        # structurally; every other asset (the vulnerable resource, a posture
        # host, the domain object, a typed template/CA/share/artifact) is the
        # thing the finding affects. Reporting those as ``affected`` is honest;
        # we never fabricate a ``target`` label we cannot derive reliably.
        role = "source" if asset.strip().lower() in source_names else "affected"
        records.append({"asset": asset, "asset_type": asset_type, "role": role})
    return records


def build_affected_assets_display_entries(
    vuln_name: str,
    vuln_data: Any,
    *,
    domain_name: str | None = None,
    attack_paths: list[dict[str, Any]] | None = None,
) -> list[tuple[str, str]]:
    """Build display entries for a deliverable PDF's Affected Assets field.

    Each tuple is ``(kind, text)`` where ``kind`` is ``"bullet"`` or
    ``"paragraph"``. The list is capped at :data:`INLINE_AFFECTED_ASSETS_CAP`
    assets, rendered in priority order (most critical first via
    :func:`_asset_priority`). When a finding has more than the cap, the top
    ``cap`` assets render as bullets followed by a single overflow paragraph
    that names the bundled appendix carrying the complete list. The render path
    therefore only ever materialises ``<= cap`` entries, so a finding with
    thousands of affected assets cannot bloat the PDF or the template loop.
    """
    summary = summarize_affected_assets(
        vuln_name,
        vuln_data,
        domain_name=domain_name,
        attack_paths=attack_paths,
    )
    total_assets = int(summary["total_assets"])
    prioritized_assets = list(summary["prioritized_assets"])

    if total_assets <= INLINE_AFFECTED_ASSETS_CAP:
        return [("bullet", asset) for asset in prioritized_assets]

    shown = prioritized_assets[:INLINE_AFFECTED_ASSETS_CAP]
    entries: list[tuple[str, str]] = [("bullet", asset) for asset in shown]
    remaining = total_assets - len(shown)
    if remaining > 0:
        entries.append(("paragraph", affected_assets_overflow_line(remaining)))
    return entries


def _wordlists_from_attempts(details: Mapping[str, Any]) -> tuple[str, list[str]]:
    """Return ``(cracked_wordlist, wordlists_tried)`` from ``details.attempts``.

    Roasting steps record every cracking pass under
    ``details.attempts = [{"wordlist": ..., "status": ..., "at": ...}, ...]``.
    The cracked wordlist is the one on the last successful attempt; if none
    succeeded, fall back to the last attempt's wordlist so the report still
    shows what was tried.
    """
    attempts = details.get("attempts")
    if not isinstance(attempts, list) or not attempts:
        return "", []

    tried: list[str] = []
    cracked = ""
    last_with_wordlist = ""
    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        wordlist = str(attempt.get("wordlist") or "").strip()
        status = str(attempt.get("status") or "").strip().lower()
        if wordlist:
            if wordlist not in tried:
                tried.append(wordlist)
            last_with_wordlist = wordlist
            if status in {"success", "cracked", "ok", "found"}:
                cracked = wordlist
    if not cracked:
        cracked = last_with_wordlist
    return cracked, tried


def extract_affected_notes(finding_key: str, details: Any) -> dict[str, Any]:
    """Return structured "Detail / Notes" context for a finding.

    The step ``notes`` payload (already flattened into ``step.details`` in
    summaries/snapshots) carries the concrete artifacts of a finding —
    certificate templates and the CA, the cracking wordlist, the share path and
    host where a secret was found, the SYSVOL artifact, the recovered password.
    This surfaces them as a structured block for the report's Notes rendering.

    Sensitive values (password, host, user) are wrapped with
    :func:`mark_sensitive` so the report sanitizer can mask them consistently.

    Returns a dict with keys: ``templates``, ``ca``, ``wordlist_cracked``,
    ``wordlists_tried``, ``share_path``, ``host``, ``artifact``, ``password``.
    Empty/absent values are normalised to ``""`` / ``[]``.
    """
    from adscan_core.sensitive import mark_sensitive

    view = _details_view(details)
    rule = rule_for(finding_key)
    extras = set(rule.extras)

    notes: dict[str, Any] = {
        "templates": [],
        "ca": [],
        "wordlist_cracked": "",
        "wordlists_tried": [],
        "share_path": "",
        "host": "",
        "artifact": "",
        "password": "",
    }
    if not view:
        return notes

    if Extra.TEMPLATES in extras:
        notes["templates"] = _adcs_template_names(view)
    if Extra.CA in extras:
        notes["ca"] = extract_adcs_ca_names(view)
    if Extra.WORDLIST in extras:
        cracked, tried = _wordlists_from_attempts(view)
        notes["wordlist_cracked"] = cracked
        notes["wordlists_tried"] = tried
    if Extra.SHARE_PATH in extras:
        # The per-hit UNC path first (what the reader opens), then the bare
        # share name the attack-graph edge / legacy collector carries.
        shares = extract_share_locations(view)
        if shares:
            notes["share_path"] = shares[0]
    if Extra.HOST in extras:
        hosts: list[str] = []
        for key in ("host", "hostname", "hosts", "hosts_list"):
            _extend_unique(hosts, _extract_strings(view.get(key)))
        if hosts:
            notes["host"] = mark_sensitive(hosts[0], "hostname")
    if Extra.ARTIFACT in extras:
        artifacts: list[str] = []
        for key in ("artifact", "source_xml"):
            _extend_unique(artifacts, _extract_strings(view.get(key)))
        if artifacts:
            notes["artifact"] = artifacts[0]
    if Extra.PASSWORD_REDACTED in extras:
        for key in ("password", "secret", "plaintext", "cleartext"):
            value = view.get(key)
            if _is_non_empty_string(value):
                notes["password"] = mark_sensitive(str(value), "password")
                break

    return notes


def build_affected_notes_display_entries(
    finding_key: str, details: Any
) -> list[tuple[str, str]]:
    """Build ``(kind, text)`` display entries for the Notes context block.

    Returns an empty list when the finding carries no surfaceable notes, so the
    report renderers can skip the block entirely.
    """
    notes = extract_affected_notes(finding_key, details)
    entries: list[tuple[str, str]] = []

    templates = notes.get("templates") or []
    if templates:
        entries.append(("bullet", "Templates: " + ", ".join(templates)))
    ca = notes.get("ca") or []
    if ca:
        entries.append(("bullet", "Certification authority: " + ", ".join(ca)))
    if notes.get("wordlist_cracked"):
        entries.append(("bullet", f"Cracked with wordlist: {notes['wordlist_cracked']}"))
    elif notes.get("wordlists_tried"):
        entries.append(
            ("bullet", "Wordlists tried: " + ", ".join(notes["wordlists_tried"]))
        )
    if notes.get("host"):
        entries.append(("bullet", f"Host: {notes['host']}"))
    if notes.get("share_path"):
        entries.append(("bullet", f"Share: {notes['share_path']}"))
    if notes.get("artifact"):
        entries.append(("bullet", f"Artifact: {notes['artifact']}"))
    if notes.get("password"):
        entries.append(("bullet", f"Recovered credential: {notes['password']}"))

    return entries

