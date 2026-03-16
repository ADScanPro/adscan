"""Domain-based inference for workspace type and lab context.

Automatically determines ``workspace_type``, ``lab_provider``, ``lab_name``,
and ``lab_name_whitelisted`` from a domain name — eliminating the need to ask
the user these questions at workspace creation time.

Inference hierarchy (highest → lowest confidence)
---------------------------------------------------
1. **Exact domain map** — ``sequel.htb`` → Escape, ``scrm.local`` →
   Scrambled, ``egotistical-bank.local`` → Sauna, ``fabricorp.local`` →
   Fuse, etc. (confidence 1.0 for platform-domain overrides such as
   ``.htb``/``.thm``/``.pg``, 0.90 otherwise). Only domains that are *unique*
   to one machine in the catalog are listed — ambiguous domains
   (``htb.local``, ``megabank.local``) are handled by the PDC hostname rule.
   See :func:`lab_catalog.get_machine_domain_index`.
2. **TLD rules** — ``.htb`` → HackTheBox (confidence 1.0),
   ``.vl`` → HackTheBox/VulnLab (1.0), ``.thm`` → TryHackMe (1.0),
   ``.pg`` → Proving Grounds (0.95).
3. **GOAD domain patterns** — ``sevenkingdoms.local``, ``essos.local``, etc.
   (confidence 0.98).
4. **Workspace name matching** — workspace name equals a whitelisted lab name
   from the catalog (confidence 0.70).
5. **Default fallback** — ``ctf`` workspace with no provider (confidence 0.10),
   reflecting that ≈95 % of real-world workspaces are CTF sessions.

CTF-only supplementary rules (only invoked when ``type == "ctf"``)
-------------------------------------------------------------------
5. **PDC hostname** — strip common DC suffixes from the PDC hostname label
   (e.g. ``FOREST-DC`` → ``forest``) and match against the catalog
   (confidence 0.75).  See :func:`infer_from_pdc_hostname`.
6. **Domain SLD** — extract the second-level label from non-CTF-TLD domains
   (``.local``, ``.corp``, ``.lan``, ``.internal``) and match against the
   catalog (e.g. ``blackfield.local`` → ``blackfield``, confidence 0.65).
   See :func:`infer_from_domain_sld`.
7. **Multi-signal fusion** — when multiple weak/medium-confidence signals
   converge on the same provider/lab, ADscan upgrades the result to a stronger
   combined inference (source ``multi_signal``).

Extending the inference rules
------------------------------
* **New CTF platform TLD**: add an entry to :data:`_TLD_RULES`.
* **New GOAD environment / variant**: add the root domain to
  :data:`_GOAD_ROOT_DOMAINS`.
* **New workspace-name heuristic**: extend ``_providers_to_check`` (Rule 3a)
  or :data:`_WORKSPACE_PROVIDER_PREFIXES` (Rule 3b) with the new provider.
* **New DC hostname suffix pattern**: extend :data:`_DC_SUFFIX_RE`.

No other files need changing when extending these constants.

Example usage::

    from adscan_core.domain_inference import infer_from_domain, InferenceSource

    result = infer_from_domain("sequel.htb", workspace_name="my_htb")
    # DomainInferenceResult(workspace_type='ctf', lab_provider='hackthebox',
    #   lab_name='escape', lab_name_whitelisted=True,
    #   confidence=1.0, source=<InferenceSource.EXACT_DOMAIN: 'exact_domain'>)

    result = infer_from_domain("dc.north.sevenkingdoms.local")
    # DomainInferenceResult(workspace_type='ctf', lab_provider='goad', ...)

    result = infer_from_pdc_hostname("FOREST-DC")
    # DomainInferenceResult(workspace_type='ctf', lab_provider='hackthebox',
    #   lab_name='forest', lab_name_whitelisted=True, confidence=0.75, ...)

    result = infer_from_domain_sld("blackfield.local")
    # DomainInferenceResult(workspace_type='ctf', lab_provider='hackthebox',
    #   lab_name='blackfield', lab_name_whitelisted=True, confidence=0.65, ...)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Final

from adscan_core.lab_catalog import (
    get_labs_for_provider,
    get_machine_domain_index,
    is_lab_whitelisted,
)
from adscan_core.lab_context import normalize_lab_name


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class InferenceSource(str, Enum):
    """Which inference rule produced the result."""

    DOMAIN_TLD = "domain_tld"
    GOAD_DOMAIN = "goad_domain"
    EXACT_DOMAIN = "exact_domain"
    WORKSPACE_NAME = "workspace_name"
    PDC_HOSTNAME = "pdc_hostname"
    DOMAIN_SLD = "domain_sld"
    MULTI_SIGNAL = "multi_signal"
    DEFAULT = "default"


@dataclass(frozen=True, slots=True)
class DomainInferenceResult:
    """Immutable result of a domain-based workspace/lab inference pass.

    Attributes:
        workspace_type: Inferred workspace type — ``"ctf"`` or ``"audit"``.
        lab_provider: Canonical provider key (e.g. ``"hackthebox"``), or
            ``None`` when the provider cannot be determined.
        lab_name: Canonical lab/machine name (e.g. ``"forest"``), or ``None``
            when not determinable.
        lab_name_whitelisted: Whether *lab_name* is present in the provider
            whitelist.  ``None`` means the check was not performed.
        confidence: Score in ``[0.0, 1.0]``.  ``1.0`` = fully certain
            (e.g. ``.htb`` TLD).  ``0.1`` = default fallback.
        source: Which rule produced this result.
    """

    workspace_type: str
    lab_provider: str | None
    lab_name: str | None
    lab_name_whitelisted: bool | None
    confidence: float
    source: InferenceSource


# ---------------------------------------------------------------------------
# Inference data — extend these constants to support new platforms
# ---------------------------------------------------------------------------

# TLD → (canonical provider key, confidence score)
# Add new CTF platforms here; order is irrelevant (all TLDs are checked).
_TLD_RULES: Final[dict[str, tuple[str, float]]] = {
    ".htb": ("hackthebox", 1.0),
    ".vl": ("hackthebox", 1.0),  # VulnLab machines (re-hosted on HTB)
    ".thm": ("tryhackme", 1.0),
    ".pg": ("proving_grounds", 0.95),
}

# GOAD root domain names.  Subdomains (e.g. dc.north.sevenkingdoms.local)
# are matched via suffix check.
# Add new GOAD environments / variants here.
_GOAD_ROOT_DOMAINS: Final[frozenset[str]] = frozenset(
    {
        "sevenkingdoms.local",
        "north.sevenkingdoms.local",
        "essos.local",
        "winterfell.local",  # GOAD-Small sub-domain
        "castle.local",
        "braavos.local",
        "meereen.local",
    }
)

# Non-CTF-TLDs whose second-level label often encodes the machine name in
# practice environments (VulnHub, OSCP-style, custom CTF labs).
# Used by infer_from_domain_sld — NOT applied to audit workspaces.
_GENERIC_INTERNAL_TLDS: Final[frozenset[str]] = frozenset(
    {".local", ".corp", ".lan", ".internal", ".home", ".lab"}
)

# Regex matching common DC hostname suffixes (case-insensitive).
# Used by _strip_dc_suffix to extract the machine name from DC hostnames.
# Extend the alternation when new suffix patterns are encountered.
#   Examples: FOREST-DC → forest, SAUNA-DC01 → sauna, CASC-DC1 → casc
_DC_SUFFIX_RE: Final = re.compile(
    r"-?(?:dc\d*|srv\d*|server\d*|ad\d*)\Z", re.IGNORECASE
)

# Workspace name prefixes that imply a specific provider.
# Used by Rule 3b: "htb_forest" → strip "htb_" → look up "forest" in HTB.
# Order matters only for readability; all are checked.
_WORKSPACE_PROVIDER_PREFIXES: Final[tuple[tuple[str, str], ...]] = (
    ("htb_", "hackthebox"),
    ("htb-", "hackthebox"),
    ("thm_", "tryhackme"),
    ("thm-", "tryhackme"),
    ("pg_", "proving_grounds"),
    ("pg-", "proving_grounds"),
    ("vulnhub_", "vulnhub"),
    ("vulnhub-", "vulnhub"),
    ("vhub_", "vulnhub"),
    ("vhub-", "vulnhub"),
    ("dockerlabs_", "dockerlabs"),
    ("dockerlabs-", "dockerlabs"),
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _strip_tld(domain_lower: str, tld: str) -> str:
    """Remove *tld* from *domain_lower*.

    Args:
        domain_lower: Lowercased domain confirmed to end with *tld*.
        tld: TLD suffix including the leading dot (e.g. ``".htb"``).

    Returns:
        Domain string without the TLD suffix.
    """
    return domain_lower[: -len(tld)]


def _extract_machine_name(domain_lower: str, tld: str) -> str | None:
    """Extract the machine/lab name from a CTF-platform FQDN.

    Uses the label immediately before the TLD as the machine name, which
    matches the naming convention of all major CTF platforms.

    Examples::

        _extract_machine_name("sequel.htb", ".htb")      → "sequel"
        _extract_machine_name("dc.sequel.htb", ".htb")   → "sequel"
        _extract_machine_name("dc01.sequel.htb", ".htb") → "sequel"
        _extract_machine_name("attacktive.thm", ".thm")  → "attacktive"

    Args:
        domain_lower: Lowercased FQDN confirmed to end with *tld*.
        tld: TLD suffix including the leading dot.

    Returns:
        Machine name string, or ``None`` if it cannot be determined.
    """
    without_tld = _strip_tld(domain_lower, tld)
    if not without_tld:
        return None
    parts = [p for p in without_tld.split(".") if p]
    if not parts:
        return None
    # The machine is always the last label before the TLD.
    return parts[-1]


def _is_goad_domain(domain_lower: str) -> bool:
    """Return True when *domain_lower* matches a known GOAD root or subdomain.

    Args:
        domain_lower: Lowercased FQDN to test.

    Returns:
        True if the domain belongs to a GOAD lab environment.
    """
    if domain_lower in _GOAD_ROOT_DOMAINS:
        return True
    return any(domain_lower.endswith(f".{root}") for root in _GOAD_ROOT_DOMAINS)


def _strip_dc_suffix(hostname_label_lower: str) -> str | None:
    """Strip a common DC hostname suffix and return the machine name candidate.

    Returns ``None`` when the label has no recognized DC suffix (use the full
    label as-is in that case) or when nothing useful remains after stripping.

    Examples::

        _strip_dc_suffix("forest-dc")   → "forest"
        _strip_dc_suffix("sauna-dc01")  → "sauna"
        _strip_dc_suffix("casc-dc1")    → "casc"
        _strip_dc_suffix("dc01")        → None  (no machine name prefix)
        _strip_dc_suffix("dc")          → None
        _strip_dc_suffix("sauna")       → None  (no suffix to strip)

    Args:
        hostname_label_lower: Lowercased first label of the PDC FQDN.

    Returns:
        Candidate machine name after stripping, or ``None``.
    """
    stripped = _DC_SUFFIX_RE.sub("", hostname_label_lower).rstrip("-_")
    if stripped and stripped != hostname_label_lower:
        return stripped
    return None


def _infer_from_exact_domain(domain_lower: str) -> DomainInferenceResult | None:
    """Resolve a known exact domain fingerprint, including platform overrides.

    Exact-domain matches are checked before generic TLD parsing because some
    CTF platforms expose a stable FQDN whose visible label is not the actual
    machine name (for example ``sequel.htb`` maps to HTB ``Escape``).

    Args:
        domain_lower: Lowercased FQDN to match. Subdomains are supported by
            progressively stripping leftmost labels.

    Returns:
        A :class:`DomainInferenceResult` when a fingerprint matches, or
        ``None`` when the domain is unknown.
    """
    domain_index = get_machine_domain_index()
    domain_candidate = domain_lower

    while domain_candidate:
        lab_entry = domain_index.get(domain_candidate)
        if lab_entry:
            entry_provider, entry_lab = lab_entry
            confidence = 0.90
            for tld, (_, tld_confidence) in _TLD_RULES.items():
                if domain_candidate.endswith(tld):
                    confidence = max(confidence, tld_confidence)
                    break

            return DomainInferenceResult(
                workspace_type="ctf",
                lab_provider=entry_provider,
                lab_name=normalize_lab_name(entry_lab),
                lab_name_whitelisted=is_lab_whitelisted(entry_provider, entry_lab),
                confidence=confidence,
                source=InferenceSource.EXACT_DOMAIN,
            )

        if "." not in domain_candidate:
            break
        domain_candidate = domain_candidate.split(".", 1)[1]

    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def infer_from_domain(
    domain: str,
    *,
    workspace_name: str | None = None,
    current_lab_provider: str | None = None,
    current_lab_name: str | None = None,
) -> DomainInferenceResult:
    """Infer workspace type and lab context from a domain name.

    The function is pure and has no side effects.  It is safe to call at every
    scan start.  Apply the result to the shell only when lab context has not
    already been set by the user.

    Inference is skipped (returns a ``DEFAULT`` result) when *domain* is empty
    or when both *current_lab_provider* and *current_lab_name* are already
    populated, indicating that the user manually configured the workspace or
    that inference was already applied in a previous scan on this workspace.

    Args:
        domain: Fully qualified domain name to analyse
            (e.g. ``"sequel.htb"``, ``"corp.example.local"``).
        workspace_name: Optional workspace name used as a secondary signal
            when TLD and GOAD rules do not match.
        current_lab_provider: Existing shell ``lab_provider`` value.  When
            both this and *current_lab_name* are non-empty, inference is
            skipped (context already set).
        current_lab_name: Existing shell ``lab_name`` value.

    Returns:
        A :class:`DomainInferenceResult` describing the inferred context.
        Never raises; always returns a valid result (falls back to
        ``DEFAULT`` when nothing matches).
    """
    _default = DomainInferenceResult(
        workspace_type="ctf",
        lab_provider=None,
        lab_name=None,
        lab_name_whitelisted=None,
        confidence=0.1,
        source=InferenceSource.DEFAULT,
    )

    if not domain or not domain.strip():
        return _default

    # Do not override explicitly set lab context.
    if current_lab_provider and current_lab_name:
        return _default

    domain_lower = domain.strip().lower()

    # --- Rule 1: Exact domain-to-lab map (confidence 0.90–1.0) -------------
    exact_domain_result = _infer_from_exact_domain(domain_lower)
    if exact_domain_result is not None:
        return exact_domain_result

    # --- Rule 2: TLD-based inference (confidence 0.95–1.0) -----------------
    for tld, (provider, confidence) in _TLD_RULES.items():
        if not domain_lower.endswith(tld):
            continue
        machine_name = _extract_machine_name(domain_lower, tld)
        whitelisted: bool | None = (
            is_lab_whitelisted(provider, machine_name) if machine_name else None
        )
        return DomainInferenceResult(
            workspace_type="ctf",
            lab_provider=provider,
            lab_name=normalize_lab_name(machine_name) if machine_name else None,
            lab_name_whitelisted=whitelisted,
            confidence=confidence,
            source=InferenceSource.DOMAIN_TLD,
        )

    # --- Rule 3: GOAD domain patterns (confidence 0.98) --------------------
    if _is_goad_domain(domain_lower):
        return DomainInferenceResult(
            workspace_type="ctf",
            lab_provider="goad",
            lab_name=None,
            lab_name_whitelisted=None,
            confidence=0.98,
            source=InferenceSource.GOAD_DOMAIN,
        )

    # --- Rule 4: Workspace name matches a whitelisted lab name (0.70) -------
    if workspace_name:
        workspace_lower = workspace_name.strip().lower()
        # Extend this tuple when new providers with name-based labs are added.
        _providers_to_check = ("hackthebox", "tryhackme", "dockerlabs", "vulnhub")
        for provider in _providers_to_check:
            for lab in get_labs_for_provider(provider):
                lab_lower = lab.lower()
                # Exact match and common separator variants (hyphens / underscores).
                if workspace_lower in (
                    lab_lower,
                    lab_lower.replace("_", "-"),
                    lab_lower.replace("-", "_"),
                ):
                    return DomainInferenceResult(
                        workspace_type="ctf",
                        lab_provider=provider,
                        lab_name=normalize_lab_name(lab),
                        lab_name_whitelisted=True,  # By definition: from the whitelist.
                        confidence=0.70,
                        source=InferenceSource.WORKSPACE_NAME,
                    )

        # --- Rule 4b: Provider-prefixed workspace name (confidence 0.65) ----
        # e.g. "htb_forest" → strip "htb_" → look up "forest" in HTB only.
        # The prefix both identifies the provider and narrows the search,
        # making false positives extremely unlikely.
        for prefix, prefix_provider in _WORKSPACE_PROVIDER_PREFIXES:
            if not workspace_lower.startswith(prefix):
                continue
            suffix = workspace_lower[len(prefix):]
            if not suffix:
                break
            for lab in get_labs_for_provider(prefix_provider):
                lab_lower = lab.lower()
                if suffix in (
                    lab_lower,
                    lab_lower.replace("_", "-"),
                    lab_lower.replace("-", "_"),
                ):
                    return DomainInferenceResult(
                        workspace_type="ctf",
                        lab_provider=prefix_provider,
                        lab_name=normalize_lab_name(lab),
                        lab_name_whitelisted=True,
                        confidence=0.65,
                        source=InferenceSource.WORKSPACE_NAME,
                    )
            break  # Prefix matched — don't test other prefixes

    # --- Rule 5: Default fallback -------------------------------------------
    return _default


def infer_from_pdc_hostname(
    pdc_hostname: str,
    *,
    current_lab_provider: str | None = None,
    current_lab_name: str | None = None,
) -> DomainInferenceResult:
    """Infer lab context from the PDC hostname label.

    Extracts the machine name from the DC hostname by trying the full label
    first, then stripping recognised DC suffixes (e.g. ``-dc``, ``-dc01``).
    Matches against the lab catalog via :func:`resolve_lab_from_text`.

    **Only safe for CTF workspaces.** The call site is responsible for gating
    on ``shell.type == "ctf"`` before invoking this function.

    Examples::

        infer_from_pdc_hostname("FOREST-DC")   → forest (hackthebox, 0.75)
        infer_from_pdc_hostname("SAUNA-DC01")  → sauna  (hackthebox, 0.75)
        infer_from_pdc_hostname("SAUNA")       → sauna  (hackthebox, 0.75)
        infer_from_pdc_hostname("DC01")        → DEFAULT (no machine name)
        infer_from_pdc_hostname("FOREST-DC.example.local") → forest (FQDN ok)

    Args:
        pdc_hostname: PDC hostname — bare label or FQDN.  Only the first
            label is used (the FQDN suffix is ignored).
        current_lab_provider: Existing shell ``lab_provider``.  When both
            this and *current_lab_name* are non-empty, inference is skipped.
        current_lab_name: Existing shell ``lab_name``.

    Returns:
        A :class:`DomainInferenceResult` with ``confidence=0.75`` on match,
        or a ``DEFAULT`` result when nothing matches.
    """
    _default = DomainInferenceResult(
        workspace_type="ctf",
        lab_provider=None,
        lab_name=None,
        lab_name_whitelisted=None,
        confidence=0.1,
        source=InferenceSource.DEFAULT,
    )

    if not pdc_hostname or not pdc_hostname.strip():
        return _default

    if current_lab_provider and current_lab_name:
        return _default

    # Use only the first label — safe to pass FQDNs.
    hostname_label = pdc_hostname.strip().lower().split(".")[0]
    if not hostname_label:
        return _default

    # Build candidate list: full label first, suffix-stripped variant second.
    candidates: list[str] = [hostname_label]
    stripped = _strip_dc_suffix(hostname_label)
    if stripped:
        candidates.append(stripped)

    for candidate in candidates:
        resolved = resolve_lab_from_text(candidate)
        if resolved:
            provider, lab_name, whitelisted = resolved
            return DomainInferenceResult(
                workspace_type="ctf",
                lab_provider=provider,
                lab_name=lab_name,
                lab_name_whitelisted=whitelisted,
                confidence=0.75,
                source=InferenceSource.PDC_HOSTNAME,
            )

    return _default


def infer_from_domain_sld(
    domain: str,
    *,
    current_lab_provider: str | None = None,
    current_lab_name: str | None = None,
) -> DomainInferenceResult:
    """Infer lab context from the second-level domain label for internal TLDs.

    For domains with non-CTF TLDs (``.local``, ``.corp``, ``.lan``, etc.),
    extracts the label immediately before the TLD and matches it against the
    lab catalog.  This catches machines like ``blackfield.local`` (→ blackfield)
    where the SLD encodes the machine name.

    **Only safe for CTF workspaces.** The call site is responsible for gating
    on ``shell.type == "ctf"`` before invoking this function.

    Examples::

        infer_from_domain_sld("blackfield.local") → blackfield (hackthebox, 0.65)
        infer_from_domain_sld("cascade.local")    → cascade    (hackthebox, 0.65)
        infer_from_domain_sld("megabank.local")   → DEFAULT (not in catalog)
        infer_from_domain_sld("sequel.htb")       → DEFAULT (CTF TLD, handled by Rule 1)

    Args:
        domain: Fully qualified domain name.  Only applied when the TLD is in
            :data:`_GENERIC_INTERNAL_TLDS`.
        current_lab_provider: Existing shell ``lab_provider``.
        current_lab_name: Existing shell ``lab_name``.

    Returns:
        A :class:`DomainInferenceResult` with ``confidence=0.65`` on match,
        or a ``DEFAULT`` result when nothing matches.
    """
    _default = DomainInferenceResult(
        workspace_type="ctf",
        lab_provider=None,
        lab_name=None,
        lab_name_whitelisted=None,
        confidence=0.1,
        source=InferenceSource.DEFAULT,
    )

    if not domain or not domain.strip():
        return _default

    if current_lab_provider and current_lab_name:
        return _default

    domain_lower = domain.strip().lower()

    # Only apply to internal/generic TLDs (not to CTF-platform TLDs).
    matched_tld: str | None = None
    for tld in _GENERIC_INTERNAL_TLDS:
        if domain_lower.endswith(tld):
            matched_tld = tld
            break
    if matched_tld is None:
        return _default

    # Extract the label immediately before the internal TLD.
    without_tld = _strip_tld(domain_lower, matched_tld)
    parts = [p for p in without_tld.split(".") if p]
    if not parts:
        return _default
    sld_candidate = parts[-1]  # Last label before TLD (e.g. "blackfield")

    resolved = resolve_lab_from_text(sld_candidate)
    if resolved:
        provider, lab_name, whitelisted = resolved
        return DomainInferenceResult(
            workspace_type="ctf",
            lab_provider=provider,
            lab_name=lab_name,
            lab_name_whitelisted=whitelisted,
            confidence=0.65,
            source=InferenceSource.DOMAIN_SLD,
        )

    return _default


def infer_from_ctf_context(
    domain: str,
    *,
    workspace_name: str | None = None,
    pdc_hostname: str | None = None,
    current_lab_provider: str | None = None,
    current_lab_name: str | None = None,
) -> DomainInferenceResult:
    """Infer CTF lab context from all currently available signals.

    This helper evaluates the existing single-signal rules and upgrades the
    result when at least two independent signals converge on the same
    ``(provider, lab_name)`` tuple.

    Combined confidence uses ``1 - Π(1 - c_i)`` and is capped at ``0.95`` to
    avoid eclipsing deterministic platform-domain matches like ``.htb``.

    Args:
        domain: Domain currently being scanned.
        workspace_name: Optional workspace name hint.
        pdc_hostname: Optional PDC hostname hint.
        current_lab_provider: Explicit provider already set on the shell.
        current_lab_name: Explicit lab already set on the shell.

    Returns:
        The strongest single-signal result, or a stronger ``MULTI_SIGNAL``
        result if multiple signals corroborate the same target lab.
    """
    default_result = DomainInferenceResult(
        workspace_type="ctf",
        lab_provider=None,
        lab_name=None,
        lab_name_whitelisted=None,
        confidence=0.1,
        source=InferenceSource.DEFAULT,
    )

    candidate_results: list[DomainInferenceResult] = []

    base_result = infer_from_domain(
        domain,
        workspace_name=workspace_name,
        current_lab_provider=current_lab_provider,
        current_lab_name=current_lab_name,
    )
    if base_result.source is not InferenceSource.DEFAULT:
        candidate_results.append(base_result)

    pdc_result = infer_from_pdc_hostname(
        pdc_hostname or "",
        current_lab_provider=current_lab_provider,
        current_lab_name=current_lab_name,
    )
    if pdc_result.source is not InferenceSource.DEFAULT:
        candidate_results.append(pdc_result)

    sld_result = infer_from_domain_sld(
        domain,
        current_lab_provider=current_lab_provider,
        current_lab_name=current_lab_name,
    )
    if sld_result.source is not InferenceSource.DEFAULT:
        candidate_results.append(sld_result)

    if not candidate_results:
        return default_result

    best_single = max(
        candidate_results,
        key=lambda result: (result.confidence, result.lab_name is not None),
    )

    grouped_results: dict[tuple[str, str], list[DomainInferenceResult]] = {}
    for result in candidate_results:
        if not result.lab_provider or not result.lab_name:
            continue
        grouped_results.setdefault((result.lab_provider, result.lab_name), []).append(
            result
        )

    best_fused: DomainInferenceResult | None = None
    for (provider, lab_name), results in grouped_results.items():
        if len(results) < 2:
            continue
        combined_confidence = 1.0
        for result in results:
            combined_confidence *= 1.0 - float(result.confidence)
        combined_confidence = min(0.95, 1.0 - combined_confidence)
        fused_result = DomainInferenceResult(
            workspace_type="ctf",
            lab_provider=provider,
            lab_name=lab_name,
            lab_name_whitelisted=any(bool(r.lab_name_whitelisted) for r in results),
            confidence=combined_confidence,
            source=InferenceSource.MULTI_SIGNAL,
        )
        if best_fused is None or fused_result.confidence > best_fused.confidence:
            best_fused = fused_result

    if best_fused and best_fused.confidence > best_single.confidence:
        return best_fused
    return best_single


# ---------------------------------------------------------------------------
# Post-scan free-text resolver (used for the optional fallback prompt)
# ---------------------------------------------------------------------------


def resolve_lab_from_text(text: str) -> tuple[str, str, bool] | None:
    """Resolve a free-text lab name to ``(provider, lab_name, whitelisted)``.

    Searches the catalog across all providers for an exact or
    separator-normalised match (underscores ↔ hyphens, case-insensitive).
    Returns the *first* match found, or ``None`` when nothing matches.

    This is intentionally strict (exact match only) to avoid false positives.
    Partial / fuzzy matching is deliberately excluded because a wrong provider
    label in telemetry is worse than no label at all.

    Args:
        text: Free-text input from the user (e.g. ``"forest"``, ``"Sauna"``,
            ``"VulnNet_Roasted"``).

    Returns:
        ``(canonical_provider, canonical_lab_name, whitelisted)`` tuple, or
        ``None`` when no catalog match is found.

    Examples::

        resolve_lab_from_text("forest")         → ("hackthebox", "forest", True)
        resolve_lab_from_text("SAUNA")          → ("hackthebox", "sauna", True)
        resolve_lab_from_text("VulnNet-Roasted")
            → ("tryhackme", "vulnnet_roasted", True)
        resolve_lab_from_text("unknownxyz")     → None
    """
    if not text or not text.strip():
        return None

    query = text.strip().lower()
    # Normalise both separators so "VulnNet-Roasted" matches "VulnNet_Roasted".
    query_normalised = query.replace("-", "_")

    _providers_to_check = ("hackthebox", "tryhackme", "dockerlabs", "vulnhub")
    for provider in _providers_to_check:
        for lab in get_labs_for_provider(provider):
            lab_lower = lab.lower()
            lab_normalised = lab_lower.replace("-", "_")
            if (
                query in (lab_lower, lab_lower.replace("_", "-"))
                or query_normalised == lab_normalised
            ):
                canonical_name = normalize_lab_name(lab)
                return (provider, canonical_name or lab_lower, True)

    return None
