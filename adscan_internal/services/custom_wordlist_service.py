"""Client-targeted custom wordlist / variation builder — modular, reusable core.

This service turns data ADscan already persists (domain FQDN + NetBIOS, company,
OU/city tokens, sAMAccountNames, ``description``/``info`` free-text, computer
``dNSHostName``, per-object ``whenCreated``) into a small, client-tuned candidate
list. The dominant real-world AD password shape is
``Capital + client-word + date/number [+ symbol]``; popular lists (rockyou,
hashmob) carry the mangling half but never the *client-word* half. That half is
derivable from the environment, and this module derives it.

One core generator, two use cases:

* **Offline crack** (kerberoast / AS-REP / NTLM) — no lockout cost, recall is the
  only objective. ``for_crack`` writes ``base.txt`` (un-mangled seed words for a
  hashcat rule file to mangle) + ``literal.txt`` (pre-expanded calendar forms a
  rule engine cannot synthesize because it does not know the *client* year/word).
* **Online spray** — ``for_spray`` returns the mined base-word set to feed the
  EXISTING spray plan builders (``build_variation_spray_plan`` /
  ``build_adaptive_year_spray_plan``), which keep their lockout + policy filtering.

Design boundaries (do NOT reinvent — this module wraps, it does not fork):

* Mangling (case / year suffix / symbol / leet) is owned by
  :func:`adscan_internal.services.password_variation_generator.generate_variations`.
  This module produces the *seed words* it mangles, never a second mangler.
* Year token parse / replace / epoch->year math is owned by
  :mod:`adscan_internal.services.password_year_variant_service`. The whenCreated
  date-seed logic here reuses that SSOT, never a second year parser.
* Per-user spray targeting + policy/lockout filtering stays in the spray plan
  services. This module only feeds base words in.

whenCreated is a **SEED, never a FILTER** for the offline crack list (spec §10):
offline cracking has no lockout cost and hashcat rejects non-matching candidates
for free, so the correct bias is recall — add likely dates (creation band + recent
band), never remove candidates. Policy/date filtering stays in the spray path only,
where the lockout cost is real.

The CORE (``mine_base_words`` / ``seed_dates_for`` / ``build_generation_spec`` /
``render_literal_lines``) is pure: no I/O, no network, no ``datetime.now()`` — the
current year is injected so L1 tests are deterministic. The adapters
(``for_crack`` / ``for_spray``) and the workspace loader are the only I/O.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
from typing import Any, Iterable, Literal, Sequence
import unicodedata

from adscan_internal.services.password_year_variant_service import (
    epoch_seconds_to_year,
)


# ---------------------------------------------------------------------------
# Constants — the always-on baseline word model (spec §5, layer 1 + 3)
# ---------------------------------------------------------------------------
#
# These are module-level so the pure core is self-contained and L1-testable
# without file I/O. The static asset files (assets/wordlists/custom/*.txt) and
# richer localization packs referenced in the spec are a LATER PR concern; this
# constant is the single source of truth for the baseline until then.

# Layer 1 — universally common corporate passwords (un-mangled seed words; the
# rule engine / generate_variations adds case/digit/symbol/leet).
BASELINE_WORDS: tuple[str, ...] = (
    "welcome",
    "password",
    "passw0rd",
    "changeme",
    "letmein",
    "company",
    "admin",
    "secret",
    "temp",
    "login",
)

# Seasons — English + a Spanish localization pack (spec §5, layer 3). Selected
# by the operator "local flavor" prompt (later PR) or inferred from OU tokens.
SEASONS_EN: tuple[str, ...] = ("spring", "summer", "autumn", "fall", "winter")
SEASONS_ES: tuple[str, ...] = (
    "primavera",
    "verano",
    "otono",
    "invierno",
)

# Keyboard walks — never carry a year, so they are seed words only.
KEYBOARD_WALKS: tuple[str, ...] = (
    "qwerty",
    "qwertyuiop",
    "1qaz2wsx",
    "zaq12wsx",
    "asdfgh",
    "1q2w3e4r",
    "qazwsx",
)

# Localization packs keyed by a short language code. ES ships in v1 (spec §11).
LOCALIZATION_PACKS: dict[str, tuple[str, ...]] = {
    "es": (
        "tequiero",
        "hola",
        "madrid",
        "barcelona",
        "espana",
        "futbol",
        "realmadrid",
        "barca",
    ),
}

# Months (calendar concatenation fodder — English + Spanish).
_MONTHS: tuple[str, ...] = (
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
    "enero",
    "febrero",
    "marzo",
    "abril",
    "mayo",
    "junio",
    "julio",
    "agosto",
    "septiembre",
    "octubre",
    "noviembre",
    "diciembre",
)

# TLD-like final domain labels to drop when deriving a company word from an FQDN.
_DOMAIN_TLD_LABELS: frozenset[str] = frozenset(
    {
        "local",
        "lan",
        "corp",
        "internal",
        "intranet",
        "ad",
        "com",
        "net",
        "org",
        "edu",
        "gov",
        "io",
        "co",
    }
)

# Stopwords dropped from description/info free-text (English + Spanish, plus
# generic AD-admin boilerplate). Kept small on purpose — the mining cap and the
# free-text priority floor keep noise bounded without an aggressive stoplist.
_STOPWORDS: frozenset[str] = frozenset(
    {
        # English
        "the", "and", "for", "with", "this", "that", "from", "user", "account",
        "service", "group", "member", "please", "not", "use", "used", "all",
        "new", "old", "test", "default", "created", "disabled", "enabled",
        "managed", "built", "role", "team", "office", "email", "mail", "phone",
        "contact", "manager", "admin", "administrator",
        # Spanish
        "cuenta", "usuario", "grupo", "servicio", "para", "con", "del", "las",
        "los", "una", "por", "que", "creado", "correo", "telefono",
    }
)

# Provenance ranks — env-structural beats operator-explicit beats free-text
# (spec §4 guardrail). Lower rank = kept first when the mined set is capped.
_PROVENANCE_RANK: dict[str, int] = {
    "domain": 0,
    "netbios": 1,
    "company": 2,
    "ou_city": 3,
    "env_hostname": 4,
    "extra": 5,
    "samaccount": 6,
    "env_description": 7,
}
_DEFAULT_PROVENANCE_RANK = 9

Provenance = Literal[
    "domain",
    "netbios",
    "company",
    "ou_city",
    "env_hostname",
    "extra",
    "samaccount",
    "env_description",
]

# Guardrails.
_MAX_BASE_WORDS = 400
_MIN_TOKEN_LEN = 3
_MIN_YEAR = 1995  # matches password_variation_plan_service._year_from_iso floor
_DEFAULT_YEAR_SWEEP_BACK = 12
_CREATION_BAND_BACK = 1  # years below whenCreated to include (around/before)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BaseWord:
    """One mined seed word with provenance.

    Attributes:
        word: Normalized (lowercased, accent-stripped, alpha) seed word.
        provenance: Where it came from — drives priority ordering and the
            sidecar provenance report.
        priority: Stable rank; lower is tried/kept first.
    """

    word: str
    provenance: Provenance
    priority: int


@dataclass(frozen=True)
class BaseWordSet:
    """Result of :func:`mine_base_words`.

    Attributes:
        base_words: Ordered, deduped, capped seed words (rules/mangling fodder).
        literals: Full-password-shaped tokens found verbatim in ``description`` /
            ``info`` (e.g. an onboarding password written in a comment). These are
            direct crack candidates — they are NOT re-mangled.
    """

    base_words: tuple[BaseWord, ...] = ()
    literals: tuple[str, ...] = ()

    def words(self) -> tuple[str, ...]:
        """Return just the seed word strings in priority order."""
        return tuple(bw.word for bw in self.base_words)


@dataclass(frozen=True)
class WordlistContext:
    """Inputs to the generator — everything is optional and degrades gracefully.

    v1 ships on existing collector fields (spec §11); missing fields are handled
    without error.

    Attributes:
        domain: Target domain FQDN (e.g. ``essos.local``).
        netbios: NetBIOS short name if known; otherwise derived from ``domain``.
        company: Company/brand word (operator-provided or from ``domains_data``).
        objects: Persisted inventory records (users.json / computers.json
            ``records`` entries) — each a dict with ``samaccountname``,
            ``distinguished_name`` and a ``properties`` sub-dict carrying
            ``whencreated`` / ``description`` / ``info_field`` / ``dnshostname``.
        operator_words: Extra base words the operator supplied (prompt UX is a
            later PR — passed in for now).
        language_packs: Localization pack codes to fold into the baseline
            (e.g. ``("es",)``).
        current_year: Injected current year — keeps the pure core deterministic.
    """

    domain: str = ""
    netbios: str = ""
    company: str = ""
    objects: tuple[dict[str, Any], ...] = ()
    operator_words: tuple[str, ...] = ()
    language_packs: tuple[str, ...] = ()
    current_year: int = 0


@dataclass(frozen=True)
class GenerationSpec:
    """Assembled candidate model (spec §5).

    Attributes:
        seed_words: Un-mangled layer 1-3 words (baseline + client + localization)
            written to ``base.txt`` for a rule engine / ``generate_variations`` to
            mangle (case / digit / symbol / leet).
        literal_lines: Pre-expanded calendar/concat forms + verbatim mined
            literals written to ``literal.txt``. Only forms a rule engine cannot
            synthesize (the *client* year/word) are pre-expanded here.
        dates: The global date band seeded from whenCreated + the recent band.
    """

    seed_words: tuple[str, ...] = ()
    literal_lines: tuple[str, ...] = ()
    dates: tuple[int, ...] = ()


@dataclass(frozen=True)
class LayerFlags:
    """Which of the 3 word-model layers are folded into the spec (spec §5)."""

    baseline: bool = True
    client: bool = True
    localization: bool = True
    pre_expand_calendar: bool = True


@dataclass(frozen=True)
class CrackWordlistArtifact:
    """Paths + counts returned by :func:`for_crack`.

    Attributes:
        base_path: ``base.txt`` — un-mangled seed words (rule fodder).
        literal_path: ``literal.txt`` — pre-expanded calendar/concat + literals.
        sidecar_path: ``<name>_sources.json`` — provenance + counts.
        base_count: Number of seed words written.
        literal_count: Number of literal lines written.
        domain: Target domain the artifact was built for.
    """

    base_path: Path
    literal_path: Path
    sidecar_path: Path
    base_count: int
    literal_count: int
    domain: str


# ---------------------------------------------------------------------------
# Normalization helpers (pure)
# ---------------------------------------------------------------------------


def _normalize_token(value: str) -> str:
    """Lowercase, strip accents (NFKD), keep ``[a-z]`` only.

    Mirrors the NFKD/ascii pass in
    ``KerberosUsernameWordlistService._split_linkedin_name`` so the two services
    normalize identically.

    Args:
        value: Raw token.

    Returns:
        Normalized alpha token, or ``""`` when nothing usable remains.
    """
    text = str(value or "").strip().lower()
    if not text:
        return ""
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z]", "", text)


def _normalize_seed(value: str) -> str:
    """Normalize a SEED word, preserving digits.

    Unlike :func:`_normalize_token` (alpha-only, for environment tokens), seed
    words legitimately carry digits (``passw0rd``, ``1qaz2wsx``, ``passw0rd2026``
    calendar forms), so this keeps ``[a-z0-9]``.

    Args:
        value: Raw seed word.

    Returns:
        Lowercased, accent-stripped alphanumeric seed word, or ``""``.
    """
    text = str(value or "").strip().lower()
    if not text:
        return ""
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]", "", text)


def _split_free_text(value: str) -> list[str]:
    """Tokenize free-text (description/info) on non-alnum boundaries.

    Args:
        value: Raw free-text field.

    Returns:
        Lowercased, accent-stripped alpha tokens of length >= ``_MIN_TOKEN_LEN``
        that are not stopwords, in appearance order (deduped).
    """
    raw = str(value or "")
    if not raw:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for chunk in re.split(r"[^0-9A-Za-zÀ-ɏ]+", raw):
        token = _normalize_token(chunk)
        if len(token) < _MIN_TOKEN_LEN:
            continue
        if token in _STOPWORDS:
            continue
        if token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out


def _looks_like_password(value: str) -> bool:
    """Heuristic: does a raw token look like a full password (not a base word)?

    A base word is mangled by rules; a full password is a direct candidate. We
    treat a token as a full password when it is >= 6 chars and mixes character
    classes (letters + digits, or contains a symbol) — the AD-complexity shape.

    Args:
        value: Raw token from description/info.

    Returns:
        ``True`` when the token should be a direct literal candidate.
    """
    token = str(value or "").strip()
    if len(token) < 6:
        return False
    has_alpha = any(c.isalpha() for c in token)
    has_digit = any(c.isdigit() for c in token)
    has_symbol = any(not c.isalnum() for c in token)
    return has_alpha and (has_digit or has_symbol)


def _company_words_from_domain(domain: str) -> list[str]:
    """Derive company/brand seed words from a domain FQDN.

    ``essos.local`` -> ``["essos"]``; multi-label domains keep every non-TLD
    alpha label (e.g. ``ad.contoso.com`` -> ``["contoso"]``).

    Args:
        domain: Domain FQDN.

    Returns:
        Normalized company/brand words (deduped, appearance order).
    """
    words: list[str] = []
    seen: set[str] = set()
    for label in str(domain or "").split("."):
        norm = _normalize_token(label)
        if len(norm) < _MIN_TOKEN_LEN:
            continue
        if norm in _DOMAIN_TLD_LABELS:
            continue
        if norm in seen:
            continue
        seen.add(norm)
        words.append(norm)
    return words


def _ou_city_tokens_from_dn(distinguished_name: str) -> list[str]:
    """Extract OU/city-looking alpha tokens from a distinguishedName.

    ``OU=Barcelona,OU=Users,DC=essos,DC=local`` -> ``["barcelona", "users"]``
    (``DC=`` components are dropped — they are the domain, already mined).

    Args:
        distinguished_name: Object DN.

    Returns:
        Normalized OU tokens (deduped, appearance order).
    """
    dn = str(distinguished_name or "")
    if not dn:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for match in re.finditer(r"OU=([^,]+)", dn, flags=re.IGNORECASE):
        token = _normalize_token(match.group(1))
        if len(token) < _MIN_TOKEN_LEN or token in _STOPWORDS or token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out


def _hostname_prefix_token(dnshostname: str) -> str:
    """Return the normalized alpha prefix of a ``dNSHostName``.

    ``dc01.essos.local`` -> ``dc``; the numeric suffix and domain are dropped.

    Args:
        dnshostname: Computer dNSHostName.

    Returns:
        Normalized alpha host prefix, or ``""``.
    """
    host = str(dnshostname or "").split(".")[0]
    # Strip trailing digits (site/index codes) so ``web03`` -> ``web``.
    host = re.sub(r"\d+$", "", host)
    return _normalize_token(host)


# ---------------------------------------------------------------------------
# whenCreated -> year (reuses password_year_variant_service for epoch values)
# ---------------------------------------------------------------------------


def when_created_to_year(value: object) -> int | None:
    """Resolve a four-digit year from a persisted ``whenCreated`` value.

    Handles the three shapes the collector may persist:

    * LDAP generalizedTime string ``"20220115000000.0Z"`` -> ``2022``.
    * ISO-ish string ``"2022-01-15..."`` -> ``2022``.
    * Epoch-second int/str -> delegated to
      :func:`password_year_variant_service.epoch_seconds_to_year` (single source
      of epoch->year math).

    Args:
        value: Raw ``whencreated`` property value.

    Returns:
        A plausible year in ``[_MIN_YEAR, 9999]``, else ``None``.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None

    # Pure digit run that is not a 4-digit year prefix -> treat as epoch seconds.
    if text.isdigit() and not re.match(r"^(19|20)\d{2}", text):
        return epoch_seconds_to_year(text)

    match = re.match(r"^(19|20)\d{2}", text)
    if match:
        year = int(match.group(0))
        if year >= _MIN_YEAR:
            return year
        return None

    return epoch_seconds_to_year(text)


# ---------------------------------------------------------------------------
# CORE — date seeding (spec §6)
# ---------------------------------------------------------------------------


def seed_dates_for(
    when_created_year: int | None,
    current_year: int,
    *,
    year_sweep_back: int = _DEFAULT_YEAR_SWEEP_BACK,
    creation_band_back: int = _CREATION_BAND_BACK,
    min_year: int = _MIN_YEAR,
) -> list[int]:
    """Seed a candidate year band for one object (spec §6, §10).

    Two independent seed sources, unioned:

    * **Creation band** — ``[when_created_year - creation_band_back ..
      when_created_year]``. Onboarding passwords are set at or just before
      account creation, so the creation contribution is bounded ABOVE by the
      creation year: it never seeds a year *after* creation. This is the
      "around/before, not after" rule.
    * **Recent band** — ``[current_year - year_sweep_back .. current_year]``.
      Passwords rotate forward, so recent years are always plausible regardless
      of when the account was created. This is a distinct seed, not a violation
      of the creation-band rule.

    whenCreated is used as a SEED, never a FILTER (spec §10): for the offline
    crack list the correct bias is recall — we ADD likely dates, we never remove
    candidates. Callers do not exclude anything based on the returned band.

    Args:
        when_created_year: Account creation year, or ``None`` when unknown.
        current_year: Injected current year (never ``datetime.now()``).
        year_sweep_back: Depth of the recent band. Pass the value from
            ``password_variation_plan_service.compute_dynamic_year_sweep_back``
            to key it on real legacy-cohort data.
        creation_band_back: Years below ``when_created_year`` to include.
        min_year: Sanity floor (AD timestamps before this are bogus).

    Returns:
        Sorted, deduped years clamped to ``[min_year, current_year]``.
    """
    years: set[int] = set()

    # Recent band — forward rotation.
    sweep = max(0, int(year_sweep_back))
    for year in range(current_year - sweep, current_year + 1):
        years.add(year)

    # Creation band — around/before creation only (never after).
    if when_created_year is not None:
        back = max(0, int(creation_band_back))
        for year in range(when_created_year - back, when_created_year + 1):
            years.add(year)

    return sorted(y for y in years if min_year <= y <= current_year)


def global_date_band(
    objects: Iterable[dict[str, Any]],
    current_year: int,
    *,
    year_sweep_back: int = _DEFAULT_YEAR_SWEEP_BACK,
) -> list[int]:
    """Union each object's :func:`seed_dates_for` band into one global band.

    hashcat runs a single ``-a 0`` wordlist for all hashes, so per-user year
    targeting is not expressible; the crack list uses the union of every
    object's band (spec §6). The per-user precision stays in the spray path's
    ``build_adaptive_year_spray_plan``.

    Args:
        objects: Persisted inventory records.
        current_year: Injected current year.
        year_sweep_back: Recent-band depth passed through to ``seed_dates_for``.

    Returns:
        Sorted, deduped global year band.
    """
    band: set[int] = set()
    saw_object = False
    for record in objects:
        saw_object = True
        props = record.get("properties") if isinstance(record, dict) else None
        wc_year = None
        if isinstance(props, dict):
            wc_year = when_created_to_year(props.get("whencreated"))
        band.update(
            seed_dates_for(wc_year, current_year, year_sweep_back=year_sweep_back)
        )
    if not saw_object:
        # No inventory -> still seed the recent band so calendar concat works.
        band.update(
            seed_dates_for(None, current_year, year_sweep_back=year_sweep_back)
        )
    return sorted(band)


# ---------------------------------------------------------------------------
# CORE — base-word mining (spec §4)
# ---------------------------------------------------------------------------


def _derive_netbios(context: WordlistContext) -> str:
    """Resolve a NetBIOS word — explicit if provided, else the FQDN first label."""
    explicit = _normalize_token(context.netbios)
    if explicit:
        return explicit
    first_label = str(context.domain or "").split(".")[0]
    return _normalize_token(first_label)


def mine_base_words(context: WordlistContext) -> BaseWordSet:
    """Mine provenance-tagged base words from persisted environment data (spec §4).

    Deterministic: the same context always yields the same ordered set. All words
    are normalized (lowercase, NFKD accent-stripped, alpha-only), deduped, and
    capped at ``_MAX_BASE_WORDS`` with a stable priority order
    (env-structural > operator-explicit > free-text).

    Args:
        context: Populated :class:`WordlistContext`. Missing fields are skipped
            gracefully.

    Returns:
        A :class:`BaseWordSet` with ordered base words and any verbatim literal
        password candidates found in description/info.
    """
    # Collect (word, provenance) with first-seen provenance winning so a token
    # mined from a high-rank source is never demoted by a later low-rank hit.
    best_provenance: dict[str, Provenance] = {}

    def _offer(word: str, provenance: Provenance) -> None:
        norm = _normalize_token(word)
        if len(norm) < _MIN_TOKEN_LEN:
            return
        current = best_provenance.get(norm)
        if current is None or _rank(provenance) < _rank(current):
            best_provenance[norm] = provenance

    # Env-structural (zero prompts, always on).
    for word in _company_words_from_domain(context.domain):
        _offer(word, "domain")
    netbios = _derive_netbios(context)
    if netbios:
        _offer(netbios, "netbios")
    if context.company:
        _offer(context.company, "company")

    literals: list[str] = []
    literals_seen: set[str] = set()

    for record in context.objects:
        if not isinstance(record, dict):
            continue
        sam = record.get("samaccountname") or ""
        # Skip machine accounts — their sAMAccountName ends with ``$`` and the
        # host prefix is mined from dNSHostName instead.
        if sam and not str(sam).endswith("$"):
            _offer(str(sam), "samaccount")

        dn = record.get("distinguished_name") or record.get("distinguishedname") or ""
        for token in _ou_city_tokens_from_dn(str(dn)):
            _offer(token, "ou_city")

        props = record.get("properties")
        if not isinstance(props, dict):
            continue

        host_prefix = _hostname_prefix_token(str(props.get("dnshostname") or ""))
        if host_prefix:
            _offer(host_prefix, "env_hostname")

        for field_name in ("description", "info_field", "info"):
            raw = props.get(field_name)
            if not raw:
                continue
            raw_str = str(raw)
            # A description that carries a verbatim password -> direct literal.
            for chunk in re.split(r"\s+", raw_str.strip()):
                if _looks_like_password(chunk) and chunk not in literals_seen:
                    literals_seen.add(chunk)
                    literals.append(chunk)
            for token in _split_free_text(raw_str):
                _offer(token, "env_description")

    # Operator-provided extras.
    for word in context.operator_words:
        _offer(word, "extra")

    # Order by (provenance rank, word) for stable, deterministic output, then cap.
    ordered = sorted(
        best_provenance.items(),
        key=lambda item: (_rank(item[1]), item[0]),
    )
    base_words = tuple(
        BaseWord(word=word, provenance=prov, priority=idx)
        for idx, (word, prov) in enumerate(ordered[:_MAX_BASE_WORDS])
    )
    return BaseWordSet(base_words=base_words, literals=tuple(literals))


def _rank(provenance: str) -> int:
    """Return the priority rank for a provenance (lower = kept first)."""
    return _PROVENANCE_RANK.get(provenance, _DEFAULT_PROVENANCE_RANK)


# ---------------------------------------------------------------------------
# CORE — the 3-layer word model + generation spec (spec §5)
# ---------------------------------------------------------------------------


def _baseline_seed_words(language_packs: Sequence[str]) -> list[str]:
    """Assemble layer 1 (baseline) + layer 3 (localization) seed words."""
    words: list[str] = []
    words.extend(BASELINE_WORDS)
    words.extend(SEASONS_EN)
    words.extend(KEYBOARD_WALKS)
    for code in language_packs:
        norm_code = str(code or "").strip().lower()
        if norm_code == "es":
            words.extend(SEASONS_ES)
        words.extend(LOCALIZATION_PACKS.get(norm_code, ()))
    return words


def build_generation_spec(
    base_words: BaseWordSet,
    dates: Sequence[int],
    *,
    language_packs: Sequence[str] = (),
    flags: LayerFlags | None = None,
) -> GenerationSpec:
    """Assemble the 3-layer model into a :class:`GenerationSpec` (spec §5).

    Pre-expand vs leave-to-rules (owner directive — keeps keyspace small):

    * **Pre-expand** (into ``literal_lines``): ONLY calendar concatenation
      ``<word><year>`` and ``<season><year>``, because a rule engine cannot
      synthesize the *client* year. Plus any verbatim mined literals.
    * **Leave to rules** (``seed_words`` only): case toggling, digit suffixes,
      symbol suffixes, leet — ``generate_variations`` /
      ``OneRuleToRuleThemStill`` already cover these at scale; pre-expanding them
      would explode the list for no recall gain.

    Args:
        base_words: Mined client base words (layer 2).
        dates: The global date band (from :func:`global_date_band`).
        language_packs: Localization codes for the baseline/season layers.
        flags: Which layers to include. Defaults to all-on.

    Returns:
        A deterministic :class:`GenerationSpec`.
    """
    flags = flags or LayerFlags()

    seed_words: list[str] = []
    seen: set[str] = set()

    def _add_seed(word: str) -> None:
        norm = _normalize_seed(word)
        if len(norm) < _MIN_TOKEN_LEN or norm in seen:
            return
        seen.add(norm)
        seed_words.append(norm)

    if flags.baseline or flags.localization:
        for word in _baseline_seed_words(language_packs):
            _add_seed(word)
    if flags.client:
        for bw in base_words.base_words:
            _add_seed(bw.word)

    date_tuple = tuple(sorted({int(d) for d in dates}))

    literal_lines: list[str] = []
    literals_seen: set[str] = set()

    def _add_literal(line: str) -> None:
        value = str(line or "").strip()
        if value and value not in literals_seen:
            literals_seen.add(value)
            literal_lines.append(value)

    # Verbatim mined literals (onboarding passwords in comments) are direct
    # candidates and are NOT re-mangled.
    for literal in base_words.literals:
        _add_literal(literal)

    # Calendar concatenation — the one thing rules cannot synthesize.
    if flags.pre_expand_calendar and date_tuple:
        for word in seed_words:
            for year in date_tuple:
                _add_literal(f"{word}{year}")
                _add_literal(f"{word}{str(year)[2:]}")

    return GenerationSpec(
        seed_words=tuple(seed_words),
        literal_lines=tuple(literal_lines),
        dates=date_tuple,
    )


def render_literal_lines(spec: GenerationSpec) -> list[str]:
    """Return the sorted, deduped literal candidate lines (deterministic).

    Args:
        spec: A built :class:`GenerationSpec`.

    Returns:
        Sorted unique ``literal.txt`` lines.
    """
    return sorted(set(spec.literal_lines))


def render_base_lines(spec: GenerationSpec) -> list[str]:
    """Return the sorted, deduped seed word lines for ``base.txt``.

    Args:
        spec: A built :class:`GenerationSpec`.

    Returns:
        Sorted unique seed words (rule/mangling fodder).
    """
    return sorted(set(word for word in spec.seed_words if word))


# ---------------------------------------------------------------------------
# CORE — top-level generator
# ---------------------------------------------------------------------------


def generate(
    context: WordlistContext,
    *,
    year_sweep_back: int = _DEFAULT_YEAR_SWEEP_BACK,
    flags: LayerFlags | None = None,
) -> GenerationSpec:
    """Run the full pure core: mine -> seed dates -> assemble the spec.

    Args:
        context: Populated :class:`WordlistContext` (``current_year`` injected).
        year_sweep_back: Recent-band depth for the date seed.
        flags: Layer selection.

    Returns:
        The assembled :class:`GenerationSpec`.
    """
    base_words = mine_base_words(context)
    dates = global_date_band(
        context.objects, context.current_year, year_sweep_back=year_sweep_back
    )
    return build_generation_spec(
        base_words,
        dates,
        language_packs=context.language_packs,
        flags=flags,
    )


# ---------------------------------------------------------------------------
# I/O — output directory + workspace inventory loader (thin)
# ---------------------------------------------------------------------------


def custom_wordlist_dir(domain: str, *, base_dir: Path | None = None) -> Path:
    """Resolve the per-domain custom wordlist asset directory.

    Mirrors the asset-dir convention of ``KerberosUsernameWordlistService``:
    host ``~/.adscan/wordlists/custom/<domain>/`` <-> container
    ``/opt/adscan/wordlists/custom/<domain>/`` (both resolve via the paths
    helper, so no path is hardcoded).

    Args:
        domain: Target domain.
        base_dir: Override for tests (defaults to ``~/.adscan``).

    Returns:
        The resolved directory Path (not yet created).
    """
    if base_dir is None:
        from adscan_core.paths import get_adscan_home_dir

        base_dir = get_adscan_home_dir()
    safe_domain = re.sub(r"[^A-Za-z0-9._-]", "_", str(domain or "unknown"))
    # Collapse any ``..`` run so the domain can never form a path-traversal
    # component, and trim leading/trailing dots.
    safe_domain = re.sub(r"\.{2,}", "_", safe_domain).strip(".") or "unknown"
    return base_dir / "wordlists" / "custom" / safe_domain


def load_objects_from_inventory(workspace_dir: str | Path, domain: str) -> list[dict[str, Any]]:
    """Load persisted user + computer inventory records for one domain.

    Best-effort: returns whatever records exist under
    ``<workspace_dir>/domains/<domain>/{users,computers}.json`` and an empty list
    when nothing is present. The pure core handles an empty object set.

    Args:
        workspace_dir: Workspace root directory.
        domain: Target domain.

    Returns:
        List of inventory record dicts (users + computers merged).
    """
    from adscan_core.rich_output import print_info_debug

    records: list[dict[str, Any]] = []
    domain_dir = Path(workspace_dir) / "domains" / domain
    for filename in ("users.json", "computers.json"):
        path = domain_dir / filename
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:  # noqa: PERF203
            print_info_debug(
                f"custom-wordlist: could not read {filename} for "
                f"{domain}: {exc}"
            )
            continue
        entries = payload.get("records") if isinstance(payload, dict) else None
        if isinstance(entries, list):
            records.extend(entry for entry in entries if isinstance(entry, dict))
    return records


# ---------------------------------------------------------------------------
# ADAPTERS (thin) — spec §3
# ---------------------------------------------------------------------------


def for_crack(
    context: WordlistContext,
    *,
    domain: str | None = None,
    output_dir: Path | None = None,
    year_sweep_back: int = _DEFAULT_YEAR_SWEEP_BACK,
    flags: LayerFlags | None = None,
    output_stem: str = "custom",
) -> CrackWordlistArtifact:
    """Offline-crack adapter: write ``base.txt`` + ``literal.txt`` + sidecar.

    No lockout logic (offline cracking has no lockout cost). The rules-ladder
    selection (``-r`` file, ``--runtime`` bound) is a LATER PR (spec §7); this
    adapter only produces the wordlists a rule engine will consume.

    Args:
        context: Populated :class:`WordlistContext`.
        domain: Target domain (defaults to ``context.domain``).
        output_dir: Directory to write into (defaults to the per-domain custom
            wordlist dir under ``~/.adscan``).
        year_sweep_back: Recent-band depth for the date seed.
        flags: Layer selection.
        output_stem: Base name for the sidecar (``<stem>_sources.json``).

    Returns:
        A :class:`CrackWordlistArtifact` with the written paths and counts.
    """
    resolved_domain = domain or context.domain or "unknown"
    base_word_set = mine_base_words(context)
    dates = global_date_band(
        context.objects, context.current_year, year_sweep_back=year_sweep_back
    )
    spec = build_generation_spec(
        base_word_set,
        dates,
        language_packs=context.language_packs,
        flags=flags,
    )

    target_dir = output_dir or custom_wordlist_dir(resolved_domain)
    target_dir.mkdir(parents=True, exist_ok=True)

    base_lines = render_base_lines(spec)
    literal_lines = render_literal_lines(spec)

    base_path = target_dir / "base.txt"
    literal_path = target_dir / "literal.txt"
    base_path.write_text("\n".join(base_lines) + ("\n" if base_lines else ""), encoding="utf-8")
    literal_path.write_text(
        "\n".join(literal_lines) + ("\n" if literal_lines else ""), encoding="utf-8"
    )

    provenance_counts: dict[str, int] = {}
    for bw in base_word_set.base_words:
        provenance_counts[bw.provenance] = provenance_counts.get(bw.provenance, 0) + 1

    sidecar_path = target_dir / f"{output_stem}_sources.json"
    sidecar_payload = {
        "domain": resolved_domain,
        "current_year": context.current_year,
        "date_band": list(spec.dates),
        "base_word_count": len(base_lines),
        "literal_count": len(literal_lines),
        "mined_literal_count": len(base_word_set.literals),
        "provenance_counts": provenance_counts,
        "base_words": [asdict(bw) for bw in base_word_set.base_words],
        "outputs": {
            "base": base_path.name,
            "literal": literal_path.name,
        },
    }
    sidecar_path.write_text(
        json.dumps(sidecar_payload, indent=2, sort_keys=True), encoding="utf-8"
    )

    return CrackWordlistArtifact(
        base_path=base_path,
        literal_path=literal_path,
        sidecar_path=sidecar_path,
        base_count=len(base_lines),
        literal_count=len(literal_lines),
        domain=resolved_domain,
    )


def for_spray(
    context: WordlistContext,
    *,
    include_baseline: bool = True,
) -> list[str]:
    """Online-spray adapter: return mined base words for the spray plan builders.

    This does NOT mangle or filter — the EXISTING
    ``build_variation_spray_plan`` / ``build_adaptive_year_spray_plan`` own
    mangling, per-user year targeting, and lockout + policy filtering (spec §8,
    §10). This adapter only supplies the base words those builders never had.

    Args:
        context: Populated :class:`WordlistContext`.
        include_baseline: When ``True``, prepend the always-on baseline words so
            a spray with zero mined words still has a floor.

    Returns:
        Ordered, deduped base-word strings (mangling fodder for the spray path).
    """
    mined = mine_base_words(context)
    out: list[str] = []
    seen: set[str] = set()

    def _push(word: str) -> None:
        norm = _normalize_seed(word)
        if len(norm) >= _MIN_TOKEN_LEN and norm not in seen:
            seen.add(norm)
            out.append(norm)

    # Client base words first — they are the highest-signal spray seeds.
    for bw in mined.base_words:
        _push(bw.word)
    if include_baseline:
        for word in _baseline_seed_words(context.language_packs):
            _push(word)
    return out


def build_context_from_workspace(
    *,
    workspace_dir: str | Path,
    domain: str,
    domain_data: dict[str, Any] | None = None,
    current_year: int | None = None,
) -> WordlistContext:
    """Assemble a :class:`WordlistContext` from a workspace + ``domains_data``.

    Single source of truth for turning on-disk inventory (users/computers) plus
    the domain's ``netbios`` / ``company`` fields into the generator input, so
    every adapter (crack, spray) builds the context the same way instead of
    inlining the recipe. Degrades gracefully: a missing/unreadable inventory
    yields an empty ``objects`` tuple (the generator still emits the baseline +
    company/netbios seeds).

    Args:
        workspace_dir: Container workspace root (host or container path).
        domain: Target domain FQDN.
        domain_data: The ``domains_data[domain]`` mapping (for netbios/company);
            ``None`` → treated as empty.
        current_year: Injected year for determinism; ``None`` → current UTC year.

    Returns:
        A populated :class:`WordlistContext`.
    """
    from datetime import datetime, timezone

    data = domain_data or {}
    try:
        objects = load_objects_from_inventory(workspace_dir, domain)
    except Exception:  # noqa: BLE001 — a missing inventory must never abort mining
        objects = []
    return WordlistContext(
        domain=str(domain or "").strip(),
        netbios=str(data.get("netbios") or "").strip(),
        company=str(data.get("company") or "").strip(),
        objects=tuple(objects),
        current_year=current_year or datetime.now(timezone.utc).year,
    )


def build_spray_candidates(
    *,
    workspace_dir: str | Path,
    domain: str,
    domain_data: dict[str, Any] | None = None,
    include_baseline: bool = True,
) -> list[str]:
    """Online-spray adapter with workspace-side context assembly.

    Convenience over :func:`build_context_from_workspace` + :func:`for_spray`:
    returns the ordered, deduped mined base words a spray flow offers as
    additional seed passwords. Each returned word is sprayed through the
    EXISTING lockout- and policy-aware plan builders unchanged — this adapter
    only supplies the seeds, it never mangles, filters, or multiplies attempts.

    Args:
        workspace_dir: Container workspace root.
        domain: Target domain FQDN.
        domain_data: ``domains_data[domain]`` mapping (netbios/company).
        include_baseline: Prepend the always-on baseline floor words.

    Returns:
        Ordered, deduped base-word strings (empty when nothing mined).
    """
    context = build_context_from_workspace(
        workspace_dir=workspace_dir, domain=domain, domain_data=domain_data
    )
    return for_spray(context, include_baseline=include_baseline)


__all__ = [
    "BASELINE_WORDS",
    "KEYBOARD_WALKS",
    "LOCALIZATION_PACKS",
    "SEASONS_EN",
    "SEASONS_ES",
    "BaseWord",
    "BaseWordSet",
    "CrackWordlistArtifact",
    "GenerationSpec",
    "LayerFlags",
    "WordlistContext",
    "build_generation_spec",
    "custom_wordlist_dir",
    "for_crack",
    "for_spray",
    "generate",
    "global_date_band",
    "load_objects_from_inventory",
    "mine_base_words",
    "render_base_lines",
    "render_literal_lines",
    "seed_dates_for",
    "when_created_to_year",
]
