"""Centralized credential recovery for the USER_NOT_FOUND verification verdict.

When a recovered credential (autologon, GPP, LSASS, DPAPI, manual entry,
attack-path) is verified and the DC answers
``KDC_ERR_C_PRINCIPAL_UNKNOWN`` (``CredentialStatus.USER_NOT_FOUND``), the
stored username is a lossy pointer to whoever actually owns the credential.
This module turns that dead-end into a recovery flow built on a single mental
model:

    The password is the verification oracle; the username is just a pointer.

So the question is never "fix the typo" but "which known account does this
secret authenticate as". Two complementary paths answer it:

* **Fuzzy fast path** — rank the failed username against the enumerated user
  list (stdlib :func:`difflib.get_close_matches`) and verify the most-likely
  owners with the recovered secret, stopping at the first VALID. OPSEC-bounded
  to a hard cap of distinct accounts so it can never degrade into an unbounded
  mini-spray (one auth attempt per distinct account = lockout-safe by
  construction).
* **Spray fallback** — when no fuzzy candidate verifies (or none exist), offer
  the existing lockout-safe spray engine across the known user list. The spray
  engine is a black box here: this module only invokes it, never reimplements
  its scope/lockout logic.

The recovery is invoked from the single choke point
``PentestShell.verify_domain_credentials`` (its ``USER_NOT_FOUND`` branch). The
protocol boundaries (candidate verification, spray, credential persistence) are
injected as callables so the orchestration is unit-testable without touching
the Kerberos or spray protocols.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from difflib import SequenceMatcher, get_close_matches
from typing import Callable

from adscan_core import telemetry
from adscan_core.rich_output import (
    print_info_debug,
    print_panel,
    print_step_status,
)

from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.credentials.privilege_role import set_credential_origin

# OPSEC: at most this many DISTINCT accounts are tested with one auth attempt
# each during the fuzzy fast path. One attempt per account keeps the fast path
# lockout-safe by construction; the cap stops it from degrading into an
# unbounded mini-spray. Raising it is an OPSEC decision, not a tuning knob.
_FUZZY_VERIFY_CAP = 3

# Number of ranked fuzzy candidates surfaced to the operator / considered.
_FUZZY_RANK_N = 5

# Similarity threshold for difflib. Matches the existing repo precedent
# (lab-name resolution in adscan.py) so behaviour is consistent across the
# product.
_FUZZY_CUTOFF = 0.6


@dataclass(frozen=True)
class FuzzyCandidate:
    """A ranked candidate username with its similarity score."""

    username: str
    score: float


def _resolve_workspace_cwd(shell: object) -> str:
    """Return the workspace CWD for a shell, tolerant of partial shells."""
    getter = getattr(shell, "_get_workspace_cwd", None)
    if callable(getter):
        try:
            resolved = getter()
            if resolved:
                return str(resolved)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
    fallback = getattr(shell, "current_workspace_dir", None)
    return str(fallback) if fallback else os.getcwd()


def _dedupe_preserving_order(names: list[str]) -> list[str]:
    """Deduplicate case-insensitively, preserving first-seen original case."""
    seen: set[str] = set()
    ordered: list[str] = []
    for raw in names:
        name = str(raw or "").strip()
        if not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(name)
    return ordered


def _load_users_json(shell: object, domain: str) -> list[str]:
    """Load samAccountNames from the canonical ``domains/<domain>/users.json``.

    Written by the unauthenticated inventory (``persist_unauth_users``); this
    is what makes recovery work for UNAUTH scans where no authenticated user
    list exists yet. Returns an empty list on any read/parse failure.
    """
    try:
        from adscan_internal.workspaces import domain_subpath

        workspace_cwd = _resolve_workspace_cwd(shell)
        domains_dir = getattr(shell, "domains_dir", "domains")
        users_path = domain_subpath(workspace_cwd, domains_dir, domain, "users.json")
        if not os.path.exists(users_path):
            return []
        with open(users_path, encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, list):
            return []
        names: list[str] = []
        for record in data:
            if isinstance(record, dict):
                sam = str(record.get("samaccountname") or "").strip()
                if sam:
                    names.append(sam)
        return names
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[credential_recovery] users.json load failed for "
            f"{mark_sensitive(domain, 'domain')}: {exc}"
        )
        return []


def load_recovery_candidates(shell: object, domain: str) -> list[str]:
    """Return the deduped candidate username pool for a domain.

    Priority cascade, first non-empty source wins (then deduped):

    1. ``enabled_users.txt`` (authenticated enumeration) via
       :func:`get_enabled_users_for_domain`.
    2. ``users.txt`` via :func:`_load_domain_users`.
    3. ``domains/<domain>/users.json`` (UNAUTH inventory).

    Reuses the existing loaders rather than re-reading files raw, so the same
    parsing/normalization rules apply everywhere. Works for both authenticated
    and unauthenticated scans.

    Args:
        shell: The active shell (for workspace/domain resolution).
        domain: Target domain whose user list to load.

    Returns:
        A deduped list of candidate usernames in original case (may be empty).
    """
    try:
        from adscan_internal.services.attack_graph_service import (
            _load_domain_users,
            get_enabled_users_for_domain,
        )

        enabled = get_enabled_users_for_domain(shell, domain)
        if enabled:
            return _dedupe_preserving_order(sorted(enabled))

        users_txt = _load_domain_users(shell, domain)
        if users_txt:
            return _dedupe_preserving_order(list(users_txt))
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[credential_recovery] authenticated user-list load failed for "
            f"{mark_sensitive(domain, 'domain')}: {exc}"
        )

    return _dedupe_preserving_order(_load_users_json(shell, domain))


def fuzzy_rank_candidates(
    failed_username: str,
    candidates: list[str],
    *,
    n: int = _FUZZY_RANK_N,
    cutoff: float = _FUZZY_CUTOFF,
) -> list[FuzzyCandidate]:
    """Rank candidates by similarity to the failed username.

    Uses stdlib :func:`difflib.get_close_matches` (no new dependency). The
    failed username and candidates are compared case-insensitively; the
    returned ``username`` preserves the candidate's original case so it can be
    persisted as-is.

    Args:
        failed_username: The username the DC reported as not found.
        candidates: The candidate username pool.
        n: Maximum number of ranked candidates to return.
        cutoff: Minimum similarity ratio (0..1) to qualify as a match.

    Returns:
        Ranked :class:`FuzzyCandidate` list, highest score first. The failed
        username itself is never returned (an exact match would not have
        produced USER_NOT_FOUND).
    """
    failed = str(failed_username or "").strip()
    if not failed or not candidates:
        return []

    failed_key = failed.lower()
    # Map lowercase key -> first original-case candidate, excluding the failed
    # name itself so we never "recover" to the same value.
    key_to_original: dict[str, str] = {}
    for candidate in candidates:
        name = str(candidate or "").strip()
        if not name:
            continue
        key = name.lower()
        if key == failed_key:
            continue
        key_to_original.setdefault(key, name)

    if not key_to_original:
        return []

    matches = get_close_matches(
        failed_key, list(key_to_original.keys()), n=n, cutoff=cutoff
    )

    ranked: list[FuzzyCandidate] = []
    for match_key in matches:
        score = SequenceMatcher(None, failed_key, match_key).ratio()
        ranked.append(FuzzyCandidate(username=key_to_original[match_key], score=score))
    return ranked


@dataclass(frozen=True)
class RecoveryResult:
    """Outcome of a credential-recovery attempt at the USER_NOT_FOUND branch."""

    resolved: bool
    resolved_username: str | None = None


def recover_user_not_found(
    shell: object,
    *,
    domain: str,
    failed_user: str,
    cred_value: str,
    verify_candidate: Callable[[str], bool],
    add_credential: Callable[[str], None],
    spray: Callable[[], None],
    confirm_spray: Callable[[], bool],
    prompt_manual_username: Callable[[], str | None],
    source_steps: list[object] | None = None,
    credential_origin: str = "credential_recovery",
) -> RecoveryResult:
    """Run the locked USER_NOT_FOUND recovery cascade.

    The cascade (decisions are locked):

    1. Load known users (cascade loader). Fuzzy-rank the failed username.
    2. Verify the top candidates with the recovered secret in similarity
       order, STOP at the first VALID, capped at :data:`_FUZZY_VERIFY_CAP`
       distinct accounts (one auth attempt each = lockout-safe).
    3. First VALID candidate is auto-adopted silently (it is proof, not a
       guess) and persisted via ``add_credential``.
    4. If no fuzzy candidate verifies (or none exist), offer to spray the
       recovered password across the known users using the existing engine.
    5. Manual escape: if recovery and spray yield nothing or the operator
       declines, let the operator enter the correct username or skip.

    The protocol boundaries (``verify_candidate``, ``spray``,
    ``add_credential``) are injected so this orchestration is unit-testable
    without exercising the Kerberos or spray protocols.

    Args:
        shell: The active shell.
        domain: Target domain.
        failed_user: The username the DC reported as not found.
        cred_value: The recovered secret (password or hash) to verify with.
        verify_candidate: Verifies a candidate username against ``cred_value``;
            returns True when VALID. Each call is one auth attempt.
        add_credential: Persists the resolved (domain, username, cred_value).
            Takes the resolved username.
        spray: Invokes the existing lockout-safe spray engine. No-arg.
        confirm_spray: Asks the operator whether to spray; auto-resolves in CI.
        prompt_manual_username: Prompts for a manual username or skip; returns
            the entered name, or None to skip.
        source_steps: Provenance steps threaded through to persistence/spray.
        credential_origin: Machine-readable provenance slug recorded for the
            resolved/manual credential so the Provenance column attributes the
            recovery technique instead of degrading to "via unknown". Applied
            as a backstop after the injected ``add_credential`` callback runs.

    Returns:
        A :class:`RecoveryResult` describing whether a credential was resolved.
    """
    marked_domain = mark_sensitive(domain, "domain")
    marked_failed_user = mark_sensitive(failed_user, "user")

    print_panel(
        f"The domain controller does not recognize "
        f"[bold]{marked_failed_user}[/bold], but the recovered secret is still "
        f"valid for whoever owns it. Searching the known accounts of "
        f"[bold]{marked_domain}[/bold] for the real owner.",
        title="🔑 Credential Recovery",
        border_style="cyan",
    )

    candidates = load_recovery_candidates(shell, domain)
    print_step_status(
        "Loading known accounts",
        status="completed" if candidates else "skipped",
        details=(
            f"{len(candidates)} known account(s)"
            if candidates
            else "no enumerated user list available"
        ),
    )

    ranked = fuzzy_rank_candidates(failed_user, candidates)

    # --- Fuzzy fast path: verify most-likely owners, stop at first VALID. ---
    if ranked:
        to_test = ranked[:_FUZZY_VERIFY_CAP]
        print_step_status(
            "Matching the secret to its likely owner",
            status="running",
            details=f"testing top {len(to_test)} of {len(ranked)} match(es)",
        )
        for candidate in to_test:
            marked_candidate = mark_sensitive(candidate.username, "user")
            pct = round(candidate.score * 100)
            print_info_debug(
                f"[credential_recovery] verifying candidate {marked_candidate} "
                f"({pct}% match) for {marked_domain}"
            )
            try:
                is_valid = bool(verify_candidate(candidate.username))
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_info_debug(
                    f"[credential_recovery] candidate verification raised for "
                    f"{marked_candidate}: {exc}"
                )
                continue

            if is_valid:
                # Auto-adopt: this is proof, not a guess. Persist silently.
                try:
                    add_credential(candidate.username)
                    set_credential_origin(
                        shell,
                        domain=domain,
                        username=candidate.username,
                        origin=credential_origin,
                    )
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_info_debug(
                        f"[credential_recovery] persisting resolved credential "
                        f"failed for {marked_candidate}: {exc}"
                    )
                print_step_status(
                    "Matching the secret to its likely owner",
                    status="completed",
                    details=f"resolved at {pct}% match",
                )
                print_panel(
                    f"Stored username [bold]{marked_failed_user}[/bold] resolved to "
                    f"[bold]{marked_candidate}[/bold] "
                    f"({pct}% match, password verified ✓).\n"
                    f"The credential was added under the verified account.",
                    title="✓ Credential Recovered",
                    border_style="green",
                )
                return RecoveryResult(
                    resolved=True, resolved_username=candidate.username
                )

        print_step_status(
            "Matching the secret to its likely owner",
            status="failed",
            details="no close match owns this secret",
        )

    # --- Spray fallback: no fuzzy candidate verified, or none existed. ---
    spray_reason = (
        "None of the closest accounts own this secret."
        if ranked
        else "No close username match was found."
    )
    if candidates:
        print_panel(
            f"{spray_reason} The recovered password can be sprayed across the "
            f"known accounts of [bold]{marked_domain}[/bold] to find its owner. "
            f"Spraying is lockout-aware and skips at-risk accounts.",
            title="🔁 Spray Fallback",
            border_style="yellow",
        )
        try:
            wants_spray = bool(confirm_spray())
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            wants_spray = False

        if wants_spray:
            print_step_status(
                "Spraying the recovered password",
                status="running",
                details=f"{len(candidates)} known account(s)",
            )
            try:
                spray()
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_info_debug(
                    f"[credential_recovery] spray fallback raised: {exc}"
                )
            # The spray engine persists its own hits via add_credential and is
            # the authority on whether anything was found; recovery does not
            # claim resolution on its behalf.
            return RecoveryResult(resolved=False)
    else:
        print_info_debug(
            "[credential_recovery] no known user list; spray fallback skipped."
        )

    # --- Manual escape: operator enters the correct username or skips. ---
    manual_name = prompt_manual_username()
    if manual_name:
        marked_manual = mark_sensitive(manual_name, "user")
        try:
            add_credential(manual_name)
            set_credential_origin(
                shell, domain=domain, username=manual_name, origin=credential_origin
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[credential_recovery] persisting manual credential failed for "
                f"{marked_manual}: {exc}"
            )
        return RecoveryResult(resolved=False, resolved_username=manual_name)

    return RecoveryResult(resolved=False)


__all__ = [
    "FuzzyCandidate",
    "RecoveryResult",
    "load_recovery_candidates",
    "fuzzy_rank_candidates",
    "recover_user_not_found",
]
