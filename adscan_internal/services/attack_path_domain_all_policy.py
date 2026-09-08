"""Policy for the domain-scope all-targets attack-path lens.

The ``scope=domain`` + ``target=all`` combination is the most severe traversal
mode the attack-path engine offers. On a large, hub-heavy directory (an Exchange
or Account Operators principal holding a control primitive over tens of thousands
of objects) it explodes the DFS to the memory/state bound and returns a
coverage-bounded stop — or no paths at all. The 11.3.0 memory bounds already
prevent a hard SIGKILL, but silently running the worst-case mode against a graph
where it cannot complete leaves the operator with a truncated or empty result and
no explanation.

That mode is not used by any production flow: the report and the web CTEM view
use ``scope=domain`` + ``target=highvalue``, and attack-path execution uses
``scope=owned`` + ``target=all`` (where all-targets IS the money-path mode). So
the domain-wide all-targets lens is treated as a DEV-ONLY capability:

* The engine (``attack_graph_core`` / ``attack_paths_core``) and the debug script
  ``scripts/debug_attack_path_filters.py`` keep it fully working — that is how the
  Potech OOM was reproduced and how benchmarks are run.
* Production surfaces (the CLI ``attack_paths <domain> --all`` at domain scope and
  the paid CTEM web backend) coerce it to the canonical high-value lens, so a
  customer run never launches the doomed worst case and a direct web API call
  cannot either.

The CLI keeps a dev escape hatch (the canonical ``dev`` environment signal) so a
maintainer can still force domain+all in the CLI for investigation; the web is the
customer product and coerces unconditionally.
"""

from __future__ import annotations

import os

# Shared "not supported in production" note. Both the CLI and the web CTEM backend
# render this so the two surfaces word the coercion identically (CLI ↔ web
# alignment). Human-grade, client-safe prose.
DOMAIN_ALL_UNSUPPORTED_NOTE = (
    "Domain-wide all-targets discovery is not available: it cannot complete on a "
    "large directory, and the report and execution flows never use it. Showing "
    "high-value (Tier-0) targets instead."
)


def is_domain_scope_all_targets(scope: str | None, target: str | None) -> bool:
    """Return whether this is the domain-scope all-targets combination.

    Args:
        scope: The compute scope (``"domain"``, ``"owned"``, ``"user"``,
            ``"principals"``). Only ``"domain"`` is guarded.
        target: The target class (``"highvalue"``, ``"all"``, ``"lowpriv"``).
            Only ``"all"`` is guarded.

    Returns:
        ``True`` only for ``scope="domain"`` and ``target="all"``. Every other
        combination (owned+all, domain+highvalue, user/principals scope) returns
        ``False`` and is never coerced.
    """
    return (str(scope or "").strip().lower() == "domain") and (
        str(target or "").strip().lower() == "all"
    )


def is_dev_override_active() -> bool:
    """Return whether the dev escape hatch for domain+all is active.

    Reuses ADscan's canonical environment classifier (machine-id + the
    ``ADSCAN_SESSION_ENV`` / ``ADSCAN_ENV`` override) rather than a bespoke
    toggle. Returns ``True`` only when the session environment resolves to
    ``"dev"`` — so on a maintainer's dev machine, or when the env override is set
    to ``dev``. Best-effort: any failure resolving the environment is treated as
    NOT dev (production), so the safe coercion still applies.
    """
    try:
        from adscan_core.telemetry import _determine_environment

        if str(_determine_environment() or "").strip().lower() == "dev":
            return True
    except Exception:  # noqa: BLE001 - never let env detection break the guard
        pass
    # Direct env fallback in case the classifier is unavailable in a stripped
    # runtime (kept in lockstep with the classifier's own override keys).
    for key in ("ADSCAN_SESSION_ENV", "ADSCAN_ENV"):
        if str(os.getenv(key, "") or "").strip().lower() == "dev":
            return True
    return False
