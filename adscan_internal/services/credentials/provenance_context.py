"""Credential provenance derived from the runtime execution context.

Provenance is a property of the SEAM, not of the caller. Every credential
ADscan captures is stored through one funnel — ``cli.creds.add_credential`` —
and when that funnel runs INSIDE an executing attack step, the technique that
produced the credential is already known: it is the step's relation. This
module is the one place that inference happens, so a new credential-yielding
attack step inherits provenance without its author remembering to pass an
origin. It mirrors the doctrine the clock-sync guard already follows
(``dc_time.ensure_clock_synced_for_target`` at the transport seam): fix it once
at the seam, and every caller gets it for free.

Why it matters beyond tidiness: ``credential_origin`` is what the client
deliverable renders as "recovered via <technique>". A credential recovered by
an ADCS ESC that never stamped its origin reads as "Method not recorded" in a
paid report, understating what the assessment actually proved. The Essos
reference workspace had exactly that shape — four executed ESC steps, one
recorded origin.

Two rules govern the inference, and both exist to make a WRONG origin
impossible rather than merely unlikely. A wrong origin is worse than a missing
one: it tells a client a technique was used against their environment that
never ran.

1. **An explicit origin always wins.** The seam only fills a gap; it never
   overrides what a caller stated. A caller that knows better (an offline
   crack, a share harvest, the scan's own starting credential) keeps its answer.
2. **The step must genuinely be executing here and now, for THIS domain.** The
   inference is refused when no step is active, when the step belongs to a
   different domain (a cross-domain capture during a trust walk), or when the
   step was entered by a different thread (a background job runtime shares the
   shell object — see ``get_active_step``). The active-step lifecycle is a
   ``finally``-cleared context manager, so a step that ends leaves nothing
   behind for a later, unrelated credential to pick up.
"""

from __future__ import annotations

from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info_debug
from adscan_internal.services.credentials.credential_origin import (
    origin_slug_for_relation,
)


def _normalize_domain(value: Any) -> str:
    """Return a domain in the comparison form the credential store uses."""
    return str(value or "").strip().rstrip(".").lower()


def resolve_active_step_credential_origin(shell: Any, *, domain: str) -> str:
    """Return the origin slug implied by the attack step executing right now.

    Args:
        shell: Shell-like object carrying the runtime attack-step context.
        domain: Domain the credential is being stored under, already
            normalized by the caller (lowercase, no trailing dot).

    Returns:
        The canonical origin slug for the active step's relation (for example
        ``"adcsesc1"``), or ``""`` when no step is executing on this thread,
        when the step targets a different domain, or when its relation does not
        resolve to a slug. Never raises — a failure to infer provenance must
        never cost the capture itself.
    """
    try:
        from adscan_internal.services.attack_graph_runtime_service import (  # noqa: PLC0415
            get_active_step,
        )

        active = get_active_step(shell)
        if active is None:
            return ""
        target_domain = _normalize_domain(domain)
        if not target_domain or _normalize_domain(active.domain) != target_domain:
            return ""
        slug = origin_slug_for_relation(active.relation)
        if not slug:
            return ""
        print_info_debug(
            "credential-provenance: derived origin "
            f"{slug} from the active attack step (relation={active.relation})."
        )
        return slug
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return ""


__all__ = ["resolve_active_step_credential_origin"]
