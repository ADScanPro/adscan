"""Whether a deliverable may print a CVSS Base score at all.

Two separate questions, and the report answers them in order:

1. *Does this finding have a verifiable CVSS Base?* — answered by
   :attr:`adscan_core.cvss.calculator.BaseCvssResult.has_formal_base`, which is
   true only where the catalog carries a Base vector the FIRST equations can be
   recomputed from. That is a fact about the finding and never changes.
2. *Does the deliverable disclose it?* — answered here. The default is **no**.

Why the default is no
---------------------
Nothing requires a CVSS of this product. "CVSS" appears zero times in DORA and
both of its RTS, in NIS2 and its implementing regulation, in RD 311/2022, in the
ENS audit instruction and in CCN-STIC 808 and 804; PCI DSS mandates it only for
external ASV scanning, and routes internal assessment to the entity's own risk
ranking under requirement 6.3.1, where CVSS is offered as one example among
others. The three Active Directory specialists a CISO compares this report with
publish no CVSS per finding either.

What a regulated buyer can actually require is a documented, reproducible
methodology applied consistently. Most Active Directory exposures have no
published Base vector, so a report led by CVSS has to either leave most of its
findings blank or print a number nobody can recompute. Leading with the ADscan
severity model, with its inputs published in the report's own methodology annex,
answers the real requirement for every finding instead of a third of them.

The named exceptions, and how to reach them
------------------------------------------
Three engagements can legitimately ask for the Base score, and the third is the
one that actually happens:

1. A **Spanish public-procurement tender for a MANAGED SERVICE or a SOC**, where
   the pliego requires CVSS 3.1 with defined severity bands because the number
   drives an SLA. Three of ten real tenders reviewed do exactly this, and all
   three are managed-service; none of the audit-only or ENS-adequacy ones do.
   When a contract requires it, the contract wins.
2. An engagement scoped under a **CREST Defensible Penetration Test**, whose
   specification says a CVSS *should* be allocated. CREST defines "should" as a
   recommendation and ADscan is not CREST-badged, so this is a scope decision
   rather than an obligation.
3. A scope pinned to **PCI DSS external scanning**, the one place in that
   standard where a CVSS is genuinely mandated.

To turn it on, set ``ADSCAN_REPORT_CVSS_BASE=1`` in the environment that runs
the report. On the Linux deployment the launcher forwards it into the container
by wildcard, so exporting it before ``adscan deliver`` / ``adscan ci`` is enough;
in the appliance it goes in the Celery service environment, and on Windows it is
an ordinary process variable. Disclosure then shows a Base score ONLY for the
findings that carry a vector, printed beside that vector, and says plainly that
no CVSS Base applies to the rest. There is no path that prints a bare number.

The score and the vector are emitted into ``technical_report.json`` as a pair
either way, so the platform and any future surface keep the data without the
flag.

Why an environment variable and not a CLI flag
----------------------------------------------
The launcher forwards every ``ADSCAN_*`` host variable into the container by
wildcard, so this needs no entry in ``adscan_core.cli_passthrough_spec``, no
mirrored valid-set in the web request schema, no Celery command-builder change
and no frontend selector. A ``deliver``/``ci`` flag would have to be mirrored in
all four per the CLI-to-web lockstep rule, which is a wide surface for a switch
two engagement types in a hundred will ask for.
"""

from __future__ import annotations

import os

#: The environment variable that opts a deliverable into CVSS Base disclosure.
CVSS_BASE_DISCLOSURE_ENV = "ADSCAN_REPORT_CVSS_BASE"

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


def cvss_base_disclosure_enabled(env: object = None) -> bool:
    """Return whether this deliverable may print a CVSS Base score.

    Args:
        env: Optional mapping to read instead of ``os.environ``, for tests.

    Returns:
        ``True`` only when the operator opted in explicitly. Anything else,
        including an unset, empty or unparseable value, reads as off, so a
        deliverable never discloses a CVSS Base by accident.
    """
    source = env if hasattr(env, "get") else os.environ
    raw = source.get(CVSS_BASE_DISCLOSURE_ENV, "")  # type: ignore[union-attr]
    if not isinstance(raw, str):
        return False
    return raw.strip().lower() in _TRUE_VALUES


__all__ = [
    "CVSS_BASE_DISCLOSURE_ENV",
    "cvss_base_disclosure_enabled",
]
