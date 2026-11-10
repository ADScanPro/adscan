"""How a mapped compliance requirement is CITED to a client, in one place.

Every framework catalog is keyed by a string the engine uses to look a
requirement up, and for three of the six that key is not how anyone cites the
requirement. DORA's key is ``art_9_4_d`` and the citation is ``Art. 9(4)(d)``.
NIS2's is ``21.2.e`` against ``Art. 21(2)(e)``. PCI DSS keys on ``1`` and cites
``Req. 1``. The ENS, CIS and ISO 27001 happen to key on the citation itself
(``op.acc.5``, ``1.1.1``, ``A.5.15``), which is exactly why the defect survived:
half the frameworks looked right.

The rendered consequence, found in a render review of a real kit: the DORA
annex printed ``art_9_4_d`` in its Non-conformity Summary and its Control
Assessment, while the verified-clear line one paragraph above on the SAME page
printed ``Art. 21(2)(e)`` correctly, so one page cited requirements two ways. A
client's auditor reads ``art_9_4_d`` as an internal identifier that leaked, and
they are right.

The catalogs already hold the answer. DORA and NIS2 derive ``metadata["id"]``
from the transcribed regulatory universe at import, precisely so a citation is
a property of the text rather than of this engine. Nothing read it: the
requirement model stamped ``"id": requirement_id``, the raw key, and the
template rendered that.

So the rule is one function. A requirement's citation is its catalog
metadata's ``id`` when it carries one, and its key otherwise, because for the
three frameworks whose key IS the citation there is nothing else to read and
inventing a second field for them would be a migration with no reader.

``adscan_core`` so the web CTEM's control cards cite identically. Pure logic.
"""

from __future__ import annotations

from typing import Any, Mapping


def requirement_citation(requirement: Any) -> str:
    """Return how one mapped requirement is cited to a client.

    The ONE accessor every surface that prints a requirement identifier calls:
    the PDF's non-conformity rows and control cards, and the web CTEM's control
    cards. A surface that prints ``requirement["id"]`` instead prints an
    internal dictionary key for half the frameworks.

    Args:
        requirement: A requirement entry from
            ``compliance_engine.build_framework_requirement_model``, carrying
            its catalog ``metadata``. A mapping that is neither is tolerated
            and yields ``""``, because a deliverable ships without a citation
            rather than failing to render.

    Returns:
        The citation as an auditor writes it (``Art. 9(4)(d)``, ``op.acc.5``),
        or ``""`` when neither a metadata citation nor a key is present.
    """
    if not isinstance(requirement, Mapping):
        return ""
    metadata = requirement.get("metadata")
    if isinstance(metadata, Mapping):
        cited = str(metadata.get("id") or "").strip()
        if cited:
            return cited
    return str(requirement.get("id") or "").strip()


def requirement_display_name(requirement: Any) -> str:
    """Return the requirement's title, falling back to its citation.

    Paired with :func:`requirement_citation` so a fallback can never land on
    the raw key: the old fallback chain read ``metadata["name"] or req["id"]``,
    which printed ``art_10`` as the title of a requirement whose universe entry
    had no title.
    """
    if not isinstance(requirement, Mapping):
        return ""
    metadata = requirement.get("metadata")
    if isinstance(metadata, Mapping):
        name = str(metadata.get("name") or "").strip()
        if name:
            return name
    return requirement_citation(requirement)


__all__ = ["requirement_citation", "requirement_display_name"]
