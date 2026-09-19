"""Attack-graph NODE label display — re-export of the shared ``adscan_core`` SSOT.

The implementation moved to
:func:`adscan_core.reporting.principal_display.format_graph_node_label` so the
``adscan_internal``-free web/appliance backend can consume the EXACT same
node-label humanizer the PDF report graph does, without crossing the tier
boundary. This module stays as the stable import path for the report side
(``pro/reporting/attack_path_narratives.format_node_label`` and
``html_pdf_generator``) and re-exports it verbatim, so there is ONE implementation
the report graph and the web CTEM can never diverge from.

An attack-graph node is one of a few shapes, and a client-facing surface must
render every one of them the SAME way whether it is the PDF report graph or the
paid web CTEM attack-graph:

* a **principal** — ``NAME@DOMAIN`` / ``NAME@WELLKNOWN`` / a bare / ``SID@REALM``
  SID — is humanized through the prose SSOT (human casing, no shouting UPN, no
  ``@domain`` on a single-domain name, a well-known name in its canonical case,
  the ``@domain`` qualifier kept only cross-domain).
* a **NetBIOS** ``DOMAIN\\name`` label — the ``DOMAIN\\`` prefix is dropped when it
  matches the report domain (or there is none to compare against).
* a **host FQDN** ``host.domain`` — compacted to the short host name intra-domain.
* the **domain node** and any other shape — returned unchanged.
"""

from __future__ import annotations

from adscan_core.reporting.principal_display import (  # noqa: F401
    format_graph_node_label,
    humanize_domain_for_display,
)
