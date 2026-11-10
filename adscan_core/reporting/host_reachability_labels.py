"""Client labels for a host's reachability classification, declared once.

The port-scan reachability report (``adscan_internal/cli/nmap.py``) classifies
each host with an engine enum (``reachable_with_important_services``,
``likely_down_or_offline``...). The Enterprise inventory printed it verbatim on
every host card and as the "Classification" row of the host panel. This module
is the wording, and the web backend stamps ``classification_label`` beside the
raw value it serves. Standard library only, so the appliance backend imports it.
"""

from __future__ import annotations

from adscan_core.reporting.attack_step_labels import label_for

#: Engine reachability classification -> what the client reads.
HOST_CLASSIFICATION_LABELS: dict[str, str] = {
    "reachable_with_important_services": "Reachable, key services exposed",
    "reachable_no_important_services": "Reachable, no key services exposed",
    "reachable_discovery_only": "Reachable (discovery only)",
    "likely_down_or_offline": "Likely offline",
    "possible_segment_or_filtered": "Not reached from the scanner (filtered segment)",
}


def host_classification_label(value: object) -> str:
    """The client label for a reachability classification ("" when absent)."""
    return label_for(HOST_CLASSIFICATION_LABELS, value)


__all__ = ["HOST_CLASSIFICATION_LABELS", "host_classification_label"]
