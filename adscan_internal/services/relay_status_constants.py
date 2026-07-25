"""SSOT for relay-avenue status / blocked-reason strings.

Extracted from ``ntlmv1_relay_graph_builder`` so client-facing report code
(``attack_path_narratives``) can reference these constants WITHOUT importing the
heavy relay-graph engine. ``ntlmv1_relay_graph_builder`` transitively pulls the
posture / ``relay`` / ``models`` closure (and ``services/relay/__init__.py``
imports the native relay engine), none of which may be bundled into the
appliance backend — importing it from the report renderer was the taproot that
dragged 11 engine modules into the appliance import closure.

Keep this a pure **leaf**: stdlib only, NO ``adscan_internal`` imports.
``ntlmv1_relay_graph_builder`` re-exports these names for backward-compat, so
every existing ``ntlmv1_relay_graph_builder.<NAME>`` reference (internal uses +
tests) keeps resolving.
"""

from __future__ import annotations

# The exact reflection blocked-reason string (refinement 1). Shared with the
# report renderer and the L1 tests — keep it as the single source of truth.
REFLECTION_BLOCKED_REASON = "single DC — self-relay reflection-mitigated"

# Emitted when an eligible relay target exists topologically but has no usable
# LDAP endpoint (missing/empty FQDN on the selected DC node). This is an ADscan
# DATA-GAP (we could not resolve a relay target), NOT a client control — it must
# surface as ``unsupported`` (data-gap), never as ``closed_by_configuration``
# (which would credit the client with a defense that does not exist).
NO_RELAY_TARGET_REASON = "no DC LDAP relay target available"

# Status for a relay avenue ADscan observed to be CLOSED with certainty by the
# environment's configuration/topology — the LDAP signing + channel binding
# composite, no ADCS/NTAuth PKI, or single-DC self-relay reflection mitigation.
# (MAQ==0 is deliberately NOT here: it is a PARTIAL close — RBCD via an already
# owned computer account still works — so it routes to theoretical, see below.)
# This is a POSITIVE, in-category Exposure-Validation fact
# ("attack surface reduced"), NOT a risk finding and NOT a Security-Validation
# claim about a defensive tool (EDR/AV/MDI). ADscan is an exposure-validation
# product: it never attributes a non-execution to a defensive control it cannot
# observe. See CLAUDE.md § Status vocabularies.
CONFIGURATION_CLOSE_STATUS = "closed_by_configuration"
