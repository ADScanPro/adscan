"""Data sources: where each detector family reads the facts it is decided from.

A finding or attack step is decided from one data source (the directory, a host's
registry, a certification authority's settings, a network probe...). Some sources
can go unread in a given run while the phase that hosts them still completes: the
account is not a local administrator of the host, the CA refuses its security
descriptor, a host does not answer. An item whose source was not read in a run
was NOT observed absent; its absence is not a fix (the Exposure-Validation rule).

This module is the single declaration of those sources. Each detector family in
``adscan_core.engagement.detectors`` names its ``source``; the rules that follow
from it:

* reconciliation (``reconcile``) words a gap on a family's own check with the
  source's ``basis`` (``check_skipped:host_registry_not_read``), the same token a
  recheck observer names (``basis_not_read:host_registry_not_read``), and both
  surfaces render it from :data:`BASIS_LABELS`;
* a family whose source ``can_go_unread`` must carry the gap somewhere
  reconciliation reads it: its own observation is required (``instrumented``),
  or the item's spec requires one of the source's ``gap_checks``, or the item is
  never closed by absence. ``tests/unit/core/engagement/test_source_declarations.py``
  fails when a family declares none of the three (its debt register lists the
  families still missing one, and only shrinks).

Stdlib only: the web backend and LITE on Windows import this package.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional

from adscan_core.engagement.specs import (
    C_COLLECTION_HOSTS,
    C_COLLECTION_MSSQL,
)


@dataclass(frozen=True)
class DataSource:
    """One source a detector family reads its facts from.

    Attributes:
        source_id: Stable id (``host.registry``).
        can_go_unread: Whether a run can complete its phase without reading
            this source (privilege, reachability or scope gated).
        basis: The ``basis_not_read`` token naming the read that was not
            obtained; empty for a source that cannot go unread.
        gap_checks: Coverage checks that already record this source's gap per
            run (the host sweep's examined set, the MSSQL sweep). An item whose
            spec requires one of them inherits the gap without its family
            having to record every outcome itself.
    """

    source_id: str
    can_go_unread: bool
    basis: str = ""
    gap_checks: tuple[str, ...] = ()


SOURCE_DIRECTORY = "directory"
SOURCE_PASSWORD_SETTINGS = "directory.password_settings"
SOURCE_SYSVOL = "domain.sysvol"
SOURCE_DC_PROBE = "dc.protocol_probe"
SOURCE_HOST_SMB = "host.smb_negotiate"
SOURCE_HOST_REGISTRY = "host.registry"
SOURCE_HOST_SAMR = "host.samr"
SOURCE_HOST_SHARE_ACL = "host.share_acl"
SOURCE_HOST_SHARE_CONTENT = "host.share_content"
SOURCE_HOST_MSSQL = "host.mssql"
SOURCE_HOST_PROBE = "host.network_probe"
SOURCE_CA_REGISTRY = "ca.registry"
SOURCE_CA_SECURITY = "ca.security"
SOURCE_CA_WEB_ENROLLMENT = "ca.web_enrollment"
#: Capture-, crack- and execution-derived outcomes. Their items are never closed
#: by absence (``never_auto``), so the source needs no gap record.
SOURCE_EXECUTION = "execution"

# Basis tokens. Persisted (an item's evaluation reason, a recheck verdict), so a
# token is never renamed; its copy in BASIS_LABELS may be reworded.
BASIS_HOST_REGISTRY = "host_registry_not_read"
BASIS_HOST_PROTOCOL = "host_protocol_not_read"
BASIS_HOST_NOT_EXAMINED = "host_not_examined"
BASIS_SHARE_PERMISSIONS = "share_permissions_not_read"
BASIS_SHARE_CONTENT = "share_content_not_read"
BASIS_SQL_SERVER = "sql_server_not_read"
BASIS_HOST_PROBE = "host_probe_not_answered"
BASIS_DC_PROBE = "dc_probe_not_answered"
BASIS_CA_REGISTRY = "ca_registry_not_read"
BASIS_CA_SECURITY = "ca_security_not_read"
BASIS_WEB_ENROLLMENT = "web_enrollment_not_verified"
BASIS_PASSWORD_SETTINGS = "fine_grained_policies_not_read"
BASIS_SYSVOL = "group_policy_files_not_read"

SOURCES: Mapping[str, DataSource] = {
    s.source_id: s
    for s in (
        DataSource(SOURCE_DIRECTORY, can_go_unread=False),
        DataSource(SOURCE_PASSWORD_SETTINGS, True, BASIS_PASSWORD_SETTINGS),
        DataSource(SOURCE_SYSVOL, True, BASIS_SYSVOL),
        DataSource(SOURCE_DC_PROBE, True, BASIS_DC_PROBE),
        DataSource(SOURCE_HOST_SMB, True, BASIS_HOST_PROTOCOL, (C_COLLECTION_HOSTS,)),
        DataSource(SOURCE_HOST_REGISTRY, True, BASIS_HOST_REGISTRY),
        DataSource(SOURCE_HOST_SAMR, True, BASIS_HOST_NOT_EXAMINED, (C_COLLECTION_HOSTS,)),
        DataSource(SOURCE_HOST_SHARE_ACL, True, BASIS_SHARE_PERMISSIONS),
        DataSource(SOURCE_HOST_SHARE_CONTENT, True, BASIS_SHARE_CONTENT),
        DataSource(SOURCE_HOST_MSSQL, True, BASIS_SQL_SERVER, (C_COLLECTION_MSSQL,)),
        DataSource(SOURCE_HOST_PROBE, True, BASIS_HOST_PROBE),
        DataSource(SOURCE_CA_REGISTRY, True, BASIS_CA_REGISTRY),
        DataSource(SOURCE_CA_SECURITY, True, BASIS_CA_SECURITY),
        DataSource(SOURCE_CA_WEB_ENROLLMENT, True, BASIS_WEB_ENROLLMENT),
        DataSource(SOURCE_EXECUTION, True),
    )
}

#: Client and operator copy per basis token: the read that was not obtained.
#: One copy for the scan lifecycle (``reporting.lifecycle_copy``) and the
#: recheck verdicts (``engagement.recheck``). It names what ADscan could not
#: read, never a defensive control.
BASIS_LABELS: Mapping[str, str] = {
    BASIS_HOST_REGISTRY: (
        "the registry of one or more hosts was not read, which needs local "
        "administrator rights on the host"
    ),
    BASIS_HOST_PROTOCOL: "one or more hosts did not answer the SMB protocol check",
    BASIS_HOST_NOT_EXAMINED: "one or more hosts were not fully examined",
    BASIS_SHARE_PERMISSIONS: "the permissions of one or more shares were not read",
    BASIS_SHARE_CONTENT: "one or more shares were not readable with this account",
    BASIS_SQL_SERVER: "SQL Server permissions were not read on every server",
    BASIS_HOST_PROBE: "one or more hosts did not answer the check",
    BASIS_DC_PROBE: "the domain controller did not give a definitive answer to the check",
    BASIS_CA_REGISTRY: (
        "the certification authority's registry settings were not read; "
        "reading them needs an administrator of the CA host"
    ),
    BASIS_CA_SECURITY: (
        "the certification authority's permissions were not read; "
        "reading them needs CA administrator rights"
    ),
    BASIS_WEB_ENROLLMENT: "the certification authority's web enrollment endpoint could not be verified",
    BASIS_PASSWORD_SETTINGS: "the fine-grained password policies were not readable with this account",
    BASIS_SYSVOL: "the Group Policy files were not read",
    # Reads a recheck observer names on a directory-derived family.
    "access_control_list_not_read": "an access control list it depends on was not returned",
    "issuance_policy_links_not_read": "the issuance policy links were not read",
}


def source(source_id: str) -> Optional[DataSource]:
    """The declared source ``source_id``, or ``None``."""
    return SOURCES.get(str(source_id or ""))


def basis_label(token: str) -> str:
    """Copy for a basis token; ``""`` when the token is not declared."""
    return BASIS_LABELS.get(str(token or ""), "")


__all__ = (
    "BASIS_LABELS",
    "DataSource",
    "SOURCES",
    "basis_label",
    "source",
)
