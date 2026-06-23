"""Credential metadata services.

Premium, native-first helpers that decorate the legacy string-keyed
``domains_data[domain]["credentials"]`` mapping with rich provenance
metadata (``secret_kind`` and Kerberos-key material) without breaking
any existing consumer.

The string mapping remains the source of truth for credential *secrets*.
The metadata lives next to it in
``domains_data[domain]["credentials_meta"]`` keyed by the same
(lowercased) username. Consumers that don't know about the metadata see
no behavioural change.

Privilege classification (DA / EA / RID 500 / LAV / enabled) is now
resolved at read time from the canonical attack graph + identity-risk
store by :func:`pick_credential_for_local_admin`. Writers should pass a
:class:`CredentialMetadata` carrying only the non-derivable fields
(``secret_kind`` and Kerberos key material).
"""

from adscan_internal.services.credentials.credential_metadata import (
    CredentialMetadata,
)
from adscan_internal.services.credentials.privilege_role import (
    ROLE_PRIORITY,
    CredentialKind,
    CredentialPrivilegeRole,
    get_credential_meta,
    pick_credential_for_local_admin,
    set_credential_kerberos_material,
    set_credential_origin,
    set_credential_secret_kind,
)
from adscan_internal.services.credentials.credential_origin import (
    origin_display_label,
)

__all__ = [
    "ROLE_PRIORITY",
    "CredentialKind",
    "CredentialMetadata",
    "CredentialPrivilegeRole",
    "get_credential_meta",
    "origin_display_label",
    "pick_credential_for_local_admin",
    "set_credential_kerberos_material",
    "set_credential_origin",
    "set_credential_secret_kind",
]
