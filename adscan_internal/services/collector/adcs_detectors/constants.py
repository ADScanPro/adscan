"""Constants for ADCS ESC detection (flag bits and EKU OIDs)."""

from __future__ import annotations

# msPKI-Certificate-Name-Flag bits (CT_FLAG_*).
#
# Values are the canonical CT_FLAG constants from MS-CRTD 2.28
# (msPKI-Certificate-Name-Flag Attribute), cross-checked against certipy
# (reference/Certipy/certipy/lib/constants.py, MsPkiCertificateNameFlag). The
# SUBJECT_ALT_REQUIRE_* block occupies the top byte; they must NOT be confused
# with the ADD_*/SUBJECT_REQUIRE_* bits. A prior nibble-shift here set UPN to
# 0x00200000 and EMAIL to 0x00400000, so the ESC14 "email SAN" test actually
# matched the DOMAIN_DNS bit (0x00400000) — ordinary machine/DC DNS-SAN
# templates then matched ESC14 in every environment. Locked by
# tests/unit/services/collector/test_adcs_name_flag_constants.py.
ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000
SUBJECT_ALT_REQUIRE_SPN = 0x00800000
SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000
SUBJECT_ALT_REQUIRE_UPN = 0x02000000
SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000
SUBJECT_ALT_REQUIRE_DNS = 0x08000000

# msPKI-Enrollment-Flag bits
PEND_ALL_REQUESTS = 0x00000002  # CT_FLAG_PEND_ALL_REQUESTS — manager approval
NO_SECURITY_EXTENSION = 0x00080000  # CT_FLAG_NO_SECURITY_EXTENSION

# Common EKUs (Extended Key Usage OIDs)
EKU_ANY_PURPOSE = "2.5.29.37.0"
EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_SMART_CARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
EKU_PKINIT_CLIENT_AUTH = "1.3.6.1.5.2.3.4"
EKU_CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"

CLIENT_AUTHENTICATION_EKUS = frozenset(
    {
        EKU_CLIENT_AUTH,
        EKU_SMART_CARD_LOGON,
        EKU_PKINIT_CLIENT_AUTH,
        EKU_ANY_PURPOSE,
    }
)

# Schannel CertificateMappingMethods bits (HKLM\System\CurrentControlSet\
# Control\SecurityProviders\SCHANNEL\CertificateMappingMethods)
CERT_MAPPING_ONE_TO_ONE = 0x0001
CERT_MAPPING_MANY_TO_ONE = 0x0002
CERT_MAPPING_UPN = 0x0004
CERT_MAPPING_S4U2SELF = 0x0008
CERT_MAPPING_S4U2SELF_EXPLICIT = 0x0010
