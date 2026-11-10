"""Drop the MIC (CVE-2019-1040) native check.

The flaw (Preempt, June 2019): a server accepted an NTLM AUTHENTICATE whose
``MsvAvFlags`` announced a MIC although the message carried none, so a relay
could remove the MIC (with the Version field and the signing / key-exchange
flags) and strip the signing request from a relayed authentication. The June
2019 update makes the server enforce the MIC whenever ``MsvAvFlags`` announces
it.

Detection: one authenticated SMB session setup whose NTLMv2 response announces a
MIC (``MsvAvFlags`` = 0x2, covered by a genuine NTProofStr) while the
AUTHENTICATE carries no MIC and no Version. ``STATUS_SUCCESS`` means the server
did not enforce the MIC: vulnerable. A patched server rejects it
(``STATUS_INVALID_PARAMETER``). This is the construction of the public Fox-IT
scanner for this CVE.

References:
    https://nvd.nist.gov/vuln/detail/CVE-2019-1040
    https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-1040
    https://www.crowdstrike.com/en-us/blog/from-the-archives-drop-the-mic-cve-2019-1040/
"""

from __future__ import annotations

from adscan_internal.services.cve_scanner.checks._ntlm_mic_bypass_check import (
    NTLMMICBypassCheck,
)
from adscan_internal.services.cve_scanner.checks._ntlm_mic_probe import (
    MIC_ANNOUNCED_NOT_SENT,
)

CVE_ID = "CVE-2019-1040"
AKA = "DropTheMIC"
# NVD (NIST) base score; the record publishes it as CVSS 3.0.
CVSS_V3 = 5.9
CVSS_VECTOR = "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"


class DropTheMICCheck(NTLMMICBypassCheck):
    """Native Drop the MIC (CVE-2019-1040) detection check."""

    cve_id = CVE_ID
    aka = AKA
    display_name = "Drop the MIC"
    log_tag = "drop-the-mic"
    cvss_v3 = CVSS_V3
    cvss_vector = CVSS_VECTOR
    msv_av_flags = MIC_ANNOUNCED_NOT_SENT
    accepted_summary = (
        "server accepted an AUTHENTICATE message that announced a MIC and carried "
        "none: Drop the MIC (CVE-2019-1040)"
    )


__all__ = ["AKA", "CVE_ID", "CVSS_V3", "CVSS_VECTOR", "DropTheMICCheck"]
