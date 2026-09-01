"""Well-known SID constants shared by the ADCS detectors."""

from __future__ import annotations

# Authenticated Users — the broadest actor for an NTLM-relay ADCS avenue
# (ESC8/ESC11): the relay only needs the authenticating principal to hold ANY
# valid domain credential, which is cross-forest capable. The collector injects
# this well-known node into the graph before persistence, so an edge sourced
# here always resolves.
AUTHENTICATED_USERS_SID = "S-1-5-11"
