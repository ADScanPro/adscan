"""Platform Abstraction Layer (PAL).

The single place in adscan_core where the runtime asks "which OS am I on".
Sub-interfaces (paths, process, auth, net, clock, tools) each pick a POSIX or
Windows backend via ``adscan_core.pal.platform``. adscan_core stays
dependency-light: PAL code imports only stdlib + rich/certifi and NEVER imports
adscan_internal or adscan_launcher.
"""
