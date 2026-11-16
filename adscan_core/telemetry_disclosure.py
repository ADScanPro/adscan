"""What ADscan tells a user about telemetry, worded once for every CLI surface.

Two surfaces print the telemetry block today (the launcher's install summary
and the in-container one); both read these rows so they cannot drift. The
public notice is ``/docs/telemetry`` on the site (``telemetry_notice`` CTA).

Wording rules (founder decision 2026-11-12):

* Never call it anonymous. Community telemetry is pseudonymous (a hashed
  install id), and PRO telemetry is linked to the licence, which is personal
  data processing under the GDPR. What is true for both is that it is
  SANITIZED: domains, hosts, IPs, users and credentials are pseudonymized or
  removed before anything leaves the machine.
* Say plainly that PRO telemetry is linked to the licence, as the support
  benefit it is, and how to turn it off.
* The Enterprise appliance forces it off; that surface states it separately.
"""

from __future__ import annotations

from adscan_core.pro_license.channel import LICENCE_CHANNEL_FIELDS

#: The scope keyword of ``set telemetry``. The telemetry preference service
#: (``SCOPE_GLOBAL``) reads it from here, so the parser and every string that
#: names the command cannot drift.
TELEMETRY_GLOBAL_KEYWORD = "global"

#: ``set telemetry off`` is handled by ``PentestShell.do_set`` (variable
#: ``telemetry``); there is no ``telemetry`` command. Without a keyword it changes
#: ONLY the current workspace.
TELEMETRY_OFF_WORKSPACE_COMMAND = "set telemetry off"

#: The same command with the ``global`` keyword: the persistent, machine-wide
#: default that every workspace inherits. Every string that promises "off for
#: every workspace" names this form.
TELEMETRY_OFF_GLOBAL_COMMAND = f"{TELEMETRY_OFF_WORKSPACE_COMMAND} {TELEMETRY_GLOBAL_KEYWORD}"

#: The matching "turn it back on" forms.
TELEMETRY_ON_WORKSPACE_COMMAND = "set telemetry on"
TELEMETRY_ON_GLOBAL_COMMAND = f"{TELEMETRY_ON_WORKSPACE_COMMAND} {TELEMETRY_GLOBAL_KEYWORD}"

#: Environment variable that turns telemetry off for one session or run.
TELEMETRY_OFF_ENV = "ADSCAN_TELEMETRY=0"

#: Launcher flag that turns telemetry off for one run.
TELEMETRY_RUN_FLAG = "--no-telemetry"

#: Status line suffix when telemetry is on.
TELEMETRY_ON_SUMMARY = "sanitized usage analytics"

#: Status line suffix when telemetry is off.
TELEMETRY_OFF_SUMMARY = "no data is collected"

#: ``(label, value)`` rows shown under the status line when telemetry is on.
TELEMETRY_DETAIL_ROWS: tuple[tuple[str, str], ...] = (
    ("What", "Commands run, feature usage, errors and sanitized, pseudonymized terminal output"),
    ("Sanitized", "IPs, domains, hosts, users and credentials are pseudonymized or removed"),
    ("PRO licence", "Linked to your licence ID so we can help you when something fails"),
    ("Session off", f"export {TELEMETRY_OFF_ENV}"),
    ("Permanent", f"{TELEMETRY_OFF_GLOBAL_COMMAND}  (inside ADscan, every workspace)"),
)

#: ``(label, value)`` rows for the Telemetry block of the PRO activation panel
#: (``adscan license activate``). Same facts as the install summary, worded for a
#: user who is about to run ADscan on a client environment.
TELEMETRY_ACTIVATION_ROWS: tuple[tuple[str, str], ...] = (
    ("Default", "On, in the interactive shell and in unattended runs such as adscan ci"),
    ("What", "Usage and diagnostic telemetry, including sanitized, pseudonymized terminal output"),
    ("Sanitized", "IPs, domains, hosts, users and credentials are pseudonymized or removed"),
    ("Licence", "Linked to this licence, so we can help you when something fails"),
    ("Off, one run", f"{TELEMETRY_RUN_FLAG} on adscan ci, or export {TELEMETRY_OFF_ENV}"),
    ("Off, always", f"{TELEMETRY_OFF_GLOBAL_COMMAND}  (inside ADscan, every workspace)"),
)

#: Rows for the Licence block. This is a separate channel from telemetry: it is part
#: of the licence, and the telemetry switches do not touch it. The fields come from
#: the channel SSOT so this block, the ``--offline`` info line and the site agree.
LICENCE_ACTIVATION_ROWS: tuple[tuple[str, str], ...] = (
    (
        "Check-in",
        "Every launch of ADscan PRO checks this licence with the ADscan licence server, "
        "also with --offline. A server that does not answer never blocks a scan.",
    ),
    (
        "Sent",
        f"{LICENCE_CHANNEL_FIELDS}, never scan data. Each domain you assess is registered "
        "as a one-way code tied to this licence plus a size band, never its name. The size counts "
        "are how many accounts, computers (by server or workstation, and by the tier their "
        "membership or role gives them), domain controllers and certificate authorities a run "
        "counted, never a name, an address or a finding.",
    ),
    (
        "Off switch",
        f"None. --offline, {TELEMETRY_RUN_FLAG}, {TELEMETRY_OFF_ENV}, {TELEMETRY_OFF_GLOBAL_COMMAND} "
        f"(every workspace) and {TELEMETRY_OFF_WORKSPACE_COMMAND} (this workspace only) "
        "do not change it, because it is part of the licence.",
    ),
    (
        "No route",
        "On a network with no route to ADscan, use the file relay "
        "(adscan license relay export, then import), or ask us for an offline engagement licence.",
    ),
)

#: Titles of the two activation blocks and of the panel.
TELEMETRY_ACTIVATION_TITLE = "Telemetry"
LICENCE_ACTIVATION_TITLE = "Licence check-in"
ACTIVATION_PANEL_TITLE = "What ADscan PRO sends"

__all__ = [
    "ACTIVATION_PANEL_TITLE",
    "LICENCE_ACTIVATION_ROWS",
    "LICENCE_ACTIVATION_TITLE",
    "TELEMETRY_ACTIVATION_ROWS",
    "TELEMETRY_ACTIVATION_TITLE",
    "TELEMETRY_GLOBAL_KEYWORD",
    "TELEMETRY_OFF_GLOBAL_COMMAND",
    "TELEMETRY_OFF_WORKSPACE_COMMAND",
    "TELEMETRY_ON_GLOBAL_COMMAND",
    "TELEMETRY_ON_WORKSPACE_COMMAND",
    "TELEMETRY_OFF_ENV",
    "TELEMETRY_RUN_FLAG",
    "TELEMETRY_DETAIL_ROWS",
    "TELEMETRY_OFF_SUMMARY",
    "TELEMETRY_ON_SUMMARY",
]
