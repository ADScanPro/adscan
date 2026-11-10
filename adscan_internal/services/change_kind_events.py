"""Which Windows events each change ADscan makes produces (single source of truth).

A technique's signals are what it leaves for a SOC to see. Two halves make them
up, and only one is free text:

* the events its declared CHANGES produce (``environment_change_kinds`` in the
  attack-step catalog), which this module derives from the map below; and
* the events of the technique's own reads and sign-ins (a Kerberos ticket
  request, a network logon, an object read), declared on the catalog entry.

So an event that only a write produces (a directory object modified, an account
created, a service installed) can appear on a row only when that row declares
the write. The client matrix once listed a service installation (7045) for two
SQL escalations that install none, and a directory write (5136) for a step that
only reads. ``tests/unit/services/test_change_kind_events.py`` fails when a
declared change has no event here, when an executed technique's catalog events
miss one its changes produce, or when it lists a write-only event no declared
change causes.

Event ids are the Windows Security log unless ``safeguard_profile._EVENT_LOG_ES``
places them elsewhere (7045 System, 15457 SQL Server error log, 33205 SQL Server
Audit).
"""

from __future__ import annotations

from typing import Any

#: change kind -> the events that change produces.
CHANGE_KIND_EVENT_IDS: dict[str, tuple[str, ...]] = {
    # Directory attribute writes: "A directory service object was modified".
    "shadow_credentials_added": ("5136",),
    "keycredentiallink_added": ("5136",),
    "dacl_ace_added": ("5136",),
    "dacl_grant_dcsync": ("5136",),
    "owner_changed": ("5136",),
    "spn_added": ("5136",),
    "spn_relocated": ("5136",),
    "rbcd_delegation_added": ("5136",),
    "template_mutated": ("5136",),
    "rodc_prp_modified": ("5136",),
    "logon_script_path_modified": ("5136",),
    "upn_changed": ("5136",),
    "altsecurityidentities_written": ("5136",),
    "victim_attribute_written": ("5136",),
    # Publishing a template on a CA writes the CA's enrollment-service object.
    "ca_template_enabled": ("5136",),
    "gpo_ldap_attribute_modified": ("5136",),
    # Directory objects created or undeleted.
    "dns_record_added": ("5137",),
    "object_restored": ("5138",),
    # Accounts.
    "password_changed": ("4723", "4724"),
    "account_enabled": ("4722",),
    "user_created": ("4720",),
    "machine_account_created": ("4741",),
    "computer_account_created": ("4741",),
    "group_membership_added": ("4728", "4732", "4756"),
    "group_membership_changed": ("4728", "4732", "4756"),
    # A domain account in Domain Admins on a domain controller, a local
    # Administrator elsewhere, or Domain Admins membership on an existing one.
    "mssql_postex_account": ("4720", "4728", "4732", "4756"),
    "mssql_admin_account_created": ("4720", "4732"),
    # Certificate Services.
    "issued_certificate": ("4886", "4887"),
    "ca_officer_added": ("4882",),
    # Host-side writes.
    "scheduled_task_created": ("4698",),
    "ca_backup_service": ("7045",),
    "ca_backup_temp_pfx": ("4663",),
    "file_written": ("4663",),
    "file_uploaded": ("5145",),
    "gpo_gpt_ini_modified": ("5145",),
    "gpo_sysvol_dir_created": ("5145",),
    "gpo_sysvol_file_created": ("5145",),
    # SQL Server.
    "mssql_xp_cmdshell_enabled": ("15457",),
    "mssql_clr_config_changed": ("15457",),
    "mssql_clr_assembly_loaded": ("33205",),
    # No event of their own, each for a stated reason:
    # the forged certificate is signed off the CA, so the CA database never sees
    # it; the CA key is read through the temporary service, whose 7045 is the
    # signal.
    "forged_certificate": (),
    "ca_private_key_exfiltrated": (),
}

#: Events only a write produces. Object reads (4662, 4663 under a SACL), share
#: access (5140, 5145), sign-ins and ticket requests can come from a read too,
#: so they are allowed as the technique's own signals.
WRITE_ONLY_EVENT_IDS: frozenset[str] = frozenset(
    {
        "5136", "5137", "5138", "4720", "4722", "4723", "4724", "4728", "4732",
        "4756", "4741", "4742", "4698", "7045", "4886", "4887", "4882", "15457",
        "33205", "4657",
    }
)


#: Where one technique makes a narrower form of a kind than the kind covers.
#: ScheduledTask's create+addmember plan adds its account to Domain Admins (a
#: global group, 4728) from whichever host holds the session, and only when the
#: session user already administers the domain (the rights ladder, 8e71fc3ec).
#: It never adds to a host's local Administrators (4732) or to a universal group
#: (cli/attack_path_execution.py, the group_membership_added write sites).
RELATION_KIND_EVENT_IDS: dict[tuple[str, str], tuple[str, ...]] = {
    ("scheduledtask", "group_membership_added"): ("4728",),
}


#: The events a sign-in leaves, success or failure, NTLM or Kerberos: a network
#: logon (4624) or a failed one (4625), a ticket granted (4768) or refused at
#: pre-authentication (4771). Every step whose sign-ins can count toward
#: lockout (``lockout_risk`` bounded or possible) lists them: the matrix once
#: called three of those steps read-only because only their reads were listed.
SIGN_IN_EVENT_IDS: tuple[str, ...] = ("4624", "4625", "4768", "4771")
#: Lockout risks that mean the step signs in with a password it is testing.
SIGNS_IN_LOCKOUT_RISKS: frozenset[str] = frozenset({"bounded", "possible"})


def events_for_kinds(
    kinds: tuple[str, ...] | list[str] | None, relation: str = ""
) -> tuple[str, ...]:
    """The events ``kinds`` produce, in first-seen order, without repeats.

    ``relation`` narrows a kind where :data:`RELATION_KIND_EVENT_IDS` says the
    technique makes only part of it. Raises ``KeyError`` for a kind the map does
    not know, so a new change kind cannot reach a client document with no
    statement of what it leaves.
    """
    out: list[str] = []
    for kind in kinds or ():
        events = RELATION_KIND_EVENT_IDS.get((relation, kind)) or CHANGE_KIND_EVENT_IDS[kind]
        for event in events:
            if event not in out:
                out.append(event)
    return tuple(out)


def signal_event_ids(entry: Any) -> tuple[str, ...]:
    """A catalog entry's signals: its declared events plus its changes' events.

    An entry that declares no native event telemetry keeps that declaration
    (the caller words it), returned as an empty tuple.
    """
    from adscan_internal.services.attack_step_catalog import (  # noqa: PLC0415
        declares_no_native_event_telemetry,
    )

    raw = getattr(entry, "detection_event_ids", None)
    if declares_no_native_event_telemetry(raw):
        return ()
    declared = [str(e) for e in (raw or ())]
    kinds = getattr(entry, "environment_change_kinds", None)
    for event in events_for_kinds(kinds, str(getattr(entry, "relation", "") or "")):
        if event not in declared:
            declared.append(event)
    if str(getattr(entry, "lockout_risk", "") or "") in SIGNS_IN_LOCKOUT_RISKS:
        for event in SIGN_IN_EVENT_IDS:
            if event not in declared:
                declared.append(event)
    return tuple(declared)


__all__ = [
    "CHANGE_KIND_EVENT_IDS",
    "RELATION_KIND_EVENT_IDS",
    "SIGN_IN_EVENT_IDS",
    "SIGNS_IN_LOCKOUT_RISKS",
    "WRITE_ONLY_EVENT_IDS",
    "events_for_kinds",
    "signal_event_ids",
]
