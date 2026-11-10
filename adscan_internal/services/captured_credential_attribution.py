"""Attribute a credential captured off the wire to a collected AD domain.

The problem this solves
-----------------------
Every coercion vector that lures an NTLM authentication to ADscan's :445
listener — broadcast poisoning, the write-share bait, the NTLM auth-type sweep —
hands its consumer a principal (``MEEREEN$``, ``jon.snow``) and, when the client
sent one, a NetBIOS domain name. Deciding WHICH domain that credential belongs to
is not cosmetic: the domain is the key under which the material is stored
(``domains_data[domain]`` and ``<workspace>/domains/<domain>/cracking/``), so the
attribution determines whether the hash is ever offered as a credential for that
domain's cracking, relay and attack-path execution. A hash filed under a
placeholder is a hash that exists on disk and reaches nothing.

The ladder
----------
:func:`resolve_capture_domain` walks progressively weaker evidence and stops at
the first layer that ANSWERS. It never guesses: when no layer resolves, it
returns ``None`` and the caller files the material in the reserved bucket
(:mod:`adscan_core.workspace_domain_buckets`) rather than inventing a domain.

1. **The principal's own realm.** A capture carrying ``user@essos.local`` or
   ``MEEREEN$@ESSOS.LOCAL`` names its domain outright. Matched against collected
   domains only, so an unknown realm does not become a domain.
2. **The NetBIOS → FQDN map**, case-insensitively. ``domains_data[d]["netbios"]``
   is recorded upper-case (``ESSOS``) and a capture may carry any case; the
   original exact ``==`` comparison in the poisoning CLI could miss on case
   alone.
3. **The machine account's own machine.** A ``HOST$`` principal names a computer,
   and a computer belongs to exactly one domain. Resolved against each collected
   domain's DC set through the alias-aware SSOT
   :func:`resolve_domain_controllers` (``recognizes_host``), then against the
   domain's collected computer inventory. This is the layer that attributes a
   captured domain-controller machine account, which is both the most common
   NetNTLMv1 capture and the most valuable one.
4. **NetBIOS as a collected domain's leftmost DNS label**, and only when exactly
   one collected domain matches. ``NORTH`` → ``north.sevenkingdoms.local``. This
   is the AD default naming convention rather than a guarantee, so it is last and
   it is bounded twice over: the answer must be a domain this workspace actually
   collected, and it must be unambiguous among them. It exists because a child
   domain frequently has no ``netbios`` recorded at all.

Order matters: 1-3 are facts the capture or the directory states, 4 is a
convention. A layer that cannot decide defers to the next; a layer that decides
is final.

Re-filing
---------
Attribution is attempted at capture time, but the evidence often arrives LATER:
the poisoning job auto-launches at the scan-entry seam and can capture before
LDAP collection has recorded a single ``netbios`` field or DC. So
:func:`reconcile_unattributed_captures` re-runs the ladder over whatever is
sitting in the reserved bucket and moves what now resolves into its real domain.
Holding the material out of the workspace until attribution succeeds was the
alternative and it is worse: a standalone ``poisoning`` run may never collect a
domain at all, and losing a crackable hash to keep the directory tidy is not a
trade this product makes.
"""

from __future__ import annotations

import os
import shutil
from typing import Any, Iterable, Mapping

from adscan_core.rich_output import print_exception, print_info_debug
from adscan_core.workspace_domain_buckets import (
    RESERVED_DOMAIN_BUCKETS,
    UNATTRIBUTED_CREDENTIALS_BUCKET,
    is_reserved_domain_bucket,
)

__all__ = [
    "is_machine_account_principal",
    "principal_realm",
    "reconcile_unattributed_captures",
    "resolve_capture_domain",
    "storage_domain_for_capture",
]


# ---------------------------------------------------------------------------
# Principal shape helpers
# ---------------------------------------------------------------------------


def is_machine_account_principal(principal: str | None) -> bool:
    """Return whether ``principal`` names a computer rather than a user.

    A machine account's ``sAMAccountName`` ends in ``$``. The realm suffix is
    stripped first so ``MEEREEN$@ESSOS.LOCAL`` answers the same as ``MEEREEN$``.
    """
    name = str(principal or "").strip()
    if not name:
        return False
    name = name.split("@", 1)[0].strip()
    return name.endswith("$")


def principal_realm(principal: str | None) -> str:
    """Return the realm suffix of a UPN-shaped principal, lowercased, or ``""``.

    Only a dotted suffix counts: ``user@essos.local`` yields ``essos.local`` but
    ``user@ESSOS`` yields ``""``, because a bare NetBIOS name after the ``@`` is
    not a realm and must go through the NetBIOS layers instead.
    """
    raw = str(principal or "").strip().rstrip(".")
    if "@" not in raw:
        return ""
    realm = raw.split("@", 1)[1].strip().strip(".").lower()
    return realm if "." in realm else ""


def _bare_principal(principal: str | None) -> str:
    """Return the principal without its realm suffix, trimmed."""
    return str(principal or "").strip().split("@", 1)[0].strip()


# ---------------------------------------------------------------------------
# The attribution ladder
# ---------------------------------------------------------------------------


#: ``domains_data`` keys that are pure capture bookkeeping. An entry holding
#: ONLY these was created by a capture writer and never by collection, so it
#: describes a bucket rather than a domain. Anything richer (a credential, a DC,
#: a base DN, posture) means something real is recorded there and the entry is
#: left alone whatever its name.
_CAPTURE_ONLY_DOMAIN_KEYS = frozenset({"poison_captured_ntlmv2_users", "captured_netntlm"})


def _collected_domains(domains_data: Mapping[str, Any] | None) -> list[str]:
    """Return the real domain keys of ``domains_data``; bucket keys removed.

    Two kinds of key are dropped, and both must be, because this is the
    CANDIDATE SET the ladder matches against and a bucket that stays in it
    competes with the real domain it was supposed to resolve to. A workspace
    holding a phantom ``north`` beside the real ``north.sevenkingdoms.local``
    made the leftmost-label layer see two matches and answer nothing, so the
    capture stayed unattributed because of the very artifact it was created by.

    * a reserved bucket name; and
    * a non-empty entry holding nothing but capture bookkeeping, which is what
      a capture writer seeds and a collection never produces. An EMPTY entry is
      kept: a domain can be declared before anything is recorded against it, and
      it contributes nothing but its own name to the match anyway.
    """
    if not isinstance(domains_data, Mapping):
        return []
    names = []
    for name in domains_data:
        if not str(name or "").strip() or is_reserved_domain_bucket(name):
            continue
        entry = domains_data.get(name)
        if (
            isinstance(entry, Mapping)
            and entry
            and set(entry).issubset(_CAPTURE_ONLY_DOMAIN_KEYS)
        ):
            continue
        names.append(str(name))
    return names


def _match_realm(realm: str, domains: Iterable[str]) -> str | None:
    """Return the collected domain equal to ``realm`` (case-insensitive)."""
    if not realm:
        return None
    for domain in domains:
        if str(domain).strip().strip(".").lower() == realm:
            return domain
    return None


def _match_netbios_field(
    netbios: str, domains_data: Mapping[str, Any], domains: Iterable[str]
) -> str | None:
    """Return the collected domain whose recorded NetBIOS name is ``netbios``."""
    wanted = netbios.strip().lower()
    if not wanted:
        return None
    for domain in domains:
        data = domains_data.get(domain)
        if not isinstance(data, Mapping):
            continue
        if str(data.get("netbios") or "").strip().lower() == wanted:
            return domain
    return None


def _match_host_against_dcs(
    host: str, domains_data: Mapping[str, Any], domains: Iterable[str]
) -> str | None:
    """Return the collected domain whose DC set recognises ``host``.

    Routed through :func:`resolve_domain_controllers` so the IP/short-name/FQDN/
    ``HOST$`` aliasing is the repo's single answer rather than a local
    re-derivation (reading ``pdc``/``dc_ip``/``dcs[]`` raw is the trap that
    module exists to close).
    """
    if not host:
        return None
    from adscan_internal.models.domain import (  # noqa: PLC0415
        resolve_domain_controllers,
    )

    for domain in domains:
        data = domains_data.get(domain)
        if not isinstance(data, Mapping):
            continue
        try:
            if resolve_domain_controllers(data).recognizes_host(host):
                return domain
        except Exception:  # noqa: BLE001 — attribution is best-effort
            continue
    return None


def _domain_computer_names(workspace_dir: str | None, domain: str) -> list[str]:
    """Return the collected computer identifiers for one domain.

    Reads the per-domain ``enabled_computers.txt`` the collector writes (one
    FQDN per line). Chosen over ``inventory/computers.json`` because it is
    written earlier in collection and is the same population; a missing or
    unreadable file simply yields nothing.
    """
    if not workspace_dir:
        return []
    path = os.path.join(str(workspace_dir), "domains", str(domain), "enabled_computers.txt")
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return [line.strip() for line in handle if line.strip()]
    except OSError:
        return []


def _match_host_against_inventory(
    host: str, workspace_dir: str | None, domains: Iterable[str]
) -> str | None:
    """Return the collected domain whose computer inventory contains ``host``."""
    if not host:
        return None
    from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
        hosts_match,
    )

    for domain in domains:
        for candidate in _domain_computer_names(workspace_dir, domain):
            try:
                if hosts_match(host, candidate):
                    return domain
            except Exception:  # noqa: BLE001 — attribution is best-effort
                continue
    return None


def _match_netbios_as_leftmost_label(netbios: str, domains: Iterable[str]) -> str | None:
    """Return the sole collected domain whose first DNS label is ``netbios``.

    The convention layer, and the reason it is safe enough to use last: the
    answer can only be a domain this workspace collected, and an ambiguous match
    resolves to nothing rather than to a coin flip.
    """
    wanted = netbios.strip().lower()
    if not wanted:
        return None
    matches = [
        domain
        for domain in domains
        if str(domain).strip().strip(".").lower().split(".", 1)[0] == wanted
    ]
    return matches[0] if len(matches) == 1 else None


def resolve_capture_domain(
    shell: Any,
    *,
    netbios: str | None = None,
    principal: str | None = None,
) -> str | None:
    """Return the collected domain a captured credential belongs to, or ``None``.

    Walks the ladder documented in this module's docstring. ``None`` means the
    material is genuinely unattributable from what the workspace knows right
    now — the caller files it in the reserved bucket and
    :func:`reconcile_unattributed_captures` retries later. Never raises.
    """
    try:
        domains_data = getattr(shell, "domains_data", None) or {}
        domains = _collected_domains(domains_data)
        if not domains:
            return None

        # 1. The principal states its own realm.
        resolved = _match_realm(principal_realm(principal), domains)
        if resolved:
            return resolved

        nb = str(netbios or "").strip()

        # 2. The recorded NetBIOS -> FQDN map, case-insensitively.
        resolved = _match_netbios_field(nb, domains_data, domains)
        if resolved:
            return resolved

        # 3. A machine account names a computer, and a computer has one domain.
        if is_machine_account_principal(principal):
            host = _bare_principal(principal)
            resolved = _match_host_against_dcs(host, domains_data, domains)
            if resolved:
                return resolved
            resolved = _match_host_against_inventory(
                host, getattr(shell, "current_workspace_dir", None), domains
            )
            if resolved:
                return resolved

        # 4. NetBIOS as the sole collected domain's leftmost label (convention).
        return _match_netbios_as_leftmost_label(nb, domains)
    except Exception as exc:  # noqa: BLE001 — attribution must never break a capture
        print_exception(exception=exc)
        return None


def storage_domain_for_capture(
    shell: Any,
    *,
    netbios: str | None = None,
    principal: str | None = None,
) -> tuple[str, bool]:
    """Return ``(storage_key, attributed)`` for one captured credential.

    The single seam every capture writer uses to pick where the material goes:
    the resolved domain when the ladder answers, otherwise the reserved
    unattributed bucket. ``attributed`` lets the caller tell the operator which
    happened, and tells it whether domain-scoped bookkeeping (provenance,
    credential stores) applies — those are meaningless for a bucket.

    Note what is NOT done here: the NetBIOS name is never used as the storage
    key. A short NetBIOS name is not a domain, and filing material under one
    produces exactly the defect this module exists to remove.
    """
    resolved = resolve_capture_domain(shell, netbios=netbios, principal=principal)
    if resolved:
        return resolved, True
    return UNATTRIBUTED_CREDENTIALS_BUCKET, False


# ---------------------------------------------------------------------------
# Deferred re-filing
# ---------------------------------------------------------------------------


def _principal_from_hash_filename(filename: str) -> str:
    """Return the principal a capture filename encodes, or ``""``.

    Capture writers name the file ``<principal>_hashes.NTLM<version>``
    (``adscan_internal.cli.creds.save_ntlm_hash``), so the principal is
    recoverable from the bucket alone without parsing the hash body.
    """
    name = str(filename or "")
    marker = "_hashes.NTLM"
    if marker not in name:
        return ""
    return name.split(marker, 1)[0].strip()


def _netbios_from_hash_file(path: str) -> str:
    """Return the NetBIOS domain recorded inside a NetNTLM hash file, or ``""``.

    A stored line is ``<principal>:<fullhash>`` where a NetNTLM ``fullhash`` is
    ``user::domain:...``. Reading the domain back out of the hash body recovers
    the attribution for material captured before the writer carried it, which is
    precisely the pre-existing ``captured/`` content on disk today.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                body = line.strip()
                if not body:
                    continue
                fields = body.split(":")
                # <principal>:<user>::<domain>:... -> index 3 is the domain.
                if len(fields) >= 4 and fields[2] == "":
                    return fields[3].strip()
    except OSError:
        return ""
    return ""


def _merge_file(source: str, destination_dir: str) -> bool:
    """Move one capture file into ``destination_dir``; never overwrite or delete.

    Returns whether the source no longer occupies the bucket. An existing
    destination is left untouched and the source is removed only because the
    same material is already filed correctly — the material itself is never
    lost, which is the one invariant this whole function has.
    """
    try:
        os.makedirs(destination_dir, exist_ok=True)
        target = os.path.join(destination_dir, os.path.basename(source))
        if os.path.exists(target):
            if os.path.getsize(target) >= os.path.getsize(source):
                os.remove(source)
                return True
            # The bucket copy holds more lines; keep both rather than choose.
            return False
        shutil.move(source, target)
        return True
    except OSError:
        return False


def _prune_empty_dirs(root: str) -> None:
    """Remove ``root`` and its empty subdirectories. Only ever empty ones."""
    for current, _dirs, _files in os.walk(root, topdown=False):
        try:
            os.rmdir(current)
        except OSError:
            return


def _is_capture_only_bucket(
    domains_root: str,
    name: str,
    cracking_dir_name: str,
    domains_data: Mapping[str, Any],
    declared_domains: Iterable[str],
) -> bool:
    """Return whether a ``domains/<name>/`` entry is a leftover capture bucket.

    Recognises the OTHER directory the removed fallback produced. It filed a
    capture under the lowercased NetBIOS short name when one was present and
    under the literal placeholder when it was not, so a workspace can hold
    ``domains/north/`` beside the real ``domains/north.sevenkingdoms.local/``
    and render both as domains. The short name is unbounded, so it cannot be
    recognised by a name list the way the reserved placeholder can; it is
    recognised by SHAPE instead, and the shape is deliberately narrow:

    * the directory contains the cracking directory and nothing else, where a
      collected domain always carries collection artifacts (``dcs.txt``, an
      ``ldap/`` directory, its own ``variables.json``, an attack graph);
    * the workspace does not declare it among its domains; and
    * its ``domains_data`` entry, if any, holds nothing but capture bookkeeping.

    All three must hold. A directory that fails any of them is left untouched,
    because the cost of re-filing a real domain's material is far higher than
    the cost of leaving one stale bucket visible.
    """
    if is_reserved_domain_bucket(name):
        return True
    declared = {str(d).strip().lower() for d in declared_domains if d}
    if str(name).strip().lower() in declared:
        return False
    entry = domains_data.get(name)
    if isinstance(entry, Mapping) and not set(entry).issubset(_CAPTURE_ONLY_DOMAIN_KEYS):
        return False
    if entry is not None and not isinstance(entry, Mapping):
        return False
    try:
        contents = {child for child in os.listdir(os.path.join(domains_root, name))}
    except OSError:
        return False
    return bool(contents) and contents == {cracking_dir_name}


def reconcile_unattributed_captures(shell: Any) -> list[tuple[str, str]]:
    """Re-file reserved-bucket captures into the domains they now resolve to.

    Runs the attribution ladder again over every capture sitting in a bucket,
    using the principal from the filename and the NetBIOS domain from the hash
    body. Two kinds of bucket are walked: the reserved names, and the
    capture-only directories the removed NetBIOS fallback left behind
    (:func:`_is_capture_only_bucket`). What resolves moves into
    ``domains/<domain>/cracking/``; what does not is consolidated under the
    current reserved name, so one workspace never carries several placeholders
    and a NetBIOS short name never remains as a directory that reads as a
    domain. An emptied bucket's phantom entry in the domain map is dropped with
    it when that entry holds nothing but capture bookkeeping.

    Returns the ``(principal, domain)`` pairs re-filed, for the caller to report.
    Never raises, never deletes captured material, and never overwrites a file
    that already holds at least as much as the one it would replace.
    """
    refiled: list[tuple[str, str]] = []
    try:
        workspace_dir = getattr(shell, "current_workspace_dir", None)
        if not workspace_dir:
            return refiled
        domains_root = os.path.join(str(workspace_dir), "domains")
        cracking_dir_name = str(getattr(shell, "cracking_dir", None) or "cracking")
        domains_data = getattr(shell, "domains_data", None) or {}
        # The declaration that protects a directory is the workspace's DOMAIN
        # LIST, not the keys of ``domains_data``. A capture writer seeds a key
        # there, so treating those keys as a declaration would make every
        # phantom vouch for itself. A real domain whose key is rich is already
        # protected by the entry check inside _is_capture_only_bucket.
        declared = list(getattr(shell, "domains", None) or [])

        try:
            on_disk = sorted(
                entry
                for entry in os.listdir(domains_root)
                if os.path.isdir(os.path.join(domains_root, entry))
            )
        except OSError:
            on_disk = []
        buckets = sorted(
            set(RESERVED_DOMAIN_BUCKETS)
            | {
                entry
                for entry in on_disk
                if _is_capture_only_bucket(
                    domains_root, entry, cracking_dir_name, domains_data, declared
                )
            }
        )

        for bucket in buckets:
            bucket_cracking = os.path.join(domains_root, bucket, cracking_dir_name)
            if not os.path.isdir(bucket_cracking):
                continue
            for filename in sorted(os.listdir(bucket_cracking)):
                source = os.path.join(bucket_cracking, filename)
                if not os.path.isfile(source):
                    continue
                principal = _principal_from_hash_filename(filename)
                netbios = _netbios_from_hash_file(source)
                domain = resolve_capture_domain(
                    shell, netbios=netbios, principal=principal
                )
                if domain:
                    destination = os.path.join(domains_root, domain, cracking_dir_name)
                    if _merge_file(source, destination):
                        refiled.append((principal or filename, domain))
                    continue
                if bucket != UNATTRIBUTED_CREDENTIALS_BUCKET:
                    # Still unattributable: consolidate the legacy bucket under
                    # the current reserved name so there is one place to look.
                    _merge_file(
                        source,
                        os.path.join(
                            domains_root,
                            UNATTRIBUTED_CREDENTIALS_BUCKET,
                            cracking_dir_name,
                        ),
                    )
            bucket_dir = os.path.join(domains_root, bucket)
            _prune_empty_dirs(bucket_dir)

            # Drop the phantom domain the bucket left in the domain map, but
            # only once its directory is gone AND the entry holds nothing but
            # capture bookkeeping. ``domains_data`` is persisted to
            # variables.json and read as "the workspace's domains" by the report
            # and the platform, so an entry a capture writer created is a second
            # way the same bucket renders as a domain. An entry carrying
            # anything else (a credential, a DC, posture) is left alone: there
            # is real material in it, and losing that is worse than one stale
            # row. Those are reported, not deleted.
            if not os.path.exists(bucket_dir):
                entry = domains_data.get(bucket)
                if isinstance(entry, Mapping) and set(entry).issubset(
                    _CAPTURE_ONLY_DOMAIN_KEYS
                ):
                    domains_data.pop(bucket, None)
                    print_info_debug(
                        f"captured-credential attribution: removed the empty "
                        f"capture bucket '{bucket}' from the domain map."
                    )

        if refiled:
            print_info_debug(
                "captured-credential attribution: re-filed "
                + ", ".join(f"{name} -> {domain}" for name, domain in refiled)
            )
    except Exception as exc:  # noqa: BLE001 — a reconcile must never break a scan
        print_exception(exception=exc)
    return refiled
