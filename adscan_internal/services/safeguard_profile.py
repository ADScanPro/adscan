"""Per-technique SAFEGUARD PROFILE — the single source of truth for the
"what does ADscan touch in the domain, and with what safeguards" axes.

WHY THIS MODULE EXISTS
----------------------
The customer-facing coverage matrix used to answer only ONE question: *which
techniques does ADscan cover*. A CISO of a regulated entity asks a different
set of questions BEFORE granting access to a production Active Directory:

1. What does the technique MODIFY in my environment?
2. Is that change rolled back, and automatically or on operator confirmation?
3. Is the technique BLOCKED (hard refusal, or disabled unless opted into)?
4. Does it stay in the directory, or does it touch endpoints / memory?
5. What is the MINIMUM privilege it needs?
6. What will my SOC see while it runs?

Those six answers already exist, scattered, across the guardrail layer, the
change ledger's write sites and the attack-step catalog. This module derives
them from those sources and NEVER authors a value that the code does not
support. An axis it cannot derive returns :data:`PENDING`, and
:func:`pending_fields` enumerates every gap so a human can fill it deliberately.

THAT RULE IS SAFETY-CRITICAL. These values ship in a document a CISO uses to
decide whether ADscan may run against production. An invented cell is worse
than an empty one: an empty cell is a question, a wrong one is a lie.

DERIVATION SOURCES (all read-only)
----------------------------------
* ``destructive_action_policy.classify_destructive`` — the hard-refusal /
  opt-in-only axes (axis 3), plus the client-safe reason.
* ``attack_step_catalog`` — ``support_kind`` (does ADscan execute it at all),
  ``source_context_requirement`` + ``execution_target_access_requirement``
  (axis 5), ``detection_event_ids`` (axis 6).
* ``cleanup_taxonomy`` — ``KIND_DISPLAY`` (the client-facing name of a change
  kind) and ``HOST_ARTIFACT_KINDS`` (directory object vs file on a host, axis 4).
* ``environment_change_ledger`` — the two change classes, ``AUTO_REVERT`` vs
  ``OPERATOR_CONFIRMED`` (axis 2).
* ``attack_step_catalog.environment_change_kinds`` — the ONE axis nothing else
  can derive: WHICH ledger change kinds a technique's execution writes. It is
  declared in the CATALOG, beside the technique, so adding a technique brings its
  impact data with it. ``()`` declares "modifies nothing"; ``None`` is UNDECLARED
  and yields ``PENDING`` for axes 1, 2 and 4 (never "assumed read-only"). The
  Every declared kind is checked against ``cleanup_taxonomy.KIND_DISPLAY`` (the
  ledger's own registry of change kinds) by a structural test, so renaming a
  kind in the ledger fails CI instead of printing a stale claim in a client
  document. There is deliberately NO ``file:line`` provenance anywhere in this
  data: a hand-copied line number is stale after the first refactor and nobody
  notices, which is the silent failure this axis exists to prevent.

WHY THE OTHER FIVE AXES ARE **NOT** CATALOG ATTRIBUTES
------------------------------------------------------
Declaring them beside the technique would let the declaration drift from the
behaviour. A catalog attribute reading "auto-rollback" while
``acl_change_cleanup_service`` marks that change ``manual_required`` is exactly
the failure this document cannot have: the attribute is what a CISO reads, and
the code is what runs. So the rollback lifecycle is derived from the change KIND
(the cleanup layer's own revert plans + the ledger's change classes), the block
state from the guardrail classifier, and the privilege and SOC axes from the
catalog fields that already exist for them. Declare once, derive the rest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from adscan_internal.services import cleanup_taxonomy as _tax
from adscan_internal.services.attack_step_catalog import (
    ATTACK_STEP_CATALOG,
    declares_no_native_event_telemetry,
)
from adscan_internal.services.coverage_stats import STEP_CATEGORY_EXCLUDE
from adscan_internal.services.destructive_action_policy import (
    classify_destructive,
    skipped_by_default_in_audit,
)
from adscan_internal.services.environment_change_ledger import (
    CHANGE_CLASS_AUTO_REVERT,
    CHANGE_CLASS_OPERATOR_CONFIRMED,
)

__all__ = [
    "PENDING",
    "SafeguardProfile",
    "KIND_LABEL_ES",
    "LEDGER_UNTRACKED_WRITES",
    "LEDGER_UNSETTLED_WRITES",
    "NO_EXECUTOR_RELATIONS",
    "UNREGISTERED_WRITE_KINDS",
    "VERIFIED_AUTO_REVERT_KINDS",
    "NEVER_AUTO_REVERT_KINDS",
    "build_safeguard_profile",
    "build_all_safeguard_profiles",
    "pending_fields",
    "HEADER_SAFEGUARDS",
]

#: Sentinel for an axis this module cannot derive from the code. Rendered as a
#: visible "pendiente" cell, never as an empty or guessed value.
PENDING = "__PENDING__"

# Lifecycle class → client-facing Spanish sentence for axis 2 (auto-rollback).
# The wording mirrors the ledger's own contract: a change is registered, the
# revert is VERIFIED, and an unverifiable revert is reported naming the object.
_ROLLBACK_AUTO = (
    "Automático al salir: el cambio queda registrado y se revierte comprobándolo; "
    "lo que no se puede verificar se reporta nombrando el objeto."
)
_ROLLBACK_OPERATOR = (
    "Requiere confirmación del operador al salir (el acceso se mantiene mientras "
    "dura la sesión); el cambio queda registrado y la reversión se comprueba, y lo "
    "que no se puede verificar se reporta nombrando el objeto."
)
_ROLLBACK_MANUAL = (
    "No se revierte desde la herramienta: se reporta nombrando el objeto para "
    "limpieza manual."
)
_ROLLBACK_NA = "No aplica: la técnica no modifica nada."
#: Registered in the ledger AND removed by the step's own RAII scope on exit,
#: but the record is never SETTLED, so ``EnvironmentChangeLedger.finalize``
#: force-transitions it to ``manual_required(session_died)``. The client is
#: therefore told to confirm the object by hand even though the step removed it.
#: That is the conservative behaviour, and it is what the document must say.
_ROLLBACK_UNSETTLED = (
    "El paso lo elimina al terminar y el cambio queda registrado, pero la "
    "reversión no se confirma en el registro, así que se reporta nombrando el "
    "objeto para que lo verifiques a mano."
)
_ROLLBACK_UNTRACKED = (
    "El propio paso deshace el cambio al terminar, pero no queda registrado en "
    "el registro central de cambios, así que no podemos afirmar reversión "
    "comprobada. Trátalo como pendiente de confirmar a mano."
)

_ROLLBACK_BY_CLASS = {
    CHANGE_CLASS_AUTO_REVERT: _ROLLBACK_AUTO,
    CHANGE_CLASS_OPERATOR_CONFIRMED: _ROLLBACK_OPERATOR,
}

#: A third lifecycle beyond the ledger's two classes: a change whose reversal
#: needs rights the assessment does not hold (revoking a certificate the CA
#: issued, retiring a stolen CA signing key). ``cleanup_taxonomy`` documents
#: these as ALWAYS manual items.
#: A third lifecycle beyond the ledger's two classes: a change whose reversal
#: needs rights the assessment does not hold.
CHANGE_CLASS_ALWAYS_MANUAL = "always_manual"
_ROLLBACK_BY_CLASS[CHANGE_CLASS_ALWAYS_MANUAL] = _ROLLBACK_MANUAL

#: Spanish, client-facing name for each change kind this module can report.
#: ``cleanup_taxonomy.KIND_DISPLAY`` is the ENGLISH SSOT (the PDF report is
#: English-only); the coverage matrix is a Spanish document, so the translation
#: lives HERE, at the boundary of authorship, keyed on the SAME kind tokens.
#: :func:`_kind_label_es` raises on an unmapped kind rather than leaking English.
KIND_LABEL_ES: dict[str, str] = {
    "shadow_credentials_added": "Credenciales shadow (msDS-KeyCredentialLink)",
    "keycredentiallink_added": "msDS-KeyCredentialLink",
    "dacl_ace_added": "ACE en la DACL del objeto (control total)",
    "owner_changed": "Propietario del objeto",
    "spn_added": "SPN añadido a la cuenta",
    "spn_relocated": "SPN movido entre cuentas",
    "password_changed": "Contraseña de la cuenta",
    "group_membership_added": "Pertenencia a grupo",
    "group_membership_changed": "Pertenencia a grupo",
    "machine_account_created": "Cuenta de equipo creada",
    "rbcd_delegation_added": "Delegación RBCD",
    "template_mutated": "Plantilla de certificado modificada",
    _tax.KIND_ISSUED_CERTIFICATE: "Certificado emitido por tu CA",
    _tax.KIND_FORGED_CERTIFICATE: "Certificado falsificado (fuera de la base de datos del CA)",
    _tax.KIND_CA_PRIVATE_KEY_EXFILTRATED: "Clave privada del CA copiada fuera del host del CA",
    _tax.KIND_CA_BACKUP_SERVICE: "Servicio temporal en el host del CA",
    _tax.KIND_CA_BACKUP_TEMP_PFX: "Fichero temporal de clave en el host del CA",
    _tax.KIND_REMOTE_FILE_WRITTEN: "Fichero escrito en el equipo evaluado",
    _tax.KIND_REMOTE_FILE_UPLOADED: "Fichero subido al equipo evaluado",
    "mssql_xp_cmdshell_enabled": "Ajuste de ejecución de comandos en SQL Server",
    "mssql_clr_assembly_loaded": "Ensamblado CLR cargado en SQL Server",
    "mssql_postex_account": "Cuenta de base de datos creada",
    "dns_record_added": "Registro ADIDNS creado",
    "rodc_prp_modified": (
        "Política de replicación de contraseñas del RODC "
        "(msDS-RevealOnDemandGroup)"
    ),
    "user_created": "Cuenta de usuario creada",
    "scheduled_task_created": "Tarea programada creada en el equipo",
    "logon_script_path_modified": "Script de inicio de sesión del usuario (scriptPath)",
}

#: Relations the catalog marks ``supported`` that have NO executor branch. They
#: write nothing because they DO NOT RUN, which is a weaker and different claim
#: from "its execution path was audited and only reads". Saying so plainly is
#: the honest form, and it also flags the catalog overstatement.
NO_EXECUTOR_RELATIONS: frozenset[str] = frozenset(
    {
        "scheduledtask",
        "mssql_impersonate_login",
        "mssql_trustworthy_db_escalation",
        "fullcontrolshare",
        "writeshare",
        "guestsession",
        # No executor branch dispatches this relation, and the only xp_dirtree
        # code ADscan runs is the read-only credential-hygiene review, which
        # never coerces authentication.
        "mssql_ntlmv2_theft",
    }
)

#: Writes CONFIRMED by reading the execution path that do NOT reach
#: ``EnvironmentChangeLedger``. The modification is real, so the matrix must
#: state it; but the standard "registered and reverted with verification"
#: sentence would be FALSE for them, because no ledger record exists and the
#: revert is the step's own best-effort ``finally``. They therefore render the
#: honest middle statement in :data:`_ROLLBACK_UNTRACKED`.
#:
#: Each entry is a bug worth closing (route the write through the ledger). Until
#: then the document must not claim a guarantee the code does not provide.
#: Writes the step REGISTERS and then removes itself on exit without settling
#: the ledger record. See :data:`_ROLLBACK_UNSETTLED`.
LEDGER_UNSETTLED_WRITES: frozenset[str] = frozenset(
    {
        # services/cross_forest_tgt_delegation_step.py registers the relay SPN
        # and the ADIDNS record, then drops them in adspn_scope /
        # adidns_a_record_scope's finally without calling mark_reverted_confirmed.
        "crossorgtgtdelegation",
        # services/exploitation/spnjack_executor.py ALWAYS reverts the SPN
        # relocation (_revert_relocation, success or failure) and registers the
        # change, but never calls mark_reverted_confirmed.
        "spnjack",
    }
)

#: Every attack-path step that writes to the environment now registers that
#: write with the change ledger at the write site and settles it with a
#: confirming read, so this set is empty: the rollback claim for each technique
#: DERIVES from its declared change kinds, never from a hand-maintained override.
#: A new technique that writes without routing through the ledger is caught by
#: tests/unit/services/test_attack_path_writes_route_through_ledger.py, not by
#: being listed here.
LEDGER_UNTRACKED_WRITES: frozenset[str] = frozenset()

#: Kinds that exist only to NAME an unregistered write (see above). They are
#: deliberately absent from ``cleanup_taxonomy.KIND_DISPLAY``, which is the
#: registry of kinds a writer actually registers.
UNREGISTERED_WRITE_KINDS: frozenset[str] = frozenset()


def _kind_label_es(kind: str) -> str:
    """Spanish label for a change kind. Raises on an unmapped kind.

    Failing loudly is deliberate: a missing entry would otherwise print the
    English label (or the raw snake_case token) in a Spanish document a CISO
    reads.
    """
    label = KIND_LABEL_ES.get(kind)
    if not label:
        raise KeyError(
            f"safeguard_profile: no Spanish label for change kind {kind!r}. "
            "Add it to KIND_LABEL_ES."
        )
    return label


#: Change kinds the cleanup layer reverts AND VERIFIES automatically at exit.
#: Grounded in ``acl_change_cleanup_service``: each of these has a
#: ``{"revert": …, "verify": …}`` plan driven through
#: ``mark_revert_in_progress → mark_reverted_confirmed`` with a bounded retry and
#: a ``mark_manual_required`` fallback that names the object.
VERIFIED_AUTO_REVERT_KINDS: frozenset[str] = frozenset(
    {
        "shadow_credentials_added",
        "dacl_ace_added",
        "owner_changed",
        "spn_added",
        "group_membership_added",
        "group_membership_changed",
        # MSSQL: registered CHANGE_CLASS_AUTO_REVERT and settled through
        # mark_reverted_confirmed after a re-read
        # (cli/mssql.py:2628 / :2889, exploitation/mssql_seimpersonate.py:647 / :670).
        "mssql_xp_cmdshell_enabled",
        "mssql_clr_assembly_loaded",
        "mssql_clr_config_changed",
        "mssql_postex_account",
        "template_mutated",
        # PrepareRodcCredentialCaching registers the msDS-RevealOnDemandGroup
        # modify and restores it with a confirming re-read in its finally
        # (cli/rodc_escalation.py).
        "rodc_prp_modified",
        # HasSession registers the created account and verifies its deletion
        # via a membership re-read; the transient scheduled task is removed
        # in the same operation and reported manual only when left behind
        # (cli/attack_path_execution.py, services/exploitation/hassession_native.py).
        "user_created",
        "scheduled_task_created",
        # WriteLogonScript restores the overwritten scriptPath with a
        # confirming re-read in _attempt_writelogonscript_cleanup_if_ready.
        "logon_script_path_modified",
    }
)

#: Change kinds that CANNOT be reverted by the tool, whatever the ledger's
#: lifecycle class says. ``password_changed`` is the load-bearing one: the
#: original secret is gone, and ``acl_change_cleanup_service`` marks it
#: ``manual_required`` explicitly ("Password reset cannot be reverted
#: automatically"). The ADCS kinds need CA rights the assessment does not hold.
NEVER_AUTO_REVERT_KINDS: frozenset[str] = frozenset(
    {
        "password_changed",
        _tax.KIND_ISSUED_CERTIFICATE,
        _tax.KIND_FORGED_CERTIFICATE,
        _tax.KIND_CA_PRIVATE_KEY_EXFILTRATED,
    }
)

_MODIFIES_NOTHING = "Nada: la técnica solo lee."
_MODIFIES_NOT_EXECUTED = (
    "Nada: ADscan no ejecuta esta técnica (la detecta y la mapea)."
)
_MODIFIES_NO_EXECUTOR = (
    "Nada, porque hoy no llega a ejecutarse: la técnica está catalogada pero no "
    "tiene ruta de ejecución. No es lo mismo que una técnica auditada como de "
    "solo lectura."
)

_SCOPE_DIRECTORY = "Solo directorio (objeto de AD)."
_SCOPE_DIRECTORY_READ = "Solo lectura: no escribe en el directorio ni en los equipos."
_SCOPE_HOST_FILE = "Toca el endpoint: escribe un fichero en el host evaluado."
_SCOPE_HOST_MEMORY = (
    "Requiere sesión de administrador local y lee memoria o registro del host."
)
_SCOPE_HOST_SQL = (
    "Corre a través de un canal de ejecución de comandos en el servidor SQL."
)
_SCOPE_CA_DATABASE = (
    "Servicio de CA: la emisión queda registrada en la base de datos del CA."
)
_SCOPE_CA_OFFLINE = (
    "Fuera del CA: el certificado se firma en local y no tiene solicitud en la "
    "base de datos del CA."
)
_SCOPE_CA_HOST = "Toca el host del CA (servicio y sistema de ficheros)."
_SCOPE_SQL_SERVER = "Toca el servidor SQL (configuración de la instancia)."
_SCOPE_DIRECTORY_DNS = "Solo directorio (zona DNS integrada en AD)."
_SCOPE_HOST_TASK = "Toca el endpoint: registra una tarea programada en el host."


#: ``allextendedrights`` is remapped at execution time to the concrete extended
#: right the target's object class confers (password reset, DCSync or LAPS read),
#: so its own profile is the union of those: stated as such rather than guessed.
_ALLEXTENDEDRIGHTS_MODIFIES = (
    "Depende de la clase del objeto: sobre un usuario reinicia su contraseña; "
    "sobre el dominio replica (DCSync) y no escribe; sobre un equipo lee la "
    "contraseña de LAPS y no escribe; sobre cualquier otra clase no intenta "
    "nada."
)



@dataclass(frozen=True, slots=True)
class SafeguardProfile:
    """The six safeguard axes for one technique. ``PENDING`` = not derivable."""

    relation: str
    #: Axis 1 — what the technique modifies in the environment.
    modifies: str
    #: Axis 2 — rollback lifecycle.
    rollback: str
    #: Axis 3 — hard block / explicit opt-in / not restricted.
    blocked: str
    #: Axis 4 — directory only, or endpoints / memory.
    scope: str
    #: Axis 5 — minimum privilege required.
    min_privilege: str
    #: Axis 6 — what the SOC can expect to see.
    soc: str
    #: Provenance: ``field -> source reference``, for auditing the document.
    sources: dict[str, str] = field(default_factory=dict)

    def pending(self) -> tuple[str, ...]:
        """Names of the axes that need human input."""
        return tuple(
            name
            for name in ("modifies", "rollback", "blocked", "scope", "min_privilege", "soc")
            if getattr(self, name) == PENDING
        )


# ── Axis 3: blocked ──────────────────────────────────────────────────────────
_BLOCK_HARD = (
    "Bloqueo duro: ADscan no la ejecuta en ningún modo, y un operador no puede "
    "forzarla."
)
#: The state a CISO weighs most and that was invisible until now: the step is
#: declined BY DEFAULT in an audit engagement. An unattended run (`adscan ci`,
#: the appliance worker) skips it outright; an interactive operator has to
#: override a prompt that is preset to no. Stronger than a bare "opt-in", and
#: deliberately NOT stated as "never", because an authorised operator can still
#: choose to run it.
_BLOCK_AUDIT_SKIP = (
    "No se ejecuta en una auditoría salvo que la autorices a mano: en una "
    "ejecución desatendida se omite, y si estás delante la pregunta viene "
    "respondida que no. En un entorno desechable (laboratorio o CTF) sí se "
    "ejecuta sola."
)
_BLOCK_OPT_IN = (
    "Opt-in explícito: desactivada por defecto; solo corre si el operador la "
    "habilita de forma interactiva, y se omite en modo no interactivo."
)
_BLOCK_NOT_EXECUTED = "No se ejecuta: ADscan la detecta y la mapea."
_BLOCK_NONE = "Sin restricción específica (sujeta al modo de ejecución elegido)."


def _blocked_axis(relation: str, entry: Any) -> tuple[str, str]:
    """(value, source) for axis 3."""
    # ForceChangePassword splits by target class: hard-blocked against a computer
    # account, opt-in-only against a user. Both halves are stated, because a CISO
    # needs the computer-account guarantee explicitly.
    verdict_user = classify_destructive(relation, "user")
    verdict_computer = classify_destructive(relation, "computer")
    src = "adscan_internal/services/destructive_action_policy.py::classify_destructive"
    if verdict_user.hard_blocked and verdict_computer.hard_blocked:
        return _BLOCK_HARD, src
    if verdict_computer.hard_blocked and verdict_user.opt_in_only:
        audit_clause = (
            " Contra una cuenta de usuario tampoco se ejecuta en una auditoría "
            "salvo que la autorices a mano: desatendida se omite, y si estás "
            "delante la pregunta viene respondida que no. En un entorno "
            "desechable (laboratorio o CTF) sí se ejecuta sola."
            if skipped_by_default_in_audit(relation, "user")
            else " Contra una cuenta de usuario está desactivada por defecto."
        )
        return (
            "Bloqueo duro contra cuentas de equipo: nunca se ejecuta, en ningún "
            "modo." + audit_clause,
            src,
        )
    if verdict_user.opt_in_only or verdict_computer.opt_in_only:
        if skipped_by_default_in_audit(relation, "user") or skipped_by_default_in_audit(
            relation, "computer"
        ):
            return _BLOCK_AUDIT_SKIP, src
        return _BLOCK_OPT_IN, src
    if getattr(entry, "support_kind", "") == "policy_blocked":
        return _BLOCK_HARD, "attack_step_catalog.support_kind == 'policy_blocked'"
    if getattr(entry, "support_kind", "") != "supported":
        return _BLOCK_NOT_EXECUTED, "attack_step_catalog.support_kind"
    return _BLOCK_NONE, "attack_step_catalog.support_kind == 'supported'"


# ── Axis 5: minimum privilege ────────────────────────────────────────────────
_MIN_PRIV_BY_CONTEXT: dict[str, str] = {
    "none": "Ninguno: no necesita credenciales de dominio.",
    "user_credentials": "Cualquier cuenta de dominio autenticada (sin privilegios).",
    "local_admin_session": "Administrador local en el equipo objetivo.",
    "machine_credential": "Credencial de cuenta de equipo (TGT o hash de la máquina).",
    "mssql_rce_session": "Canal de ejecución de comandos ya establecido en el servidor SQL.",
}
_TARGET_REACHABLE_SUFFIX = " Además necesita alcanzar el equipo objetivo por red."


def _min_privilege_axis(entry: Any) -> tuple[str, str]:
    ctx = getattr(entry, "source_context_requirement", "") or ""
    base = _MIN_PRIV_BY_CONTEXT.get(ctx)
    if not base:
        return PENDING, ""
    if getattr(entry, "execution_target_access_requirement", "") == "computer_reachable":
        base += _TARGET_REACHABLE_SUFFIX
    return base, (
        "attack_step_catalog.source_context_requirement"
        " + .execution_target_access_requirement"
    )


# ── Axis 6: what the SOC sees ────────────────────────────────────────────────
#: Spanish, client-facing SOC cell for each technique that declares
#: ``NO_NATIVE_EVENT_TELEMETRY``. The catalog declares the FACT (in English,
#: like every other catalog string); this is the Spanish boundary, mirroring
#: :data:`KIND_LABEL_ES`.
#:
#: Each sentence must say WHERE the audit log is blind and WHAT detection sees
#: the technique instead. They are authored per technique and deliberately not
#: derived from one template: these three are invisible for three different
#: reasons, and a SOC lead reading a generic "no deja eventos" learns nothing
#: actionable. A bare "ninguno" would be worse than a pending cell.
_NO_NATIVE_EVENT_SOC_ES: dict[str, str] = {
    "timeroasting": (
        "Ninguno propio: la petición es una consulta de hora MS-SNTP legítima "
        "al controlador de dominio, y el registro de seguridad de Windows no "
        "la audita. La detección es de red: el volumen de peticiones MS-SNTP "
        "que llevan identificadores de cuentas de equipo llegando desde un "
        "mismo origen."
    ),
    "ldapanonymousbind": (
        "Ninguno propio: los controladores de dominio no auditan los enlaces "
        "LDAP, así que un enlace anónimo y sus lecturas del directorio no "
        "dejan rastro en el registro de seguridad. La visibilidad se consigue "
        "subiendo el registro de diagnóstico de la interfaz LDAP en el "
        "controlador de dominio, que anota los enlaces sin firma y en claro, o "
        "con telemetría de red de los enlaces al puerto 389 que llegan con un "
        "nombre distinguido vacío."
    ),
    "ms17-010": (
        "Ninguno propio: el exploit viaja dentro del tráfico SMBv1 previo a la "
        "autenticación, así que ni un intento fallido ni uno exitoso generan "
        "evento de seguridad, y lo único que el equipo puede mostrar es una "
        "caída del kernel. La detección es por inspección de red de la "
        "transacción SMBv1 malformada; la señal previa útil es activar la "
        "auditoría de acceso SMBv1 en el servidor, que registra el uso "
        "legítimo de SMBv1 y con ello la exposición que el exploit necesita."
    ),
}


def _no_native_event_soc_es(relation: str) -> str:
    """Spanish SOC sentence for a no-native-event technique. Raises if missing.

    Failing loudly is deliberate and mirrors :func:`_kind_label_es`: a sentinel
    without its sentence would otherwise publish an empty or English cell in a
    Spanish document a CISO reads.
    """
    text = _NO_NATIVE_EVENT_SOC_ES.get(relation)
    if not text:
        raise KeyError(
            f"safeguard_profile: {relation!r} declares NO_NATIVE_EVENT_TELEMETRY "
            "but has no Spanish SOC sentence. Add it to _NO_NATIVE_EVENT_SOC_ES, "
            "naming where the SOC is blind and what detection it takes instead."
        )
    return text


def _soc_axis(entry: Any) -> tuple[str, str]:
    raw = getattr(entry, "detection_event_ids", ())
    if declares_no_native_event_telemetry(raw):
        return (
            _no_native_event_soc_es(str(getattr(entry, "relation", "") or "")),
            "attack_step_catalog.NO_NATIVE_EVENT_TELEMETRY",
        )
    ids = tuple(str(i) for i in (raw or ()))
    if not ids:
        return PENDING, ""
    return (
        _soc_sentence_es(ids),
        "attack_step_catalog.detection_event_ids",
    )


#: Which Windows log carries each event, for the IDs that are NOT in the
#: Security log. The cell used to send every ID to "eventos de Windows ... en el
#: controlador de dominio", which is where a SOC analyst then looks: the Security
#: log. For seven of the catalog's thirty-three IDs that is the wrong log, so the
#: analyst finds nothing and concludes the claim is wrong. Naming the log is the
#: difference between a cell they can act on and one that costs them a search.
#:
#: Verified per ID, because an event id in a paid deliverable is checked against
#: a real SIEM:
#:   150 / 770 / 771  DNS Server, the plug-in DLL load the DnsAdmins abuse needs
#:   316              PrintService, the spooler driver install
#:   7045             System, Service Control Manager installing a service
#:   15457            SQL Server's own error log (severity 0, informational),
#:                    which SQL Server also mirrors into the Application log
#:   33205            SQL Server Audit, which writes into the Application log
_EVENT_LOG_ES: dict[str, str] = {
    "150": "del registro del servidor DNS",
    "770": "del registro del servidor DNS",
    "771": "del registro del servidor DNS",
    "316": "del registro del servicio de cola de impresión",
    "7045": "del registro del sistema",
    "15457": "del registro de errores de SQL Server",
    "33205": "de la auditoría de SQL Server, en el registro de aplicación",
}

#: The Security log, where the remaining IDs live. Kept as its own phrase so the
#: single-log case reads as one sentence rather than a list of one group.
_SECURITY_LOG_ES = (
    "de seguridad de Windows {ids} en el controlador de dominio o en el host "
    "implicado"
)


def _join_es(items: "list[str]") -> str:
    """Join with commas and a Spanish ``y`` before the last item."""
    if len(items) == 1:
        return items[0]
    return f"{', '.join(items[:-1])} y {items[-1]}"


def _soc_sentence_es(ids: "tuple[str, ...]") -> str:
    """Name the events AND the log each one is written to.

    Groups by log, preserving the order the catalog declared, so the Security
    log leads when it is present. Every ID the map does not know is Security,
    which is the right default: the catalog's 4xxx and 5xxx ids are all audit
    policy events and a new one will be too.
    """
    security = [i for i in ids if i not in _EVENT_LOG_ES]
    clauses: list[str] = []
    if security:
        word = "Eventos" if len(security) > 1 else "Evento"
        clauses.append(f"{word} " + _SECURITY_LOG_ES.format(ids=_join_es(security)))

    grouped: dict[str, list[str]] = {}
    for event_id in ids:
        log = _EVENT_LOG_ES.get(event_id)
        if log:
            grouped.setdefault(log, []).append(event_id)
    for log, log_ids in grouped.items():
        word = "Eventos" if len(log_ids) > 1 else "Evento"
        if clauses:
            word = word.lower()
        clauses.append(f"{word} {_join_es(log_ids)} {log}")

    return "; ".join(clauses) + "."


# ── Axes 1, 2, 4: modification, rollback, scope ──────────────────────────────
# All three are DERIVED from the catalog's declared change kinds, so one
# declaration beside the technique populates three columns and none of them can
# contradict what the cleanup layer and the ledger actually do.
#: Where each change kind LIVES. Axis 4 ("directory only, or endpoints?") is
#: this classification, not a guess: a certificate lives in the CA database, a
#: dump file on the host filesystem, an ACE in the directory.
_KIND_SCOPE: dict[str, str] = {
    _tax.KIND_ISSUED_CERTIFICATE: _SCOPE_CA_DATABASE,
    _tax.KIND_FORGED_CERTIFICATE: _SCOPE_CA_OFFLINE,
    _tax.KIND_CA_PRIVATE_KEY_EXFILTRATED: _SCOPE_CA_HOST,
    _tax.KIND_CA_BACKUP_SERVICE: _SCOPE_CA_HOST,
    _tax.KIND_CA_BACKUP_TEMP_PFX: _SCOPE_CA_HOST,
    _tax.KIND_REMOTE_FILE_WRITTEN: _SCOPE_HOST_FILE,
    _tax.KIND_REMOTE_FILE_UPLOADED: _SCOPE_HOST_FILE,
    "mssql_xp_cmdshell_enabled": _SCOPE_SQL_SERVER,
    "mssql_clr_assembly_loaded": _SCOPE_SQL_SERVER,
    "mssql_clr_config_changed": _SCOPE_SQL_SERVER,
    "mssql_postex_account": _SCOPE_SQL_SERVER,
    "mssql_admin_account_created": _SCOPE_SQL_SERVER,
    "scheduled_task_created": _SCOPE_HOST_TASK,
    "dns_record_added": _SCOPE_DIRECTORY_DNS,
    "rodc_prp_modified": _SCOPE_DIRECTORY,
}


def _scope_for_kind(kind: str) -> str:
    """Where this change kind lives. Defaults to the directory.

    Safe default: every kind not listed in :data:`_KIND_SCOPE` is a directory
    object written over LDAP (the ACL/ACE, membership, SPN, owner, delegation
    and shadow-credential families), and a new kind that is NOT would fail
    :func:`_kind_label_es` first, so it cannot reach here unnoticed.
    """
    return _KIND_SCOPE.get(kind, _SCOPE_DIRECTORY)
#: Change kinds the owning service keeps on a successful run and reverts only on
#: operator confirmation at exit (the ledger's ``OPERATOR_CONFIRMED`` class).
_OPERATOR_CONFIRMED_KINDS: frozenset[str] = frozenset(
    {
        "machine_account_created",
        "rbcd_delegation_added",
        "keycredentiallink_added",
        _tax.KIND_CA_BACKUP_SERVICE,
        _tax.KIND_CA_BACKUP_TEMP_PFX,
    }
)


def _rollback_for_kind(kind: str) -> str:
    """Rollback lifecycle sentence for ONE change kind, or :data:`PENDING`.

    Ordered strictest-first so a kind that cannot be reverted is never described
    by a weaker guarantee.
    """
    if kind in NEVER_AUTO_REVERT_KINDS:
        return _ROLLBACK_MANUAL
    if kind in _OPERATOR_CONFIRMED_KINDS:
        return _ROLLBACK_OPERATOR
    if kind in VERIFIED_AUTO_REVERT_KINDS or _tax.kind_is_host_artifact(kind):
        return _ROLLBACK_AUTO
    return PENDING


# Strictness order for combining several kinds on one technique: the weakest
# guarantee present is the one the document may claim.
_ROLLBACK_STRICTNESS: dict[str, int] = {
    PENDING: 0,
    _ROLLBACK_UNTRACKED: 1,
    _ROLLBACK_UNSETTLED: 1,
    _ROLLBACK_MANUAL: 2,
    _ROLLBACK_OPERATOR: 3,
    _ROLLBACK_AUTO: 4,
}


def _writes_axes(relation: str, entry: Any) -> tuple[str, str, str, dict[str, str]]:
    """(modifies, rollback, scope, sources) for axes 1, 2 and 4."""
    sources: dict[str, str] = {}

    kinds = getattr(entry, "environment_change_kinds", None)
    if kinds is None:
        # UNDECLARED. Never assumed read-only: a technique whose impact data was
        # not declared gets three visible "pendiente" cells.
        return PENDING, PENDING, PENDING, sources

    sources["modifies"] = "attack_step_catalog.environment_change_kinds"
    sources["rollback"] = (
        "cleanup_taxonomy revert plans + environment_change_ledger change classes"
    )
    sources["scope"] = "cleanup_taxonomy change-kind classification"

    if not kinds:
        # Declared as writing nothing. Distinguish "runs and only reads" from
        # "ADscan does not run it at all": both modify nothing, but a CISO reads
        # them differently.
        if relation in NO_EXECUTOR_RELATIONS:
            sources["modifies"] = "safeguard_profile.NO_EXECUTOR_RELATIONS"
            return _MODIFIES_NO_EXECUTOR, _ROLLBACK_NA, _SCOPE_DIRECTORY_READ, sources
        if getattr(entry, "support_kind", "") == "supported":
            return _MODIFIES_NOTHING, _ROLLBACK_NA, _SCOPE_DIRECTORY_READ, sources
        return _MODIFIES_NOT_EXECUTED, _ROLLBACK_NA, _SCOPE_DIRECTORY_READ, sources

    labels = [_kind_label_es(kind) for kind in kinds]
    if relation == "allextendedrights":
        # The declared kind (the password reset the user branch performs) drives
        # the rollback and scope columns, but naming only that write would hide
        # the other two branches, which read instead. So the modification cell
        # states the per-object-class behaviour and the derived columns stay
        # derived, grounded on the strongest write any branch can make.
        labels = [_ALLEXTENDEDRIGHTS_MODIFIES]
        sources["modifies"] = (
            "ace_step_execution.execute_ace_step (remap por clase de objeto)"
            " + attack_step_catalog.environment_change_kinds"
        )

    if relation in LEDGER_UNTRACKED_WRITES:
        rollback = _ROLLBACK_UNTRACKED
        sources["rollback"] = "safeguard_profile.LEDGER_UNTRACKED_WRITES"
    elif relation in LEDGER_UNSETTLED_WRITES:
        rollback = _ROLLBACK_UNSETTLED
        sources["rollback"] = "safeguard_profile.LEDGER_UNSETTLED_WRITES"
    else:
        rollbacks = [_rollback_for_kind(kind) for kind in kinds]
        rollback = min(rollbacks, key=lambda r: _ROLLBACK_STRICTNESS.get(r, 0))
    if rollback == PENDING:
        sources.pop("rollback", None)

    scope_parts: list[str] = []
    for kind in kinds:
        scope = _scope_for_kind(kind)
        if scope not in scope_parts:
            scope_parts.append(scope)
    if getattr(entry, "source_context_requirement", "") == "local_admin_session":
        scope_parts.append(_SCOPE_HOST_MEMORY)
    elif getattr(entry, "source_context_requirement", "") == "mssql_rce_session":
        scope_parts.append(_SCOPE_HOST_SQL)

    return " · ".join(labels), rollback, " ".join(scope_parts), sources


def build_safeguard_profile(relation: str, entry: Any | None = None) -> SafeguardProfile:
    """Derive the six safeguard axes for one catalog relation.

    Args:
        relation: The catalog key / BloodHound relation name.
        entry: The catalog entry; looked up when omitted.

    Returns:
        A :class:`SafeguardProfile`. Any axis the code does not support is
        :data:`PENDING`.
    """
    resolved = entry if entry is not None else ATTACK_STEP_CATALOG.get(relation)
    if resolved is None:
        return SafeguardProfile(
            relation=relation,
            modifies=PENDING, rollback=PENDING, blocked=PENDING,
            scope=PENDING, min_privilege=PENDING, soc=PENDING,
        )
    modifies, rollback, scope, sources = _writes_axes(relation, resolved)
    blocked, blocked_src = _blocked_axis(relation, resolved)
    min_priv, min_priv_src = _min_privilege_axis(resolved)
    soc, soc_src = _soc_axis(resolved)
    if blocked_src:
        sources["blocked"] = blocked_src
    if min_priv_src:
        sources["min_privilege"] = min_priv_src
    if soc_src:
        sources["soc"] = soc_src
    return SafeguardProfile(
        relation=relation,
        modifies=modifies,
        rollback=rollback,
        blocked=blocked,
        scope=scope,
        min_privilege=min_priv,
        soc=soc,
        sources=sources,
    )


def build_all_safeguard_profiles() -> dict[str, SafeguardProfile]:
    """Profiles for every customer-facing technique in the catalog.

    Applies the same ``context``-category exclusion as the coverage SSOT, so the
    profile set and the headline technique count describe the same population.
    """
    out: dict[str, SafeguardProfile] = {}
    for relation, entry in ATTACK_STEP_CATALOG.items():
        category = getattr(entry, "category", None)
        if not category or category in STEP_CATEGORY_EXCLUDE:
            continue
        out[relation] = build_safeguard_profile(relation, entry)
    return out


def pending_fields() -> list[tuple[str, str, tuple[str, ...]]]:
    """Every technique with at least one axis needing human input.

    Returns:
        ``[(relation, category, (axis, …)), …]`` sorted by category then relation.
        This is the hand-off list: each tuple is a cell a human must fill before
        the document can stop printing "pendiente" there.
    """
    rows: list[tuple[str, str, tuple[str, ...]]] = []
    for relation, profile in build_all_safeguard_profiles().items():
        gaps = profile.pending()
        if not gaps:
            continue
        entry = ATTACK_STEP_CATALOG.get(relation)
        rows.append((relation, getattr(entry, "category", "") or "", gaps))
    rows.sort(key=lambda r: (r[1], r[0]))
    return rows


# ── Header-level safeguards (the block that goes ABOVE, not in small print) ──
# A CISO with a SOC background told us the honest answer to his question is the
# unverifiable-revert disclosure, and that burying it at the end SUBTRACTS. So
# these four statements are the document's HEADER, next to the read-only mode
# and the hard block. The wording of (2) and (3) is FIXED — it is the exact
# formulation we are allowed to make, and it must not be paraphrased into
# "everything is reversible" or "it executes nothing".
HEADER_SAFEGUARDS: tuple[tuple[str, str], ...] = (
    (
        "Modo de solo mapeo",
        "Hay un modo que mapea y reporta las vías sin ejecutarlas, se elige al "
        "lanzarlo.",
    ),
    (
        "Registro y reversión comprobada",
        "Cada cambio queda registrado y se revierte comprobándolo; lo que no se "
        "puede verificar se reporta nombrando el objeto.",
    ),
    (
        "Bloqueo duro",
        "Las técnicas que tumbarían un servicio en producción no se ejecutan en "
        "ningún modo, y un operador no puede forzarlas.",
    ),
    (
        "En auditoría no se ejecutan solas",
        "Las técnicas disruptivas pero recuperables, como reiniciar la "
        "contraseña de un usuario, no se ejecutan en una auditoría salvo que el "
        "operador las autorice a mano: en una ejecución desatendida se omiten. "
        "Solo se ejecutan solas en un entorno desechable, de laboratorio o CTF.",
    ),
)
