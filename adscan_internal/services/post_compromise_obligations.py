"""What a PROVEN compromise obliges the client to do, derived from the workspace.

A report that proves domain compromise and then lists "fix the certificate
template" has told the client about the hole and said nothing about the water
already inside the building. Three consequences follow from an assessment that
actually succeeded, and none of them is a finding:

1. **Key material that signs every Kerberos ticket was recovered.** Until the
   krbtgt password is reset twice, with replication completing between the two
   resets, forged tickets keep working no matter what else is remediated.
2. **Every credential the assessment recovered is compromised.** They belong to
   real accounts, they were obtained during the engagement, and the report has
   to name them so the client knows exactly what to rotate.
3. **A certificate the assessment had the CA issue keeps authenticating.** It
   outlives the engagement by design; only revocation stops it.

This module derives those obligations from what the engagement actually PROVED,
never from what it merely identified. A run that never pulled key material must
not tell the client to reset krbtgt — that is the inverse dishonesty of the
omission it fixes, and it trains a reader to skip the block.

Tier-shared by design (CLAUDE.md § Dual-tier reporting, layer 1): the paid kit
and the free exposure report derive the same obligations from the same workspace
so the two can never disagree about what a compromise obliges. Composition —
where the block sits and how it is drawn — stays per document.

Sources of proof, all read from the workspace, none inferred:

* ``variables.json`` ``domains_data[<domain>]["credentials"]`` +
  ``["credentials_meta"]`` — the credential store. A principal is *recovered*
  when the assessment obtained its secret, which is the same test the
  credential-provenance table applies: an origin outside
  :data:`~adscan_internal.services.session_compromise_state_service.NON_COMPROMISE_ORIGINS`
  (those identify the login the operator supplied, which was never compromised).
* ``domains_data[<domain>]["dcsync_all_done"]`` — set only after a full
  directory replication completed, which means every account's password hash in
  that domain was exposed, not just the ones the store kept.
* The same credential store's recorded ORIGINS, read through the provenance
  SSOT (:func:`~adscan_internal.services.credentials.credential_origin.build_method_set`
  plus :func:`~adscan_internal.services.credentials.credential_origin.classify_origin_acquisition`).
  An origin names the technique that produced the secret, and a handful of those
  techniques do not read one account: they take a COPY of a credential store off
  a host. That copy is the fourth consequence, and it was the one missing. A
  report can state zero directory modifications, name five accounts to rotate,
  and still never tell the client that a credential database left a domain
  controller, which is the disclosure with legal shape. See
  :data:`DIRECTORY_DATABASE_ORIGINS` / :data:`HOST_CREDENTIAL_STORE_ORIGINS`.

  The gate is EXECUTION, never reach: an origin is only present in the store
  because a run produced a secret through it, and a derived acquisition (an
  offline transform of material already held) is excluded. A technique ADscan
  attempted and failed leaves no origin, so a failed replication cannot
  manufacture this disclosure. That is the same honesty gate the rest of the
  report applies, and here it is what keeps a containment instruction from
  being invented.
* The environment-change ledger — certificates the CA issued during the
  assessment, with the identity each authenticates as and the date it expires.
  Resolved from the workspace through the ledger SSOT
  (:func:`~adscan_internal.services.environment_change_ledger.resolve_environment_changes`)
  exactly like the credential store, so a caller that hands over only a
  workspace still gets the certificate obligation. A caller holding a fresher
  block passes it and that wins; the way to say "consider no ledger at all" is
  the explicit :data:`NO_ENVIRONMENT_CHANGES`, never ``None``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from adscan_core.reporting.clock_frame import (
    StampFrame,
    clock_offset_phrase,
    format_instant_for_client,
    resolve_stamp_frame,
    stamp_post_dates,
)
from adscan_internal.principal_utils import is_machine_account
from adscan_internal.services import cleanup_taxonomy as _tax
from adscan_internal.services.credentials.credential_origin import (
    ORIGIN_BACKUP_OPERATORS,
    ORIGIN_DPAPI,
    ORIGIN_LSA_SECRETS,
    ORIGIN_LSASS_DUMP,
    ORIGIN_NTDS,
    ORIGIN_SAM_DUMP,
    ORIGIN_SECRETSDUMP,
    CredentialAcquisition,
    _normalize_origin,
    build_method_set,
    classify_origin_acquisition,
    is_blank_anonymous_credential,
)
from adscan_internal.services.session_compromise_state_service import (
    NON_COMPROMISE_ORIGINS,
)

__all__ = [
    "CERTIFICATE_CHANGE_KINDS",
    "DIRECTORY_DATABASE_ORIGINS",
    "HOST_CREDENTIAL_STORE_ORIGINS",
    "KRBTGT_PRINCIPAL",
    "NO_ENVIRONMENT_CHANGES",
    "OBLIGATION_CERTIFICATE",
    "OBLIGATION_CREDENTIALS",
    "OBLIGATION_EXTRACTION",
    "OBLIGATION_KRBTGT",
    "SCOPE_DIRECTORY_DATABASE",
    "SCOPE_HOST_CREDENTIAL_STORE",
    "CredentialStoreExtraction",
    "IssuedCertificate",
    "Obligation",
    "ObligationStep",
    "build_post_compromise_obligations",
    "credential_store_extractions",
    "is_compromised_credential_origin",
    "load_workspace_credential_store",
    "load_post_compromise_obligations",
    "obligation_to_dict",
    "obligations_to_dicts",
    "recovered_principals",
]


class _NoEnvironmentChanges:
    """The type of :data:`NO_ENVIRONMENT_CHANGES`."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover — debugging aid only
        return "NO_ENVIRONMENT_CHANGES"


#: Passed as ``environment_changes`` to mean "consider no ledger at all".
#:
#: ``None`` deliberately does NOT mean this. In
#: :func:`load_post_compromise_obligations`, ``None`` means "read the ledger from
#: the workspace for me" — the same treatment the credential store already gets.
#: The two were once collapsed onto ``None``, and the result was a caller that
#: passed a workspace and silently lost the certificate-revocation obligation:
#: the report still said rotate krbtgt and rotate the credentials, so it read
#: complete, while omitting the one instruction with legal weight. A missing
#: instruction that leaves no trace is the worst thing this module can ship, so
#: "no ledger" has to be said out loud.
NO_ENVIRONMENT_CHANGES = _NoEnvironmentChanges()

#: The account whose key signs every Kerberos ticket the domain issues.
KRBTGT_PRINCIPAL = "krbtgt"

#: The built-in Guest account (sAMAccountName always ``Guest``, RID 501). Its
#: "recovered credential" is a blank/anonymous logon mapped to Guest, not a real
#: secret, so telling the client to ROTATE its password is wrong — a blank
#: password cannot be rotated into safety, and the correct action is to DISABLE
#: it (which finding F-001 already prescribes). Handled as its own containment
#: step, excluded from the rotate-every-account list.
GUEST_PRINCIPAL = "guest"


def _is_builtin_guest(name: str) -> bool:
    """Return True when ``name`` is the built-in Guest account.

    Matches the invariant sAMAccountName (``Guest``), case-insensitively, and its
    domain-suffixed profile form (``guest.CICADA``). The built-in Guest name is
    stable across every Windows/AD install, so a name match is reliable here.
    """
    token = str(name or "").strip().lower()
    if not token:
        return False
    return token == GUEST_PRINCIPAL or token.startswith(f"{GUEST_PRINCIPAL}.")

#: Ledger change kinds that leave a certificate able to authenticate after the
#: engagement ends. Both are sourced from the cleanup taxonomy SSOT.
CERTIFICATE_CHANGE_KINDS: frozenset[str] = frozenset(
    {_tax.KIND_ISSUED_CERTIFICATE, _tax.KIND_FORGED_CERTIFICATE}
)

#: Obligation identifiers, stable so a renderer can style or order them.
OBLIGATION_KRBTGT = "krbtgt_reset"
OBLIGATION_CREDENTIALS = "credential_rotation"
OBLIGATION_CERTIFICATE = "certificate_revocation"
OBLIGATION_EXTRACTION = "credential_store_custody"

#: The two scopes of credential-store extraction, which decide what the client
#: is told was inside the copy. They are NOT severity bands: they are a
#: statement of CONTENT, and the content is what makes one of them reach the
#: whole domain.
#:
#: The split matters because the wrong one is a lie in either direction. Telling
#: a client that krbtgt was read when a run only took a host's registry hives
#: invents an emergency and trains the reader to discount the block. Telling a
#: client that "credential material" was read when a full replication took the
#: entire database understates a total compromise.
SCOPE_DIRECTORY_DATABASE = "directory_database"
SCOPE_HOST_CREDENTIAL_STORE = "host_credential_store"

#: Origins that take a copy of THE DIRECTORY DATABASE, so every account in the
#: domain was read, krbtgt included.
#:
#: ``ntds`` / ``secretsdump`` parse the database file itself. A full replication
#: is recorded separately by the ``dcsync_all_done`` marker, which is the
#: authoritative "everything" signal, and it is read alongside these.
#:
#: A TARGETED replication is deliberately NOT here. The ``dcsync`` origin alone
#: proves specific accounts were replicated, which is already disclosed by
#: naming them for rotation, and krbtgt among them is already caught by the
#: krbtgt-in-store test. Treating it as a whole-database copy would claim more
#: than the workspace proves.
DIRECTORY_DATABASE_ORIGINS: frozenset[str] = frozenset(
    _normalize_origin(origin)
    for origin in (ORIGIN_NTDS, ORIGIN_SECRETSDUMP)
)

#: Origins that take a copy of A HOST'S credential stores: its local account
#: database, its LSA secrets, the memory of the process that holds logon
#: material, the data protection master keys.
#:
#: On an ordinary member server that copy reaches that server. On a domain
#: controller it includes the controller's own Kerberos key, which authenticates
#: AS a domain controller and may therefore replicate the directory, so the
#: reach is the whole domain even though the directory database itself never
#: moved. The obligation says that in those words rather than asserting krbtgt
#: was read, because it was not.
HOST_CREDENTIAL_STORE_ORIGINS: frozenset[str] = frozenset(
    _normalize_origin(origin)
    for origin in (
        ORIGIN_BACKUP_OPERATORS,
        ORIGIN_SAM_DUMP,
        ORIGIN_LSA_SECRETS,
        ORIGIN_LSASS_DUMP,
        ORIGIN_DPAPI,
    )
)


@dataclass(frozen=True)
class ObligationStep:
    """One numbered action, with the command that performs it.

    Attributes:
        text: What to do and why, in one or two sentences.
        commands: Native commands that perform the step. Empty when the step is
            a decision or a wait rather than something to run.
    """

    text: str
    commands: tuple[str, ...] = ()


@dataclass(frozen=True)
class Obligation:
    """One consequence the proven compromise imposes on the client.

    Attributes:
        key: Stable identifier (:data:`OBLIGATION_KRBTGT` and siblings).
        title: Imperative headline — the action, not the risk.
        proof: What the assessment proved, stated plainly. This is the sentence
            that earns the instruction; without it the block is advice.
        rationale: Why the obvious remediation is not enough, or what a reader
            would otherwise get wrong.
        steps: The ordered actions.
        caveat: What stays true even after the action completes. Empty when
            there is nothing to warn about.
        domains: The domains the obligation applies to.
        accounts: Named principals the obligation covers, when it has any.
        runbook: A verbatim procedure the ledger already rendered for this
            obligation, split into lines. Carried for a document that has
            nowhere else to put it; a document that prints the procedure in
            full elsewhere (the paid kit's Environment Modifications section)
            points at that instead of repeating it. Empty for obligations whose
            steps are self-contained.
        containment_kind: Which rung of the containment ladder this obligation
            sits on, from
            :data:`~adscan_internal.services.remediation_start_here.CONTAINMENT_KIND_ORDER`
            (``krbtgt`` then ``certificate`` then ``credential``, in
            time-criticality order). Carried so a renderer that groups or sorts
            containment work reads the SAME ladder the ranked remediation rows
            use, instead of growing a second one. Empty when the obligation
            predates the ladder.
    """

    key: str
    title: str
    proof: str
    rationale: str
    steps: tuple[ObligationStep, ...] = ()
    caveat: str = ""
    domains: tuple[str, ...] = ()
    accounts: tuple[str, ...] = field(default=())
    runbook: tuple[str, ...] = ()
    containment_kind: str = ""


@dataclass(frozen=True)
class CredentialStoreExtraction:
    """A credential store this assessment copied off a host, with its content.

    Attributes:
        domain: The domain the copy belongs to.
        scope: :data:`SCOPE_DIRECTORY_DATABASE` or
            :data:`SCOPE_HOST_CREDENTIAL_STORE`.
        host: The host the copy came off, as the workspace recorded it. Empty
            when the workspace did not name one, in which case the prose says
            "a domain controller" rather than inventing a name.
        methods: The client-safe labels of the techniques that produced it.
        principals: The accounts whose secrets the copy yielded.
        machine_accounts: Those of them that are machine accounts. On a domain
            controller this is the key that reaches the whole domain.
        observed_at: When the extraction was recorded, for the client to scope
            their own logs against. Empty when unrecorded.
        observed_at_frame: Which clock produced ``observed_at``, resolved
            through :func:`~adscan_core.reporting.clock_frame.resolve_stamp_frame`.
            The scan steps the host clock to the DC mid-run, so a stamp written
            afterwards reads the DC's clock, and that is the clock the client's
            own Security log is written in.
    """

    domain: str
    scope: str
    host: str = ""
    methods: tuple[str, ...] = ()
    principals: tuple[str, ...] = ()
    machine_accounts: tuple[str, ...] = ()
    observed_at: str = ""
    observed_at_frame: StampFrame = field(default_factory=StampFrame)

    @property
    def took_whole_directory(self) -> bool:
        """True when the copy was the directory database, krbtgt included."""
        return self.scope == SCOPE_DIRECTORY_DATABASE


@dataclass(frozen=True)
class IssuedCertificate:
    """A certificate the assessment had the client's CA issue."""

    domain: str
    principal: str
    template: str
    authority: str
    not_after: str
    #: The revocation procedure the ledger already rendered for this
    #: certificate, verbatim. Never re-derived here.
    remediation: str = ""


# --- Reading the proof ------------------------------------------------------


def is_compromised_credential_origin(origin: Any) -> bool:
    """True when a credential was OBTAINED by the assessment, not supplied to it.

    The single test both the credential-provenance table and the obligations
    apply, so "what did we break into" means the same thing in both places.

    Args:
        origin: ``credentials_meta[<user>]["credential_origin"]``.

    Returns:
        False for the operator-supplied login and for a manually entered
        credential; True for everything else, including an unrecorded origin
        (an account in the store with no provenance was still obtained).
    """
    return str(origin or "").strip().lower() not in NON_COMPROMISE_ORIGINS


def load_workspace_credential_store(workspace_dir: Any) -> dict[str, dict[str, Any]]:
    """Load ``variables.json`` and return its per-domain store.

    Domain names are returned exactly as the workspace recorded them — the
    report prints them, so the casing is the client's, not ours. Consumers that
    need to match a domain do so case-insensitively.

    Best-effort: a missing or malformed file yields an empty mapping and never
    raises, so a report renders with the block omitted rather than failing.

    Args:
        workspace_dir: Workspace root holding ``variables.json``.

    Returns:
        ``{domain: domains_data[<domain>]}``.
    """
    try:
        path = os.path.join(str(workspace_dir), "variables.json")
        if not os.path.isfile(path):
            return {}
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        store = data.get("domains_data") if isinstance(data, dict) else None
        if not isinstance(store, dict):
            return {}
        return {
            str(name).strip(): payload
            for name, payload in store.items()
            if isinstance(name, str) and isinstance(payload, dict)
        }
    except Exception:  # noqa: BLE001 — absence is graceful, never fatal
        return {}


def recovered_principals(domain_store: Any) -> tuple[str, ...]:
    """Return the accounts whose secrets this assessment obtained, sorted.

    Args:
        domain_store: ``variables.json`` ``domains_data[<domain>]`` mapping.

    Returns:
        sAMAccountNames, case-preserved, sorted case-insensitively. Empty when
        the domain has no credential store or holds only the supplied login.
    """
    if not isinstance(domain_store, Mapping):
        return ()
    credentials = domain_store.get("credentials")
    if not isinstance(credentials, Mapping):
        return ()
    meta_map = domain_store.get("credentials_meta")
    meta_map = meta_map if isinstance(meta_map, Mapping) else {}

    out: list[str] = []
    for principal in credentials:
        name = str(principal or "").strip()
        if not name:
            continue
        meta = meta_map.get(principal)
        origin = meta.get("credential_origin") if isinstance(meta, Mapping) else None
        if not is_compromised_credential_origin(origin):
            continue
        out.append(name)
    out.sort(key=str.lower)
    return tuple(out)


def _blank_anonymous_principal_names(domain_store: Any) -> set[str]:
    """Return the lower-cased names whose credential is a blank / anonymous logon.

    A blank / anonymous logon (the built-in Guest, the anonymous session) has no
    secret to rotate — it must be DISABLED. The carve-out that separates these
    from the rotate-every-account list keys on the credential-representation SSOT
    (:func:`is_blank_anonymous_credential`), the SAME fact the compromised-
    credentials provenance table uses to label the credential TYPE, so the two
    surfaces can never disagree about which accounts hold a rotatable secret.
    """
    if not isinstance(domain_store, Mapping):
        return set()
    credentials = domain_store.get("credentials")
    if not isinstance(credentials, Mapping):
        return set()
    meta_map = domain_store.get("credentials_meta")
    meta_map = meta_map if isinstance(meta_map, Mapping) else {}
    out: set[str] = set()
    for principal in credentials:
        name = str(principal or "").strip()
        if not name:
            continue
        meta = meta_map.get(principal)
        origin = meta.get("credential_origin") if isinstance(meta, Mapping) else None
        if is_blank_anonymous_credential(origin):
            out.add(name.lower())
    return out


def _directory_replicated(domain_store: Any) -> bool:
    """True when a full replication of the directory database completed.

    Marker written only after a successful "replicate everything" run, so it is
    proof that every account's password hash in the domain was exposed — not
    only the ones the credential store kept.
    """
    if not isinstance(domain_store, Mapping):
        return False
    return bool(domain_store.get("dcsync_all_done"))


def _extraction_host(domain_store: Mapping[str, Any], *, scope: str) -> tuple[str, str]:
    """Return ``(host, observed_at)`` for an extraction, from the workspace.

    Resolved from what the workspace actually recorded, never guessed. The
    Backup Operators flow persists the host it succeeded against and when, so
    that wins when it is there. A directory replication always runs against a
    domain controller, so the domain's own controller name is correct for that
    scope. Anything else returns an empty host and the prose says "a domain
    controller" instead of naming one, because a wrong host name in a
    containment instruction sends the client to the wrong machine.
    """
    success = domain_store.get("backup_ops_success")
    if isinstance(success, Mapping):
        host = str(success.get("hostname") or "").strip()
        stamp = str(success.get("timestamp") or "").strip()
        if host:
            return host, stamp
    if scope == SCOPE_DIRECTORY_DATABASE:
        for field_name in ("pdc_hostname", "dc_fqdn", "pdc_hostname_fqdn", "pdc"):
            host = str(domain_store.get(field_name) or "").strip()
            if host:
                return host, ""
    return "", ""


def credential_store_extractions(
    domain_store: Any, domain: str
) -> tuple[CredentialStoreExtraction, ...]:
    """Return the credential-store copies this assessment PROVED it took.

    Reads the credential store's recorded provenance through the origin SSOT:
    a store entry exists because a run produced that secret, and its origins
    name which technique did. An origin in
    :data:`DIRECTORY_DATABASE_ORIGINS` or
    :data:`HOST_CREDENTIAL_STORE_ORIGINS` means that technique took a COPY of a
    credential store rather than reading one account, which is the fact this
    disclosure rests on.

    Three gates keep it honest, and all three matter:

    * **Executed only.** A derived acquisition (resolving a hash ADscan already
      held to its plaintext) performed no act against the environment, so it
      moved no copy. Classified through
      :func:`~adscan_internal.services.credentials.credential_origin.classify_origin_acquisition`,
      never by reading the raw slug.
    * **Recovered only.** The operator's own login is in the same store and was
      never compromised, so it is excluded by the same test the provenance table
      applies.
    * **Nothing from reach.** A technique that was mapped, or attempted and
      failed, leaves no store entry and therefore no origin, so it cannot
      produce this block. A run whose replication failed and whose Backup
      Operators read succeeded discloses the read, and only the read.

    ONE extraction is returned per domain, at the WIDEST scope observed, merged
    across every account and technique it produced. The client needs to know
    that a copy left and what was inside it, not one row per hash and not two
    rows for one engagement: a run that replicated the directory database and
    also read a controller's registry stores took the database, and a second
    disclosure saying a subset of it also left would only dilute the first.

    Args:
        domain_store: ``variables.json`` ``domains_data[<domain>]`` mapping.
        domain: The domain name, as the report prints it.

    Returns:
        A one-element tuple, or empty when nothing was copied. Returning a
        tuple keeps the caller's loop unchanged if a future scope has to be
        reported separately.
    """
    if not isinstance(domain_store, Mapping):
        return ()
    credentials = domain_store.get("credentials")
    credentials = credentials if isinstance(credentials, Mapping) else {}
    meta_map = domain_store.get("credentials_meta")
    meta_map = meta_map if isinstance(meta_map, Mapping) else {}

    # scope -> (methods, principals, machine accounts), insertion-ordered so the
    # prose lists them the way the engagement found them.
    found: dict[str, tuple[dict[str, None], dict[str, None], dict[str, None]]] = {}

    def _bucket(scope: str) -> tuple[dict[str, None], dict[str, None], dict[str, None]]:
        return found.setdefault(scope, ({}, {}, {}))

    for principal in credentials:
        name = str(principal or "").strip()
        if not name:
            continue
        meta = meta_map.get(principal)
        meta = meta if isinstance(meta, Mapping) else {}
        primary = meta.get("credential_origin")
        if not is_compromised_credential_origin(primary):
            continue
        for entry in build_method_set(primary, meta.get("origins")):
            slug = str(entry.get("method") or "")
            acquisition = str(entry.get("acquisition") or "").strip().lower()
            if not acquisition:
                acquisition = classify_origin_acquisition(slug).value
            if acquisition != CredentialAcquisition.EXECUTED.value:
                continue
            normalized = _normalize_origin(slug)
            if normalized in DIRECTORY_DATABASE_ORIGINS:
                scope = SCOPE_DIRECTORY_DATABASE
            elif normalized in HOST_CREDENTIAL_STORE_ORIGINS:
                scope = SCOPE_HOST_CREDENTIAL_STORE
            else:
                continue
            methods, principals, machines = _bucket(scope)
            methods[str(entry.get("method_label") or slug)] = None
            principals[name] = None
            if is_machine_account(name):
                machines[name] = None

    # A completed full replication is the authoritative "the whole database was
    # read" marker, and it is recorded on the domain rather than on any single
    # credential. It stands on its own: a replication that completed and whose
    # secrets were not kept in the store still took the copy.
    if _directory_replicated(domain_store):
        _bucket(SCOPE_DIRECTORY_DATABASE)

    if not found:
        return ()
    widest = (
        SCOPE_DIRECTORY_DATABASE
        if SCOPE_DIRECTORY_DATABASE in found
        else SCOPE_HOST_CREDENTIAL_STORE
    )
    methods: dict[str, None] = {}
    principals: dict[str, None] = {}
    machines: dict[str, None] = {}
    for scope_methods, scope_principals, scope_machines in found.values():
        methods.update(scope_methods)
        principals.update(scope_principals)
        machines.update(scope_machines)
    host, observed_at = _extraction_host(domain_store, scope=widest)
    return (
        CredentialStoreExtraction(
            domain=str(domain or "").strip(),
            scope=widest,
            host=host,
            methods=tuple(methods),
            principals=tuple(sorted(principals, key=str.lower)),
            machine_accounts=tuple(sorted(machines, key=str.lower)),
            observed_at=observed_at,
            observed_at_frame=resolve_stamp_frame(domain_store, observed_at),
        ),
    )


def _issued_certificates(
    environment_changes: Any,
) -> tuple[IssuedCertificate, ...]:
    """Extract the certificates the assessment had the CA issue.

    Reads the persisted ledger block ``{summary, changes}``. Only changes still
    outstanding count: one the client already revoked carries no obligation.
    """
    if not isinstance(environment_changes, Mapping):
        return ()
    changes = environment_changes.get("changes")
    if not isinstance(changes, list):
        return ()
    out: list[IssuedCertificate] = []
    for entry in changes:
        if not isinstance(entry, Mapping):
            continue
        if str(entry.get("kind") or "") not in CERTIFICATE_CHANGE_KINDS:
            continue
        status = str(entry.get("revert_status") or _tax.STATUS_PENDING)
        if _tax.cleanup_bucket(status) == _tax.CLEANUP_BUCKET_REVERTED:
            continue
        detail = entry.get("detail")
        detail = detail if isinstance(detail, Mapping) else {}
        out.append(
            IssuedCertificate(
                domain=str(entry.get("domain") or "").strip(),
                principal=str(detail.get("principal") or "").strip(),
                template=str(detail.get("template") or "").strip(),
                authority=str(
                    detail.get("ca_name") or detail.get("ca_host") or ""
                ).strip(),
                not_after=str(detail.get("not_after") or "").strip(),
                remediation=str(
                    entry.get("remediation_command")
                    or entry.get("manual_cleanup_instructions")
                    or ""
                ).strip(),
            )
        )
    return tuple(out)


# --- Writing the obligations ------------------------------------------------


def _join_names(names: Sequence[str], *, cap: int = 12) -> str:
    """Render a principal list for prose, capped so a paragraph stays readable."""
    shown = list(names[:cap])
    remainder = len(names) - len(shown)
    body = ", ".join(shown)
    if remainder > 0:
        body += f", and {remainder} more"
    return body


def _plural(count: int, singular: str, plural: str = "") -> str:
    """Return the singular or plural form for ``count``."""
    return singular if count == 1 else (plural or f"{singular}s")


def _domains_phrase(domains: Sequence[str]) -> str:
    """Render one or more domain names for prose."""
    if not domains:
        return "the assessed domain"
    if len(domains) == 1:
        return domains[0]
    return ", ".join(domains[:-1]) + f" and {domains[-1]}"


def _host_artifact_counts(environment_changes: Any) -> tuple[bool, int, int]:
    """Return ``(determined, host_artifacts, manual_required)`` from the ledger.

    The teardown step is written from the change ledger rather than from what
    the extraction code happens to do, because the ledger is the record the
    client can audit and the one the environment-modifications section already
    prints. ``determined`` is carried separately so an unreadable ledger never
    renders as "nothing was left behind": an absent record is not a clean host,
    which is the same third state the engagement-integrity note keeps.
    """
    from adscan_internal.services.environment_change_ledger import (  # noqa: PLC0415
        environment_changes_determined,
    )

    if not isinstance(environment_changes, Mapping):
        return False, 0, 0
    # The determined/undetermined call belongs to the ledger SSOT, not to a
    # second reading of the same key here: a legacy block with no explicit
    # marker counts as determined there, and a copy of that rule would drift.
    determined = environment_changes_determined(dict(environment_changes))
    changes = environment_changes.get("changes")
    if not isinstance(changes, list):
        return determined, 0, 0
    artifacts = 0
    manual = 0
    for entry in changes:
        if not isinstance(entry, Mapping):
            continue
        if not _tax.kind_is_host_artifact(entry.get("kind")):
            continue
        artifacts += 1
        status = str(entry.get("revert_status") or _tax.STATUS_PENDING)
        if _tax.cleanup_bucket(status) == _tax.CLEANUP_BUCKET_MANUAL:
            manual += 1
    return determined, artifacts, manual


def _log_window_day(observed_at: str) -> str:
    """Return the calendar day of an extraction stamp, for a log query.

    The stamp records when the read COMPLETED, to the microsecond. A client
    searching their own security log needs a start boundary that is certain to
    sit before the read, so the query opens at the start of that day and the
    prose carries the exact moment. A stamp we cannot parse yields an obvious
    fill-in rather than a half-formed date.
    """
    text = str(observed_at or "").strip()
    day = text[:10]
    if len(day) == 10 and day[4] == "-" and day[7] == "-" and day.replace("-", "").isdigit():
        return day
    return "<assessment date, from the timeline>"


@dataclass(frozen=True)
class _ContainmentWindow:
    """The log-search window a containment step may print, and its frame.

    Attributes:
        when_sentence: The "it was performed against X at Y" sentence, with the
            clock the instant belongs to stated. Never names an instant the
            report cannot stand behind.
        search_window: What the following sentence tells the client to search.
        query_start: The ``StartTime`` boundary for the rendered query.
    """

    when_sentence: str
    search_window: str
    query_start: str


def _resolve_containment_window(
    extraction: CredentialStoreExtraction,
    *,
    host: str,
    generated_at: datetime | None,
) -> _ContainmentWindow:
    """Decide which instant, if any, the containment step may name.

    The scan steps the host clock to the DC for Kerberos and holds host NTP off
    for the rest of the run, so a stamp written after that point reads the DC's
    clock while the document is generated back on real time. The two are not
    comparable, and the DC's clock is the one its Security log is written in, so
    a stamp in that frame is the RIGHT instant to print: it gets a label, not a
    conversion.

    A stamp no record places in any clock is a different matter. If it sits
    after this document's own generation, the report cannot stand behind it, so
    the instant is dropped and the client is pointed at the assessment window in
    the timeline instead. Naming a moment that has not happened sends them to an
    empty search, and the step that follows would then read their empty result
    as a verdict about their auditing.
    """
    if generated_at is None:
        generated_at = datetime.now(timezone.utc)
    stamp = extraction.observed_at
    timeline = "the assessment window recorded in this report's timeline"
    fallback_start = "<assessment date, from the timeline>"
    if not stamp:
        return _ContainmentWindow(
            when_sentence=f"It was performed against {host}.",
            search_window=timeline,
            query_start=fallback_start,
        )

    frame = extraction.observed_at_frame
    if frame.comparable_to_generation and stamp_post_dates(stamp, generated_at):
        return _ContainmentWindow(
            when_sentence=(
                f"It was performed against {host}. This report does not name the "
                "instant: the only stamp recorded for the read sits after the "
                "moment this document was generated, so the two did not come "
                "from the same clock, and naming either of them would point you "
                "at a window that may never have existed."
            ),
            search_window=timeline,
            query_start=fallback_start,
        )

    when = f"It was performed against {host} at {format_instant_for_client(stamp)}"
    if frame.agrees_with_target:
        when += (
            ", on that host's own clock, which is the clock its Security log is "
            "written in."
        )
        span = clock_offset_phrase(frame.offset_seconds) if frame.stepped else ""
        if span:
            when += (
                f" The assessment host's clock was {span} away from it and was "
                "synchronised to it for the run, which is why the generation "
                "time on this report does not match that instant. The target's "
                "clock is the one to search by."
            )
    else:
        when += (
            ". That instant comes from the assessment host's clock, and this "
            f"report cannot confirm it agreed with {host}'s, so treat the day "
            "rather than the second as the boundary."
        )
    return _ContainmentWindow(
        when_sentence=when,
        search_window="that day",
        query_start=_log_window_day(stamp),
    )


def _custody_step(*, self_operated: bool, workspace_label: str) -> ObligationStep:
    """Return the custody step, scaled to who operated the assessment.

    Third party (the default, and the branch an UNKNOWN role takes): a copy of
    credential material left the client's estate on someone else's machine, so
    the client is owed a destruction confirmation while the engagement is still
    open.

    Self-operated: there is no third party to recover a copy from, so demanding
    one would invent an obligation. What the client needs instead is the facts
    that let them decide for themselves: where the copy sits, that nothing
    expires it, and the single question this report cannot answer for them.

    It states NO retention figure, and that is a decision rather than an
    omission. The engine's own expiry is a build-time PyArmor ``--expired``
    flag baked into the obfuscated runtime (``build_adscan.sh``), so it is not
    a value this code can read at render time. It also differs by deployment:
    the free proof-of-value appliance and a paid annual one are both operated
    by the client's own people, so any constant printed here would be a false
    statement to one of them about how long their own data stays usable.
    ``license.json`` is not a substitute either, since no code in this tree
    writes it and a hand-placed file would not carry the baked date.
    """
    if not self_operated:
        return ObligationStep(
            text=(
                "Put the custody of the copy on the record. The values were read "
                "over the network onto the assessment host and parsed there; what "
                "this deliverable keeps is the account list and the recovered "
                "hashes, not the stores themselves. Ask the assessment team for "
                "written confirmation that the working copy and every extracted "
                "hash file have been destroyed, and file that confirmation with "
                "this report. It is the record an auditor asks for, and the "
                "engagement is still open, which is the only point at which it is "
                "easy to obtain."
            )
        )

    workspace = workspace_label or "<workspace-name>"
    return ObligationStep(
        text=(
            "Record where the copy is held and decide how long you keep it. Your "
            "own team ran this assessment, so no outside party holds a copy of "
            "what it read. The values came over the network onto the host that "
            "ran it and were parsed there, and what stays on that host is the "
            f"workspace {workspace}, holding the account list and the recovered "
            "hashes rather than the stores themselves. On Linux that is "
            f"~/.adscan/workspaces/{workspace} and on Windows "
            f"%LOCALAPPDATA%\\ADscan\\workspaces\\{workspace}. A host that "
            "runs ADscan is deliberately kept out of the domain it assesses, "
            "which is why this report locates the copy by path and gives it no "
            "directory tier. That leaves you one question this report cannot "
            "answer from inside the directory: who can read that path today, "
            "whether it is carried into a backup, and the date on which the "
            "workspace is deleted. Nothing in it expires on its own, so a "
            "workspace left in place keeps authenticating material for as long "
            "as it sits there."
        ),
        commands=(
            "# On the host that ran the assessment, when the retention date arrives:",
            f"rm -rf ~/.adscan/workspaces/{workspace}",
            "Remove-Item -Recurse -Force "
            f'"$env:LOCALAPPDATA\\ADscan\\workspaces\\{workspace}"',
        ),
    )


def _extraction_obligation(
    extraction: CredentialStoreExtraction,
    *,
    environment_changes: Any,
    krbtgt_obligation_present: bool,
    self_operated: bool = False,
    workspace_label: str = "",
    generated_at: datetime | None = None,
) -> Obligation:
    """Build the custody obligation for one proven credential-store copy.

    The obligation this module was missing. A report could state that no
    directory object was modified, name the accounts to rotate, and never say
    that a copy of a credential store had left a domain controller. The client
    then reads "nothing was altered" as "nothing left", which are different
    facts, and the second one is the one with legal weight.

    Its claims are scoped to what the copy actually contained
    (:data:`SCOPE_DIRECTORY_DATABASE` versus
    :data:`SCOPE_HOST_CREDENTIAL_STORE`). krbtgt is named only when the
    directory database itself was taken; a run that read a host's registry
    stores is told what that reaches instead, which on a domain controller is
    still the whole domain and is stated as such.

    ``self_operated`` scales the ASK to who ran the assessment, because the one
    fact that holds in both deployment shapes is narrower than the obligation
    first written for it. What holds either way: credential material moved out
    of a domain controller's protected store onto a host that is not a domain
    controller, and nothing in the directory revokes a copy. What does not hold
    either way is custody. A consultancy engagement pulled that material onto a
    third party's machine and carried it away, so the client is owed a custody
    record and a destruction confirmation. An Enterprise appliance running
    inside the client's own environment, operated by their own staff, moved it
    between two hosts the client owns, and demanding destruction from a third
    party that does not exist overclaims exactly as much as staying silent
    underclaims.

    Self-operated therefore states what is OBSERVABLE (the path the copy sits
    at, and that nothing expires it) and hands the client the one question only
    they can answer. The host the assessment ran from holds no tier in the
    directory it assessed, and that is the CORRECT arrangement rather than a
    gap: the shipped appliance is deliberately not domain-joined, so the copy is
    described by location instead of by directory tier. The prose must never
    read as a limitation.

    What it must not do is guess at that host's protection. Disk encryption is a
    real property of the shipped appliance image, but no reliable signal in this
    tree says "I am the appliance" — there is no deployment marker, and sniffing
    the provisioned env bundle (``ADSCAN_CLIENT_NAME`` and siblings) as a proxy
    would rest a client-facing claim about disk encryption on a heuristic that
    one stray variable flips. So this branch claims nothing about encryption,
    and the encryption sentence waits on an explicit
    ``ADSCAN_DEPLOYMENT=appliance`` marker set by appliance provisioning with a
    predicate in ``adscan_core`` to gate it (tracked as follow-up).
    """
    host = extraction.host or "the domain controller"
    domain = extraction.domain or "the assessed domain"
    count = len(extraction.principals)
    determined, artifacts, manual = _host_artifact_counts(environment_changes)

    if extraction.took_whole_directory:
        title = (
            f"Record where the copy of the directory database taken from {host} "
            "is held"
            if self_operated
            else f"Account for the copy of the directory database taken from {host}"
        )
        proof = (
            f"This assessment read the Active Directory database of {domain} out of "
            f"{host} and parsed it off that controller. That database holds the "
            "password hash and the Kerberos keys of every account in the domain, "
            "the krbtgt account included. The accounts this report names for "
            "rotation are the ones it recorded, not the limit of what was read: "
            f"every account in {domain} had its credential material exposed."
        )
        rationale = (
            "Closing the route that allowed the read is a finding and it belongs "
            "on the roadmap. The copy is not a finding, and closing the route "
            "does not reach it. A copy does not expire, and nothing in the "
            "directory revokes one. Two things follow from it: the krbtgt reset "
            "below, without which a forged ticket survives every password change "
            "in the domain, and "
            + (
                "a decision about where that copy is held and when it goes away."
                if self_operated
                else "a written record of what happened to the copy."
            )
        )
    else:
        title = (
            f"Record where the credential material copied off {host} is held"
            if self_operated
            else f"Account for the credential material copied off {host}"
        )
        stores = (
            "the local account database and the LSA secrets, which hold the "
            "computer's own Kerberos key"
        )
        proof = (
            f"This assessment read the credential stores of {host} in {domain} and "
            f"parsed them away from that host: {stores}. "
        )
        if count:
            proof += (
                f"{count} {_plural(count, 'account')} came out of that read and "
                f"the rotation below names {'it' if count == 1 else 'them'}. "
            )
        if extraction.machine_accounts:
            proof += (
                "A domain controller's own key is not an ordinary machine "
                "password. It authenticates as a domain controller, and a domain "
                "controller is entitled to replicate the directory, so holding "
                f"that key is enough to read every password hash in {domain} "
                "without using any route in this report."
            )
        else:
            proof += (
                "Material read out of a host's credential stores keeps "
                "authenticating until the account it belongs to is given a new "
                "password."
            )
        rationale = (
            "This is containment rather than hardening, which is what separates "
            "it from the findings later in this report. Removing the privilege "
            "that permitted the read stops the next attacker and changes nothing "
            "about material that is already outside the directory. A copy does "
            "not expire, and closing the route it came through does not revoke it."
        )

    steps: list[ObligationStep] = []
    steps.append(
        _custody_step(self_operated=self_operated, workspace_label=workspace_label)
    )

    if not determined:
        steps.append(
            ObligationStep(
                text=(
                    "Check the host for what the read may have left behind. The "
                    "assessment's change ledger could not be read, so this report "
                    "does not state whether a file was written on "
                    f"{host}. Treat that as unverified: look for a saved registry "
                    "hive, a process dump or a volume snapshot created inside the "
                    "window in the next step, and remove anything you find. A "
                    "snapshot of the system volume carries the directory database "
                    "with it, so it is as sensitive as the database itself."
                ),
                commands=(
                    "# Run on the affected host, as an administrator:",
                    "vssadmin list shadows",
                    "Get-ChildItem -Path $env:windir\\Temp -File | "
                    "Sort-Object LastWriteTime -Descending | "
                    "Select-Object -First 20 Name, LastWriteTime, Length",
                ),
            )
        )
    elif artifacts:
        left = (
            (
                f"{manual} of them could not be removed automatically and is "
                "still on the host, holding credential material. "
                if manual == 1
                else f"{manual} of them could not be removed automatically and "
                "are still on the host, each holding credential material. "
            )
            if manual
            else "Each was deleted and the removal confirmed against the host. "
        )
        steps.append(
            ObligationStep(
                text=(
                    "Clear what the read left on the host. The change ledger "
                    f"records {artifacts} "
                    f"{_plural(artifacts, 'file')} written on assessed hosts to "
                    f"carry out techniques of this kind. {left}"
                    "The environment-modifications record in this report carries "
                    "each path and the command that deletes it. Delete them, then "
                    "confirm the path is gone rather than assuming the deletion "
                    "ran: the expected result is False."
                ),
                commands=(
                    "# Run on the affected host, as an administrator:",
                    "Test-Path '<path from the environment modifications record>'",
                    "vssadmin list shadows",
                ),
            )
        )
    else:
        steps.append(
            ObligationStep(
                text=(
                    "Confirm the host carries no leftover copy. The assessment's "
                    "change ledger records no file written on any assessed host, "
                    f"which means the read on {host} left nothing to delete. "
                    "Verify that against the host itself rather than taking the "
                    "record on trust, and include the system volume's snapshots: "
                    "a snapshot carries the directory database with it, so it is "
                    "as sensitive as the database."
                ),
                commands=(
                    "# Run on the affected host, as an administrator:",
                    "vssadmin list shadows",
                    "Get-ChildItem -Path $env:windir\\Temp -File | "
                    "Sort-Object LastWriteTime -Descending | "
                    "Select-Object -First 20 Name, LastWriteTime, Length",
                ),
            )
        )

    window = _resolve_containment_window(
        extraction, host=host, generated_at=generated_at
    )
    target = extraction.host or "<domain-controller>"
    steps.append(
        ObligationStep(
            text=(
                "Scope the read in your own records, so you can tell this "
                "assessment apart from anyone else who may have done the same "
                f"thing. {window.when_sentence} Search {window.search_window} "
                "for event 4672 on the privileged logon, 4663 on access to the "
                "registry hives and the directory database, and 4624 for the "
                "logon that carried it. The same pattern on any other date was "
                "not this assessment, and that is the comparison worth making. "
                "An empty result does not settle the question on its own: it is "
                "what you would see if object-access auditing is off on that "
                "host, and also what you would see if the window searched is not "
                "the one the read landed in. The second command answers the "
                "first of those, and the answer is worth having either way, "
                "because without that auditing the host keeps no record of a "
                "read like this one."
            ),
            commands=(
                f"Get-WinEvent -ComputerName {target} "
                "-FilterHashtable @{LogName='Security'; Id=4672,4663,4624; "
                f"StartTime=(Get-Date '{window.query_start}')" + "} | "
                "Select-Object TimeCreated, Id, UserId | Sort-Object TimeCreated",
                "auditpol /get /subcategory:'Kernel Object','Registry'",
            ),
        )
    )

    if extraction.took_whole_directory:
        steps.append(
            ObligationStep(
                text=(
                    "Plan the rotation against the whole account population, not "
                    "only the accounts this report names. Order it by what each "
                    "account can reach, set a deadline, and verify it afterwards: "
                    f"every enabled account in {domain} should show a "
                    "pwdLastSet later than the date of this assessment, and any "
                    "that does not still holds a password this assessment read."
                ),
                commands=(
                    "Get-ADUser -Filter 'Enabled -eq $true' "
                    "-Properties PasswordLastSet, MemberOf -Server <a-domain-controller> | "
                    "Select-Object SamAccountName, PasswordLastSet | "
                    "Sort-Object PasswordLastSet",
                    "Get-ADComputer -Filter 'Enabled -eq $true' "
                    "-Properties PasswordLastSet | "
                    "Select-Object Name, PasswordLastSet | Sort-Object PasswordLastSet",
                ),
            )
        )

    caveat = (
        "Rotating the material changes what authenticates from now on. It does "
        "not answer whether anyone else used the copy while it existed, and only "
        "your own logs hold that answer. The window to examine is the one above."
    )
    if extraction.took_whole_directory and not krbtgt_obligation_present:
        caveat += (
            " The krbtgt reset belongs to this as well. A forged ticket does not "
            "care who forged it: while that key material exists anywhere, in the "
            "working copy, in a backup of it, on a volume that is restored or a "
            "host that is rebuilt and handed on, it can mint a ticket this domain "
            "accepts, and no password change made afterwards closes that."
            if self_operated
            else " The krbtgt reset is part of this: until it completes twice, a "
            "ticket forged from the key in that copy outlives every password "
            "change in the domain."
        )

    return Obligation(
        key=OBLIGATION_EXTRACTION,
        title=title,
        proof=proof,
        rationale=rationale,
        steps=tuple(steps),
        caveat=caveat,
        domains=(extraction.domain,) if extraction.domain else (),
        accounts=extraction.principals,
        containment_kind=(
            "krbtgt" if extraction.took_whole_directory else "credential"
        ),
    )


def _krbtgt_obligation(domains: Sequence[str]) -> Obligation:
    """Build the krbtgt reset obligation for the domains that proved it."""
    scope = _domains_phrase(domains)
    return Obligation(
        key=OBLIGATION_KRBTGT,
        title="Reset the krbtgt password twice, with replication in between",
        proof=(
            f"This assessment recovered the krbtgt account's key material in {scope}. "
            "That key signs every Kerberos ticket the domain issues, so anyone holding "
            "it can mint a ticket for any account, including accounts that do not "
            "exist, and every domain controller will accept it."
        ),
        rationale=(
            "Reset it twice. A domain controller keeps the previous krbtgt key and "
            "keeps honouring tickets signed with it, which is deliberate: it stops a "
            "single reset from cutting off every session in the domain at once. It "
            "also means one reset leaves forged tickets working. The second reset is "
            "what removes the old key from circulation, and it only works if the first "
            "one has replicated everywhere before you run it."
        ),
        steps=(
            ObligationStep(
                text=(
                    "Reset the password once. The value you type is discarded and the "
                    "domain replaces it with a random key, so any long random string "
                    "will do."
                ),
                commands=(
                    "Set-ADAccountPassword -Identity krbtgt -Reset "
                    "-NewPassword (Read-Host -AsSecureString 'New krbtgt password')",
                ),
            ),
            ObligationStep(
                text=(
                    "Confirm the reset has reached every domain controller before you "
                    "go further. Every controller must report the same new pwdLastSet."
                ),
                commands=(
                    "repadmin /replsummary",
                    "Get-ADDomainController -Filter * | ForEach-Object { "
                    "Get-ADUser krbtgt -Server $_.HostName -Properties pwdLastSet | "
                    "Select-Object @{n='DC';e={$_.PSComputerName}}, "
                    "@{n='pwdLastSet';e={[datetime]::FromFileTime($_.pwdLastSet)}} }",
                ),
            ),
            ObligationStep(
                text=(
                    "Wait out the maximum ticket lifetime, ten hours under the default "
                    "Kerberos policy, so tickets issued under the old key have expired "
                    "on their own. Resetting twice inside that window forces every "
                    "session in the domain to re-authenticate at once, which is what "
                    "turns a contained incident into an outage."
                ),
            ),
            ObligationStep(
                text="Reset the password a second time, exactly as in step 1.",
                commands=(
                    "Set-ADAccountPassword -Identity krbtgt -Reset "
                    "-NewPassword (Read-Host -AsSecureString 'New krbtgt password')",
                ),
            ),
            ObligationStep(
                text=(
                    "If the forest holds read-only domain controllers, each one has its "
                    "own krbtgt account (krbtgt_<number>). Reset those on the same "
                    "schedule; they are separate keys and the two resets above do not "
                    "touch them."
                ),
                commands=(
                    "Get-ADUser -LDAPFilter '(samAccountName=krbtgt_*)' "
                    "-Properties pwdLastSet",
                ),
            ),
        ),
        caveat=(
            "Tickets already issued stay valid until they expire, so plan the two "
            "resets alongside the credential rotation below rather than treating "
            "either as an instant cut-off."
        ),
        domains=tuple(domains),
        containment_kind="krbtgt",
    )


def _credential_obligation(
    *,
    domains: Sequence[str],
    principals: Sequence[str],
    machine_accounts: Sequence[str],
    full_replication_domains: Sequence[str],
    guest_accounts: Sequence[str] = (),
    krbtgt_obligation_present: bool = False,
) -> Obligation:
    """Build the credential-rotation obligation for the recovered accounts.

    The built-in Guest (``guest_accounts``) is carved out of the rotate list and
    gets its own "disable, do not rotate" step: its blank anonymous logon is not a
    rotatable secret, so telling the client to reset its password would be wrong.

    ``krbtgt_obligation_present`` exists because the machine-account step used to
    send the reader to "the same change window as the krbtgt resets"
    unconditionally, including in a report that carried no krbtgt reset anywhere.
    A client reading that goes looking for a procedure the document does not
    contain, and the sentence that was meant to convey urgency instead reads as
    an omission. The clause is now only written when the procedure it points at
    is actually in the document.
    """
    count = len(principals)
    if count:
        proof = (
            f"The assessment recovered credential material for {count} "
            f"{_plural(count, 'account')} in {_domains_phrase(domains)}: "
            f"{_join_names(principals)}. Each is compromised, whatever was "
            "recovered for it: a password hash and a Kerberos key authenticate as "
            "the account just as a password does."
        )
    else:
        # Only the built-in Guest was reached — the proof is about disabling it,
        # not rotating a secret that does not exist.
        proof = (
            f"The assessment reached {_domains_phrase(domains)} through the "
            "built-in Guest account, which authenticated with a blank, anonymous "
            "logon rather than a recovered secret."
        )
    if count and full_replication_domains:
        proof += (
            " A full replication of the directory database also completed in "
            f"{_domains_phrase(full_replication_domains)}, which means every "
            "account's password hash in that domain was exposed, not only the "
            "accounts named above. Treat the list as the confirmed minimum."
        )

    steps: list[ObligationStep] = []
    if count:
        steps.extend(
            (
                ObligationStep(
                    text=(
                        "Reset the password on every account named above. Disabling, "
                        "renaming or moving an account does not help: the recovered "
                        "material is derived from the password, so only a password "
                        "change invalidates it."
                    ),
                    commands=(
                        "Set-ADAccountPassword -Identity <account> -Reset "
                        "-NewPassword (Read-Host -AsSecureString 'New password')",
                        "Set-ADUser -Identity <account> -ChangePasswordAtLogon $true",
                    ),
                ),
                ObligationStep(
                    text=(
                        "Handle the service accounts first and separately. An account "
                        "with a registered service principal name is running something, "
                        "and resetting it without updating wherever that service stores "
                        "the password takes the service down. Find them, schedule the "
                        "change, update the service configuration and the reset together."
                    ),
                    commands=(
                        "Get-ADUser -LDAPFilter '(servicePrincipalName=*)' "
                        "-Properties servicePrincipalName, PasswordLastSet | "
                        "Select-Object SamAccountName, PasswordLastSet, servicePrincipalName",
                    ),
                ),
                ObligationStep(
                    text=(
                        "Where a service account can move to a group managed service "
                        "account, move it. The directory then rotates the password on "
                        "its own every thirty days and this class of exposure stops "
                        "recurring."
                    ),
                    commands=(
                        "New-ADServiceAccount -Name <gmsa-name> -DNSHostName <service-host-fqdn> "
                        "-PrincipalsAllowedToRetrieveManagedPassword '<HOST$>'",
                        "Install-ADServiceAccount -Identity <gmsa-name>",
                    ),
                ),
            )
        )

    if guest_accounts:
        steps.append(
            ObligationStep(
                text=(
                    f"The built-in Guest account ({_join_names(guest_accounts)}) "
                    "authenticated with a blank, anonymous logon rather than a "
                    "recovered secret, so there is no password to rotate. Disable it "
                    "instead (the fix the corresponding finding already prescribes) "
                    "and confirm it stays disabled."
                ),
                commands=(
                    "Disable-ADAccount -Identity Guest",
                    "Get-ADUser -Identity Guest -Properties Enabled | "
                    "Select-Object SamAccountName, Enabled",
                ),
            )
        )

    if machine_accounts:
        machine_count = len(machine_accounts)
        steps.append(
            ObligationStep(
                text=(
                    f"{machine_count} of these "
                    f"{'is a' if machine_count == 1 else 'are'} "
                    f"machine {_plural(machine_count, 'account')} "
                    f"({_join_names(machine_accounts)}). A machine account key also "
                    "unwraps material protected by that computer, so rotate it from "
                    "the host itself rather than from the directory. If the host is "
                    "a domain controller, the account is part of the identity control "
                    "plane: it authenticates as a controller and can therefore "
                    "replicate the directory, so treat the rotation as a Tier 0 "
                    "change and schedule it with the other privileged rotations"
                    + (
                        ", in the same change window as the krbtgt resets above."
                        if krbtgt_obligation_present
                        else " rather than in the routine batch."
                    )
                ),
                commands=(
                    "# Run on the affected host, as an administrator:",
                    "Reset-ComputerMachinePassword -Server <a-domain-controller>",
                    "Test-ComputerSecureChannel -Repair -Server <a-domain-controller>",
                ),
            )
        )

    if count:
        steps.append(
            ObligationStep(
                text=(
                    "Check whether any of these passwords is in use anywhere else: a "
                    "local administrator account, a scheduled task, an application "
                    "configuration file, a second directory. A recovered password is "
                    "compromised everywhere it was ever used, not only where it was "
                    "found."
                ),
            )
        )

    title = (
        "Treat every recovered credential as compromised and rotate it"
        if count
        else "Disable the built-in Guest account reached during the assessment"
    )
    return Obligation(
        key=OBLIGATION_CREDENTIALS,
        title=title,
        proof=proof,
        rationale=(
            "How each account was reached is a separate question from what to do "
            "about it. Closing the route stops the next attacker; it does nothing "
            "about the credential itself, which is already outside your control and "
            "has to be replaced."
        ),
        steps=tuple(steps),
        caveat=(
            (
                "Rotate in order of privilege, not alphabetically: an account that "
                "can reach a domain controller matters more than one that cannot, "
                "and a partial rotation that leaves the privileged accounts for last "
                "leaves the compromise intact."
            )
            if count
            else ""
        ),
        domains=tuple(domains),
        accounts=tuple(principals),
        containment_kind="credential",
    )


def _certificate_obligation(
    certificates: Sequence[IssuedCertificate],
) -> Obligation:
    """Build the certificate-revocation obligation."""
    count = len(certificates)
    identities = [c.principal for c in certificates if c.principal]
    expiries = sorted({c.not_after for c in certificates if c.not_after})

    proof = (
        f"Your certification authority issued {count} "
        f"{_plural(count, 'certificate')} during this assessment"
    )
    if identities:
        proof += f", authenticating as {_join_names(sorted(set(identities)), cap=4)}"
    if expiries:
        proof += f", valid until {expiries[-1]}"
    proof += (
        ". A certificate outlives the engagement by design: it keeps authenticating "
        "until it expires or is revoked, and nothing in the directory takes it out "
        "of service."
    )

    return Obligation(
        key=OBLIGATION_CERTIFICATE,
        title="Revoke the certificate your CA issued during the assessment",
        proof=proof,
        rationale=(
            "Revoking needs certificate-manager rights on the issuing CA, which this "
            "assessment did not hold, so it is the one action only your team can "
            "complete."
        ),
        steps=(
            ObligationStep(
                text=(
                    "Revoke each certificate on the issuing CA, as a member of its "
                    "Certificate Managers group: locate the record by request ID, "
                    "revoke it with reason code 1 (key compromise) because the private key "
                    "was generated outside your control, publish a fresh revocation "
                    "list, then confirm the record's disposition reads 21."
                ),
            ),
            ObligationStep(
                text=(
                    "Close the template that allowed the certificate to be requested "
                    "with someone else's identity. Revoking one certificate without "
                    "fixing the template means the next request succeeds the same way."
                ),
            ),
        ),
        caveat=(
            "Revocation only stops future authentication. A Kerberos ticket already "
            "obtained with the certificate stays valid for its lifetime, and if the "
            "certificate carried a privileged identity, that account's password has "
            "to be reset once the revocation is confirmed."
        ),
        domains=tuple(sorted({c.domain for c in certificates if c.domain})),
        containment_kind="certificate",
        runbook=tuple(
            line
            for cert in certificates
            for line in cert.remediation.splitlines()
            if line.strip()
        ),
    )


def build_post_compromise_obligations(
    *,
    credential_store: Mapping[str, Any] | None,
    environment_changes: Mapping[str, Any] | None = None,
    domain_order: Iterable[str] | None = None,
    self_operated: bool = False,
    workspace_label: str = "",
    generated_at: datetime | None = None,
) -> tuple[Obligation, ...]:
    """Derive the obligations this engagement's PROVEN outcomes impose.

    Pure: every input is supplied, nothing is read from disk. ``None`` for
    either store therefore means "there is none" — reading a workspace is
    :func:`load_post_compromise_obligations`'s job, and that is where ``None``
    instead means "resolve it for me".

    Args:
        credential_store: ``{domain: domains_data[<domain>]}`` from the workspace
            ``variables.json`` (see :func:`load_workspace_credential_store`).
            Domain keys are matched case-insensitively.
        environment_changes: The resolved ledger block ``{summary, changes}``.
        domain_order: Preferred domain ordering for the prose. Domains absent
            from this sequence are appended alphabetically.
        self_operated: True when the client's OWN people operated the
            assessment inside their own environment, which scales the custody
            ASK (see :func:`_custody_step`). **The default is False, the
            third-party framing, and that is deliberate: it is also the branch
            an UNKNOWN operator role takes.** Asking a self-run client for a
            custody record they do not need is merely excessive; dropping it on
            a real consultancy engagement loses an obligation that was genuinely
            owed. Do not "simplify" this default to follow the OS or the CTA
            lane: :func:`~adscan_core.operator_role.resolve_cta_lane` resolves an
            unknown role on Windows into the buyer lane, which would hand the
            self-run text to an engagement on an inference.
        workspace_label: Name of the workspace holding the recovered material,
            for the self-operated branch's location sentence. Degrades to an
            obvious fill-in token rather than a fabricated path.
        generated_at: When the document carrying these obligations is being
            generated. Defaults to now, which is correct because this runs at
            render time, and is injectable so a test can pin it. No containment
            instruction may name an instant after it unless the instant is
            known to come from a different clock: a client sent to search a
            moment that has not happened finds nothing, and an empty search is
            exactly what the step that follows must not read as a verdict.

    Returns:
        The obligations, in the order the client should act on them. Empty when
        the engagement proved none of them — which is the point: a scan that
        recovered nothing must not tell anyone to reset krbtgt.
    """
    if generated_at is None:
        generated_at = datetime.now(timezone.utc)
    store: dict[str, Any] = {}
    if isinstance(credential_store, Mapping):
        store = {
            str(name).strip(): payload
            for name, payload in credential_store.items()
            if isinstance(payload, Mapping) and str(name).strip()
        }

    # The caller's preferred order first (matched case-insensitively, since the
    # report and the workspace do not always agree on casing), then the rest
    # alphabetically. Names are printed as the workspace recorded them.
    preferred = [str(d).strip().lower() for d in (domain_order or []) if str(d).strip()]
    by_lower = {name.lower(): name for name in store}
    ordered_keys = [by_lower[key] for key in preferred if key in by_lower]
    ordered_keys += sorted(
        (name for name in store if name.lower() not in set(preferred)), key=str.lower
    )

    krbtgt_domains: list[str] = []
    credential_domains: list[str] = []
    replicated_domains: list[str] = []
    principals: list[str] = []
    machine_accounts: list[str] = []
    guest_accounts: list[str] = []
    extractions: list[CredentialStoreExtraction] = []

    for display in ordered_keys:
        domain_data = store.get(display)
        names = recovered_principals(domain_data)
        replicated = _directory_replicated(domain_data)
        if replicated:
            replicated_domains.append(display)
        # A copy of a credential store that left a host is its own consequence,
        # disclosed on what the copy CONTAINED. The directory-database scope also
        # earns the krbtgt reset on its own: the database file carries that key
        # whether or not the credential store happened to keep it, so a report
        # that proves the file was parsed must carry the reset.
        domain_extractions = credential_store_extractions(domain_data, display)
        extractions.extend(domain_extractions)
        took_directory = any(e.took_whole_directory for e in domain_extractions)
        if (
            any(n.strip().lower() == KRBTGT_PRINCIPAL for n in names)
            or replicated
            or took_directory
        ):
            krbtgt_domains.append(display)
        # krbtgt carries its own obligation; listing it again under "rotate
        # these accounts" would read as a second, weaker instruction. A blank /
        # anonymous logon (the built-in Guest, the anonymous session) is likewise
        # carved out of the rotate list: it has no secret to rotate, so it gets
        # its own "disable, do not rotate" step. The carve-out keys on the
        # credential-representation SSOT (the SAME fact the provenance table's
        # credential-type column uses), with the built-in-Guest NAME kept as a
        # backstop for a store that recorded the account without its origin slug.
        blank_anon = _blank_anonymous_principal_names(domain_data)
        disable_not_rotate = {
            n for n in names if n.strip().lower() in blank_anon or _is_builtin_guest(n)
        }
        rotatable = [
            n
            for n in names
            if n.strip().lower() != KRBTGT_PRINCIPAL and n not in disable_not_rotate
        ]
        guests_here = [n for n in names if n in disable_not_rotate]
        for name in guests_here:
            if name not in guest_accounts:
                guest_accounts.append(name)
        if rotatable or guests_here:
            credential_domains.append(display)
        for name in rotatable:
            if name not in principals:
                principals.append(name)
            if is_machine_account(name) and name not in machine_accounts:
                machine_accounts.append(name)

    obligations: list[Obligation] = []
    # The custody disclosure leads. It is the statement that earns every row
    # beneath it ("a copy of this left your control"), so a reader who meets the
    # rotation first has been handed the instruction before the reason. Its
    # ``containment_kind`` still places it on the shared time-criticality ladder
    # for a renderer that groups by rung.
    krbtgt_present = bool(krbtgt_domains)
    for extraction in extractions:
        obligations.append(
            _extraction_obligation(
                extraction,
                environment_changes=environment_changes,
                krbtgt_obligation_present=krbtgt_present,
                self_operated=self_operated,
                workspace_label=workspace_label,
                generated_at=generated_at,
            )
        )
    if krbtgt_domains:
        obligations.append(_krbtgt_obligation(krbtgt_domains))
    if principals or guest_accounts:
        obligations.append(
            _credential_obligation(
                domains=credential_domains,
                principals=principals,
                machine_accounts=machine_accounts,
                guest_accounts=guest_accounts,
                full_replication_domains=replicated_domains,
                krbtgt_obligation_present=krbtgt_present,
            )
        )
    certificates = _issued_certificates(environment_changes)
    if certificates:
        obligations.append(_certificate_obligation(certificates))
    return tuple(obligations)


def _resolve_environment_changes_block(workspace_dir: Any) -> Mapping[str, Any] | None:
    """Read the change ledger from a workspace through the ledger SSOT.

    Delegates to
    :func:`~adscan_internal.services.environment_change_ledger.resolve_environment_changes`
    rather than reading ``environment_changes.json`` here, so this module
    inherits its source ordering and its undetermined/empty distinction instead
    of growing a second, subtly different reader.

    Returns:
        The ``{summary, changes, determined}`` block, or ``None`` when no ledger
        could be read.
    """
    from adscan_internal.services.environment_change_ledger import (  # noqa: PLC0415
        resolve_environment_changes,
    )

    return resolve_environment_changes(workspace_dir=str(workspace_dir)).block


def _resolve_self_operated() -> bool:
    """Return True only when a BUYER role is on record for this install.

    Reads the operator-role SSOT
    (:func:`~adscan_core.operator_role.operator_runs_own_estate`, which reads
    :func:`~adscan_core.operator_role.get_operator_role`) and collapses its
    three-valued answer in the conservative direction: an UNKNOWN role resolves
    to False, the third-party framing.

    Deliberately NOT :func:`~adscan_core.operator_role.resolve_cta_lane`. That
    resolver turns an unknown role on a Windows host into the buyer lane, which
    is the right guess for a commercial link and the wrong one here: it would
    hand the self-run location text to a consultancy engagement on an
    inference about the operating system, and the obligation it drops on the
    way is the one with legal weight. Never raises.
    """
    try:
        from adscan_core.operator_role import operator_runs_own_estate  # noqa: PLC0415

        return operator_runs_own_estate() is True
    except Exception:  # noqa: BLE001 — a report must ship
        return False


def _workspace_label(workspace_dir: Any) -> str:
    """Return the workspace's own directory name, for the location sentence."""
    try:
        return os.path.basename(str(workspace_dir).rstrip("/\\")).strip()
    except Exception:  # noqa: BLE001
        return ""


def load_post_compromise_obligations(
    workspace_dir: Any,
    *,
    environment_changes: Mapping[str, Any] | _NoEnvironmentChanges | None = None,
    domain_order: Iterable[str] | None = None,
) -> tuple[Obligation, ...]:
    """Read the workspace and derive its obligations. Never raises.

    The one entry point both tiers call, so a report and the free exposure
    report state the same obligations from the same proof. Everything it needs
    is resolved from ``workspace_dir`` — the credential store AND the change
    ledger — so passing the workspace alone is sufficient and complete.

    Args:
        workspace_dir: Workspace root holding ``variables.json`` and the change
            ledger.
        environment_changes: ``None`` (the default) resolves the ledger from the
            workspace. A caller holding a fresher block — the live session
            ledger, or the block already attached to ``technical_report.json`` —
            passes it and it wins. Pass :data:`NO_ENVIRONMENT_CHANGES` to state
            that no ledger should be considered at all.
        domain_order: Preferred domain ordering for the prose.

    Returns:
        The derived obligations; empty on any read failure.

    Who operated the assessment is resolved here rather than asked of the
    caller, so both tiers inherit the same answer from the same SSOT and
    neither has to know the rule. It comes from the persisted operator role;
    unknown takes the conservative third-party branch, whatever the host OS.
    """
    try:
        if environment_changes is NO_ENVIRONMENT_CHANGES:
            block: Mapping[str, Any] | None = None
        elif environment_changes is None:
            block = _resolve_environment_changes_block(workspace_dir)
        else:
            block = environment_changes  # type: ignore[assignment]
        return build_post_compromise_obligations(
            credential_store=load_workspace_credential_store(workspace_dir),
            environment_changes=block,
            domain_order=domain_order,
            self_operated=_resolve_self_operated(),
            workspace_label=_workspace_label(workspace_dir),
        )
    except Exception:  # noqa: BLE001 — a report must ship
        return ()


def obligation_to_dict(obligation: Obligation) -> dict[str, Any]:
    """Project one obligation into the plain mapping a template renders."""
    return {
        "key": obligation.key,
        "title": obligation.title,
        "proof": obligation.proof,
        "rationale": obligation.rationale,
        "caveat": obligation.caveat,
        "domains": list(obligation.domains),
        "accounts": list(obligation.accounts),
        "runbook": list(obligation.runbook),
        "containment_kind": obligation.containment_kind,
        "steps": [
            {"text": step.text, "commands": list(step.commands)}
            for step in obligation.steps
        ],
    }


def obligations_to_dicts(
    obligations: Iterable[Obligation],
) -> list[dict[str, Any]]:
    """Project obligations into the render shape both templates consume."""
    return [obligation_to_dict(o) for o in obligations]
