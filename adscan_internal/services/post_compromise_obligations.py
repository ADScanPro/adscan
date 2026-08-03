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
from typing import Any, Iterable, Mapping, Sequence

from adscan_internal.principal_utils import is_machine_account
from adscan_internal.services import cleanup_taxonomy as _tax
from adscan_internal.services.session_compromise_state_service import (
    NON_COMPROMISE_ORIGINS,
)

__all__ = [
    "CERTIFICATE_CHANGE_KINDS",
    "KRBTGT_PRINCIPAL",
    "NO_ENVIRONMENT_CHANGES",
    "IssuedCertificate",
    "Obligation",
    "ObligationStep",
    "build_post_compromise_obligations",
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

#: Ledger change kinds that leave a certificate able to authenticate after the
#: engagement ends. Both are sourced from the cleanup taxonomy SSOT.
CERTIFICATE_CHANGE_KINDS: frozenset[str] = frozenset(
    {_tax.KIND_ISSUED_CERTIFICATE, _tax.KIND_FORGED_CERTIFICATE}
)

#: Obligation identifiers, stable so a renderer can style or order them.
OBLIGATION_KRBTGT = "krbtgt_reset"
OBLIGATION_CREDENTIALS = "credential_rotation"
OBLIGATION_CERTIFICATE = "certificate_revocation"


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


def _directory_replicated(domain_store: Any) -> bool:
    """True when a full replication of the directory database completed.

    Marker written only after a successful "replicate everything" run, so it is
    proof that every account's password hash in the domain was exposed — not
    only the ones the credential store kept.
    """
    if not isinstance(domain_store, Mapping):
        return False
    return bool(domain_store.get("dcsync_all_done"))


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


def _krbtgt_obligation(domains: Sequence[str]) -> Obligation:
    """Build the krbtgt reset obligation for the domains that proved it."""
    scope = _domains_phrase(domains)
    return Obligation(
        key=OBLIGATION_KRBTGT,
        title="Reset the krbtgt password twice, with replication in between",
        proof=(
            f"This assessment recovered the krbtgt account's key material in {scope}. "
            "That key signs every Kerberos ticket the domain issues, so anyone holding "
            "it can mint a ticket for any account — including accounts that do not "
            "exist — and every domain controller will accept it."
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
                    "Reset the password once. The value you type is discarded — the "
                    "domain replaces it with a random key — so any long random string "
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
                    "Wait out the maximum ticket lifetime — ten hours under the default "
                    "Kerberos policy — so tickets issued under the old key have expired "
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
    )


def _credential_obligation(
    *,
    domains: Sequence[str],
    principals: Sequence[str],
    machine_accounts: Sequence[str],
    full_replication_domains: Sequence[str],
) -> Obligation:
    """Build the credential-rotation obligation for the recovered accounts."""
    count = len(principals)
    proof = (
        f"The assessment recovered credential material for {count} "
        f"{_plural(count, 'account')} in {_domains_phrase(domains)}: "
        f"{_join_names(principals)}. Each is compromised, whatever was recovered "
        "for it — a password hash and a Kerberos key authenticate as the account "
        "just as a password does."
    )
    if full_replication_domains:
        proof += (
            " A full replication of the directory database also completed in "
            f"{_domains_phrase(full_replication_domains)}, which means every "
            "account's password hash in that domain was exposed, not only the "
            "accounts named above. Treat the list as the confirmed minimum."
        )

    steps: list[ObligationStep] = [
        ObligationStep(
            text=(
                "Reset the password on every account named above. Disabling, "
                "renaming or moving an account does not help: the recovered "
                "material is derived from the password, so only a password change "
                "invalidates it."
            ),
            commands=(
                "Set-ADAccountPassword -Identity <account> -Reset "
                "-NewPassword (Read-Host -AsSecureString 'New password')",
                "Set-ADUser -Identity <account> -ChangePasswordAtLogon $true",
            ),
        ),
        ObligationStep(
            text=(
                "Handle the service accounts first and separately. An account with "
                "a registered service principal name is running something, and "
                "resetting it without updating wherever that service stores the "
                "password takes the service down. Find them, schedule the change, "
                "update the service configuration and the reset together."
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
                "account, move it. The directory then rotates the password on its "
                "own every thirty days and this class of exposure stops recurring."
            ),
            commands=(
                "New-ADServiceAccount -Name <gmsa-name> -DNSHostName <service-host-fqdn> "
                "-PrincipalsAllowedToRetrieveManagedPassword '<HOST$>'",
                "Install-ADServiceAccount -Identity <gmsa-name>",
            ),
        ),
    ]

    if machine_accounts:
        machine_count = len(machine_accounts)
        steps.append(
            ObligationStep(
                text=(
                    f"{machine_count} of these are machine {_plural(machine_count, 'account')} "
                    f"({_join_names(machine_accounts)}). A machine account key also "
                    "unwraps material protected by that computer, so rotate it from "
                    "the host itself rather than from the directory. If the host is "
                    "a domain controller, the account is part of the identity control "
                    "plane and the rotation belongs in the same change window as the "
                    "krbtgt resets."
                ),
                commands=(
                    "# Run on the affected host, as an administrator:",
                    "Reset-ComputerMachinePassword -Server <a-domain-controller>",
                    "Test-ComputerSecureChannel -Repair -Server <a-domain-controller>",
                ),
            )
        )

    steps.append(
        ObligationStep(
            text=(
                "Check whether any of these passwords is in use anywhere else — a "
                "local administrator account, a scheduled task, an application "
                "configuration file, a second directory. A recovered password is "
                "compromised everywhere it was ever used, not only where it was found."
            ),
        )
    )

    return Obligation(
        key=OBLIGATION_CREDENTIALS,
        title="Treat every recovered credential as compromised and rotate it",
        proof=proof,
        rationale=(
            "How each account was reached is a separate question from what to do "
            "about it. Closing the route stops the next attacker; it does nothing "
            "about the credential itself, which is already outside your control and "
            "has to be replaced."
        ),
        steps=tuple(steps),
        caveat=(
            "Rotate in order of privilege, not alphabetically: an account that can "
            "reach a domain controller matters more than one that cannot, and a "
            "partial rotation that leaves the privileged accounts for last leaves "
            "the compromise intact."
        ),
        domains=tuple(domains),
        accounts=tuple(principals),
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
                    "revoke it with reason code 1 (key compromise) — the private key "
                    "was generated outside your control — publish a fresh revocation "
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

    Returns:
        The obligations, in the order the client should act on them. Empty when
        the engagement proved none of them — which is the point: a scan that
        recovered nothing must not tell anyone to reset krbtgt.
    """
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

    for display in ordered_keys:
        domain_data = store.get(display)
        names = recovered_principals(domain_data)
        replicated = _directory_replicated(domain_data)
        if replicated:
            replicated_domains.append(display)
        if any(n.strip().lower() == KRBTGT_PRINCIPAL for n in names) or replicated:
            krbtgt_domains.append(display)
        # krbtgt carries its own obligation; listing it again under "rotate
        # these accounts" would read as a second, weaker instruction.
        rotatable = [n for n in names if n.strip().lower() != KRBTGT_PRINCIPAL]
        if rotatable:
            credential_domains.append(display)
            for name in rotatable:
                if name not in principals:
                    principals.append(name)
                if is_machine_account(name) and name not in machine_accounts:
                    machine_accounts.append(name)

    obligations: list[Obligation] = []
    if krbtgt_domains:
        obligations.append(_krbtgt_obligation(krbtgt_domains))
    if principals:
        obligations.append(
            _credential_obligation(
                domains=credential_domains,
                principals=principals,
                machine_accounts=machine_accounts,
                full_replication_domains=replicated_domains,
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
