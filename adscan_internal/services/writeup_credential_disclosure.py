"""How a writeup discloses the secrets a run recovered, and where they live.

**The store is the unsanitized side; every document is the sanitized side.**
That is the whole principle here. A credential store holding cleartext is
correct and intended: the pentester needs the secrets ADscan recovered, the
same way impacket and nxc hand them over, and losing that information would
make the tool worse. Sanitization belongs at the OUTPUT boundary, which is the
reports, the web CTEM and telemetry. The writeup's defect was never that it
contained secrets; it was that a DOCUMENT (one built to leave the machine, with
publication framing on it) was behaving like a store.

So this module decides WHETHER the writeup prints a recovered secret. It never
decides where secrets are stored, it creates no store of its own, and it
proposes no change to what the existing ones keep. It REFERENCES them:

* The credential store at the workspace-root ``variables.json``
  (``domains_data.<domain>.credentials`` / ``.credentials_meta``) is where the
  recovered VALUES live, hashes and cleartext alike. It is the single source of
  truth for workspace state, so it is the path a document points at. The
  per-domain ``domains/<domain>/variables.json`` snapshot carries a flattened
  copy of the same keys, but its own contract calls it derived, write-only and
  routinely stale, so sending a reader there would be the same class of defect
  as pointing at a file that does not exist.
* ``<workspace>/domains/<domain>/inventory/dcsync_dump.json`` is the canonical
  per-account REGISTER (``samaccountname``, ``rid``, ``nt_hash``, ``is_blank``,
  ``is_machine_account`` and a value-free ``plaintext_recovered`` flag). It is
  schema-versioned and feeds the platform's DCSync Intelligence figures.
  :mod:`adscan_internal.services.dcsync_inventory_persistence` holds no
  plaintext there on purpose, and that guarantee is not ours to relax.

Do NOT point the ledger at ``domains/<domain>/cracking/``. That directory holds
what the cracking flow itself wrote, which on a run whose plaintext came from
an offline corpus lookup is a single file out of hundreds of recovered secrets,
so the pointer would resolve to a directory that exists and answers nothing.

**Two decisions, two opposite safe defaults.** They are resolved separately and
on purpose, because the protective side of each one points a different way:

* *Does the writeup print the secret VALUES?* Inline for a practice target, the
  count plus shape-masked exemplars for everything else. A CTF writeup is a
  teaching artifact whose content IS the cracked credential, and masking it
  guts the genre. A client engagement record carrying hundreds of cleartext
  employee passwords is a confidentiality incident the first time anyone
  forwards the file, and cleartext is the part that matters: an NT hash already
  lives in the client's own NTDS, while a reused employee password opens the
  VPN, the SaaS tenant and a personal mailbox. The cost of the two mistakes is
  not comparable, so an UNCLASSIFIED workspace masks, and the operator who
  wanted one complete file loses the seconds it takes to pass
  ``--full-credentials``.
* *Does the file carry blog publication framing?* Only a workspace classified
  as an ``audit`` clears it. ``draft: true`` and ``published: false`` are
  themselves a protection (Hugo and Jekyll both honour them, so a spine dropped
  into a site repository cannot go live by accident), and an engagement record
  does not need them because it is never going near a site repository. An
  unclassified workspace therefore KEEPS them.

The engagement type is never re-derived here: it comes from
:mod:`adscan_internal.services.compliance_scope`, the one reader of the
workspace's persisted ``variables.json`` ``type``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Protocol, Sequence

from adscan_core.interaction import env_truthy
from adscan_core.lab_context import normalize_workspace_type
from adscan_internal.services.compliance_scope import (
    AUDIT_ENGAGEMENT,
    CTF_ENGAGEMENT,
    resolve_engagement_type,
)

#: Disclosure modes. ``INLINE_FULL`` prints every recovered secret in the
#: writeup itself; ``MASKED_EXEMPLARS`` prints the count, a handful of rows with
#: each value replaced by its shape, and the path of the canonical register.
DISCLOSURE_INLINE_FULL = "inline_full"
DISCLOSURE_MASKED_EXEMPLARS = "masked_exemplars"

#: The operator's explicit opt-in to one complete, unmasked record. The flag
#: (``adscan writeup --full-credentials``) and this variable are the same
#: decision; the variable exists so the REPL verb and a non-interactive run can
#: take it without a flag. Forwarded into the container for free by the
#: launcher's wildcard ``ADSCAN_*`` rule.
FULL_CREDENTIALS_ENV = "ADSCAN_WRITEUP_FULL_CREDENTIALS"

#: How many rows the masked writeup shows. Enough to evidence the step that
#: recovered them (the krbtgt row proves a directory replication ran, a roasted
#: service account proves the roast landed); more than that is a data dump that
#: evidences nothing the count does not already carry.
EXEMPLAR_LIMIT = 4

#: The canonical per-account register, relative to the domain directory.
DCSYNC_REGISTER_RELPATH = ("inventory", "dcsync_dump.json")

#: The credential store: workspace-root ``variables.json``, the single source of
#: truth for workspace state (and so for the recovered values).
CREDENTIAL_STORE_RELPATH = "variables.json"

#: How the store's own keys are named to the reader, so a pointer at a large
#: JSON file says which part of it to open. Filled with the REAL domain, never
#: left as a ``<domain>`` token: an unfilled placeholder in a document is the
#: defect this module exists to stop, in miniature.
CREDENTIAL_STORE_KEYS_TEMPLATE = "domains_data.{domain}.credentials"

_HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")

_KRBTGT = "krbtgt"


class CredentialLike(Protocol):
    """The shape this module needs from a recovered-credential row.

    Structural rather than an import of ``writeup_spine.CredentialRow``: the
    spine consumes this module, so the dependency only runs one way.
    """

    principal: str
    secret_kind: str
    origin: Optional[str]
    value: str


# ── The two policy decisions ─────────────────────────────────────────────────


def full_credentials_requested(*, flag: Optional[bool] = None) -> bool:
    """Whether the operator explicitly asked for one complete, unmasked record.

    Args:
        flag: The command-line opt-in, when the caller has one. ``True`` wins
            outright; ``None``/``False`` falls through to the environment.
    """
    if flag:
        return True
    return env_truthy(FULL_CREDENTIALS_ENV)


def resolve_credential_disclosure(
    engagement_type: Optional[str],
    *,
    force_inline: bool = False,
) -> str:
    """Decide whether this writeup prints the recovered secret values.

    Only a workspace positively classified as a CTF discloses inline by
    default. See the module docstring for why an unclassified workspace masks
    rather than inheriting the CTF behaviour.
    """
    if force_inline:
        return DISCLOSURE_INLINE_FULL
    if normalize_workspace_type(engagement_type) == CTF_ENGAGEMENT:
        return DISCLOSURE_INLINE_FULL
    return DISCLOSURE_MASKED_EXEMPLARS


def writeup_is_publication_framed(engagement_type: Optional[str]) -> bool:
    """Whether the writeup carries blog publication framing.

    Only a workspace positively classified as an ``audit`` drops it. See the
    module docstring: the unpublishable frontmatter is a protection, so the
    safe default for an unclassified workspace is to keep it.
    """
    return normalize_workspace_type(engagement_type) != AUDIT_ENGAGEMENT


def resolve_writeup_engagement_type(
    *,
    shell: Any = None,
    workspace_dir: Any = None,
) -> Optional[str]:
    """Resolve the engagement type for a writeup, workspace first.

    Delegates to the compliance-scope SSOT twice rather than reading
    ``variables.json`` a second time: once against the workspace (the
    authoritative source, since the type is a property of the scan that
    produced the data) and, only when that workspace carries no
    classification, once against the live shell. The second consultation
    matters for a shell generating its own writeup before its variables have
    been saved; without it a CTF run would be masked as though unclassified.
    """
    persisted = resolve_engagement_type(workspace_dir=workspace_dir)
    if persisted:
        return persisted
    return resolve_engagement_type(shell=shell)


# ── Masking ──────────────────────────────────────────────────────────────────


def mask_secret_to_shape(value: Any) -> str:
    """Return the SHAPE of a secret: its length and whether it is hex.

    Deliberately not a prefix (the flag masker shows four characters so an
    author recognises their own capture; four characters of an employee
    password is four characters of an employee password). The shape is what a
    reader needs to read the row as evidence: a 32-hex value is a hash pulled
    from the directory, a 12-character value is a login credential.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    noun = "character" if len(text) == 1 else "characters"
    if _HEX_ONLY.match(text):
        return f"{len(text)} hex {noun}"
    return f"{len(text)} {noun}"


def select_exemplars(
    rows: Sequence[CredentialLike],
    *,
    limit: int = EXEMPLAR_LIMIT,
) -> tuple[CredentialLike, ...]:
    """Pick the rows that EVIDENCE the chain, deterministically.

    krbtgt first (its presence is the proof a directory replication ran), then
    rows whose provenance is recorded (an exemplar with no recovery technique
    is a sample rather than evidence), then the rest in workspace order. A
    ledger at or under the limit is returned whole and unreordered.
    """
    ordered = list(rows)
    if len(ordered) <= limit:
        return tuple(ordered)

    def rank(row: CredentialLike) -> int:
        if str(getattr(row, "principal", "") or "").strip().lower() == _KRBTGT:
            return 0
        return 1 if getattr(row, "origin", None) else 2

    return tuple(sorted(ordered, key=rank)[:limit])


# ── Pointing at the stores that already exist ────────────────────────────────


@dataclass(frozen=True)
class CredentialStorePointers:
    """Where a masked ledger sends the reader for what it withheld.

    Two DIFFERENT artifacts, so they are carried as named fields rather than an
    unlabelled list of paths: one holds the recovered VALUES, the other is a
    value-free per-account register. Telling the reader which is which is the
    point of the pointer.
    """

    values_path: Optional[str] = None
    #: The store's own keys, with the real domain already substituted, so the
    #: reader is told which part of a large JSON file to open.
    values_keys: Optional[str] = None
    register_path: Optional[str] = None

    @property
    def resolved(self) -> bool:
        """Whether anything at all could be pointed at."""
        return bool(self.values_path or self.register_path)


def credential_store_pointers(
    workspace_dir: Any,
    *,
    domains_dir: str = "domains",
    domain: str,
) -> CredentialStorePointers:
    """Resolve the workspace-relative paths of the stores that EXIST.

    Existence is checked rather than assumed: a writeup that points at a file
    which is not there is worse than one that points nowhere, because the
    reader goes looking and finds nothing. An artifact that is absent is simply
    not named.
    """
    root = Path(str(workspace_dir or "."))
    domain_root = Path(str(domains_dir or "domains")) / str(domain or "")

    values_path: Optional[str] = None
    values_keys: Optional[str] = None
    store = Path(CREDENTIAL_STORE_RELPATH)
    if (root / store).is_file():
        values_path = store.as_posix()
        if str(domain or "").strip():
            values_keys = CREDENTIAL_STORE_KEYS_TEMPLATE.format(
                domain=str(domain).strip()
            )

    register_path: Optional[str] = None
    register = domain_root.joinpath(*DCSYNC_REGISTER_RELPATH)
    if (root / register).is_file():
        register_path = register.as_posix()

    return CredentialStorePointers(
        values_path=values_path,
        values_keys=values_keys,
        register_path=register_path,
    )


def masked_ledger_notice(
    *,
    total: int,
    shown: int,
    pointers: CredentialStorePointers = CredentialStorePointers(),
) -> tuple[str, ...]:
    """Return the paragraphs that replace a full credential table.

    Worded here rather than in the renderer so one place owns how the
    withholding is explained, and so a second consumer of the same policy
    cannot word it differently. Each artifact is named for what it holds: a
    pointer that does not say which file carries the values and which carries
    the register is a pointer the reader has to guess at.
    """
    noun = "secret" if total == 1 else "secrets"
    lines = [f"The run recovered {total:,} {noun}."]

    withheld = "The values are withheld here"
    if pointers.values_path:
        keys = f" (`{pointers.values_keys}`)" if pointers.values_keys else ""
        sentence = (
            f"{withheld} and stay in the workspace credential store at "
            f"`{pointers.values_path}`{keys}, which is where they belong under "
            f"the engagement's handling terms."
        )
        if pointers.register_path:
            sentence += (
                f" `{pointers.register_path}` lists each account it covers, "
                f"with no values in it."
            )
        lines.append(sentence)
    elif pointers.register_path:
        lines.append(
            f"{withheld}. `{pointers.register_path}` lists each account it "
            f"covers, with no values in it."
        )
    else:
        lines.append(
            f"{withheld} so this file can be read and forwarded without carrying them."
        )

    if shown >= total:
        lines.append(
            "Each row below carries the shape of its secret in place of the "
            "secret itself."
        )
    else:
        lines.append(
            f"The {shown} rows below carry the shape of each secret in place of "
            f"the secret itself, chosen to evidence the steps that recovered "
            f"them. Pass `--full-credentials` to write the complete table into "
            f"this file instead."
        )
    return tuple(lines)


__all__ = (
    "CREDENTIAL_STORE_KEYS_TEMPLATE",
    "CREDENTIAL_STORE_RELPATH",
    "DCSYNC_REGISTER_RELPATH",
    "DISCLOSURE_INLINE_FULL",
    "DISCLOSURE_MASKED_EXEMPLARS",
    "EXEMPLAR_LIMIT",
    "FULL_CREDENTIALS_ENV",
    "CredentialLike",
    "CredentialStorePointers",
    "credential_store_pointers",
    "full_credentials_requested",
    "mask_secret_to_shape",
    "masked_ledger_notice",
    "resolve_credential_disclosure",
    "resolve_writeup_engagement_type",
    "select_exemplars",
    "writeup_is_publication_framed",
)
