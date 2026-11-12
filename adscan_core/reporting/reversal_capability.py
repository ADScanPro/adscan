"""What the cleanup account can undo, per forest, domain and CA: ONE derivation.

The pre-scan capability checklist (reversible-by-construction design § 10.1b)
is rendered in four places that must not disagree: the CLI command
(``cleanup_credential check``), the start of ``adscan ci`` / ``adscan start``,
the web scan form, and the report and web CTEM disclosure. They all read the
block :func:`build_reversal_capability_block` produces and the view
:func:`reversal_capability_view` derives from it, mirroring the
``cracking_coverage`` pair. No renderer words a row itself.

The checklist is SCOPE-DRIVEN. One section per in-scope forest, rows per
in-scope domain and per in-scope CA, read from the engagement scope; nothing
outside the scope produces a row or a warning. A row has three possible
answers: yes, not with this account (with what would close it), and nobody can
(so ADscan declines the change). A verdict that could not be established is
"could not be confirmed" and counts as "not with this account": never as yes.

Where a section shows a gap, the fix is derived, never a separate warning:

* the account belongs to another forest (or this forest has none): the forest
  needs its own account, because an Enterprise Admin of one forest holds nothing
  across a forest trust;
* a domain or the forest configuration is uncovered: one line naming an
  Enterprise Admin of the forest root, which covers every domain of the forest
  and its CAs (§ 8.1);
* only a CA is uncovered: the narrower ask of § 8.5, the one permission on that
  CA, never a bigger account.

Only rows the policy GATES on (``required``) can raise a gap. A ``backstop``
row (a change its own author undoes) reads "ADscan undoes it with the account
that made it" when the cleanup account cannot, because that is the truth.

Pure and stdlib-only: the engine builds the block, the PRO and LITE reports and
the web backend read it.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from adscan_core.scan_policy.revert_rights import (
    NEED_BACKSTOP,
    NEED_REQUIRED,
    REASON_CA_UNREACHABLE,
    REASON_LACKS_RIGHT,
    REASON_NO_CA_ROLE,
    REASON_PROBE_FAILED,
    REASON_NO_CLEANUP_ACCOUNT,
    REASON_NO_DIRECTORY_DATA,
    REASON_OFFICER_RIGHTS_RESTRICTED,
    REASON_OFFICER_RIGHTS_UNREADABLE,
    REASON_OTHER_FOREST,
    REASON_PRINCIPAL_NOT_FOUND,
    REASON_ROLE_SEPARATION_BOTH_ROLES,
    REASON_ROLE_SEPARATION_UNREADABLE,
    REASON_ROLES_UNREADABLE,
    SCOPE_CA,
    SCOPE_DOMAIN,
    SCOPE_FOREST,
    STATE_PERMITTED,
    STATE_UNDETERMINABLE,
    RightVerdict,
    revert_right,
)

#: ``domains_data[<domain>]`` key holding the verdicts recorded for that domain.
REVERSAL_CAPABILITY_KEY = "reversal_capability"
#: Version of the persisted block shape (display only, never a decision).
BLOCK_VERSION = 1

ANSWER_YES = "yes"
ANSWER_NO = "not_with_this_account"
ANSWER_UNCONFIRMED = "not_confirmed"
ANSWER_AUTHOR = "undone_by_its_author"
ANSWER_NOBODY = "nobody"

ANSWER_LABELS: Mapping[str, str] = {
    ANSWER_YES: "yes",
    ANSWER_NO: "not with this account",
    ANSWER_UNCONFIRMED: "could not be confirmed",
    ANSWER_AUTHOR: "undone with the account that made it",
    ANSWER_NOBODY: "nobody can undo it",
}

_REASON_TEXT: Mapping[str, str] = {
    REASON_NO_CLEANUP_ACCOUNT: "no cleanup account was supplied for it",
    REASON_OTHER_FOREST: "the account belongs to another forest",
    REASON_NO_DIRECTORY_DATA: "ADscan could not read the account's group memberships there yet",
    REASON_PRINCIPAL_NOT_FOUND: "ADscan could not find the account in the directory",
    REASON_CA_UNREACHABLE: "the CA did not answer its administration interface",
    REASON_ROLES_UNREADABLE: "the CA did not say which roles the account holds",
    REASON_ROLE_SEPARATION_UNREADABLE: "ADscan could not read whether role separation is on",
    REASON_ROLE_SEPARATION_BOTH_ROLES: (
        "role separation is on and the account holds both CA roles, so the CA refuses it"
    ),
    REASON_OFFICER_RIGHTS_UNREADABLE: "ADscan could not read the CA's certificate manager restrictions",
    REASON_OFFICER_RIGHTS_RESTRICTED: (
        "the CA restricts which accounts each certificate manager may act on"
    ),
    REASON_LACKS_RIGHT: "it does not hold that right",
    REASON_NO_CA_ROLE: "the CA reports that it holds no role there",
    REASON_PROBE_FAILED: "the check did not complete",
}


def reason_text(reason: str) -> str:
    """The client sentence fragment for a verdict reason, or ``""``."""
    return _REASON_TEXT.get(str(reason or ""), "")


# ── the block (what the engine persists) ─────────────────────────────────────


def build_reversal_capability_block(
    *,
    forests: Iterable[Mapping[str, Any]],
    verdicts: Iterable[RightVerdict | Mapping[str, Any]],
    token_needs: Mapping[str, str],
    checked_at: str,
    nobody: Iterable[Mapping[str, Any]] = (),
    policy_name: str = "",
    now_running: Iterable[str] = (),
    turned_off_by_policy: Iterable[str] = (),
    cleanup_account_supplied: bool = False,
) -> dict[str, Any]:
    """The persisted, JSON-safe block every surface reads.

    Args:
        forests: One mapping per in-scope forest: ``root`` (the forest root, or
            the domain itself when the forest could not be resolved),
            ``root_in_scope``, ``principal`` (the cleanup account used for it,
            never a secret), ``account_in_forest`` (the account was found to be
            of this forest; ``None`` when unknown), ``domains`` (in-scope domain
            names) and ``cas`` (``{"key", "name", "host", "domain",
            "holders"}`` for each in-scope CA).
        verdicts: Every :class:`RightVerdict` the run established.
        token_needs: ``{token: required|backstop}`` (from the change-kind map).
        checked_at: ISO-8601 UTC time of the check (display only).
        nobody: ``{"title", "subject", "policy_accepts"}`` per change nobody can
            undo (password resets, a copied CA key).
        policy_name: The active policy's display name.
        now_running: Titles of the techniques this account lets run under it.
        turned_off_by_policy: Titles of the techniques this account could undo
            but the policy explicitly switches off.
        cleanup_account_supplied: Whether a cleanup account is configured at all.
    """
    rows: list[dict[str, Any]] = []
    for v in verdicts:
        verdict = v if isinstance(v, RightVerdict) else RightVerdict.from_mapping(v)
        rows.append(verdict.to_dict())
    return {
        "version": BLOCK_VERSION,
        "checked_at": str(checked_at or ""),
        "cleanup_account_supplied": bool(cleanup_account_supplied),
        "forests": [_forest_dict(f) for f in forests],
        "verdicts": rows,
        "token_needs": {str(k): str(v) for k, v in dict(token_needs).items()},
        "nobody": [dict(n) for n in nobody if isinstance(n, Mapping)],
        "policy_name": str(policy_name or ""),
        "now_running": sorted({str(t) for t in now_running if str(t).strip()}),
        "turned_off_by_policy": sorted({str(t) for t in turned_off_by_policy if str(t).strip()}),
    }


def _forest_dict(forest: Mapping[str, Any]) -> dict[str, Any]:
    in_forest = forest.get("account_in_forest")
    return {
        "root": str(forest.get("root") or ""),
        "root_in_scope": bool(forest.get("root_in_scope")),
        "principal": str(forest.get("principal") or ""),
        "account_in_forest": None if in_forest is None else bool(in_forest),
        "domains": sorted({str(d) for d in (forest.get("domains") or ()) if str(d).strip()}),
        "cas": [
            {
                "key": str(ca.get("key") or ""),
                "name": str(ca.get("name") or ""),
                "host": str(ca.get("host") or ""),
                "domain": str(ca.get("domain") or ""),
                "holders": [str(h) for h in (ca.get("holders") or ()) if str(h).strip()],
            }
            for ca in (forest.get("cas") or ())
            if isinstance(ca, Mapping)
        ],
    }


# ── the view (what every surface renders) ───────────────────────────────────


def _answer(verdict: RightVerdict, need: str) -> str:
    if verdict.state == STATE_PERMITTED:
        return ANSWER_YES
    if need == NEED_BACKSTOP:
        return ANSWER_AUTHOR
    if verdict.state == STATE_UNDETERMINABLE:
        return ANSWER_UNCONFIRMED
    return ANSWER_NO


def _join(parts: list[str]) -> str:
    if not parts:
        return ""
    return parts[0] if len(parts) == 1 else f"{', '.join(parts[:-1])} and {parts[-1]}"


def _rows_for_target(
    verdicts: list[RightVerdict], token_needs: Mapping[str, str], *, place: str
) -> list[dict[str, Any]]:
    """One row per answer for one target: rights with the same answer share a row."""
    grouped: dict[tuple[str, str], list[RightVerdict]] = {}
    order: list[tuple[str, str]] = []
    for verdict in sorted(
        verdicts,
        key=lambda v: (getattr(revert_right(v.token), "checklist_order", 999), v.token),
    ):
        need = token_needs.get(verdict.token, NEED_BACKSTOP)
        answer = _answer(verdict, need)
        reason = verdict.reason if answer in (ANSWER_UNCONFIRMED, ANSWER_NO) else ""
        key = (answer, reason)
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(verdict)
    rows: list[dict[str, Any]] = []
    for answer, reason in order:
        members = grouped[(answer, reason)]
        subjects = [getattr(revert_right(v.token), "row_label", v.token) for v in members]
        rows.append(
            {
                "place": place,
                "scope": members[0].scope,
                "target": members[0].target,
                "tokens": [v.token for v in members],
                "subjects": subjects,
                "subject": _join(subjects),
                "answer": answer,
                "answer_label": ANSWER_LABELS[answer],
                "reason": reason,
                "reason_text": _REASON_TEXT.get(reason, ""),
                "required": any(
                    token_needs.get(v.token, NEED_BACKSTOP) == NEED_REQUIRED for v in members
                ),
                "checked_at": max((v.checked_at for v in members), default=""),
            }
        )
    return rows


def _ca_ask(ca: Mapping[str, Any], rows: list[dict[str, Any]]) -> str:
    """The narrower ask of § 8.5 for one CA, only where a gated row reads no."""
    missing: list[str] = []
    for row in rows:
        if not row["required"] or row["answer"] not in (ANSWER_NO, ANSWER_UNCONFIRMED):
            continue
        for token in row["tokens"]:
            right = revert_right(token)
            if right is not None and right.console_name and right.console_name not in missing:
                missing.append(right.console_name)
    if not missing:
        return ""
    name = str(ca.get("name") or ca.get("key") or "this CA")
    perms = _join([f'"{m}"' for m in missing])
    line = f"An account holding {perms} on {name} closes this gap."
    holders = [str(h) for h in (ca.get("holders") or ()) if str(h).strip()]
    if holders:
        line += f" Held today by {_join(holders[:4])}."
    return line


def _forest_view(
    forest: Mapping[str, Any],
    verdicts: list[RightVerdict],
    token_needs: Mapping[str, str],
    *,
    several_forests: bool,
) -> dict[str, Any]:
    root = str(forest.get("root") or "")
    by_target: dict[tuple[str, str], list[RightVerdict]] = {}
    for v in verdicts:
        by_target.setdefault((v.scope, v.target.lower()), []).append(v)

    rows: list[dict[str, Any]] = []
    for domain in forest.get("domains") or ():
        rows += _rows_for_target(
            by_target.get((SCOPE_DOMAIN, str(domain).lower()), []),
            token_needs,
            place=str(domain),
        )
    if forest.get("root_in_scope"):
        rows += _rows_for_target(
            by_target.get((SCOPE_FOREST, root.lower()), []),
            token_needs,
            place=f"{root} forest configuration",
        )
    ca_asks: list[str] = []
    for ca in forest.get("cas") or ():
        ca_rows = _rows_for_target(
            by_target.get((SCOPE_CA, str(ca.get("key") or "").lower()), []),
            token_needs,
            place=str(ca.get("name") or ca.get("key") or ""),
        )
        rows += ca_rows
        ask = _ca_ask(ca, ca_rows)
        if ask:
            ca_asks.append(ask)

    lines: list[str] = []
    in_forest = forest.get("account_in_forest")
    principal = str(forest.get("principal") or "")
    gap = any(
        r["required"] and r["answer"] in (ANSWER_NO, ANSWER_UNCONFIRMED) and r["scope"] != SCOPE_CA
        for r in rows
    )
    if not principal or in_forest is False:
        if several_forests or principal:
            lines.append(
                f"{root} needs its own cleanup account. An Enterprise Admin of one forest "
                "holds nothing across a forest trust."
            )
    elif gap:
        lines.append(
            f"An Enterprise Admin of {root} covers every domain of this forest and its CAs."
        )
        lines += ca_asks
    else:
        lines += ca_asks
    return {"root": root, "principal": principal, "rows": rows, "lines": lines}


def nobody_row_text(subject: str, policy_accepts: Any) -> str:
    """The "nobody can undo" sentence. ``policy_accepts`` ``None``: no policy chosen yet.

    Worded once, from the one answer ``cleanup_capability.policy_accepts_not_reversible``
    gives, so the scan form (which runs before a policy is chosen) states the rule
    instead of a verdict, and ``ci`` / ``start`` / the report state the verdict.
    """
    if policy_accepts is None:
        return (
            f"Nobody can undo {subject}. ADscan makes such a change only when the scan "
            "policy accepts a change that cannot be undone; Audit and "
            "Production-sensitive do not."
        )
    if policy_accepts:
        return (
            f"Nobody can undo {subject}. Your scan policy accepts a change that "
            "cannot be undone, so ADscan may make it and the report names the object."
        )
    return (
        f"Nobody can undo {subject}. Your scan policy does not accept a change that "
        "cannot be undone, so ADscan does not make it."
    )


def reversal_capability_view(block: Any) -> dict[str, Any]:
    """The render shape every surface reads. Empty sections for an empty block."""
    if not isinstance(block, Mapping):
        return {"present": False, "forests": [], "nobody_rows": [], "lines": []}
    verdicts = [
        RightVerdict.from_mapping(v) for v in (block.get("verdicts") or ()) if isinstance(v, Mapping)
    ]
    token_needs = {
        str(k): str(v) for k, v in dict(block.get("token_needs") or {}).items()
    }
    forests_raw = [f for f in (block.get("forests") or ()) if isinstance(f, Mapping)]
    several = len(forests_raw) > 1
    forests = []
    for forest in forests_raw:
        members = {str(d).lower() for d in forest.get("domains") or ()}
        root = str(forest.get("root") or "").lower()
        ca_keys = {str(ca.get("key") or "").lower() for ca in forest.get("cas") or ()}
        mine = [
            v
            for v in verdicts
            if (v.scope == SCOPE_DOMAIN and v.target.lower() in members)
            or (v.scope == SCOPE_FOREST and v.target.lower() == root)
            or (v.scope == SCOPE_CA and v.target.lower() in ca_keys)
        ]
        forests.append(_forest_view(forest, mine, token_needs, several_forests=several))

    nobody_rows = []
    for item in block.get("nobody") or ():
        if not isinstance(item, Mapping):
            continue
        subject = str(item.get("subject") or item.get("title") or "")
        nobody_rows.append(
            {
                "subject": subject,
                "answer": ANSWER_NOBODY,
                "answer_label": ANSWER_LABELS[ANSWER_NOBODY],
                "text": nobody_row_text(subject, item.get("policy_accepts")),
            }
        )

    lines: list[str] = []
    policy = str(block.get("policy_name") or "")
    running = [str(t) for t in block.get("now_running") or ()]
    if running:
        where = f" under {policy}" if policy else ""
        lines.append(
            f"With this account, these techniques now run{where} ({_join(running)})."
        )
    off = [str(t) for t in block.get("turned_off_by_policy") or ()]
    if off:
        lines.append(
            "This account could undo these techniques, and your scan policy turns them "
            f"off ({_join(off)})."
        )
    return {
        "present": True,
        "checked_at": str(block.get("checked_at") or ""),
        "cleanup_account_supplied": bool(block.get("cleanup_account_supplied")),
        "forests": forests,
        "nobody_rows": nobody_rows,
        "lines": lines,
    }


def checklist_text_lines(view: Mapping[str, Any]) -> list[str]:
    """Plain-text rendering (CLI, logs, the grant script's vocabulary)."""
    if not view or not view.get("present"):
        return []
    out: list[str] = []
    for forest in view.get("forests") or ():
        who = f", cleanup account {forest['principal']}" if forest.get("principal") else ""
        out.append(f"Forest {forest['root']}{who}")
        for row in forest.get("rows") or ():
            text = f"  {row['place']}, {row['subject']}, {row['answer_label']}"
            if row.get("reason_text"):
                text += f" ({row['reason_text']})"
            out.append(text)
        for line in forest.get("lines") or ():
            out.append(f"  {line}")
    for row in view.get("nobody_rows") or ():
        out.append(f"  {row['text']}")
    out.extend(view.get("lines") or ())
    return out


def merge_reversal_capability(domains_data: Any) -> dict[str, Any] | None:
    """The newest block persisted under any domain, or ``None``.

    The engine writes the same run-level block under every in-scope domain (a
    report renders one domain at a time); the newest stamp wins.
    """
    best: Mapping[str, Any] | None = None
    if not isinstance(domains_data, Mapping):
        return None
    for entry in domains_data.values():
        if not isinstance(entry, Mapping):
            continue
        block = entry.get(REVERSAL_CAPABILITY_KEY)
        if not isinstance(block, Mapping) or "forests" not in block:
            continue
        if best is None or str(block.get("checked_at") or "") > str(best.get("checked_at") or ""):
            best = block
    return dict(best) if best is not None else None


__all__ = (
    "ANSWER_AUTHOR",
    "ANSWER_LABELS",
    "ANSWER_NO",
    "ANSWER_NOBODY",
    "ANSWER_UNCONFIRMED",
    "ANSWER_YES",
    "BLOCK_VERSION",
    "REVERSAL_CAPABILITY_KEY",
    "build_reversal_capability_block",
    "checklist_text_lines",
    "merge_reversal_capability",
    "reason_text",
    "reversal_capability_view",
)
