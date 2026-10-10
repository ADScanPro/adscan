"""The declared ENS scope of the system a workspace assessed: read, never decided.

The ENS category belongs to the SYSTEM, not to the command that renders a
report: art. 40.1 scopes it to "un sistema de información", the Anexo IV
glossary defines it as a grade with which "un sistema de información" is
qualified, and Anexo II apartado 2.2 admits granularity below the system. So the
declaration is PERSISTED WORKSPACE STATE, and every surface reads it: ``adscan
deliver``, the REPL, the web. None of them decides it, and nothing here ever
infers a category.

Where it lives
--------------
``<workspace>/compliance_scope.json``, its own file rather than a key in
``variables.json``. Two reasons: ``variables.json`` is the SCAN's own state,
rewritten on every workspace save, and a declaration is an operator/client input
that must survive a re-render (``deliver`` mutates the workspace); and keeping it
separate makes it the auditable artifact it is, a file the client's security
officer can be shown.

``--compliance-scope <file>`` overrides the path, which is what CI uses and what
a client who sends their categorisation in writing gets read from. The env var
``ADSCAN_COMPLIANCE_SCOPE`` does the same for a containerised run, since the
launcher forwards every ``ADSCAN_*`` variable.

The shape::

    {
      "ens": {
        "ens_version": "RD 311/2022",
        "profile": "general",
        "dimensions": {"C": "medio", "I": "medio", "T": "bajo",
                       "A": "medio", "D": "bajo"},
        "compensatory_measures": ["op.cont.3"],
        "system": "<the system or subsystem this declaration covers>"
      }
    }

Only the five dimension levels are taken. The category is DERIVED from them
(Anexo I apdo. 4.1 defines it as their maximum), so a declaration cannot
contradict itself, and the five levels are exactly the breakdown the ITS de
Auditoría apartado VI.7 obliges an audit report to declare. A flat block without
the ``"ens"`` wrapper is also accepted, because that is what an operator writes
by hand on the first try.

An absent, unreadable or empty file is NOT an error and never prompts: the
resolver answers with the common core of measures Anexo II requires from the
lowest level upward, which hold at every category (see
:func:`~adscan_core.reporting.ens_applicability.resolve_ens_applicability`).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable, Optional

from adscan_core.reporting.ens_applicability import (
    EnsScope,
    EnsScopeResolution,
    parse_ens_scope,
    resolve_ens_applicability,
)
from adscan_core.rich_output import print_info_debug

#: The per-workspace declaration file.
COMPLIANCE_SCOPE_FILENAME = "compliance_scope.json"

#: Path override, for CI and for a client-supplied declaration.
COMPLIANCE_SCOPE_ENV = "ADSCAN_COMPLIANCE_SCOPE"

#: The framework key the ENS block is nested under.
_ENS_KEY = "ens"


def compliance_scope_path(workspace_dir: Any = None) -> Optional[Path]:
    """Resolve the declaration file to read, env override first.

    Returns ``None`` when neither an override nor a workspace directory is
    available, which is a data gap and not an error.
    """
    override = os.environ.get(COMPLIANCE_SCOPE_ENV, "").strip()
    if override:
        return Path(override)
    if not workspace_dir:
        return None
    return Path(str(workspace_dir)) / COMPLIANCE_SCOPE_FILENAME


def read_compliance_scope_declaration(
    workspace_dir: Any = None, *, path: Any = None
) -> Optional[dict[str, Any]]:
    """Read the raw declaration mapping, or ``None``.

    Never raises: an unreadable or malformed declaration is a data gap, and the
    caller's conservative default is correct for it.
    """
    target = Path(str(path)) if path else compliance_scope_path(workspace_dir)
    if target is None:
        return None
    try:
        if not target.is_file():
            return None
        data = json.loads(target.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - a bad declaration is a data gap
        print_info_debug(f"ENS scope: declaration at {target} unreadable: {exc}")
        return None
    if not isinstance(data, dict):
        return None
    nested = data.get(_ENS_KEY)
    if isinstance(nested, dict):
        return nested
    # A flat block is what an operator writes by hand on the first try; reading
    # it is strictly better than silently ignoring a correct declaration over
    # its nesting.
    return data if "dimensions" in data else None


def load_ens_scope(workspace_dir: Any = None, *, path: Any = None) -> Optional[EnsScope]:
    """Load the workspace's declared ENS scope, or ``None`` when undeclared."""
    declaration = read_compliance_scope_declaration(workspace_dir, path=path)
    if declaration is None:
        return None
    return parse_ens_scope(declaration)


def resolve_ens_scope_for_workspace(
    workspace_dir: Any = None, *, path: Any = None
) -> EnsScopeResolution:
    """Resolve Anexo II applicability for one workspace. The SSOT entry point.

    An undeclared workspace resolves the common core rather than assuming a
    category, so this always returns a usable, non-empty resolution.
    """
    return resolve_ens_applicability(load_ens_scope(workspace_dir, path=path))


#: The frameworks whose exigible requirement set is a function of a client
#: declaration. The ONE place that answers "does this framework have a declared
#: scope at all", so no consumer writes its own framework comparison.
#:
#: ENS is the only one today: its applicable-measure set follows the normative
#: version, the compliance profile and the five dimension levels. The other five
#: regimes have no declared-scope input yet, so they resolve to no resolver and
#: behave exactly as they did before this subsystem existed.
DECLARED_SCOPE_FRAMEWORKS: frozenset[str] = frozenset({"ens"})


def applicability_resolver_for(
    framework_key: str, workspace_dir: Any = None, *, path: Any = None
) -> Optional[Callable[[str], Optional[dict[str, Any]]]]:
    """Return one framework's declared-scope resolver, or ``None``.

    The resolver answers "what does this client's declared scope make of this
    requirement", in the serialized shape both
    ``compliance_engine.build_framework_requirement_model`` and
    ``adscan_core.reporting.control_exigibility.annotate_control_codes``
    consume, so one resolver serves the report's compliance section and the
    control citations the bonus documents print.

    Args:
        framework_key: Canonical framework key (``"ens"``, ``"iso27001"``, ...).
        workspace_dir: Workspace whose declaration to read.
        path: Explicit declaration path, for tests and the env override.

    Returns:
        A callable, or ``None`` when the framework has no declared-scope
        dimension or the declaration could not be resolved. Best-effort: a
        framework left unresolved renders unannotated rather than breaking the
        deliverable.
    """
    key = str(framework_key or "").strip().lower()
    if key not in DECLARED_SCOPE_FRAMEWORKS:
        return None
    try:
        resolution = resolve_ens_scope_for_workspace(workspace_dir, path=path)
    except Exception as exc:  # noqa: BLE001 - the document ships without it
        print_info_debug(f"ENS scope: applicability unresolved: {exc}")
        return None

    def _resolve(requirement_id: str) -> Optional[dict[str, Any]]:
        measure = resolution.measure(requirement_id)
        return measure.as_dict() if measure is not None else None

    return _resolve


def build_applicability_resolvers(
    workspace_dir: Any = None,
    *,
    frameworks: Any = None,
    path: Any = None,
) -> dict[str, Callable[[str], Optional[dict[str, Any]]]]:
    """Build the resolver for every declared-scope framework in the selection.

    Built once per document and threaded down, rather than per finding: one ENS
    resolution walks all 73 Anexo II measures, so resolving it per cited control
    would repeat that work for every row.

    Args:
        workspace_dir: Workspace whose declaration to read.
        frameworks: The operator's framework selection. ``None`` means every
            declared-scope framework, matching the all-frameworks default the
            deliverable builders use.
        path: Explicit declaration path, for tests and the env override.

    Returns:
        ``{framework_key: resolver}``, containing only the frameworks that have
        a declared scope AND resolved. Empty when none do.
    """
    if frameworks is None:
        selected = set(DECLARED_SCOPE_FRAMEWORKS)
    else:
        selected = {
            str(key).strip().lower() for key in frameworks if str(key).strip()
        } & DECLARED_SCOPE_FRAMEWORKS
    out: dict[str, Callable[[str], Optional[dict[str, Any]]]] = {}
    for key in sorted(selected):
        resolver = applicability_resolver_for(key, workspace_dir, path=path)
        if resolver is not None:
            out[key] = resolver
    return out


def write_compliance_scope_declaration(
    workspace_dir: Any, declaration: dict[str, Any]
) -> Path:
    """Persist an ENS declaration into a workspace, for the REPL/web writers.

    Writes the nested shape so a second framework's declaration can join it
    later without a migration. Returns the path written.
    """
    target = Path(str(workspace_dir)) / COMPLIANCE_SCOPE_FILENAME
    existing: dict[str, Any] = {}
    try:
        if target.is_file():
            loaded = json.loads(target.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                existing = loaded
    except Exception as exc:  # noqa: BLE001 - overwrite a corrupt declaration
        print_info_debug(f"ENS scope: replacing unreadable declaration: {exc}")
    existing[_ENS_KEY] = declaration
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(existing, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return target


__all__ = (
    "COMPLIANCE_SCOPE_ENV",
    "COMPLIANCE_SCOPE_FILENAME",
    "DECLARED_SCOPE_FRAMEWORKS",
    "applicability_resolver_for",
    "build_applicability_resolvers",
    "compliance_scope_path",
    "load_ens_scope",
    "read_compliance_scope_declaration",
    "resolve_ens_scope_for_workspace",
    "write_compliance_scope_declaration",
)
