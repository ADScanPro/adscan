"""Saved scan policies: named policies a CLI user keeps and reuses.

A saved policy is a YAML file holding the same ``checks`` and ``pacing``
sections a scan configuration and the web's saved policies carry, plus a name
and a description::

    name: Corp production
    description: Held to the written authorization of 2026-11.
    revision: 2
    checks:
      base: production_sensitive
      execution_mode: attended
      disabled: [step:kerberoasting, family:password_attacks]
      new_checks: disabled
      saved_at_registry_version: 12
    pacing:
      level: polite

The top-level ``pacing`` is the POLICY's pace, exactly the web's ``pacing``
column: the default pace of a scan run under it and the fastest it allows. It
lands in the definition's pacing block; ``checks.pacing`` is accepted too, but
not both.

Two stores, one format:

* **workspace**: ``<workspace>/scan_policies/<slug>.yaml``, travels with the
  workspace;
* **global**: ``<state dir>/scan_policies/<slug>.yaml``, under
  :func:`adscan_core.paths.get_state_dir`, which the launcher mounts into the
  container and which resolves to ``%LOCALAPPDATA%\\ADscan\\state`` on Windows.

On a name collision the workspace policy wins. The built-in policies are listed
first and are read-only; they come from the scan-policy model through ONE
adapter, :func:`scan_policy_model`, so a change to the model (new built-ins, new
defaults per workspace type, a per-step execution mode) is rewired in one place.

Validation goes through the scan-policy SSOT: :func:`parse_policy_definition`
for shape and syntax (the pace through the pacing SSOT it calls), and
:func:`adscan_internal.services.scan_controls.resolve_definition` (strict) for
check ids this engine does not know.

Import also reads the two shapes the web produces: the export envelope
(``format: adscan.scan_policy.export``) and the flat create/update body
(``name``, ``base``, ``enabled``, ``disabled``, ``new_checks``, ``pacing``), so a
policy moves between the platform and the CLI in either direction.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Mapping

from adscan_core.paths import get_state_dir
from adscan_core.scan_policy.policy import (
    BASE_AUDIT,
    BUILTIN_DESCRIPTIONS,
    BUILTIN_IDS,
    BUILTIN_LABELS,
    EXECUTION_ATTENDED,
    LEGACY_BASES,
    PolicyIdentity,
    ScanPolicyDefinition,
    ScanPolicyError,
    builtin_definition,
    ENVIRONMENTS,
    builtin_for_environment,
    definition_to_section,
    parse_policy_definition,
)

POLICY_DIRNAME = "scan_policies"
POLICY_SUFFIX = ".yaml"
#: ``format`` marker of the web export envelope (``scan_policy_materialize.export_payload``).
WEB_EXPORT_FORMAT = "adscan.scan_policy.export"
#: ``format`` marker this module writes on export, so a reader knows the shape.
DOCUMENT_FORMAT = "adscan.scan_policy"
DOCUMENT_FORMAT_VERSION = 1

SCOPE_BUILTIN = "builtin"
SCOPE_WORKSPACE = "workspace"
SCOPE_GLOBAL = "global"
SAVE_SCOPES: tuple[str, ...] = (SCOPE_WORKSPACE, SCOPE_GLOBAL)

SCOPE_LABELS: dict[str, str] = {
    SCOPE_BUILTIN: "built-in",
    SCOPE_WORKSPACE: "this workspace",
    SCOPE_GLOBAL: "all workspaces",
}

#: Same limits as the web (``ScanPolicyCreate``), so a name valid here is valid there.
NAME_MAX = 255
DESCRIPTION_MAX = 2000

_DOCUMENT_KEYS = frozenset(
    {"format", "format_version", "name", "description", "revision", "checks", "pacing"}
)
#: Keys of the web's flat create/update body (``app/schemas/scan_policy.py``).
_WEB_FLAT_KEYS = frozenset(
    {"name", "description", "base", "enabled", "disabled", "new_checks", "pacing",
     "saved_at_registry_version", "revision", "execution_mode", "environment",
     "password_attempts", "settings"}
)


class SavedPolicyError(ValueError):
    """A saved policy cannot be read, written or found."""


# ---------------------------------------------------------------------------
# The ONE adapter onto the scan-policy model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BuiltinPolicy:
    """One built-in policy, as the CLI lists it (read-only)."""

    key: str
    name: str
    description: str
    definition: ScanPolicyDefinition


@dataclass(frozen=True)
class ScanPolicyModel:
    """What this module needs from the scan-policy model.

    Attributes:
        builtins: The built-in policies, in the order they are listed.
        default_key_by_environment: The built-in preselected for a workspace
            with no policy of its own, by the environment it last had
            (``lab`` / ``real``).
        fallback_default_key: The built-in preselected when the type is unknown.
        for_interactive_scan: Maps a definition to what an INTERACTIVE scan
            (``start``, the REPL) applies. An interactive scan only uses a
            policy's exclusions; unattended execution of attack steps belongs to
            ``adscan ci``. It drops the unattended authorization (the definition
            is held to "decide during scan"); the engine gate makes an
            interactive entry attended anyway, so this is the second lock.
    """

    builtins: tuple[BuiltinPolicy, ...]
    default_key_by_environment: Mapping[str, str]
    fallback_default_key: str
    for_interactive_scan: Callable[[ScanPolicyDefinition], ScanPolicyDefinition] = field(
        default=lambda definition: definition
    )

    def builtin(self, key: str) -> BuiltinPolicy | None:
        """The built-in with this key, or ``None``."""
        return next((b for b in self.builtins if b.key == key), None)

    def default_for_environment(self, environment: str | None) -> BuiltinPolicy:
        """The built-in preselected for a workspace of this environment."""
        key = self.default_key_by_environment.get(
            str(environment or "").strip().lower(), self.fallback_default_key
        )
        found = self.builtin(key) or self.builtin(self.fallback_default_key)
        assert found is not None
        return found


def scan_policy_model() -> ScanPolicyModel:
    """ADAPTER: the only place this module reads the scan-policy model.

    Rewire this function when the model changes. Everything else in the CLI
    policy surfaces consumes its result.

    The built-ins are Lab / CTF, Audit and Production-sensitive
    (``BUILTIN_IDS``); the first-generation keys still resolve through
    ``builtin_definition`` but are not listed. A workspace without a policy
    preselects the built-in for the environment it last had, Lab / CTF for a lab
    and Audit otherwise (:func:`adscan_core.scan_policy.policy.builtin_for_environment`,
    the same rule the consent gate falls back to). An interactive scan drops the
    unattended authorization: there, a policy only subtracts.
    """
    builtins = tuple(
        BuiltinPolicy(
            key=base,
            name=BUILTIN_LABELS[base],
            description=BUILTIN_DESCRIPTIONS[base],
            definition=builtin_definition(base),
        )
        for base in BUILTIN_IDS
    )
    return ScanPolicyModel(
        builtins=builtins,
        default_key_by_environment={
            environment: builtin_for_environment(environment) for environment in ENVIRONMENTS
        },
        fallback_default_key=BASE_AUDIT,
        for_interactive_scan=_for_interactive_scan,
    )


def _for_interactive_scan(definition: ScanPolicyDefinition) -> ScanPolicyDefinition:
    """An interactive scan decides each attack step live: never unattended."""
    return replace(definition, execution_mode=EXECUTION_ATTENDED)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SavedPolicy:
    """A built-in or saved policy.

    Attributes:
        name: Display name (the built-in's label for a built-in).
        scope: :data:`SCOPE_BUILTIN`, :data:`SCOPE_WORKSPACE` or :data:`SCOPE_GLOBAL`.
        definition: The definition, identity stamped (``<scope>:<slug>``, name,
            revision).
        description: Free text.
        path: The file, ``None`` for a built-in.
        key: The built-in key (built-ins only).
        shadowed: A global policy hidden by a workspace policy of the same name.
    """

    name: str
    scope: str
    definition: ScanPolicyDefinition
    description: str = ""
    path: Path | None = None
    key: str = ""
    shadowed: bool = False

    @property
    def read_only(self) -> bool:
        return self.scope == SCOPE_BUILTIN

    @property
    def slug(self) -> str:
        return self.key if self.read_only else policy_slug(self.name)

    @property
    def reference(self) -> str:
        """``builtin:<key>``, ``workspace:<slug>`` or ``global:<slug>``."""
        return f"{self.scope}:{self.slug}"


# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------


def global_policies_dir() -> Path:
    """Directory of the global saved policies (host and container see the same)."""
    return get_state_dir() / POLICY_DIRNAME


def workspace_policies_dir(workspace_dir: str | os.PathLike[str]) -> Path:
    """Directory of a workspace's saved policies."""
    return Path(workspace_dir) / POLICY_DIRNAME


def _store_dir(scope: str, workspace_dir: str | os.PathLike[str] | None) -> Path:
    if scope == SCOPE_GLOBAL:
        return global_policies_dir()
    if scope == SCOPE_WORKSPACE:
        if not workspace_dir:
            raise SavedPolicyError("Open a workspace first: a workspace policy is saved in it.")
        return workspace_policies_dir(workspace_dir)
    raise SavedPolicyError(f"A policy is saved to the workspace or globally, not '{scope}'.")


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def policy_slug(name: str) -> str:
    """File stem for a policy name (``Corp production`` → ``corp-production``)."""
    slug = _SLUG_RE.sub("-", str(name or "").strip().lower()).strip("-")
    return slug[:64].strip("-")


def normalise_name(name: Any) -> str:
    """A validated policy name (trimmed, non-empty, within the web's limit)."""
    token = " ".join(str(name or "").split())
    if not token:
        raise SavedPolicyError("A scan policy needs a name.")
    if len(token) > NAME_MAX:
        raise SavedPolicyError(f"A scan policy name has at most {NAME_MAX} characters.")
    if not policy_slug(token):
        raise SavedPolicyError(
            f"'{token}' cannot be a policy name: use at least one letter or digit."
        )
    return token


def _is_builtin_name(name: str, model: ScanPolicyModel) -> bool:
    lowered = name.strip().lower()
    slug = policy_slug(name)
    for builtin in model.builtins:
        if lowered in (builtin.key, builtin.name.lower()) or slug == policy_slug(builtin.name):
            return True
        if slug == policy_slug(builtin.key):
            return True
    # First-generation built-ins still resolve by name, so their names stay
    # reserved: a saved "Full validation" would shadow the real one.
    for base in LEGACY_BASES:
        if slug in (policy_slug(base), policy_slug(BUILTIN_LABELS[base])):
            return True
    return False


# ---------------------------------------------------------------------------
# Document <-> definition
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyDocument:
    """A parsed policy document (any accepted shape)."""

    name: str
    description: str
    definition: ScanPolicyDefinition
    revision: int = 0


def _merge_pacing(checks: Mapping[str, Any], pacing: Any, *, where: str) -> dict[str, Any]:
    section = dict(checks)
    if pacing is not None:
        if section.get("pacing") is not None:
            raise SavedPolicyError(
                f"{where}: give the policy's pace once, either 'pacing' or 'checks.pacing'."
            )
        section["pacing"] = pacing
    return section


def parse_policy_document(data: Any, *, default_name: str = "") -> PolicyDocument:
    """Validate a policy document into a :class:`PolicyDocument`.

    Accepts this module's YAML (``name``/``description``/``checks``/``pacing``),
    a bare scan configuration that has a ``checks`` section, the web export
    envelope and the web's flat create body. Shape, syntax and the pace are
    validated here; unknown check ids by :func:`validate_definition`.

    Raises:
        SavedPolicyError: On any malformed part, naming it.
    """
    if not isinstance(data, Mapping):
        raise SavedPolicyError("A scan policy file must hold a mapping.")
    revision_raw: Any = data.get("revision")
    if data.get("format") == WEB_EXPORT_FORMAT:
        meta = data.get("policy") or {}
        if not isinstance(meta, Mapping) or not isinstance(data.get("definition"), Mapping):
            raise SavedPolicyError("The web export has no 'policy' or 'definition' block.")
        name = meta.get("name") or default_name
        description = meta.get("description") or ""
        revision_raw = meta.get("revision")
        section = dict(data["definition"])
        section.pop("policy", None)
    elif _looks_like_scan_config(data):
        # A whole scan configuration: its ``checks`` section is the policy. Its
        # ``pacing`` is a per-scan request, not the policy's pace, so it is
        # validated with the rest of the file and left out.
        from adscan_internal.services.scan_config import ScanConfigError, parse_scan_config

        config_part = {
            k: v for k, v in data.items() if k not in ("format", "format_version", "name", "description", "revision")
        }
        try:
            config = parse_scan_config(config_part)
        except ScanConfigError as exc:
            raise SavedPolicyError(str(exc)) from exc
        name = data.get("name") or default_name
        description = data.get("description") or ""
        section = definition_to_section(config.checks.definition)
        section.pop("policy", None)
    elif "checks" in data or set(data) <= _DOCUMENT_KEYS:
        unknown = sorted(str(k) for k in data if str(k) not in _DOCUMENT_KEYS)
        if unknown:
            raise SavedPolicyError(
                f"Unknown key(s) in the policy file: {', '.join(unknown)}. "
                f"Valid: {', '.join(sorted(_DOCUMENT_KEYS))}."
            )
        checks = data.get("checks") or {}
        if not isinstance(checks, Mapping):
            raise SavedPolicyError("'checks' must be a mapping.")
        name = data.get("name") or default_name
        description = data.get("description") or ""
        section = _merge_pacing(checks, data.get("pacing"), where="policy file")
        section.pop("policy", None)
    elif set(data) <= _WEB_FLAT_KEYS:
        name = data.get("name") or default_name
        description = data.get("description") or ""
        section = {
            key: data[key]
            for key in (
                "base",
                "enabled",
                "disabled",
                "new_checks",
                "saved_at_registry_version",
                "pacing",
                "execution_mode",
                "environment",
                "password_attempts",
                "settings",
            )
            if key in data and data[key] is not None
        }
    else:
        unknown = sorted(str(k) for k in data if str(k) not in _DOCUMENT_KEYS | _WEB_FLAT_KEYS)
        raise SavedPolicyError(f"Unknown key(s) in the policy file: {', '.join(unknown)}.")
    try:
        definition = parse_policy_definition(section)
    except ScanPolicyError as exc:
        raise SavedPolicyError(str(exc)) from exc
    description_text = str(description or "").strip()
    if len(description_text) > DESCRIPTION_MAX:
        raise SavedPolicyError(f"A policy description has at most {DESCRIPTION_MAX} characters.")
    try:
        revision = int(revision_raw or 0)
    except (TypeError, ValueError) as exc:
        raise SavedPolicyError("'revision' must be an integer.") from exc
    return PolicyDocument(
        name=normalise_name(name),
        description=description_text,
        definition=definition,
        revision=max(revision, 0),
    )


_SCAN_CONFIG_ONLY_KEYS = frozenset(
    {"phases", "trust_enumeration", "attack_paths", "audit_extras", "host_cap", "cracking",
     "poisoning", "pivoting", "writeshare_bait", "durable_changes"}
)


def _looks_like_scan_config(data: Mapping[str, Any]) -> bool:
    return bool(set(data) & _SCAN_CONFIG_ONLY_KEYS)


def policy_document(
    name: str, definition: ScanPolicyDefinition, *, description: str = "", revision: int = 0
) -> dict[str, Any]:
    """The YAML mapping of a policy (what is saved and exported).

    ``checks`` is :func:`definition_to_section` without its identity or pace;
    the pace is the top-level ``pacing``, the field the web stores it in.
    """
    section = definition_to_section(definition)
    section.pop("policy", None)
    pacing = section.pop("pacing", None)
    out: dict[str, Any] = {
        "format": DOCUMENT_FORMAT,
        "format_version": DOCUMENT_FORMAT_VERSION,
        "name": name,
    }
    if description:
        out["description"] = description
    if revision:
        out["revision"] = int(revision)
    out["checks"] = section
    if pacing:
        out["pacing"] = pacing
    return out


def web_create_body(policy: SavedPolicy) -> dict[str, Any]:
    """The body the web's ``POST /api/v1/scan-policies`` accepts for this policy."""
    definition = policy.definition
    body: dict[str, Any] = {
        "name": policy.name,
        "base": definition.base,
        "enabled": list(definition.enabled),
        "disabled": list(definition.disabled),
        "new_checks": definition.new_checks,
    }
    if policy.description:
        body["description"] = policy.description
    if definition.pacing:
        body["pacing"] = dict(definition.pacing)
    if definition.execution_mode:
        body["execution_mode"] = definition.execution_mode
    if definition.environment:
        body["environment"] = definition.environment
    if definition.password_attempts:
        body["password_attempts"] = dict(definition.password_attempts)
    if definition.settings:
        body["settings"] = dict(definition.settings)
    return body


def dump_policy_yaml(document: Mapping[str, Any]) -> str:
    """Serialise a policy document to YAML (stable key order, block style)."""
    import yaml

    return yaml.safe_dump(dict(document), sort_keys=False, default_flow_style=False, allow_unicode=True)


def read_policy_text(text: str, *, default_name: str = "") -> PolicyDocument:
    """Parse YAML or JSON text into a document."""
    import yaml

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SavedPolicyError(f"Not valid YAML or JSON: {exc}") from exc
    return parse_policy_document(data, default_name=default_name)


def read_policy_file(path: str | os.PathLike[str]) -> PolicyDocument:
    """Parse a policy file (the file stem is the name when the file has none)."""
    file_path = Path(path).expanduser()
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SavedPolicyError(f"Cannot read {file_path}: {exc.strerror or exc}") from exc
    return read_policy_text(text, default_name=file_path.stem)


def validate_definition(definition: ScanPolicyDefinition) -> Any:
    """Resolve strictly against this engine's registry; returns the resolution.

    Raises:
        SavedPolicyError: When the policy names a check this version does not know.
    """
    from adscan_internal.services.scan_controls import ScanControlsError, resolve_definition

    try:
        return resolve_definition(definition, strict=True)
    except ScanControlsError as exc:
        raise SavedPolicyError(
            f"{exc} Press Tab after 'policy exclude' in the shell to list the valid ids."
        ) from exc


def _identity(scope: str, name: str, revision: int) -> PolicyIdentity:
    return PolicyIdentity(policy_id=f"{scope}:{policy_slug(name)}", name=name, revision=revision)


def _stamp(document: PolicyDocument, scope: str) -> ScanPolicyDefinition:
    return replace(
        document.definition, identity=_identity(scope, document.name, document.revision)
    )


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


def _load_store(scope: str, directory: Path) -> list[SavedPolicy]:
    if not directory.is_dir():
        return []
    out: list[SavedPolicy] = []
    for path in sorted(directory.glob(f"*{POLICY_SUFFIX}")):
        try:
            document = read_policy_file(path)
        except SavedPolicyError:
            continue
        out.append(
            SavedPolicy(
                name=document.name,
                scope=scope,
                definition=_stamp(document, scope),
                description=document.description,
                path=path,
            )
        )
    return out


def unreadable_policy_files(workspace_dir: str | os.PathLike[str] | None = None) -> list[tuple[Path, str]]:
    """Policy files that cannot be read, with the reason (for ``policy list``)."""
    dirs = [global_policies_dir()]
    if workspace_dir:
        dirs.insert(0, workspace_policies_dir(workspace_dir))
    bad: list[tuple[Path, str]] = []
    for directory in dirs:
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob(f"*{POLICY_SUFFIX}")):
            try:
                read_policy_file(path)
            except SavedPolicyError as exc:
                bad.append((path, str(exc)))
    return bad


def list_policies(
    workspace_dir: str | os.PathLike[str] | None = None,
    *,
    include_shadowed: bool = False,
    model: ScanPolicyModel | None = None,
) -> list[SavedPolicy]:
    """Built-ins first, then workspace policies, then global ones, each by name.

    A global policy with the same name as a workspace policy is hidden (or
    returned with ``shadowed=True`` when ``include_shadowed``).
    """
    model = model or scan_policy_model()
    builtins = [
        SavedPolicy(
            name=b.name, scope=SCOPE_BUILTIN, definition=b.definition,
            description=b.description, key=b.key,
        )
        for b in model.builtins
    ]
    workspace = (
        _load_store(SCOPE_WORKSPACE, workspace_policies_dir(workspace_dir)) if workspace_dir else []
    )
    workspace_slugs = {p.slug for p in workspace}
    global_ = []
    for policy in _load_store(SCOPE_GLOBAL, global_policies_dir()):
        if policy.slug in workspace_slugs:
            if include_shadowed:
                global_.append(replace(policy, shadowed=True))
            continue
        global_.append(policy)
    by_name = lambda p: p.name.lower()  # noqa: E731 - local sort key
    return builtins + sorted(workspace, key=by_name) + sorted(global_, key=by_name)


def find_policy(
    name: str,
    workspace_dir: str | os.PathLike[str] | None = None,
    *,
    scope: str | None = None,
    model: ScanPolicyModel | None = None,
) -> SavedPolicy | None:
    """Find a policy by built-in key or label, name or slug (case-insensitive).

    Precedence: built-in, then workspace, then global. ``scope`` restricts it.
    """
    token = str(name or "").strip()
    if not token:
        return None
    lowered = token.lower()
    slug = policy_slug(token)
    for policy in list_policies(workspace_dir, model=model):
        if scope and policy.scope != scope:
            continue
        candidates = {policy.name.lower(), policy.slug}
        if policy.read_only:
            candidates.add(policy.key)
            candidates.add(policy.key.replace("_", "-"))
        if lowered in candidates or slug in candidates:
            return policy
    if scope in (None, SCOPE_BUILTIN):
        # A first-generation built-in (``safe_for_production``, ``full_validation``,
        # ``detection_only``) is no longer listed but still resolves, with its own
        # definition, so a saved command line or note keeps working.
        for base in LEGACY_BASES:
            label = BUILTIN_LABELS[base].lower()
            if lowered in {base, base.replace("_", "-"), label} or slug == policy_slug(label):
                return SavedPolicy(
                    name=BUILTIN_LABELS[base],
                    scope=SCOPE_BUILTIN,
                    definition=builtin_definition(base),
                    description=BUILTIN_DESCRIPTIONS[base],
                    key=base,
                )
    return None


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def save_policy(
    name: str,
    definition: ScanPolicyDefinition,
    *,
    scope: str,
    workspace_dir: str | os.PathLike[str] | None = None,
    description: str = "",
    overwrite: bool = False,
    model: ScanPolicyModel | None = None,
) -> SavedPolicy:
    """Validate and save a policy; returns it with its identity stamped.

    ``saved_at_registry_version`` is stamped with this engine's registry version
    (as the web does), and the revision increases on every overwrite.

    Raises:
        SavedPolicyError: Bad name, a built-in's name, an existing policy without
            ``overwrite``, a check id this engine does not know, or a pace faster
            than the built-in the policy is based on allows.
    """
    model = model or scan_policy_model()
    clean_name = normalise_name(name)
    if _is_builtin_name(clean_name, model):
        raise SavedPolicyError(
            f"'{clean_name}' is the name of a built-in policy. Choose another name."
        )
    description_text = str(description or "").strip()
    if len(description_text) > DESCRIPTION_MAX:
        raise SavedPolicyError(f"A policy description has at most {DESCRIPTION_MAX} characters.")
    directory = _store_dir(scope, workspace_dir)
    path = directory / f"{policy_slug(clean_name)}{POLICY_SUFFIX}"
    revision = 1
    if path.exists():
        if not overwrite:
            raise SavedPolicyError(
                f"A policy named '{clean_name}' is already saved for {SCOPE_LABELS[scope]}."
            )
        try:
            revision = read_policy_file(path).revision + 1
        except SavedPolicyError:
            revision = 1
    # The one save-time pace limit, shared with the web policy API: a policy's
    # pace is its default and its ceiling, so it is never looser than its base.
    from adscan_core.scan_policy.pace_limits import (  # noqa: PLC0415
        PacingConfigError,
        pace_above_base,
    )

    try:
        violation = pace_above_base(definition.base, definition.pacing)
    except PacingConfigError as exc:
        raise SavedPolicyError(str(exc)) from exc
    if violation is not None:
        raise SavedPolicyError(violation.message)
    resolved = validate_definition(definition)
    # Re-stamping the registry version acknowledges the checks added since the
    # policy was saved. Pin each of them to what runs today first, so a save
    # never silently turns one on or off (a ``new_checks: disabled`` policy
    # would otherwise start running them).
    from adscan_core.scan_policy.new_checks import (  # noqa: PLC0415
        acknowledge_new_checks,
        new_checks_since_saved,
    )

    notice = new_checks_since_saved(definition, resolved=resolved)
    if notice is not None:
        definition = acknowledge_new_checks(
            definition, notice, [c.check_id for c in notice.checks if c.on]
        )
    stored = replace(
        definition,
        saved_at_registry_version=int(resolved.registry_version),
        identity=_identity(scope, clean_name, revision),
    )
    document = policy_document(
        clean_name, stored, description=description_text, revision=revision
    )
    _atomic_write(path, dump_policy_yaml(document))
    return SavedPolicy(
        name=clean_name, scope=scope, definition=stored, description=description_text, path=path
    )


def delete_policy(
    name: str,
    *,
    workspace_dir: str | os.PathLike[str] | None = None,
    scope: str | None = None,
    model: ScanPolicyModel | None = None,
) -> SavedPolicy:
    """Delete a saved policy (the workspace one first when the name exists in both).

    Raises:
        SavedPolicyError: Unknown name, or a built-in.
    """
    policy = find_policy(name, workspace_dir, scope=scope, model=model)
    if policy is None:
        raise SavedPolicyError(f"No saved policy named '{name}'.")
    if policy.read_only or policy.path is None:
        raise SavedPolicyError(f"'{policy.name}' is a built-in policy and cannot be deleted.")
    policy.path.unlink()
    return policy


def import_policy(
    path: str | os.PathLike[str],
    *,
    scope: str,
    workspace_dir: str | os.PathLike[str] | None = None,
    name: str | None = None,
    overwrite: bool = False,
    model: ScanPolicyModel | None = None,
) -> SavedPolicy:
    """Read a policy file (any accepted shape) and save it to a store."""
    document = read_policy_file(path)
    return save_policy(
        name or document.name,
        document.definition,
        scope=scope,
        workspace_dir=workspace_dir,
        description=document.description,
        overwrite=overwrite,
        model=model,
    )


def ensure_single_policy_source(scan_config: Any, policy_name: str | None) -> None:
    """Refuse ``--policy`` together with a ``checks`` section: the run would be ambiguous.

    Raises:
        SavedPolicyError: When both are given.
    """
    checks = getattr(scan_config, "checks", None)
    if str(policy_name or "").strip() and checks is not None and not checks.is_default:
        raise SavedPolicyError(
            "Give the scan policy once: either --policy or a 'checks' section in "
            "--scan-config, not both."
        )


def scan_config_with_saved_policy(
    scan_config: Any,
    name: str,
    *,
    workspace_dir: str | os.PathLike[str] | None = None,
    model: ScanPolicyModel | None = None,
) -> Any:
    """``adscan ci --policy <name>``: the scan config with that policy as its ``checks``.

    The FULL definition is applied: ``adscan ci`` is the one consumer that runs
    a policy's enabled attack steps unattended. Validation is strict here too, so
    an unknown id in a saved file aborts the run instead of running unrestricted.

    Raises:
        SavedPolicyError: Unknown name, listing the names that exist.
    """
    from adscan_internal.services.scan_config import ChecksConfig

    policy = find_policy(name, workspace_dir, model=model)
    if policy is None:
        available = ", ".join(p.name for p in list_policies(workspace_dir, model=model))
        raise SavedPolicyError(f"No scan policy named '{name}'. Available: {available}.")
    validate_definition(policy.definition)
    return replace(scan_config, checks=ChecksConfig(definition=policy.definition))


def export_policy_text(policy: SavedPolicy, *, fmt: str = "yaml") -> str:
    """The text ``policy export`` writes: YAML (default) or the web create body as JSON."""
    import json

    revision = int(policy.definition.identity.revision or 0)
    if fmt == "json":
        return json.dumps(web_create_body(policy), indent=2) + "\n"
    if fmt != "yaml":
        raise SavedPolicyError("Export format is yaml or json.")
    return dump_policy_yaml(
        policy_document(policy.name, policy.definition, description=policy.description, revision=revision)
    )


__all__ = [
    "BuiltinPolicy",
    "DOCUMENT_FORMAT",
    "PolicyDocument",
    "SAVE_SCOPES",
    "SCOPE_BUILTIN",
    "SCOPE_GLOBAL",
    "SCOPE_LABELS",
    "SCOPE_WORKSPACE",
    "SavedPolicy",
    "SavedPolicyError",
    "ScanPolicyModel",
    "WEB_EXPORT_FORMAT",
    "delete_policy",
    "dump_policy_yaml",
    "export_policy_text",
    "find_policy",
    "global_policies_dir",
    "import_policy",
    "list_policies",
    "normalise_name",
    "parse_policy_document",
    "policy_document",
    "policy_slug",
    "read_policy_file",
    "read_policy_text",
    "save_policy",
    "scan_policy_model",
    "unreadable_policy_files",
    "validate_definition",
    "web_create_body",
    "workspace_policies_dir",
]
