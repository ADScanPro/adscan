"""``RunPlan``: one run of the engine, described by the engine contract.

``adscan run --plan <file>`` is the canonical entry an orchestrator uses (the
appliance worker, a scanner node, an OEM consumer). The legacy ``ci``,
``doctor`` and ``deliver`` flags normalise into the SAME plan
(:meth:`RunPlan.from_ci_args` and siblings), and a plan converts back into the
exact namespace those commands' handlers already consume
(:meth:`RunPlan.to_ci_namespace` and siblings). So there is one execution path
per kind (the handler), two ways to describe the run, and a round-trip test
proving the two descriptions are the same run.

The plan never holds a secret. A credential is a reference
(``env:NAME``, ``file:<relpath>``, ``node:<profile>``, ``engagement:<principal>``)
resolved only when the namespace is built. ``file:`` references, and the
non-secret input files a run needs (a client logo, a cover fragment), are
relative to the RUN DIRECTORY: the directory that holds the plan file. A flag
that carried a value (``--password``) or a host path (``--client-logo``) is
staged into that directory when a plan is built from flags, so the plan can be
logged, stored and signed while the value stays in a 0600 file beside it.

Validation is the shared schema (:mod:`adscan_core.engagement.contract`) plus
the per-kind rules the schema cannot express: which sections a kind may carry,
which fields a kind requires.
"""

from __future__ import annotations

import argparse
import copy
import dataclasses
import json
import os
import shutil
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Optional

from adscan_core.engagement.contract import ContractError, schema_tag, validate

PLAN_SCHEMA_NAME = "run_plan"
PLAN_SCHEMA_TAG = schema_tag(PLAN_SCHEMA_NAME)

#: Process environment the run identity travels in, so every writer of a run
#: artifact (coverage, events, run summary) stamps the same id.
RUN_ID_ENV = "ADSCAN_RUN_ID"
RUN_KIND_ENV = "ADSCAN_RUN_KIND"
EVENTS_FILE_ENV = "ADSCAN_EVENTS_FILE"
#: Container directory the launcher mounts env: secrets into, one file per name.
ENV_SECRETS_DIR_ENV = "ADSCAN_RUN_ENV_SECRETS_DIR"

#: Kinds this engine executes today. ``recheck`` and ``postprocess`` are valid
#: plans (the console can build and store them) but have no engine path yet.
RUNNABLE_KINDS = ("scan", "doctor", "deliver")

#: The legacy command each kind normalises from, used for the tier gate and the
#: session-capture label so a plan run is classified exactly like its flags run.
KIND_COMMAND = {"scan": "ci", "doctor": "doctor", "deliver": "deliver"}

_SECRETS_DIR = "secrets"
_PASSWORD_FILE = "password"
_ASSETS_DIR = "assets"

# --------------------------------------------------------------------------- #
# Field tables: one row per plan field, its namespace dest, its default.
# --------------------------------------------------------------------------- #

_VALUE = "value"
_BOOL = "bool"
_CSV = "csv"  # plan list <-> comma-separated namespace string
_SECRET = "secret"
_ASSET = "asset"
_SCAN_CONFIG = "scan_config"
_SLUGS = "slugs"  # comma list kept as a normalised string in the plan
_DOMAINS = "domains"  # plan list of domains <-> comma string, normalised like the doctor parser
_PACING_SET = "pacing_set"  # repeatable KNOB=VALUE flags <-> canonical validated list


@dataclass(frozen=True)
class _Field:
    path: tuple[str, ...]
    dest: str
    kind: str = _VALUE
    default: Any = None
    #: Always written into the canonical plan, the default included: a value
    #: whose consequence an auditor reads off the plan (which trusted domains a
    #: validation may touch) is stated, never implied by omission.
    explicit: bool = False


_CI_FIELDS: tuple[_Field, ...] = (
    _Field(("workspace", "name"), "workspace"),
    _Field(("workspace", "type"), "type"),
    _Field(("workspace", "ephemeral"), "ephemeral", _BOOL, False),
    _Field(("target", "mode"), "mode"),
    _Field(("target", "domain"), "domain"),
    _Field(("target", "dc_ip"), "dc_ip"),
    _Field(("target", "dns_server"), "dns_server"),
    _Field(("target", "hosts"), "hosts"),
    _Field(("target", "interface"), "interface"),
    _Field(("credentials", "username"), "username"),
    _Field(("credentials", "secret"), "password", _SECRET),
    _Field(("scan", "read_only"), "read_only", _BOOL, False),
    _Field(("scan", "show_structural"), "show_structural", _BOOL, False),
    _Field(("scan", "scan_config"), "scan_config_data", _SCAN_CONFIG),
    _Field(("scan", "pacing"), "pacing"),
    _Field(("scan", "pacing_set"), "pacing_set", _PACING_SET),
    _Field(("scan", "policy"), "policy"),
    _Field(("scan", "pace_profile"), "pace_profile"),
    _Field(("scan", "auto_revert"), "auto_revert"),
    _Field(("report", "generate"), "generate_report", _BOOL, False),
    _Field(("report", "only"), "only", _SLUGS, "report"),
    _Field(("report", "format"), "report_format", _VALUE, "pdf"),
    _Field(("report", "frameworks"), "frameworks", _CSV),
    _Field(("report", "engine"), "report_engine"),
    _Field(("report", "renderer"), "report_renderer"),
    _Field(("report", "template"), "report_template"),
    _Field(("report", "theme"), "report_theme"),
    # The deliverable options the shared model (adscan_core.report_options)
    # adds to `ci`, so a plan renders the same branded kit the flags do.
    _Field(("report", "kit_theme"), "theme"),
    _Field(("report", "display_name"), "display_name"),
    _Field(("report", "client"), "client"),
    _Field(("report", "engagement"), "engagement"),
    _Field(("report", "branding"), "branding"),
    _Field(("report", "emit"), "emit", _SLUGS),
    _Field(("report", "no_navigator"), "no_navigator", _BOOL, False),
    _Field(("report", "client_logo"), "client_logo", _ASSET),
    _Field(("report", "client_cover"), "client_cover", _ASSET),
    _Field(("report", "client_back"), "client_back", _ASSET),
)

_DOCTOR_FIELDS: tuple[_Field, ...] = (
    _Field(("workspace", "name"), "workspace"),
    _Field(("target", "domain"), "domain"),
    _Field(("target", "dc_ip"), "dc_ip"),
    _Field(("target", "dns_server"), "dns_server"),
    _Field(("target", "interface"), "interface"),
    _Field(("credentials", "username"), "username"),
    _Field(("credentials", "secret"), "password", _SECRET),
    _Field(("doctor", "trust_scope"), "trust_scope", _VALUE, "origin_only", explicit=True),
    _Field(("doctor", "trust_domains"), "trust_domains", _DOMAINS),
    _Field(("doctor", "json"), "json_output", _BOOL, False),
)

_DELIVER_FIELDS: tuple[_Field, ...] = (
    _Field(("workspace", "name"), "workspace"),
    _Field(("deliver", "client"), "client"),
    _Field(("deliver", "engagement"), "engagement"),
    _Field(("deliver", "only"), "only", _SLUGS),
    _Field(("deliver", "frameworks"), "frameworks", _CSV),
    _Field(("deliver", "no_navigator"), "no_navigator", _BOOL, False),
    _Field(("deliver", "theme"), "theme", _VALUE, ""),
    _Field(("deliver", "report_theme"), "report_theme", _VALUE, ""),
    _Field(("deliver", "branding"), "branding"),
    _Field(("deliver", "emit"), "emit", _SLUGS),
    _Field(("deliver", "client_logo"), "client_logo", _ASSET),
    _Field(("deliver", "client_cover"), "client_cover", _ASSET),
    _Field(("deliver", "client_back"), "client_back", _ASSET),
    # The Executive Progress Report model, shipped beside the plan; the PDF is
    # written next to it, so a plan run stays inside its run directory.
    _Field(("deliver", "progress_model"), "progress_model", _ASSET),
)

#: Namespace dests a legacy command carries that a plan deliberately does not:
#: operator-console switches of ``adscan run`` itself (``-v``/``-d``/``--dev``)
#: and, for ``deliver``, an output directory OUTSIDE the workspace, which the
#: contract forbids (a node writes only inside its workspace).
_CONSOLE_DESTS = ("verbose", "debug", "dev")
_UNREPRESENTABLE_DESTS = {"deliver": ("output",), "scan": ("output",)}

_KIND_FIELDS: dict[str, tuple[_Field, ...]] = {
    "scan": _CI_FIELDS,
    "doctor": _DOCTOR_FIELDS,
    "deliver": _DELIVER_FIELDS,
}

#: Fields a kind cannot run without. The schema leaves them optional because a
#: plan of another kind omits them.
_KIND_REQUIRED: dict[str, tuple[tuple[str, ...], ...]] = {
    # The scan policy is required by the run itself (``scan.policy`` or a
    # ``checks`` section in ``scan.scan_config``); ``ci`` refuses a plan that
    # names neither with its guidance. ``workspace.type`` is retired: it still
    # parses, so an old plan gets that guidance instead of a schema error.
    "scan": (("target", "mode"),),
}


def _pointer(path: tuple[str, ...]) -> str:
    return "/" + "/".join(path)


def _get(doc: Mapping[str, Any], path: tuple[str, ...]) -> Any:
    node: Any = doc
    for key in path:
        if not isinstance(node, Mapping) or key not in node:
            return None
        node = node[key]
    return node


def _set(doc: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    node = doc
    for key in path[:-1]:
        node = node.setdefault(key, {})
    node[path[-1]] = value


def _csv_to_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        items = value.split(",")
    else:
        items = list(value)
    out: list[str] = []
    for item in items:
        token = str(item).strip()
        if token and token not in out:
            out.append(token)
    return out


def _slugs(value: Any) -> Optional[str]:
    items = _csv_to_list(value)
    return ",".join(items) if items else None


# --------------------------------------------------------------------------- #
# Scan configuration: the canonical, non-default projection of a ScanConfig.
# --------------------------------------------------------------------------- #


def scan_config_to_plan(config: Any) -> dict[str, Any]:
    """Return the canonical plan form of a parsed ``ScanConfig``.

    Only non-default values are emitted, lists are arrays and the ``skip`` alias
    is already resolved by the parser, so a scan-config file and a plan section
    describing the same configuration produce the same dictionary.
    """
    from adscan_internal.services import scan_config as sc  # noqa: PLC0415

    out: dict[str, Any] = {}
    phases: dict[str, Any] = {}
    if config.phases.disabled:
        phases["disabled"] = list(config.phases.disabled)
    if config.phases.steps:
        phases["steps"] = {
            phase: {"disabled": list(steps)} for phase, steps in sorted(config.phases.steps.items())
        }
    if phases:
        out["phases"] = phases

    trust: dict[str, Any] = {}
    if config.trust_enumeration.policy != sc.TRUST_POLICY_INTERACTIVE:
        trust["policy"] = config.trust_enumeration.policy
    if config.trust_enumeration.domains:
        trust["domains"] = list(config.trust_enumeration.domains)
    if trust:
        out["trust_enumeration"] = trust

    paths: dict[str, Any] = {}
    if config.attack_paths.policy != sc.ATTACK_PATH_POLICY_INTERACTIVE:
        paths["policy"] = config.attack_paths.policy
    if config.attack_paths.selected:
        paths["selected"] = list(config.attack_paths.selected)
    if paths:
        out["attack_paths"] = paths

    if config.audit_extras.target_scope != sc.CVE_TARGET_SCOPE_DEFAULT:
        out["audit_extras"] = {"target_scope": config.audit_extras.target_scope}
    if config.host_cap != sc.HOST_CAP_DEFAULT:
        out["host_cap"] = config.host_cap

    cracking: dict[str, Any] = {}
    if config.cracking.effort != sc.CRACKING_EFFORT_DEFAULT:
        cracking["effort"] = config.cracking.effort
    if config.cracking.wordlist:
        cracking["wordlist"] = config.cracking.wordlist
    if cracking:
        out["cracking"] = cracking

    for section in ("poisoning", "pivoting", "writeshare_bait"):
        enabled = getattr(config, section).enabled
        if enabled is not None:
            out[section] = {"enabled": enabled}

    durable: dict[str, Any] = {}
    for key in ("keep", "allow_ca_key_backup"):
        value = getattr(config.durable_changes, key)
        if value is not None:
            durable[key] = value
    if durable:
        out["durable_changes"] = durable

    if not config.checks.is_default:
        from adscan_core.scan_policy.policy import definition_to_section  # noqa: PLC0415

        out["checks"] = definition_to_section(config.checks.definition)
    pacing = sc.pacing_section(config.pacing)
    if pacing:
        out["pacing"] = pacing
    return out


def _canonical_scan_config(raw: Any, *, where: str) -> Optional[dict[str, Any]]:
    from adscan_internal.services.scan_config import (  # noqa: PLC0415
        ScanConfigError,
        parse_scan_config,
    )

    try:
        canonical = scan_config_to_plan(parse_scan_config(raw))
    except ScanConfigError as exc:
        raise ContractError("invalid_scan_config", where, str(exc)) from exc
    return canonical or None


# --------------------------------------------------------------------------- #
# The plan
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RunPlan:
    """A validated, canonical ``adscan.run_plan/1`` document.

    Two plans are equal when they describe the same run: defaults are omitted,
    lists are normalised and the scan configuration is canonical, so a plan
    built from flags and the same plan written by hand compare equal.

    Attributes:
        document: The canonical document (read through :meth:`to_dict`).
        base_dir: The run directory ``file:`` references resolve against. Not
            part of the plan's identity.
    """

    document: dict[str, Any]
    base_dir: Optional[Path] = field(default=None, compare=False)
    #: Secret files THIS process staged from flags (``from_*_args``); removed by
    #: :meth:`discard_staged_secrets`. A plan loaded from a file stages nothing,
    #: so hand-written secret files are never touched.
    staged: tuple[Path, ...] = field(default=(), compare=False)

    # ── construction ──────────────────────────────────────────────────────

    @classmethod
    def from_dict(cls, doc: Mapping[str, Any], *, base_dir: Optional[Path]) -> "RunPlan":
        """Validate ``doc`` and return its canonical plan.

        Raises:
            ContractError: Schema violation, a section the kind does not use
                (``section_not_allowed``), a missing per-kind field
                (``required``) or an invalid scan configuration.
        """
        if not isinstance(doc, Mapping):
            raise ContractError("type", "", "a run plan is a JSON object")
        validate(PLAN_SCHEMA_NAME, doc)
        kind = str(doc["kind"])
        fields = _KIND_FIELDS.get(kind, ())
        _reject_foreign_fields(doc, kind, fields)
        canonical: dict[str, Any] = {"schema": PLAN_SCHEMA_TAG, "kind": kind}
        if doc.get("run_id"):
            canonical["run_id"] = doc["run_id"]
        for spec in fields:
            value = _get(doc, spec.path)
            normalised = _normalise_plan_value(spec, value)
            if normalised is not None:
                _set(canonical, spec.path, normalised)
        for path in _KIND_REQUIRED.get(kind, ()):
            if _get(canonical, path) is None:
                raise ContractError("required", _pointer(path))
        validate(PLAN_SCHEMA_NAME, canonical)
        return cls(document=canonical, base_dir=Path(base_dir) if base_dir is not None else None)

    @classmethod
    def from_file(cls, path: Path) -> "RunPlan":
        """Load a plan file; its directory is the run directory."""
        plan_path = Path(path)
        try:
            raw = json.loads(plan_path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ContractError("unreadable_plan", "", str(exc)) from exc
        except ValueError as exc:
            raise ContractError("invalid_json", "", str(exc)) from exc
        return cls.from_dict(raw, base_dir=plan_path.parent)

    @classmethod
    def from_ci_args(
        cls, ns: argparse.Namespace, *, run_dir: Optional[Path], run_id: Optional[str] = None
    ) -> "RunPlan":
        """Normalise ``adscan ci`` flags (and ``--scan-config``) into a plan."""
        return cls._from_args("scan", ns, run_dir=run_dir, run_id=run_id)

    @classmethod
    def from_doctor_args(
        cls, ns: argparse.Namespace, *, run_dir: Optional[Path], run_id: Optional[str] = None
    ) -> "RunPlan":
        """Normalise ``adscan doctor`` flags into a plan."""
        return cls._from_args("doctor", ns, run_dir=run_dir, run_id=run_id)

    @classmethod
    def from_deliver_args(
        cls, ns: argparse.Namespace, *, run_dir: Optional[Path], run_id: Optional[str] = None
    ) -> "RunPlan":
        """Normalise ``adscan deliver`` flags into a plan."""
        return cls._from_args("deliver", ns, run_dir=run_dir, run_id=run_id)

    @classmethod
    def _from_args(
        cls, kind: str, ns: argparse.Namespace, *, run_dir: Optional[Path], run_id: Optional[str]
    ) -> "RunPlan":
        for dest in _UNREPRESENTABLE_DESTS.get(kind, ()):
            if getattr(ns, dest, None):
                raise ContractError(
                    "not_representable",
                    f"/{dest}",
                    "a plan writes only inside the workspace; drop the flag or move the output",
                )
        has_user = bool(getattr(ns, "username", None))
        has_secret = bool(getattr(ns, "password", None))
        if has_user != has_secret:
            raise ContractError(
                "not_representable",
                "/credentials",
                "a plan carries a username and its secret together, or neither",
            )
        doc: dict[str, Any] = {"schema": PLAN_SCHEMA_TAG, "kind": kind}
        if run_id:
            doc["run_id"] = run_id
        resolved_run_dir = Path(run_dir) if run_dir is not None else None
        staged: list[Path] = []
        try:
            for spec in _KIND_FIELDS[kind]:
                value = _plan_value_from_namespace(spec, ns, run_dir=resolved_run_dir, staged=staged)
                if value is not None:
                    _set(doc, spec.path, value)
            plan = cls.from_dict(doc, base_dir=resolved_run_dir)
        except BaseException:
            _discard_paths(staged)
            raise
        return dataclasses.replace(plan, staged=tuple(staged))

    def discard_staged_secrets(self) -> None:
        """Remove the secret files this plan staged from flags (idempotent).

        The orchestrator calls this once the run has consumed them. Only files
        :meth:`from_ci_args` and siblings wrote are removed, never a file the
        plan merely references.
        """
        _discard_paths(self.staged)

    # ── projection ────────────────────────────────────────────────────────

    @property
    def kind(self) -> str:
        """The run kind (``scan``, ``doctor``, ``deliver``, ...)."""
        return str(self.document["kind"])

    @property
    def run_id(self) -> Optional[str]:
        """The orchestrator-assigned run id, when the plan carries one."""
        value = self.document.get("run_id")
        return str(value) if value else None

    def to_dict(self) -> dict[str, Any]:
        """Return a deep copy of the canonical document."""
        return copy.deepcopy(self.document)

    def to_ci_namespace(self, **console: bool) -> argparse.Namespace:
        """Return the ``ci`` handler namespace, credentials resolved."""
        return self._to_namespace("scan", "ci", console)

    def to_doctor_namespace(self, **console: bool) -> argparse.Namespace:
        """Return the ``doctor`` handler namespace, credentials resolved."""
        return self._to_namespace("doctor", "doctor", console)

    def to_deliver_namespace(self, **console: bool) -> argparse.Namespace:
        """Return the ``deliver`` handler namespace, assets resolved."""
        return self._to_namespace("deliver", "deliver", console)

    def to_namespace(self, **console: bool) -> argparse.Namespace:
        """Return the handler namespace for this plan's kind."""
        if self.kind not in KIND_COMMAND:
            raise ContractError("unsupported_kind", "/kind", self.kind)
        return self._to_namespace(self.kind, KIND_COMMAND[self.kind], console)

    def _to_namespace(self, kind: str, command: str, console: Mapping[str, bool]) -> argparse.Namespace:
        if self.kind != kind:
            raise ContractError("kind_mismatch", "/kind", f"plan is {self.kind}, not {kind}")
        values: dict[str, Any] = {"command": command}
        for dest in _CONSOLE_DESTS:
            values[dest] = bool(console.get(dest, False))
        for dest in _UNREPRESENTABLE_DESTS.get(kind, ()):
            values[dest] = None
        for spec in _KIND_FIELDS[kind]:
            value = _get(self.document, spec.path)
            if spec.kind == _SCAN_CONFIG:
                if value is not None:
                    values[spec.dest] = copy.deepcopy(value)
                continue
            values[spec.dest] = self._namespace_value(spec, value)
        return argparse.Namespace(**values)

    def _namespace_value(self, spec: _Field, value: Any) -> Any:
        if value is None:
            return spec.default
        if spec.kind in (_CSV, _DOMAINS):
            return ",".join(value) if value else spec.default
        if spec.kind == _SECRET:
            return self.resolve_secret(value["ref"], where=_pointer(spec.path))
        if spec.kind == _ASSET:
            return str(self._resolve_file(value["ref"], where=_pointer(spec.path)))
        return value

    # ── references ────────────────────────────────────────────────────────

    def resolve_secret(self, ref: str, *, where: str = "/credentials/secret") -> str:
        """Return the value a credential reference points at.

        Raises:
            ContractError: ``unresolved_reference`` when the variable or file is
                missing, ``reference_outside_run_dir`` when a file reference
                escapes the run directory (a symlink), ``unsupported_reference``
                for ``node:``/``engagement:``, which only a scanner node or the
                engagement vault can resolve.
        """
        scheme, _, name = ref.partition(":")
        if scheme == "env":
            # Through the launcher an env: secret arrives as a file in a private
            # read-only directory (never as a container variable, which docker
            # inspect would print); run in-process (Windows) it is the variable.
            env_dir = str(os.environ.get(ENV_SECRETS_DIR_ENV, "") or "").strip()
            if env_dir:
                candidate = Path(env_dir) / name
                if candidate.is_file() and not candidate.is_symlink():
                    return candidate.read_text(encoding="utf-8")
            if name not in os.environ:
                raise ContractError("unresolved_reference", where, f"environment variable {name} is not set")
            return os.environ[name]
        if scheme == "file":
            path = self._resolve_file(ref, where=where)
            text = path.read_text(encoding="utf-8")
            # One trailing newline is an editor artifact; anything else is the value.
            if text.endswith("\r\n"):
                return text[:-2]
            return text[:-1] if text.endswith("\n") else text
        raise ContractError("unsupported_reference", where, f"{scheme}: references are resolved by the scanner node")

    def _resolve_file(self, ref: str, *, where: str) -> Path:
        if self.base_dir is None:
            raise ContractError("unresolved_reference", where, "the plan has no run directory")
        relpath = ref.partition(":")[2]
        base = self.base_dir.resolve()
        try:
            target = (base / relpath).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ContractError("unresolved_reference", where, f"{relpath} does not exist in the run directory") from exc
        if not target.is_relative_to(base):
            raise ContractError("reference_outside_run_dir", where, relpath)
        return target


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _reject_foreign_fields(doc: Mapping[str, Any], kind: str, fields: tuple[_Field, ...]) -> None:
    """A field the kind does not consume is an error, never silently dropped."""
    allowed_paths = {spec.path for spec in fields}
    allowed_sections = {spec.path[0] for spec in fields}
    for section, value in doc.items():
        if section in ("schema", "kind", "run_id"):
            continue
        if section not in allowed_sections:
            raise ContractError("section_not_allowed", f"/{section}", f"{kind} plans do not use '{section}'")
        if isinstance(value, Mapping):
            for key in value:
                if (section, key) not in allowed_paths:
                    raise ContractError("section_not_allowed", f"/{section}/{key}", f"{kind} plans do not use it")


def _normalise_plan_value(spec: _Field, value: Any) -> Any:
    """Return the canonical form of one plan value, ``None`` when it is a default."""
    if spec.explicit:
        return spec.default if value is None or value == "" else value
    if value is None:
        return None
    if spec.kind == _BOOL:
        return None if value == spec.default else value
    if spec.kind == _CSV:
        return _csv_to_list(value) or None
    if spec.kind == _DOMAINS:
        return _domain_list(value) or None
    if spec.kind == _SLUGS:
        slugs = _slugs(value)
        return None if slugs is None or slugs == spec.default else slugs
    if spec.kind == _SCAN_CONFIG:
        return _canonical_scan_config(value, where=_pointer(spec.path))
    if spec.kind == _PACING_SET:
        return _canonical_pacing_set(value, where=_pointer(spec.path))
    if spec.kind in (_SECRET, _ASSET):
        return {"ref": value["ref"]}
    if value == spec.default or value == "":
        return None
    return value


def _plan_value_from_namespace(
    spec: _Field, ns: argparse.Namespace, *, run_dir: Optional[Path], staged: list[Path]
) -> Any:
    if spec.kind == _SCAN_CONFIG:
        return _scan_config_from_namespace(ns)
    value = getattr(ns, spec.dest, None)
    if value is None or value == "":
        return None
    if spec.kind == _SECRET:
        return {"ref": _stage_secret(str(value), run_dir=run_dir, where=_pointer(spec.path), staged=staged)}
    if spec.kind == _ASSET:
        return {"ref": _stage_asset(str(value), run_dir=run_dir, where=_pointer(spec.path))}
    if spec.kind == _CSV:
        return _csv_to_list(value) or None
    if spec.kind == _DOMAINS:
        return _domain_list(value) or None
    if spec.kind == _PACING_SET:
        return _canonical_pacing_set(value, where=_pointer(spec.path))
    return value


def _canonical_pacing_set(value: Any, *, where: str) -> Optional[list[str]]:
    """Validate ``--pacing-set`` items into their canonical ``KNOB=VALUE`` list."""
    from adscan_core.scan_pacing import PacingConfigError  # noqa: PLC0415
    from adscan_internal.services.scan_controls import canonical_pacing_assignments  # noqa: PLC0415

    items = [value] if isinstance(value, str) else list(value or ())
    try:
        return canonical_pacing_assignments(items) or None
    except PacingConfigError as exc:
        raise ContractError("invalid_pacing", where, str(exc)) from exc


def _domain_list(value: Any) -> list[str]:
    """Normalise a domain list exactly as the doctor parser does (lowercase, dedupe)."""
    from adscan_internal.cli.doctor import _parse_trust_domains  # noqa: PLC0415

    raw = value if isinstance(value, str) else ",".join(str(item) for item in value)
    return list(_parse_trust_domains(raw))


def _scan_config_from_namespace(ns: argparse.Namespace) -> Any:
    """Fold ``--scan-config`` (or the launcher's ``ADSCAN_SCAN_CONFIG``) into the plan."""
    from adscan_internal.services.scan_config import ScanConfigError, load_scan_config  # noqa: PLC0415

    data = getattr(ns, "scan_config_data", None)
    if isinstance(data, Mapping):
        return dict(data)
    path = getattr(ns, "scan_config", None) or os.environ.get("ADSCAN_SCAN_CONFIG") or ""
    if not path:
        return None
    try:
        return scan_config_to_plan(load_scan_config(path))
    except ScanConfigError as exc:
        raise ContractError("invalid_scan_config", "/scan/scan_config", str(exc)) from exc


def _require_run_dir(run_dir: Optional[Path], where: str, what: str) -> Path:
    if run_dir is None:
        raise ContractError(
            "not_representable", where, f"{what} must be staged in a run directory to be referenced"
        )
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def _discard_paths(paths: Any) -> None:
    """Unlink staged secret files and remove their ``secrets/`` directory when empty."""
    for path in paths or ():
        try:
            Path(path).unlink(missing_ok=True)
        except OSError:
            continue
        parent = Path(path).parent
        if parent.name == _SECRETS_DIR:
            try:
                parent.rmdir()
            except OSError:
                pass  # not empty, or already gone


def _stage_secret(value: str, *, run_dir: Optional[Path], where: str, staged: list[Path]) -> str:
    """Write a flag-supplied secret to a 0600 file in the run directory; return its reference.

    The write never follows or replaces anything already in place: a symlinked or
    non-directory ``secrets/`` and any existing ``secrets/password`` (a file or a
    planted symlink) are refused, and the file is created with
    ``O_CREAT|O_EXCL|O_NOFOLLOW``. Refused on Windows, where 0600 has no
    equivalent without an ACL API: point the plan at an ``env:`` reference there.
    """
    from adscan_core.pal.platform import is_windows  # noqa: PLC0415

    if is_windows():
        raise ContractError(
            "not_supported",
            where,
            "staging a secret file is not supported on Windows; reference an environment variable (env:NAME)",
        )
    base = _require_run_dir(run_dir, where, "a password")
    secrets_dir = base / _SECRETS_DIR
    if secrets_dir.is_symlink() or (secrets_dir.exists() and not secrets_dir.is_dir()):
        raise ContractError("unsafe_staging", where, f"{_SECRETS_DIR}/ is not a plain directory")
    secrets_dir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(secrets_dir, 0o700)
    target = secrets_dir / _PASSWORD_FILE
    if target.is_symlink() or target.exists():
        raise ContractError("unsafe_staging", where, f"{_SECRETS_DIR}/{_PASSWORD_FILE} already exists")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags, 0o600)
    except FileExistsError as exc:
        raise ContractError("unsafe_staging", where, f"{_SECRETS_DIR}/{_PASSWORD_FILE} already exists") from exc
    staged.append(target)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(value)
    return f"file:{_SECRETS_DIR}/{_PASSWORD_FILE}"


def _safe_asset_name(name: str) -> str:
    cleaned = "".join(ch if (ch.isalnum() or ch in "._-") else "_" for ch in name)
    cleaned = cleaned.lstrip(".") or "asset"
    return cleaned


def _stage_asset(value: str, *, run_dir: Optional[Path], where: str) -> str:
    """Copy a host file or directory into the run directory; return its reference."""
    source = Path(value).expanduser()
    if not source.exists():
        raise ContractError("unresolved_reference", where, f"{value} does not exist")
    base = _require_run_dir(run_dir, where, "an input file")
    assets_dir = base / _ASSETS_DIR
    assets_dir.mkdir(exist_ok=True)
    name = _safe_asset_name(source.name)
    target = assets_dir / name
    if source.resolve() != target.resolve():
        if source.is_dir():
            shutil.copytree(source, target, dirs_exist_ok=True)
        else:
            shutil.copyfile(source, target)
    return f"file:{_ASSETS_DIR}/{name}"


# --------------------------------------------------------------------------- #
# ``adscan run``
# --------------------------------------------------------------------------- #


def add_run_subparser(subparsers: Any) -> argparse.ArgumentParser:
    """Register the container ``run`` subparser.

    Module-level and importable so the launcher pass-through SSOT
    (``adscan_core.cli_passthrough_spec.RUN_PASSTHROUGH``) is locked against it.
    """
    parser = subparsers.add_parser(
        "run",
        help="Run one engine plan (adscan.run_plan/1): a scan, a validation or a deliverable kit.",
        description=(
            "Run the engine from a RunPlan file (schema adscan.run_plan/1).\n\n"
            "The plan names the run kind (scan, doctor, deliver), the target and "
            "the options; credentials are references (env:NAME or file:<path> "
            "relative to the plan's directory), never values. The same run can "
            "be described with `adscan ci`, `adscan doctor` or `adscan deliver` "
            "flags; both descriptions execute the same code."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--plan",
        required=True,
        metavar="FILE",
        help="RunPlan JSON file. Its directory is the run directory file: references resolve against.",
    )
    parser.add_argument(
        "--events-file",
        dest="events_file",
        default=None,
        metavar="FILE",
        help="Append the versioned event stream (adscan.events/1) to FILE, one JSON line per event.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output.")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode.")
    parser.add_argument("--dev", action="store_true", help=argparse.SUPPRESS)
    return parser


def _is_pro_tier() -> bool:
    from adscan_core.tier import is_pro  # noqa: PLC0415

    return bool(is_pro())


@contextmanager
def _scoped_env(overrides: Mapping[str, Optional[str]]) -> Iterator[None]:
    """Apply environment overrides for the run and restore them afterwards."""
    saved = {key: os.environ.get(key) for key in overrides}
    try:
        for key, value in overrides.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _report_plan_error(prefix: str, exc: ContractError) -> None:
    from rich.markup import escape  # noqa: PLC0415

    from adscan_core.rich_output import print_error  # noqa: PLC0415

    detail = f" ({exc.detail})" if exc.detail else ""
    print_error(escape(f"{prefix}: {exc.code} at {exc.path or '/'}{detail}"))


def run_plan_command(
    args: argparse.Namespace,
    *,
    handlers: Mapping[str, Callable[[argparse.Namespace], Any]],
    on_command_resolved: Optional[Callable[[str], None]] = None,
) -> int:
    """Execute ``adscan run --plan``. Returns the process exit code.

    Args:
        args: The parsed ``run`` namespace.
        handlers: ``kind -> handler(namespace) -> exit code``; the legacy
            command handlers, so a plan run executes the same code as its flags.
        on_command_resolved: Called with the legacy command name once the plan is
            valid and allowed, so the caller can label the session.

    Exit codes: ``2`` for an invalid or unrunnable plan, ``42`` (with the
    ``pro_required`` JSON line) when the kind needs the paid tier, otherwise the
    handler's own code.
    """
    try:
        plan = RunPlan.from_file(Path(args.plan))
    except ContractError as exc:
        _report_plan_error("Invalid run plan", exc)
        return 2

    if plan.kind not in RUNNABLE_KINDS or plan.kind not in handlers:
        from adscan_core.rich_output import print_error  # noqa: PLC0415

        print_error(f"Run kind '{plan.kind}' is not supported by this engine version.")
        return 2

    command = KIND_COMMAND[plan.kind]
    from adscan_core.cli_catalog import is_pro_only  # noqa: PLC0415

    if is_pro_only(command) and not _is_pro_tier():
        import sys  # noqa: PLC0415

        print(json.dumps({"error": "pro_required", "feature": command}))
        sys.stdout.flush()
        return 42

    try:
        namespace = plan.to_namespace(
            verbose=bool(getattr(args, "verbose", False)),
            debug=bool(getattr(args, "debug", False)),
            dev=bool(getattr(args, "dev", False)),
        )
    except ContractError as exc:
        _report_plan_error("Run plan could not be prepared", exc)
        return 2

    run_id = plan.run_id or os.environ.get(RUN_ID_ENV) or uuid.uuid4().hex
    overrides: dict[str, Optional[str]] = {RUN_ID_ENV: run_id, RUN_KIND_ENV: plan.kind}
    events_file = getattr(args, "events_file", None)
    if events_file:
        overrides[EVENTS_FILE_ENV] = str(Path(events_file))
    if _get(plan.document, ("scan", "show_structural")):
        overrides["ADSCAN_SHOW_STRUCTURAL"] = "1"

    if on_command_resolved is not None:
        on_command_resolved(command)
    with _scoped_env(overrides):
        return _run_with_lifecycle(plan.kind, handlers[plan.kind], namespace)


def _run_status_for_exit(kind: str, exit_code: int) -> str:
    """``completed`` or ``failed`` for a run that ended with ``exit_code``.

    A scan whose deliverable did not render (``CI_EXIT_DELIVERABLE_FAILED``)
    still completed: its results stand and the kit can be rendered again.
    """
    from adscan_core.ci_exit_codes import scan_results_stand  # noqa: PLC0415

    if kind == "scan":
        return "completed" if scan_results_stand(exit_code) else "failed"
    return "completed" if exit_code == 0 else "failed"


def _run_with_lifecycle(kind: str, handler: Callable[[argparse.Namespace], Any], ns: argparse.Namespace) -> int:
    """Run ``handler`` between ``run_started`` and ``run_completed`` events.

    After the handler returns (and so after its ``do_exit`` restored the host
    clock and NTP), the run summary and artifact manifest are written for the
    workspace the handler noted, never for one it removed. ``run_completed`` is
    emitted on every exit, a handler's ``sys.exit`` and an operator interrupt
    (including one while the results are written) included; the versioned file
    stream is closed afterwards.
    """
    from adscan_internal.cli import ci_events  # noqa: PLC0415
    from adscan_internal.services.engagement import run_summary  # noqa: PLC0415

    run_summary.reset_last_result_path()
    ci_events.emit_run_started(kind=kind)
    status = "failed"
    exit_code = 1
    try:
        exit_code = int(handler(ns) or 0)
        status = _run_status_for_exit(kind, exit_code)
        return exit_code
    except SystemExit as exc:
        code = exc.code
        exit_code = code if isinstance(code, int) else (0 if code is None else 1)
        status = _run_status_for_exit(kind, exit_code)
        raise
    except KeyboardInterrupt:
        status, exit_code = "interrupted", 130
        raise
    finally:
        try:
            if status != "interrupted":
                run_summary.finalize_noted_run(kind=kind, status=status)
        except KeyboardInterrupt:
            status, exit_code = "interrupted", 130
            raise
        finally:
            ci_events.emit_run_completed(
                kind=kind,
                status=status,
                exit_code=exit_code,
                result_path=run_summary.last_result_path(),
            )
            ci_events.reset_event_file_stream()


__all__ = (
    "EVENTS_FILE_ENV",
    "KIND_COMMAND",
    "PLAN_SCHEMA_TAG",
    "RUNNABLE_KINDS",
    "RUN_ID_ENV",
    "RUN_KIND_ENV",
    "RunPlan",
    "add_run_subparser",
    "run_plan_command",
    "scan_config_to_plan",
)
