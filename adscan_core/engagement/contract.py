"""Engine contract v1: the JSON Schemas and a small stdlib validator.

The engine contract is what an orchestrator (the appliance's Celery worker, a
scanner node, an OEM consumer) exchanges with the engine:

* ``run_plan`` (``adscan.run_plan/1``): what to run. Credentials only by
  reference, never inline, so a plan can be logged, stored and signed.
* ``events`` (``adscan.events/1``): one JSON object per line, the first a
  ``stream_header``, each carrying a contiguous ``seq``.
* ``run_summary`` (``adscan.run_summary/1``): the metadata projection of a run
  (counts, ratios and closed enums only; no identifier).
* ``artifact_manifest`` (``adscan.artifact_manifest/1``): every artifact the
  run left in its workspace, with its egress class.
* ``coverage`` (``adscan.coverage/1``): which checks ran on which scope, the
  record that decides what a run may close.
* ``recheck_result`` (``adscan.recheck_result/1``): what one ``adscan recheck``
  run decided per item, what it read and where a walk went (also what
  ``adscan recheck --json`` prints).

The same loader and validator serve the **output contract**: the files a scan
writes to its workspace (``technical_report.json``, ``attack_graph.json``,
``inventory/*.json`` ...), whose versions live in
:mod:`adscan_core.engagement.output_formats`. Their schemas sit beside these as
``<name>.v<major>.json``, each at its own major.

Two conventions tell a declared object from a free-form one, and
:func:`undeclared_fields` enforces them in the contract tests:

* an object schema with ``properties`` DECLARES its fields. A key outside them
  is undeclared unless ``additionalProperties`` is ``true`` (free-form
  extension) or a schema (a map, e.g. keyed by domain). An output schema leaves
  ``additionalProperties`` unset on declared objects, so a reader validating an
  older schema still accepts a newer minor's additive field, while the
  contract test still fails when the engine writes a field the schema does not
  declare.
* an object schema without ``properties`` is opaque (``details``, ``notes``,
  ``properties``): its content is not frozen by the contract.

The schemas are JSON files under ``schemas/`` so non-Python consumers read the
same documents. This module validates against the subset of JSON Schema
(draft 2020-12) those files use: ``type``, ``const``, ``enum``, ``required``,
``properties``, ``additionalProperties`` (boolean or schema), ``pattern``,
``items``, ``minimum``, ``maximum``, ``minLength``, ``maxLength``,
``maxItems``, ``oneOf``, ``not`` and local ``$ref`` (``#/$defs/<name>``). A
keyword outside that set is a programming error and raises at load time, so a
schema can never carry a constraint this validator silently ignores.

Dependency-light by contract: stdlib only. The web backend, the launcher and
the node service import this module.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from importlib.resources import files
from typing import Any, Mapping

from adscan_core.engagement.output_formats import OUTPUT_FORMATS, OUTPUT_SCHEMA_NAMES

#: The contract's documents, in the order the specification lists them.
SCHEMA_NAMES: tuple[str, ...] = (
    "run_plan",
    "events",
    "run_summary",
    "artifact_manifest",
    "observations",
    "ledger",
    "coverage",
    "recheck_result",
)

#: Major version of every v1 document. Additive fields only within a major.
CONTRACT_MAJOR = 1

#: Every schema this module can load: the engine contract, then the output contract.
KNOWN_SCHEMA_NAMES: tuple[str, ...] = SCHEMA_NAMES + OUTPUT_SCHEMA_NAMES

_SUPPORTED_KEYWORDS = frozenset(
    {
        "$schema",
        "$id",
        "$defs",
        "$ref",
        "$comment",
        "title",
        "description",
        "type",
        "const",
        "enum",
        "required",
        "properties",
        "additionalProperties",
        "pattern",
        "items",
        "minimum",
        "maximum",
        "minLength",
        "maxLength",
        "maxItems",
        "oneOf",
        "not",
    }
)

_JSON_TYPES: dict[str, tuple[type, ...]] = {
    "object": (dict,),
    "array": (list, tuple),
    "string": (str,),
    "boolean": (bool,),
    "null": (type(None),),
}


class ContractError(ValueError):
    """A document does not satisfy its contract schema.

    Attributes:
        code: Machine-readable reason (``additional_property``, ``required``,
            ``type``, ``enum``, ``const``, ``pattern``, ``minimum``,
            ``maximum``, ``min_length``, ``max_length``, ``max_items``,
            ``one_of``, ``not``, ``unknown_schema``), or a normaliser code such
            as ``not_representable``.
        path: JSON Pointer to the offending location (``""`` is the root).
    """

    def __init__(self, code: str, path: str, detail: str = "") -> None:
        self.code = code
        self.path = path
        self.detail = detail
        message = f"{code} at {path or '/'}"
        if detail:
            message = f"{message}: {detail}"
        super().__init__(message)


def schema_tag(name: str) -> str:
    """Return the version tag a document of ``name`` carries in ``schema``."""
    return f"adscan.{name}/{CONTRACT_MAJOR}"


def schema_major(name: str) -> int:
    """Return the major version of the schema ``name`` (engine or output contract)."""
    if name in OUTPUT_FORMATS:
        return OUTPUT_FORMATS[name].major
    return CONTRACT_MAJOR


def schema_id(name: str) -> str:
    """Return the identifier of the schema ``name``, ``adscan.<name>/<major>``."""
    return f"adscan.{name}/{schema_major(name)}"


@lru_cache(maxsize=None)
def _load_schema_text(name: str) -> str:
    resource = files("adscan_core.engagement") / "schemas" / f"{name}.v{schema_major(name)}.json"
    return resource.read_text(encoding="utf-8")


def load_schema(name: str) -> dict[str, Any]:
    """Return a fresh copy of the JSON Schema for ``name``.

    Raises:
        ContractError: ``unknown_schema`` when ``name`` is neither an engine
            contract document nor an output-contract file.
    """
    if name not in KNOWN_SCHEMA_NAMES:
        raise ContractError("unknown_schema", "", name)
    schema = json.loads(_load_schema_text(name))
    _check_keywords(schema, "#")
    return schema


@lru_cache(maxsize=None)
def _cached_schema(name: str) -> dict[str, Any]:
    return load_schema(name)


def _check_keywords(node: Any, where: str) -> None:
    """Fail loud on a schema keyword the validator does not implement."""
    if not isinstance(node, dict):
        return
    unknown = set(node) - _SUPPORTED_KEYWORDS
    if unknown:
        raise AssertionError(f"unsupported JSON Schema keyword(s) {sorted(unknown)} at {where}")
    for key in ("properties", "$defs"):
        for child_name, child in (node.get(key) or {}).items():
            _check_keywords(child, f"{where}/{key}/{child_name}")
    for key in ("items", "not", "additionalProperties"):
        if isinstance(node.get(key), dict):
            _check_keywords(node[key], f"{where}/{key}")
    for index, child in enumerate(node.get("oneOf") or ()):
        _check_keywords(child, f"{where}/oneOf/{index}")


def validate(schema_name: str, doc: Any) -> None:
    """Validate ``doc`` against the contract schema ``schema_name``.

    Args:
        schema_name: One of :data:`KNOWN_SCHEMA_NAMES`.
        doc: The parsed JSON document (an object, or an array for a list-rooted file).

    Raises:
        ContractError: On the first violation found, with its code and path.
    """
    schema = _cached_schema(schema_name)
    _validate_node(doc, schema, schema, "")


def is_valid(schema_name: str, doc: Any) -> bool:
    """Return whether ``doc`` satisfies ``schema_name`` (never raises for a bad doc)."""
    try:
        validate(schema_name, doc)
    except ContractError as exc:
        if exc.code == "unknown_schema":
            raise
        return False
    return True


def _resolve_ref(root: Mapping[str, Any], ref: str) -> Mapping[str, Any]:
    prefix = "#/$defs/"
    if not ref.startswith(prefix):
        raise AssertionError(f"only local $defs references are supported, got {ref}")
    return root["$defs"][ref[len(prefix) :]]


def _type_matches(value: Any, expected: str) -> bool:
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, _JSON_TYPES[expected])


def _pointer(path: str, token: Any) -> str:
    text = str(token).replace("~", "~0").replace("/", "~1")
    return f"{path}/{text}"


def _validate_node(value: Any, schema: Mapping[str, Any], root: Mapping[str, Any], path: str) -> None:
    if "$ref" in schema:
        _validate_node(value, _resolve_ref(root, schema["$ref"]), root, path)
        return

    expected = schema.get("type")
    if expected is not None:
        options = expected if isinstance(expected, list) else [expected]
        if not any(_type_matches(value, option) for option in options):
            raise ContractError("type", path, f"expected {'|'.join(options)}")

    if "const" in schema and value != schema["const"]:
        raise ContractError("const", path)
    if "enum" in schema and value not in schema["enum"]:
        raise ContractError("enum", path)

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise ContractError("min_length", path)
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise ContractError("max_length", path)
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            raise ContractError("pattern", path)

    if _type_matches(value, "number"):
        if "minimum" in schema and value < schema["minimum"]:
            raise ContractError("minimum", path)
        if "maximum" in schema and value > schema["maximum"]:
            raise ContractError("maximum", path)

    if isinstance(value, dict):
        _validate_object(value, schema, root, path)

    if isinstance(value, (list, tuple)):
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise ContractError("max_items", path)
        if isinstance(schema.get("items"), dict):
            for index, item in enumerate(value):
                _validate_node(item, schema["items"], root, _pointer(path, index))

    if "not" in schema:
        try:
            _validate_node(value, schema["not"], root, path)
        except ContractError:
            pass
        else:
            raise ContractError("not", path)

    if "oneOf" in schema:
        _validate_one_of(value, schema["oneOf"], root, path)


def _validate_object(
    value: Mapping[str, Any], schema: Mapping[str, Any], root: Mapping[str, Any], path: str
) -> None:
    # Unknown keys are reported before missing ones: a document carrying an
    # inline ``password`` where a ``secret`` reference belongs is a forbidden
    # field first and an incomplete one second, and the first is the finding.
    properties = schema.get("properties", {})
    additional = schema.get("additionalProperties", True)
    if additional is False:
        for key in value:
            if key not in properties:
                raise ContractError("additional_property", _pointer(path, key))
    for key in schema.get("required", ()):
        if key not in value:
            raise ContractError("required", _pointer(path, key))
    for key, child in value.items():
        if key in properties:
            _validate_node(child, properties[key], root, _pointer(path, key))
        elif isinstance(additional, dict):
            _validate_node(child, additional, root, _pointer(path, key))


def _validate_one_of(value: Any, options: list[Mapping[str, Any]], root: Mapping[str, Any], path: str) -> None:
    """Exactly one branch must match; report the closest branch's error otherwise.

    "Closest" is the branch whose error sits deepest in the document, which is
    the branch the author meant: a ``scan_started`` event with a bad field fails
    inside its own branch, deeper than the ``const`` mismatch every other
    branch raises at ``/type``.
    """
    matches = 0
    deepest: ContractError | None = None
    for option in options:
        try:
            _validate_node(value, option, root, path)
        except ContractError as exc:
            if deepest is None or exc.path.count("/") > deepest.path.count("/"):
                deepest = exc
        else:
            matches += 1
    if matches == 1:
        return
    if matches == 0 and deepest is not None:
        raise deepest
    raise ContractError("one_of", path, f"{matches} branches matched")


def undeclared_fields(schema_name: str, doc: Any) -> list[str]:
    """Return JSON Pointers to every key ``doc`` carries that ``schema_name`` does not declare.

    Applies the declared-object convention in the module docstring. ``doc`` must
    already be valid (call :func:`validate` first): a ``oneOf`` is resolved to
    the branch the document matches.
    """
    schema = _cached_schema(schema_name)
    out: list[str] = []
    _collect_undeclared(doc, schema, schema, "", out)
    return out


def _collect_undeclared(
    value: Any, schema: Mapping[str, Any], root: Mapping[str, Any], path: str, out: list[str]
) -> None:
    if "$ref" in schema:
        _collect_undeclared(value, _resolve_ref(root, schema["$ref"]), root, path, out)
        return
    for option in schema.get("oneOf") or ():
        try:
            _validate_node(value, option, root, path)
        except ContractError:
            continue
        _collect_undeclared(value, option, root, path, out)
        break
    if isinstance(value, dict):
        properties = schema.get("properties")
        additional = schema.get("additionalProperties")
        for key, child in value.items():
            pointer = _pointer(path, key)
            if properties is not None and key in properties:
                _collect_undeclared(child, properties[key], root, pointer, out)
            elif isinstance(additional, dict):
                _collect_undeclared(child, additional, root, pointer, out)
            elif properties is not None and additional is not True:
                out.append(pointer)
    if isinstance(value, (list, tuple)) and isinstance(schema.get("items"), dict):
        for index, item in enumerate(value):
            _collect_undeclared(item, schema["items"], root, _pointer(path, index), out)


__all__ = (
    "CONTRACT_MAJOR",
    "KNOWN_SCHEMA_NAMES",
    "SCHEMA_NAMES",
    "ContractError",
    "is_valid",
    "load_schema",
    "schema_id",
    "schema_major",
    "schema_tag",
    "undeclared_fields",
    "validate",
)
