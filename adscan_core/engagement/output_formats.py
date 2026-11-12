"""Versions of the files a scan writes to its workspace: the output contract.

Partners and clients ingest the files a scan leaves in its workspace, exactly as
ADscan's own web platform does. This module is the single place that says which
version of each file the engine writes. Every writer stamps its file's version
marker from :func:`output_marker`, and the JSON Schema that describes the file
ships beside the engine contract schemas as
``adscan_core/engagement/schemas/<name>.v<major>.json`` (loaded and validated by
:mod:`adscan_core.engagement.contract`).

Version semantics (the same for every file):

* ``major`` changes when a reader written for the previous version could break:
  a field removed, renamed or retyped, a meaning changed, an optional field made
  required, a closed enum narrowed. A new major ships a NEW schema file, and the
  previous major's schema stays in the package for the deprecation window
  (:data:`DEPRECATION_WINDOW`), so a reader can still validate older files.
* ``minor`` changes for an additive change a reader may ignore: a new optional
  field, a new block, a new value in an open vocabulary. The schema file of the
  major is updated in place and keeps validating every older minor of it, so an
  integrator pinned to a major never has to change anything.

The marker is the ``schema_version`` field at the root of the file. Its value is
``<prefix><major>.<minor>``; the prefix exists only for the two families that
already shipped with one (``inventory-1.0``, ``membership-1.0``), kept so no
existing reader breaks. The engagement documents (``coverage.json``,
``events``, ``run_summary``, ...) keep their own ``schema`` tag
(``adscan.<name>/<major>``, :func:`adscan_core.engagement.contract.schema_tag`);
both families name their schema with the same identifier,
``adscan.<name>/<major>`` (:attr:`OutputFormat.schema_id`), which is the
schema's ``$id``.

One registered format is not a workspace file: ``license_register`` is the
output of ``adscan license register export`` (the PRO licence reconciliation
file a partner reads), versioned the same way.

Every change to a format bumps its version here, updates its schema in the same
change, and adds a line to the ``### Output format`` subsection of the release
in ``CHANGELOG.md``. ``tests/unit/contracts/test_output_contract.py`` fails when
any of the three is missing.

Dependency-light by contract: stdlib only (the web backend imports it).
"""

from __future__ import annotations

from dataclasses import dataclass

#: Root field carrying the version marker of every output file.
SCHEMA_VERSION_KEY = "schema_version"

#: How long a previous major stays readable after a breaking change, stated to
#: integrators in the release notes: the next two minor engine releases or 90
#: days, whichever is longer.
DEPRECATION_WINDOW = "two minor engine releases or 90 days, whichever is longer"


@dataclass(frozen=True)
class OutputFormat:
    """One versioned workspace file family.

    Attributes:
        name: Schema name; the schema file is ``<name>.v<major>.json``.
        major: Breaking-change counter.
        minor: Additive-change counter.
        files: Workspace-relative glob(s) the format applies to.
        marker_prefix: Literal prefix of the marker value (legacy families only).
        has_marker: ``False`` for a file whose root cannot carry a marker today
            (a JSON array). Its schema is still published and contract-tested.
        display: How the release notes name the file when the file name alone
            is ambiguous.
    """

    name: str
    major: int
    minor: int
    files: tuple[str, ...]
    marker_prefix: str = ""
    has_marker: bool = True
    display: str = ""

    @property
    def version(self) -> str:
        """``<major>.<minor>``."""
        return f"{self.major}.{self.minor}"

    @property
    def marker(self) -> str:
        """The exact value the writer stamps into ``schema_version``."""
        return f"{self.marker_prefix}{self.version}"

    @property
    def schema_id(self) -> str:
        """The schema's identifier, ``adscan.<name>/<major>``."""
        return f"adscan.{self.name}/{self.major}"

    @property
    def label(self) -> str:
        """How the release notes name the file (``attack_graph.json``, ``inventory/*.json``)."""
        if self.display:
            return self.display
        parts = self.files[0].split("/")
        return "/".join(parts[-2:]) if parts[-1].startswith("*") else parts[-1]

    @property
    def schema_filename(self) -> str:
        """The schema file shipped under ``adscan_core/engagement/schemas/``."""
        return f"{self.name}.v{self.major}.json"


#: The output contract, one entry per file family. Bump here, never at a writer.
OUTPUT_FORMATS: dict[str, OutputFormat] = {
    fmt.name: fmt
    for fmt in (
        OutputFormat("technical_report", 2, 4, ("technical_report.json",)),
        OutputFormat("attack_graph", 1, 2, ("domains/*/attack_graph.json",)),
        OutputFormat("attack_paths_snapshot", 1, 1, ("domains/*/attack_paths_snapshot.json",)),
        OutputFormat("environment_changes", 1, 1, ("environment_changes.json",)),
        OutputFormat("scan_summary", 1, 0, ("scan_summary.json",)),
        OutputFormat(
            "inventory", 1, 0, ("domains/*/inventory/*.json",), marker_prefix="inventory-"
        ),
        OutputFormat(
            "memberships", 1, 0, ("domains/*/memberships.json",), marker_prefix="membership-"
        ),
        OutputFormat(
            "license_register",
            1,
            0,
            ("license register export",),
            display="adscan license register export",
        ),
        OutputFormat(
            "unauth_users",
            1,
            0,
            ("domains/*/users.json",),
            has_marker=False,
            display="domains/<domain>/users.json",
        ),
    )
}

#: Schema names of the output contract, in declaration order.
OUTPUT_SCHEMA_NAMES: tuple[str, ...] = tuple(OUTPUT_FORMATS)


def output_format(name: str) -> OutputFormat:
    """Return the registered format ``name``.

    Raises:
        KeyError: ``name`` is not an output format.
    """
    return OUTPUT_FORMATS[name]


def output_marker(name: str) -> str:
    """Return the ``schema_version`` value the writer of ``name`` stamps."""
    fmt = OUTPUT_FORMATS[name]
    if not fmt.has_marker:
        raise ValueError(f"{name} carries no version marker")
    return fmt.marker


def is_readable_marker(name: str, value: object) -> bool:
    """Whether a persisted ``schema_version`` is a format this build reads.

    Every minor of the current major is readable: a minor only adds fields, so
    a reader that rejected a newer or older minor would throw away a valid file
    (for a ledger, a session's record of what it changed). A different major,
    a foreign prefix or a missing marker is not.
    """
    fmt = OUTPUT_FORMATS[name]
    if not isinstance(value, str) or not value.startswith(fmt.marker_prefix):
        return False
    major, _, minor = value[len(fmt.marker_prefix) :].partition(".")
    return major == str(fmt.major) and minor.isdigit()


__all__ = (
    "DEPRECATION_WINDOW",
    "is_readable_marker",
    "OUTPUT_FORMATS",
    "OUTPUT_SCHEMA_NAMES",
    "OutputFormat",
    "SCHEMA_VERSION_KEY",
    "output_format",
    "output_marker",
)
