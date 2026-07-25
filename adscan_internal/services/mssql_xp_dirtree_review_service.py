"""Low-privilege MSSQL filesystem/credential-hygiene review via ``xp_dirtree``.

``xp_dirtree`` (and its siblings ``xp_fileexist`` / ``xp_subdirs``) are, by
default, EXECUTE-granted to the ``public`` server role -- every authenticated
database login, even one with zero server roles and no command-execution
surface, can walk the SQL service account's filesystem view this way. This
module is the pure-logic half of the review: parsing the capability probe,
reconstructing absolute paths from ``xp_dirtree``'s depth-based rows, and
building the SAME manifest shape :class:`WindowsFileMappingService` produces
so the existing credential-hygiene analysis pipeline (credsweeper_service,
loot_credential_analysis_service, spidering_service,
``WindowsFileMappingService.select_entries_by_extensions``) consumes it
unchanged, regardless of which transport discovered the files.

Reports one of three honest states, mirroring the report's
exploited/partial/closed doctrine (see CLAUDE.md
"Exposure Validation, NOT Security Validation"):

  * ``closed_by_configuration`` -- EXECUTE on ``xp_dirtree`` is revoked from
    this login. A POSITIVE, observed hardening fact.
  * ``granted_exposure`` -- EXECUTE is granted AND the review surfaced at
    least one file entry: an open low-privilege filesystem-read avenue the
    client should close, regardless of whether a credential was found in it.
  * ``granted_hardening_note`` -- EXECUTE is granted but nothing was found: a
    hardening recommendation, not an exploited finding.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from typing import Any, Iterable

from adscan_internal.services.smb_sensitive_file_policy import (
    resolve_effective_sensitive_extension,
)
from adscan_internal.services.windows_file_mapping_service import (
    WindowsFileMapEntry,
    WindowsFileMappingService,
)

# ---------------------------------------------------------------------------
# Capability classification
# ---------------------------------------------------------------------------

#: Extended stored procedures probed for EXECUTE grant. ``xp_dirtree`` is the
#: one actually used to walk the filesystem; the other two are supplementary
#: signals surfaced for reporting completeness.
XP_DIRTREE_PROCEDURES: tuple[str, ...] = ("xp_dirtree", "xp_fileexist", "xp_subdirs")

STATUS_CLOSED_BY_CONFIGURATION = "closed_by_configuration"
STATUS_GRANTED_EXPOSURE = "granted_exposure"
STATUS_GRANTED_HARDENING_NOTE = "granted_hardening_note"


def _row_get_ci(row: dict, key: str) -> Any:
    """Case-insensitive dict lookup for one T-SQL result row.

    Column-name casing returned by the TDS driver is not guaranteed to match
    the alias exactly as authored in the query -- the same lesson as the
    case-insensitive LDAP attribute read fix: never trust exact key casing
    from a remote protocol result set.
    """
    if key in row:
        return row[key]
    lowered = key.strip().lower()
    for existing_key, value in row.items():
        if str(existing_key).strip().lower() == lowered:
            return value
    return None


@dataclass(frozen=True, slots=True)
class XpDirtreeCapabilitySignals:
    """Per-procedure EXECUTE-grant signals for the current MSSQL login."""

    xp_dirtree: bool
    xp_fileexist: bool
    xp_subdirs: bool

    @property
    def can_walk(self) -> bool:
        """Return True when the login can drive a directory walk (``xp_dirtree``)."""
        return self.xp_dirtree


def parse_xp_dirtree_capability_rows(
    rows: Iterable[dict],
) -> XpDirtreeCapabilitySignals:
    """Parse ``XP_DIRTREE_CAPABILITY_PROBE`` query rows into capability signals."""
    granted: set[str] = set()
    for row in rows:
        proc_name = str(_row_get_ci(row, "proc_name") or "").strip().lower()
        if proc_name:
            granted.add(proc_name)
    return XpDirtreeCapabilitySignals(
        xp_dirtree="xp_dirtree" in granted,
        xp_fileexist="xp_fileexist" in granted,
        xp_subdirs="xp_subdirs" in granted,
    )


def classify_xp_dirtree_review_outcome(
    *, capability: XpDirtreeCapabilitySignals, found_any_entries: bool
) -> str:
    """Classify the low-privilege file-review outcome into one honest state.

    See the module docstring for the three states. The classification is
    driven by ``xp_dirtree`` specifically (the walk-capable procedure);
    ``xp_fileexist``/``xp_subdirs`` are supplementary signals surfaced on
    :class:`XpDirtreeCapabilitySignals` for completeness/reporting but do
    not change this outcome.
    """
    if not capability.can_walk:
        return STATUS_CLOSED_BY_CONFIGURATION
    if found_any_entries:
        return STATUS_GRANTED_EXPOSURE
    return STATUS_GRANTED_HARDENING_NOTE


# ---------------------------------------------------------------------------
# Path reconstruction -- xp_dirtree rows carry names + depth, not full paths
# ---------------------------------------------------------------------------


def _coerce_xp_dirtree_bit(value: Any) -> bool:
    """Coerce an ``xp_dirtree`` ``file`` bit column to bool, tolerant of driver quirks."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value or "").strip().lower() in {"1", "true", "yes"}


def reconstruct_paths_from_xp_dirtree_rows(
    root: str, rows: Iterable[dict]
) -> list[dict[str, object]]:
    """Reconstruct absolute paths from raw ``xp_dirtree`` rows.

    ``xp_dirtree`` emits ``subdirectory``/``depth``/``file`` triples carrying
    only a NAME per row (never a full path) -- the row's ancestry must be
    tracked via ``depth`` to rebuild the absolute path. A stack of ancestor
    directory names is maintained, indexed by depth; a row's ancestry is the
    stack truncated to ``depth - 1``, with the row's own name appended when
    it is a directory (so descendants at ``depth + 1`` resolve against it).

    Returns one dict per row with ``full_path``, ``is_file``, ``name`` and
    ``depth``. Rows with a blank name or a non-positive depth are skipped
    (defensive against a truncated or malformed result set).
    """
    normalized_root = str(root or "").strip().rstrip("\\")
    stack: list[str] = []
    reconstructed: list[dict[str, object]] = []
    for row in rows:
        name = str(_row_get_ci(row, "subdirectory") or "").strip()
        if not name:
            continue
        raw_depth = _row_get_ci(row, "depth")
        try:
            depth = int(raw_depth) if raw_depth is not None else 0
        except (TypeError, ValueError):
            continue
        if depth < 1:
            continue
        is_file = _coerce_xp_dirtree_bit(_row_get_ci(row, "file"))
        # Ancestry for this row is the stack truncated to its parent chain.
        stack = stack[: depth - 1]
        if is_file:
            full_path = "\\".join([normalized_root, *stack, name])
        else:
            stack.append(name)
            full_path = "\\".join([normalized_root, *stack])
        reconstructed.append(
            {"full_path": full_path, "is_file": is_file, "name": name, "depth": depth}
        )
    return reconstructed


# ---------------------------------------------------------------------------
# Manifest builder -- SAME shape WindowsFileMappingService.generate_file_map produces
# ---------------------------------------------------------------------------


def _entries_from_reconstructed_rows(
    reconstructed_rows: Iterable[dict[str, object]],
) -> list[WindowsFileMapEntry]:
    """Convert reconstructed ``xp_dirtree`` rows (files only) into manifest entries.

    ``xp_dirtree`` does not report file size or last-write time -- those
    fields are left at zero-value defaults. Downstream extension-based
    selection (``WindowsFileMappingService.select_entries_by_extensions``)
    only reads ``full_name``/``extension``, so the manifest is fully usable
    by the existing analysis pipeline despite the missing metadata.
    """
    entries: list[WindowsFileMapEntry] = []
    seen: set[str] = set()
    for row in reconstructed_rows:
        if not row.get("is_file"):
            continue
        full_path = str(row.get("full_path") or "").strip()
        if not full_path:
            continue
        identity = full_path.replace("/", "\\").lower()
        if identity in seen:
            continue
        seen.add(identity)
        extension = resolve_effective_sensitive_extension(full_path) or (
            os.path.splitext(full_path)[1].strip().lower()
        )
        directory = full_path.rsplit("\\", 1)[0] if "\\" in full_path else ""
        entries.append(
            WindowsFileMapEntry(
                full_name=full_path,
                extension=extension,
                length=0,
                directory=directory,
                last_write_time_utc="",
            )
        )
    return entries


def build_manifest_from_xp_dirtree_walk(
    *,
    roots: Iterable[str],
    rows_by_root: dict[str, list[dict]],
    metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    """Build the SAME manifest shape ``WindowsFileMappingService.generate_file_map`` produces.

    ``rows_by_root`` maps each review root to the raw rows returned by
    ``ImpacketMSSQLBackend.enumerate_filesystem_via_xp_dirtree`` for that
    root (empty/absent when the root did not exist or the query failed --
    callers skip failed roots upstream). Feeding a fake row set here (no
    live backend needed) is the intended test seam for the discovery
    producer's manifest shape.
    """
    all_entries: list[WindowsFileMapEntry] = []
    roots_tuple = tuple(str(root) for root in roots if str(root).strip())
    for root in roots_tuple:
        rows = rows_by_root.get(root) or []
        reconstructed = reconstruct_paths_from_xp_dirtree_rows(root, rows)
        all_entries.extend(_entries_from_reconstructed_rows(reconstructed))
    return {
        "schema_version": WindowsFileMappingService.SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "roots": list(roots_tuple),
        "excluded_path_prefixes": [],
        "excluded_directory_names": [],
        "metadata": dict(metadata or {}),
        "entries": all_entries,
    }


# ---------------------------------------------------------------------------
# Discovery orchestrator -- drives the backend, walks the review roots
# ---------------------------------------------------------------------------

#: Directories worth a low-privilege review pass by default. Not exhaustive --
#: a best-effort last-resort avenue, not a replacement for the exec-driven
#: full filesystem mapping.
DEFAULT_XP_DIRTREE_REVIEW_ROOTS: tuple[str, ...] = (
    "C:\\inetpub\\wwwroot",
    "C:\\Program Files\\Microsoft SQL Server\\MSSQL\\Backup",
    "C:\\ProgramData\\MSSQLSERVER\\MSSQL\\Backup",
    "C:\\Windows\\Temp",
)

DEFAULT_XP_DIRTREE_WALK_DEPTH = 3


def discover_filesystem_via_xp_dirtree(
    backend: Any,
    *,
    domain: str,
    username: str,
    secret: str,
    roots: Iterable[str] = DEFAULT_XP_DIRTREE_REVIEW_ROOTS,
    depth: int = DEFAULT_XP_DIRTREE_WALK_DEPTH,
    timeout: int = 30,
) -> dict[str, object]:
    """Walk the default review roots via ``xp_dirtree`` and build a manifest.

    ``backend`` is duck-typed (an ``ImpacketMSSQLBackend`` in production) so
    tests can pass a stub exposing only ``enumerate_filesystem_via_xp_dirtree``.
    A root that does not exist or errors is silently skipped -- the review is
    best-effort across a fixed candidate list, not a hard requirement that
    every root exists on the target host.
    """
    roots_tuple = tuple(roots)
    rows_by_root: dict[str, list[dict]] = {}
    for root in roots_tuple:
        result = backend.enumerate_filesystem_via_xp_dirtree(
            domain=domain,
            username=username,
            secret=secret,
            root=root,
            depth=depth,
            timeout=timeout,
        )
        if getattr(result, "success", False):
            rows_by_root[root] = list(getattr(result, "rows", None) or [])
    return build_manifest_from_xp_dirtree_walk(
        roots=roots_tuple,
        rows_by_root=rows_by_root,
        metadata={"transport": "mssql_xp_dirtree"},
    )


# ---------------------------------------------------------------------------
# Low-privilege content retrieval -- HTTP GET (web-served roots) fallback
# ---------------------------------------------------------------------------
#
# DISCOVERY roots (``DEFAULT_XP_DIRTREE_REVIEW_ROOTS`` above) stay broad -- they
# feed the OPENROWSET(BULK ...) content-read avenue and the hardening finding
# regardless of whether a path happens to be web-served. HTTP-GET retrieval is
# a NARROWER, DIFFERENT question: "is this specific file reachable over HTTP
# at all" -- true only for files under an actual IIS web root. Attempting
# HTTP-GET against ``C:\Windows\Temp`` or the MSSQL Backup directories is a
# guaranteed 404 (they are never web-served), so the two root sets are kept
# separate on purpose.

#: The default IIS web-served root. Additional (non-default) site roots are
#: discovered at runtime via :func:`discover_additional_iis_site_roots`.
DEFAULT_WEB_SERVED_ROOTS: tuple[str, ...] = ("C:\\inetpub\\wwwroot",)

#: Parent directory IIS creates every site root under. Listing its immediate
#: children (depth=1) surfaces a site hosted OUTSIDE the default ``wwwroot``
#: (e.g. ``C:\inetpub\CustomSite``) without needing IIS configuration access
#: (``applicationHost.config`` parsing is deliberately out of scope -- this is
#: a best-effort heuristic, not virtual-directory/host-header resolution).
IIS_SITES_PARENT_ROOT = "C:\\inetpub"

#: Candidate HTTP(S) ports tried when the host's actual open-port inventory is
#: unavailable, or as the seed list intersected against it.
DEFAULT_HTTP_CANDIDATE_PORTS: tuple[int, ...] = (80, 8080, 8000, 8888)
DEFAULT_HTTPS_CANDIDATE_PORTS: tuple[int, ...] = (443, 8443)


def discover_additional_iis_site_roots(
    backend: Any,
    *,
    domain: str,
    username: str,
    secret: str,
    timeout: int = 30,
) -> tuple[str, ...]:
    """Best-effort discovery of non-default IIS site roots under ``C:\\inetpub``.

    Lists ``C:\\inetpub``'s immediate child directories (``depth=1``) via
    ``xp_dirtree`` so a site hosted OUTSIDE the default ``wwwroot`` is still a
    valid HTTP-GET candidate root. Any failure (query error, ``C:\\inetpub``
    absent, no rows) yields no additional roots -- the default ``wwwroot``
    root from :data:`DEFAULT_WEB_SERVED_ROOTS` is unaffected either way.
    """
    try:
        result = backend.enumerate_filesystem_via_xp_dirtree(
            domain=domain,
            username=username,
            secret=secret,
            root=IIS_SITES_PARENT_ROOT,
            depth=1,
            timeout=timeout,
        )
    except Exception:  # noqa: BLE001 -- best-effort discovery, never blocks the review
        return ()
    if not getattr(result, "success", False):
        return ()
    reconstructed = reconstruct_paths_from_xp_dirtree_rows(
        IIS_SITES_PARENT_ROOT, list(getattr(result, "rows", None) or [])
    )
    default_root_lower = DEFAULT_WEB_SERVED_ROOTS[0].strip().lower()
    roots: list[str] = []
    seen: set[str] = set()
    for row in reconstructed:
        if row.get("is_file"):
            continue
        full_path = str(row.get("full_path") or "").strip()
        if not full_path:
            continue
        identity = full_path.lower()
        if identity == default_root_lower or identity in seen:
            continue
        seen.add(identity)
        roots.append(full_path)
    return tuple(roots)


def select_web_ports_from_open_ports(
    open_ports: Iterable[int] | None,
) -> dict[str, tuple[int, ...]]:
    """Map a host's OBSERVED open ports to the web ports worth an HTTP-GET try.

    Intersects the candidate HTTP/HTTPS port lists against the host's actual
    open-port inventory (never guesses blindly at scale) so a host that only
    has an unrelated port open does not get probed on ports it never
    advertised. Falls back to the plain ``80``/``443`` defaults when
    ``open_ports`` is empty/``None`` (inventory unavailable) OR when none of
    the candidate web ports intersect it (e.g. a stale/incomplete inventory --
    still worth the one cheap try rather than skipping HTTP-GET outright).
    """
    if not open_ports:
        return {"http": (80,), "https": (443,)}
    open_set = {int(port) for port in open_ports}
    http_ports = tuple(port for port in DEFAULT_HTTP_CANDIDATE_PORTS if port in open_set)
    https_ports = tuple(port for port in DEFAULT_HTTPS_CANDIDATE_PORTS if port in open_set)
    if not http_ports and not https_ports:
        return {"http": (80,), "https": (443,)}
    return {"http": http_ports, "https": https_ports}


def build_candidate_http_url(
    *, host: str, web_root: str, full_path: str, use_https: bool = False, port: int | None = None
) -> str | None:
    """Map a discovered file under a known IIS web root to an HTTP(S) URL.

    Returns ``None`` when ``full_path`` is not actually rooted under
    ``web_root`` (case-insensitively) -- the caller tries the next candidate
    web root, then falls back to the MSSQL-native download path. ``port`` is
    omitted from the URL when it is the scheme's default (80 for HTTP, 443 for
    HTTPS) or unset.
    """
    normalized_root = str(web_root or "").strip().rstrip("\\")
    normalized_path = str(full_path or "").strip()
    if not normalized_root or not normalized_path:
        return None
    if not normalized_path.lower().startswith(normalized_root.lower()):
        return None
    relative = normalized_path[len(normalized_root) :].lstrip("\\").replace("\\", "/")
    scheme = "https" if use_https else "http"
    default_port = 443 if use_https else 80
    authority = host if not port or port == default_port else f"{host}:{port}"
    return f"{scheme}://{authority}/{relative}"


def build_candidate_http_urls(
    *,
    hosts: Iterable[str],
    web_roots: Iterable[str],
    full_path: str,
    ports: dict[str, Iterable[int]] | None = None,
) -> list[str]:
    """Build every candidate HTTP(S) URL worth trying for one discovered file.

    ``full_path`` must be rooted under one of ``web_roots`` to yield ANY
    candidate -- a Backup/Temp-rooted path (never web-served) correctly yields
    an empty list, so the caller skips straight to the MSSQL-native download
    path without wasting a network round trip on a guaranteed 404.

    Iterates web_root x scheme x port x host, HTTP before HTTPS, in ascending
    port order, and de-duplicated hosts (an IP and a hostname that happen to
    resolve the same physical box are both tried -- cheap and occasionally the
    only one that resolves DNS-wise from the scanning vantage).
    """
    resolved_ports = ports or {
        "http": DEFAULT_HTTP_CANDIDATE_PORTS[:1],
        "https": DEFAULT_HTTPS_CANDIDATE_PORTS[:1],
    }
    ordered_hosts: list[str] = []
    seen_hosts: set[str] = set()
    for host in hosts:
        clean = str(host or "").strip()
        if not clean or clean.lower() in seen_hosts:
            continue
        seen_hosts.add(clean.lower())
        ordered_hosts.append(clean)

    urls: list[str] = []
    for web_root in web_roots:
        for use_https, port_list in (
            (False, resolved_ports.get("http") or ()),
            (True, resolved_ports.get("https") or ()),
        ):
            for port in port_list:
                for host in ordered_hosts:
                    url = build_candidate_http_url(
                        host=host,
                        web_root=web_root,
                        full_path=full_path,
                        use_https=use_https,
                        port=int(port),
                    )
                    if url:
                        urls.append(url)
    return urls


@dataclass(frozen=True, slots=True)
class HttpRetrievalAttempt:
    """One HTTP-GET attempt against a candidate URL for a discovered file.

    ``status`` is the HTTP response status code when the server responded at
    all (even a 404/403/401) -- distinct from ``status=None``, which means the
    request never got a response (connection refused, DNS failure, timeout,
    TLS error). This distinction is what lets the caller tell "the file exists
    on disk but is not retrievable this way" from "this host/port is not
    reachable at all".
    """

    url: str
    status: int | None
    succeeded: bool
    content: bytes | None = None


def fetch_file_via_http_get(url: str, *, timeout: float = 15.0) -> HttpRetrievalAttempt:
    """Best-effort HTTP GET for a web-served file discovered under an IIS web root.

    Requires ZERO MSSQL permission beyond the directory listing that already
    found the file -- a genuinely lower-privilege avenue than
    ``OPENROWSET(BULK ...)``, which needs its own server permission. Uses the
    stdlib client for one stateless GET (no new dependency, mirrors the ADCS
    web-enrollment probe's minimal-footprint rationale).

    Returns an :class:`HttpRetrievalAttempt` reporting the response status even
    on failure (a 404/403/401 is a DIAGNOSIS, not silence) so the caller can
    distinguish "found on disk but not retrievable over HTTP" from "host/port
    unreachable" -- never just ``None``.
    """
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310
            status = getattr(response, "status", None) or response.getcode()
            if status != 200:
                return HttpRetrievalAttempt(url=url, status=status, succeeded=False)
            return HttpRetrievalAttempt(
                url=url, status=status, succeeded=True, content=response.read()
            )
    except urllib.error.HTTPError as exc:
        return HttpRetrievalAttempt(url=url, status=exc.code, succeeded=False)
    except (urllib.error.URLError, OSError, ValueError):
        return HttpRetrievalAttempt(url=url, status=None, succeeded=False)


def fetch_file_via_http_get_candidates(
    urls: Iterable[str], *, timeout: float = 15.0
) -> tuple[bytes | None, list[HttpRetrievalAttempt]]:
    """Try every candidate URL in order; return the first success's bytes.

    Stops at the first success but returns every attempt made up to and
    including it, so the caller can classify the outcome via
    :func:`classify_web_retrieval_outcome` for reporting/diagnosis, not just a
    bare bytes-or-None.
    """
    attempts: list[HttpRetrievalAttempt] = []
    for url in urls:
        attempt = fetch_file_via_http_get(url, timeout=timeout)
        attempts.append(attempt)
        if attempt.succeeded:
            return attempt.content, attempts
    return None, attempts


def classify_web_retrieval_outcome(attempts: list[HttpRetrievalAttempt]) -> str:
    """Classify a sequence of :class:`HttpRetrievalAttempt` into one honest state.

    * ``"not_attempted"`` -- no candidate URL existed for this file (it is not
      rooted under a known web-served root); HTTP-GET was never a valid avenue.
    * ``"retrieved"`` -- at least one attempt succeeded (HTTP 200).
    * ``"found_not_retrievable"`` -- the SQL-discovered file sits under a web
      root and at least one attempt got a real (non-200) HTTP response --
      e.g. 401/403/404 -- so the server is reachable but this exact file is
      not retrievable this way (auth required, different URL, or not actually
      web-served at that path). Worth a manual look, never silence.
    * ``"unreachable"`` -- every attempt failed at the connection level (no
      HTTP response at all) -- the candidate host/port(s) were not reachable,
      not a statement about the file.
    """
    if not attempts:
        return "not_attempted"
    if any(attempt.succeeded for attempt in attempts):
        return "retrieved"
    if any(attempt.status is not None for attempt in attempts):
        return "found_not_retrievable"
    return "unreachable"


__all__ = [
    "XP_DIRTREE_PROCEDURES",
    "STATUS_CLOSED_BY_CONFIGURATION",
    "STATUS_GRANTED_EXPOSURE",
    "STATUS_GRANTED_HARDENING_NOTE",
    "XpDirtreeCapabilitySignals",
    "parse_xp_dirtree_capability_rows",
    "classify_xp_dirtree_review_outcome",
    "reconstruct_paths_from_xp_dirtree_rows",
    "build_manifest_from_xp_dirtree_walk",
    "DEFAULT_XP_DIRTREE_REVIEW_ROOTS",
    "DEFAULT_XP_DIRTREE_WALK_DEPTH",
    "discover_filesystem_via_xp_dirtree",
    "DEFAULT_WEB_SERVED_ROOTS",
    "IIS_SITES_PARENT_ROOT",
    "DEFAULT_HTTP_CANDIDATE_PORTS",
    "DEFAULT_HTTPS_CANDIDATE_PORTS",
    "discover_additional_iis_site_roots",
    "select_web_ports_from_open_ports",
    "build_candidate_http_url",
    "build_candidate_http_urls",
    "HttpRetrievalAttempt",
    "fetch_file_via_http_get",
    "fetch_file_via_http_get_candidates",
    "classify_web_retrieval_outcome",
]
