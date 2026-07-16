"""CLI orchestration for hash cracking (hashcat and weakpass).

This module keeps hash cracking *UI + reporting* logic out of the monolith. The
service layer (e.g. ``HashcatCrackingService``) handles post-processing of
results; this module:

- selecciona y resuelve rutas de wordlists
- construye comandos hashcat compatibles con distintos runtimes
- maneja cracking de hashes NTLM con weakpass
- imprime cabeceras de operación y mensajes Rich
- emite telemetría de alto nivel
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, Sequence
from pathlib import Path
import os
import re
import shlex
import subprocess

from adscan_internal import (
    print_error,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_success,
    print_success_verbose,
    print_warning,
    print_warning_debug,
    print_operation_header,
    telemetry,
)
from adscan_internal.cli.common import build_lab_event_fields
from adscan_internal.cli.host_file_picker import (
    is_full_container_runtime as _shared_is_full_container_runtime,
    maybe_import_host_file_to_workspace as _shared_import_host_file_to_workspace,
    select_host_file_via_gui as _shared_select_host_file_via_gui,
)
from adscan_internal.path_utils import get_adscan_home
from adscan_internal.questionary_prompts import prompt_questionary_select
from adscan_internal.rich_output import mark_sensitive, print_exception, print_panel
from adscan_internal.text_utils import strip_ansi_codes
from adscan_core.theme import (
    COLOR_AMBER,
    COLOR_CRIMSON,
    COLOR_MUTED,
    COLOR_SAGE,
    COLOR_STEEL,
)
from adscan_core.tui.patience_notice import (
    PatienceNoticeConfig,
    maybe_show_patience_notice,
)
from adscan_core.tui.progress_dashboard import (
    ProgressDashboard,
    ProgressDashboardConfig,
)

# Import services directly to avoid circular dependencies
try:
    from adscan_internal.services.credential_service import CredentialService
    from adscan_internal.services.kerberos_ticket_service import KerberosTicketService
except ImportError:
    # Fallback if services module has issues
    CredentialService = None  # type: ignore[assignment, misc]
    KerberosTicketService = None  # type: ignore[assignment, misc]

from adscan_internal.services.hashcat_service import HashcatCrackingService
from adscan_internal.services.weakpass_service import WeakpassService, weakpass_allowed
from adscan_internal.services.cracking_history_service import (
    build_cracking_attempt,
    find_matching_attempt,
    register_cracking_attempt,
)
from adscan_internal.services.cracking_benchmark import load_cached_benchmark
from adscan_internal.services.cracking_wordlist_policy import (
    EffortEstimate,
    base_for,
    estimate_effort,
    resolve_single_tier,
)
from adscan_core.rich_output import questionary_select_index
import rich.box
from rich.console import Group
from rich.table import Table
from rich.prompt import Confirm, Prompt
from rich.text import Text
from adscan_internal.interaction import is_non_interactive

# Lazily bound to avoid an import cycle: the ``background_jobs`` package
# __init__ imports poisoning_job -> cli.creds -> cli.cracking. A module-level
# ``from ... import enqueue_cracking_job`` therefore deadlocks at import time.
# Kept as a module GLOBAL (not a local) so tests can still patch
# ``adscan_internal.cli.cracking.enqueue_cracking_job`` and the dispatch resolves
# the patched value at call time.
enqueue_cracking_job = None  # type: ignore[assignment]


def _ensure_enqueue_cracking_job():
    """Resolve :func:`enqueue_cracking_job` lazily (cycle-safe)."""
    global enqueue_cracking_job  # noqa: PLW0603
    if enqueue_cracking_job is None:
        from adscan_internal.services.background_jobs.cracking_enqueue import (  # noqa: PLC0415
            enqueue_cracking_job as _impl,
        )

        enqueue_cracking_job = _impl
    return enqueue_cracking_job

_MINIMUM_TIMEROAST_HASHCAT_VERSION = (7, 1, 2)
_GRAPH_TRACKED_ROAST_HASH_TYPES = {"asreproast", "kerberoast"}
_HASHCAT_NO_DEVICE_TEXT = "No devices found/left"
_HASHCAT_EXHAUSTED_EXIT_CODE = 1
# hashcat exits with code 2 when a run is aborted cleanly (e.g. the --runtime
# cap is reached). When ADscan sets --runtime itself this is expected, not a
# failure — the potfile still holds any creds recovered before the cap.
_HASHCAT_RUNTIME_ABORT_EXIT_CODE = 2
_HASHCAT_FATAL_ERROR_PATTERNS = (
    "Kernel /",
    "build failed",
    ".kernel: Permission denied",
)
# Out-of-memory: hashcat / CUDA / OpenCL cannot allocate enough device or host
# memory for the attack (typically exits rc 252). This is NOT "no candidate
# matched" — another wordlist will not help; the operator needs a smaller
# wordlist, more free memory, or a machine with a dedicated GPU. Classified as a
# DISTINCT cause so the no-match panel gives the right advice instead of the
# misleading "try a different wordlist" (field session a38bbbff: a 256 MB host
# crashed with this and got told to try another wordlist).
_HASHCAT_OOM_ERROR_PATTERNS = (
    "not enough allocatable device memory",
    "cuda_error_out_of_memory",
    "cl_out_of_resources",
    "cl_mem_object_allocation_failure",
    "out of memory",
)
_HASHCAT_BENIGN_STDERR_PATTERNS = (
    "nvmlDeviceGetFanSpeed(): Not Supported",
    "Mixing --show with --username or --dynamic-x can cause exponential delay in output.",
)

# Output signatures that mean hashcat could NOT PARSE the hash file (a FORMAT
# error), as opposed to "wordlist exhausted / no match". These are emitted by
# hashcat at parse time, before any candidate is tried, so they must never be
# interpreted as a genuine no-match. The single most common cause in ADscan is
# a hash line that is not ``--username``-safe (see ``_HASHCAT_USERNAME_RULES``):
# every crack ADscan launches passes ``--username``, which strips the first
# colon-field of each line, so a line that lacks a leading ``username:`` field
# gets its real hash corrupted -> "Token length exception" / "No hashes loaded".
_HASHCAT_FORMAT_ERROR_MARKERS = (
    "token length exception",
    "salt-length exception",
    "separator unmatched",
    "no hashes loaded",
    "signature unmatched",
)

# Placeholder used for the prepended username field when a hash line is bare
# AND no embedded username can be extracted AND we cannot prompt (CI). It keeps
# the line a valid ``field:hash`` shape so hashcat parses it; the field is
# stripped by ``--username`` and never affects the crack itself.
_HASHCAT_UNKNOWN_USERNAME = "unknown"

# Symbols used in cracked / not-cracked rows. Glyphs pair with color so the
# panels stay legible under NO_COLOR.
_GLYPH_CRACKED = "★"
_GLYPH_FAILED = "✗"
_GLYPH_INFO = "•"


def _count_hashes_in_file(hash_file: str) -> int:
    """Best-effort count of non-empty hash lines for the pre-flight panel."""
    if not hash_file or not os.path.exists(hash_file):
        return 0
    try:
        with open(hash_file, "r", encoding="utf-8", errors="ignore") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return 0


def _classify_hashcat_failure(combined_output: str, returncode: int | None) -> str:
    """Return a short label for the most likely failure cause.

    Returns one of: ``no_device``, ``out_of_memory``, ``exhausted``,
    ``hash_format``, ``runtime``, ``unknown``.
    """
    lowered = (combined_output or "").lower()
    if _HASHCAT_NO_DEVICE_TEXT.lower() in lowered:
        return "no_device"
    if "no hashes loaded" in lowered or "separator unmatched" in lowered:
        return "hash_format"
    if "salt-length exception" in lowered or "token length exception" in lowered:
        return "hash_format"
    if any(pattern in lowered for pattern in _HASHCAT_OOM_ERROR_PATTERNS):
        return "out_of_memory"
    if _is_fatal_hashcat_runtime_error(combined_output):
        return "runtime"
    if int(returncode or 0) == _HASHCAT_EXHAUSTED_EXIT_CODE:
        return "exhausted"
    return "unknown"


# The wordlists the image actually ships as SELECTABLE standalone files.
# ``kaonashi`` and ``kerberoast_pws`` are no longer shipped standalone — they are
# folded into ``combined_audit_base.txt`` (see the wordlist manifest components),
# so they must not appear as bundled telemetry names or as selector options.
_BUNDLED_WORDLIST_TELEMETRY_NAMES: frozenset[str] = frozenset(
    {
        "rockyou.txt",
        "combined_audit_base.txt",
        "hashmob.net_2025.micro.found",
    }
)

# Canonical telemetry labels for non-bundled wordlists. A generic operator list
# buckets to ``custom``; a list built by ``custom_wordlist_service`` (mined from
# this environment) gets its own ``custom_targeted`` label so the crack-ratio
# analytics can A/B the targeted builder against generic lists.
_GENERIC_CUSTOM_TELEMETRY_LABEL = "custom"
_CUSTOM_TARGETED_TELEMETRY_LABEL = "custom_targeted"

# The SSOT layout for a targeted custom wordlist is
# ``.../wordlists/custom/<domain>/`` (see
# ``custom_wordlist_service.custom_wordlist_dir`` — host ``~/.adscan`` <->
# container ``/opt/adscan``). This marker segment is what distinguishes a
# targeted build from an arbitrary operator "other" path.
_CUSTOM_WORDLIST_PATH_MARKER = "/wordlists/custom/"


def _is_targeted_custom_wordlist(wordlist: str | None) -> bool:
    """Return ``True`` when ``wordlist`` is a targeted list built by the service.

    A targeted custom wordlist always lives under ``.../wordlists/custom/`` (the
    SSOT layout of ``custom_wordlist_service.custom_wordlist_dir``), so a path
    location check reliably separates it from an arbitrary operator-supplied
    "other" path. Never raises — telemetry labelling must not crash a crack.
    """
    if not wordlist:
        return False
    normalized = str(wordlist).replace("\\", "/")
    return _CUSTOM_WORDLIST_PATH_MARKER in normalized


def _wordlist_telemetry_label(wordlist: str | None) -> str | None:
    """Map a wordlist path/name to a telemetry-safe analytics label.

    Operator-supplied CUSTOM wordlists are often named after the client or its
    domain, so the raw basename either leaks client data into telemetry OR gets
    pseudonymized into an unreadable token by the domain sanitizer (a bare
    ``word.ext`` looks like an FQDN). Emit the basename ONLY for a KNOWN bundled
    wordlist; a wordlist mined from this environment gets the dedicated
    ``custom_targeted`` label; everything else buckets to ``custom``. This keeps
    the crack-ratio analytics clean (real bundled names + a ``custom`` /
    ``custom_targeted`` aggregate for the A/B) and guarantees no client-named
    path reaches the recording. The operator still sees the real wordlist name
    on screen; this is the telemetry LABEL only.

    Idempotent: ``run_cracking`` labels the wordlist once and passes the LABEL to
    ``execute_cracking``, which re-labels it — a value already mapped to a
    canonical label passes through unchanged (so ``custom_targeted`` is never
    silently downgraded to ``custom`` on the second pass).
    """
    if not wordlist:
        return None
    name = os.path.basename(str(wordlist)).strip()
    if name in {_GENERIC_CUSTOM_TELEMETRY_LABEL, _CUSTOM_TARGETED_TELEMETRY_LABEL}:
        return name
    if name in _BUNDLED_WORDLIST_TELEMETRY_NAMES:
        return name
    if _is_targeted_custom_wordlist(wordlist):
        return _CUSTOM_TARGETED_TELEMETRY_LABEL
    return _GENERIC_CUSTOM_TELEMETRY_LABEL


def format_chosen_wordlist_line(
    *,
    wordlist_path: str | None = None,
    rules_path: str | None = None,
    tiers: "Sequence[tuple[str, str | None]] | None" = None,
) -> str:
    """Format the operator-visible "which wordlist/rules got picked" line.

    Two calling shapes:

    * ``tiers`` — an ordered sequence of ``(base_path, rule_path)`` pairs, for
      when the effort engine (``cracking_wordlist_policy.resolve_effort``)
      resolved an escalating ladder of tiers to try in order. Takes priority
      over ``wordlist_path``/``rules_path`` when non-empty.
    * ``wordlist_path`` (+ optional ``rules_path``) — the plain single-choice
      interactive selection.

    Only basenames are shown (never a full path). Returns ``""`` when nothing
    was resolved (defensive; callers should not print an empty line).
    """

    def _piece(base_path: str, rule_path: str | None) -> str:
        piece = os.path.basename(str(base_path))
        if rule_path:
            piece += f"  ·  rules: {os.path.basename(str(rule_path))}"
        return piece

    if tiers:
        pieces = [_piece(base, rule) for base, rule in tiers if base]
        if not pieces:
            return ""
        if len(pieces) == 1:
            return f"Cracking with wordlist: {pieces[0]}"
        return "Cracking with wordlists: " + " → ".join(pieces)

    if not wordlist_path:
        return ""
    return f"Cracking with wordlist: {_piece(wordlist_path, rules_path)}"


_HASH_TYPE_TO_HARVEST_SOURCE: dict[str, str] = {
    "kerberoast": "kerberoasting",
    "asreproast": "asreproasting",
    "NTLMv1": "poisoning",
    "NTLMv2": "poisoning",
}


def _harvest_source_for_hash_type(hash_type: str) -> str:
    """Map a hashcat ``hash_type`` label to the shared harvest ``source`` slug.

    NTLMv1/v2 crack successes reaching this path are broadcast-poisoning
    captures (the only NTLM-capture flow that lands in ``execute_cracking``'s
    interactive path); kerberoast/asreproast map 1:1 to their own harvest
    source. Falls back to the raw ``hash_type`` for anything unmapped
    (e.g. ``timeroast``) so a future hash type still gets a source label
    instead of an empty string.
    """
    return _HASH_TYPE_TO_HARVEST_SOURCE.get(hash_type, hash_type)


def _next_action_for_failure(cause: str, hash_type: str) -> str:
    """Human-readable next action paired with a failure cause."""
    if cause == "exhausted":
        return (
            "Wordlist exhausted without a match. "
            "Retry with the combined audit base wordlist or a targeted ruleset."
        )
    if cause == "no_device":
        return _hashcat_no_device_guidance()
    if cause == "hash_format":
        return (
            "Hash file did not parse as expected for this mode. "
            "Confirm the hash type and that the file format matches hashcat "
            "(one hash per line, no extra prefixes)."
        )
    if cause == "runtime":
        return (
            "Hashcat hit a fatal runtime error before any candidates were tried. "
            "Re-run with ADSCAN_HASHCAT_FORCE_CPU=1 to bypass an unstable GPU stack."
        )
    if cause == "out_of_memory":
        return (
            "Hashcat ran out of GPU/host memory before cracking could begin, so no "
            "candidates were tried. Free up memory, use a smaller wordlist, or run "
            "on a machine with more RAM or a dedicated GPU. A different wordlist "
            "will not help."
        )
    if hash_type == "asreproast":
        return "Try a Kerberos-specific wordlist or AS-REP rule set."
    if hash_type == "kerberoast":
        return "Service accounts often use long passphrases; try the combined audit base wordlist."
    return "Try a different wordlist or add hashcat rules."


@dataclass(frozen=True)
class HashcatBackendSelection:
    """Resolved hashcat backend strategy for the current runtime."""

    args: tuple[str, ...]
    label: str
    is_available: bool
    probe_output: str = ""


class CrackingShell(Protocol):
    """Minimal shell surface used by the cracking controller."""

    console: object
    auto: bool
    type: str | None
    scan_mode: str | None
    current_workspace_dir: str | None
    domains_data: dict
    username: str | None

    def run_command(
        self,
        command: str,
        *,
        timeout: int | None = None,
        shell: bool = False,
        capture_output: bool = False,
        text: bool = False,
        use_clean_env: bool | None = None,
        **kwargs,
    ): ...

    def _get_lab_slug(self) -> str | None: ...

    def ask_for_cracking(
        self, hash_type: str, domain: str, hashes_file: str
    ) -> None: ...

    def add_credential(
        self, domain: str, username: str, password: str, **kwargs: object
    ) -> None: ...

    def cracking(
        self, type: str, domain: str, hash: str, failed: bool = False
    ) -> None: ...

    def ask_for_kerberoast_preauth(self, domain: str, user: str) -> None: ...

    def _is_full_adscan_container_runtime(self) -> bool: ...

    def _sudo_validate(self) -> bool: ...

    def _is_ntp_service_available(self, host: str, timeout: int = 3) -> bool: ...

    def _is_tcp_port_open(self, host: str, port: int, timeout: int = 3) -> bool: ...

    def _sync_clock_via_net_time(
        self, host: str, *, domain: str | None = None
    ) -> bool: ...

    def do_sync_clock_with_pdc(self, domain: str, verbose: bool = False) -> bool: ...


class HashCrackingShell(Protocol):
    """Minimal shell surface required for weakpass hash cracking."""

    domains_data: dict
    # Session type ("ctf" / "audit" / None) — read by ``weakpass_allowed`` to
    # gate external egress.
    type: str | None

    def run_command(
        self, command: str, *, timeout: int | None = None, **kwargs
    ) -> subprocess.CompletedProcess[str] | None: ...


def _cracking_wordlist_option_rows(workspace_type: str) -> list[tuple[str, str]]:
    """Return the ``(key, label)`` rows offered by the wordlist selector.

    Only the wordlists the image actually ships standalone are offered, so an
    operator can never pick a file that was folded into
    ``combined_audit_base.txt`` and no longer exists on disk (``kaonashi14M``,
    ``kerberoast_pws``, the retired hashmob-medium list). The shipped set is:
    the combined audit base, rockyou, the per-domain targeted custom list
    (mined from this environment, ``custom_targeted`` — a selectable option but
    NEVER the non-interactive default, so ``adscan ci`` never auto-builds it),
    and an "Other" custom-path escape hatch. Audit workspaces lead with the
    combined base; every other workspace leads with rockyou (the CTF default).
    """
    targeted_row = (
        "custom_targeted",
        "Targeted custom wordlist (mined from this environment)",
    )
    other_row = ("other", "Other (custom path)")
    if str(workspace_type or "").strip().lower() == "audit":
        return [
            (
                "combined_audit",
                "combined_audit_base.txt (Recommended for real-world environments)",
            ),
            ("rockyou", "rockyou.txt (Recommended for CTFs)"),
            targeted_row,
            other_row,
        ]
    return [
        ("rockyou", "rockyou.txt (Recommended for CTF)"),
        ("combined_audit", "combined_audit_base.txt"),
        targeted_row,
        other_row,
    ]


def choose_cracking_wordlist(
    shell: CrackingShell, hash_type: str, wordlists_dir: str, *, domain: str | None = None
) -> str:
    """Interactive wordlist selector for cracking operations.

    Args:
        shell: Active cracking shell (workspace, non-interactive predicate).
        hash_type: Logical hash type being cracked (drives copy only).
        wordlists_dir: Directory holding the bundled wordlists.
        domain: Target domain, required to offer the targeted custom wordlist
            (mined from this environment). When ``None`` the targeted option is
            still shown but resolves to the generic default if chosen.
    """
    from adscan_internal import print_instruction

    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    default_wordlist = (
        os.path.join(wordlists_dir, "combined_audit_base.txt")
        if workspace_type == "audit"
        else os.path.join(wordlists_dir, "rockyou.txt")
    )

    option_rows = _cracking_wordlist_option_rows(workspace_type)
    options = [label for _, label in option_rows]
    key_by_label = {label: key for key, label in option_rows}
    recommended_key = option_rows[0][0] if option_rows else "rockyou"

    message_lines = [f"Select the cracking wordlist for {hash_type}:"]
    for idx, (key, label) in enumerate(option_rows, start=1):
        suffix = " [recommended]" if key == recommended_key else ""
        message_lines.append(f"{idx}) {label}{suffix}")
    print_instruction("\n".join(message_lines) + "\n")

    if bool(getattr(shell, "auto", False)) or is_non_interactive(shell=shell):
        print_info_debug(
            "[cracking] Non-interactive/auto mode detected; using default wordlist: "
            f"{os.path.basename(default_wordlist)}."
        )
        return default_wordlist

    selection: str | None = None

    if hasattr(shell, "_questionary_select"):
        idx = shell._questionary_select(
            f"Select the cracking wordlist for {hash_type}", options, default_idx=0
        )
        if idx is None:
            selection = None
        elif 0 <= idx < len(option_rows):
            selection = option_rows[idx][0]
        else:
            selection = None
    else:
        selected_label = prompt_questionary_select(
            title=f"Select the cracking wordlist for {hash_type}",
            options=options,
        )
        selection = key_by_label.get(selected_label or "")
        if not selection:
            # Backward-compatible aliases for older wrappers/tests. The
            # ``kaonashi``/``kerberoast_pws`` keys are no longer offered in the
            # live menu (folded into combined_audit_base), but the aliases +
            # resolution branches below are retained so an externally-supplied
            # legacy label still resolves deterministically rather than falling
            # through to the default.
            selected_lower = str(selected_label or "").strip().lower()
            aliases = {
                "rockyou": "rockyou",
                "rockyou (default)": "rockyou",
                "kerberoast_pwd": "kerberoast_pws",
                "kerberoast_pws": "kerberoast_pws",
                "other (custom path)": "other",
                "other": "other",
                "combined": "combined_audit",
                "combined_audit": "combined_audit",
                "combined_audit_base.txt": "combined_audit",
                # Legacy aliases: the retired hashmob-medium keys now resolve to
                # the shipped combined audit base (medium's content is subsumed).
                "hashmob": "combined_audit",
                "hashmob medium": "combined_audit",
                "hashmob_medium": "combined_audit",
                "kaonashi": "kaonashi14M",
                "kaonashi14m": "kaonashi14M",
                "kaonashi14m.txt (recommended for audit - es environments)": "kaonashi14M",
            }
            selection = aliases.get(selected_lower)
    if selection is None:
        # User aborted (Ctrl+C). Stay robust and keep workspace-aware default.
        return default_wordlist

    if selection == "rockyou":
        return os.path.join(wordlists_dir, "rockyou.txt")
    if selection == "kerberoast_pws":
        return os.path.join(wordlists_dir, "kerberoast_pws")
    if selection == "combined_audit":
        return os.path.join(wordlists_dir, "combined_audit_base.txt")
    if selection == "kaonashi14M":
        return os.path.join(wordlists_dir, "kaonashi14M.txt")
    if selection == "custom_targeted":
        built = _build_targeted_custom_wordlist(shell, domain=domain)
        if built:
            return built
        print_warning(
            "Could not build a targeted custom wordlist for this environment; "
            "using the recommended default wordlist instead."
        )
        return default_wordlist
    if selection == "other":
        return _prompt_custom_wordlist_path(shell, default_wordlist=default_wordlist)

    return default_wordlist


def _prompt_custom_wordlist_path(
    shell: CrackingShell, *, default_wordlist: str
) -> str:
    """Prompt for an operator-supplied wordlist path (the "Other / custom" escape
    hatch), returning ``default_wordlist`` when nothing is provided or the stream
    ends. Shared by :func:`choose_cracking_wordlist` and
    :func:`choose_cracking_effort` so the picker behaviour stays identical."""
    in_container_runtime = _is_full_container_runtime(shell)

    custom_path = ""
    if in_container_runtime:
        custom_path = (
            _select_host_file_via_gui(
                shell,
                title="Select the cracking wordlist (host file)",
                initial_dir=str(Path.home()),
            )
            or ""
        ).strip()
        if not custom_path:
            print_info_debug(
                "[cracking] Host GUI picker not used/failed; falling back to manual path prompt"
            )
    else:
        print_info_debug(
            "[cracking] Not running in container runtime; skipping host GUI picker"
        )

    if not custom_path:
        try:
            custom_path = (
                Prompt.ask("Enter the full path of the wordlist", default="") or ""
            ).strip()
        except EOFError:
            print_warning(
                "Input stream ended while requesting custom wordlist path. "
                "Using recommended default wordlist."
            )
            return default_wordlist
    if not custom_path:
        print_warning("No path provided. Using recommended default wordlist.")
        return default_wordlist
    # In Docker runtime, user-provided paths commonly refer to the host FS and
    # will be imported into the workspace later. Avoid emitting a false warning
    # before we get a chance to do that.
    if not in_container_runtime and not os.path.exists(custom_path):
        marked_path = mark_sensitive(custom_path, "path")
        print_warning(f"Wordlist not found at {marked_path}. Hashcat may fail.")
    return custom_path


# --- Benchmark-driven interactive effort selector -----------------------------
#
# Replaces the legacy audit WORDLIST picker with an EFFORT picker: for the hash
# type being cracked, offer fast / balanced / thorough with real per-tier time
# estimates pulled from the hardware benchmark (cracking_benchmark), plus an
# "Other / custom wordlist" escape hatch for power users. fast runs INLINE
# (blocking, a few seconds); balanced / thorough run as BACKGROUND jobs so the
# REPL is never blocked for minutes/hours (same deferred-notification bus as the
# poisoning capture-crack). See docs/superpowers/specs/2026-07-07-cracking-
# effort-engine-design.md.

_EFFORT_SELECTOR_LEVELS: tuple[str, ...] = ("fast", "balanced", "thorough")
_EFFORT_SELECTOR_DEFAULT_IDX = 1  # balanced

# Wall-clock ceilings (seconds) applied ONLY when a background tier has to run
# INLINE (a non-NetNTLM audit crack that cannot be handed to the NetNTLM
# background job yet) so it can never hang the REPL. 0 = no cap (fast is a bare
# wordlist and finishes on its own). Mirrors the policy tier budgets.
_EFFORT_INLINE_RUNTIME_CAP: dict[str, int] = {"fast": 0, "balanced": 300, "thorough": 3600}


@dataclass(frozen=True)
class EffortSelection:
    """The operator's effort choice from :func:`choose_cracking_effort`."""

    kind: str  # "inline" | "background" | "custom"
    effort: str  # fast | balanced | thorough | custom
    wordlist: str | None
    rule_path: str | None = None
    is_blocking: bool = True
    provisional: bool = False


@dataclass(frozen=True)
class _EffortDispatch:
    """How :func:`run_cracking` should proceed after the effort selector."""

    dispatched_background: bool
    wordlist: str | None
    rules_path: str | None = None
    runtime_seconds: int | None = None


def _effort_tier_label(level: str, est: EffortEstimate) -> str:
    """Menu label for one effort tier: ``Balanced — ≈ 8 min · background``."""
    title = level.capitalize()
    lane = "runs now" if level == "fast" else "background"
    suffix = " (estimating…)" if est.provisional else ""
    return f"{title} — {est.human} · {lane}{suffix}"


def choose_cracking_effort(
    shell: CrackingShell,
    *,
    hash_type: str,
    mode: str,
    wordlists_dir: str,
    domain: str | None = None,
) -> EffortSelection:
    """Interactive effort selector for the audit crack path.

    Presents fast / balanced / thorough with live per-tier time estimates for
    ``mode`` on THIS hardware (plus an "Other / custom wordlist" escape hatch).
    Non-interactive resolves to ``balanced`` with NO prompt. ``fast`` -> inline
    (blocking); ``balanced`` / ``thorough`` -> background (enqueued by the
    caller). ``mode`` is the resolved hashcat mode string driving the estimate.
    """
    from adscan_internal import print_instruction  # noqa: PLC0415

    workspace_type = str(getattr(shell, "type", "") or "").strip().lower() or "audit"
    benchmark = load_cached_benchmark()
    _base_path, base_lines = base_for(workspace_type, wordlists_dir)
    default_wordlist = os.path.join(wordlists_dir, "combined_audit_base.txt")

    estimates = {
        level: estimate_effort(level, mode, benchmark=benchmark, base_lines=base_lines)
        for level in _EFFORT_SELECTOR_LEVELS
    }

    def _selection_for(level: str) -> EffortSelection:
        est = estimates[level]
        tier = resolve_single_tier(
            level,
            workspace_type=workspace_type,
            wordlists_dir=wordlists_dir,
            benchmark=benchmark,
        )
        # Routing is by LEVEL, not by the per-mode estimate: per the effort-
        # engine design, fast stays inline (blocking) and balanced/thorough
        # ALWAYS run as background jobs -- even on a fast hash mode where the
        # balanced keyspace would finish in a few seconds. ``is_blocking`` on
        # the estimate stays informational (drives the web artifact).
        return EffortSelection(
            kind="inline" if level == "fast" else "background",
            effort=level,
            wordlist=tier.base_path,
            rule_path=tier.rule_path,
            is_blocking=est.is_blocking,
            provisional=est.provisional,
        )

    if bool(getattr(shell, "auto", False)) or is_non_interactive(shell=shell):
        print_info_debug(
            "[cracking] Non-interactive/auto mode; using default cracking effort: balanced."
        )
        return _selection_for("balanced")

    tier_labels = [_effort_tier_label(level, estimates[level]) for level in _EFFORT_SELECTOR_LEVELS]
    options = tier_labels + ["Other / custom wordlist"]

    message_lines = [f"Select the cracking effort for {hash_type}:"]
    for idx, label in enumerate(options, start=1):
        message_lines.append(f"{idx}) {label}")
    print_instruction("\n".join(message_lines) + "\n")

    idx = questionary_select_index(
        title=f"Select the cracking effort for {hash_type}",
        options=options,
        default_idx=_EFFORT_SELECTOR_DEFAULT_IDX,
        shell=shell,
    )
    if idx is None:
        # Cancelled (Ctrl+C): the least-surprising safe default is a quick
        # inline fast crack rather than launching a long background job.
        return _selection_for("fast")
    if idx == len(_EFFORT_SELECTOR_LEVELS):
        custom_path = _prompt_custom_wordlist_path(shell, default_wordlist=default_wordlist)
        return EffortSelection(
            kind="custom", effort="custom", wordlist=custom_path, is_blocking=True
        )
    level = _EFFORT_SELECTOR_LEVELS[idx] if 0 <= idx < len(_EFFORT_SELECTOR_LEVELS) else "balanced"
    return _selection_for(level)


def _ntlm_version_for_hash_type(hash_type: str) -> str | None:
    """Map a NetNTLM hash type to the ``v1``/``v2`` the background crack job
    keys on. ``None`` for non-NetNTLM types (Kerberoast / AS-REP / timeroast) —
    for those the background job keys on the hashcat ``mode`` directly, so this
    returns ``None`` and the caller passes no ``ntlm_version``."""
    t = str(hash_type or "").strip().lower()
    if t in {"ntlmv1", "netntlmv1"}:
        return "v1"
    if t in {"ntlmv2", "netntlmv2"}:
        return "v2"
    return None


def _primary_user_for_hash_file(hash_file: str, mode: str, domain: str) -> str:
    """Resolve a representative principal for a hash file, for the crack-job scope.

    The per-mode embedded-username extractor is tried FIRST — it correctly parses
    the principal out of a raw ``$krb5tgs$`` / ``$krb5asrep$`` (roast) or
    ``user::domain`` (NetNTLM) line, and is not fooled by the colons inside an
    AS-REP body the way a naive ``split(":")`` would be. Only when no mode
    extractor matches does it fall back to the first ``user:hash`` colon-field
    (an already-prepended file). Falls back to the domain (or ``"captured"``)
    when nothing can be resolved. Never raises.
    """
    try:
        if os.path.exists(hash_file):
            with open(hash_file, "r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    embedded = extract_embedded_username(line, mode=str(mode))
                    if embedded:
                        return embedded
    except OSError as exc:
        telemetry.capture_exception(exc)
    users = _extract_hash_users(hash_file)
    if users:
        return users[0]
    return domain or "captured"


def _maybe_dispatch_audit_effort(
    shell: CrackingShell,
    *,
    hash_type: str,
    hashcat_mode: str,
    domain: str,
    hash_file: str,
    wordlists_dir: str,
    failed: bool,
) -> _EffortDispatch | None:
    """Run the interactive effort selector for the audit crack path and decide
    inline-vs-background.

    Returns ``None`` when the selector does not apply (non-audit workspace,
    unknown mode, failed-retry re-prompt, or non-interactive/CI) so
    :func:`run_cracking` keeps its existing wordlist resolution. Otherwise a
    :class:`_EffortDispatch`: ``dispatched_background`` short-circuits
    ``run_cracking`` (a background job now owns the crack); ``wordlist`` (+
    optional ``rules_path``/``runtime_seconds``) drives an inline crack.
    """
    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    if workspace_type != "audit":
        return None
    if not hashcat_mode or hashcat_mode == "Unknown":
        return None
    if failed:
        return None
    if bool(getattr(shell, "auto", False)) or is_non_interactive(shell=shell):
        return None

    selection = choose_cracking_effort(
        shell,
        hash_type=hash_type,
        mode=str(hashcat_mode),
        wordlists_dir=wordlists_dir,
        domain=domain,
    )

    if selection.kind != "background":
        # fast (inline) or the custom escape hatch: run inline as today.
        return _EffortDispatch(dispatched_background=False, wordlist=selection.wordlist)

    # A background tier was chosen. Hand it to the generalized background crack
    # job for ANY supported hashcat mode — NetNTLM (5500/5600) AND Kerberoast /
    # AS-REP roast (13100/18200 and their AES variants). The job runs
    # ``-m <mode>`` off the scan flow. ``hashcat_mode`` is already the concrete,
    # etype-resolved mode here (the roast mixed-etype split ran upstream in
    # ``run_cracking``), so the roast hash file it points at is single-mode.
    version = _ntlm_version_for_hash_type(hash_type)  # None for roast
    user = _primary_user_for_hash_file(hash_file, hashcat_mode, domain)
    job_id = None
    try:
        job_id = _ensure_enqueue_cracking_job()(
            shell,
            domain=domain or "",
            user=user,
            mode=str(hashcat_mode),
            ntlm_version=version,
            hash_file=hash_file,
            effort=selection.effort,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
    if job_id:
        print_success(
            f"Cracking handed off to a background job at {selection.effort} effort — "
            "the scan continues and you'll get a notification when it finishes."
        )
        return _EffortDispatch(dispatched_background=True, wordlist=None)

    # No background job launched (e.g. enqueue declined by policy — a machine
    # NetNTLM account — or an internal failure): fall back to an inline
    # (benchmark-capped) run so the audit crack still completes.
    cap = _EFFORT_INLINE_RUNTIME_CAP.get(selection.effort) or None
    print_info(f"Running the {selection.effort} cracking tier now.")
    return _EffortDispatch(
        dispatched_background=False,
        wordlist=selection.wordlist,
        rules_path=selection.rule_path,
        runtime_seconds=cap,
    )


def _is_full_container_runtime(shell: CrackingShell) -> bool:
    """Return True if running inside the ADscan FULL container runtime."""
    return _shared_is_full_container_runtime(shell)


def _select_host_file_via_gui(
    shell: CrackingShell,
    *,
    title: str,
    initial_dir: str | None = None,
) -> str | None:
    """Open a host GUI file picker (Docker runtime) and return selected host path."""
    return _shared_select_host_file_via_gui(
        shell,
        title=title,
        initial_dir=initial_dir,
        log_prefix="cracking",
    )


def _read_int_env(name: str, *, default: int) -> int:
    """Parse an int env var, returning default on errors."""

    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _maybe_import_wordlist_from_host(
    shell: CrackingShell, *, domain: str, wordlist_path: str
) -> str:
    """Best-effort: import a host file into the workspace when running in Docker.

    This is intended for Docker mode where users may type a host filesystem path
    that is not bind-mounted into the container.

    Note:
        This is intentionally permissive for now (user can paste any host path).
        If the file isn't available inside the container but the host helper is,
        we import it into the current workspace and use that path for hashcat.
    """

    return _shared_import_host_file_to_workspace(
        shell,
        domain=domain,
        source_path=wordlist_path,
        dest_dir="wordlists_custom",
        log_prefix="cracking",
    )


def _hashcat_device_args(shell: CrackingShell) -> list[str]:
    """Return hashcat device selection args for the current runtime."""

    return list(_select_hashcat_backend(shell).args)


def _select_hashcat_backend(shell: CrackingShell) -> HashcatBackendSelection:
    """Choose the best available hashcat backend.

    Preference order:
    1. GPU/CUDA/OpenCL backends exposed to the container
    2. CPU OpenCL fallback
    3. Unavailable when hashcat cannot see any compute device
    """

    cached = getattr(shell, "_hashcat_backend_selection_cache", None)
    if isinstance(cached, HashcatBackendSelection):
        return cached

    force_cpu = os.getenv("ADSCAN_HASHCAT_FORCE_CPU", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }

    from adscan_internal.cli.tools_env import maybe_wrap_hashcat_for_container

    try:
        probe_cmd = maybe_wrap_hashcat_for_container("hashcat -I")
        probe = shell.run_command(probe_cmd, timeout=30)
        if probe is None:
            raise RuntimeError("hashcat -I probe returned no result")

        output = (
            (getattr(probe, "stdout", "") or "")
            + "\n"
            + (getattr(probe, "stderr", "") or "")
        ).strip()
        has_gpu = bool(
            re.search(r"Type\s*\.+?:\s*(GPU|Accelerator)\b", output, re.IGNORECASE)
        )
        has_cpu_opencl = bool(re.search(r"Type\s*\.+?:\s*CPU\b", output, re.IGNORECASE))
        no_devices = _HASHCAT_NO_DEVICE_TEXT.lower() in output.lower()

        if force_cpu and has_cpu_opencl:
            selection = HashcatBackendSelection(
                args=("-D", "1", "--opencl-device-types", "1"),
                label="CPU OpenCL (forced)",
                is_available=True,
                probe_output=output,
            )
        elif has_gpu:
            selection = HashcatBackendSelection(
                args=(),
                label="GPU auto-select",
                is_available=True,
                probe_output=output,
            )
        elif has_cpu_opencl:
            selection = HashcatBackendSelection(
                args=("-D", "1", "--opencl-device-types", "1"),
                label="CPU OpenCL fallback",
                is_available=True,
                probe_output=output,
            )
        elif no_devices:
            selection = HashcatBackendSelection(
                args=(),
                label="Unavailable",
                is_available=False,
                probe_output=output,
            )
        else:
            selection = HashcatBackendSelection(
                args=(),
                label="Unavailable",
                is_available=False,
                probe_output=output,
            )
    except Exception as exc:  # noqa: BLE001
        print_info_debug(f"[cracking] hashcat backend probe failed: {exc}")
        selection = HashcatBackendSelection(
            args=(),
            label="Unavailable",
            is_available=False,
            probe_output=str(exc),
        )

    setattr(shell, "_hashcat_backend_selection_cache", selection)
    setattr(shell, "_hashcat_device_args_cache", list(selection.args))
    return selection


# --- Hashcat rules (-r) + interactive runtime cap -----------------------------
#
# A hashcat rule file (``-r``) mangles each wordlist candidate into many variants
# (best64, OneRule...), multiplying the candidate space. ADscan uses two rules,
# chosen by mode + wordlist size:
#
#   best64.rule                 ~77 rules    bundled in-repo; cheap, always safe
#   OneRuleToRuleThemStill.rule ~49.5k rules managed (large); ONLY for a small
#                                            custom list on a FAST (RC4) mode
#
# The rule multiplier is only affordable when the base wordlist is small (a
# custom list) OR the per-candidate cost is low (RC4 modes). AES roast modes are
# 20-40x slower than RC4, so they always take the cheap best64 rule regardless
# of list size. Every rules-enabled run is bounded by a ``--runtime`` cap so a
# mangled attack cannot run unbounded during the interactive step.
_RULES_ASSET_DIR = Path(__file__).resolve().parents[1] / "assets" / "rules"

# Canonical rule filenames.
BEST64_RULE = "best64.rule"
ONE_RULE_TO_RULE_THEM_STILL = "OneRuleToRuleThemStill.rule"

# hashcat modes whose per-candidate cost is high (AES-encrypted Kerberos
# tickets). Feeding a large rule to these explodes the runtime, so they always
# get the cheap best64 rule.
_AES_ROAST_HASHCAT_MODES: frozenset[str] = frozenset(
    {"19600", "19700", "19800", "19900"}
)

# Interactive runtime caps (seconds) for a rules-mangled attack.
_RULES_RUNTIME_CAP_AES = 300
_RULES_RUNTIME_CAP_FAST = 180


def resolve_rules_path(name: str) -> str | None:
    """Resolve a hashcat rule file by name to an on-disk path.

    Search order:
      1. the bundled in-repo asset dir (``adscan_internal/assets/rules/``) —
         ships ``best64.rule``;
      2. the managed rules dir under the ADscan home
         (``~/.adscan/wordlists/rules/`` on the host, ``/opt/adscan/wordlists/
         rules/`` in the container) — where a large downloaded rule (e.g.
         ``OneRuleToRuleThemStill.rule``) is placed by the operator.

    Args:
        name: Rule filename (e.g. ``best64.rule``).

    Returns:
        The first existing path as a string, or ``None`` when the rule is not
        present (so the caller can fall back to a no-rules attack).
    """
    if not name:
        return None
    bundled = _RULES_ASSET_DIR / name
    if bundled.is_file():
        return str(bundled)
    try:
        managed = get_adscan_home() / "wordlists" / "rules" / name
    except Exception:  # noqa: BLE001
        return None
    if managed.is_file():
        return str(managed)
    return None


def select_rules_for_crack(
    mode: str, wordlist_is_custom: bool
) -> tuple[str | None, int | None]:
    """Pick the hashcat rule file and runtime cap for a crack run.

    Policy (see the module comment above):

    * AES roast modes (19600/19700/19800/19900) -> ``best64`` regardless of
      wordlist size; the per-candidate cost is too high for a large rule.
    * A small CUSTOM wordlist on a FAST (RC4/NTLM) mode -> the large
      ``OneRuleToRuleThemStill`` rule, falling back to ``best64`` when the large
      rule is not installed.
    * The default path -- a big BUNDLED wordlist on a fast mode -> ``(None,
      None)`` so existing behaviour is unchanged unless a caller opts in (the
      bundled lists are already ~14M lines, so they are left unmangled).

    Args:
        mode: The resolved hashcat mode string (e.g. ``13100``, ``19700``).
        wordlist_is_custom: ``True`` when the base wordlist is an operator/custom
            list (small) rather than a large bundled list.

    Returns:
        ``(rules_path, runtime_seconds)``. ``rules_path`` is ``None`` when no
        rule applies (or the resolved rule is missing on disk); ``runtime_seconds``
        is ``None`` on the behaviour-preserving default path.
    """
    if mode in _AES_ROAST_HASHCAT_MODES:
        return resolve_rules_path(BEST64_RULE), _RULES_RUNTIME_CAP_AES
    if wordlist_is_custom:
        rule = resolve_rules_path(ONE_RULE_TO_RULE_THEM_STILL) or resolve_rules_path(
            BEST64_RULE
        )
        return rule, _RULES_RUNTIME_CAP_FAST
    # Default non-custom (big bundled) fast path -- behaviour-preserving.
    return None, None


def _build_hashcat_cmd(
    hash_value: str,
    wordlist: str,
    mode: str,
    shell: CrackingShell,
    *,
    rules_path: str | None = None,
    runtime_seconds: int | None = None,
) -> str:
    """Build a hashcat command string for a given mode.

    Args:
        hash_value: Path to the hashfile hashcat should crack.
        wordlist: Path to the base wordlist.
        mode: The hashcat ``-m`` mode string.
        shell: The cracking shell (provides device/backend args).
        rules_path: Optional hashcat rule file (``-r``); appended only when set.
        runtime_seconds: Optional interactive time cap (``--runtime=<n>``);
            appended only when a positive value is given.
    """

    device_args = _hashcat_device_args(shell)
    tuning_args = ["-w", "1"] if device_args else []
    rules_args = ["-r", rules_path] if rules_path else []
    runtime_args = (
        [f"--runtime={int(runtime_seconds)}"]
        if runtime_seconds is not None and int(runtime_seconds) > 0
        else []
    )
    argv: list[str] = [
        "hashcat",
        "-m",
        mode,
        "-a",
        "0",
        "--username",
        "--force",
        *tuning_args,
        *device_args,
        *rules_args,
        *runtime_args,
        hash_value,
        wordlist,
    ]
    return " ".join(shlex.quote(a) for a in argv)


# --- Per-hash etype → hashcat-mode routing (AES-only domains) -----------------
#
# A Kerberos roast hash carries its ticket encryption type (etype) in its 2nd
# ``$``-delimited field: ``$krb5tgs$<etype>$...`` (TGS-REP / kerberoast) and
# ``$krb5asrep$<etype>$...`` (AS-REP roast). hashcat uses a DIFFERENT mode per
# etype, and runs exactly ONE mode per invocation. Hardcoding the RC4 (etype 23)
# mode means AES tickets (etype 17/18 — the DEFAULT on hardened / AES-only
# domains) get fed to an RC4-only kernel, which rejects them at parse time
# (``Separator unmatched``) and they are SILENTLY never cracked.
#
# The mode is therefore a function of the hash's etype, not of the hash_type
# alone. ``_KRB_ETYPE_HASHCAT_MODES`` is the canonical map; ``18`` (AES256) and
# ``17`` (AES128) are the increasingly-common defaults, ``23`` (RC4) the legacy.
_KRB_ETYPE_HASHCAT_MODES: dict[str, dict[int, str]] = {
    # kerberoast (TGS-REP): RC4 -> 13100, AES128 -> 19600, AES256 -> 19700
    "kerberoast": {23: "13100", 17: "19600", 18: "19700"},
    # AS-REP roast: RC4 -> 18200, AES128 -> 19800, AES256 -> 19900
    "asreproast": {23: "18200", 17: "19800", 18: "19900"},
}

# Human-readable description per resolved hashcat mode (keeps the preflight /
# cracked-credentials panels accurate when the mode is etype-derived rather than
# the hash_type default).
_HASHCAT_MODE_DESCRIPTIONS: dict[str, str] = {
    "13100": "Kerberos 5 TGS-REP etype 23 (RC4)",
    "19600": "Kerberos 5 TGS-REP etype 17 (AES128)",
    "19700": "Kerberos 5 TGS-REP etype 18 (AES256)",
    "18200": "Kerberos 5 AS-REP etype 23 (RC4)",
    "19800": "Kerberos 5 AS-REP etype 17 (AES128)",
    "19900": "Kerberos 5 AS-REP etype 18 (AES256)",
    "31300": "MS-SNTP Timeroast",
    "5500": "NetNTLMv1",
    "5600": "NetNTLMv2",
}

# The etype field of every AES mode needs the same --username prepend handling as
# its RC4 sibling: the on-disk format is the identical ``$krb5tgs$``/``$krb5asrep$``
# raw shape, only the etype digit differs. Register the AES modes against the same
# extractor/needs-prepend rules so the SSOT hashfile writer materialises them
# --username-safe too (see ``_HASHCAT_USERNAME_RULES`` below, which adds them).


def _parse_krb_hash_etype(raw_hash: str) -> int | None:
    """Return the Kerberos etype encoded in a ``$krb5(tgs|asrep)$<etype>$`` line.

    The etype is the 2nd ``$``-delimited field of a kerberoast / AS-REP roast
    hash. Returns ``None`` when the line is not a recognised Kerberos roast hash
    or carries no numeric etype field (some legacy AS-REP emitters omit it).
    """
    match = re.match(r"\$krb5(?:tgs|asrep)\$(\d+)\$", (raw_hash or "").strip())
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def resolve_hashcat_mode_for_hash(raw_hash: str, hash_type: str) -> str:
    """Resolve the correct hashcat mode for a SINGLE roast hash by its etype.

    For ``kerberoast`` / ``asreproast`` the mode is a function of the per-hash
    etype field, NOT the hash_type alone (an AES256 TGS-REP must route to 19700,
    not the RC4-only 13100). For every other hash_type, or an unparseable etype,
    fall back to the hash_type default from
    :func:`_resolve_hashcat_mode_and_description`.
    """
    etype_map = _KRB_ETYPE_HASHCAT_MODES.get(hash_type)
    if etype_map is not None:
        etype = _parse_krb_hash_etype(raw_hash)
        if etype is not None and etype in etype_map:
            return etype_map[etype]
    default_mode, _ = _resolve_hashcat_mode_and_description(hash_type)
    return default_mode


def _resolve_hashcat_mode_and_description(
    hash_type: str, *, mode_override: str | None = None
) -> tuple[str, str]:
    """Return the hashcat mode and human-readable description for a hash type.

    Args:
        hash_type: The logical hash type (``kerberoast``, ``asreproast``,
            ``timeroast``, ``NTLMv1``/``NTLMv2``).
        mode_override: When set (e.g. a per-etype-resolved mode for a single
            roast group), use this exact hashcat mode and look its description up
            in :data:`_HASHCAT_MODE_DESCRIPTIONS`. This is how mixed-etype roast
            captures keep an accurate per-mode description.
    """
    if mode_override is not None:
        return mode_override, _HASHCAT_MODE_DESCRIPTIONS.get(mode_override, hash_type)

    hash_details = {
        "asreproast": ("18200", "Kerberos 5 AS-REP etype 23"),
        "kerberoast": ("13100", "Kerberos 5 TGS-REP etype 23"),
        "timeroast": ("31300", "MS-SNTP Timeroast"),
    }
    if "NTLMv1" in hash_type:
        return "5500", "NetNTLMv1"
    if "NTLMv2" in hash_type:
        return "5600", "NetNTLMv2"
    return hash_details.get(hash_type, ("Unknown", hash_type))


def _hashcat_no_device_guidance() -> str:
    """Return a user-facing hint when no hashcat backend is available."""

    if os.getenv("ADSCAN_CONTAINER_RUNTIME") == "1":
        return (
            "This ADscan container does not currently expose a usable hashcat device. "
            "For NVIDIA hosts, relaunch with ADSCAN_DOCKER_GPU=nvidia (or auto) and "
            "ensure nvidia-container-toolkit is installed on the host."
        )
    return (
        "The local runtime does not expose any usable hashcat compute device. "
        "Check OpenCL/CUDA availability with `hashcat -I`."
    )


def _is_fatal_hashcat_runtime_error(output: str) -> bool:
    """Return True when hashcat failed before any useful cracking work began."""

    lowered = output.lower()
    return any(pattern.lower() in lowered for pattern in _HASHCAT_FATAL_ERROR_PATTERNS)


def _is_benign_hashcat_stderr(stderr: str) -> bool:
    """Return True when stderr only contains known non-fatal hashcat warnings."""

    lines = [line.strip() for line in (stderr or "").splitlines() if line.strip()]
    if not lines:
        return False
    return all(
        any(
            pattern.lower() in line.lower()
            for pattern in _HASHCAT_BENIGN_STDERR_PATTERNS
        )
        for line in lines
    )


def _is_nonfatal_hashcat_exit_code(returncode: int | None) -> bool:
    """Return True for hashcat exit codes that are not operational failures."""

    return int(returncode or 0) in {0, _HASHCAT_EXHAUSTED_EXIT_CODE}


def _parse_hashcat_version(output: str) -> tuple[int, int, int] | None:
    """Extract a semantic version tuple from ``hashcat --version`` output."""

    match = re.search(r"\bv?(\d+)\.(\d+)\.(\d+)\b", output)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def _ensure_timeroast_hashcat_support(shell: CrackingShell) -> bool:
    """Return ``True`` when the installed hashcat version supports Timeroast."""

    from adscan_internal.cli.tools_env import maybe_wrap_hashcat_for_container

    minimum = ".".join(str(part) for part in _MINIMUM_TIMEROAST_HASHCAT_VERSION)
    try:
        version_cmd = maybe_wrap_hashcat_for_container("hashcat --version")
        result = shell.run_command(version_cmd, timeout=15)
        if result is None:
            raise RuntimeError("hashcat --version returned no result")

        output = (
            (getattr(result, "stdout", "") or "")
            + "\n"
            + (getattr(result, "stderr", "") or "")
        ).strip()
        parsed_version = _parse_hashcat_version(output)
        if parsed_version is None:
            raise ValueError(f"Unable to parse hashcat version from: {output!r}")
        if parsed_version < _MINIMUM_TIMEROAST_HASHCAT_VERSION:
            print_error(
                f"Timeroast cracking requires hashcat >= {minimum}. "
                f"Detected version: {'.'.join(str(part) for part in parsed_version)}"
            )
            return False
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(
            "Unable to confirm the local hashcat version required for Timeroast."
        )
        print_exception(exc)
        return False


def _extract_hash_users(hash_file: str) -> list[str]:
    """Extract usernames from a hash file formatted as user:hash."""
    if not os.path.exists(hash_file):
        return []
    try:
        with open(hash_file, "r", encoding="utf-8") as handle:
            users = []
            for line in handle:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                user = line.split(":", 1)[0].strip()
                if user:
                    users.append(user)
            return users
    except OSError:
        return []


# --- Centralized --username guardrail -----------------------------------------
#
# ALL ADscan cracking goes through ``_build_hashcat_cmd``, which ALWAYS passes
# ``--username``. ``--username`` makes hashcat strip the first colon-field of
# every hashfile line as a username, so EVERY line must be shaped ``field:hash``
# for the real hash to survive parsing. A BARE hash line (no leading field)
# gets its first hash token stripped -> "Token length exception" / "No hashes
# loaded" -> the crack SILENTLY reports "no match".
#
# The per-mode behaviour below was validated empirically against hashcat v7.1.2
# (see the PR handoff for the full table). For each mode ADscan invokes:
#
#   mode 13100 (kerberoast)  raw ``$krb5tgs$...``      NOT --username-safe -> prepend
#   mode 18200 (asreproast)  raw ``$krb5asrep$...``    NOT --username-safe -> prepend
#   mode 31300 (timeroast)   ``RID:$sntp-ms$...``      already field:hash  -> leave
#   mode  5500 (NetNTLMv1)   ``user::dom:...``         NOT --username-safe -> prepend
#   mode  5600 (NetNTLMv2)   ``user::dom:...``         NOT --username-safe -> prepend
#
# The guardrail is CONSERVATIVE: it only prepends a field to a line it can
# CONFIDENTLY identify as bare-and-needing-a-prepend for its mode, and it never
# touches a line that already parses (already has a leading ``field:`` for a
# mode that wants one, or is a mode that does not want one at all). Anything it
# cannot fix is left untouched so Layer 3 (post-run format-error detection)
# catches it loudly.


def _extract_kerberoast_username(hash_value: str) -> str | None:
    """Extract the principal from a ``$krb5tgs$`` line (mode 13100).

    Format: ``$krb5tgs$<etype>$*<user>$<realm>$<spn>*$<checksum>$<edata>``.
    The username is the ``*<user>$`` segment immediately after the etype.
    """
    match = re.search(r"\$krb5tgs\$\d+\$\*([^$*]+)\$", hash_value)
    if match:
        user = match.group(1).strip()
        return user or None
    return None


def _extract_asrep_username(hash_value: str) -> str | None:
    """Extract the principal from a ``$krb5asrep$`` line (mode 18200).

    Format: ``$krb5asrep$<etype>$<user>@<realm>:<checksum>$<edata>``.
    The username is the ``<user>@<realm>`` token before the first ``:``.
    """
    match = re.search(r"\$krb5asrep\$\d+\$([^:$]+@[^:$]+):", hash_value)
    if match:
        user = match.group(1).strip()
        return user or None
    # Some emitters omit the etype prefix on the principal; fall back to the
    # leading ``user@realm`` token if one is present before a colon.
    match = re.search(r"\$krb5asrep\$([^:$]+@[^:$]+):", hash_value)
    if match:
        user = match.group(1).strip()
        return user or None
    return None


def _extract_netntlm_username(hash_value: str) -> str | None:
    """Extract the account from a NetNTLMv1/v2 line (modes 5500/5600).

    Format: ``<user>::<domain>:...``. The username is the field before the
    ``::`` separator.
    """
    idx = hash_value.find("::")
    if idx <= 0:
        return None
    user = hash_value[:idx].strip()
    return user or None


def _sanitize_username_field(username: str) -> str:
    """Collapse characters that would shift hashcat's ``--username`` split."""
    return username.replace(":", "_").replace(" ", "_").strip() or _HASHCAT_UNKNOWN_USERNAME


# Per-mode guardrail rules. ``needs_prepend`` is True when the mode's raw on-disk
# format does NOT carry a leading ``field:`` for ``--username`` to strip (so a
# bare line must be repaired by prepending the embedded username). ``extractor``
# pulls that embedded username from the raw hash for the auto-fix; ``None`` means
# the mode is already field-prefixed and must be left untouched.
_HASHCAT_USERNAME_RULES: dict[str, dict[str, object]] = {
    # kerberoast (TGS-REP) — identical raw ``$krb5tgs$`` shape across etypes, so
    # RC4 (13100) AND AES (19600/19700) share the same prepend extractor.
    "13100": {"needs_prepend": True, "extractor": _extract_kerberoast_username},
    "19600": {"needs_prepend": True, "extractor": _extract_kerberoast_username},
    "19700": {"needs_prepend": True, "extractor": _extract_kerberoast_username},
    # AS-REP roast — identical raw ``$krb5asrep$`` shape across etypes, so RC4
    # (18200) AND AES (19800/19900) share the same prepend extractor.
    "18200": {"needs_prepend": True, "extractor": _extract_asrep_username},
    "19800": {"needs_prepend": True, "extractor": _extract_asrep_username},
    "19900": {"needs_prepend": True, "extractor": _extract_asrep_username},
    "31300": {"needs_prepend": False, "extractor": None},
    "5500": {"needs_prepend": True, "extractor": _extract_netntlm_username},
    "5600": {"needs_prepend": True, "extractor": _extract_netntlm_username},
}


def extract_embedded_username(raw_hash: str, *, mode: str) -> str | None:
    """Return the account embedded in ``raw_hash`` for ``mode`` (or ``None``).

    Public accessor over the per-mode extractor table so other modules (e.g. the
    roasting materialisation path) can resolve the per-line principal without
    reaching into the private rules dict. Mirrors exactly the extraction
    ``write_crack_hashfile`` performs internally.
    """
    extractor = _HASHCAT_USERNAME_RULES.get(mode, {}).get("extractor")
    if not callable(extractor):
        return None
    return extractor((raw_hash or "").strip())


def _line_is_username_safe_for_mode(line: str, mode: str) -> bool:
    """Return True when ``line`` already survives hashcat ``--username`` parsing.

    A line is safe when stripping its first colon-field leaves an intact hash.
    For modes that do NOT need a prepend (e.g. timeroast, whose RID is the
    field), every non-empty line is considered safe. For modes that DO need a
    prepend, a line is only safe when its first colon-field is a plain prefix
    (no hash-signature characters / no ``::`` immediately after the first
    field), i.e. it has already been repaired.
    """
    rule = _HASHCAT_USERNAME_RULES.get(mode)
    if rule is None or not rule.get("needs_prepend"):
        return True
    if ":" not in line:
        # No field at all -> --username would strip the whole line. Not safe.
        return False
    first_field, remainder = line.split(":", 1)
    # The raw, un-repaired formats all begin their hash material right at the
    # start of the line: ``$krb5tgs$``, ``$krb5asrep$`` (signature in the first
    # field) or ``user::dom`` (the ``::`` lands so the remainder starts with a
    # colon). A repaired line has a clean leading field and a remainder that is
    # itself a valid bare hash for the mode.
    if first_field.startswith("$krb5"):
        return False
    if "$" in first_field:
        return False
    if remainder.startswith(":"):
        # Pattern ``user::dom:...`` — first_field is the real account but the
        # remainder still starts with the second ``:`` of ``::``; --username
        # leaves ``:dom:...`` which corrupts the NetNTLM hash. Not safe.
        return False
    return True


def write_crack_hashfile(
    path: str,
    pairs: "list[tuple[str | None, str]]",
    *,
    mode: str,
) -> int:
    """Write a ``--username``-safe hashfile for ``mode`` and return line count.

    This is the single, make-it-impossible writer for crack hashfiles. Every
    caller that materialises hashes for ADscan cracking should route through it
    so a bare (un-parseable-under-``--username``) file can never be produced.

    Args:
        path: Destination hashfile path.
        pairs: ``(username, raw_hash)`` tuples. ``username`` may be ``None`` /
            empty; for modes that need a prepend the SUPPLIED username wins when
            present (the caller knows the real principal, incl. domain fallback),
            otherwise the embedded username is extracted from the raw hash,
            falling back to a safe placeholder. For modes that are already
            field-shaped (timeroast), the raw hash is written verbatim.
        mode: hashcat mode string (e.g. ``"5600"``).

    Returns:
        Number of de-duplicated lines written.
    """
    rule = _HASHCAT_USERNAME_RULES.get(mode, {})
    needs_prepend = bool(rule.get("needs_prepend"))
    extractor = rule.get("extractor")
    seen: set[str] = set()
    lines: list[str] = []
    for supplied_user, raw_hash in pairs:
        raw_hash = (raw_hash or "").strip()
        if not raw_hash:
            continue
        if needs_prepend and _line_is_username_safe_for_mode(raw_hash, mode) is False:
            supplied = (supplied_user or "").strip()
            embedded = extractor(raw_hash) if callable(extractor) else None
            username = supplied or embedded or _HASHCAT_UNKNOWN_USERNAME
            line = f"{_sanitize_username_field(username)}:{raw_hash}"
        else:
            line = raw_hash
        if line in seen:
            continue
        seen.add(line)
        lines.append(line)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("".join(f"{line}\n" for line in lines))
    return len(lines)


def _preflight_fix_crack_hashfile(
    shell: CrackingShell,
    *,
    hash_file: str,
    mode: str,
) -> int:
    """Repair bare hash lines in-place so hashcat ``--username`` can parse them.

    Mode-aware pre-flight (Layer 2). For each line that is NOT already
    ``--username``-safe for ``mode`` it tries, in order:

    1. Extract the embedded username from the hash and prepend it.
    2. If extraction fails, prompt the operator (interactive) for the username.
    3. In non-interactive / CI mode it cannot prompt, so it prepends a
       deterministic placeholder and logs a LOUD warning (never hangs, never
       silently drops the hash).

    Lines that already parse are left untouched (conservative). Returns the
    number of lines that were auto-fixed.
    """
    rule = _HASHCAT_USERNAME_RULES.get(mode)
    if rule is None or not rule.get("needs_prepend"):
        return 0
    if not hash_file or not os.path.exists(hash_file):
        return 0
    try:
        with open(hash_file, "r", encoding="utf-8") as handle:
            raw_lines = handle.read().splitlines()
    except OSError as exc:
        telemetry.capture_exception(exc)
        return 0

    extractor = rule.get("extractor")
    non_interactive = bool(getattr(shell, "auto", False)) or is_non_interactive(shell=shell)
    fixed_count = 0
    placeholder_count = 0
    out_lines: list[str] = []
    for line in raw_lines:
        stripped = line.strip()
        if not stripped:
            continue
        if _line_is_username_safe_for_mode(stripped, mode):
            out_lines.append(stripped)
            continue
        embedded = extractor(stripped) if callable(extractor) else None
        username = (embedded or "").strip()
        if not username:
            if non_interactive:
                username = _HASHCAT_UNKNOWN_USERNAME
                placeholder_count += 1
                marked_hash = mark_sensitive(stripped[:24] + "…", "hash")
                print_warning(
                    "Could not extract a username from a hash line and cannot "
                    f"prompt in non-interactive mode; using placeholder "
                    f"'{_HASHCAT_UNKNOWN_USERNAME}' so it still cracks: {marked_hash}"
                )
            else:
                from adscan_core.rich_output import prompt_ask

                marked_hash = mark_sensitive(stripped[:24] + "…", "hash")
                answer = prompt_ask(
                    f"Username for hash {marked_hash} (blank = "
                    f"'{_HASHCAT_UNKNOWN_USERNAME}')",
                    default=_HASHCAT_UNKNOWN_USERNAME,
                )
                username = (answer or "").strip() or _HASHCAT_UNKNOWN_USERNAME
        out_lines.append(f"{_sanitize_username_field(username)}:{stripped}")
        fixed_count += 1

    if fixed_count:
        try:
            with open(hash_file, "w", encoding="utf-8") as handle:
                handle.write("".join(f"{ln}\n" for ln in out_lines))
        except OSError as exc:
            telemetry.capture_exception(exc)
            print_warning(
                "Failed to rewrite the repaired hash file; cracking may fail to "
                "parse the original bare lines."
            )
            return 0
        suffix = (
            f" ({placeholder_count} with placeholder username)"
            if placeholder_count
            else ""
        )
        print_info(
            f"[cracking] Pre-flight repaired {fixed_count} bare hash line(s) for "
            f"hashcat --username (mode {mode}){suffix}."
        )
    return fixed_count


def _detect_hashcat_format_error(combined_output: str) -> bool:
    """Return True when hashcat reported a parse/FORMAT error (Layer 3).

    A format error means hashcat could not load the hashes at all — distinct
    from "wordlist exhausted / no candidate matched". The most common cause in
    ADscan is a ``--username``-unsafe line (see ``_HASHCAT_FORMAT_ERROR_MARKERS``).
    """
    lowered = (combined_output or "").lower()
    if any(marker in lowered for marker in _HASHCAT_FORMAT_ERROR_MARKERS):
        return True
    # ``Parsing Hashes: 0/N`` with no successful parse is also a format error.
    if re.search(r"parsing hashes:\s*0/\d+", lowered) and "parsed hashes:" not in lowered:
        return True
    return False


def _render_cracking_preflight(
    shell: CrackingShell,
    *,
    domain: str,
    hash_type: str,
    hash_description: str,
    hashcat_mode: str,
    backend_label: str,
    backend_is_gpu: bool,
    wordlist_name: str,
    hash_count: int,
    failed_retry: bool,
    rules_path: str | None = None,
    runtime_seconds: int | None = None,
) -> None:
    """Render a premium pre-flight panel before hashcat starts.

    Shows the operator the inputs at a glance, the compute mode, and a brief
    note on what to expect while waiting. Uses tabular layout over paragraph
    copy so eyes can scan the row that changed since the last attempt. When a
    hashcat rule file is in play (targeted custom wordlist) the chosen rules and
    the interactive runtime cap are surfaced too.
    """
    table = Table(
        show_header=False,
        show_edge=False,
        box=None,
        padding=(0, 1),
        expand=False,
    )
    table.add_column("label", style=f"bold {COLOR_STEEL}", no_wrap=True)
    table.add_column("value", overflow="fold")

    marked_domain = mark_sensitive(domain, "domain")
    backend_style = COLOR_SAGE if backend_is_gpu else COLOR_AMBER
    backend_glyph = "▲" if backend_is_gpu else "△"
    backend_value = f"[{backend_style}]{backend_glyph} {backend_label}[/{backend_style}]"

    count_text = (
        f"[bold]{hash_count}[/bold] hash{'es' if hash_count != 1 else ''}"
        if hash_count > 0
        else "[dim]unknown[/dim]"
    )

    table.add_row("Domain", marked_domain)
    table.add_row("Hash type", f"{hash_description} [dim](mode {hashcat_mode})[/dim]")
    table.add_row("Hashes queued", count_text)
    table.add_row("Wordlist", wordlist_name)
    if rules_path:
        from rich.markup import escape as _rich_escape

        rules_label = _rich_escape(os.path.basename(str(rules_path)))
        cap_suffix = (
            f" [dim](cap {int(runtime_seconds)}s)[/dim]"
            if runtime_seconds is not None and int(runtime_seconds) > 0
            else ""
        )
        table.add_row("Rules", f"{rules_label}{cap_suffix}")
    table.add_row("Compute", backend_value)
    if failed_retry:
        table.add_row("Mode", f"[{COLOR_AMBER}]retry with a different wordlist[/]")

    if backend_is_gpu:
        eta_hint = "Hashcat will stream progress and ETA. Press q in the hashcat window for status."
    else:
        eta_hint = (
            "CPU mode is slower than GPU. Consider a focused wordlist or relaunch with "
            "GPU passthrough for production workloads."
        )

    body = Group(
        table,
        Text(""),
        Text.from_markup(f"[{COLOR_MUTED}]{_GLYPH_INFO} {eta_hint}[/]"),
    )

    print_panel(
        body,
        title=f"[bold]Hash Cracking[/bold] [{COLOR_MUTED}]· preparing[/]",
        title_align="left",
        border_style=COLOR_STEEL,
        box=rich.box.ROUNDED,
        padding=(1, 2),
    )


def _render_custom_wordlist_summary(
    *,
    domain: str,
    base_count: int,
    literal_count: int,
    combined_count: int,
    date_band: "list[int]",
) -> None:
    """Render a premium summary of a freshly-built targeted custom wordlist.

    Shown BEFORE the crack so the operator sees what was mined from this
    environment: how many base (rule-fodder) seed words, the whenCreated-seeded
    date band, how many pre-expanded calendar candidates, and the combined line
    count hashcat will consume. The chosen rules + hashcat mode are surfaced by
    the downstream pre-flight panel (they depend on the per-hash etype).
    """
    table = Table(
        show_header=False,
        show_edge=False,
        box=None,
        padding=(0, 1),
        expand=False,
    )
    table.add_column("label", style=f"bold {COLOR_STEEL}", no_wrap=True)
    table.add_column("value", overflow="fold")

    if date_band:
        low, high = date_band[0], date_band[-1]
        band_text = f"{low}" if low == high else f"{low}–{high}"
        band_value = f"{band_text} [dim]({len(date_band)} year(s), from whenCreated + recent)[/dim]"
    else:
        band_value = "[dim]none seeded[/dim]"

    table.add_row("Domain", mark_sensitive(domain, "domain"))
    table.add_row(
        "Base words mined",
        f"[bold]{base_count}[/bold] [dim](seed words for rule mangling)[/dim]",
    )
    table.add_row("Date band", band_value)
    table.add_row(
        "Pre-expanded",
        f"[bold]{literal_count}[/bold] [dim]calendar/literal candidate(s)[/dim]",
    )
    table.add_row(
        "Total candidates",
        f"[bold]{combined_count}[/bold] [dim]line(s) before rule mangling[/dim]",
    )

    body = Group(
        table,
        Text(""),
        Text.from_markup(
            f"[{COLOR_MUTED}]{_GLYPH_INFO} Mined from data already collected for this "
            f"environment. Hashcat rules multiply these candidates further.[/]"
        ),
    )
    print_panel(
        body,
        title=f"[bold]Targeted Custom Wordlist[/bold] [{COLOR_MUTED}]· mined from this environment[/]",
        title_align="left",
        border_style=COLOR_SAGE,
        box=rich.box.ROUNDED,
        padding=(1, 2),
    )


def _build_targeted_custom_wordlist(
    shell: CrackingShell, *, domain: str | None
) -> str | None:
    """Build a targeted wordlist mined from this environment; return its path.

    Wraps the reusable :mod:`custom_wordlist_service` core (never re-implements
    mining/date-seeding): loads the persisted user/computer inventory for
    ``domain``, mines base words + whenCreated date seeds, and writes
    ``base.txt`` (rule fodder) + ``literal.txt`` (pre-expanded calendar forms).
    Because hashcat runs a single ``-a 0`` wordlist, the two are merged into one
    de-duplicated ``custom_targeted.txt`` under the SSOT
    ``.../wordlists/custom/<domain>/`` dir — the seeds get mangled by the
    mode-aware rules :func:`select_rules_for_crack` picks, the literals are tried
    verbatim (a rule engine cannot synthesize the client year).

    Returns the combined wordlist path, or ``None`` on any failure so the caller
    falls back to a generic list (never aborts the crack). ``current_year`` is
    injected here (the I/O boundary) so the pure core stays deterministic.
    """
    resolved_domain = str(domain or "").strip()
    if not resolved_domain:
        print_warning_debug(
            "[cracking] targeted custom wordlist requested without a domain; "
            "cannot mine environment words."
        )
        return None

    from datetime import datetime, timezone

    from adscan_internal.services import custom_wordlist_service as cwl

    workspace_dir = str(getattr(shell, "current_workspace_dir", None) or os.getcwd())
    try:
        objects = cwl.load_objects_from_inventory(workspace_dir, resolved_domain)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        objects = []

    try:
        domain_data = dict(
            (getattr(shell, "domains_data", {}) or {}).get(resolved_domain, {}) or {}
        )
    except Exception:  # noqa: BLE001
        domain_data = {}
    netbios = str(domain_data.get("netbios") or "").strip()
    company = str(domain_data.get("company") or "").strip()

    context = cwl.WordlistContext(
        domain=resolved_domain,
        netbios=netbios,
        company=company,
        objects=tuple(objects),
        current_year=datetime.now(timezone.utc).year,
    )

    try:
        artifact = cwl.for_crack(
            context, domain=resolved_domain, output_stem="custom_targeted"
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning_debug(
            f"[cracking] targeted custom wordlist build failed: {type(exc).__name__}: {exc}"
        )
        return None

    # Merge base (rule fodder) + literal (verbatim calendar forms) into ONE
    # hashcat wordlist, de-duped, order-stable.
    combined_path = artifact.base_path.parent / "custom_targeted.txt"
    seen: set[str] = set()
    combined_lines: list[str] = []
    for source in (artifact.base_path, artifact.literal_path):
        try:
            content = source.read_text(encoding="utf-8")
        except OSError:
            continue
        for line in content.splitlines():
            token = line.strip()
            if token and token not in seen:
                seen.add(token)
                combined_lines.append(token)

    if not combined_lines:
        print_warning_debug(
            "[cracking] targeted custom wordlist produced no candidates "
            "(no inventory / no mined words)."
        )
        return None

    try:
        combined_path.write_text(
            "\n".join(combined_lines) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_warning_debug(
            f"[cracking] could not write combined targeted wordlist: {exc}"
        )
        return None

    try:
        date_band = cwl.global_date_band(objects, context.current_year)
    except Exception:  # noqa: BLE001
        date_band = []

    _render_custom_wordlist_summary(
        domain=resolved_domain,
        base_count=artifact.base_count,
        literal_count=artifact.literal_count,
        combined_count=len(combined_lines),
        date_band=date_band,
    )
    return str(combined_path)


def crack_captured_netntlm(
    shell: CrackingShell,
    *,
    domain: str,
    captures: list[dict[str, Any]],
) -> None:
    """Crack captured NetNTLM (v1/v2) responses with the existing hashcat path.

    Reuses :func:`run_cracking` end-to-end — wordlist resolution (CI-safe),
    backend selection, the pre-flight panel, ``hashcat`` invocation, the
    potfile ``--show`` extraction, and the credential feed-back via
    ``shell.add_credential``. NOTHING about hashcat is reimplemented here; this
    helper only materialises the captured ``fullhash`` tokens into per-version
    hash files and dispatches each batch with the CORRECT mode:

    * ``NTLMv1`` → ``hash_type="NTLMv1"`` → ``hashcat -m 5500``
    * ``NTLMv2`` → ``hash_type="NTLMv2"`` → ``hashcat -m 5600``

    The version is taken from each capture's ``ntlm_version`` (already the real
    value classified from the wire by the listener — never assumed). Captures of
    mixed versions in one session are split into separate batches so each runs
    under its own mode.

    Args:
        shell: Active session shell (workspace dir, ``add_credential``, run env).
        domain: Domain the captures belong to (drives the cracking output dir).
        captures: List of capture dicts as persisted in
            ``domains_data[domain]["captured_netntlm"]`` — each with at least a
            ``fullhash`` and ``ntlm_version``.
    """
    # Group hashes by their canonical NetNTLM version so each batch runs under
    # the right hashcat mode. Empty / malformed captures are skipped.
    #
    # Each line is materialised as ``username:<fullhash>`` (the bare sAMAccountName
    # prepended with a colon) to match the kerberoast/asrep convention consumed by
    # :func:`_extract_hash_users` ("hash file formatted as user:hash"). hashcat is
    # always invoked with ``--username`` (see :func:`_build_hashcat_cmd`), which
    # strips the first colon-field of every line before parsing the hash. A bare
    # NetNTLMv2 line (``user::domain:challenge:ntproof:blob``) would have its
    # leading ``user`` stripped, leaving ``:domain:...`` -> "Token length exception"
    # -> "No hashes loaded". Prepending the username gives ``--username`` a field to
    # strip, so the real NetNTLM hash parses AND the cracked plaintext is attributed
    # back to the right account by the ``--show --outfile-format 2`` step.
    batches: dict[str, list[tuple[str, str]]] = {}
    for cap in captures or []:
        cap_dict = cap or {}
        fullhash = str(cap_dict.get("fullhash") or "").strip()
        if not fullhash:
            continue
        # Capture dicts carry the principal under ``user`` (clean_user /
        # sAMAccountName); accept ``username`` too for robustness. A missing /
        # empty username must NOT produce a bare hash line (``--username`` would
        # then strip the first field of the hash itself), so fall back to the
        # capture's domain, then to a literal ``unknown`` placeholder -- either
        # keeps the line a valid ``field:hash`` shape that hashcat can parse.
        username = str(
            cap_dict.get("user") or cap_dict.get("username") or ""
        ).strip()
        if not username:
            username = str(cap_dict.get("domain") or "").strip() or "unknown"
        # A colon or whitespace in the prepended field would shift hashcat's
        # split point; collapse them so the username stays a single clean field.
        username = username.replace(":", "_").replace(" ", "_")
        raw_version = str(cap_dict.get("ntlm_version") or "").strip().lower()
        version = "NTLMv1" if "v1" in raw_version else "NTLMv2"
        batches.setdefault(version, []).append((username, fullhash))

    if not batches:
        print_info("[~] No captured NTLM hashes to crack.")
        return

    cracking_directory = os.path.join(
        shell.current_workspace_dir or os.getcwd(),
        "domains",
        domain,
        "cracking",
    )
    try:
        os.makedirs(cracking_directory, exist_ok=True)
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_error("Could not prepare the cracking workspace directory.")
        return

    wordlists_dir = str(get_adscan_home() / "wordlists")

    for version, entries in batches.items():
        # Deterministic per-version file the existing potfile/--show step reads.
        hash_file = os.path.join(cracking_directory, f"captured_{version.lower()}.txt")
        mode = "5500" if version == "NTLMv1" else "5600"
        try:
            # Route through the centralized --username-safe writer (Layer 1):
            # it prepends the captured account so the bare ``user::dom:...``
            # NetNTLM hash survives hashcat's --username field-stripping, and it
            # de-dupes while preserving order.
            written = write_crack_hashfile(
                hash_file,
                [(username, fullhash) for username, fullhash in entries],
                mode=mode,
            )
        except OSError as exc:
            telemetry.capture_exception(exc)
            print_error(f"Could not write the captured {version} hash file.")
            continue

        print_info(
            f"[*] Cracking {written} captured {version} hash(es) "
            f"(mode {mode})."
        )
        try:
            run_cracking(
                shell,
                hash_type=version,
                domain=domain,
                hash_file=hash_file,
                wordlists_dir=wordlists_dir,
                failed=False,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error(f"Cracking the captured {version} hash(es) failed.")
            print_exception(show_locals=False, exception=exc)


def _split_roast_hashfile_by_mode(
    hash_file: str, hash_type: str
) -> dict[str, str]:
    """Split a roast hashfile into one per-etype-resolved-mode hashfile.

    A single Kerberoast / AS-REP roast capture can contain hashes of DIFFERENT
    etypes (e.g. one RC4 + one AES256) — common on AES-only domains where the
    krbtgt or service account only has AES keys. hashcat runs ONE mode per
    invocation, so every group must be cracked under its own correct mode.

    Each hash is routed to its mode via :func:`resolve_hashcat_mode_for_hash`
    and re-materialised through the SSOT ``--username``-safe writer
    :func:`write_crack_hashfile` (one file per mode). Returns a mapping of
    ``{hashcat_mode: per_mode_hashfile_path}``. When all hashes resolve to the
    SAME mode (the common single-etype case) the result is a single entry —
    written to a per-mode file so the downstream pipeline is unchanged.

    On any read error or an empty file, returns an empty mapping so the caller
    falls back to the legacy single-file path.
    """
    try:
        raw = Path(hash_file).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return {}

    # Each on-disk line may already be ``username:$krb5...`` (materialised by the
    # roasting path) or a bare ``$krb5...`` hash. Recover the raw hash + any
    # supplied username so the per-mode writer keeps the --username prepend.
    by_mode: dict[str, list[tuple[str | None, str]]] = {}
    for line in (ln.strip() for ln in raw.splitlines()):
        if not line:
            continue
        supplied_user: str | None = None
        raw_hash = line
        if not line.startswith("$krb5") and ":" in line:
            head, rest = line.split(":", 1)
            if rest.lstrip().startswith("$krb5"):
                supplied_user = head.strip() or None
                raw_hash = rest.strip()
        mode = resolve_hashcat_mode_for_hash(raw_hash, hash_type)
        by_mode.setdefault(mode, []).append((supplied_user, raw_hash))

    if not by_mode:
        return {}

    # When everything is one mode, keep using the original file path so the
    # common case produces no extra artifacts and the existing tests/paths hold.
    if len(by_mode) == 1:
        only_mode = next(iter(by_mode))
        return {only_mode: hash_file}

    out: dict[str, str] = {}
    for mode, pairs in by_mode.items():
        per_mode_path = f"{hash_file}.m{mode}"
        try:
            write_crack_hashfile(per_mode_path, pairs, mode=mode)
        except OSError as exc:
            telemetry.capture_exception(exc)
            continue
        out[mode] = per_mode_path
    return out


def run_cracking(
    shell: CrackingShell,
    *,
    hash_type: str,
    domain: str,
    hash_file: str,
    wordlists_dir: str,
    failed: bool = False,
    mode_override: str | None = None,
    rules_path: str | None = None,
    runtime_seconds: int | None = None,
) -> None:
    """High-level cracking entrypoint used by the CLI shell.

    For Kerberoast / AS-REP roast captures the hashes may span MULTIPLE etypes
    (RC4 + AES), each requiring a different hashcat mode. This entrypoint groups
    the hashes by their etype-resolved mode and runs the single-mode pipeline
    once per group, so AES tickets are cracked under 19600/19700/19800/19900
    instead of being silently rejected by the RC4-only mode. ``mode_override``
    is set internally on the per-group recursion to force that group's mode.

    ``rules_path`` (hashcat ``-r``) and ``runtime_seconds`` (``--runtime``) are
    OPTIONAL and default to no rules / no cap, so the default crack behaviour is
    unchanged; a caller (e.g. a custom-wordlist adapter) opts in via
    :func:`select_rules_for_crack`. Both are forwarded through the per-etype
    recursion and into the hashcat command.
    """
    if hash_type == "timeroast" and not _ensure_timeroast_hashcat_support(shell):
        return

    # Belt-and-braces: never launch hashcat on an empty/absent hashfile. An
    # empty hashfile makes hashcat exit with "hashfile is empty or corrupt"
    # (RC 255); this early return protects EVERY caller from that and from the
    # downstream "crack with another wordlist?" re-prompt loop.
    if _count_hashes_in_file(hash_file) <= 0:
        print_info("No hashes to crack — skipping (hashfile is empty or absent).")
        return

    # Mixed-etype dispatch: only for the roast hash types, only on the top-level
    # call (mode_override unset). Split the capture into per-mode hashfiles and
    # crack each group under its correct mode. A single-mode capture stays on the
    # original file (no extra artifacts) — the common case is unchanged.
    if mode_override is None and hash_type in _KRB_ETYPE_HASHCAT_MODES:
        groups = _split_roast_hashfile_by_mode(hash_file, hash_type)
        if len(groups) > 1:
            print_info_debug(
                "[cracking] mixed-etype roast capture: "
                f"{len(groups)} hashcat mode group(s) -> "
                f"{', '.join(sorted(groups))}"
            )
            for group_mode, group_file in groups.items():
                run_cracking(
                    shell,
                    hash_type=hash_type,
                    domain=domain,
                    hash_file=group_file,
                    wordlists_dir=wordlists_dir,
                    failed=failed,
                    mode_override=group_mode,
                    rules_path=rules_path,
                    runtime_seconds=runtime_seconds,
                )
            return
        if len(groups) == 1:
            # Single etype across the whole capture — force that exact mode so an
            # all-AES capture does not fall back to the RC4 default.
            mode_override = next(iter(groups))

    hashcat_mode, hash_description = _resolve_hashcat_mode_and_description(
        hash_type, mode_override=mode_override
    )
    backend_selection = (
        _select_hashcat_backend(shell)
        if hashcat_mode != "Unknown"
        else HashcatBackendSelection(args=(), label="N/A", is_available=True)
    )
    if hashcat_mode != "Unknown" and not backend_selection.is_available:
        print_error("Hashcat could not find a usable compute device for cracking.")
        print_panel(
            f"[{COLOR_AMBER}]{_GLYPH_FAILED} {_hashcat_no_device_guidance()}[/]\n\n"
            f"[bold]Next:[/bold] verify hashcat sees a device with [code]hashcat -I[/code], "
            f"then re-run the cracking step.",
            title=f"[bold]Cracking cannot start[/bold] [{COLOR_MUTED}]· no compute device[/]",
            title_align="left",
            border_style=COLOR_CRIMSON,
        )
        print_info_debug(
            "hashcat -I output (first 40 lines):\n"
            + "\n".join(backend_selection.probe_output.splitlines()[:40])
        )
        return

    # Interactive audit path: offer the benchmark-driven effort selector. A
    # background tier short-circuits here (a job now owns the crack); an inline
    # choice hands back a preselected wordlist (+ optional rules/runtime) so the
    # rest of this function runs unchanged. Every other path (CTF, CI/non-
    # interactive, failed-retry) returns None and keeps the legacy resolution.
    effort_dispatch = _maybe_dispatch_audit_effort(
        shell,
        hash_type=hash_type,
        hashcat_mode=hashcat_mode,
        domain=domain,
        hash_file=hash_file,
        wordlists_dir=wordlists_dir,
        failed=failed,
    )
    if effort_dispatch is not None and effort_dispatch.dispatched_background:
        return
    if effort_dispatch is not None and effort_dispatch.rules_path is not None:
        rules_path = effort_dispatch.rules_path
    if effort_dispatch is not None and effort_dispatch.runtime_seconds is not None:
        runtime_seconds = effort_dispatch.runtime_seconds

    wordlist = resolve_cracking_wordlist(
        shell=shell,
        hash_type=hash_type,
        domain=domain,
        wordlists_dir=wordlists_dir,
        failed=failed,
        preselected_wordlist=(
            effort_dispatch.wordlist if effort_dispatch is not None else None
        ),
    )

    wordlist_name = os.path.basename(wordlist) if wordlist else "N/A"
    hash_count = _count_hashes_in_file(hash_file)
    backend_is_gpu = "GPU" in backend_selection.label

    # A targeted custom wordlist (mined from this environment) is small, so it
    # earns the mode-aware rule ladder: the big rule list on fast RC4/NTLM modes,
    # best64 on the 20-40x-slower AES roast modes — each bounded by an interactive
    # --runtime cap. Only auto-select when the operator picked the targeted list
    # AND the caller did not already pass explicit rules (e.g. credsweeper).
    if (
        rules_path is None
        and runtime_seconds is None
        and hashcat_mode != "Unknown"
        and _is_targeted_custom_wordlist(wordlist)
    ):
        rules_path, runtime_seconds = select_rules_for_crack(
            hashcat_mode, wordlist_is_custom=True
        )

    announce_line = format_chosen_wordlist_line(
        wordlist_path=wordlist, rules_path=rules_path
    )
    if announce_line:
        print_info(announce_line)

    _render_cracking_preflight(
        shell,
        domain=domain,
        hash_type=hash_type,
        hash_description=hash_description,
        hashcat_mode=hashcat_mode,
        backend_label=backend_selection.label,
        backend_is_gpu=backend_is_gpu,
        wordlist_name=wordlist_name,
        hash_count=hash_count,
        failed_retry=failed,
        rules_path=rules_path,
        runtime_seconds=runtime_seconds,
    )

    # hashcat is ALWAYS invoked with --username (see _build_hashcat_cmd), so
    # every hash line must be shaped ``field:hash``. Repair any bare line for
    # this mode BEFORE building the command (Layer 2 of the --username
    # guardrail). Conservative: lines that already parse are left untouched.
    command = None
    if hashcat_mode != "Unknown":
        try:
            _preflight_fix_crack_hashfile(shell, hash_file=hash_file, mode=hashcat_mode)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"[cracking] hashfile pre-flight repair failed (continuing): {exc}"
            )
        command = _build_hashcat_cmd(
            hash_file,
            wordlist,
            hashcat_mode,
            shell,
            rules_path=rules_path,
            runtime_seconds=runtime_seconds,
        )

    if hashcat_mode != "Unknown":
        print_info_debug(
            f"[cracking] hashcat backend selected: {backend_selection.label}"
        )
    if command:
        marked_command = command
        try:
            marked_hash = mark_sensitive(hash_file, "path")
            marked_wordlist = mark_sensitive(wordlist, "path")
            marked_command = marked_command.replace(hash_file, marked_hash).replace(
                wordlist,
                marked_wordlist,
            )
        except Exception:  # noqa: BLE001
            pass
        print_warning_debug(f"Command: {marked_command}")

    wordlist_name_for_telemetry = _wordlist_telemetry_label(wordlist)

    attempt_template = build_cracking_attempt(
        tool="hashcat",
        crack_type=hash_type,
        wordlist_name=wordlist_name_for_telemetry,
        wordlist_path=wordlist,
        hash_file=hash_file,
        result="started",
        cracked_count=0,
    )
    previous_attempt = find_matching_attempt(
        shell,
        domain=domain,
        attempt=attempt_template,
    )
    if previous_attempt:
        marked_domain = mark_sensitive(domain, "domain")
        marked_wordlist = mark_sensitive(
            wordlist_name_for_telemetry or wordlist or "N/A", "path"
        )
        print_warning(
            f"This cracking attempt appears to have already been run for {marked_domain} using {marked_wordlist}."
        )
        print_info_debug(
            "[cracking] repeated attempt detected: "
            f"type={hash_type} wordlist={marked_wordlist} previous_result={previous_attempt.get('result')} "
            f"previous_timestamp={previous_attempt.get('timestamp')}"
        )
        if not (getattr(shell, "auto", False) or is_non_interactive(shell=shell)):
            if not Confirm.ask(
                "Do you want to continue with this cracking attempt?",
                default=False,
            ):
                print_info(
                    "Cracking cancelled because the same inputs were already attempted."
                )
                return

    try:
        properties = {
            "hash_type": hash_type,
            "scan_mode": getattr(shell, "scan_mode", None),
            "retry": failed,
            "workspace_type": getattr(shell, "type", None),
            "auto_mode": getattr(shell, "auto", False),
            "wordlist": wordlist_name_for_telemetry,
        }
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture("cracking_started", properties)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    if hash_type in {"asreproast", "kerberoast"}:
        try:
            from adscan_internal.services.attack_graph_service import (
                update_roast_entry_edge_status,
            )

            users = _extract_hash_users(hash_file)
            for user in users:
                update_roast_entry_edge_status(
                    shell,
                    domain,
                    roast_type=hash_type,
                    status="attempted",
                    username=user,
                    wordlist=wordlist_name_for_telemetry,
                )
        except Exception as exc:  # pragma: no cover
            telemetry.capture_exception(exc)

    # Live current-operation telemetry — surface the cracking step on the
    # platform's live operation strip. hashcat runs blocking and streams to its
    # own window, so there is no per-hash loop to throttle here: one "started"
    # event (0 of N) and one "completed" event (recovered of N) is enough to
    # show the step advance without flooding. No secret reaches the event: only
    # hash counts + the domain. Client-safe, vendor-neutral label.
    def _emit_cracking_progress(*, current: int, done: bool = False) -> None:
        try:
            from adscan_internal.cli.ci_events import (  # noqa: PLC0415
                emit_operation_progress,
            )

            emit_operation_progress(
                operation="credential_cracking",
                label="Credential cracking",
                phase="quick_credential_wins",
                phase_label="Quick Credential Wins",
                current=current,
                total=hash_count or None,
                detail=domain or None,
                done=done,
            )
        except Exception:  # noqa: BLE001 -- telemetry must not abort cracking
            pass

    _emit_cracking_progress(current=0)

    result = execute_cracking(
        shell,
        command=command or "",
        hash_type=hash_type,
        domain=domain,
        hash=hash_file,
        wordlist_name=wordlist_name_for_telemetry,
        mode_override=mode_override,
        runtime_seconds=runtime_seconds,
    )
    # The cracking step finished — mark this terminal tick done so the platform's
    # live strip clears the operation instead of freezing on the recovered count.
    _emit_cracking_progress(
        current=int((result or {}).get("cracked_count") or 0), done=True
    )
    register_cracking_attempt(
        shell,
        domain=domain,
        attempt=build_cracking_attempt(
            tool="hashcat",
            crack_type=hash_type,
            wordlist_name=wordlist_name_for_telemetry,
            wordlist_path=wordlist,
            hash_file=hash_file,
            result=str((result or {}).get("status") or "unknown"),
            cracked_count=int((result or {}).get("cracked_count") or 0),
        ),
    )


def resolve_cracking_wordlist(
    *,
    shell: CrackingShell,
    hash_type: str,
    domain: str,
    wordlists_dir: str,
    failed: bool = False,
    preselected_wordlist: str | None = None,
) -> str:
    """Resolve the effective cracking wordlist using workspace-aware UX rules.

    ``preselected_wordlist`` (set by the interactive effort selector — see
    :func:`_maybe_dispatch_audit_effort`) bypasses the wordlist prompt entirely
    and is used as-is (still passed through the host-import + missing-file
    guard), so the effort selector and the legacy prompt share ONE resolution
    tail.
    """
    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    should_prompt_wordlist_selector = failed or workspace_type == "audit"

    if preselected_wordlist is not None:
        wordlist = preselected_wordlist
    elif should_prompt_wordlist_selector:
        if workspace_type == "audit" and not failed:
            print_info(
                "Audit workspace detected: select a cracking wordlist (rockyou is not forced by default)."
            )
        wordlist = choose_cracking_wordlist(
            shell, hash_type, wordlists_dir, domain=domain
        )
    else:
        print_info("Using rockyou as the default wordlist.")
        wordlist = os.path.join(wordlists_dir, "rockyou.txt")

    wordlist = _maybe_import_wordlist_from_host(
        shell,
        domain=domain,
        wordlist_path=wordlist,
    )
    if wordlist and not os.path.exists(wordlist):
        marked_wordlist = mark_sensitive(wordlist, "path")
        print_warning(
            f"Wordlist not found at {marked_wordlist}. Hashcat may fail; continuing anyway."
        )
    return wordlist


def ask_for_cracking(
    shell: CrackingShell,
    hash_type: str,
    domain: str,
    hashes_file: str,
    *,
    confirm: bool = True,
) -> None:
    """Ask the user whether to attempt cracking, honoring auto mode."""

    from rich.prompt import Confirm

    if shell.auto or not confirm:
        run_cracking(
            shell,
            hash_type=hash_type,
            domain=domain,
            hash_file=hashes_file,
            wordlists_dir=str(get_adscan_home() / "wordlists"),
            failed=False,
        )
        return

    marked_domain = mark_sensitive(domain, "domain")
    if Confirm.ask(
        f"Do you want to attempt to crack the {hash_type} hashes for domain {marked_domain}?",
        default=True,
    ):
        run_cracking(
            shell,
            hash_type=hash_type,
            domain=domain,
            hash_file=hashes_file,
            wordlists_dir=str(get_adscan_home() / "wordlists"),
            failed=False,
        )


def run_sync_clock(shell: CrackingShell, domain: str, *, verbose: bool = False) -> bool:
    """Synchronize local system clock with PDC using the service layer.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name for clock synchronization.
        verbose: Whether to emit verbose messages.

    Returns:
        True if clock synchronization succeeded, False otherwise.
    """
    if domain not in shell.domains_data:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Domain '{marked_domain}' is not configured.")
        return False

    pdc_ip = shell.domains_data[domain].get("pdc")
    if not pdc_ip:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"PDC not configured for domain '{marked_domain}'.")
        return False

    marked_domain = mark_sensitive(domain, "domain")
    marked_pdc = mark_sensitive(pdc_ip, "ip")
    print_operation_header(
        "Clock Synchronization",
        details={
            "Domain": domain,
            "PDC": pdc_ip,
            "Method": "NTP / RPC",
        },
        icon="🕐",
    )

    # Delegate to the single physical-sync implementation
    # (``do_sync_clock_with_pdc`` → ``sync_clock_with_pdc`` → SSOT
    # ``ensure_clock_synced_fresh``). This collapses the previously divergent
    # ``KerberosTicketService.sync_clock_with_pdc`` callback variant so there is
    # exactly one physical-sync code path.
    success = bool(shell.do_sync_clock_with_pdc(domain, verbose=verbose))

    if success:
        print_success_verbose(f"Clock synchronized successfully with PDC {marked_pdc}")
    else:
        print_warning(f"Failed to synchronize clock with PDC {marked_pdc}")

    return success


def _build_spray_dashboard() -> ProgressDashboard:
    """Indeterminate password-spraying dashboard (kerbrute stdout is opaque).

    kerbrute's spray subprocess is blocking and exposes no parseable live
    stream, so a determinate X/N bar would require a guessed (lying) ETA.
    Indeterminate mode shows a spinner + elapsed so the operator can see the
    spray is alive and avoid Ctrl+C-ing a working run.
    """
    return ProgressDashboard(
        ProgressDashboardConfig(
            title="Password Spraying",
            total=None,  # indeterminate -- spinner + elapsed (no per-try stream)
            unit="attempts",
        )
    )


def _estimate_spray_candidate_count(command: str) -> int:
    """Best-effort count of spray candidates for the patience notice.

    kerbrute embeds the users-file path as a positional argument; a single
    password is sprayed against every user, so the user count is the natural
    scale (users x passwords collapses to the user count for one password).
    The command is parsed best-effort: the first existing file argument is
    treated as the users file and its non-empty lines are counted. Returns 0
    on any failure so the notice simply stays silent.

    Args:
        command: Full kerbrute spray command string.

    Returns:
        Number of candidate usernames, or 0 when it cannot be determined.
    """
    try:
        for token in shlex.split(command):
            if not token or token.startswith("-"):
                continue
            if os.path.isfile(token):
                with open(token, encoding="utf-8", errors="ignore") as handle:
                    return sum(1 for line in handle if line.strip())
    except (OSError, ValueError):
        return 0
    return 0


def _run_spray_with_dashboard(run_spray: "Any") -> Any:
    """Run the blocking kerbrute spray under an indeterminate dashboard.

    ``run_spray`` is a zero-arg callable that executes the blocking spray and
    returns its result dict. It runs in a single worker thread so the dashboard
    spinner + elapsed can tick while kerbrute blocks. The thread is always
    joined (the ``with`` on the pool blocks until the future resolves), so it
    never leaks; ``fut.result()`` re-raises any worker exception, preserving the
    caller's error handling exactly.

    FAIL-SAFE: if the dashboard cannot be built / driven, the blocking call is
    still executed directly so the spray always runs and the result handling is
    never skipped. ``call_started`` distinguishes a dashboard/LiveSession setup
    failure (fall back to a plain call) from a failure raised by ``run_spray``
    itself (must propagate -- never re-run the spray).

    Args:
        run_spray: Zero-arg callable performing the blocking spray.

    Returns:
        Whatever ``run_spray`` returns (the spray result dict).
    """
    import concurrent.futures
    import time as _time

    try:
        dashboard = _build_spray_dashboard()
    except Exception:  # noqa: BLE001 -- dashboard build must never block the scan
        return run_spray()

    def _safe_update(dash: "ProgressDashboard") -> None:
        try:
            dash.update()
        except Exception:  # noqa: BLE001 -- a render error must not abort the run
            pass

    call_started = False
    try:
        with dashboard.live_session():
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(run_spray)
                call_started = True
                while not fut.done():
                    _safe_update(dashboard)
                    _time.sleep(0.25)
                result = fut.result()  # re-raises worker exceptions here
                _safe_update(dashboard)
                return result
    except Exception:  # noqa: BLE001
        if call_started:
            # ``run_spray`` (or its worker plumbing) raised -- propagate to the
            # caller's existing try/except. Do NOT re-run the spray.
            raise
        # Dashboard / LiveSession failed before the call started -- fall back to
        # a plain blocking call so the spray still completes.
        return run_spray()


def run_password_spraying(
    shell: CrackingShell,
    command: str,
    domain: str,
) -> None:
    """Execute password spraying command using the service layer.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name for spraying operation.
        command: Full kerbrute command string to execute.
    """
    from adscan_internal.cli.common import SECRET_MODE

    # Upfront patience notice -- threshold-gated on the candidate count. Silent
    # for small lists; a single line under non-interactive runs. Never blocks.
    try:
        maybe_show_patience_notice(
            PatienceNoticeConfig(
                operation="Password spraying",
                unit="candidate usernames",
                threshold=500,
                env_var="ADSCAN_PATIENCE_THRESHOLD_SPRAY",
            ),
            count=_estimate_spray_candidate_count(command),
            non_interactive=is_non_interactive(shell),
        )
    except Exception:  # noqa: BLE001 -- notice must never abort the spray
        pass

    # Create executor that uses shell.run_command
    def executor(cmd: str, timeout: int | None) -> Any:
        from adscan_internal.subprocess_env import command_string_needs_clean_env

        use_clean_env = command_string_needs_clean_env(cmd)
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            f"[spray] Executing spraying command with "
            f"use_clean_env={use_clean_env} on domain {marked_domain}"
        )

        return shell.run_command(
            cmd,
            timeout=timeout,
            shell=True,
            capture_output=True,
            text=True,
            use_clean_env=use_clean_env,
        )

    service = CredentialService()

    # Indeterminate live dashboard. The blocking spray runs in a worker thread
    # so the spinner + elapsed tick while kerbrute blocks; LiveSession falls
    # back to inline logging on non-TTY/CI itself. FAIL-SAFE: a render error
    # never aborts the run -- the helper falls back to a direct blocking call
    # and the result handling below is unchanged.
    def _run_spray() -> Any:
        return service.execute_password_spraying(
            command=command,
            domain=domain,
            executor=executor,
            scan_id=None,
        )

    result = _run_spray_with_dashboard(_run_spray)

    # Process results and display to user
    if result["returncode"] != 0:
        print_error(
            f"Password spraying command failed with return code: {result['returncode']}"
        )
        print_warning_debug(
            f"[spray] Debug context: returncode={result['returncode']}, "
            f"stdout_len={len(result['stdout'])}, stderr_len={len(result['stderr'])}"
        )

        output_lines = result["stdout"].splitlines() if result["stdout"] else []
        if output_lines:
            print_warning("Command output (last 20 lines):")
            for line in output_lines[-20:]:
                print_info_verbose(f"  {line}")

        if result["stderr"]:
            print_warning_debug("[spray] Error output:")
            for line in result["stderr"].splitlines():
                clean_line = strip_ansi_codes(line)
                print_info_debug(f"[spray][stderr] {clean_line}")
    elif not result["found_credentials"]:
        print_warning("No valid credentials found.")
        if result["stdout"] and SECRET_MODE:
            print_info_verbose("Full command output:")
            for line in result["stdout"].splitlines():
                print_info_verbose(f"  {line}")
        elif result["stdout"]:
            error_lines = [
                line
                for line in result["stdout"].splitlines()
                if "error" in line.lower() or "failed" in line.lower()
            ]
            if error_lines:
                print_warning("Errors detected in output:")
                for line in error_lines[:5]:
                    print_info_verbose(f"  {line}")

    # Process found credentials
    for cred in result["credentials"]:
        username = cred["username"]
        password = cred["password"]
        print_success(f"[!] VALID LOGIN: {username}@{domain}:{password}")
        shell.add_credential(domain, username, password, credential_origin="spray")


def handle_hash_cracking(
    shell: HashCrackingShell, domain: str, user: str, cred: str
) -> tuple[str, bool]:
    """Attempt to crack an NTLM hash with weakpass.

    Args:
        shell: Shell instance with cracking helpers and runtime context.
        domain: Domain name for the credential.
        user: Username for the credential.
        cred: NTLM hash to crack.

    Returns:
        Tuple of (credential, is_hash). If cracking succeeds, returns the
        cracked password and False. On failure, returns original hash
        and True.
    """
    if not weakpass_allowed(shell):
        # Egress disabled for this context: keep the hash hashcat-ready, no
        # external lookup. Local cracking (hashcat/John) is unaffected.
        print_info_verbose(
            f"weakpass lookup skipped for user '{mark_sensitive(user, 'user')}' "
            "(external NT-hash lookup disabled for this session); hash saved."
        )
        return cred, True

    try:
        marked_cred = mark_sensitive(cred, "password")
        marked_user = mark_sensitive(user, "user")
        print_info_verbose(f"Attempting to crack NTLM hash for user '{marked_user}'...")
        print_info_debug("Weakpass lookup mode: internal HTTP client")
        service = WeakpassService()
        result = service.lookup_hash(cred)

        if result.used_insecure_tls_fallback:
            print_warning(
                "Weakpass TLS verification failed in this environment. "
                "Falling back to an unverified HTTPS request for this best-effort public lookup."
            )
            print_info_debug(
                f"[weakpass] insecure TLS fallback used for hash {marked_cred}: "
                f"reason={mark_sensitive(str(result.error or 'ssl_verification_failed'), 'error')}"
            )

        if result.password:
            password = result.password
            marked_user = mark_sensitive(user, "user")
            marked_password = mark_sensitive(password, "password")
            print_warning(
                f"Hash cracked successfully for user '{marked_user}'. Password cracked: {marked_password}"
            )
            return password, False

        if result.error:
            print_info_debug(
                f"[weakpass] lookup failed for hash {marked_cred}: "
                f"error={mark_sensitive(result.error, 'error')}"
            )

        marked_user = mark_sensitive(user, "user")
        print_info_verbose(
            f"Could not crack the hash for user '{marked_user}'. Proceeding with the hash."
        )
    except Exception as e:  # pragma: no cover - mirrors legacy best-effort handling
        telemetry.capture_exception(e)
        print_error("An unexpected error occurred during hash cracking.")
        print_exception(show_locals=False, exception=e)

    return cred, True  # Return original hash if cracking fails


def handle_hash_cracking_batch(
    shell: HashCrackingShell, hashes: list[str]
) -> dict[str, str]:
    """Attempt to crack multiple NTLM hashes with a single weakpass call.

    Args:
        shell: Shell instance with cracking helpers and runtime context.
        hashes: Candidate NTLM hashes (32 hex chars). Duplicates are allowed.

    Returns:
        Mapping ``hash_lower -> cracked_password`` for successfully cracked
        hashes. Missing entries indicate "not cracked".
    """
    if not hashes:
        return {}

    valid_hashes: list[str] = []
    seen_hashes: set[str] = set()
    for hash_value in hashes:
        candidate = str(hash_value or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{32}", candidate):
            continue
        if candidate in seen_hashes:
            continue
        seen_hashes.add(candidate)
        valid_hashes.append(candidate)

    if not valid_hashes:
        return {}

    if not weakpass_allowed(shell):
        # Egress disabled for this context: nothing cracked externally. The
        # hashes remain hashcat-ready for local cracking.
        print_info_verbose(
            f"weakpass batch lookup skipped for {len(valid_hashes)} hash(es) "
            "(external NT-hash lookup disabled for this session)."
        )
        return {}

    cracked_by_hash: dict[str, str] = {}
    try:
        print_info_verbose(
            f"Attempting batch NTLM crack for {len(valid_hashes)} hash(es)..."
        )
        print_info_debug(
            f"Weakpass batch lookup mode: internal HTTP client "
            f"(workers={max(4, min(32, len(valid_hashes)))})"
        )
        service = WeakpassService()
        results = service.lookup_hashes(
            valid_hashes,
            max_workers=max(4, min(32, len(valid_hashes))),
        )

        insecure_fallback_used = any(
            result.used_insecure_tls_fallback for result in results.values()
        )
        if insecure_fallback_used and service.consume_tls_fallback_notice():
            print_warning(
                "Weakpass TLS verification failed in this environment. "
                "Falling back to unverified HTTPS requests for this best-effort public lookup."
            )

        for hash_key, result in results.items():
            if result.password:
                cracked_by_hash[hash_key] = result.password

        error_results = {
            hash_key: result
            for hash_key, result in results.items()
            if getattr(result, "error", None)
        }
        tls_failed_count = sum(
            1 for result in results.values() if getattr(result, "tls_verification_failed", False)
        )
        fallback_count = sum(
            1 for result in results.values() if getattr(result, "used_insecure_tls_fallback", False)
        )
        missing_result_count = max(len(valid_hashes) - len(results), 0)
        if error_results or tls_failed_count or fallback_count or missing_result_count:
            print_info_debug(
                "[weakpass] batch diagnostics: "
                f"requested={len(valid_hashes)} returned={len(results)} "
                f"cracked={len(cracked_by_hash)} errors={len(error_results)} "
                f"tls_failed={tls_failed_count} insecure_fallback={fallback_count} "
                f"missing_results={missing_result_count}"
            )
        for hash_key, result in list(error_results.items())[:10]:
            print_info_debug(
                f"[weakpass] batch lookup failed for hash {mark_sensitive(hash_key, 'password')}: "
                f"error={mark_sensitive(str(result.error), 'error')}"
            )
        if len(error_results) > 10:
            print_info_debug(
                f"[weakpass] {len(error_results) - 10} additional batch lookup error(s) omitted."
            )

        print_info_verbose(
            f"Batch NTLM crack finished: {len(cracked_by_hash)}/{len(valid_hashes)} hash(es) cracked."
        )
    except Exception as e:  # pragma: no cover - mirrors existing best-effort handling
        telemetry.capture_exception(e)
        print_error("An unexpected error occurred during batch hash cracking.")
        print_exception(show_locals=False, exception=e)

    return cracked_by_hash


def do_cracking(shell: CrackingShell, args: str) -> None:
    """
    Command to crack Active Directory hashes.

    Usage: cracking <type> <domain> <hash>

    Where:
    - <type> is the type of hash to crack (asreproast, kerberoast, NTLMv2)
    - <domain> is the Active Directory domain of the hash
    - <hash> is the hash to crack

    This command uses hashcat to crack the hash with the wordlist selected by the user.
    """
    args_list = args.split()
    if len(args_list) != 3:
        print_error("Usage: cracking <type> <domain> <hash>")
        return
    hash_type = args_list[0]
    domain = args_list[1]
    hash_file = args_list[2]
    shell.cracking(hash_type, domain, hash_file)


def run_cracking_history(
    shell: CrackingShell,
    *,
    domain: str,
    recent_limit: int = 20,
) -> None:
    """Render recent cracking attempts stored in workspace history."""
    from adscan_internal.services.cracking_history_service import get_cracking_history

    history = get_cracking_history(shell)
    domain_entry = history.get(domain, {}) if isinstance(history, dict) else {}
    attempts = (
        domain_entry.get("attempts", []) if isinstance(domain_entry, dict) else []
    )
    if not isinstance(attempts, list) or not attempts:
        marked_domain = mark_sensitive(domain, "domain")
        print_panel(
            f"[{COLOR_AMBER}]No cracking history found for {marked_domain}.[/]",
            title="Cracking History",
            border_style=COLOR_AMBER,
        )
        return

    limited_attempts = attempts[-max(1, int(recent_limit)) :]
    table = Table(
        title="Cracking History",
        show_header=True,
        header_style=f"bold {COLOR_STEEL}",
        box=rich.box.ROUNDED,
    )
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Tool", style=COLOR_STEEL)
    table.add_column("Type", style="bold")
    table.add_column("Wordlist", style="white", overflow="fold")
    table.add_column("Result", style="bold")
    table.add_column("Cracked", style=COLOR_SAGE, justify="right")
    table.add_column("Targets", style="white", overflow="fold")
    table.add_column("When", style="dim")

    for idx, attempt in enumerate(reversed(limited_attempts), start=1):
        if not isinstance(attempt, dict):
            continue
        target_users = attempt.get("target_users") or []
        artifact_paths = attempt.get("artifact_paths") or []
        targets = ", ".join(str(user) for user in target_users[:3] if str(user).strip())
        if not targets and artifact_paths:
            targets = ", ".join(
                str(path) for path in artifact_paths[:2] if str(path).strip()
            )
        if len(target_users) > 3:
            targets = f"{targets}, +{len(target_users) - 3} more"
        elif not targets:
            targets = "-"

        wordlist = str(
            attempt.get("wordlist_name") or attempt.get("wordlist_path") or "-"
        )
        result = str(attempt.get("result") or "unknown")
        result_style, result_glyph = {
            "success": (COLOR_SAGE, _GLYPH_CRACKED),
            "no_match": (COLOR_AMBER, _GLYPH_FAILED),
            "error": (COLOR_CRIMSON, _GLYPH_FAILED),
        }.get(result, ("white", _GLYPH_INFO))
        table.add_row(
            str(idx),
            str(attempt.get("tool") or "-"),
            str(attempt.get("crack_type") or "-"),
            mark_sensitive(wordlist, "path"),
            f"[{result_style}]{result_glyph} {result}[/{result_style}]",
            str(int(attempt.get("cracked_count") or 0)),
            mark_sensitive(targets, "user"),
            str(attempt.get("timestamp") or "-"),
        )

    print_operation_header(
        "Cracking History",
        details={
            "Domain": domain,
            "Entries": str(len(attempts)),
            "Showing": str(min(len(attempts), max(1, int(recent_limit)))),
        },
        icon="🧾",
    )
    shell.console.print(table)


def _render_cracked_credentials_panel(
    shell: CrackingShell,
    *,
    creds: dict[str, str],
    hash_type: str,
    hash_description: str,
    wordlist_name: str | None,
    total_hashes: int,
) -> None:
    """Render the 'moment of value' panel when one or more hashes crack.

    The panel deliberately uses a celebratory framing (star glyph, sage rows,
    crimson border on the title for visceral feedback) without leaning on color
    alone, so it still reads under NO_COLOR.
    """
    cracked_count = len(creds)
    coverage = (
        f"{cracked_count}/{total_hashes}" if total_hashes else f"{cracked_count}"
    )
    title_markup = (
        f"[bold {COLOR_SAGE}]{_GLYPH_CRACKED} Cracked Credentials[/] "
        f"[{COLOR_MUTED}]· {coverage} · {hash_description}[/]"
    )

    table = Table(
        show_header=True,
        header_style=f"bold {COLOR_STEEL}",
        box=rich.box.ROUNDED,
        expand=False,
        padding=(0, 1),
    )
    table.add_column("", width=2, no_wrap=True)
    table.add_column("Username", style=COLOR_STEEL, overflow="fold")
    table.add_column("Password", style=f"bold {COLOR_SAGE}", overflow="fold")

    for username, password in creds.items():
        marked_username = mark_sensitive(username, "user")
        marked_password = mark_sensitive(password, "password")
        table.add_row(
            f"[{COLOR_SAGE}]{_GLYPH_CRACKED}[/]",
            marked_username,
            marked_password,
        )

    next_lines = []
    if hash_type in {"kerberoast", "asreproast"}:
        next_lines.append(
            f"[bold]Next:[/bold] use these credentials with [code]use {hash_type}[/code] "
            "or move directly to authenticated enumeration."
        )
    elif hash_type == "timeroast":
        next_lines.append(
            "[bold]Next:[/bold] machine account passwords unlock silver tickets and "
            "RBCD primitives against the corresponding host."
        )
    elif "NTLMv1" in hash_type or "NTLMv2" in hash_type:
        next_lines.append(
            "[bold]Next:[/bold] try the cracked passwords across the domain "
            "with password spraying, watching for reused credentials."
        )
    if wordlist_name:
        next_lines.append(
            f"[{COLOR_MUTED}]{_GLYPH_INFO} Wordlist used: {wordlist_name}[/]"
        )

    body_items: list[Any] = [table]
    if next_lines:
        body_items.append(Text(""))
        body_items.extend(Text.from_markup(line) for line in next_lines)

    print_panel(
        Group(*body_items),
        title=title_markup,
        title_align="left",
        border_style=COLOR_SAGE,
        box=rich.box.HEAVY,
        padding=(1, 2),
    )


def _render_credential_harvest_for_crack(
    shell: CrackingShell,
    *,
    domain: str,
    hash_type: str,
    creds: dict[str, str],
    hash_file: str,
) -> None:
    """Build + persist + render HarvestedPrincipal records for a crack success.

    Runs on the foreground REPL thread only (``execute_cracking`` is never
    called from a background thread). Best-effort — a classification or
    rendering failure here never blocks the credential from having already
    been persisted by the caller's ``add_credential`` step above.

    Every cracked secret is left cleartext on the operator's terminal (the
    shared harvest panel marks the principal fields itself); only the
    ``username`` is interpolated here, and the shared panel handles masking.
    """
    from datetime import UTC, datetime

    from adscan_internal.cli.widgets.credential_harvest_panel import (
        build_credential_harvest_panel,
        offer_credential_harvest_actions,
    )
    from adscan_internal.services.captured_credential_policy import classify_principal
    from adscan_internal.services.credential_harvest_classification import (
        classify_harvested_principal_tier,
        classify_harvested_principals_reach,
    )
    from adscan_internal.services.credential_harvest_record import HarvestedPrincipal
    from adscan_internal.services.credential_harvest_store import append_harvest_records
    from adscan_internal.services.high_value import normalize_samaccountname

    if not creds:
        return
    source = _harvest_source_for_hash_type(hash_type)
    ntlm_version = "v2" if "NTLMv2" in hash_type else "v1" if "NTLMv1" in hash_type else ""
    usernames = list(creds.keys())
    reach_by_user = classify_harvested_principals_reach(
        shell, domain=domain, usernames=usernames
    )
    records: list[HarvestedPrincipal] = []
    for username in usernames:
        account_type = classify_principal(
            username, getattr(shell, "domains_data", None), domain
        )
        tier = classify_harvested_principal_tier(
            shell, domain=domain, username=username, account_type=account_type
        )
        # ``tier`` / ``reach`` may be None (UNDETERMINED — no membership/graph
        # data at capture time); persist None so the row renders "Unknown" /
        # "Not assessed" rather than a false Tier 2 / Standard reach. It is
        # re-derived to the real tier once collection populates the graph.
        reach = reach_by_user.get(normalize_samaccountname(username))
        records.append(
            HarvestedPrincipal(
                domain=domain,
                username=username,
                source=source,
                account_type=account_type,
                ntlm_version=ntlm_version,
                crack_status="cracked",
                privilege_tier=tier.value if tier is not None else None,
                compromise_reach=reach.value if reach is not None else None,
                hash_file=hash_file,
                captured_at=datetime.now(UTC).replace(microsecond=0).isoformat(),
            )
        )
    if not records:
        return
    # Persist + render the classified harvest ALWAYS (interactive or CI) — the
    # tier/reach/status records feed the web/artefact ingestion regardless of
    # session mode.
    append_harvest_records(shell, records)
    console = getattr(shell, "console", None)
    if console is not None:
        console.print(build_credential_harvest_panel(records))
    # The add-credential + pivot offer is INTERACTIVE polish only. In a
    # non-interactive run (`adscan ci`) the crack-success loop below already
    # persisted every cracked principal with its REAL secret, and the scan flow
    # pivots from all known credentials — so auto-adding the same principals
    # (with no secret, via the shared checkbox default) and launching a
    # redundant attack-path pass here would duplicate that work. Offer it only
    # when an operator is present to choose.
    if not (bool(getattr(shell, "auto", False)) or is_non_interactive(shell=shell)):
        offer_credential_harvest_actions(shell, domain, records)


def _render_cracking_format_error_panel(
    *,
    hash_type: str,
    hash_description: str,
    hashcat_mode: str,
    hash_file: str,
) -> None:
    """Render a DISTINCT, loud panel when hashcat could not PARSE the hashfile.

    This is the Layer 3 verdict surface. A format error is fundamentally
    different from "no match": hashcat never loaded any hash, so reporting a
    generic no-crack would be misleading. The panel names the likely cause (a
    ``--username`` formatting issue: every line must be ``username:hash``) and
    points at the file so the operator can act.
    """
    marked_file = mark_sensitive(hash_file, "path")
    body = Group(
        Text.from_markup(
            f"[{COLOR_CRIMSON}]{_GLYPH_FAILED}[/] "
            f"[bold]{hash_description}[/bold] "
            f"[{COLOR_MUTED}]· hash file could not be parsed[/]"
        ),
        Text(""),
        Text.from_markup(
            f"[bold]Diagnosis:[/bold] hashcat could not parse the hash file for "
            f"mode {hashcat_mode} — this is a FORMAT error, not a failed crack. "
            f"No password was even attempted."
        ),
        Text.from_markup(
            f"[{COLOR_MUTED}]{_GLYPH_INFO} Cracking always runs with --username, "
            f"so every line must be shaped [code]username:hash[/code]. A bare hash "
            f"line has its first token stripped and stops parsing.[/]"
        ),
        Text.from_markup(f"[{COLOR_MUTED}]{_GLYPH_INFO} Hash file: {marked_file}[/]"),
        Text(""),
        Text.from_markup(
            "[bold]Next:[/bold] re-run cracking — ADscan auto-repairs bare lines "
            "before launching hashcat. If this persists, the file may contain a "
            "hash that does not match the selected mode."
        ),
    )
    print_panel(
        body,
        title=f"[bold]Hash Cracking[/bold] [{COLOR_MUTED}]· format error[/]",
        title_align="left",
        border_style=COLOR_CRIMSON,
        box=rich.box.ROUNDED,
        padding=(1, 2),
    )


def _render_cracking_failure_panel(
    *,
    hash_type: str,
    hash_description: str,
    wordlist_name: str | None,
    cause: str,
    total_hashes: int,
) -> None:
    """Render a clear verdict panel when nothing cracked.

    The body separates the diagnosis from the next action so the operator can
    decide whether to relaunch with a different wordlist or escalate the
    problem to the underlying tooling.
    """
    cause_label = {
        "exhausted": "Wordlist exhausted without a match",
        "no_device": "No usable hashcat compute device",
        "hash_format": "Hash format did not match the selected mode",
        "runtime": "Hashcat hit a fatal runtime error",
        "out_of_memory": "Insufficient GPU/host memory for the attack",
        "unknown": "Hashcat finished without recovering any password",
    }.get(cause, "Hashcat finished without recovering any password")

    diag_lines: list[str] = [
        f"[bold]Diagnosis:[/bold] {cause_label}.",
    ]
    coverage = (
        f"{total_hashes} hash{'es' if total_hashes != 1 else ''}"
        if total_hashes
        else "the hash file"
    )
    if wordlist_name:
        diag_lines.append(
            f"[{COLOR_MUTED}]{_GLYPH_INFO} Wordlist used: {wordlist_name} "
            f"against {coverage}.[/]"
        )

    next_text = _next_action_for_failure(cause, hash_type)
    diag_lines.append("")
    diag_lines.append(f"[bold]Next:[/bold] {next_text}")

    body = Group(
        Text.from_markup(
            f"[{COLOR_CRIMSON}]{_GLYPH_FAILED}[/] "
            f"[bold]{hash_description}[/bold] "
            f"[{COLOR_MUTED}]· not cracked[/]"
        ),
        Text(""),
        *(Text.from_markup(line) for line in diag_lines),
    )
    border = (
        COLOR_CRIMSON
        if cause in {"no_device", "runtime", "hash_format", "out_of_memory"}
        else COLOR_AMBER
    )
    print_panel(
        body,
        title=f"[bold]Hash Cracking[/bold] [{COLOR_MUTED}]· no match[/]",
        title_align="left",
        border_style=border,
        box=rich.box.ROUNDED,
        padding=(1, 2),
    )


def _maybe_materialize_poison_capture_crack_edge(
    shell: CrackingShell, domain: str, username: str
) -> None:
    """Materialize the PoisonCaptureNtlmv2Crack edge for a poisoner-cracked user.

    Only fires when the poisoning capture handler recorded ``username`` as a
    NetNTLMv2 principal captured via broadcast poisoning
    (``domains_data[domain]["poison_captured_ntlmv2_users"]``). This keeps a
    NetNTLMv2 hash cracked from any other origin (e.g. MSSQL coercion) from being
    mis-attributed to wire poisoning. Best-effort — a materialization failure
    must never break the cracking flow.
    """
    from adscan_core.rich_output import print_info_debug

    user_clean = str(username or "").strip()
    if not user_clean:
        return
    try:
        domains_data = getattr(shell, "domains_data", {}) or {}
        domain_state = domains_data.get(domain) or {}
        captured = domain_state.get("poison_captured_ntlmv2_users") or []
        if not isinstance(captured, list):
            return
        # Case-insensitive membership: the capture stores the raw sAMAccountName.
        captured_lower = {str(u).strip().lower() for u in captured}
        if user_clean.lower() not in captured_lower:
            return
        from adscan_internal.services.attack_graph_service import (
            upsert_poison_capture_ntlmv2_crack_edge,
        )

        upsert_poison_capture_ntlmv2_crack_edge(
            shell, domain, username=user_clean, status="success"
        )
        print_info_debug(
            "Materialized PoisonCaptureNtlmv2Crack edge for a poisoner-cracked "
            "NetNTLMv2 credential."
        )
    except Exception as exc:  # noqa: BLE001 — materialization is best-effort
        telemetry.capture_exception(exc)


def _maybe_materialize_ntlmv1_crack_edge(
    shell: CrackingShell, domain: str, username: str
) -> None:
    """Materialize a ``CrackNTLMv1`` edge for a wordlist-cracked USER NetNTLMv1.

    Account-type-aware counterpart of
    :func:`_maybe_materialize_poison_capture_crack_edge`. A captured NetNTLMv1
    challenge/response for a USER account has a human-chosen password, so
    ordinary wordlist cracking recovers it (``supported``); a machine account
    has a random DC-generated password that only rainbow tables recover, so it
    stays ``unsupported`` and this function is a no-op for it (the
    coercion-relay avenue already models that case separately). Best-effort —
    a materialization failure must never break the cracking flow.
    """
    from adscan_core.rich_output import print_info_debug

    user_clean = str(username or "").strip()
    if not user_clean:
        return
    try:
        from adscan_internal.services.attack_step_catalog import (
            ntlmv1_crack_support_for,
        )
        from adscan_internal.services.captured_credential_policy import (
            classify_principal,
        )

        domains_data = getattr(shell, "domains_data", None)
        account_type = classify_principal(user_clean, domains_data, domain)
        if ntlmv1_crack_support_for(account_type) != "supported":
            return

        from adscan_internal.services.attack_graph_service import (
            upsert_ntlmv1_crack_user_edge,
        )

        upsert_ntlmv1_crack_user_edge(
            shell, domain, username=user_clean, status="success"
        )
        print_info_debug(
            "Materialized CrackNTLMv1 edge for a wordlist-cracked user "
            "NetNTLMv1 credential."
        )
    except Exception as exc:  # noqa: BLE001 — materialization is best-effort
        telemetry.capture_exception(exc)


def execute_cracking(
    shell: CrackingShell,
    command: str,
    hash_type: str,
    domain: str,
    hash: str,
    wordlist_name: str | None = None,
    mode_override: str | None = None,
    runtime_seconds: int | None = None,
) -> dict[str, object]:
    """Execute the cracking command and process results.

    ``mode_override`` forces the resolved hashcat mode for this run (used by the
    per-etype roast grouping in :func:`run_cracking` so the ``--show`` pass uses
    the SAME mode the cracking command used — an AES roast group must read back
    under 19700/19900, not the RC4 default).

    ``runtime_seconds`` mirrors the ``--runtime`` cap baked into ``command`` (see
    :func:`_build_hashcat_cmd`): it widens the subprocess timeout so the process
    is not killed before hashcat's own cap elapses, and it lets a clean
    runtime-limit abort be treated as non-fatal. It is ``None`` (unchanged
    behaviour) unless a caller opts into rules-based cracking.
    """
    from adscan_internal.cli.tools_env import maybe_wrap_hashcat_for_container
    from adscan_internal.services.hashcat_coordination import hashcat_slot

    hashcat_mode, hash_description = _resolve_hashcat_mode_and_description(
        hash_type, mode_override=mode_override
    )
    total_hashes = _count_hashes_in_file(hash)
    initial_failure_cause = "unknown"

    try:
        # First phase: execute the initial cracking command
        if command:
            cracking_cmd = maybe_wrap_hashcat_for_container(command)
            # When hashcat carries its own --runtime cap, widen the subprocess
            # timeout past that cap (+60s buffer) so the process is not killed
            # before hashcat aborts cleanly and writes any recovered creds.
            subprocess_timeout = 300
            if runtime_seconds is not None and int(runtime_seconds) > 0:
                subprocess_timeout = max(300, int(runtime_seconds) + 60)
            # Serialize this real crack against every other hashcat launch (a
            # concurrent crack, or the best-effort benchmark warm-up) via the
            # shared single-instance slot. block=True: the interactive crack is
            # a real crack — it always eventually runs, never collides with
            # hashcat's single-instance lock, and the warm-up yields to it.
            with hashcat_slot(block=True):
                completed_process_initial = shell.run_command(
                    cracking_cmd, timeout=subprocess_timeout
                )

            if completed_process_initial is None:
                print_error("Cracking command failed to execute.")
                return {"status": "error", "cracked_count": 0}

            combined_output = (
                (completed_process_initial.stdout or "")
                + "\n"
                + (completed_process_initial.stderr or "")
            )
            initial_stderr = completed_process_initial.stderr or ""
            # A clean --runtime abort exits with code 2; when we set the cap
            # ourselves that is expected (not a failure) and the potfile still
            # holds any creds recovered before the cap, so treat it as non-fatal.
            runtime_capped_abort = (
                runtime_seconds is not None
                and int(runtime_seconds) > 0
                and int(completed_process_initial.returncode or 0)
                == _HASHCAT_RUNTIME_ABORT_EXIT_CODE
            )
            if runtime_capped_abort:
                initial_failure_cause = "runtime_capped"
                print_info_debug(
                    "hashcat reached the --runtime cap "
                    f"({int(runtime_seconds)}s); checking the potfile for "
                    "recovered credentials."
                )
            if not runtime_capped_abort and not _is_nonfatal_hashcat_exit_code(
                completed_process_initial.returncode
            ):
                print_warning(
                    f"Initial cracking command may have failed. Return code: {completed_process_initial.returncode}"
                )
                if initial_stderr and not _is_benign_hashcat_stderr(initial_stderr):
                    print_error(f"Error output: {initial_stderr}")
                elif initial_stderr:
                    print_info_debug(
                        "Non-fatal hashcat stderr during initial cracking run:\n"
                        f"{initial_stderr}"
                    )
                if _HASHCAT_NO_DEVICE_TEXT in combined_output:
                    print_warning(
                        "Hashcat could not find a usable compute device (CUDA/OpenCL backend). "
                        "This can happen in containers/VMs with limited GPU or OpenCL support."
                    )
                    print_warning(_hashcat_no_device_guidance())
                    try:
                        probe_cmd = maybe_wrap_hashcat_for_container("hashcat -I")
                        probe = shell.run_command(probe_cmd, timeout=30)
                        if probe is None:
                            raise RuntimeError("hashcat -I probe returned no result")
                        probe_out = (probe.stdout or "") + "\n" + (probe.stderr or "")
                        print_info_debug(
                            "hashcat -I output (first 40 lines):\n"
                            + "\n".join(probe_out.splitlines()[:40])
                        )
                    except Exception:
                        print_info_debug(
                            "hashcat -I probe failed while diagnosing devices."
                        )
                    return {"status": "unavailable", "cracked_count": 0}
                if _is_fatal_hashcat_runtime_error(combined_output):
                    print_warning(
                        "Hashcat hit a fatal runtime error before cracking could begin."
                    )
                    return {"status": "error", "cracked_count": 0}
            elif completed_process_initial.returncode == _HASHCAT_EXHAUSTED_EXIT_CODE:
                initial_failure_cause = "exhausted"
                print_info_debug(
                    "hashcat finished with exit code 1 (candidate space exhausted). "
                    "Checking the potfile for recovered credentials."
                )
                if initial_stderr and not _is_benign_hashcat_stderr(initial_stderr):
                    print_info_debug(
                        "hashcat emitted additional stderr during the exhausted run:\n"
                        f"{initial_stderr}"
                    )
            # Record failure cause hint for the no-match panel later.
            cause_from_output = _classify_hashcat_failure(
                combined_output,
                completed_process_initial.returncode,
            )
            if cause_from_output != "unknown":
                initial_failure_cause = cause_from_output

            # Layer 3 — hard FORMAT-error detection. A parse error means hashcat
            # never loaded the hashes (NOT "wordlist exhausted / no match"), so
            # the silent "no match" path below would be misleading. Surface a
            # distinct, loud panel and return FORMAT_ERROR so this class can
            # never again be confused with a genuine no-crack.
            if _detect_hashcat_format_error(combined_output):
                _render_cracking_format_error_panel(
                    hash_type=hash_type,
                    hash_description=hash_description,
                    hashcat_mode=hashcat_mode,
                    hash_file=hash,
                )
                return {"status": "format_error", "cracked_count": 0}

        # Second phase: hashcat --show to extract cracked passwords
        file_name = f"cracked_{hash_type}.txt"
        cracking_directory = os.path.join(
            shell.current_workspace_dir or os.getcwd(),
            "domains",
            domain,
            "cracking",
        )
        os.makedirs(cracking_directory, exist_ok=True)
        file_path = os.path.join(cracking_directory, file_name)

        show_argv = ["hashcat"]
        if hashcat_mode != "Unknown":
            show_argv.extend(["-m", hashcat_mode])
        show_argv.extend(
            [
                "--username",
                "--outfile-format",
                "2",
                hash,
                "--show",
            ]
        )
        show_cmd = " ".join(shlex.quote(str(a)) for a in show_argv)
        show_cmd = maybe_wrap_hashcat_for_container(show_cmd)
        print_info_debug(f"Executing hashcat show command: {show_cmd}")
        # The --show read is a second hashcat launch — serialize it too so it
        # never collides with a concurrent crack or the benchmark warm-up.
        with hashcat_slot(block=True):
            completed_process_show = shell.run_command(show_cmd, timeout=300)

        # Layer 3 (continued) — the --show pass is a second hashcat invocation
        # over the same file; a parse error here is the same FORMAT class. Catch
        # it so it is never silently downgraded to "no match".
        if completed_process_show is not None:
            show_combined = (
                (completed_process_show.stdout or "")
                + "\n"
                + (completed_process_show.stderr or "")
            )
            if _detect_hashcat_format_error(show_combined):
                _render_cracking_format_error_panel(
                    hash_type=hash_type,
                    hash_description=hash_description,
                    hashcat_mode=hashcat_mode,
                    hash_file=hash,
                )
                return {"status": "format_error", "cracked_count": 0}

        if completed_process_show is None:
            print_warning("'hashcat --show' command failed to execute.")
        elif completed_process_show.returncode != 0:
            print_warning(
                f"'hashcat --show' command may have failed. Return code: {completed_process_show.returncode}"
            )
            if completed_process_show.stderr and not _is_benign_hashcat_stderr(
                completed_process_show.stderr
            ):
                print_error(f"Error output: {completed_process_show.stderr}")
            elif completed_process_show.stderr:
                print_info_debug(
                    "Non-fatal hashcat stderr during '--show':\n"
                    f"{completed_process_show.stderr}"
                )
        elif completed_process_show.stderr:
            if _is_benign_hashcat_stderr(completed_process_show.stderr):
                print_info_debug(
                    "Non-fatal hashcat stderr during '--show':\n"
                    f"{completed_process_show.stderr}"
                )
            else:
                print_warning_debug(
                    "Unexpected hashcat stderr during '--show':\n"
                    f"{completed_process_show.stderr}"
                )

        show_stdout = ""
        if completed_process_show is not None and completed_process_show.stdout:
            show_stdout = completed_process_show.stdout.strip()
        show_lines = []
        if show_stdout:
            for line in show_stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                if ":" not in line:
                    continue
                if line.startswith("NOTE:") or line.lower().startswith("hash-mode"):
                    continue
                if line.lower().startswith("do not report"):
                    continue
                left = line.split(":", 1)[0].strip()
                if not left or " " in left:
                    continue
                show_lines.append(line)
        try:
            with open(file_path, "w", encoding="utf-8") as handle:
                for line in show_lines:
                    handle.write(line + "\n")
        except OSError as exc:
            telemetry.capture_exception(exc)
            print_error("Failed to write hashcat cracked output file.")
            print_exception(show_locals=False, exception=exc)

        # Third phase: extract and display credentials
        if os.path.exists(file_path) and os.path.getsize(file_path) > 1:
            service = HashcatCrackingService()
            result = service.extract_creds_from_hash(file_path)
            if result and result.has_credentials():
                creds = result.credentials
                # Telemetry: track successful hash cracking
                try:
                    properties = {
                        "hash_type": hash_type,
                        "credentials_cracked": len(creds),
                        "scan_mode": getattr(shell, "scan_mode", None),
                        "workspace_type": shell.type,
                        "auto_mode": shell.auto,
                        "wordlist": _wordlist_telemetry_label(wordlist_name),
                    }
                    properties.update(
                        build_lab_event_fields(shell=shell, include_slug=True)
                    )
                    telemetry.capture("hash_cracked", properties)
                    # Track victory for session summary (Hormozi: Give:Ask ratio)
                    if hasattr(shell, "_session_victories"):
                        shell._session_victories.append("hash_cracked")
                except Exception as e:
                    telemetry.capture_exception(e)
                try:
                    if str(getattr(shell, "type", "") or "").strip().lower() == "audit":
                        audit_properties = {
                            "hash_type": hash_type,
                            "wordlist": _wordlist_telemetry_label(wordlist_name),
                            "hashes_cracked": len(creds),
                            "scan_mode": getattr(shell, "scan_mode", None),
                            "workspace_type": getattr(shell, "type", None),
                            "auto_mode": getattr(shell, "auto", False),
                        }
                        audit_properties.update(
                            build_lab_event_fields(shell=shell, include_slug=True)
                        )
                        telemetry.capture(
                            "audit_wordlist_cracked",
                            audit_properties,
                        )
                except Exception as exc:  # pragma: no cover - telemetry best effort
                    telemetry.capture_exception(exc)

                _render_cracked_credentials_panel(
                    shell,
                    creds=creds,
                    hash_type=hash_type,
                    hash_description=hash_description,
                    wordlist_name=wordlist_name,
                    total_hashes=total_hashes,
                )
                try:
                    _render_credential_harvest_for_crack(
                        shell,
                        domain=domain,
                        hash_type=hash_type,
                        creds=creds,
                        hash_file=file_path,
                    )
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                # Persist credentials after displaying them
                attempted_users = set(_extract_hash_users(hash))
                cracked_users = set(creds.keys())
                for username, password in creds.items():
                    if (
                        hash_type in _GRAPH_TRACKED_ROAST_HASH_TYPES
                        or hash_type == "timeroast"
                    ):
                        try:
                            from adscan_internal.services.attack_graph_service import (
                                update_roast_entry_edge_status,
                            )

                            update_roast_entry_edge_status(
                                shell,
                                domain,
                                roast_type=hash_type,
                                status="success",
                                username=username,
                                wordlist=wordlist_name,
                            )
                        except Exception as exc:  # pragma: no cover
                            telemetry.capture_exception(exc)
                    # Centralized metadata: a cracked TGS/AS-REP is by
                    # definition a kerberoastable / asrep-roastable principal.
                    # Tag it so the privilege-role picker can rank it.
                    cred_metadata = None
                    try:
                        from adscan_internal.services.credentials import (
                            CredentialKind,
                            CredentialMetadata,
                        )

                        if hash_type in ("kerberoast", "asreproast"):
                            # Cracked roast hashes are always cleartext
                            # passwords; record secret_kind so downstream
                            # consumers don't have to infer it.
                            cred_metadata = CredentialMetadata(
                                secret_kind=CredentialKind.PASSWORD,
                            )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)

                    shell.add_credential(
                        domain, username, password, metadata=cred_metadata,
                        credential_origin=hash_type,
                    )

                    # Broadcast-poison NetNTLMv2 → materialize the attack-graph
                    # entry-vector edge on crack SUCCESS only (the capture itself
                    # is the LLMNR/NBT-NS poisoning finding, not an edge). Gated on
                    # the provenance the poisoning capture handler recorded, so a
                    # NetNTLMv2 captured via another origin is never mis-attributed.
                    if "NTLMv2" in hash_type:
                        _maybe_materialize_poison_capture_crack_edge(
                            shell, domain, username
                        )

                    # NetNTLMv1 crack SUCCESS: account-type-aware. A user
                    # account is wordlist-crackable (supported) and is
                    # materialized as its own exploited CrackNTLMv1 edge; a
                    # machine account stays unsupported (rainbow-only) and is
                    # a no-op here.
                    if "NTLMv1" in hash_type:
                        _maybe_materialize_ntlmv1_crack_edge(
                            shell, domain, username
                        )

                # Mark remaining attempted users as failed for this wordlist.
                if hash_type in _GRAPH_TRACKED_ROAST_HASH_TYPES:
                    remaining = sorted(
                        (attempted_users - cracked_users),
                        key=str.lower,
                    )
                    for user in remaining:
                        try:
                            from adscan_internal.services.attack_graph_service import (
                                update_roast_entry_edge_status,
                            )

                            update_roast_entry_edge_status(
                                shell,
                                domain,
                                roast_type=hash_type,
                                status="failed",
                                username=user,
                                wordlist=wordlist_name,
                            )
                        except Exception as exc:  # pragma: no cover
                            telemetry.capture_exception(exc)
                return {"status": "success", "cracked_count": len(creds)}
            else:
                _render_cracking_failure_panel(
                    hash_type=hash_type,
                    hash_description=hash_description,
                    wordlist_name=wordlist_name,
                    cause=initial_failure_cause,
                    total_hashes=total_hashes,
                )
                return {"status": "no_match", "cracked_count": 0}
        else:
            # Telemetry: track failed hash cracking
            try:
                properties = {
                    "hash_type": hash_type,
                    "scan_mode": getattr(shell, "scan_mode", None),
                    "workspace_type": shell.type,
                    "auto_mode": shell.auto,
                    "wordlist": _wordlist_telemetry_label(wordlist_name),
                }
                properties.update(
                    build_lab_event_fields(shell=shell, include_slug=True)
                )
                telemetry.capture("hash_not_cracked", properties)
            except Exception as e:
                telemetry.capture_exception(e)

            _render_cracking_failure_panel(
                hash_type=hash_type,
                hash_description=hash_description,
                wordlist_name=wordlist_name,
                cause=initial_failure_cause,
                total_hashes=total_hashes,
            )
            if hash_type in _GRAPH_TRACKED_ROAST_HASH_TYPES:
                try:
                    from adscan_internal.services.attack_graph_service import (
                        update_roast_entry_edge_status,
                    )

                    users = _extract_hash_users(hash)
                    for user in users:
                        update_roast_entry_edge_status(
                            shell,
                            domain,
                            roast_type=hash_type,
                            status="failed",
                            username=user,
                            wordlist=wordlist_name,
                        )
                except Exception as exc:  # pragma: no cover
                    telemetry.capture_exception(exc)
            from adscan_internal.interaction import is_non_interactive as _is_non_interactive
            _non_interactive = _is_non_interactive(shell)
            if hash_type == "asreproast":
                marked_domain = mark_sensitive(domain, "domain")
                if (
                    not _non_interactive
                    and Confirm.ask(
                        f"Do you want to crack the asreproast hashes for domain {marked_domain} with another wordlist?",
                        default=False,
                    )
                ):
                    shell.cracking("asreproast", domain, hash, failed=True)
            if (
                hash_type == "asreproast"
                and shell.domains_data[domain]["auth"] != "auth"
            ):
                shell.ask_for_kerberoast_preauth(domain, shell.username or "")
            if hash_type == "kerberoast":
                marked_domain = mark_sensitive(domain, "domain")
                if (
                    not _non_interactive
                    and Confirm.ask(
                        f"Do you want to crack the kerberoast hashes for domain {marked_domain} with another wordlist?",
                        default=False,
                    )
                ):
                    shell.cracking("kerberoast", domain, hash, failed=True)
            if hash_type == "timeroast":
                marked_domain = mark_sensitive(domain, "domain")
                if (
                    not _non_interactive
                    and Confirm.ask(
                        f"Do you want to crack the timeroast hashes for domain {marked_domain} with another wordlist?",
                        default=False,
                    )
                ):
                    shell.cracking("timeroast", domain, hash, failed=True)
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing hashcat.")
        print_exception(show_locals=False, exception=e)
        return {"status": "error", "cracked_count": 0}

    return {"status": "no_match", "cracked_count": 0}


__all__ = [
    "CrackingShell",
    "HashCrackingShell",
    "ask_for_cracking",
    "choose_cracking_wordlist",
    "format_chosen_wordlist_line",
    "run_cracking",
    "do_cracking",
    "execute_cracking",
    "run_sync_clock",
    "run_password_spraying",
    "handle_hash_cracking",
]
