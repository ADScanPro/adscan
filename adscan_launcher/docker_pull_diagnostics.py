"""Diagnostic helpers for ``docker pull`` failures.

The default Python representation of a captured ``docker pull`` stderr/stdout
is hostile to humans: Docker writes progress with ANSI cursor-positioning
escapes (``\\x1b[36A`` etc.) so it can update layer rows in place on a TTY.
When ADscan captures that output for telemetry and then prints it with
``f"{!r}"`` formatting on failure, the operator sees thousands of literal
``\\x1b[...]`` codes — useless noise that buries the one line that actually
explains what happened.

This module exists to:

1. Strip ANSI / carriage-return progress artefacts from captured output so
   the operator (and the telemetry backend) see clean text.
2. Classify the failure into one of a small set of well-known kinds, each
   with targeted, copy-pasteable remediation.
3. Provide the title, glyph, and severity tier for a premium failure
   panel — semantic colour, single-CTA layout, no jargon.

Adding a new failure kind is intentionally cheap:

* Add a member to :class:`PullFailureKind`.
* Add a matcher entry to ``_CLASSIFIERS`` (regex + ordering matters — the
  first match wins, so put the most specific patterns first).
* Add a presentation entry to ``_PRESENTATION`` (title, glyph, severity).

Never bake per-release prose here. The remediation panels work for any
version transition the product will ever ship; per-version content lives
on the release-notes page and is linked from the panel only when it
genuinely helps.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal


# ─────────────────────────────────────────────────────────────────────
# ANSI / progress noise stripping
# ─────────────────────────────────────────────────────────────────────


# CSI sequences are the bulk of Docker's progress noise:
#   ESC [ <params> <intermediates> <final byte>
# We strip both the canonical CSI form and the OSC form to cover terminal
# titles + a few other uncommon sequences Docker may emit.
_ANSI_CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ANSI_OSC_RE = re.compile(r"\x1b\][^\x07]*\x07")
# Carriage-return progress: Docker overwrites each layer's progress line
# with ``\r`` between updates. After ANSI removal the captured output is
# typically several hundred ``\r`` joins per layer — collapse them to
# newlines so we see one row per state change instead of one mega-line.
_CR_PROGRESS_RE = re.compile(r"\r+")


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from a string (CSI + OSC).

    Safe to call on empty strings. Best-effort: covers the sequences
    Docker actually emits during ``docker pull``. Not a complete VT
    parser — does not handle DEC private modes or every legacy sequence,
    but those do not appear in Docker output.
    """
    if not text:
        return ""
    cleaned = _ANSI_CSI_RE.sub("", text)
    cleaned = _ANSI_OSC_RE.sub("", cleaned)
    return cleaned


def tail_meaningful_lines(text: str, max_lines: int = 5) -> list[str]:
    """Return up to ``max_lines`` of substantive trailing output.

    Splits on either real newlines or ``\\r``-based progress overwrites
    (which Docker uses to keep each layer's status on a single visual
    line). Filters out empty lines and pure progress noise so the
    operator sees the actual error message at the tail, not the last
    "Downloading X/YMB" tick.
    """
    if not text:
        return []
    # Collapse progress overwrites: each ``\r``-separated chunk is the
    # latest state of one layer's progress row. The most recent value
    # wins on a real terminal; we keep them all but on separate lines
    # so the tail still contains the final state.
    flattened = _CR_PROGRESS_RE.sub("\n", text)
    candidates = [ln.strip() for ln in flattened.splitlines()]
    # Drop empty lines and pure progress lines ("Downloading 1.5MB/2.0MB",
    # "Extracting", "Waiting") — these are noise once we have ANSI off.
    progress_marker_re = re.compile(
        r"^[0-9a-f]{12}: (Downloading|Extracting|Waiting|Pulling fs layer|"
        r"Verifying Checksum|Download complete|Pull complete|Already exists)"
    )
    substantive = [
        ln for ln in candidates
        if ln and not progress_marker_re.match(ln)
    ]
    return substantive[-max_lines:]


# ─────────────────────────────────────────────────────────────────────
# Failure classification
# ─────────────────────────────────────────────────────────────────────


PullFailureKind = Literal[
    "auth_or_rate_limit",
    "manifest_not_found",
    "registry_consistency",
    "no_disk_space",
    "network_dns",
    "network_timeout",
    "daemon_unreachable",
    "runtime_unsupported",
    "unknown",
]


@dataclass(frozen=True, slots=True)
class PullFailureDiagnosis:
    """Outcome of classifying a ``docker pull`` failure.

    Attributes:
        kind: Best-match failure kind. ``"unknown"`` when no pattern
            matched — the panel falls back to the generic remediation
            in that case. ``"runtime_unsupported"`` is not classified
            from captured stderr/stdout at all — it is recorded directly
            by the container-runtime preflight (see
            ``_ensure_supported_container_runtime`` in
            ``docker_commands.py``) when ADscan refuses to pull because
            the runtime is a rejected Podman compatibility shim rather
            than Docker Engine. That refusal already prints its own
            explanation, so this is a distinct terminal outcome and
            never falls through to the generic "unclassified error"
            panel.
        evidence: The cleaned, ANSI-stripped line(s) from the captured
            output that contain the actual error message. Safe to log
            and to display in a debug section of the failure panel.
        rate_limit_likely: ``True`` iff the evidence suggests Docker
            Hub anonymous rate limit specifically (the auth-vs-ratelimit
            ambiguity that motivated this module — see the panel copy).
    """

    kind: PullFailureKind
    evidence: list[str]
    rate_limit_likely: bool = False


# Ordered: the FIRST regex that matches wins. Put the most specific
# patterns above the generic ones so e.g. "toomanyrequests" wins over a
# generic "unauthorized" if both appear in stderr.
_CLASSIFIERS: tuple[tuple[re.Pattern[str], PullFailureKind, bool], ...] = (
    (re.compile(r"\btoomanyrequests\b", re.IGNORECASE), "auth_or_rate_limit", True),
    (
        re.compile(r"\bunauthorized\b.*\bauthentication\s+required\b", re.IGNORECASE),
        "auth_or_rate_limit",
        False,
    ),
    (
        re.compile(r"\bdenied\b.*\brequested\s+access\b", re.IGNORECASE),
        "auth_or_rate_limit",
        False,
    ),
    (
        re.compile(r"\bno\s+space\s+left\s+on\s+device\b", re.IGNORECASE),
        "no_disk_space",
        False,
    ),
    (
        re.compile(r"\bmanifest\b.*\bnot\s+found\b", re.IGNORECASE),
        "manifest_not_found",
        False,
    ),
    (re.compile(r"\bmanifest\s+unknown\b", re.IGNORECASE), "manifest_not_found", False),
    (
        re.compile(
            r"\b(blob\s+unknown|content\s+descriptor\b[^\n]*not\s+found)\b",
            re.IGNORECASE,
        ),
        "registry_consistency",
        False,
    ),
    # DNS resolution failure. Placed BEFORE network_timeout: a name-lookup
    # error must be diagnosed as DNS, not mis-caught as a generic timeout.
    # The DNS form is specifically `dial tcp: lookup <host>` (no timeout/
    # refused token), so it does not collide with the timeout classifier's
    # `dial tcp ... timeout|refused` pattern above.
    (
        re.compile(
            r"(temporary\s+failure\s+in\s+name\s+resolution|"
            r"nameresolutionerror|"
            r"failed\s+to\s+resolve|"
            r"lookup\s+\S+[^\n]*\b(no\s+such\s+host|server\s+misbehaving|"
            r"temporary\s+failure)\b|"
            r"dial\s+tcp:\s+lookup\s+)",
            re.IGNORECASE,
        ),
        "network_dns",
        False,
    ),
    (
        re.compile(
            r"\b(i/o\s+timeout|context\s+deadline\s+exceeded|"
            r"dial\s+tcp\b[^\n]*\b(timeout|refused)\b|"
            r"connection\s+(refused|reset)|"
            r"net/http:\s*request\s+canceled)\b",
            re.IGNORECASE,
        ),
        "network_timeout",
        False,
    ),
    (
        re.compile(
            r"\b(cannot\s+connect\s+to\s+the\s+docker\s+daemon|"
            r"is\s+the\s+docker\s+daemon\s+running)\b",
            re.IGNORECASE,
        ),
        "daemon_unreachable",
        False,
    ),
)


def classify_pull_failure(stderr: str, stdout: str) -> PullFailureDiagnosis:
    """Classify a ``docker pull`` failure from captured output.

    Both ``stderr`` and ``stdout`` are inspected because Docker writes
    its progress bar to stdout but its error messages to stderr — and
    when a Docker client mode mixes them (newer versions), the error
    can end up in either stream. We strip ANSI noise first so the
    matchers operate on clean text.
    """
    clean_stderr = strip_ansi(stderr or "")
    clean_stdout = strip_ansi(stdout or "")
    combined = f"{clean_stderr}\n{clean_stdout}"

    evidence = tail_meaningful_lines(combined, max_lines=5)

    for pattern, kind, rate_limit_likely in _CLASSIFIERS:
        if pattern.search(combined):
            return PullFailureDiagnosis(
                kind=kind,
                evidence=evidence,
                rate_limit_likely=rate_limit_likely,
            )

    return PullFailureDiagnosis(kind="unknown", evidence=evidence)


# ─────────────────────────────────────────────────────────────────────
# Panel presentation metadata
# ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class PullFailurePresentation:
    """Title, glyph, semantic colour, and copy blocks for a failure panel.

    Each presentation lives in one place so the panel renderer is a
    pure consumer (no chrome decisions live in the renderer). To add a
    new failure kind: register a new ``PullFailurePresentation`` in
    ``_PRESENTATION`` and the renderer picks it up.

    Attributes:
        glyph: Short visual marker. Paired with the title text so the
            signal is legible under ``NO_COLOR``. Never use colour alone.
        title: Headline shown in the panel title bar. Plain language;
            no jargon (the operator may be reading at 2am).
        border_style: Rich colour name. ``"red"`` for unrecoverable
            without operator action, ``"yellow"`` for transient /
            environmental, ``"cyan"`` for retry-and-it-might-work.
        what_lines: 1-3 plain-English lines explaining what happened.
        why_lines: 1-3 lines explaining *why*. The auth/rate-limit case
            is a list of the three possible causes — Docker Hub does
            not tell the client which one, so we tell the operator the
            three options and recommend a one-shot fix that covers all.
        fix_steps: Numbered list of copy-pasteable commands.
        followup: Optional final line — "if this doesn't work, try X".
    """

    glyph: str
    title: str
    border_style: str
    what_lines: tuple[str, ...]
    why_lines: tuple[str, ...]
    fix_steps: tuple[str, ...]
    followup: str = ""


_PRESENTATION: dict[PullFailureKind, PullFailurePresentation] = {
    "auth_or_rate_limit": PullFailurePresentation(
        glyph="🔐",
        title="The registry rejected the pull (auth or rate limit)",
        border_style="yellow",
        what_lines=(
            "The registry returned `unauthorized: authentication required`, "
            "`denied: requested access`, or `toomanyrequests` while pulling "
            "the image.",
        ),
        why_lines=(
            "A registry typically returns the same error response for several "
            "causes and does not tell the client which one:",
            "  1. The image is in a private/partner repo and the daemon is not "
            "logged in (or the token has no access to it).",
            "  2. Anonymous rate limit hit (Docker Hub: 100 pulls per 6h per "
            "IP). Common on VPN exit nodes, corporate NAT, shared CI runners.",
            "  3. Bearer token expired during a slow pull (token TTL ~5 min).",
            "  4. Transient registry backend hiccup.",
        ),
        fix_steps=(
            "{login_command}   # refresh/establish credentials for this registry",
            "{retry_command}",
        ),
        followup=(
            "If the image is in a private/partner repo (e.g. the PRO image on "
            "ghcr.io), ensure your account/token has been granted read access "
            "to it first."
        ),
    ),
    "manifest_not_found": PullFailurePresentation(
        glyph="📦",
        title="Image or tag does not exist on the registry",
        border_style="red",
        what_lines=(
            "The registry returned `manifest unknown` or `not found` — the "
            "image:tag combination ADscan is asking for is not published.",
        ),
        why_lines=(
            "Either the launcher and runtime image versions drifted and "
            "the launcher is requesting an outdated tag that has been "
            "rotated away, OR a PRO partner-tag was revoked or renamed.",
        ),
        fix_steps=(
            "adscan update                   # refresh launcher to the current tag",
            "{retry_command}",
        ),
        followup=(
            "If `adscan update` does not resolve it, the partner tag may "
            "have been rotated. Contact ADscan support with the failing "
            "image name."
        ),
    ),
    "registry_consistency": PullFailurePresentation(
        glyph="♻",
        title="Transient registry inconsistency",
        border_style="cyan",
        what_lines=(
            "Docker Hub reported a `blob unknown` or `content descriptor "
            "not found` error — the manifest references a layer that the "
            "registry cannot find right now.",
        ),
        why_lines=(
            "This is a registry-side consistency hiccup. It usually clears "
            "in seconds-to-minutes without operator action.",
        ),
        fix_steps=(
            "{retry_command}                 # wait 30s first if it fails again",
        ),
    ),
    "no_disk_space": PullFailurePresentation(
        glyph="💾",
        title="Out of disk space",
        border_style="red",
        what_lines=(
            "Docker reported `no space left on device` while extracting "
            "image layers.",
        ),
        why_lines=(
            "The filesystem backing Docker's storage path is full. "
            "ADscan layers + cached images can total several GB.",
        ),
        fix_steps=(
            "df -h /var/lib/docker            # confirm which mount is full",
            "docker system prune -af --volumes   # reclaim unused image + layer storage",
            "{retry_command}",
        ),
        followup=(
            "If you are routinely running short of disk, consider moving "
            "Docker's storage path to a larger partition via "
            "`/etc/docker/daemon.json` (`data-root`)."
        ),
    ),
    "network_dns": PullFailurePresentation(
        glyph="🌐",
        title="Could not resolve the registry hostname (DNS)",
        border_style="yellow",
        what_lines=(
            "Docker could not resolve the registry hostname to an IP address, "
            "so the pull never reached the registry.",
        ),
        why_lines=(
            "The name lookup failed (`Temporary failure in name resolution` / "
            "`no such host`). Usual causes:",
            "  1. The machine is offline or has no working DNS server.",
            "  2. A required VPN is not connected, so the registry name only "
            "resolves once the tunnel is up.",
            "  3. `/etc/resolv.conf` points at an unreachable or wrong resolver.",
        ),
        fix_steps=(
            "ping -c1 1.1.1.1                 # confirm the machine is online",
            "cat /etc/resolv.conf            # confirm a reachable DNS server is set",
            "{retry_command}                 # retry once name resolution works",
        ),
        followup=(
            "If the registry name only resolves through a corporate VPN, "
            "connect the VPN first, confirm it resolves, then retry."
        ),
    ),
    "network_timeout": PullFailurePresentation(
        glyph="⏱",
        title="Network timeout or connection failure",
        border_style="yellow",
        what_lines=(
            "The pull stalled or the connection was reset before Docker "
            "could finish fetching all image layers.",
        ),
        why_lines=(
            "Common causes are slow Wi-Fi, VPN throttling, a corporate "
            "proxy interfering with TLS, or registry-side timeouts on "
            "very large layers.",
        ),
        fix_steps=(
            "{retry_command} --pull-timeout 7200   # raise the ceiling to 2 hours",
            "{retry_command} --pull-timeout 0      # or disable the timeout entirely",
        ),
        followup=(
            "If you are on a corporate proxy, set `HTTPS_PROXY` and "
            "`NO_PROXY` correctly and ensure Docker is configured to use "
            "the same proxy."
        ),
    ),
    "daemon_unreachable": PullFailurePresentation(
        glyph="🔌",
        title="Docker daemon is not running",
        border_style="red",
        what_lines=(
            "The Docker client could not talk to the Docker daemon API.",
        ),
        why_lines=(
            "The Docker service is stopped, or `DOCKER_HOST` points "
            "somewhere unreachable, or your user is not in the `docker` "
            "group.",
        ),
        fix_steps=(
            "sudo systemctl start docker         # start the daemon",
            "sudo systemctl status docker        # confirm it is running",
            "{retry_command}",
        ),
        followup=(
            "If `DOCKER_HOST` is set in your shell, unset it (`unset DOCKER_HOST`) "
            "before retrying."
        ),
    ),
    "runtime_unsupported": PullFailurePresentation(
        glyph="⛔",
        title="Unsupported container runtime (Podman compatibility mode)",
        border_style="red",
        what_lines=(
            "ADscan refused to pull because the `docker` CLI on this host "
            "is a Podman compatibility shim, not Docker Engine.",
        ),
        why_lines=(
            "The rejection message printed before this pull attempt "
            "already explains how to install Docker Engine or opt in to "
            "Podman compatibility mode.",
        ),
        fix_steps=(),
    ),
    "unknown": PullFailurePresentation(
        glyph="❓",
        title="Docker pull failed (unclassified error)",
        border_style="yellow",
        what_lines=(
            "ADscan could not match the failure to a known pattern. The "
            "captured tail is shown below for diagnosis.",
        ),
        why_lines=(),
        fix_steps=(
            "{retry_command}                       # plain retry first",
            "docker pull {image_name}              # bypass ADscan to isolate the issue",
            "{retry_command} --pull-timeout 7200   # increase patience",
        ),
        followup=(
            "If the failure persists, capture the output of "
            "`docker pull {image_name}` and open an issue at "
            "https://adscanpro.com/docs."
        ),
    ),
}


def get_presentation(kind: PullFailureKind) -> PullFailurePresentation:
    """Return the panel presentation for a failure kind."""
    return _PRESENTATION.get(kind, _PRESENTATION["unknown"])


# ─────────────────────────────────────────────────────────────────────
# Last-diagnosis holder
# ─────────────────────────────────────────────────────────────────────
#
# `ensure_image_pulled` is the function that actually runs `docker pull`
# and therefore the only place with access to the raw captured streams.
# The premium failure panel is rendered later, after the multi-attempt
# retry loop in `_ensure_image_pulled_with_legacy_fallback` gives up.
# Threading the diagnosis through every call site would touch a dozen
# signatures, so we record the most-recent failure here and the renderer
# consumes it on demand. Single-use, single-thread launcher — no risk of
# concurrent pulls in this process.

_last_diagnosis: PullFailureDiagnosis | None = None


def record_last_failure(diagnosis: PullFailureDiagnosis) -> None:
    """Record the diagnosis from the most recent docker pull failure."""
    global _last_diagnosis
    _last_diagnosis = diagnosis


def peek_last_failure() -> PullFailureDiagnosis | None:
    """Return the most recent docker pull failure without clearing it.

    Used by the retry loop in ``_ensure_image_pulled_with_legacy_fallback``
    to read the diagnosis of an intermediate failure (so it can render a
    transparent retry message naming the cause) without consuming the
    record. The final ``consume_last_failure`` call by the panel renderer
    still gets whatever the *latest* failure was.
    """
    return _last_diagnosis


def consume_last_failure() -> PullFailureDiagnosis | None:
    """Return and clear the most recent docker pull failure diagnosis."""
    global _last_diagnosis
    diagnosis = _last_diagnosis
    _last_diagnosis = None
    return diagnosis


__all__ = (
    "PullFailureKind",
    "PullFailureDiagnosis",
    "PullFailurePresentation",
    "classify_pull_failure",
    "consume_last_failure",
    "get_presentation",
    "peek_last_failure",
    "record_last_failure",
    "strip_ansi",
    "tail_meaningful_lines",
)
