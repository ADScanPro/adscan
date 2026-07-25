"""PRO partner-tag start gate.

Under the shared-image distribution model, the PRO Docker image
(``adscan/adscan-pro``) is identical for every partner. Access control is the
revocable registry token plus a short expiry fuse baked into the binary. The
*partner tag* — which used to be baked per-partner at build time — is instead
asked once at runtime and persisted to the bind-mounted volume
(``~/.adscan`` ↔ ``/opt/adscan``), so it survives across ``docker run`` and is
only re-asked if the customer wipes the volume.

This module is the single entry point for that gate. It runs at PRO startup:

* **LITE** — no gate at all.
* **PRO, tag already resolved** (env var or persisted volume file) — no-op.
* **PRO, tag missing, interactive** — render a premium prompt, validate the
  format, persist it to the volume, continue.
* **PRO, tag missing, non-interactive** — if the env var is set, use it;
  otherwise print a clear English error and refuse to start PRO. It never
  blocks waiting on stdin (that would hang ``adscan ci``).

The validation is format-only (lowercase / digits / hyphens) — there is no
membership check against any list; the registry token is the real gate.
"""

from __future__ import annotations

import os
import re

from adscan_core import telemetry
from adscan_core.rich_output import (
    print_error,
    print_info_debug,
    print_instruction,
    print_success,
    prompt_ask,
)
from adscan_internal.interaction import is_non_interactive
from adscan_core.rich_output import print_exception

# Format contract for a partner tag: starts with a lowercase letter or digit,
# then 1-40 more of lowercase letters, digits, or hyphens (2-41 chars total).
# Deliberately strict: no uppercase, no spaces, no underscores, no leading
# hyphen — this is a URL/telemetry-safe slug like "glenn-mssp".
_PARTNER_TAG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")

_MAX_PROMPT_ATTEMPTS = 3


def validate_partner_tag(tag: str) -> bool:
    """Return True when ``tag`` matches the partner-tag format contract.

    Accepts e.g. ``glenn-mssp``; rejects empty strings, uppercase, whitespace,
    odd characters, and tags longer than 41 characters. Pure function — safe to
    unit test with no I/O.

    Args:
        tag: Candidate partner tag.

    Returns:
        True if the tag is well-formed, False otherwise.
    """
    if not isinstance(tag, str):
        return False
    return bool(_PARTNER_TAG_PATTERN.match(tag.strip()))


def is_pro_mode(license_mode: object) -> bool:
    """Return True when ``license_mode`` denotes the PRO tier.

    Accepts the raw ``shell.license_mode`` value (a string like ``"PRO"`` /
    ``"LITE"``) and normalizes it. Anything that is not PRO (including None)
    is treated as not-PRO so the gate fails safe toward "no gate".
    """
    return str(license_mode or "").strip().upper() == "PRO"


def _runtime_image_tag() -> str:
    """Return the tag of the running runtime image, or '' if undeterminable.

    Reads ``ADSCAN_RUNTIME_IMAGE`` (set by the launcher, e.g.
    ``adscan/adscan-pro:edge``) and extracts the tag. Tolerant of a registry
    ``host:port`` prefix (``registry:5000/adscan/adscan-pro:edge`` -> ``edge``)
    by only splitting the final path segment on ``:``.
    """
    image = str(os.getenv("ADSCAN_RUNTIME_IMAGE") or "").strip().lower()
    if not image:
        return ""
    last_segment = image.rsplit("/", 1)[-1]  # name:tag, drops registry/path
    if ":" not in last_segment:
        return ""
    return last_segment.rsplit(":", 1)[-1]


def _is_dev_edge_runtime() -> bool:
    """True when running the internal dev/CI ``:edge`` image.

    Partners always receive ``:latest`` or a pinned ``:vX.Y.Z`` tag; only the
    founder's own ``--dev`` runs and the CI regression workflows run ``:edge``.
    The partner-tag gate is attribution, not access control (the registry token
    and expiry fuse are), so skipping it for ``:edge`` only means those internal
    sessions carry no ``partner_tag`` — which is correct, and it keeps the
    founder able to smoke-test the real gate by running the ``:latest`` image.
    """
    return _runtime_image_tag() == "edge"


def partner_tag_required(license_mode: object) -> bool:
    """Return True when the PRO start gate must ask for a partner tag.

    The gate is required only when the session is PRO, is *not* the internal
    dev/CI ``:edge`` image, and no partner tag is currently resolvable (neither
    env var nor persisted volume file).
    """
    if not is_pro_mode(license_mode):
        return False
    if _is_dev_edge_runtime():
        # Internal dev/CI :edge build — never gate the founder's own runs.
        print_info_debug(
            "Partner-tag gate skipped: running the dev/CI :edge image."
        )
        return False
    return not telemetry.resolve_partner_tag()


def _render_intro_panel(console: object) -> None:
    """Render the premium onboarding panel above the prompt."""
    from rich.panel import Panel
    from rich.text import Text

    from adscan_core.theme import ADSCAN_PRIMARY

    body = Text.from_markup(
        "\n"
        "[bold]This is ADscan PRO.[/bold]\n\n"
        "Enter the [bold]partner tag[/bold] from your onboarding email to "
        "continue. It links this install to your account and is stored on this "
        "machine, so you are asked only once.\n\n"
        "[dim]Format: lowercase letters, digits and hyphens "
        "(for example, glenn-mssp).[/dim]\n"
    )
    panel = Panel(
        body,
        title=f"[bold {ADSCAN_PRIMARY}]» ADscan PRO · activation[/bold {ADSCAN_PRIMARY}]",
        border_style=ADSCAN_PRIMARY,
        padding=(1, 2),
    )
    console.print(panel)


def _prompt_for_partner_tag() -> str | None:
    """Render the premium prompt loop and return a validated tag or None.

    Only ever called on the interactive path (the caller gates on
    ``is_non_interactive`` first), so ``prompt_ask`` here always blocks on a
    real terminal — it never auto-resolves a default into an invalid tag.

    Returns:
        A validated partner tag, or None if the operator gave up / the prompt
        could not collect a valid value within the attempt budget.
    """
    from adscan_internal import get_console

    _render_intro_panel(get_console())

    for attempt in range(1, _MAX_PROMPT_ATTEMPTS + 1):
        try:
            raw = prompt_ask("  Partner tag")
        except (EOFError, KeyboardInterrupt):
            return None
        candidate = (raw or "").strip()
        if validate_partner_tag(candidate):
            return candidate.lower()
        remaining = _MAX_PROMPT_ATTEMPTS - attempt
        if remaining > 0:
            print_error(
                "Invalid partner tag. Use lowercase letters, digits and "
                f"hyphens, 2-41 characters. {remaining} attempt(s) left."
            )
    return None


def ensure_partner_tag_for_pro(license_mode: object) -> bool:
    """Enforce the PRO partner-tag gate at session start.

    Args:
        license_mode: The resolved session license mode (``shell.license_mode``).

    Returns:
        True when the session may proceed (LITE, or PRO with a resolved/
        newly-persisted tag). False when a PRO session must be refused because
        no tag could be resolved in a non-interactive run, or the operator
        failed to supply a valid tag interactively.
    """
    if not partner_tag_required(license_mode):
        # LITE, or PRO with a tag already resolved — nothing to do.
        return True

    if is_non_interactive():
        # Non-interactive: only the env var can satisfy the gate. We must never
        # block on stdin here (it would hang `adscan ci`). `partner_tag_required`
        # already consulted the env var via `resolve_partner_tag`, so reaching
        # this point means it is absent.
        print_error(
            "ADscan PRO requires a partner tag, but none was provided. "
            "Set ADSCAN_PARTNER_TAG to the tag from your onboarding email "
            "(for example, ADSCAN_PARTNER_TAG=glenn-mssp) and re-run."
        )
        print_info_debug(
            "Partner-tag gate refused PRO start in non-interactive mode: "
            "no ADSCAN_PARTNER_TAG and no persisted partner.json."
        )
        return False

    tag = _prompt_for_partner_tag()
    if not tag:
        print_error(
            "A valid partner tag is required to use ADscan PRO. "
            "Check your onboarding email and try again."
        )
        return False

    try:
        telemetry.persist_partner_tag(tag)
        telemetry.refresh_partner_tag()
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(
            "Could not save the partner tag to the ADscan volume. "
            "Check that ~/.adscan is writable and try again."
        )
        return False

    print_success("Partner tag saved. Welcome to ADscan PRO.")
    print_instruction(
        "Stored in this install's volume — you will not be asked again unless "
        "the volume is reset."
    )
    return True
