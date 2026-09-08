# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the Windows onefile ``adscan.exe`` (LITE).

This is the LONG-TERM Windows distribution target: a single file a sysadmin
downloads and runs, like PingCastle.exe. It builds ON TOP of the same inputs
as the validated folder-bundle assembled by ``scripts/build_adscan_windows.ps1``
(the embeddable-CPython + ``site\\`` + ``vendor\\`` + engine-source layout).

SEPARATE from the Linux ``adscan.spec`` on purpose:
  * entry point is ``adscan.py`` directly (no PyArmor pack, LITE strips ``pro/``),
  * NO Linux terminfo datas (Windows console needs none of it),
  * NO POSIX runtime paths (no opt-adscan tree, no usr-bin Chromium) — the
    Playwright browser is resolved from the exe's ``_MEIPASS`` by a Windows
    runtime hook,
  * the vendored native stack and its transitive pure-python deps are declared
    as hiddenimports so onefile analysis does not miss the runtime imports the
    embeddable ``._pth`` covers in the folder-bundle.

VALIDATED vs TODO
-----------------
VALIDATED (proven by the hand-assembled folder-bundle that compromised a domain):
  * the vendored-stack import set (aardwolf/aiosmb/asysocks/badauth/badldap/
    kerbad/pypykatz/winacl) and its transitive pure-python deps below,
  * the engine-source layout (adscan.py + adscan_internal + adscan_core, LITE).

TODO (author-only here; NOT yet proven end-to-end in onefile form):
  * embedded tool binaries under ``tools\\`` (hashcat/john/rclone/kerbrute/
    PKINITtools) and Chromium — the recipe stages the dirs; the actual pinned
    downloads are marked TODO in the recipe. The ``binaries``/``datas`` globs
    below pick them up once staged, but onefile packaging of large native
    tools has not been validated.
  * ``arc4`` and the ``bitstruct`` C accelerator are RDP-optional (aardwolf).
    They were NOT in the working bundle and RDP degraded gracefully; add them
    to the folder-bundle + ``hiddenimports`` if full RDP is required.
  * onefile end-to-end was intentionally NOT built/run in this change.
  * code-signing (``codesign_identity`` / an Authenticode step) is unset.
"""

import os

from PyInstaller.utils.hooks import collect_all, collect_submodules

# ---------------------------------------------------------------------------
# Data files embedded into the onefile archive (extracted to _MEIPASS at run).
# Only Windows-relevant, LITE-safe assets. NO pro/ templates, NO terminfo.
# ---------------------------------------------------------------------------
datas = [
    ("adscan_internal/services/report_design/_css", "adscan_internal/services/report_design/_css"),
    ("adscan_internal/assets/logos", "adscan_internal/assets/logos"),
    ("adscan_internal/assets/demo_workspace", "adscan_internal/assets/demo_workspace"),
    ("adscan_internal/assets/report_samples", "adscan_internal/assets/report_samples"),
    # assets/rules ships the hashcat effort-ladder rule files: the committed
    # best64.rule + OneRuleToRuleThemStill-10k.rule, AND — once the recipe has
    # fetched it into this dir — the full 48k OneRuleToRuleThemStill.rule (the
    # effort ladder's top rung, resolved module-relatively at runtime; a missing
    # 48k rule degrades to the committed 10k prefix).
    ("adscan_internal/assets/rules", "adscan_internal/assets/rules"),
    # assets/cracking holds john.conf (the John the Ripper rule ladder). It is
    # resolved via a module-relative path at runtime, so the onefile archive must
    # carry the data dir explicitly or Windows John cracking loses its ruleset.
    ("adscan_internal/assets/cracking", "adscan_internal/assets/cracking"),
]

# Bundled wordlists + tool binaries, embedded only when the recipe has staged
# them (they are large and fetched by the recipe, not tracked in git). Guarded so
# the spec parses and builds even before Phase 4 staging.
#
# CRITICAL: PyInstaller runs from the REPO ROOT, but the recipe builds the merged
# combined_audit_base.txt and stages the tools INTO THE BUNDLE dir
# (dist/adscan-windows/{wordlists,tools}) — a DIFFERENT dir from the repo's own
# gitignored ./wordlists (which in CI holds only rockyou). A bare
# ``os.path.isdir("wordlists")`` therefore bundled the REPO's rockyou-only dir and
# silently DROPPED the 94M-line combined the recipe just built. The recipe now
# exports ADSCAN_WIN_WORDLISTS / ADSCAN_WIN_TOOLS with the absolute BUNDLE paths;
# read those, falling back to the repo-relative dir for a manual build that stages
# next to the spec.
_bundle_wordlists = os.environ.get("ADSCAN_WIN_WORDLISTS") or "wordlists"
_bundle_tools = os.environ.get("ADSCAN_WIN_TOOLS") or "tools"

# The wordlists dir carries rockyou.txt AND — once the recipe has run
# scripts/build_combined_audit_wordlist.ps1 — the merged combined_audit_base.txt
# (the ~94M-line audit base, priority-concat + order-preserving dedup), so
# Windows audit-mode cracking has the same coverage as the Linux runtime image.
# Always mapped to <_MEIPASS>/wordlists so the frozen runtime's
# _bundled_wordlists_dir() (cracking_wordlist_policy) resolves it.
if os.path.isdir(_bundle_wordlists):
    datas.append((_bundle_wordlists, "wordlists"))  # includes combined_audit_base.txt when staged

binaries = []
# tools\ holds the embedded native helper binaries (hashcat/john/rclone/
# kerbrute/PKINITtools) and, when staged, the bundled Chromium. They are
# executables, so they go into `binaries` (marked as data-like via a nested
# dest dir); the Windows Playwright runtime hook points Chromium at _MEIPASS.
if os.path.isdir(_bundle_tools):
    for root, _dirs, files in os.walk(_bundle_tools):
        for fname in files:
            src = os.path.join(root, fname)
            # dest must be the tools-relative subpath (so <_MEIPASS>/tools/...),
            # NOT relative to CWD — the bundle dir may be an absolute path.
            dest = os.path.join("tools", os.path.relpath(root, _bundle_tools))
            binaries.append((src, dest))

# ---------------------------------------------------------------------------
# Hidden imports: the vendored native stack + its transitive PURE-PYTHON deps.
# In the folder-bundle these resolve via the embeddable ._pth; onefile analysis
# must be told about them explicitly.
# ---------------------------------------------------------------------------
hiddenimports = [
    # Vendored skelsec native AD stack (must match the ._pth in the recipe).
    "aardwolf",
    "aiosmb",
    "asysocks",
    "badauth",
    "badldap",
    "kerbad",
    "pypykatz",
    "winacl",
    # Transitive pure-python deps that had to be present in the working bundle.
    "unicrypto",
    "unicrypto.backends.pycryptodomex",
    "asn1crypto",
    "asn1tools",
    "pyparsing",
    "bitstruct",
    "unidns",
    "minidump",
    "aiowinreg",
    "aesedb",
    "pyperclip",
    "tabulate",
    "colorama",
    # Normal runtime deps.
    "Cryptodome",
    "cryptography",
    "cffi",
    "_cffi_backend",
    "pycparser",
    "h11",
    "dns",
    "dns.resolver",
    "rich",
    "questionary",
    "prompt_toolkit",
    "wcwidth",
    "PIL",
    "six",
    "tqdm",
    "jinja2",
    "certifi",
    "playwright",
    "playwright.sync_api",
    # Engine internals PyInstaller cannot always trace from a dynamic import.
    "adscan_internal.services.attack_graph_service",
]

# collect_submodules pulls in the deep module trees of the vendored stack so no
# dynamically-imported submodule is dropped from the onefile archive.
for _pkg in ("aardwolf", "aiosmb", "asysocks", "badauth", "badldap", "kerbad", "pypykatz", "winacl"):
    hiddenimports += collect_submodules(_pkg)

# The console/TUI layer (rich, questionary, prompt_toolkit) is reached through
# the output SSOT, not by a top-level static import PyInstaller can trace — a
# missing `rich` here is a HARD startup crash (ModuleNotFoundError on adscan.py
# line 3). collect_all also grabs each package's bundled DATA (rich ships its
# default theme/emoji tables), so a hiddenimport alone is not enough. Belt-and-
# suspenders: full module tree + data for every UI dependency.
for _ui_pkg in ("rich", "questionary", "prompt_toolkit", "wcwidth", "colorama"):
    # collect_all returns (datas, binaries, hiddenimports) — in THAT order.
    _datas, _bins, _mods = collect_all(_ui_pkg)
    datas += _datas
    binaries += _bins
    hiddenimports += _mods
hiddenimports += collect_submodules("unicrypto")
hiddenimports += collect_submodules("Cryptodome")
hiddenimports += collect_submodules("jinja2")
hiddenimports += collect_submodules("playwright")


# The recipe pip-installs the whole ``.[cli]`` dep tree (rich, questionary,
# playwright, impacket, …) into the bundle's ``site\`` with ``pip install
# --target`` — NOT into the build Python's own site-packages. PyInstaller runs
# under the build Python, so unless ``site\`` is on the analysis path it cannot
# import those deps and the onefile .exe dies at startup with
# ``ModuleNotFoundError: No module named 'rich'`` (adscan.py line 3). The recipe
# exports ADSCAN_WIN_SITE with the absolute site dir; fall back to the default
# -OutDir layout so a manual ``pyinstaller adscan.windows.spec`` still resolves.
import os as _os

_site_dir = _os.environ.get("ADSCAN_WIN_SITE") or _os.path.join(
    "dist", "adscan-windows", "site"
)

a = Analysis(
    ["adscan.py"],
    pathex=[
        # The whole pip-installed dependency tree (rich/questionary/playwright/
        # impacket/native transitive deps) lives here — MUST be on pathex.
        _site_dir,
        # The vendored editable installs live under vendor\<lib>; keep them on
        # the analysis path so imports resolve the same way the ._pth does.
        "vendor/aardwolf",
        "vendor/aiosmb",
        "vendor/asysocks",
        "vendor/badauth",
        "vendor/badldap",
        "vendor/kerbad",
        "vendor/pypykatz",
        "vendor/winacl",
    ],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=["pyinstaller_hooks"],
    hooksconfig={},
    # Reuse the pydantic-plugin disable hook (platform-neutral). The Playwright
    # runtime hook is Windows-specific and resolves the browser from _MEIPASS —
    # do NOT reuse the Linux pyinstaller_runtime_hook_playwright.py, which
    # hardcodes POSIX runtime paths (the opt-adscan tree + a usr-bin Chromium).
    runtime_hooks=[
        "pyinstaller_runtime_hook_disable_pydantic_plugins.py",
        "pyinstaller_runtime_hook_playwright_windows.py",
    ],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="adscan",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    # UPX can corrupt some Windows native DLLs (and defenders flag it); leave
    # it off for the Windows onefile until validated.
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    # TODO(signing): set codesign_identity / add an Authenticode signing step in
    # the CI workflow so Windows SmartScreen does not block adscan.exe.
    codesign_identity=None,
    entitlements_file=None,
)
