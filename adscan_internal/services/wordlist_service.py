"""Wordlist management service for ADscan.

This module centralizes configuration and lifecycle management for the
wordlists used across the CLI (e.g. for cracking and spraying).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, Mapping, Optional, Tuple
import os
import shutil
import subprocess

from adscan_internal import telemetry
from adscan_internal.rich_output import print_error, print_info, print_warning
from adscan_internal.services.base_service import BaseService
from adscan_internal.subprocess_env import get_clean_env_for_compilation
from adscan_internal import path_utils
from adscan_core import offline
from adscan_core.pal.platform import is_windows
from adscan_core.rich_output import print_exception


#: Status token ``verify_all``/``install_all`` use for a REQUIRED wordlist that
#: is absent. Callers render it as a hard failure and clear ``all_ok``.
MISSING_REQUIRED = "missing"

#: Status token for an OPTIONAL wordlist that is absent. The scan proceeds; the
#: only consequence is reduced password-cracking coverage, which the deliverable
#: declares as a data gap (see ``cracking_coverage``).
MISSING_OPTIONAL = "missing (optional)"

#: The combined audit base filename — the ONE corpus whose availability check
#: must match the crack selector (``cracking_wordlist_policy.base_for``), since
#: on the Windows .exe it lives inside the bundle, not the LOCALAPPDATA dir.
#: Kept in lockstep with the policy SSOT (``_DEFAULT_AUDIT_BASE_FILENAME``).
_COMBINED_AUDIT_BASE_FILENAME = "combined_audit_base.txt"


@dataclass(frozen=True)
class WordlistDefinition:
    """Configuration for a single wordlist.

    ``required`` is the criticality axis. It defaults to ``True`` so a wordlist
    added later is treated as load-bearing until someone deliberately says
    otherwise — a silent downgrade is the failure mode worth guarding against.
    A definition is only marked optional when every consumer already tolerates
    its absence at run time.
    """

    name: str
    url: str
    dest: str
    extract_xz: bool = False
    extract_7z: bool = False
    required: bool = True


#: Image repositories ADscan publishes. Anything else is a locally-built or
#: re-tagged image, for which ``adscan update`` would pull a DIFFERENT image
#: than the one running and so must not be offered as the repair.
_PUBLISHED_IMAGE_REPOS = ("adscan/adscan-lite", "adscan/adscan-pro")


def _runtime_image_is_published(image: Optional[str] = None) -> bool:
    """Return whether the running runtime image is one ADscan publishes.

    Reads ``ADSCAN_RUNTIME_IMAGE`` (the launcher sets it, e.g.
    ``adscan/adscan-lite:latest``) unless ``image`` is given. An empty or
    unparseable value returns ``False``: without positive evidence that the
    image came from us, pointing the operator at ``adscan update`` would send
    them to pull an unrelated image.
    """

    raw = image if image is not None else os.getenv("ADSCAN_RUNTIME_IMAGE")
    normalized = str(raw or "").strip().lower()
    if not normalized:
        return False
    repo = normalized.split("@", 1)[0].rsplit(":", 1)
    # Only the FINAL path segment may carry a tag; a registry host:port prefix
    # must not be mistaken for one.
    if len(repo) == 2 and "/" not in repo[1]:
        normalized = repo[0]
    return any(normalized.endswith(candidate) for candidate in _PUBLISHED_IMAGE_REPOS)


def missing_optional_guidance(wordlist_name: str) -> list[str]:
    """Return the operator-facing lines for an absent optional wordlist.

    The corpus is baked into the runtime image at build time; it is not a host
    bind mount and there is no runtime download for it, so "reinstall it" is
    not an action anyone can take. What the operator can act on is the image:
    re-pull a published one, or rebuild a local one. Offering ``adscan update``
    for a locally-built image would pull a different image than the one running
    and leave the corpus exactly as absent as before.
    """

    lines = [
        f"{wordlist_name} is not present in this image. Password cracking will "
        "run with reduced coverage; every other phase is unaffected.",
        "This corpus is baked into the runtime image at build time, so it "
        "cannot be restored from inside a running container.",
    ]
    if _runtime_image_is_published():
        lines.append("Re-pull the runtime image to restore it: adscan update")
    else:
        lines.append(
            "This runtime image was not published by ADscan. Rebuild it with "
            "wordlist preparation enabled, or switch to a published image."
        )
    return lines


class WordlistService(BaseService):
    """Service responsible for installing and verifying wordlists."""

    def __init__(
        self,
        wordlists_dir: Optional[str] = None,
        definitions: Optional[Mapping[str, Mapping[str, Any]]] = None,
    ):
        """Initialize the service.

        Args:
            wordlists_dir: Base directory for wordlists. If None, uses the
                standard ADscan wordlists directory under ADSCAN_BASE_DIR.
            definitions: Optional raw configuration mapping (as used in the
                legacy WORDLISTS_CONFIG). When omitted, a sensible default
                is used.
        """

        super().__init__()
        if wordlists_dir is None:
            # Reuse the same base resolution logic as the main CLI.
            # Use get_adscan_home() which respects ADSCAN_HOME when set (e.g., in Docker containers)
            adscan_home = path_utils.get_adscan_home()
            wordlists_dir = str(adscan_home / "wordlists")

        self.wordlists_dir = wordlists_dir
        self._repo_wordlists_dir = Path(__file__).resolve().parents[2] / "wordlists"
        self._definitions: Dict[str, WordlistDefinition] = {}

        # Default definitions = the wordlist FILES that ship in the runtime image
        # and that `adscan check` reports on:
        #   - rockyou.txt              (the CTF/fast base, downloaded at build)
        #   - combined_audit_base.txt  (the ~94M audit base, a build-time merge)
        #
        # The audit base is a build-time merge (hashmob-large + kerberoast_pws,
        # order-preserving rling dedup) produced by
        # scripts/build_combined_audit_wordlist.sh; its raw components are staged
        # from wordlists/manifest.json and DROPPED after the merge, so the image
        # ships the combined only. Those raw components are therefore NOT checked
        # here (they never exist at runtime) and combined_audit_base.txt has no
        # runtime download URL — it is baked into the image layer, never fetched.
        #
        # BOTH are OPTIONAL. They feed password cracking and nothing else, and
        # every consumer already tolerates their absence at run time: the crack
        # job skips a tier whose file is missing (cracking_job), the selector
        # warns and continues (cli/cracking), and the effort policy falls through
        # to its documented fallback base (cracking_wordlist_policy.base_for).
        # Blocking a whole scan — collection, attack paths, the report — on a
        # corpus none of them read would deny far more than it protects. What a
        # missing corpus does cost is cracking coverage, and the deliverable
        # declares that as a data gap rather than rendering an empty section.
        raw_defs = definitions or {
            "rockyou.txt": {
                "url": "https://github.com/brannondorsey/naive-hashcat/"
                "releases/download/data/rockyou.txt",
                "dest": "rockyou.txt",
                "required": False,
            },
            "combined_audit_base.txt": {
                # Build-time artifact — no runtime download source.
                "url": "",
                "dest": "combined_audit_base.txt",
                "required": False,
            },
        }

        for name, cfg in raw_defs.items():
            self._definitions[name] = WordlistDefinition(
                name=name,
                url=cfg["url"],
                dest=cfg["dest"],
                extract_xz=bool(cfg.get("extract_xz", False)),
                extract_7z=bool(cfg.get("extract_7z", False)),
                required=bool(cfg.get("required", True)),
            )

    @property
    def definitions(self) -> Mapping[str, WordlistDefinition]:
        """Return immutable mapping of wordlist definitions."""

        return dict(self._definitions)

    def _final_path_for(self, definition: WordlistDefinition) -> str:
        """Return the final on-disk path for a wordlist."""

        final_name = definition.dest.replace(".xz", "").replace(".7z", "")
        return os.path.join(self.wordlists_dir, final_name)

    @staticmethod
    def _allows_insecure_tls_fallback(url: str) -> bool:
        """Return True when a public download may retry with insecure TLS.

        Weakpass-hosted wordlists are a best-effort public dependency and may
        be intercepted by enterprise TLS inspection appliances. For those URLs
        we allow a curl `-k` retry after a normal verified attempt fails.
        """

        return url.startswith("https://weakpass.com/")

    def _download_wordlist(self, url: str, destination: str) -> None:
        """Download a wordlist with a verified TLS attempt first.

        Args:
            url: Source URL to download.
            destination: Local filesystem path for the downloaded archive/file.

        Raises:
            subprocess.CalledProcessError: If both the primary download and any
                allowed fallback fail.
        """

        clean_env = get_clean_env_for_compilation()
        primary_command = ["curl", "-fsSL", "-o", destination, url]
        result = subprocess.run(
            primary_command,
            env=clean_env,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return

        if not self._allows_insecure_tls_fallback(url):
            raise subprocess.CalledProcessError(
                result.returncode, primary_command, result.stdout, result.stderr
            )

        insecure_command = ["curl", "-kfsSL", "-o", destination, url]
        insecure_result = subprocess.run(
            insecure_command,
            env=clean_env,
            capture_output=True,
            text=True,
            check=False,
        )
        if insecure_result.returncode == 0:
            return

        raise subprocess.CalledProcessError(
            insecure_result.returncode,
            insecure_command,
            insecure_result.stdout,
            insecure_result.stderr,
        )

    def _repo_source_candidates(self, definition: WordlistDefinition) -> list[Path]:
        """Return repo-local candidate paths for a wordlist."""

        final_name = Path(self._final_path_for(definition)).name
        candidates = [
            self._repo_wordlists_dir / final_name,
            self._repo_wordlists_dir / definition.dest,
        ]
        return candidates

    def _copy_or_extract_repo_wordlist(
        self, definition: WordlistDefinition, final_wl_path: str
    ) -> bool:
        """Populate a wordlist from the repo-local `wordlists/` directory if present."""

        os.makedirs(self.wordlists_dir, exist_ok=True)

        for candidate in self._repo_source_candidates(definition):
            if not candidate.exists():
                continue

            if candidate.name == Path(final_wl_path).name:
                shutil.copy2(candidate, final_wl_path)
                return os.path.exists(final_wl_path)

            clean_env = get_clean_env_for_compilation()
            dl_wl_path = os.path.join(self.wordlists_dir, definition.dest)
            shutil.copy2(candidate, dl_wl_path)

            if definition.extract_xz:
                subprocess.run(
                    ["xz", "-d", "-f", dl_wl_path],
                    env=clean_env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
            if definition.extract_7z:
                subprocess.run(
                    ["7z", "x", "-y", f"-o{self.wordlists_dir}", dl_wl_path],
                    env=clean_env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                try:
                    os.remove(dl_wl_path)
                except OSError:
                    pass

            return os.path.exists(final_wl_path)

        return False

    def ensure_wordlist_installed(self, name: str, *, fix: bool) -> bool:
        """Ensure a configured wordlist exists under ``wordlists_dir``."""

        definition = self._definitions.get(name)
        if not definition:
            print_error(f"Unknown wordlist: {name}")
            return False

        final_wl_path = self._final_path_for(definition)
        if os.path.exists(final_wl_path):
            return True

        # Special-case rockyou: prefer system copy when available.
        if name == "rockyou.txt":
            system_txt = "/usr/share/wordlists/rockyou.txt"
            system_gz = "/usr/share/wordlists/rockyou.txt.gz"
            try:
                if os.path.exists(system_txt):
                    os.makedirs(self.wordlists_dir, exist_ok=True)
                    shutil.copy2(system_txt, final_wl_path)
                    return os.path.exists(final_wl_path)
                if os.path.exists(system_gz) and fix:
                    import gzip

                    os.makedirs(self.wordlists_dir, exist_ok=True)
                    with (
                        gzip.open(system_gz, "rb") as src,
                        open(final_wl_path, "wb") as dst,
                    ):
                        shutil.copyfileobj(src, dst)
                    return os.path.exists(final_wl_path)
            except Exception:  # noqa: BLE001
                return False
            if self._copy_or_extract_repo_wordlist(definition, final_wl_path):
                return True
            return False

        if self._copy_or_extract_repo_wordlist(definition, final_wl_path):
            return True

        if not fix:
            return False

        # Build-time-only artifacts (e.g. combined_audit_base.txt) carry no
        # download URL — they are baked into the image, never fetched at runtime.
        # If such a file is missing and no repo-local copy exists, it cannot be
        # auto-fixed; report failure instead of attempting an empty-URL download.
        if not definition.url:
            return False

        # Offline-first: never fetch over the network on Windows-native (where
        # wordlists ship embedded in the bundle) or when offline mode is enabled
        # (air-gapped / sovereignty-driven engagements). A missing wordlist then
        # degrades gracefully — the caller renders the reduced-coverage warning —
        # rather than phoning home. (See docs/superpowers/specs/
        # 2026-09-03-windows-native-runtime-portability-design.md.)
        if is_windows() or offline.offline_mode_enabled():
            return False

        try:
            os.makedirs(self.wordlists_dir, exist_ok=True)
            dl_wl_path = os.path.join(self.wordlists_dir, definition.dest)
            self._download_wordlist(definition.url, dl_wl_path)
            clean_env = get_clean_env_for_compilation()
            if definition.extract_xz:
                subprocess.run(
                    ["xz", "-d", dl_wl_path],
                    env=clean_env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
            if definition.extract_7z:
                subprocess.run(
                    ["7z", "x", "-y", f"-o{self.wordlists_dir}", dl_wl_path],
                    env=clean_env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                try:
                    os.remove(dl_wl_path)
                except OSError:
                    pass
            return os.path.exists(final_wl_path)
        except Exception as exc:  # pragma: no cover - network/env dependent
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return False

    def install_all(self) -> Tuple[bool, Dict[str, str]]:
        """Install or ensure all wordlists are available.

        Returns:
            A tuple ``(all_ok, details)`` where:
            - ``all_ok`` indica si todas las wordlists se han procesado bien.
            - ``details`` mapea nombre de wordlist -> mensaje corto de estado.
        """

        os.makedirs(self.wordlists_dir, exist_ok=True)
        print_info("Setting up wordlists...")
        details: Dict[str, str] = {}
        all_ok = True

        for wl_name, definition in self._definitions.items():
            final_wl_path = self._final_path_for(definition)
            if os.path.exists(final_wl_path):
                details[wl_name] = f"exists at {final_wl_path}"
                continue

            print_info(f"Ensuring {wl_name} is available...")
            if self.ensure_wordlist_installed(wl_name, fix=True):
                details[wl_name] = "installed"
                continue

            if definition.required:
                print_error(f"Failed to download/process {wl_name}.")
                details[wl_name] = "failed"
                all_ok = False
                continue

            details[wl_name] = MISSING_OPTIONAL
            for line in missing_optional_guidance(wl_name):
                print_warning(line)

        return all_ok, details

    def _is_present(self, definition: WordlistDefinition) -> bool:
        """Whether a wordlist is resolvable on disk, managed dir or system dir.

        For the combined audit base this defers to the crack SELECTOR's SSOT
        (``cracking_wordlist_policy.audit_base_is_available``) so the
        availability check and ``base_for`` never disagree: on the Windows .exe
        the combined ships inside the bundle (plain or xz-compressed under
        ``_MEIPASS``), not in the LOCALAPPDATA wordlists dir this method
        historically inspected, which made the availability check report it
        "not present" while cracking actually used it.
        """

        final_wl_path = self._final_path_for(definition)
        if os.path.exists(final_wl_path):
            return True
        if os.path.basename(final_wl_path) == _COMBINED_AUDIT_BASE_FILENAME:
            from adscan_internal.services.cracking_wordlist_policy import (
                audit_base_is_available,
            )

            if audit_base_is_available(self.wordlists_dir):
                return True
        system_wl_path = os.path.join(
            "/usr/share/wordlists", os.path.basename(final_wl_path)
        )
        return os.path.exists(system_wl_path)

    def missing_optional_wordlists(self) -> list[str]:
        """Names of the OPTIONAL corpora absent from this runtime.

        A read-only observation used to declare the cracking data gap in the
        deliverable. Never installs, never prints, never raises: an unreadable
        directory yields an empty list, so an IO problem degrades into "no gap
        observed" rather than a fabricated gap notice in a client report.
        """

        missing: list[str] = []
        for name, definition in self._definitions.items():
            if definition.required:
                continue
            try:
                if not self._is_present(definition):
                    missing.append(name)
            except OSError:
                continue
        return missing

    def verify_all(self, *, fix: bool) -> Tuple[bool, Dict[str, str]]:
        """Verify that all configured wordlists are available.

        If ``fix`` es True, intenta instalar aquellas que falten.
        """

        os.makedirs(self.wordlists_dir, exist_ok=True)
        details: Dict[str, str] = {}
        all_ok = True

        for wl_name, definition in self._definitions.items():
            final_wl_path = self._final_path_for(definition)
            if os.path.exists(final_wl_path):
                details[wl_name] = f"found at {final_wl_path}"
                continue

            system_wl_path = os.path.join(
                "/usr/share/wordlists",
                os.path.basename(final_wl_path),
            )
            if os.path.exists(system_wl_path):
                details[wl_name] = f"found at system path {system_wl_path}"
                continue

            if fix and self.ensure_wordlist_installed(wl_name, fix=True):
                details[wl_name] = "installed via --fix"
                continue

            if definition.required:
                details[wl_name] = MISSING_REQUIRED
                print_error(
                    f"{wl_name} not found. Try reinstalling into the "
                    f"{self.wordlists_dir} wordlists directory.",
                )
                all_ok = False
                continue

            details[wl_name] = MISSING_OPTIONAL
            for line in missing_optional_guidance(wl_name):
                print_warning(line)

        return all_ok, details


def record_cracking_coverage_for_domain(
    shell: Any,
    domain: str,
    *,
    wordlists_dir: Optional[str] = None,
    engine: Optional[str] = None,
    ruleset: Optional[str] = None,
) -> None:
    """Stamp the cracking-coverage statement for *domain* into the report.

    Called from the seams where a crack is about to run, so the declaration
    only appears for an assessment that actually attempted password recovery —
    a scan that captured no hashes has no cracking coverage to describe, and
    stamping one anyway would put a gap notice in a report for work nobody
    asked for.

    ``engine`` / ``ruleset`` are the backend and rule set an attempt actually
    ran (``CrackResult.engine`` / ``.ruleset``). When supplied — i.e. from the
    seam that has the effort-ladder result — the recorded block also declares,
    in vendor-neutral prose, which cracker class and rule effort ran, so the
    deliverable is honest about the strength of the attempt. Absent (the pre-run
    seam that only knows the wordlist state), the block carries only the corpus
    data-gap declaration, exactly as before.

    Idempotent: both crack seams may call it many times per domain and the
    recorder overwrites the same block with the same observation. Best-effort
    throughout — a report is never failed over its own coverage note.
    """

    if not domain:
        return
    try:
        from adscan_core.reporting.cracking_coverage import (  # noqa: PLC0415
            build_cracking_coverage,
        )
        from adscan_core.reporting.technical_report import (  # noqa: PLC0415
            record_cracking_coverage,
        )

        service = WordlistService(wordlists_dir=wordlists_dir)
        missing = service.missing_optional_wordlists()
        record_cracking_coverage(
            shell,
            domain,
            coverage=build_cracking_coverage(
                missing_wordlists=missing, engine=engine, ruleset=ruleset
            ),
        )
    except Exception as exc:  # noqa: BLE001 — coverage persistence is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


__all__ = [
    "MISSING_OPTIONAL",
    "MISSING_REQUIRED",
    "WordlistDefinition",
    "WordlistService",
    "missing_optional_guidance",
    "record_cracking_coverage_for_domain",
]
