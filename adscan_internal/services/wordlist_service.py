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
from adscan_internal.rich_output import print_error, print_info
from adscan_internal.services.base_service import BaseService
from adscan_internal.subprocess_env import get_clean_env_for_compilation
from adscan_internal import path_utils


@dataclass(frozen=True)
class WordlistDefinition:
    """Configuration for a single wordlist."""

    name: str
    url: str
    dest: str
    extract_xz: bool = False
    extract_7z: bool = False


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

        raw_defs = definitions or {
            "rockyou.txt": {
                "url": "https://github.com/brannondorsey/naive-hashcat/"
                "releases/download/data/rockyou.txt",
                "dest": "rockyou.txt",
            },
            "kerberoast_pws": {
                "url": (
                    "https://gist.github.com/The-Viper-One/"
                    "a1ee60d8b3607807cc387d794e809f0b/raw/"
                    "b7d83af6a8bbb43013e04f78328687d19d0cf9a7/kerberoast_pws.xz"
                ),
                "dest": "kerberoast_pws.xz",
                "extract_xz": True,
            },
            "hashmob_medium_2025": {
                "url": "https://weakpass.com/download/2073/hashmob.net_2025.medium.found.7z",
                "dest": "hashmob.net_2025.medium.found.7z",
                "extract_7z": True,
            },
            "kaonashi14M": {
                "url": "https://weakpass.com/download/1938/kaonashi14M.txt.7z",
                "dest": "kaonashi14M.txt.7z",
                "extract_7z": True,
            },
        }

        for name, cfg in raw_defs.items():
            self._definitions[name] = WordlistDefinition(
                name=name,
                url=cfg["url"],
                dest=cfg["dest"],
                extract_xz=bool(cfg.get("extract_xz", False)),
                extract_7z=bool(cfg.get("extract_7z", False)),
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
        if definition.name == "hashmob_medium_2025":
            candidates.extend(
                [
                    self._repo_wordlists_dir / "hashmob.net_2025.micro.found",
                    self._repo_wordlists_dir / "hashmob.net_2025.micro.found.7z",
                ]
            )
        return candidates

    def _copy_or_extract_repo_wordlist(self, definition: WordlistDefinition, final_wl_path: str) -> bool:
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
            else:
                print_error(f"Failed to download/process {wl_name}.")
                details[wl_name] = "failed"
                all_ok = False

        return all_ok, details

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

            details[wl_name] = "missing"
            print_error(
                f"{wl_name} not found. Try reinstalling into the {self.wordlists_dir} wordlists directory.",
            )
            all_ok = False

        return all_ok, details


__all__ = [
    "WordlistDefinition",
    "WordlistService",
]
