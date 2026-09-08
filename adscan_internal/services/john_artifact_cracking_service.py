"""Reusable John-the-Ripper helpers for artifact cracking workflows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
import os
import re
import shlex
import shutil
import subprocess

from adscan_core.pal import tools as pal_tools
from adscan_core.pal.paths import bin_dir, tools_dir
from adscan_core.pal.platform import is_windows
from adscan_internal import print_info_debug, print_warning, print_warning_debug
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.base_service import BaseService


CommandExecutor = Callable[..., subprocess.CompletedProcess[str] | None]


def _shell_quote(arg: str) -> str:
    """Quote one argument for the CURRENT OS's command shell.

    The John command strings this module builds run through the OS shell
    (cmd.exe/PowerShell on Windows, ``/bin/sh`` on POSIX). POSIX ``shlex.quote``
    emits SINGLE quotes, which cmd.exe does not treat as quoting metacharacters —
    it passes them literally as part of the argument, so John reads a ``'...'``
    path and the crack pot and the ``--show`` pot diverge, silently returning no
    results. On Windows use ``subprocess.list2cmdline`` (the standard cmd.exe
    quoter: double-quotes only when needed, correct backslash/quote escaping); on
    POSIX return ``shlex.quote`` unchanged so Linux behaviour is byte-identical.
    Never raises.
    """
    try:
        if is_windows():
            return subprocess.list2cmdline([str(arg)])
        return shlex.quote(str(arg))
    except Exception:
        return shlex.quote(str(arg))


@dataclass(frozen=True)
class JohnArtifactCrackingResult:
    """Outcome of one John cracking attempt."""

    hash_file: str
    cracked_secret: str | None
    converter_succeeded: bool
    john_succeeded: bool


class JohnArtifactCrackingService(BaseService):
    """Encapsulate converter -> john -> john --show workflows."""

    def __init__(
        self,
        *,
        command_executor: CommandExecutor | None = None,
        john_path: str | None = None,
    ) -> None:
        """Initialize cracking service dependencies."""
        super().__init__()
        self._command_executor = command_executor
        self._john_path = (
            str(john_path or self.resolve_john_path() or "john").strip() or "john"
        )

    @staticmethod
    def resolve_john_path() -> str | None:
        """Resolve the preferred John binary path.

        Consults the PAL capability registry for CPU password recovery first. On
        a platform where john is deliberately not shipped (DEGRADE) this is an
        honest skip (return ``None``). On POSIX (EMBEDDED_BINARY) the concrete
        candidate order below stays the authority — it recognises the bundled
        ``tools/john/run/john`` location the registry's single binary name does
        not — so the present-binary path is byte-identical to before. On Windows
        the same bundled layout carries ``john.exe`` (the openwall jumbo win64
        build ships ``tools/john/run/john.exe`` + its cygwin DLLs), so the
        ``.exe`` variants are tried too.
        """
        if pal_tools.resolve_strategy("cracking_cpu") == pal_tools.Strategy.DEGRADE:
            return None
        # PAL locator is the single source of truth for "where is bundled john"
        # — layout-aware (flat / name-subdir / versioned / versioned+run), so PAL
        # capability availability and this resolver can never disagree (the
        # braavos divergence). The explicit candidates below stay as a fallback
        # for byte-identical resolution.
        bundled = pal_tools.resolve_bundled_tool("john")
        if bundled is not None:
            return os.path.realpath(str(bundled))
        candidates = [
            str(tools_dir() / "john" / "run" / "john"),
            str(bin_dir() / "john"),
        ]
        if is_windows():
            # The win64 jumbo bundle's binary is john.exe (alongside its cygwin
            # DLLs in the same run/ dir, which is why it must run in-place). POSIX
            # candidates stay first, so POSIX resolution is byte-identical.
            candidates += [
                str(tools_dir() / "john" / "run" / "john.exe"),
                str(bin_dir() / "john.exe"),
            ]
        candidates.append(shutil.which("john"))
        for candidate in candidates:
            normalized = str(candidate or "").strip()
            if normalized and os.path.exists(normalized):
                return os.path.realpath(normalized)
        return None

    @staticmethod
    def resolve_converter_path(converter_name: str) -> str | None:
        """Resolve one ``*2john`` converter path from official and legacy locations."""
        normalized_name = str(converter_name or "").strip()
        if not normalized_name:
            return None

        bin_root = bin_dir()
        john_run = tools_dir() / "john" / "run"
        candidates = [
            shutil.which(normalized_name),
            shutil.which(f"{normalized_name}.py"),
            shutil.which(f"{normalized_name}.pl"),
            str(bin_root / normalized_name),
            str(bin_root / f"{normalized_name}.py"),
            str(bin_root / f"{normalized_name}.pl"),
            str(john_run / normalized_name),
            str(john_run / f"{normalized_name}.py"),
            str(john_run / f"{normalized_name}.pl"),
        ]

        if normalized_name == "keepass2john":
            candidates.extend(
                [
                    str(tools_dir() / "keepass2john" / "keepass2john.py"),
                    "reference/keepass2john/keepass2john.py",
                ]
            )

        for candidate in candidates:
            normalized = str(candidate or "").strip()
            if normalized and os.path.exists(normalized):
                return normalized
        return None

    def extract_hash_with_script(
        self,
        *,
        script_path: str,
        input_paths: list[str],
        hash_file: str,
        python_executable: str | None = None,
        timeout: int = 300,
    ) -> bool:
        """Run one external converter script and persist the resulting John hash."""
        if not self._command_executor:
            return False
        normalized_inputs = [
            str(path or "").strip() for path in input_paths if str(path or "").strip()
        ]
        if not script_path or not normalized_inputs or not hash_file:
            return False

        os.makedirs(os.path.dirname(hash_file) or ".", exist_ok=True)
        files_str = " ".join(_shell_quote(path) for path in normalized_inputs)
        command = self._build_converter_command(
            converter_path=script_path,
            files_str=files_str,
            hash_file=hash_file,
            python_executable=python_executable,
        )
        print_info_debug(
            "John artifact converter command: "
            f"script={mark_sensitive(script_path, 'path')} "
            f"hash_file={mark_sensitive(hash_file, 'path')} "
            f"inputs={len(normalized_inputs)}"
        )
        completed = self._command_executor(
            command,
            timeout=timeout,
            use_clean_env=True,
        )
        self.normalize_hash_file(hash_file)
        if completed is None:
            return False
        if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
            return True
        print_warning_debug(
            "John artifact converter produced no hash output: "
            f"script={mark_sensitive(script_path, 'path')} rc={completed.returncode}"
        )
        return False

    @staticmethod
    def _build_converter_command(
        *,
        converter_path: str,
        files_str: str,
        hash_file: str,
        python_executable: str | None = None,
    ) -> str:
        """Build one converter command line that persists output through ``tee``."""
        normalized_converter = str(converter_path or "").strip()
        normalized_python = str(python_executable or "python3").strip() or "python3"
        if normalized_converter.endswith(".py"):
            runner = f"{_shell_quote(normalized_python)} {_shell_quote(normalized_converter)}"
        else:
            runner = _shell_quote(normalized_converter)
        return f"{runner} {files_str} | tee {_shell_quote(hash_file)}"

    def crack_hash(
        self,
        *,
        hash_file: str,
        wordlist_path: str,
        timeout: int = 300,
    ) -> JohnArtifactCrackingResult:
        """Run John using one resolved wordlist and return cracked secret if any."""
        if not self._command_executor:
            return JohnArtifactCrackingResult(
                hash_file=hash_file,
                cracked_secret=None,
                converter_succeeded=False,
                john_succeeded=False,
            )
        marked_hash = mark_sensitive(hash_file, "path")
        marked_wordlist = mark_sensitive(wordlist_path, "path")
        command = (
            f"{_shell_quote(self._john_path)} --wordlist={_shell_quote(wordlist_path)} "
            f"{_shell_quote(hash_file)}"
        )
        print_info_debug(
            "John cracking command prepared: "
            f"hash_file={marked_hash} wordlist={marked_wordlist}"
        )
        completed = self._command_executor(
            command,
            timeout=timeout,
            use_clean_env=True,
        )
        if completed is None:
            return JohnArtifactCrackingResult(
                hash_file=hash_file,
                cracked_secret=None,
                converter_succeeded=True,
                john_succeeded=False,
            )
        cracked_secret = self._show_cracked_secret(hash_file=hash_file, timeout=timeout)
        return JohnArtifactCrackingResult(
            hash_file=hash_file,
            cracked_secret=cracked_secret,
            converter_succeeded=True,
            john_succeeded=int(getattr(completed, "returncode", 1)) == 0,
        )

    def _show_cracked_secret(
        self,
        *,
        hash_file: str,
        timeout: int,
    ) -> str | None:
        """Return the cracked secret from ``john --show`` output when present."""
        if not self._command_executor:
            return None
        command = f"{_shell_quote(self._john_path)} --show {_shell_quote(hash_file)}"
        completed = self._command_executor(
            command,
            timeout=timeout,
            use_clean_env=True,
        )
        if completed is None or int(getattr(completed, "returncode", 1)) != 0:
            return None
        stdout_text = str(getattr(completed, "stdout", "") or "")
        secret = self.parse_john_show_output(stdout_text)
        if secret:
            print_warning(f"Password found: {mark_sensitive(secret, 'password')}")
            return secret
        return None

    @staticmethod
    def normalize_hash_file(hash_file: str) -> bool:
        """Normalize known converter artifacts in one generated John hash file."""
        normalized_hash_file = str(hash_file or "").strip()
        if not normalized_hash_file or not os.path.exists(normalized_hash_file):
            return False
        try:
            with open(normalized_hash_file, "r", encoding="utf-8") as handle:
                original = handle.read()
        except OSError:
            return False

        placeholder = "<SHOULD_BE_REMOVED_INCLUDING_COLON>:"
        sanitized = original
        if placeholder in sanitized:
            normalized_lines: list[str] = []
            for line in sanitized.splitlines():
                if placeholder not in line:
                    normalized_lines.append(line)
                    continue
                _prefix, suffix = line.split(placeholder, 1)
                normalized_lines.append(suffix)
            sanitized = "\n".join(normalized_lines)
            if original.endswith("\n"):
                sanitized += "\n"
        if sanitized == original:
            return False

        with open(normalized_hash_file, "w", encoding="utf-8") as handle:
            handle.write(sanitized)
        return True

    # John token-format markers. A hashcat-shaped roast file prefixes each line
    # with a ``<login>:`` field and then the ``$krb5*$`` token; John cannot load
    # that prefixed line, so for these formats the leading field is stripped down
    # to the bare token (which itself embeds ``user@REALM``).
    _TOKEN_FORMAT_MARKERS: dict[str, str] = {
        "krb5asrep": "$krb5asrep$",
        "krb5tgs": "$krb5tgs$",
    }
    # NetNTLM formats are already John-native (``user::domain:...``) — passed
    # through verbatim. ``nt`` is a bare 32-hex hash with an optional ``login:``
    # prefix to strip.
    _NETNTLM_FORMATS: frozenset[str] = frozenset({"netntlmv1", "netntlmv2"})

    def crack_hashes_file(
        self,
        *,
        hash_file: str,
        wordlist_path: str,
        john_format: str,
        rules: str | None = None,
        john_config: str | None = None,
        timeout: int = 300,
        _hash_file_reader: Callable[[str], str] | None = None,
    ) -> dict[str, str]:
        """Crack a multi-principal roast/NetNTLM hash file with John (CPU).

        The capture file is hashcat-shaped (one ``<login>:$krb5*$...`` line per
        principal). John cannot load that shape for the Kerberos token formats:
        the leading ``<login>:`` prefix breaks its parser ("No password hashes
        loaded"). So the file is first converted to John's native shape per
        format (:meth:`to_john_input_lines`), written to a sibling temp file, and
        John runs against THAT. It then parses ``john --format=<fmt> --show`` and
        recovers ``{username: password}`` — for token formats the username is
        extracted from the ``user@REALM`` embedded in the echoed token, not from a
        separate login field. Multi-secret sibling of :meth:`crack_hash`; never
        raises, returns ``{}`` on any failure/timeout.

        Args:
            hash_file: Path to the hashcat-shaped ``field:hash`` capture file.
            wordlist_path: Wordlist to try.
            john_format: John ``--format`` value (e.g. ``krb5tgs``, ``netntlmv2``).
            rules: John rule-section name to apply (the effort-rung ruleset, e.g.
                ``adscan_r1``). When set, the CRACK command adds
                ``--config=<john_config> --rules=<rules>``. When ``None`` (rung 0)
                NEITHER flag is emitted — a byte-identical plain wordlist pass.
            john_config: Path to the ``john.conf`` that defines the ``rules``
                section. Used only when ``rules`` is set; if ``rules`` is set but
                this is ``None`` the bundled conf path is resolved as a fallback so
                the section is always found.
            timeout: Per-invocation subprocess timeout in seconds.
            _hash_file_reader: Test seam to inject the capture-file reader.

        Returns:
            ``{username: password}`` for every cracked principal (possibly empty).
        """
        if not self._command_executor:
            return {}
        normalized_format = str(john_format or "").strip()
        if not hash_file or not wordlist_path or not normalized_format:
            return {}

        john_input_file = self._prepare_john_input_file(
            hash_file=hash_file,
            john_format=normalized_format,
            hash_file_reader=_hash_file_reader,
        )
        if not john_input_file:
            return {}

        # Pin an explicit pot so the --wordlist crack and the --show read share
        # ONE known pot regardless of env/cwd. Without this, use_clean_env=True
        # (and any cwd difference between the two clean-env invocations) lets John
        # derive a DIFFERENT pot for each — the crack writes results to one pot and
        # --show reads an empty other pot, so recovery silently returns {} even
        # though the hash cracked. The pot lives next to the .john input file and
        # is created fresh (a stale one is removed first) so the call is
        # self-contained and a prior run can never taint these results.
        pot_file = f"{john_input_file}.pot"
        self._remove_stale_file(pot_file)

        marked_hash = mark_sensitive(john_input_file, "path")
        marked_wordlist = mark_sensitive(wordlist_path, "path")
        quoted_pot = _shell_quote(pot_file)
        # Rung 0 (rules=None) emits NEITHER --config nor --rules: a plain wordlist
        # pass, byte-identical to the pre-Phase-2 command. Rung 1+ adds both, so
        # John finds the named [List.Rules:<name>] section in the bundled conf.
        rules_fragment = ""
        normalized_rules = str(rules or "").strip()
        if normalized_rules:
            conf_path = (
                str(john_config or "").strip() or self._resolve_john_config_path()
            )
            rules_fragment = (
                f"--config={_shell_quote(conf_path)} "
                f"--rules={_shell_quote(normalized_rules)} "
            )
        crack_command = (
            f"{_shell_quote(self._john_path)} --format={_shell_quote(normalized_format)} "
            f"{rules_fragment}"
            f"--pot={quoted_pot} "
            f"--wordlist={_shell_quote(wordlist_path)} {_shell_quote(john_input_file)}"
        )
        print_info_debug(
            "John multi-principal cracking command prepared: "
            f"format={normalized_format} hash_file={marked_hash} "
            f"wordlist={marked_wordlist}"
        )
        crack_completed = self._command_executor(
            crack_command, timeout=timeout, use_clean_env=True
        )
        show_command = (
            f"{_shell_quote(self._john_path)} --format={_shell_quote(normalized_format)} "
            f"--pot={quoted_pot} "
            f"--show {_shell_quote(john_input_file)}"
        )
        show_completed = self._command_executor(
            show_command, timeout=timeout, use_clean_env=True
        )
        # --show against the pinned pot is authoritative. As defense-in-depth,
        # also parse the crack run's OWN stdout — when John cracks during
        # --wordlist it prints ``password (login-or-token)`` lines directly, so a
        # misbehaving --show/pot on some host still recovers the credential.
        pairs: dict[str, str] = {}
        if crack_completed is not None:
            crack_stdout = str(getattr(crack_completed, "stdout", "") or "")
            pairs.update(
                self.parse_john_live_crack_output(
                    crack_stdout, john_format=normalized_format
                )
            )
        if show_completed is not None:
            show_stdout = str(getattr(show_completed, "stdout", "") or "")
            pairs.update(
                self.parse_john_show_all(show_stdout, john_format=normalized_format)
            )
        return pairs

    @staticmethod
    def _resolve_john_config_path() -> str:
        """Resolve the bundled ``john.conf`` path (fallback when none is passed in).

        The engine normally passes ``john_config`` explicitly; this fallback keeps
        :meth:`crack_hashes_file` self-contained when ``rules`` is set but no conf
        path was supplied, so the named rule section is always resolvable. Imported
        lazily to avoid a services-layer import cycle at module load.
        """
        from adscan_internal.services.cracking.john_rules import (  # noqa: PLC0415
            john_conf_path,
        )

        return john_conf_path()

    @staticmethod
    def _remove_stale_file(path: str) -> None:
        """Delete a stale file at ``path`` if present (best-effort, never raises)."""
        try:
            if path and os.path.exists(path):
                os.remove(path)
        except OSError:
            pass

    @classmethod
    def parse_john_live_crack_output(
        cls, stdout_text: str, *, john_format: str
    ) -> dict[str, str]:
        """Return ``{user: password}`` pairs from a live ``--wordlist`` crack run.

        When John recovers a password during the crack it prints the plaintext
        followed by the source identifier in parentheses, e.g.::

            fr3edom          ($krb5asrep$23$missandei@ESSOS.LOCAL)
            Summer2024!      (svc_web)

        The password is the text before the parenthesised source; the source is
        the ``(...)`` field. For Kerberos token formats the username is extracted
        from the ``user@REALM`` embedded in the token, exactly as
        :meth:`parse_john_show_all` does; otherwise the parenthesised value is the
        login. Summary/banner lines are skipped. Never raises.
        """
        normalized_format = str(john_format or "").strip().lower()
        is_token_format = normalized_format in cls._TOKEN_FORMAT_MARKERS
        line_re = re.compile(r"^(?P<secret>.+?)\s+\((?P<source>.+)\)\s*$")
        pairs: dict[str, str] = {}
        for raw in str(stdout_text or "").splitlines():
            normalized = str(raw or "").strip()
            if not normalized or normalized.startswith("#"):
                continue
            match = line_re.match(normalized)
            if not match:
                continue
            secret = match.group("secret").strip()
            source = match.group("source").strip()
            if not secret or not source:
                continue
            if is_token_format:
                user = cls._username_from_token(source, normalized_format)
            else:
                user = source
            if user and secret:
                pairs[user] = secret
        return pairs

    def _prepare_john_input_file(
        self,
        *,
        hash_file: str,
        john_format: str,
        hash_file_reader: Callable[[str], str] | None,
    ) -> str | None:
        """Convert the hashcat-shaped capture to a John-native sibling temp file.

        Returns the path John should load, or ``None`` when the source cannot be
        read or holds no loadable line. Never raises.
        """
        reader = hash_file_reader or self._read_text_file
        try:
            raw = reader(hash_file)
        except OSError:
            return None
        source_lines = [line for line in str(raw or "").splitlines() if line.strip()]
        if not source_lines:
            return None
        converted = self.to_john_input_lines(source_lines, john_format=john_format)
        if not converted:
            return None
        john_input_file = f"{hash_file}.john"
        try:
            with open(john_input_file, "w", encoding="utf-8") as handle:
                handle.write("\n".join(converted) + "\n")
        except OSError:
            return None
        return john_input_file

    @staticmethod
    def _read_text_file(path: str) -> str:
        """Read one text file (UTF-8, replacement on decode errors)."""
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()

    @classmethod
    def to_john_input_lines(cls, lines: list[str], *, john_format: str) -> list[str]:
        """Convert hashcat-shaped capture lines to John's native input per format.

        - ``krb5asrep`` / ``krb5tgs``: strip everything up to and including the
          first ``$krb5asrep$`` / ``$krb5tgs$`` marker, leaving the bare token.
          Lines without the marker are dropped (John could not load them anyway).
        - ``netntlmv1`` / ``netntlmv2``: passed through unchanged (already native
          ``user::domain:...``).
        - ``nt``: strip a leading ``login:`` prefix so John gets the bare 32-hex
          hash; keep an already-bare hash as-is.
        - anything else: passed through unchanged.
        """
        normalized_format = str(john_format or "").strip().lower()
        marker = cls._TOKEN_FORMAT_MARKERS.get(normalized_format)
        converted: list[str] = []
        for raw in lines:
            line = str(raw or "").strip()
            if not line:
                continue
            if marker:
                idx = line.find(marker)
                if idx < 0:
                    continue
                converted.append(line[idx:])
            elif normalized_format == "nt":
                converted.append(cls._strip_login_prefix_for_nt(line))
            else:
                converted.append(line)
        return converted

    @staticmethod
    def _strip_login_prefix_for_nt(line: str) -> str:
        """Return the bare 32-hex NT hash, stripping a leading ``login:`` prefix."""
        if ":" in line:
            candidate = line.rsplit(":", 1)[-1].strip()
            if re.fullmatch(r"[0-9a-fA-F]{32}", candidate):
                return candidate
        return line

    @classmethod
    def parse_john_show_all(
        cls, stdout_text: str, *, john_format: str
    ) -> dict[str, str]:
        """Return every ``{user: password}`` pair from ``john --show`` output.

        The multi-principal sibling of :meth:`parse_john_show_output`. The
        ``--show`` shape depends on the format:

        - Kerberos token formats (``krb5asrep`` / ``krb5tgs``): ``--show`` echoes
          the token followed by ``:<password>``, e.g.
          ``$krb5asrep$23$missandei@ESSOS.LOCAL:fr3edom``. The token itself
          contains colons, so the password is the field AFTER the final ``:`` and
          the username is the ``user`` in the ``user@REALM`` embedded in the token.
        - NetNTLM / ``nt`` and everything else: native ``login:password`` — the
          username is the first ``:``-separated field.

        Summary lines (``N password hashes cracked, M left``), comments, and the
        ``No password hashes loaded`` banner are skipped.
        """
        summary_re = re.compile(
            r"^\d+\s+password\s+hash(?:es)?\s+cracked,\s+\d+\s+left$",
            re.IGNORECASE,
        )
        normalized_format = str(john_format or "").strip().lower()
        is_token_format = normalized_format in cls._TOKEN_FORMAT_MARKERS
        pairs: dict[str, str] = {}
        for line in str(stdout_text or "").splitlines():
            normalized = str(line or "").strip()
            if not normalized or normalized.startswith("#"):
                continue
            if normalized.lower().startswith("no password hashes loaded"):
                continue
            if summary_re.match(normalized):
                continue
            if ":" not in normalized:
                continue
            if is_token_format:
                token, secret = normalized.rsplit(":", 1)
                user = cls._username_from_token(token, normalized_format)
                secret = secret.strip()
                if user and secret:
                    pairs[user] = secret
                continue
            user, secret = normalized.split(":", 1)
            user = user.strip()
            secret = secret.strip()
            if user and secret:
                pairs[user] = secret
        return pairs

    @classmethod
    def _username_from_token(cls, token: str, john_format: str) -> str:
        """Extract the sAMAccountName from a ``$krb5*$`` token's ``user@REALM``.

        krb5asrep tokens carry ``$krb5asrep$23$<user>@<REALM>``; krb5tgs tokens
        carry ``$krb5tgs$23$*<user>$<REALM>$...``. Both expose ``<user>`` as the
        label immediately before the ``@`` (asrep) or between the leading ``*``
        and the next ``$`` (tgs). Falls back to the label before the first ``@``.
        """
        marker = cls._TOKEN_FORMAT_MARKERS.get(john_format, "")
        body = token[token.find(marker) + len(marker) :] if marker else token
        # krb5tgs shape: 23$*<user>$<REALM>$... — the user is the field after '*'.
        tgs_match = re.search(r"\*([^$*]+)\$", body)
        if john_format == "krb5tgs" and tgs_match:
            return tgs_match.group(1).strip()
        # krb5asrep shape: 23$<user>@<REALM> — the user is the label before '@'.
        at_idx = body.find("@")
        if at_idx > 0:
            candidate = body[:at_idx]
            # Drop the leading etype prefix (e.g. "23$") if present.
            candidate = candidate.rsplit("$", 1)[-1]
            return candidate.strip()
        return ""

    @staticmethod
    def parse_john_show_output(stdout_text: str) -> str | None:
        """Return one cracked secret from ``john --show`` output, skipping summaries."""
        summary_re = re.compile(
            r"^\d+\s+password\s+hash(?:es)?\s+cracked,\s+\d+\s+left$",
            re.IGNORECASE,
        )
        for line in str(stdout_text or "").splitlines():
            normalized = str(line or "").strip()
            if not normalized or normalized.startswith("#"):
                continue
            if normalized.lower().startswith("no password hashes loaded"):
                return None
            if summary_re.match(normalized):
                continue
            if ":" in normalized:
                _, secret = normalized.split(":", 1)
                secret = secret.strip()
                if secret:
                    return secret
                continue
            tokens = normalized.split()
            if tokens:
                candidate = tokens[-1].strip()
                if candidate and candidate.lower() != "left":
                    return candidate
        return None
