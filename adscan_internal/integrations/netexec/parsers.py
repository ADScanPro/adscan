"""NetExec output parsers.

The goal of this module is to turn NetExec stdout/stderr into stable, typed
models and intermediate structures.

Important:
- This code must be resilient to wrapped lines (Rich rendering) and minor output
  changes between NetExec versions.
- It must *not* assume that callers can safely insert invisible markers into
  commands. Markers are only for display/logging, not command execution.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import DefaultDict
import re

from adscan_internal.spraying import normalize_username
from adscan_internal.text_utils import normalize_cli_output


_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)


@dataclass(frozen=True)
class ParsedShare:
    """Parsed SMB share entry."""

    host: str
    share: str
    permission: str


def parse_smb_share_map(output: str) -> dict[str, dict[str, str]]:
    """Parse NetExec SMB ``--shares`` output into a host->share->perm map.

    Args:
        output: NetExec stdout/stderr (text).

    Returns:
        Mapping of host ip/hostname -> {share_name -> permission_string}
    """
    share_map: DefaultDict[str, dict[str, str]] = defaultdict(dict)
    if not output:
        return {}

    current_host: str | None = None
    parsing_shares = False

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Identify the host for subsequent share lines.
        if "Enumerated shares" in line:
            match = _IPV4_RE.search(line)
            if match:
                current_host = match.group(0)
                parsing_shares = True
            continue

        if not parsing_shares or not current_host:
            continue

        # Skip common header/separator lines.
        lowered = line.lower()
        if (
            "share" in lowered
            and "permission" in lowered
            or "remark" in lowered
            or "-----" in line
        ):
            continue

        # Skip common system shares (but keep SYSVOL/NETLOGON).
        if any(system in line for system in ("ADMIN$", "C$", "IPC$", "print$")):
            continue

        # NetExec rows usually look like:
        # SMB <ip> <port> <host> <share> <perm> <remark...>
        # But the token count can vary, so search for permissions in the tail.
        perm = None
        if "READ,WRITE" in line:
            perm = "READ,WRITE"
        elif "READ" in line:
            perm = "READ"
        elif "WRITE" in line:
            perm = "WRITE"

        if not perm:
            continue

        # Extract share name as the token immediately before the permission token.
        parts = line.split()
        try:
            perm_idx = parts.index(perm)
        except ValueError:
            continue
        if perm_idx <= 0:
            continue

        share_name = parts[perm_idx - 1].strip()
        if not share_name:
            continue

        share_map[current_host][share_name] = perm

    return {host: dict(shares) for host, shares in share_map.items()}


def flatten_share_map(share_map: dict[str, dict[str, str]]) -> list[ParsedShare]:
    """Flatten a share map into a list of parsed share entries."""
    flattened: list[ParsedShare] = []
    for host, shares in share_map.items():
        for share, perm in shares.items():
            flattened.append(ParsedShare(host=host, share=share, permission=perm))
    return flattened


def parse_netexec_gmsa_credentials(output: str) -> list[tuple[str, str]]:
    """Parse NetExec GMSA output for account NTLM hashes.

    Args:
        output: Raw NetExec stdout/stderr.

    Returns:
        List of (account, ntlm_hash) tuples.
    """
    if not output:
        return []

    normalized = normalize_cli_output(output)
    pattern = re.compile(
        r"Account:\s*(\S+)\s+NTLM:\s*([a-f0-9]{32})",
        re.IGNORECASE,
    )
    return [(match.group(1), match.group(2)) for match in pattern.finditer(normalized)]


def parse_netexec_laps_credentials(output: str) -> list[tuple[str, str, str]]:
    """Parse NetExec LAPS output for computer credentials.

    Args:
        output: Raw NetExec stdout/stderr.

    Returns:
        List of (computer_name, laps_user, laps_password) tuples.
    """
    if not output:
        return []

    normalized = normalize_cli_output(output)
    pattern = re.compile(
        r"Computer:\s*(\S+?)\$\s+User:\s*(\S+)\s+Password:\s*([^\s]+)",
        re.IGNORECASE | re.DOTALL,
    )
    return [
        (match.group(1), match.group(2), match.group(3))
        for match in pattern.finditer(normalized)
    ]


@dataclass(frozen=True)
class NetexecExecStatus:
    """Parsed status for NetExec remote command execution."""

    executed: bool
    method: str | None
    not_found: list[str]


def parse_netexec_exec_status(output: str) -> NetexecExecStatus:
    """Parse NetExec output for remote command execution status."""
    normalized = normalize_cli_output(output or "")
    method_match = re.search(
        r"Executed command via\s+([A-Za-z0-9_-]+)", normalized, re.IGNORECASE
    )
    method = method_match.group(1).lower() if method_match else None
    executed = bool(method_match)
    not_found = re.findall(r"Could Not Find ([^\r\n]+)", normalized, re.IGNORECASE)
    return NetexecExecStatus(
        executed=executed,
        method=method,
        not_found=[entry.strip() for entry in not_found if entry.strip()],
    )


def parse_netexec_sysvol_listing(output: str) -> list[str]:
    """Parse a SYSVOL directory listing for sensitive hive files."""
    normalized = normalize_cli_output(output or "")
    found: list[str] = []
    for name in ("SAM", "SYSTEM", "SECURITY"):
        if re.search(rf"\b{name}\b", normalized, re.IGNORECASE):
            found.append(name)
    return found


def parse_netexec_remote_command_output(output: str) -> str:
    """Strip NetExec banner/prefix lines and return only remote command output."""
    normalized = normalize_cli_output(output or "")
    cleaned_lines: list[str] = []
    prefix_re = re.compile(
        r"^(SMB|LDAP|MSSQL|WINRM|RDP|VNC|FTP|HTTP|HTTPS)\s+\S+\s+\d+\s+\S+\s+",
        re.IGNORECASE,
    )
    for raw_line in normalized.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        line = prefix_re.sub("", line).strip()
        if not line:
            continue
        if line.startswith(("[*]", "[+]", "[-]")):
            continue
        if "Executed command via" in line:
            continue
        if "(Pwn3d!)" in line:
            continue
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines)


@dataclass(frozen=True)
class NetexecShareEntry:
    """Parsed SMB share directory entry from NetExec output."""

    perms: str
    size: int
    path: str
    raw: str


def parse_netexec_share_dir_listing(output: str) -> list[NetexecShareEntry]:
    """Parse NetExec SMB --share/--dir output into entries."""
    normalized = normalize_cli_output(output or "")
    entries: list[NetexecShareEntry] = []
    prefix_re = re.compile(
        r"^(SMB)\s+\S+\s+\d+\s+\S+\s+",
        re.IGNORECASE,
    )
    for raw_line in normalized.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        line = prefix_re.sub("", line).strip()
        if not line:
            continue
        if line.startswith(("[*]", "[+]", "[-]")):
            continue
        if line.lower().startswith("perms"):
            continue
        if line.startswith("-----"):
            continue
        parts = line.split()
        if len(parts) < 8:
            continue
        perms = parts[0].strip()
        size_str = parts[1].strip()
        if not size_str.isdigit():
            continue
        try:
            size = int(size_str)
        except ValueError:
            continue
        path = " ".join(parts[7:]).strip()
        if not path:
            continue
        entries.append(
            NetexecShareEntry(
                perms=perms,
                size=size,
                path=path,
                raw=line,
            )
        )
    return entries


def summarize_share_map(
    share_map: dict[str, dict[str, str]],
) -> tuple[list[str], list[str], set[str], set[str]]:
    """Summarize a share map into read/write share names and hosts.

    Returns:
        (read_shares, write_shares, read_hosts, write_hosts)
    """
    read_shares: set[str] = set()
    write_shares: set[str] = set()
    read_hosts: set[str] = set()
    write_hosts: set[str] = set()

    for host, shares in share_map.items():
        for share, perm in shares.items():
            if "READ" in perm:
                read_shares.add(share)
                read_hosts.add(host)
            if "WRITE" in perm:
                write_shares.add(share)
                write_hosts.add(host)

    return (
        sorted(read_shares),
        sorted(write_shares),
        read_hosts,
        write_hosts,
    )


def parse_rid_usernames(output: str) -> list[str]:
    """Parse NetExec ``--rid-brute`` output and extract usernames.

    NetExec prints SID type information, e.g. lines containing ``SidTypeUser``.
    Historically the CLI used a grep/awk/sed pipeline to pull the 6th token and
    strip the ``DOMAIN\\`` prefix. This function implements the same intent in
    Python to avoid brittle shell pipelines.

    Args:
        output: NetExec stdout/stderr (text).

    Returns:
        A de-duplicated list of usernames (original order preserved).
    """
    if not output:
        return []

    excluded = {
        "guest",
        "defaultaccount",
        "wdagutilityaccoun",  # observed truncated variant
        "wdagutilityaccount",
        "invitado",
        "krbtgt",
    }

    results: list[str] = []
    seen: set[str] = set()

    for raw_line in output.splitlines():
        if "SidTypeUser" not in raw_line:
            continue

        # Prefer DOMAIN\user tokens when present.
        match = re.search(r"(?P<account>[^\s\\]+\\[^\s]+)", raw_line)
        if not match:
            # Fallback: take the 6th token if it exists (mimics old awk '{print $6}').
            parts = raw_line.split()
            if len(parts) < 6:
                continue
            token = parts[5]
        else:
            token = match.group("account")

        username = token.split("\\")[-1].strip().strip("'\"")
        if not username:
            continue

        lowered = username.lower()
        if lowered in excluded:
            continue
        if username.endswith("$"):
            continue

        if lowered in seen:
            continue
        seen.add(lowered)
        results.append(username)

    return results


def parse_smb_usernames(output: str) -> list[str]:
    """Parse NetExec SMB ``--users`` output and extract usernames.

    Historically the CLI used a shell pipeline resembling:
    - filter table headers/noise
    - take the 5th column
    - strip the ``DOMAIN\\`` prefix

    This function implements the same intent in Python to avoid brittle shell
    pipelines and keep behaviour consistent across platforms.

    Args:
        output: NetExec stdout/stderr (text).

    Returns:
        A de-duplicated list of usernames (original order preserved).
    """
    if not output:
        return []

    results: list[str] = []
    seen: set[str] = set()

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if "-Username-" in line or "never" in line.lower():
            continue
        if "]" in line:
            continue

        match = re.search(r"(?P<account>[^\s\\]+\\[^\s]+)", line)
        token: str | None
        if match:
            token = match.group("account")
        else:
            parts = line.split()
            if len(parts) < 5:
                continue
            token = parts[4]

        username = token.split("\\")[-1].strip().strip("'\"")
        if not username:
            continue

        key = username.lower()
        if key in seen:
            continue
        seen.add(key)
        results.append(username)

    return results


def parse_adcs_detection_output(output: str) -> tuple[str | None, str | None]:
    """Parse NetExec LDAP ADCS module output.

    Args:
        output: NetExec stdout/stderr (text).

    Returns:
        Tuple of (enrollment_server, ca_name).
    """
    if not output:
        return None, None

    enrollment_match = re.search(r"Found PKI Enrollment Server: ([^\n]+)", output)
    ca_match = re.search(r"Found CN: ([^\n]+)", output)

    enrollment_server = enrollment_match.group(1).strip() if enrollment_match else None
    ca_name = ca_match.group(1).strip() if ca_match else None

    return enrollment_server or None, ca_name or None


def parse_netexec_group_members(output: str) -> list[str]:
    """Parse NetExec LDAP ``--groups`` output and extract member names.

    Args:
        output: NetExec stdout/stderr (text).

    Returns:
        Member names as a de-duplicated list (order preserved). Names are returned
        without the ``DOMAIN\\`` prefix when present.
    """
    if not output:
        return []

    members: list[str] = []
    seen: set[str] = set()

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "GROUP-MEM" not in line:
            continue
        if "Found the following members" in line:
            continue

        token = line.split()[-1]
        member = token.split("\\")[-1].strip().strip("'\"")
        if not member:
            continue

        key = member.lower()
        if key in seen:
            continue
        seen.add(key)
        members.append(member)

    return members


def parse_netexec_ldap_query_attribute_values(output: str, attribute: str) -> list[str]:
    """Parse NetExec LDAP ``--query`` output and extract attribute values.

    NetExec prints query results using aligned columns, for example:

        LDAP ... [+] Response for object: CN=Remote Management Users,CN=Builtin,DC=htb,DC=local
        LDAP ... sAMAccountName       Remote Management Users

    Args:
        output: NetExec stdout.
        attribute: Attribute name to match (e.g. ``sAMAccountName``).

    Returns:
        List of extracted attribute values (stripped). May include duplicates
        if NetExec prints the same attribute multiple times.
    """
    needle = (attribute or "").strip()
    if not needle:
        return []

    values: list[str] = []
    # Match the attribute as a standalone token and capture the rest of the line.
    import re

    pattern = re.compile(rf"(?i)\b{re.escape(needle)}\b\s+(?P<value>.+?)\s*$")
    for line in (output or "").splitlines():
        match = pattern.search(line)
        if not match:
            continue
        value = (match.group("value") or "").strip()
        if value:
            values.append(value)
    return values


def parse_netexec_samaccountnames(output: str) -> list[str]:
    """Parse NetExec LDAP ``--query ... samAccountName`` output.

    Args:
        output: NetExec stdout/stderr (text).

    Returns:
        A de-duplicated list of sAMAccountName values.
    """
    if not output:
        return []

    results: list[str] = []
    seen: set[str] = set()

    for raw_line in output.splitlines():
        if "sAMAccountName:" not in raw_line:
            continue
        value = raw_line.split("sAMAccountName:", 1)[1].strip().strip("'\"")
        if not value:
            continue
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        results.append(value)

    return results


def parse_netexec_ldap_query_objects(output: str) -> list[dict[str, object]]:
    """Parse NetExec LDAP ``--query`` output into structured objects.

    NetExec prints LDAP query results as repeated blocks, for example::

        LDAP ... [+] Response for object: CN=Guest,CN=Users,DC=baby,DC=vl
        LDAP ... objectClass          top
        LDAP ...                      person
        LDAP ... cn                   Guest
        LDAP ... sAMAccountName       Guest

    This helper groups the lines by object and keeps multi-valued attributes
    together so higher-level LDAP enumeration code can reason about partial
    anonymous-bind results.

    Args:
        output: NetExec stdout/stderr text.

    Returns:
        List of dictionaries in the form::

            {
                "distinguished_name": "...",
                "attributes": {"objectclass": ["top", "person"], "cn": ["Guest"]},
            }
    """
    if not output:
        return []

    import re

    objects: list[dict[str, object]] = []
    current_dn: str | None = None
    current_attrs: dict[str, list[str]] = {}
    last_attr: str | None = None

    attr_name_re = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")

    def flush_current() -> None:
        nonlocal current_dn, current_attrs, last_attr
        if not current_dn:
            current_attrs = {}
            last_attr = None
            return
        objects.append(
            {
                "distinguished_name": current_dn,
                "attributes": current_attrs,
            }
        )
        current_dn = None
        current_attrs = {}
        last_attr = None

    for raw_line in output.splitlines():
        line = (raw_line or "").rstrip()
        if not line:
            continue

        parts = line.split(None, 4)
        body = parts[4] if len(parts) >= 5 else line.strip()
        if not body:
            continue

        if "Response for object:" in body:
            flush_current()
            current_dn = body.split("Response for object:", 1)[1].strip()
            continue

        if current_dn is None:
            continue

        body = body.rstrip()
        attr_parts = re.split(r"\s{2,}", body.strip(), maxsplit=1)
        if len(attr_parts) == 2 and attr_name_re.match(attr_parts[0].strip()):
            attr_name = attr_parts[0].strip().casefold()
            attr_value = attr_parts[1].strip()
            if attr_value:
                current_attrs.setdefault(attr_name, []).append(attr_value)
            else:
                current_attrs.setdefault(attr_name, [])
            last_attr = attr_name
            continue

        continuation = body.strip()
        if continuation and last_attr:
            current_attrs.setdefault(last_attr, []).append(continuation)

    flush_current()
    return objects




def parse_netexec_computer_badpwd(output: str) -> dict[str, int]:
    """Parse NetExec LDAP computer query output for BadPwdCount.

    Expected output format (example):
        ... Response for object: CN=DC01,OU=Domain Controllers,DC=example,DC=local
        ... badPwdCount          0
        ... badPasswordTime      133622272035020273
        ... sAMAccountName       DC01$

    Args:
        output: NetExec stdout/stderr (text).

    Returns:
        Mapping of normalized computer sAMAccountName -> bad password count.
    """
    if not output:
        return {}

    normalized = normalize_cli_output(output)
    results: dict[str, int] = {}

    current_sam: str | None = None
    current_badpwd: int | None = None

    for raw_line in normalized.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        lower = line.lower()
        if "response for object" in lower:
            if current_sam and current_badpwd is not None:
                results[normalize_username(current_sam)] = int(current_badpwd)
            current_sam = None
            current_badpwd = None
            continue

        if "badpwdcount" in lower:
            parts = line.split()
            try:
                current_badpwd = int(parts[-1])
            except (ValueError, IndexError):
                current_badpwd = None
            if current_sam and current_badpwd is not None:
                results[normalize_username(current_sam)] = int(current_badpwd)
            continue

        if "samaccountname" in lower:
            parts = line.split()
            if parts:
                current_sam = parts[-1].strip().strip("'\"")
                if current_badpwd is not None:
                    results[normalize_username(current_sam)] = int(current_badpwd)
            continue

    if current_sam and current_badpwd is not None:
        results[normalize_username(current_sam)] = int(current_badpwd)

    return results


def parse_machine_account_quota(output: str) -> int | None:
    """Extract MachineAccountQuota integer from output."""
    if not output:
        return None
    match = re.search(r"MachineAccountQuota:\s*(\d+)", output, flags=re.IGNORECASE)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def parse_smb_user_descriptions(output: str) -> dict[str, str]:
    """Parse NetExec SMB ``--users`` output to extract user descriptions.

    NetExec SMB --users output format includes a table with columns like:
    SMB IP PORT STATUS USERNAME BadPW LastLogon Description ...

    This function extracts username->description mappings from the output.

    Args:
        output: NetExec stdout/stderr (text).

    Returns:
        Dictionary mapping username -> description.
    """
    if not output:
        return {}

    user_descriptions: dict[str, str] = {}
    lines = output.splitlines()

    # Find header ("-Username-") boundary
    header_index: int | None = None
    for idx, line in enumerate(lines):
        if "-Username-" in line:
            header_index = idx
            break

    if header_index is None:
        return {}

    # Find footer ("local users") boundary
    footer_index: int | None = None
    for idx in range(header_index + 1, len(lines)):
        if "local users" in lines[idx].lower():
            footer_index = idx
            break

    if footer_index is None:
        footer_index = len(lines)

    # Process data lines between header and footer
    data_lines = lines[header_index + 1 : footer_index]

    for line in data_lines:
        line = line.rstrip("\r\n")
        if not line.strip():
            continue

        # NetExec SMB output has leading columns (e.g. 'SMB IP PORT STATUS')
        # Descriptions table includes a status token like "[+]" or "[-]" before username.
        parts = line.split()
        if len(parts) < 5:
            continue

        username = ""
        status_idx = next(
            (idx for idx, token in enumerate(parts) if token in {"[+]", "[-]", "[*]"}),
            None,
        )
        if status_idx is not None and status_idx + 1 < len(parts):
            username = parts[status_idx + 1]
        else:
            # Fallback: legacy heuristic (may be wrong for some outputs)
            username = parts[4]

        # Heuristic: search for the first integer column *after* username (BadPW)
        badpw_index: int | None = None
        start_idx = (status_idx + 2) if status_idx is not None else 5
        for idx in range(start_idx, len(parts)):
            try:
                # Column is considered BadPW if it can be parsed as int and
                # the next token is not clearly a timestamp pattern like 'YYYY-MM-DD'
                int(parts[idx])
                badpw_index = idx
                break
            except ValueError:
                continue

        if badpw_index is None or badpw_index + 1 >= len(parts):
            continue

        desc_start = badpw_index + 1
        # Skip LastLogon-like token when present (e.g. 2024-01-01, <never>)
        if desc_start < len(parts):
            last_logon = parts[desc_start]
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", last_logon) or (
                last_logon.startswith("<") and last_logon.endswith(">")
            ):
                desc_start += 1

        description_tokens = parts[desc_start:]
        description = " ".join(description_tokens).strip()

        if description:
            user_descriptions[username] = description

    return user_descriptions


_DUMPED_CREDENTIAL_TOKEN_RE = re.compile(r"(?P<token>[^\s\\]+\\[^\s:]+:[^\s]+)")
_DUMPED_SAM_TOKEN_RE = re.compile(
    r"(?P<token>[^\s:]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:[^\s]*)"
)


def extract_dumped_credentials(
    output: str,
    *,
    excluded_substrings: set[str] | None = None,
) -> list[str]:
    """Extract dumped credential tokens from NetExec output.

    NetExec dump modules (e.g. ``--lsa`` / ``--sam``) often print the credential
    blob as a single token in the output line (historically extracted via
    ``awk '{print $5}'``). This helper finds those tokens without relying on
    shell pipelines. Supports tokens with ``DOMAIN\\user:...`` and SAM-style
    entries without a domain prefix (common on DCs).

    Args:
        output: NetExec stdout/stderr (text).
        excluded_substrings: Optional set of substrings that, when present in a
            token (case-insensitive), cause it to be skipped.

    Returns:
        List of extracted credential tokens (order preserved, de-duplicated).
    """
    if not output:
        return []

    excluded_lower = {value.lower() for value in (excluded_substrings or set())}
    results: list[str] = []
    seen: set[str] = set()

    for raw_line in output.splitlines():
        for pattern in (_DUMPED_CREDENTIAL_TOKEN_RE, _DUMPED_SAM_TOKEN_RE):
            for match in pattern.finditer(raw_line):
                token = match.group("token").strip().strip(",;\"'")
                if not token:
                    continue
                token_lower = token.lower()
                if excluded_lower and any(
                    excl in token_lower for excl in excluded_lower
                ):
                    continue
                if token_lower in seen:
                    continue
                seen.add(token_lower)
                results.append(token)

    return results
