"""Container-runtime capability probe — does this runtime let ADscan run?

ADscan's runtime image carries file capabilities on its network binaries
(``setcap cap_net_raw,cap_net_admin,cap_net_bind_service+ep`` on the venv
python; ``cap_net_admin`` on the ligolo proxy). In a **remapped user namespace**
(rootless Docker, rootless Podman, or ``dockerd --userns-remap``) the kernel
refuses to ``exec`` a capability-bearing binary for the (non-root) run user with
``EPERM`` — "Operation not permitted" — so ADscan never starts. Even when it
could be made to start, rootless runtimes cannot grant ``NET_RAW`` / ``NET_ADMIN``
over the real network, so ICMP discovery and tun-based pivoting are unavailable.

This module answers the only question that actually matters — *"can ADscan run,
with the capabilities it needs, in THIS runtime?"* — by **probing the real image
as the real run user**, not by guessing from a proxy like "is it rootless". A
short ephemeral container reports, from inside the actual user namespace:

* whether the user namespace is remapped (``/proc/self/uid_map``),
* the effective capability set (``/proc/self/status`` ``CapEff``),
* and, decisively, whether the capability-bearing python can actually ``exec``.

Because it reproduces the exact failure in the exact runtime/user, it correctly
covers rootless Docker, rootless Podman, ``--userns-remap`` rootful, AND
rootful-with-caps-stripped (seccomp/AppArmor) — none of which a coarse
"rootless?" check would get right.

The docker invocation is injected (``run_docker_fn``) so the parsing/verdict
logic is pure and unit-testable without a daemon.
"""

from __future__ import annotations

from dataclasses import dataclass

# Linux capability bit positions (see <linux/capability.h>).
_CAP_NET_BIND_SERVICE = 10
_CAP_NET_ADMIN = 12
_CAP_NET_RAW = 13
_CAP_SYS_TIME = 25

_PROBE_MARKER = "ADSCANPROBE"

# Shell probe run INSIDE the image as the real run user. Emits one marker line.
# Kept POSIX-sh portable and dependency-free (no python/awk assumptions beyond
# coreutils that the runtime image ships). uid_map spaces are squeezed to '_'
# so the marker is trivially splittable.
#
# ``capeff`` is the SHELL's effective set and is kept for diagnostics only. It
# is NOT the capability set ADscan runs with: the kernel clears permitted and
# effective caps when a process runs as a non-root uid, so a plain ``/bin/sh``
# under ``--user 1000:1000`` reports ``CapEff: 0`` on EVERY runtime, rootful or
# rootless, no matter what ``--cap-add`` was passed. Reading network caps off
# that shell declared every host "reduced network mode".
#
# ``pycapeff`` is the load-bearing one: the effective set of the venv python
# AFTER exec, which is where the file capabilities land
# (``cap_net_raw,cap_net_admin,cap_net_bind_service=ep``) and is exactly the
# process that opens ADscan's raw sockets and tun devices.
_PROBE_SCRIPT = (
    'um=$(head -n1 /proc/self/uid_map 2>/dev/null | tr -s " " | '
    'sed -e "s/^_//" -e "s/ /_/g" | tr " " "_"); '
    'ce=$(grep -m1 "^CapEff:" /proc/self/status 2>/dev/null | '
    "cut -f2 | tr -d ' \t'); "
    'py=$(readlink -f /opt/adscan/venv/bin/python 2>/dev/null); '
    'if [ -n "$py" ] && "$py" -c "" 2>/dev/null; then fx=ok; else fx=fail; fi; '
    'pce=$("$py" -c "print(open(\'/proc/self/status\').read())" 2>/dev/null | '
    "grep -m1 '^CapEff:' | cut -f2 | tr -d ' \t'); "
    'printf "%s|uidmap=%s|capeff=%s|pycapeff=%s|filecap_exec=%s\\n" '
    f'"{_PROBE_MARKER}" "$um" "$ce" "$pce" "$fx"'
)


@dataclass(frozen=True)
class RuntimeCapabilityVerdict:
    """Outcome of probing the container runtime for ADscan's needs.

    ``supported`` is the load-bearing field: it is ``True`` only when ADscan's
    capability-bearing binaries can actually execute in this runtime as the run
    user. ``degraded`` flags a runtime where it runs but the network caps ADscan
    wants (NET_RAW/NET_ADMIN) are missing. ``probe_ok`` is ``False`` when the
    probe itself could not run/parse — callers must treat that as UNKNOWN and
    not block (fail-open), since we could not prove a problem.
    """

    probe_ok: bool
    supported: bool
    degraded: bool
    userns_remapped: bool
    filecap_exec_ok: bool
    net_raw: bool
    net_admin: bool
    reason: str
    raw: str = ""


def _decode_capeff(capeff_hex: str) -> set[int]:
    """Decode a ``CapEff`` hex bitmask into the set of capability bit positions."""
    text = (capeff_hex or "").strip().lower().removeprefix("0x")
    if not text:
        return set()
    try:
        mask = int(text, 16)
    except ValueError:
        return set()
    return {bit for bit in range(64) if mask & (1 << bit)}


def _userns_remapped_from_uidmap(uidmap: str) -> bool | None:
    """Return whether the uid_map indicates a remapped userns, or ``None`` if unknown.

    First uid_map line is ``<container_id> <host_id> <count>`` (squeezed to
    ``_`` here). The init namespace maps container 0 → host 0; any other host_id
    (e.g. 100000) means a remapped (rootless / userns-remap) namespace.
    """
    parts = [p for p in (uidmap or "").split("_") if p != ""]
    if len(parts) < 2:
        return None
    host_id = parts[1]
    if not host_id.isdigit():
        return None
    return host_id != "0"


def _parse_probe_output(stdout: str) -> dict[str, str] | None:
    """Extract the ``key=val`` fields from the probe marker line, or ``None``."""
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith(_PROBE_MARKER + "|"):
            continue
        fields: dict[str, str] = {}
        for chunk in line.split("|")[1:]:
            if "=" in chunk:
                key, _, val = chunk.partition("=")
                fields[key.strip()] = val.strip()
        return fields
    return None


def build_verdict_from_probe(
    *, returncode: int, stdout: str, stderr: str
) -> RuntimeCapabilityVerdict:
    """Build a :class:`RuntimeCapabilityVerdict` from a raw probe result (pure)."""
    parsed = _parse_probe_output(stdout)
    if parsed is None:
        # The probe did not emit its marker — could not prove anything. Fail-open.
        detail = (stderr or stdout or "").strip().splitlines()
        tail = detail[-1] if detail else "no output"
        return RuntimeCapabilityVerdict(
            probe_ok=False,
            supported=True,  # do not block on an inconclusive probe
            degraded=False,
            userns_remapped=False,
            filecap_exec_ok=True,
            net_raw=False,
            net_admin=False,
            reason=f"runtime probe inconclusive (rc={returncode}): {tail}",
            raw=(stdout or "").strip(),
        )

    filecap_exec_ok = parsed.get("filecap_exec", "").lower() == "ok"
    remapped = _userns_remapped_from_uidmap(parsed.get("uidmap", ""))
    # Read the caps off the file-capability-bearing python, which is the process
    # that actually does ADscan's network work. The shell's set is empty for any
    # non-root uid and would report every runtime as degraded. An older probe
    # output without the field falls back to the shell set.
    caps = _decode_capeff(parsed.get("pycapeff", "")) or _decode_capeff(
        parsed.get("capeff", "")
    )
    net_raw = _CAP_NET_RAW in caps
    net_admin = _CAP_NET_ADMIN in caps

    supported = filecap_exec_ok
    degraded = supported and not (net_raw and net_admin)
    if not supported:
        reason = (
            "the runtime cannot exec ADscan's capability-bearing binaries "
            "(rootless / user-namespace-remapped container runtime)"
        )
    elif degraded:
        reason = (
            "binaries run but NET_RAW/NET_ADMIN are unavailable "
            "(reduced network mode: no ICMP discovery / tun pivoting)"
        )
    else:
        reason = "runtime provides the capabilities ADscan needs"

    return RuntimeCapabilityVerdict(
        probe_ok=True,
        supported=supported,
        degraded=degraded,
        userns_remapped=bool(remapped),
        filecap_exec_ok=filecap_exec_ok,
        net_raw=net_raw,
        net_admin=net_admin,
        reason=reason,
        raw=(stdout or "").strip(),
    )


def probe_runtime_capability(
    *,
    image: str,
    uid: int,
    gid: int,
    cap_add: tuple[str, ...] = (),
    run_docker_fn=None,
    timeout: int = 60,
) -> RuntimeCapabilityVerdict:
    """Probe ``image`` as ``uid:gid`` and return the capability verdict.

    Runs ``docker run --rm --user <uid>:<gid> [--cap-add ...] --entrypoint
    /bin/sh <image> -c <probe>``. Running as the SAME uid:gid the real container
    uses is essential: in a remapped userns, file caps may be honored for
    container-root but NOT for the gosu run user, so probing as root would
    false-pass. Injecting ``run_docker_fn`` keeps this testable.

    Returns a fail-open verdict (``probe_ok=False``, ``supported=True``) if the
    probe cannot be run, so a flaky daemon never blocks the user.
    """
    if run_docker_fn is None:
        from adscan_launcher.docker_runtime import run_docker_command

        def run_docker_fn(args):  # type: ignore[misc]
            return run_docker_command(
                args, check=False, capture_output=True, timeout=timeout
            )

    args = ["docker", "run", "--rm", "--user", f"{uid}:{gid}"]
    for cap in cap_add:
        args.extend(["--cap-add", cap])
    args.extend(["--entrypoint", "/bin/sh", image, "-c", _PROBE_SCRIPT])

    try:
        proc = run_docker_fn(args)
    except Exception as exc:  # noqa: BLE001 — fail-open on any probe error
        return RuntimeCapabilityVerdict(
            probe_ok=False,
            supported=True,
            degraded=False,
            userns_remapped=False,
            filecap_exec_ok=True,
            net_raw=False,
            net_admin=False,
            reason=f"runtime probe could not run: {exc}",
            raw="",
        )

    return build_verdict_from_probe(
        returncode=int(getattr(proc, "returncode", 1) or 0),
        stdout=str(getattr(proc, "stdout", "") or ""),
        stderr=str(getattr(proc, "stderr", "") or ""),
    )


def describe_verdict(verdict: RuntimeCapabilityVerdict) -> list[str]:
    """Return operator-facing guidance lines for a non-supported/degraded verdict.

    Empty when the runtime is fully supported (nothing to say).
    """
    if verdict.supported and not verdict.degraded:
        return []
    lines: list[str] = []
    if not verdict.supported:
        lines.append(
            "Rootless / user-namespace container runtime detected (rootless "
            "Docker or Podman). The kernel will not let ADscan's network "
            "binaries start in this runtime."
        )
    else:
        lines.append(
            "Rootless / user-namespace container runtime detected: ADscan can "
            "run, but in reduced network mode (no ICMP host discovery, no "
            "tun-based pivoting) — those need NET_RAW/NET_ADMIN, which a "
            "rootless runtime cannot grant."
        )
    lines.append(
        "For full functionality, run ADscan on a standard (rootful) Docker "
        "daemon. To use it as your normal user without sudo, add your user to "
        "the 'docker' group."
    )
    return lines


__all__ = [
    "RuntimeCapabilityVerdict",
    "probe_runtime_capability",
    "build_verdict_from_probe",
    "describe_verdict",
]
