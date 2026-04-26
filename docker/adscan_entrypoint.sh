#!/usr/bin/env bash
set -euo pipefail

uid="${ADSCAN_UID:-1000}"
gid="${ADSCAN_GID:-1000}"

# Always mark the process as running inside the ADscan FULL container runtime.
# The official host launcher provides additional wiring (host-helper socket,
# local resolver IP, launcher marker), but manual `docker run` / `docker exec`
# should still be recognized as container runtime so the Python guard can block
# unsupported launch paths clearly.
export ADSCAN_CONTAINER_RUNTIME=1

# Entry-point log file for ADscan runtime diagnostics.
ENTRYPOINT_LOG="/opt/adscan/state/entrypoint.log"
mkdir -p "$(dirname "${ENTRYPOINT_LOG}")" >/dev/null 2>&1 || true
: > "${ENTRYPOINT_LOG}" 2>/dev/null || true

_ep_log() {
  # Log entrypoint diagnostics both to stderr (for docker logs) and to a
  # structured log file that the Python runtime can later ingest and forward
  # through the Rich + telemetry pipeline.
  local msg="$*"
  echo "[entrypoint] ${msg}" >&2
  # Best-effort only: failures here must never break container startup.
  {
    printf '%s\n' "${msg}" >>"${ENTRYPOINT_LOG}"
  } 2>/dev/null || true
}

if ! command -v gosu >/dev/null 2>&1; then
  _ep_log "gosu not found; image build is incomplete"
  exit 1
fi

_check_launcher_runtime_contract() {
  local issues=()

  if [[ "${ADSCAN_CONTAINER_RUNTIME:-}" != "1" ]]; then
    return 0
  fi

  if [[ "${ADSCAN_OFFICIAL_LAUNCHER:-}" != "1" ]]; then
    issues+=("missing_official_launcher_marker")
  fi

  if [[ -z "${ADSCAN_HOST_HELPER_SOCK:-}" ]]; then
    issues+=("missing_host_helper_socket_env")
  elif [[ ! -S "${ADSCAN_HOST_HELPER_SOCK}" ]]; then
    issues+=("host_helper_socket_not_ready")
  fi

  if [[ -z "${ADSCAN_LOCAL_RESOLVER_IP:-}" ]]; then
    issues+=("missing_local_resolver_ip")
  fi

  if [[ "${#issues[@]}" -eq 0 ]]; then
    _ep_log "launcher runtime contract OK"
    return 0
  fi

  _ep_log "launcher runtime contract incomplete: ${issues[*]}"
  _ep_log "FULL runtime should be started via the official host launcher (pipx/pip install adscan)"
  _ep_log "manual in-container launches will be blocked by the Python runtime guard"
  if [[ -n "${ADSCAN_HOST_HELPER_SOCK:-}" ]]; then
    _ep_log "host helper socket path: ${ADSCAN_HOST_HELPER_SOCK}"
  fi
}

_check_launcher_runtime_contract

if ! getent group "${gid}" >/dev/null 2>&1; then
  groupadd -g "${gid}" adscan >/dev/null 2>&1 || true
fi

if ! getent passwd "${uid}" >/dev/null 2>&1; then
  useradd -u "${uid}" -g "${gid}" -d /opt/adscan -s /bin/bash adscan >/dev/null 2>&1 || true
fi

# Allow the unprivileged ADscan user to run specific host-style maintenance
# commands as root inside the container without prompting for a password.
if command -v sudo >/dev/null 2>&1; then
  {
    echo "Defaults:adscan !requiretty"
    echo "Defaults:adscan env_keep += \"HOME XDG_CONFIG_HOME XDG_CACHE_HOME ADSCAN_HOME\""
    echo "adscan ALL=(root) NOPASSWD: /usr/bin/nmap"
    echo "adscan ALL=(root) NOPASSWD: /usr/sbin/ntpdate"
    echo "adscan ALL=(root) NOPASSWD: /usr/bin/ntpdig"
    echo "adscan ALL=(root) NOPASSWD: /usr/sbin/ntpdig"
    echo "adscan ALL=(root) NOPASSWD: /usr/bin/install"
    # Needed so sudo_validate() non-interactive probe succeeds in this container.
    echo "adscan ALL=(root) NOPASSWD: /usr/bin/true"
    echo "adscan ALL=(root) NOPASSWD: /bin/true"
    # kill is used by stop_background() to terminate root-owned process groups.
    echo "adscan ALL=(root) NOPASSWD: /bin/kill"
    echo "adscan ALL=(root) NOPASSWD: /usr/bin/kill"
    # Background tools launched via launch_background() (needs_root=True).
    # Responder — scoped to the dedicated venv python running Responder.py only.
    echo "adscan ALL=(root) NOPASSWD: /opt/adscan/tool_venvs/responder/venv/bin/python"
    # ntlmrelayx — will be added here when the relay attack module is implemented.
  } > /etc/sudoers.d/adscan
  chmod 0440 /etc/sudoers.d/adscan
fi

# Ensure the unprivileged user can interact with the allocated pseudo-TTY.
# Some interactive libraries (prompt_toolkit/questionary) may attempt to open
# /dev/tty in addition to using stdin; in containers the PTY is typically
# group-owned by `tty`.
if getent group tty >/dev/null 2>&1; then
  usermod -a -G tty adscan >/dev/null 2>&1 || true
fi

mkdir -p /opt/adscan/workspaces /opt/adscan/logs /opt/adscan/.config /opt/adscan/.cache

_fix_ownership_same_fs() {
  local target="$1"
  local label="$2"
  if [[ ! -e "${target}" ]]; then
    return 0
  fi

  # Important: do not traverse into nested mount points (e.g. CIFS mounts under
  # workspaces). Those may be read-only and are not owned by the container
  # runtime to begin with.
  if ! chown "${uid}:${gid}" "${target}" >/dev/null 2>&1; then
    _ep_log "ownership fix skipped for ${label} root: ${target}"
  fi

  if command -v find >/dev/null 2>&1; then
    if ! find "${target}" -xdev \( ! -uid "${uid}" -o ! -gid "${gid}" \) -exec chown "${uid}:${gid}" {} + >/dev/null 2>&1; then
      _ep_log "ownership fix encountered non-fatal errors under ${label}: ${target}"
    fi
  fi
}

_fix_ownership_same_fs /opt/adscan/workspaces "workspaces"
_fix_ownership_same_fs /opt/adscan/logs "logs"
_fix_ownership_same_fs /opt/adscan/.config "config"
_fix_ownership_same_fs /opt/adscan/.cache "cache"

# Hashcat writes compiled OpenCL kernels under its own `kernels/` directory.
# If that tree was previously touched by root, later runs as the unprivileged
# ADscan user fail with `*.kernel: Permission denied`.
if [[ -d /opt/adscan/tools ]]; then
  for hashcat_dir in /opt/adscan/tools/hashcat-*; do
    if [[ -d "${hashcat_dir}" ]]; then
      mkdir -p "${hashcat_dir}/kernels" >/dev/null 2>&1 || true
      _fix_ownership_same_fs "${hashcat_dir}/kernels" "hashcat kernels"
    fi
  done
fi

# Fix common TTY settings for interactive prompts.
# - Rich Prompt.ask relies on the terminal line discipline for editing keys.
# - In some Docker/PTY setups, the terminal "erase" key is misconfigured which
#   causes backspace to render as "^H" instead of deleting.
# - questionary/prompt_toolkit works around this by using raw mode, which is
#   why it tends to behave better.
if [[ -t 0 ]] && command -v stty >/dev/null 2>&1; then
  # Don't echo control chars like ^H when users press backspace.
  stty -echoctl >/dev/null 2>&1 || true

  # Align the erase key with the terminal's backspace capability.
  # Prefer terminfo if available; fall back to leaving the current erase.
  if command -v tput >/dev/null 2>&1; then
    kbs="$(tput kbs 2>/dev/null || true)"
    if [[ "${#kbs}" -eq 1 ]]; then
      if [[ "${kbs}" == $'\b' ]]; then
        stty erase '^H' >/dev/null 2>&1 || true
      elif [[ "${kbs}" == $'\x7f' ]]; then
        stty erase '^?' >/dev/null 2>&1 || true
      fi
    fi
  fi
fi

# Docker mounts /etc/hosts inside the container. It is writable but cannot be
# atomically replaced (rename/unlink). Make it directly writable by the ADscan
# user so ADscan can update it without sudo.
chown "${uid}:${gid}" /etc/hosts >/dev/null 2>&1 || true
chmod 0664 /etc/hosts >/dev/null 2>&1 || true

# Allow the (unprivileged) ADscan process to update the generated Unbound config snippet.
mkdir -p /etc/unbound/unbound.conf.d
_fix_ownership_same_fs /etc/unbound/unbound.conf.d "unbound-config"

# Ensure the container resolver uses Unbound first.
# NOTE: Avoid escaping quotes inside awk programs. Escaped quotes (e.g. \"name\")
# become literal backslashes and can cause awk syntax errors in some environments.
existing_ns="$(awk '$1 == "nameserver" { print $2 }' /etc/resolv.conf 2>/dev/null | tr '\n' ' ' | xargs || true)"
existing_extra_lines="$(awk '!/^[[:space:]]*#/ && $1 != "nameserver" {print}' /etc/resolv.conf 2>/dev/null | sed '/^[[:space:]]*$/d' || true)"
_ep_log "upstream nameservers from initial /etc/resolv.conf: ${existing_ns:-<none>}"
resolver_ip_candidates=()
# Prefer explicit override if provided by the host launcher, but always include
# a small loopback pool as fallback. When running with --network host, the
# container shares the host network namespace. If the host already has a DNS
# daemon bound to 127.0.0.1:53, Unbound cannot bind there. Using another
# 127.0.0.x address typically avoids touching host services.
# Prefer 127.0.0.2+ first: in `--network host` mode, 127.0.0.1:53 is commonly
# occupied by host DNS daemons (systemd-resolved/dnsmasq/unbound). Using another
# loopback address avoids touching host services.
resolver_ip_candidates=("127.0.0.2" "127.0.0.3" "127.0.0.4" "127.0.0.5" "127.0.0.1")
if [[ -n "${ADSCAN_LOCAL_RESOLVER_IP:-}" ]]; then
  resolver_ip_candidates=("${ADSCAN_LOCAL_RESOLVER_IP}" "${resolver_ip_candidates[@]}")
fi

# De-duplicate while preserving order.
deduped_candidates=()
for ip in "${resolver_ip_candidates[@]}"; do
  seen=0
  for existing in "${deduped_candidates[@]}"; do
    if [[ "${existing}" == "${ip}" ]]; then
      seen=1
      break
    fi
  done
  if [[ "${seen}" -eq 0 ]]; then
    deduped_candidates+=("${ip}")
  fi
done
resolver_ip_candidates=("${deduped_candidates[@]}")

_is_public_resolver() {
  local candidate="$1"
  case "${candidate}" in
    1.1.1.1|1.0.0.1|8.8.8.8|8.8.4.4|9.9.9.9|149.112.112.112)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

_public_dns_mode() {
  if [[ "${ADSCAN_ALLOW_PUBLIC_DNS:-1}" != "1" ]]; then
    echo "disabled"
    return 0
  fi
  local mode
  mode="$(printf '%s' "${ADSCAN_PUBLIC_DNS_MODE:-prefer-public}" | tr '[:upper:]' '[:lower:]' | tr '_' '-')"
  case "${mode}" in
    prefer|public|prefer-public)
      echo "prefer-public"
      ;;
    inherit|host|system)
      echo "inherit"
      ;;
    disabled|off|false|no)
      echo "disabled"
      ;;
    *)
      _ep_log "unknown ADSCAN_PUBLIC_DNS_MODE='${ADSCAN_PUBLIC_DNS_MODE:-}'; using inherit"
      echo "inherit"
      ;;
  esac
}

_public_dns_resolvers() {
  local raw="${ADSCAN_PUBLIC_DNS_RESOLVERS:-1.1.1.1,8.8.8.8,8.8.4.4}"
  raw="${raw//,/ }"
  local resolver
  local -a emitted=()
  for resolver in ${raw}; do
    [[ -z "${resolver}" ]] && continue
    local seen=0
    for existing in "${emitted[@]}"; do
      if [[ "${existing}" == "${resolver}" ]]; then
        seen=1
        break
      fi
    done
    if [[ "${seen}" -eq 0 ]]; then
      emitted+=("${resolver}")
      printf '%s\n' "${resolver}"
    fi
  done
}

_write_resolv_conf_local_first() {
  local local_resolver_ip="$1"
  local allow_public_dns="${ADSCAN_ALLOW_PUBLIC_DNS:-1}"
  if [[ ! -w /etc/resolv.conf ]]; then
    _ep_log "/etc/resolv.conf is not writable; cannot enforce ${local_resolver_ip} first"
    return 1
  fi
  local -a additional_fallback_ns=()
  while IFS= read -r ns; do
    [[ -n "${ns}" ]] && additional_fallback_ns+=("${ns}")
  done < <(_get_unbound_upstreams "${local_resolver_ip}")
  {
    echo "# Managed by ADscan container runtime"
    echo "nameserver ${local_resolver_ip}"
    for ns in ${existing_ns:-}; do
      if [[ "${allow_public_dns}" != "1" ]] && _is_public_resolver "${ns}"; then
        continue
      fi
      if [[ "${ns}" != "${local_resolver_ip}" ]]; then
        echo "nameserver ${ns}"
      fi
    done
    # If the host/docker resolv.conf didn't include any usable upstreams (for
    # example it only contained the same loopback IP), optionally add public
    # fallbacks when ADSCAN_ALLOW_PUBLIC_DNS=1.
    for ns in "${additional_fallback_ns[@]}"; do
      if [[ "${ns}" == "${local_resolver_ip}" ]]; then
        continue
      fi
      if [[ "${allow_public_dns}" != "1" ]] && _is_public_resolver "${ns}"; then
        continue
      fi
      local seen=0
      for existing in ${existing_ns:-}; do
        if [[ "${existing}" == "${ns}" ]]; then
          seen=1
          break
        fi
      done
      if [[ "${seen}" -eq 0 ]]; then
        echo "nameserver ${ns}"
      fi
    done
    if [[ -n "${existing_extra_lines}" ]]; then
      echo ""
      echo "${existing_extra_lines}"
    fi
  } > /etc/resolv.conf
  # Log the final resolver order without embedding awk directly in the echo to
  # avoid escaping issues in some shells.
  local ns_order=""
  if command -v awk >/dev/null 2>&1; then
    ns_order="$(awk '$1 == "nameserver" { print $2 }' /etc/resolv.conf 2>/dev/null | tr '\n' ' ' | xargs || true)"
  fi
  _ep_log "enforced /etc/resolv.conf order (local first): ${ns_order:-<none>}"
}

_get_unbound_upstreams() {
  local local_resolver_ip="$1"
  local -a upstreams=()
  local public_dns_mode
  public_dns_mode="$(_public_dns_mode)"

  _append_upstream() {
    local ns="$1"
    if [[ -z "${ns}" ]]; then
      return 0
    fi
    if [[ "${ns}" == "${local_resolver_ip}" || "${ns}" == "127.0.0.53" || "${ns}" == 127.* ]]; then
      return 0
    fi
    if [[ "${public_dns_mode}" == "disabled" ]] && _is_public_resolver "${ns}"; then
      return 0
    fi
    local seen=0
    for existing in "${upstreams[@]}"; do
      if [[ "${existing}" == "${ns}" ]]; then
        seen=1
        break
      fi
    done
    if [[ "${seen}" -eq 0 ]]; then
      upstreams+=("${ns}")
    fi
  }

  _get_systemd_resolved_upstreams() {
    local resolver_ip="$1"
    local -a resolved_upstreams=()
    local path=""
    for path in /run/systemd/resolve/resolv.conf /run/systemd/resolve/stub-resolv.conf; do
      if [[ -r "${path}" ]]; then
        while IFS= read -r ns; do
          [[ -z "${ns}" ]] && continue
          if [[ "${ns}" == "${resolver_ip}" ]]; then
            continue
          fi
          if [[ "${ns}" == 127.* ]]; then
            continue
          fi
          if [[ "${public_dns_mode}" == "disabled" ]] && _is_public_resolver "${ns}"; then
            continue
          fi
          local seen=0
          for existing in "${resolved_upstreams[@]}"; do
            if [[ "${existing}" == "${ns}" ]]; then
              seen=1
              break
            fi
          done
          if [[ "${seen}" -eq 0 ]]; then
            resolved_upstreams+=("${ns}")
          fi
        done < <(awk '$1 == "nameserver" { print $2 }' "${path}" 2>/dev/null)
      fi
    done
    printf '%s\n' "${resolved_upstreams[@]}"
  }

  if [[ "${public_dns_mode}" == "prefer-public" ]]; then
    while IFS= read -r ns; do
      _append_upstream "${ns}"
    done < <(_public_dns_resolvers)
  fi

  # Prefer whatever Docker/host provided in the initial resolv.conf. This is
  # used either as primary policy (inherit) or as fallback after preferred
  # public resolvers (prefer-public).
  for ns in ${existing_ns:-}; do
    _append_upstream "${ns}"
  done

  # Fallback: if the initial resolv.conf only had a loopback entry (common when
  # a host-local resolver was configured), try systemd-resolved's upstream list.
  if [[ "${#upstreams[@]}" -eq 0 ]]; then
    while IFS= read -r ns; do
      _append_upstream "${ns}"
    done < <(_get_systemd_resolved_upstreams "${local_resolver_ip}")
    if [[ "${#upstreams[@]}" -gt 0 ]]; then
      _ep_log "upstream nameservers from systemd-resolved: ${upstreams[*]}"
    fi
  fi

  # Final fallback: optionally add public resolvers when allowed.
  if [[ "${#upstreams[@]}" -eq 0 ]] && [[ "${public_dns_mode}" != "disabled" ]]; then
    while IFS= read -r ns; do
      _append_upstream "${ns}"
    done < <(_public_dns_resolvers)
  fi

  printf '%s\n' "${upstreams[@]}"
}

# Write a minimal Unbound config that listens on the selected loopback IP and
# forwards everything to the current upstreams (from /etc/resolv.conf). ADscan
# will later rewrite /etc/unbound/unbound.conf.d/10-adscan.conf with conditional
# forwarding zones.
_write_unbound_entrypoint_config() {
  local local_resolver_ip="$1"
  local conf_path="/etc/unbound/unbound.conf.d/10-adscan.conf"
  {
    echo "# ADscan Unbound configuration"
    echo "# Auto-generated - do not edit manually"
    echo ""
    echo "server:"
    echo "  interface: ${local_resolver_ip}"
    echo "  port: 53"
    echo "  access-control: 127.0.0.0/8 allow"
    echo "  do-ip6: no"
    echo ""
    echo "forward-zone:"
    echo '  name: "."'
    while IFS= read -r ns; do
      [[ -n "${ns}" ]] && echo "  forward-addr: ${ns}"
    done < <(_get_unbound_upstreams "${local_resolver_ip}")
    echo ""
  } > "${conf_path}"
  chmod 0644 "${conf_path}" >/dev/null 2>&1 || true
  chown "${uid}:${gid}" "${conf_path}" >/dev/null 2>&1 || true
}

# Start Unbound (no systemd in containers). Keep this script as PID 1 so we can
# reap processes and avoid zombies.
unbound_pid=""
local_resolver_ip_selected=""
if command -v unbound >/dev/null 2>&1; then
  _unbound_is_listening_on() {
    local ip="$1"
    # Verify the daemon actually bound port 53 on the selected loopback.
    # We avoid "dig . SOA" health checks here because many upstream resolvers
    # (or forwarding setups) can refuse/FORMERR root queries even when Unbound
    # itself is healthy. Socket-level checks are the most reliable signal in
    # container/CI environments.
    # Use numeric output (-n) to avoid "domain" service-name rendering (":domain"
    # instead of ":53"), which breaks string matching and causes flaky startup
    # detection.
    ss -Hn -lunp 2>/dev/null | grep -F "${ip}:53" | grep -q "unbound" && return 0
    ss -Hn -ltnp 2>/dev/null | grep -F "${ip}:53" | grep -q "unbound" && return 0
    return 1
  }

  _detect_running_unbound_ip() {
    # Best-effort: detect which 127.0.0.x Unbound is currently bound to.
    # If not found, return empty.
    local ip=""
    ip="$(ss -Hn -lunp 2>/dev/null | grep -F ':53' | grep -F 'unbound' | sed -nE 's/.*[[:space:]]([0-9.]+):53[[:space:]].*/\1/p' | head -n 1 || true)"
    if [[ -z "${ip}" ]]; then
      ip="$(ss -Hn -ltnp 2>/dev/null | grep -F ':53' | grep -F 'unbound' | sed -nE 's/.*[[:space:]]([0-9.]+):53[[:space:]].*/\1/p' | head -n 1 || true)"
    fi
    if [[ -n "${ip}" ]]; then
      echo "${ip}"
    fi
  }

  _wait_for_unbound_to_listen() {
    local ip="$1"
    local pid="$2"
    local timeout_s="${3:-5}"

    # Poll for up to N seconds; Unbound can take a moment to bind depending on
    # system load and entropy. Using a fixed sleep (e.g. 0.3s) is too flaky in CI.
    local deadline
    deadline="$(($(date +%s) + timeout_s))"
    while [[ "$(date +%s)" -lt "${deadline}" ]]; do
      if ! kill -0 "${pid}" >/dev/null 2>&1; then
        return 1
      fi
      if _unbound_is_listening_on "${ip}"; then
        return 0
      fi
      sleep 0.1
    done
    return 1
  }

  # Sometimes Unbound can be left as a defunct/stale process (e.g. after a failed
  # start). Treat "process exists but no listening socket" as not running.
  if pgrep -x unbound >/dev/null 2>&1; then
    existing_ip="$(_detect_running_unbound_ip || true)"
    if [[ -n "${existing_ip}" ]] && _unbound_is_listening_on "${existing_ip}"; then
      local_resolver_ip_selected="${existing_ip}"
      _ep_log "Detected existing Unbound listener on ${local_resolver_ip_selected}:53"
    else
      _ep_log "Unbound process exists but is not listening on port 53; restarting"
      pkill -x unbound >/dev/null 2>&1 || true
      unbound_pid=""
      local_resolver_ip_selected=""
    fi
  fi

  if [[ -z "${local_resolver_ip_selected}" ]]; then
    # Debian's systemd unit runs helper scripts to ensure the trust anchor exists.
    # Re-run the update here so Unbound doesn't exit immediately.
    if [[ -x /usr/libexec/unbound-helper ]]; then
      /usr/libexec/unbound-helper root_trust_anchor_update >/dev/null 2>&1 || true
    fi
    # Fallback: some minimal/container environments do not ship the trust anchor
    # file by default. Create it using unbound-anchor if needed.
    if [[ ! -f /var/lib/unbound/root.key ]]; then
      mkdir -p /var/lib/unbound >/dev/null 2>&1 || true
      if getent passwd unbound >/dev/null 2>&1; then
        chown -R unbound:unbound /var/lib/unbound >/dev/null 2>&1 || true
      fi
      if [[ -f /usr/share/dns/root.key ]]; then
        cp -f /usr/share/dns/root.key /var/lib/unbound/root.key >/dev/null 2>&1 || true
      fi
      if command -v unbound-anchor >/dev/null 2>&1; then
        unbound-anchor -a /var/lib/unbound/root.key >/dev/null 2>&1 || true
      fi
    fi

    # Start in foreground (-d) and background it, so PID 1 can reap properly.
    # Log to file for debugging (and to stdout when interactive).
    unbound_log="/opt/adscan/logs/unbound.log"
    touch "${unbound_log}" >/dev/null 2>&1 || true

    for candidate_ip in "${resolver_ip_candidates[@]}"; do
      _write_unbound_entrypoint_config "${candidate_ip}" || true
      if command -v unbound-checkconf >/dev/null 2>&1; then
        if ! unbound-checkconf /etc/unbound/unbound.conf >/dev/null 2>&1; then
          _ep_log "unbound-checkconf failed; not starting unbound on ${candidate_ip}"
          unbound-checkconf /etc/unbound/unbound.conf >&2 || true
          continue
        fi
      fi
      if unbound -d -c /etc/unbound/unbound.conf >>"${unbound_log}" 2>&1 & then
        unbound_pid="$!"
      else
        unbound_pid=""
      fi

      if [[ -n "${unbound_pid}" ]]; then
        # Ensure the process is still alive and the port is bound.
        if _wait_for_unbound_to_listen "${candidate_ip}" "${unbound_pid}" 5; then
          local_resolver_ip_selected="${candidate_ip}"
          _ep_log "Unbound is listening on ${local_resolver_ip_selected}:53"
          _ep_log "Unbound forwarders: $(tr '\n' ' ' < <(_get_unbound_upstreams "${candidate_ip}") | xargs)"
          break
        fi
      fi

      if [[ -n "${unbound_pid}" ]]; then
        kill "${unbound_pid}" >/dev/null 2>&1 || true
        wait "${unbound_pid}" >/dev/null 2>&1 || true
        unbound_pid=""
      fi
    done
  fi
fi

if [[ -n "${local_resolver_ip_selected}" ]]; then
  export ADSCAN_LOCAL_RESOLVER_IP="${local_resolver_ip_selected}"
  _write_resolv_conf_local_first "${local_resolver_ip_selected}" || true
else
  _ep_log "unbound did not respond on any loopback candidate (127.0.0.x:53); leaving /etc/resolv.conf unchanged"
  # If the host launcher provided ADSCAN_LOCAL_RESOLVER_IP but Unbound couldn't
  # start, make sure the ADscan process doesn't assume a working local resolver.
  unset ADSCAN_LOCAL_RESOLVER_IP || true
fi

cleanup() {
  if [[ -n "${unbound_pid}" ]]; then
    kill "${unbound_pid}" >/dev/null 2>&1 || true
    wait "${unbound_pid}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

# Run ADscan in the foreground so it keeps a functional TTY (Prompts, selection UIs).
gosu "${uid}:${gid}" /usr/local/bin/adscan "$@"
