"""Engagement scope for the local DNS forwarder's upstreams.

The local forwarder (Unbound) is its own process: it sends DNS queries to the
upstream servers written in its configuration, and no in-process check can see
those queries. So the scope is applied to the CONFIGURATION, before it is
written: an upstream the engagement scope excludes is never in it.

The decision is the engagement-scope SSOT's
(:mod:`adscan_internal.services.engagement_scope`); this module only maps the
forwarder's two kinds of upstream onto it:

* a DOMAIN forwarder is the DNS server of an Active Directory domain (usually a
  domain controller). It is a host of the assessed estate, so it must pass the
  scope in full, for the name-resolution purpose: a denied one is dropped, and
  under an allow-list only a named one, or a domain controller used for
  directory reads, stays;
* a ROOT forwarder is the resolver the scanning host already used before the
  scan (its own network's DNS), for every name outside the assessed domains. It
  is not an asset of the engagement, so an allow-list does not remove it; it is
  dropped only when a deny entry names it.

When every DNS server of a domain is excluded the domain cannot be resolved,
and that is said once, up front, instead of surfacing later as a string of
unexplained lookup failures.
"""

from __future__ import annotations

from typing import Any, Mapping

from adscan_core import telemetry
from adscan_core.rich_output import print_error, print_exception
from adscan_internal.rich_output import mark_sensitive

_SURFACE = "dns_forwarder"


def forwarders_in_engagement_scope(
    shell: Any,
    *,
    domain_forwarders: Mapping[str, list[str]],
    root_forwarders: list[str],
) -> tuple[dict[str, list[str]], list[str]]:
    """Return the forwarder configuration with every excluded upstream removed.

    Args:
        shell: The session shell (carries the engagement scope).
        domain_forwarders: Domain -> upstream DNS server IPs.
        root_forwarders: Upstream DNS servers for every other name.

    Returns:
        ``(domain_forwarders, root_forwarders)`` holding in-scope upstreams
        only. Without an asset scope both are returned as given. A domain whose
        upstreams are all excluded keeps no forward zone.

    Fails closed: when the scope cannot be consulted, no domain forwarder is
    written (the caller's own verification then reports that the domain does
    not resolve), rather than forwarding to a server that may be excluded.
    """
    domains = {str(name): list(ips or []) for name, ips in (domain_forwarders or {}).items()}
    roots = list(root_forwarders or [])
    try:
        from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
            ASSET_REASON_DENIED,
            Contact,
            asset_scope_recorded,
            host_scope_verdict,
            partition_targets_in_scope,
            require_host_in_scope,
        )

        if not asset_scope_recorded(shell):
            return domains, roots
        kept_domains: dict[str, list[str]] = {}
        for domain, upstreams in domains.items():
            allowed = list(
                partition_targets_in_scope(
                    shell,
                    upstreams,
                    contact=Contact("dns"),
                    surface=_SURFACE,
                    what="DNS forwarding",
                    domain=domain,
                ).allowed
            )
            if allowed:
                kept_domains[domain] = allowed
            elif upstreams:
                print_error(
                    f"Every DNS server of {mark_sensitive(domain, 'domain')} is "
                    "excluded from the engagement scope, so its names cannot be "
                    "resolved. Name a DNS server inside the scope (--dns-server)."
                )
        kept_roots: list[str] = []
        for upstream in roots:
            verdict = host_scope_verdict(
                shell, host=upstream, contact=Contact("dns")
            )
            if not verdict.allowed and verdict.reason == ASSET_REASON_DENIED:
                # Recorded and announced by the SSOT (a handful of servers at most).
                require_host_in_scope(
                    shell,
                    host=upstream,
                    contact=Contact("dns"),
                    surface=_SURFACE,
                    what="DNS forwarding",
                )
                continue
            kept_roots.append(upstream)
        return kept_domains, kept_roots
    except Exception as exc:  # noqa: BLE001 - an unknown verdict forwards to no AD server
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(
            "The engagement scope could not be checked for the DNS servers, so no "
            "domain DNS forwarding was configured."
        )
        return {}, roots


__all__ = ("forwarders_in_engagement_scope",)
