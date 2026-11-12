"""PRO licence: signed per-installation licences issued by the ADscan licence server.

Design: ``docs/superpowers/specs/2026-11-11-pro-licence-server-design.md``.

A person (free trial) or an engine installation (revenue-share partner, paid
PRO) activates ONCE against the licence server and receives a licence signed
with the server's key, in the same format 2 envelope as the Enterprise licence
(:mod:`adscan_core.enterprise_license`). After that the engine checks it
locally; it contacts the server only when it has queued work (a new domain to
register, a band report, a due renewal), directly or through a partner's
platform (relay mode). An offline engagement licence covers a client network
with no route at all.

Modules:

* :mod:`.model` — the licence document and its validation.
* :mod:`.installation` — the installation key pair that signs every request.
* :mod:`.domain_code` — the per-partner HMAC code of a forest.
* :mod:`.documents` — requests the installation signs, answers the server signs.
* :mod:`.state` — the local store (licence, pending requests, register).
* :mod:`.evaluation` — licence status and domain admission.
* :mod:`.client` — direct transport, relay export/import, activation.

Dependency-light: the standard library and ``cryptography``. Imported by the
host launcher (``adscan license``), the engine and the licence server.
"""
