"""The TDS client ADscan opens: impacket's, with its reply held in bounded memory.

impacket's TDS client reads a whole reply into one buffer and then parses it one
token at a time. Every parsed token keeps a reference to the buffer it was parsed
from (``Structure.rawData``), and that buffer is a fresh copy of everything that
was still unparsed. A reply of N rows therefore holds N copies of its own
remainder: memory grows with the square of the row count. Measured on impacket
0.13.1: 1,000 rows of 400 bytes hold 200 MB, 2,000 hold 800 MB, and the listing
of one real drive (hundreds of thousands of rows) cannot complete on any
machine. A file read back through ``xp_cmdshell`` in base64 rows has the same
shape.

This module does not fork or patch impacket. It subclasses the client in two
places where impacket calls a method of its own:

* ``parseRow``: once impacket has read a row's values, the row token drops its
  reference to the remaining reply. Nothing reads it afterwards (the values are
  already in ``rows``), and memory becomes linear in the reply size.
* ``socketRecv``: the bytes of one reply are counted, and a reply past
  :data:`MAX_REPLY_BYTES` is refused before it is buffered whole. A query that
  can return that much is a defect in the caller, which must bound what it asks
  for (see ``WindowsFileMappingService.generate_bounded_file_map``).

The parse still copies the remainder once per token, so its TIME stays quadratic
in the row count. Callers keep their replies small for that reason; this client
is the guarantee that a reply which is not small costs time, not the process.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

#: The largest reply one query may return, in bytes received. Far above every
#: reply ADscan asks for (a bounded listing page is about 0.25 MB on the wire, a
#: 10 MB document read back in base64 rows about 30 MB), and low enough that the
#: buffered reply and its parse stay within a few hundred megabytes.
MAX_REPLY_BYTES = 256 * 1024 * 1024


class MSSQLReplyTooLargeError(RuntimeError):
    """One MSSQL reply passed :data:`MAX_REPLY_BYTES` and was refused."""

    def __init__(self, limit: int) -> None:
        super().__init__(
            f"The MSSQL reply passed {limit // (1024 * 1024)} MB and was refused. "
            "The query must be narrowed so that it returns less."
        )
        self.limit = limit


@lru_cache(maxsize=1)
def _bounded_client_class() -> type:
    """Build the subclass once (impacket is imported on first use)."""
    from impacket import tds  # noqa: PLC0415

    class BoundedMSSQL(tds.MSSQL):
        """impacket's client with a linear-memory row parse and a reply ceiling."""

        adscan_max_reply_bytes: int = MAX_REPLY_BYTES
        _adscan_reply_bytes: int = 0

        def sendTDS(self, packetType, data, packetID=1):  # noqa: N802,N803 - impacket's names
            # A request starts a new reply: the count restarts with it.
            self._adscan_reply_bytes = 0
            return super().sendTDS(packetType, data, packetID)

        def socketRecv(self, bufsize):  # noqa: N802 - impacket's name
            data = super().socketRecv(bufsize)
            self._adscan_reply_bytes += len(data)
            if self._adscan_reply_bytes > self.adscan_max_reply_bytes:
                raise MSSQLReplyTooLargeError(self.adscan_max_reply_bytes)
            return data

        def parseRow(self, token, tuplemode=False):  # noqa: N802 - impacket's name
            consumed = super().parseRow(token, tuplemode)
            # The values are in ``self.rows``. The token's ``rawData`` is the
            # whole reply from this row to its end: dropping it is what keeps
            # the parse from holding one copy of the remainder per row.
            token.rawData = None
            return consumed

    return BoundedMSSQL


def bounded_mssql_client(host: str, port: int, remote_name: str) -> Any:
    """Open ADscan's TDS client for ``host`` (not yet connected).

    Args:
        host: The address to connect to.
        port: The TDS port.
        remote_name: The name the Kerberos service ticket is requested for.
    """
    return _bounded_client_class()(host, port=port, remoteName=remote_name)


__all__ = ("MAX_REPLY_BYTES", "MSSQLReplyTooLargeError", "bounded_mssql_client")
