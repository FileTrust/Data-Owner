# do_map_tiles.py — make the keeper map usable on a network with dead IPv6.
#
# The map draws nothing and reports nothing on such a network, which is the
# worst way for it to fail. The tile host publishes both an A and an AAAA
# record, Python tries the AAAA first, and that connection is not refused --
# it hangs until the kernel gives up. Measured here: 15 to 30 seconds for one
# tile, thirteen tiles for one screen, and the widget has no timeout and no
# error path, so the window simply stays blank.
#
# Nothing about the tile provider fixes it: every provider on a dual-stack
# host behaves the same way, and swapping between them only changes which one
# hangs. So the fix is to stop trying IPv6, and only on a machine where IPv6
# has been shown not to work -- a working IPv6 network is left alone.

from __future__ import annotations

import socket

# The tile host itself, so the probe tests the route the tiles will take
# rather than IPv6 in the abstract.
PROBE_HOST = "tile.openstreetmap.org"
PROBE_PORT = 443
PROBE_TIMEOUT_SECONDS = 1.5

_applied: bool | None = None


def ipv6_can_reach(
    host: str = PROBE_HOST,
    port: int = PROBE_PORT,
    timeout: float = PROBE_TIMEOUT_SECONDS,
) -> bool:
    """Can this machine actually open an IPv6 connection to *host*?

    A dead IPv6 route answers neither way, so the question is only ever
    answered by a short timeout -- never by an error.
    """
    if not socket.has_ipv6:
        return False
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        return False
    for family, socktype, proto, _canon, address in infos:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        try:
            sock.connect(address)
            return True
        except OSError:
            continue
        finally:
            sock.close()
    return False


def prefer_ipv4_if_ipv6_is_dead() -> bool:
    """Ask urllib3 for IPv4 only when IPv6 has been shown not to work.

    Returns whether the preference was applied. Decided once per run: the
    probe costs a second and the answer does not change while the app is open.

    The switch is urllib3-wide rather than map-only, because urllib3 offers no
    per-request address family. That is acceptable precisely because it is
    conditional: it is applied only on a machine where IPv6 connections do not
    complete, and on such a machine every other connection is better off on
    IPv4 too.
    """
    global _applied
    if _applied is not None:
        return _applied
    try:
        import urllib3.util.connection as urllib3_connection
    except Exception:
        _applied = False
        return _applied
    if ipv6_can_reach():
        _applied = False
        return _applied
    urllib3_connection.allowed_gai_family = lambda: socket.AF_INET
    _applied = True
    return _applied
