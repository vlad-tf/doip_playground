# Copyright 2026 Vladislav Vostrykh, Technica Engineering GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""
Small cross-platform socket helpers shared by the TCP listener and the UDP
announcer.

These exist because Windows differs from Linux in ways that make a socket
setup that "just works" on Linux silently misbehave there: interface names
are not the ``ethN`` strings ``if_nametoindex`` expects, and a UDP socket can
be killed by an ICMP port-unreachable. Keeping the workarounds here means
``server.py`` and ``udp.py`` cannot drift apart.
"""

from __future__ import annotations

import logging
import socket
import sys

logger = logging.getLogger("virtecu.netutil")

#: SIO_UDP_CONNRESET from <mstcpip.h> (_WSAIOW(IOC_VENDOR, 12)). Python's
#: ``socket.ioctl`` only accepts a fixed set of commands and rejects this one,
#: so it is issued through WSAIoctl directly.
_SIO_UDP_CONNRESET = 0x9800000C


def resolve_if_index(interface: str, what: str = "interface") -> int:
    """Resolve ``listen.interface`` to an interface index; 0 means "any".

    A bare number is taken as the index itself. On Windows the ifIndex shown
    by ``Get-NetIPInterface`` is stable, whereas the friendly name
    ``if_nametoindex`` wants ("Ethernet 2") is awkward to type and localised.
    A name that fails to resolve logs a warning and yields 0, matching the
    previous behaviour of both call sites.
    """
    if not interface:
        return 0
    if interface.isdigit():
        index = int(interface)
        if index == 0:
            logger.warning("%s: interface index 0 means 'any interface'", what)
        return index
    try:
        return socket.if_nametoindex(interface)
    except OSError as exc:
        logger.warning("%s: cannot resolve interface %r: %s (using 0)",
                       what, interface, exc)
        return 0


def _disable_udp_connreset(fileno: int) -> None:
    """Issue WSAIoctl(SIO_UDP_CONNRESET, FALSE) on a Windows socket handle."""
    import ctypes
    from ctypes import wintypes

    ws2_32 = ctypes.WinDLL("ws2_32", use_last_error=True)  # type: ignore[attr-defined]
    wsa_ioctl = ws2_32.WSAIoctl
    # Explicit prototypes: SOCKET is pointer-sized, and without argtypes a
    # mismatch would surface as ctypes.ArgumentError instead of a WinError.
    wsa_ioctl.argtypes = [
        ctypes.c_size_t, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, ctypes.c_void_p,
    ]
    wsa_ioctl.restype = ctypes.c_int

    flag = wintypes.DWORD(0)
    returned = wintypes.DWORD(0)
    rc = wsa_ioctl(fileno, _SIO_UDP_CONNRESET,
                   ctypes.byref(flag), ctypes.sizeof(flag),
                   None, 0, ctypes.byref(returned), None, None)
    if rc != 0:
        raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]


def harden_udp_socket(sock: socket.socket) -> None:
    """Stop an ICMP port-unreachable from breaking a UDP socket on Windows.

    After a ``sendto`` to a port nobody listens on (a tester that has already
    gone away), Windows fails the *next* ``recvfrom`` on the same socket with
    WSAECONNRESET, which can tear down asyncio's datagram transport. Turning
    that behaviour off makes Windows behave like Linux. No-op elsewhere.
    """
    if sys.platform != "win32":
        return
    try:
        _disable_udp_connreset(sock.fileno())
    except Exception as exc:  # best effort: never abort the announcer over this
        logger.warning("UDP: cannot disable SIO_UDP_CONNRESET: %s", exc)
