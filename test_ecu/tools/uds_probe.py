#!/usr/bin/env python3
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
One-shot DoIP client: connect, activate routing, send UDS requests, print replies.

    python3 tools/uds_probe.py --host ::1 --uds "22 F1 90"
    python3 tools/uds_probe.py --host ::1 --uds "10 03" --uds "22 01 00"

Requests run in order on one connection, so session and security state carries
between them.  ResponsePending (7F xx 78) frames are printed and then waited
through, exactly as a real tester would.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
from typing import List, Optional, Tuple

PT_ROUTING_ACT_REQUEST     = 0x0005
PT_ROUTING_ACT_RESPONSE    = 0x0006
PT_DIAGNOSTIC_MESSAGE      = 0x8001
PT_DIAGNOSTIC_POSITIVE_ACK = 0x8002
PT_DIAGNOSTIC_NEGATIVE_ACK = 0x8003

PT_NAMES = {
    0x0000: "Header NACK",
    PT_ROUTING_ACT_RESPONSE:    "Routing Activation Response",
    0x0007:                     "Alive Check Request",
    PT_DIAGNOSTIC_MESSAGE:      "Diagnostic Message",
    PT_DIAGNOSTIC_POSITIVE_ACK: "Diagnostic ACK",
    PT_DIAGNOSTIC_NEGATIVE_ACK: "Diagnostic NACK",
}


def build(payload_type: int, payload: bytes) -> bytes:
    return struct.pack("!BBHI", 0x02, 0xFD, payload_type, len(payload)) + payload


def recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks = b""
    while len(chunks) < count:
        block = sock.recv(count - len(chunks))
        if not block:
            raise ConnectionError("peer closed the connection")
        chunks += block
    return chunks


def read_frame(sock: socket.socket) -> Tuple[int, bytes]:
    header = recv_exact(sock, 8)
    length = struct.unpack("!I", header[4:8])[0]
    return struct.unpack("!H", header[2:4])[0], recv_exact(sock, length)


def hexs(data: bytes) -> str:
    return data.hex(" ").upper() if data else "(empty)"


def activate(sock: socket.socket, tester: int) -> bool:
    sock.sendall(build(PT_ROUTING_ACT_REQUEST,
                       struct.pack("!H", tester) + b"\x00" + b"\x00\x00\x00\x00"))
    ptype, payload = read_frame(sock)
    if ptype != PT_ROUTING_ACT_RESPONSE or len(payload) < 5:
        print("!! routing activation failed: %s %s"
              % (PT_NAMES.get(ptype, hex(ptype)), hexs(payload)))
        return False
    code = payload[4]
    print("routing activation -> 0x%02X (%s)"
          % (code, "success" if code == 0x10 else "denied"))
    return code == 0x10


def send_uds(sock: socket.socket, tester: int, target: int, uds: bytes,
             timeout: float) -> Optional[bytes]:
    print("\n-> %s" % hexs(uds))
    sock.sendall(build(PT_DIAGNOSTIC_MESSAGE,
                       struct.pack("!HH", tester, target) + uds))
    sock.settimeout(timeout)
    while True:
        try:
            ptype, payload = read_frame(sock)
        except socket.timeout:
            print("<- (no response within %.1fs)" % timeout)
            return None

        if ptype == PT_DIAGNOSTIC_POSITIVE_ACK:
            print("   ack 0x8002")
            continue
        if ptype == PT_DIAGNOSTIC_NEGATIVE_ACK:
            print("<- NACK code 0x%02X" % (payload[4] if len(payload) > 4 else 0xFF))
            return None
        if ptype != PT_DIAGNOSTIC_MESSAGE:
            print("   %s %s" % (PT_NAMES.get(ptype, hex(ptype)), hexs(payload)))
            continue

        response = payload[4:]
        if len(response) >= 3 and response[0] == 0x7F and response[2] == 0x78:
            print("   pending 7F %02X 78" % response[1])
            continue
        print("<- %s" % hexs(response))
        return response


def parse_hex(text: str) -> bytes:
    cleaned = text.replace("0x", "").replace(",", " ").replace("_", " ")
    try:
        return bytes.fromhex(cleaned.replace(" ", ""))
    except ValueError:
        raise SystemExit("not a hex byte string: %r" % text)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="One-shot DoIP/UDS probe")
    parser.add_argument("--host", default="::1")
    parser.add_argument("--port", type=int, default=13400)
    parser.add_argument("--tester", default="0x0E00", help="tester logical address")
    parser.add_argument("--target", default="0x0002", help="ECU logical address")
    parser.add_argument("--timeout", type=float, default=6.0)
    parser.add_argument("--uds", action="append", default=[], metavar="HEX",
                        help='UDS request, e.g. "22 F1 90"; repeatable')
    args = parser.parse_args(argv)

    if not args.uds:
        parser.error("give at least one --uds request")

    tester = int(args.tester, 0)
    target = int(args.target, 0)

    info = socket.getaddrinfo(args.host, args.port, socket.AF_INET6, socket.SOCK_STREAM)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.settimeout(args.timeout)
    try:
        sock.connect(info[0][4])
    except OSError as exc:
        print("cannot connect to [%s]:%d — %s" % (args.host, args.port, exc))
        return 1

    try:
        if not activate(sock, tester):
            return 1
        for request in args.uds:
            send_uds(sock, tester, target, parse_hex(request), args.timeout)
    except (ConnectionError, OSError) as exc:
        print("\nconnection error: %s" % exc)
        return 1
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
