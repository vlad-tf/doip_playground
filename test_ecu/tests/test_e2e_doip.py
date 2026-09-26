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

"""End to end over a real IPv6 socket: DoIP framing, routing activation, UDS."""

from __future__ import annotations

import asyncio
import socket
import struct

import pytest

from conftest import ECU_ADDR, TESTER_ADDR, make_ecu, merge, run
from testecu import Plugin, on_service
from testecu.doip import (
    PT_ALIVE_CHECK_REQUEST,
    PT_ALIVE_CHECK_RESPONSE,
    PT_DIAGNOSTIC_MESSAGE,
    PT_DIAGNOSTIC_NEGATIVE_ACK,
    PT_DIAGNOSTIC_POSITIVE_ACK,
    PT_ENTITY_STATUS_REQUEST,
    PT_ENTITY_STATUS_RESPONSE,
    PT_HEADER_NACK,
    PT_POWER_MODE_REQUEST,
    PT_ROUTING_ACT_REQUEST,
    PT_ROUTING_ACT_RESPONSE,
    build_frame,
    read_frame,
)
from testecu.server import TestEcuServer

pytestmark = pytest.mark.skipif(not socket.has_ipv6, reason="no IPv6 on this host")

CONFIG = {
    "listen": {"host": "::1", "port": 0, "interface": ""},
    "data_identifiers": {
        0xF190: {"type": "ascii", "length": 17, "value": "1HGBH41JXMN109186"},
    },
}


class Client:
    """Raw-bytes DoIP client, in the style of doip_edgenode/tests/mock_ecu.py."""

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer

    @classmethod
    async def connect(cls, port, host="::1"):
        reader, writer = await asyncio.open_connection(host, port)
        return cls(reader, writer)

    async def send(self, payload_type, payload, version=0x02):
        self.writer.write(build_frame(payload_type, payload, version=version))
        await self.writer.drain()

    async def recv(self, timeout=2.0):
        raw = await asyncio.wait_for(read_frame(self.reader), timeout=timeout)
        return struct.unpack("!H", raw[2:4])[0], raw[8:]

    async def recv_version(self, timeout=2.0):
        """Like ``recv`` but also returns the response frame's version byte
        (architecture roadmap P5)."""
        raw = await asyncio.wait_for(read_frame(self.reader), timeout=timeout)
        return raw[0], struct.unpack("!H", raw[2:4])[0], raw[8:]

    async def activate(self, tester=TESTER_ADDR, version=0x02):
        await self.send(PT_ROUTING_ACT_REQUEST,
                        struct.pack("!H", tester) + b"\x00" + b"\x00\x00\x00\x00",
                        version=version)
        return await self.recv()

    async def diagnostic(self, uds, target=ECU_ADDR, tester=TESTER_ADDR, version=0x02):
        await self.send(PT_DIAGNOSTIC_MESSAGE,
                        struct.pack("!HH", tester, target) + uds,
                        version=version)
        return await self.recv()

    async def send_raw_header(self, payload_type, declared_len, real_bytes=b""):
        """
        Write a generic header whose length field may not match ``real_bytes``.

        Used to simulate a peer that lies about the payload length — see
        ``TestFrameLengthCap`` below.
        """
        hdr = struct.pack("!BBHI", 0x02, 0xFD, payload_type, declared_len)
        self.writer.write(hdr + real_bytes)
        await self.writer.drain()

    async def close(self):
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except Exception:
            pass


async def with_server(scenario, extra=None, plugins=None):
    """Start a server on an ephemeral ::1 port, run ``scenario(port)``, tear down."""
    ecu = make_ecu(extra or CONFIG, plugins if plugins is not None else [])
    server_wrapper = TestEcuServer(ecu)
    server = await server_wrapper.start(serve_forever=False)
    port = server_wrapper.port
    try:
        return await scenario(port)
    finally:
        server.close()
        try:
            await server.wait_closed()
        except Exception:
            pass
        await server_wrapper.stop()


async def with_server_ipv4(scenario, plugins=None):
    """Start a server on an ephemeral 127.0.0.1 port over IPv4, run ``scenario(port)``."""
    # UDP is disabled so the announcer doesn't try to broadcast on 255.255.255.255
    # during the test — this test targets the v4 TCP listener only.
    extra = merge(CONFIG, {"listen": {"host": "127.0.0.1", "family": "ipv4"},
                           "udp": {"enabled": False}})
    ecu = make_ecu(extra, plugins if plugins is not None else [])
    server_wrapper = TestEcuServer(ecu)
    server = await server_wrapper.start(serve_forever=False)
    port = server_wrapper.port
    try:
        return await scenario(port)
    finally:
        server.close()
        try:
            await server.wait_closed()
        except Exception:
            pass
        await server_wrapper.stop()


class TestIPv4:
    def test_activation_then_read_vin_over_ipv4(self):
        async def scenario(port):
            client = await Client.connect(port, host="127.0.0.1")
            ptype, payload = await client.activate()
            assert ptype == PT_ROUTING_ACT_RESPONSE
            assert payload[4] == 0x10

            ptype, payload = await client.diagnostic(b"\x22\xF1\x90")
            assert ptype == PT_DIAGNOSTIC_POSITIVE_ACK
            ptype, payload = await client.recv()
            assert ptype == PT_DIAGNOSTIC_MESSAGE
            assert payload[4:] == b"\x62\xF1\x90" + b"1HGBH41JXMN109186"
            await client.close()
            return True

        assert run(with_server_ipv4(scenario))


class TestLifecycle:
    def test_activation_then_read_vin(self):
        async def scenario(port):
            client = await Client.connect(port)
            ptype, payload = await client.activate()
            assert ptype == PT_ROUTING_ACT_RESPONSE
            assert payload[4] == 0x10                       # success
            assert struct.unpack("!H", payload[0:2])[0] == TESTER_ADDR
            assert struct.unpack("!H", payload[2:4])[0] == ECU_ADDR

            ptype, payload = await client.diagnostic(b"\x22\xF1\x90")
            assert ptype == PT_DIAGNOSTIC_POSITIVE_ACK
            assert payload[4] == 0x00
            # ISO 13400-2 Table 28 / DoIP-066: the ACK's SA is the ECU that
            # sends it, TA is the requesting tester — swapped vs the request.
            assert struct.unpack("!H", payload[0:2])[0] == ECU_ADDR
            assert struct.unpack("!H", payload[2:4])[0] == TESTER_ADDR

            ptype, payload = await client.recv()
            assert ptype == PT_DIAGNOSTIC_MESSAGE
            assert struct.unpack("!H", payload[0:2])[0] == ECU_ADDR
            assert struct.unpack("!H", payload[2:4])[0] == TESTER_ADDR
            assert payload[4:] == b"\x62\xF1\x90" + b"1HGBH41JXMN109186"
            await client.close()
            return True

        assert run(with_server(scenario))

    def test_diagnostic_before_activation_is_nacked_and_socket_closed(self):
        async def scenario(port):
            client = await Client.connect(port)

            # A never-activated socket has no registered SA, so any Diagnostic
            # Message on it is the same DoIP-070 violation as a spoofed SA:
            # NACK 0x02 and close the TCP_DATA socket.
            await client.send(PT_DIAGNOSTIC_MESSAGE,
                              struct.pack("!HH", TESTER_ADDR, ECU_ADDR) + b"\x3E\x00")
            ptype, payload = await client.recv(timeout=1.0)
            assert ptype == PT_DIAGNOSTIC_NEGATIVE_ACK
            assert payload[4] == 0x02

            with pytest.raises((asyncio.IncompleteReadError, ConnectionResetError,
                                asyncio.TimeoutError)):
                await client.recv(timeout=1.0)
            await client.close()
            return True

        assert run(with_server(scenario))

    def test_unknown_target_address_is_nacked(self):
        async def scenario(port):
            client = await Client.connect(port)
            await client.activate()
            ptype, payload = await client.diagnostic(b"\x3E\x00", target=0x1234)
            assert ptype == PT_DIAGNOSTIC_NEGATIVE_ACK
            # ISO 13400-2 Table 26: 0x03 = unknown target address (0x00/0x01
            # are reserved by ISO 13400 and must never appear on the wire).
            assert payload[4] == 0x03
            # ISO 13400-2 Table 28 / DoIP-066: the NACK's SA is always this
            # ECU's own address — never 0x1234, the invalid target the
            # requester sent, which it doesn't own.
            assert struct.unpack("!H", payload[0:2])[0] == ECU_ADDR
            assert struct.unpack("!H", payload[2:4])[0] == TESTER_ADDR
            await client.close()
            return True

        assert run(with_server(scenario))

    def test_functional_diagnostic_ack_uses_our_own_address(self):
        # ISO 13400-2 Table 28 / DoIP-066: a functional (broadcast) request's
        # ``tgt`` is the functional address, not this ECU's own — the ACK's
        # SA must still be this ECU's own address, not the functional one.
        async def scenario(port):
            client = await Client.connect(port)
            await client.activate()
            ptype, payload = await client.diagnostic(b"\x3E\x00", target=0x1FFF)
            assert ptype == PT_DIAGNOSTIC_POSITIVE_ACK
            assert struct.unpack("!H", payload[0:2])[0] == ECU_ADDR
            assert struct.unpack("!H", payload[2:4])[0] == TESTER_ADDR
            await client.close()
            return True

        assert run(with_server(scenario))

    def test_diagnostic_from_unregistered_sa_is_nacked_and_socket_closed(self):
        async def scenario(port):
            client = await Client.connect(port)
            await client.activate()

            # A diagnostic message whose SA was not the one that activated
            # routing on this socket (ISO 13400-2 DoIP-070 / Table 31 0x02) must
            # be NACKed 0x02 and the TCP_DATA socket closed.
            ptype, payload = await client.diagnostic(b"\x3E\x00", tester=TESTER_ADDR + 1)
            assert ptype == PT_DIAGNOSTIC_NEGATIVE_ACK
            assert payload[4] == 0x02

            # The socket must be closed after the NACK; a further read then
            # hits EOF (or a reset), never another DoIP frame.
            with pytest.raises((asyncio.IncompleteReadError, ConnectionResetError,
                                asyncio.TimeoutError)):
                await client.recv(timeout=1.0)
            return True

        assert run(with_server(scenario))

    def test_diagnostic_from_registered_sa_still_works(self):
        async def scenario(port):
            client = await Client.connect(port)
            await client.activate()
            ptype, payload = await client.diagnostic(b"\x3E\x00")
            assert ptype == PT_DIAGNOSTIC_POSITIVE_ACK
            await client.close()
            return True

        assert run(with_server(scenario))

    def test_routing_activation_from_out_of_range_sa_is_denied(self):
        async def scenario(port):
            client = await Client.connect(port)
            # 0x0BAD falls outside the tester SA range (0x0E00-0x0FFF, ISO
            # 13400-2 Table 13) — must be denied, not accepted.
            ptype, payload = await client.activate(tester=0x0BAD)
            assert ptype == PT_ROUTING_ACT_RESPONSE
            assert payload[4] == 0x00                        # unknown source address
            # ISO 13400-2 Table 25: a denial (any code but 0x10/0x11) closes
            # the socket — the client is expected to reconnect, not retry here.
            with pytest.raises((asyncio.IncompleteReadError, ConnectionResetError,
                                asyncio.TimeoutError)):
                await client.recv(timeout=1.0)
            await client.close()
            return True

        assert run(with_server(scenario))

    def test_truncated_routing_activation_request_gets_generic_nack(self):
        async def scenario(port):
            client = await Client.connect(port)
            # 3-byte payload: SA(2) + activation_type(1), missing the 4-byte
            # reserved field required by ISO 13400-2 Table 15 (7 bytes total).
            await client.send(PT_ROUTING_ACT_REQUEST,
                              struct.pack("!H", TESTER_ADDR) + b"\x00")
            ptype, payload = await client.recv()
            assert ptype == PT_HEADER_NACK
            assert payload == b"\x04"                        # invalid payload length
            await client.close()
            return True

        assert run(with_server(scenario))

    def test_truncated_diagnostic_message_gets_generic_nack(self):
        async def scenario(port):
            client = await Client.connect(port)
            await client.activate()
            # 4-byte payload: SA(2) + TA(2), no UDS bytes at all -- below the
            # 5-byte minimum (SA+TA+ >=1 UDS byte). Must be NACKed, not
            # silently dropped (which left the tester with nothing to see
            # but its own P2 timeout).
            await client.send(PT_DIAGNOSTIC_MESSAGE,
                              struct.pack("!HH", TESTER_ADDR, ECU_ADDR))
            ptype, payload = await client.recv()
            assert ptype == PT_HEADER_NACK
            assert payload == b"\x04"    # invalid payload length
            # Not a spoofing/addressing violation, so the socket stays open.
            ptype, payload = await client.diagnostic(b"\x3E\x00")
            assert ptype == PT_DIAGNOSTIC_POSITIVE_ACK
            await client.close()
            return True

        assert run(with_server(scenario))

    def test_wrong_protocol_version_gets_a_header_nack(self):
        async def scenario(port):
            client = await Client.connect(port)
            client.writer.write(struct.pack("!BBHI", 0x09, 0x00, 0x0005, 0))
            await client.writer.drain()
            ptype, payload = await client.recv()
            assert ptype == PT_HEADER_NACK
            assert payload == b"\x00"
            await client.close()
            return True

        assert run(with_server(scenario))

    def test_unknown_payload_type_gets_a_header_nack(self):
        async def scenario(port):
            client = await Client.connect(port)
            await client.send(0x00FF, b"")
            ptype, payload = await client.recv()
            assert ptype == PT_HEADER_NACK
            assert payload == b"\x01"
            await client.close()
            return True

        assert run(with_server(scenario))


class TestRoutingActivationValidation:
    def test_rebind_to_different_sa_is_denied(self):
        async def scenario(port):
            client = await Client.connect(port)
            ptype, payload = await client.activate(tester=TESTER_ADDR)
            assert ptype == PT_ROUTING_ACT_RESPONSE
            assert payload[4] == 0x10

            # ISO 13400-2 Table 48 code 0x02: a second Routing Activation for a
            # *different* SA on the same socket must be denied, not re-bound.
            ptype, payload = await client.activate(tester=TESTER_ADDR + 1)
            assert ptype == PT_ROUTING_ACT_RESPONSE
            assert payload[4] == 0x02
            # A re-bind denial closes the socket too (Table 25) — the tester
            # is expected to reconnect with the correct SA, not keep talking.
            with pytest.raises((asyncio.IncompleteReadError, ConnectionResetError,
                                asyncio.TimeoutError)):
                await client.recv(timeout=1.0)
            await client.close()
            return True

        assert run(with_server(scenario))

    def test_rebind_to_same_sa_stays_active(self):
        async def scenario(port):
            client = await Client.connect(port)
            ptype, payload = await client.activate(tester=TESTER_ADDR)
            assert payload[4] == 0x10

            # A repeat Request for the same already-active SA just re-confirms
            # success (0x10) — idempotent, not a protocol violation.
            ptype, payload = await client.activate(tester=TESTER_ADDR)
            assert ptype == PT_ROUTING_ACT_RESPONSE
            assert payload[4] == 0x10
            await client.close()
            return True

        assert run(with_server(scenario))

    def test_unsupported_activation_type_is_denied(self):
        async def scenario(port):
            client = await Client.connect(port)
            # ISO 13400-2 Table 48 code 0x06: only activation types 0x00/0x01
            # are supported — 0x02 must be denied, not silently accepted.
            await client.send(PT_ROUTING_ACT_REQUEST,
                              struct.pack("!H", TESTER_ADDR) + b"\x02" + b"\x00\x00\x00\x00")
            ptype, payload = await client.recv()
            assert ptype == PT_ROUTING_ACT_RESPONSE
            assert payload[4] == 0x06
            # Unsupported-activation-type denial closes the socket too.
            with pytest.raises((asyncio.IncompleteReadError, ConnectionResetError,
                                asyncio.TimeoutError)):
                await client.recv(timeout=1.0)
            await client.close()
            return True

        assert run(with_server(scenario))


class TestNodeServices:
    def test_entity_status_and_power_mode_are_rejected_over_tcp(self):
        # ISO 13400-2 classes both Entity Status (0x4001/0x4002) and Power
        # Mode Info (0x4003/0x4004) as UDP_DISCOVERY-only message types — a
        # TCP_DATA socket sending either gets Header NACK 0x01, the same as
        # any other payload type this socket doesn't accept. See
        # test_udp.py for the UDP side, which does answer both.
        async def scenario(port):
            client = await Client.connect(port)
            await client.send(PT_ENTITY_STATUS_REQUEST, b"")
            ptype, payload = await client.recv()
            assert ptype == PT_HEADER_NACK
            assert payload == b"\x01"

            await client.send(PT_POWER_MODE_REQUEST, b"")
            ptype, payload = await client.recv()
            assert ptype == PT_HEADER_NACK
            assert payload == b"\x01"
            await client.close()
            return True

        assert run(with_server(scenario))

    def test_alive_check_request_is_answered_with_our_address(self):
        async def scenario(port):
            client = await Client.connect(port)
            await client.send(0x0007, b"")
            ptype, payload = await client.recv()
            assert ptype == PT_ALIVE_CHECK_RESPONSE
            assert struct.unpack("!H", payload)[0] == ECU_ADDR
            await client.close()
            return True

        assert run(with_server(scenario))


class TestSourceAddressConflict:
    def test_a_dead_session_is_evicted_and_the_new_one_accepted(self):
        async def scenario(port):
            first = await Client.connect(port)
            ptype, payload = await first.activate()
            assert payload[4] == 0x10

            # The first client never answers the Alive Check probe, so the ECU
            # must time it out, evict it, and accept the second connection.
            second = await Client.connect(port)
            ptype, payload = await second.activate()
            assert ptype == PT_ROUTING_ACT_RESPONSE
            assert payload[4] == 0x10
            await first.close()
            await second.close()
            return True

        assert run(with_server(scenario))


class TestSessionStateSurvivesReconnect:
    """
    Architecture roadmap P9: UDS session state is keyed by tester SA in
    ``EcuCore``, not created fresh per socket -- a tester that drops TCP and
    reconnects within S3 finds the same session/security state a real ECU
    would still have.
    """

    #: 0xF186 is the built-in "active diagnostic session" DID (needs the
    #: ``dynamic`` declaration to reach the core's handling of it); 0xF1B0
    #: is a made-up DID gated on security level 1, unlockable via the
    #: standard seed/key exchange (seed 11223344 XOR key A5A5A5A5).
    CONFIG_SEC = {
        "listen": {"host": "::1", "port": 0, "interface": ""},
        "data_identifiers": {
            0xF186: {"type": "dynamic"},
            0xF1B0: {"type": "hex", "value": "AA", "read_security": 1},
        },
    }
    GOOD_KEY = bytes.fromhex("B4 87 96 E1".replace(" ", ""))

    async def _enter_extended_and_unlock(self, client):
        ptype, payload = await client.diagnostic(b"\x10\x03")
        assert ptype == PT_DIAGNOSTIC_POSITIVE_ACK
        ptype, payload = await client.recv()
        assert payload[4:6] == b"\x50\x03"

        ptype, payload = await client.diagnostic(b"\x27\x01")
        assert ptype == PT_DIAGNOSTIC_POSITIVE_ACK
        ptype, payload = await client.recv()
        assert payload[4] == 0x67   # positive response to 0x27 01 (seed)

        ptype, payload = await client.diagnostic(b"\x27\x02" + self.GOOD_KEY)
        assert ptype == PT_DIAGNOSTIC_POSITIVE_ACK
        ptype, payload = await client.recv()
        assert payload[4:6] == b"\x67\x02"   # positive response to 0x27 02 (key)

    def test_state_survives_a_reconnect_within_s3(self):
        async def scenario(port):
            first = await Client.connect(port)
            await first.activate()
            await self._enter_extended_and_unlock(first)
            await first.close()   # TCP drops -- deliberately, not ECUReset
            # Let the closed session's own cleanup (SessionRegistry.unregister)
            # finish server-side before reconnecting -- otherwise Routing
            # Activation for the same SA hits the §9.3 alive-probe path
            # (waits out ``alive_check_timeout_ms``, 500ms default), which
            # would dwarf the 200ms ``s3_server_ms`` this test relies on.
            await asyncio.sleep(0.05)

            # Reconnect promptly (well within the 200ms s3_server_ms test
            # default) and re-activate -- same tester SA, new socket.
            second = await Client.connect(port)
            ptype, payload = await second.activate()
            assert payload[4] == 0x10

            ptype, payload = await second.diagnostic(b"\x22\xF1\x86")
            assert ptype == PT_DIAGNOSTIC_POSITIVE_ACK
            ptype, payload = await second.recv()
            assert payload[4:] == b"\x62\xF1\x86\x03"   # still extended (0x03)

            ptype, payload = await second.diagnostic(b"\x22\xF1\xB0")
            assert ptype == PT_DIAGNOSTIC_POSITIVE_ACK
            ptype, payload = await second.recv()
            assert payload[4:] == b"\x62\xF1\xB0\xAA"   # still unlocked -- readable
            await second.close()
            return True

        assert run(with_server(scenario, self.CONFIG_SEC))

    def test_state_does_not_survive_past_s3(self):
        async def scenario(port):
            first = await Client.connect(port)
            await first.activate()
            await self._enter_extended_and_unlock(first)
            await first.close()

            # Wait past s3_server_ms (200ms default) before reconnecting.
            await asyncio.sleep(0.35)

            second = await Client.connect(port)
            ptype, payload = await second.activate()
            assert payload[4] == 0x10

            ptype, payload = await second.diagnostic(b"\x22\xF1\x86")
            ptype, payload = await second.recv()
            assert payload[4:] == b"\x62\xF1\x86\x01"   # back to default (0x01)

            ptype, payload = await second.diagnostic(b"\x22\xF1\xB0")
            ptype, payload = await second.recv()
            assert ptype == PT_DIAGNOSTIC_MESSAGE
            assert payload[4] == 0x7F and payload[6] == 0x33   # securityAccessDenied
            await second.close()
            return True

        assert run(with_server(scenario, self.CONFIG_SEC))

    def test_two_different_testers_have_independent_state(self):
        async def scenario(port):
            a = await Client.connect(port)
            await a.activate(tester=TESTER_ADDR)
            await self._enter_extended_and_unlock(a)
            await a.close()

            b = await Client.connect(port)
            await b.activate(tester=TESTER_ADDR + 1)
            ptype, payload = await b.diagnostic(b"\x22\xF1\x86", tester=TESTER_ADDR + 1)
            ptype, payload = await b.recv()
            # A different tester's fresh session is unaffected by A's state.
            assert payload[4:] == b"\x62\xF1\x86\x01"
            await b.close()
            return True

        assert run(with_server(scenario, self.CONFIG_SEC))

    def test_reset_drops_connection_closes_the_socket_and_forgets_state(self):
        config = {**self.CONFIG_SEC, "uds": {"reset_drops_connection": True}}

        async def scenario(port):
            client = await Client.connect(port)
            await client.activate()
            await self._enter_extended_and_unlock(client)

            ptype, payload = await client.diagnostic(b"\x11\x01")
            assert ptype == PT_DIAGNOSTIC_POSITIVE_ACK

            # The final "51 01" response and the abortive RST (SO_LINGER 0)
            # race on the wire -- a real vanishing ECU offers no stronger
            # guarantee either. Either the response arrives and the read
            # after it fails, or the RST wins outright; either way nothing
            # further can ever be read from this socket.
            try:
                ptype, payload = await client.recv(timeout=0.3)
                assert payload[4:] == b"\x51\x01"
            except (asyncio.IncompleteReadError, ConnectionResetError,
                    asyncio.TimeoutError):
                pass
            with pytest.raises((asyncio.IncompleteReadError, ConnectionResetError,
                                asyncio.TimeoutError)):
                await client.recv(timeout=0.3)
            await asyncio.sleep(0.05)   # let server-side cleanup finish

            # A fresh connection for the same tester finds default/locked state,
            # not whatever was unlocked before the reset.
            second = await Client.connect(port)
            await second.activate()
            ptype, payload = await second.diagnostic(b"\x22\xF1\x86")
            ptype, payload = await second.recv()
            assert payload[4:] == b"\x62\xF1\x86\x01"
            await second.close()
            return True

        assert run(with_server(scenario, config))


class TestConcurrencyLimit:
    """Architecture roadmap P3: ``doip.max_concurrent_sessions`` is enforced,
    not just advertised."""

    LIMIT_CONFIG = {"doip": {"max_concurrent_sessions": 2}}

    def test_a_tester_beyond_the_limit_is_denied_0x01_and_closed(self):
        async def scenario(port):
            clients = []
            for i in range(2):
                c = await Client.connect(port)
                ptype, payload = await c.activate(tester=TESTER_ADDR + i)
                assert ptype == PT_ROUTING_ACT_RESPONSE
                assert payload[4] == 0x10
                clients.append(c)

            # The 3rd distinct tester, with the limit already saturated at 2,
            # must be denied with 0x01 ("all sockets in use"), not accepted.
            third = await Client.connect(port)
            ptype, payload = await third.activate(tester=TESTER_ADDR + 2)
            assert ptype == PT_ROUTING_ACT_RESPONSE
            assert payload[4] == 0x01

            # Table 25: any non-success code closes the TCP_DATA socket; a
            # further read must fail rather than hang or return more data.
            with pytest.raises((asyncio.IncompleteReadError, ConnectionResetError,
                                asyncio.TimeoutError)):
                await third.recv(timeout=0.3)

            for c in clients:
                await c.close()
            await third.close()
            return True

        assert run(with_server(scenario, self.LIMIT_CONFIG))

    def test_an_idempotent_repeat_activation_is_never_denied_by_the_limit(self):
        async def scenario(port):
            clients = []
            for i in range(2):
                c = await Client.connect(port)
                ptype, payload = await c.activate(tester=TESTER_ADDR + i)
                assert payload[4] == 0x10
                clients.append(c)

            # Repeating activation for an already-registered SA on the same
            # socket must re-confirm success even though the registry is
            # already at the limit -- it does not add a new registration.
            ptype, payload = await clients[0].activate(tester=TESTER_ADDR)
            assert ptype == PT_ROUTING_ACT_RESPONSE
            assert payload[4] == 0x10

            for c in clients:
                await c.close()
            return True

        assert run(with_server(scenario, self.LIMIT_CONFIG))

    def test_server_wires_the_same_config_value_into_the_udp_announcer(self):
        """
        Entity Status is UDP-only (see ``TestNodeServices`` above), so this
        checks the wiring at the level that matters: ``TestEcuServer.start()``
        must feed ``run_announcer`` the *same* ``max_concurrent_sessions`` the
        Routing Activation check enforces, not the TCP listen backlog.
        ``test_udp.py`` already covers ``_entity_status_payload`` turning
        ``max_sockets`` into the wire byte; this closes the gap between that
        and the config value actually enforced above.
        """
        import unittest.mock as mock
        import testecu.server as server_module

        captured = {}
        real_run_announcer = server_module.run_announcer

        async def spy(config, **kwargs):
            captured.update(kwargs)
            raise asyncio.CancelledError()   # never actually bind/run

        async def scenario(port):
            await asyncio.sleep(0.05)   # let the scheduled announcer task run once
            return True

        # BASE_CONFIG disables UDP by default (see conftest.py) to keep other
        # e2e tests quiet -- re-enable it here since that is exactly the path
        # under test.
        config = {**self.LIMIT_CONFIG, "udp": {"enabled": True}}
        with mock.patch.object(server_module, "run_announcer", spy):
            assert run(with_server(scenario, config))

        assert captured.get("max_sockets") == 2

    def test_entity_status_max_sockets_matches_the_configured_limit_directly(self):
        """
        Same fact as above, exercised at the layer ``test_udp.py`` already
        drives (``_UDPProtocol`` against a fake transport), using the real
        config value instead of a hand-picked one -- belt and suspenders
        against the two ever drifting apart again.
        """
        from testecu.config import parse_config
        from testecu.udp import _UDPProtocol

        config = parse_config({
            "listen": {"host": "::1", "port": 0, "interface": ""},
            "doip": {"max_concurrent_sessions": 2},
        })

        class _FakeTransport:
            def sendto(self, data, addr):
                pass

        protocol = _UDPProtocol(config, if_index=0,
                                max_sockets=config.doip.max_concurrent_sessions)
        protocol.connection_made(_FakeTransport())
        payload = protocol._entity_status_payload()
        assert payload[1] == 2


class TestProtocolVersionEcho:
    """Architecture roadmap P5: every response is framed in the version of
    the request it answers, not always the entity's own default."""

    def test_a_0x03_request_gets_0x03_framed_responses_throughout(self):
        async def scenario(port):
            client = await Client.connect(port)
            await client.send(
                PT_ROUTING_ACT_REQUEST,
                struct.pack("!H", TESTER_ADDR) + b"\x00" + b"\x00\x00\x00\x00",
                version=0x03,
            )
            ver, ptype, payload = await client.recv_version()
            assert ver == 0x03
            assert ptype == PT_ROUTING_ACT_RESPONSE
            assert payload[4] == 0x10

            await client.send(PT_DIAGNOSTIC_MESSAGE,
                              struct.pack("!HH", TESTER_ADDR, ECU_ADDR) + b"\x22\xF1\x90",
                              version=0x03)
            ver, ptype, _ = await client.recv_version()
            assert ver == 0x03
            assert ptype == PT_DIAGNOSTIC_POSITIVE_ACK

            ver, ptype, payload = await client.recv_version()
            assert ver == 0x03
            assert ptype == PT_DIAGNOSTIC_MESSAGE
            assert payload[4:] == b"\x62\xF1\x90" + b"1HGBH41JXMN109186"

            await client.send(PT_ALIVE_CHECK_REQUEST, b"", version=0x03)
            ver, ptype, _ = await client.recv_version()
            assert ver == 0x03
            assert ptype == PT_ALIVE_CHECK_RESPONSE

            await client.close()
            return True

        assert run(with_server(scenario, CONFIG))

    def test_a_0x02_request_is_unaffected(self):
        async def scenario(port):
            client = await Client.connect(port)
            await client.send(
                PT_ROUTING_ACT_REQUEST,
                struct.pack("!H", TESTER_ADDR) + b"\x00" + b"\x00\x00\x00\x00",
                version=0x02,
            )
            ver, ptype, payload = await client.recv_version()
            assert ver == 0x02
            assert ptype == PT_ROUTING_ACT_RESPONSE
            assert payload[4] == 0x10
            await client.close()
            return True

        assert run(with_server(scenario, CONFIG))

    def test_version_is_not_sticky_across_a_connection(self):
        # A tester that mixes versions on one socket gets each answer framed
        # in the version it asked *that* time -- no "remembered" version.
        async def scenario(port):
            client = await Client.connect(port)
            await client.send(
                PT_ROUTING_ACT_REQUEST,
                struct.pack("!H", TESTER_ADDR) + b"\x00" + b"\x00\x00\x00\x00",
                version=0x03,
            )
            ver, _, _ = await client.recv_version()
            assert ver == 0x03

            await client.send(PT_ALIVE_CHECK_REQUEST, b"", version=0x02)
            ver, ptype, _ = await client.recv_version()
            assert ver == 0x02
            assert ptype == PT_ALIVE_CHECK_RESPONSE

            await client.close()
            return True

        assert run(with_server(scenario, CONFIG))

    def test_a_bad_header_nack_uses_the_entity_own_default_version(self):
        # There is no valid request version to echo when the header itself
        # is what's wrong -- the NACK must go out in the entity's own
        # default (doip.VER = 0x02), not the bogus/rejected version.
        async def scenario(port):
            client = await Client.connect(port)
            await client.send(PT_ALIVE_CHECK_REQUEST, b"", version=0x01)
            ver, ptype, payload = await client.recv_version()
            assert ver == 0x02
            assert ptype == PT_HEADER_NACK
            assert payload == b"\x00"
            return True

        assert run(with_server(scenario, CONFIG))

    def test_the_response_under_a_slow_handler_still_echoes_its_own_request(self):
        """
        Pump/worker split regression guard (architecture roadmap P5 x P1):
        the *worker*'s eventual response for a slow Diagnostic Message must
        echo the version *that* request arrived in, not whatever version a
        later frame -- answered by the pump while the worker is still busy --
        happens to use.
        """
        async def scenario(port):
            client = await PumpingClient.connect(port)
            await client.activate()

            # Kick off a slow request in version 0x03, but don't wait for its
            # final response yet.
            await client.send(PT_DIAGNOSTIC_MESSAGE,
                              struct.pack("!HH", TESTER_ADDR, ECU_ADDR) + b"\x22\xF1\x90",
                              version=0x03)
            ver, ptype = (await client.recv_version())[:2]
            assert ver == 0x03
            assert ptype == PT_DIAGNOSTIC_POSITIVE_ACK   # sent by the pump

            # While the slow handler is still running, answer an Alive Check
            # on the same socket in version 0x02.
            await client.send(PT_ALIVE_CHECK_REQUEST, b"", version=0x02)
            ver, ptype, _ = await client.recv_version()
            assert ver == 0x02
            assert ptype == PT_ALIVE_CHECK_RESPONSE

            # The slow handler's own response must still come back in 0x03 --
            # not 0x02, even though that was the most recently read frame's
            # version by the time the worker actually sends it.
            ver, ptype, payload = await client.recv_version(timeout=2.0)
            assert ver == 0x03
            assert ptype == PT_DIAGNOSTIC_MESSAGE
            assert payload[4:] == b"\x62\x01"
            await client.close()
            return True

        assert run(with_server(scenario, plugins=[TestPumpWorkerSplit._slow_plugin()]))


class TestSuppressionOverTheWire:
    def test_tester_present_with_the_suppress_bit_sends_only_the_ack(self):
        async def scenario(port):
            client = await Client.connect(port)
            await client.activate()
            ptype, _ = await client.diagnostic(b"\x3E\x80")
            assert ptype == PT_DIAGNOSTIC_POSITIVE_ACK
            with pytest.raises(asyncio.TimeoutError):
                await client.recv(timeout=0.3)
            await client.close()
            return True

        assert run(with_server(scenario))


class TestInactivityTimers:
    """ISO 13400-2 §7.2.2 / §7.2.3: initial and general inactivity timers."""
    TIMERS = {"doip": {"initial_inactivity_ms": 150, "general_inactivity_ms": 250}}

    def test_unregistered_socket_closed_by_initial_timer(self):
        async def scenario(port):
            client = await Client.connect(port)
            # No Routing Activation — the initial inactivity timer closes it.
            # This socket was never trusted (no successful Routing Activation),
            # so the teardown is abortive (TCP RST), not an orderly FIN —
            # readexactly() surfaces that as ConnectionResetError specifically.
            with pytest.raises(ConnectionResetError):
                await client.recv(timeout=2.0)
            await client.close()
            return True

        assert run(with_server(scenario, extra=self.TIMERS))

    def test_registered_idle_socket_closed_by_general_timer(self):
        async def scenario(port):
            client = await Client.connect(port)
            ptype, payload = await client.activate()
            assert payload[4] == 0x10
            # Registered but idle — the general inactivity timer closes it.
            with pytest.raises((asyncio.IncompleteReadError, ConnectionResetError)):
                await client.recv(timeout=2.0)
            await client.close()
            return True

        assert run(with_server(scenario, extra=self.TIMERS))

    def test_traffic_resets_the_general_timer(self):
        async def scenario(port):
            client = await Client.connect(port)
            await client.activate()
            # Stay active far beyond the 250 ms general timer by pinging every
            # 100 ms — each exchange must push the deadline forward, and the
            # connection must never be closed underneath us.
            for _ in range(4):
                await client.diagnostic(b"\x3E\x00")
                await asyncio.sleep(0.1)
            assert True
            await client.close()
            return True

        assert run(with_server(scenario, extra=self.TIMERS))


class TestFrameLengthCap:
    """
    ``read_frame`` bounds the declared payload length before reading it.

    Without this, a peer that sends a genuine 8-byte header with a hostile
    32-bit length (up to ~4 GiB, ISO 13400-2 Table 2) makes ``readexactly``
    wait for the rest of those bytes forever — hanging the connection open
    indefinitely, since the general inactivity timer only resets once a full
    frame has actually been read.
    """

    #: Small on purpose so "at the cap" / "one byte over" are cheap to set up.
    SMALL_MAX = {"doip": {"max_payload_bytes": 64}}

    def test_hostile_declared_length_is_nacked_and_socket_closed(self):
        async def scenario(port):
            client = await Client.connect(port)
            await client.activate()

            # Declare ~4 GiB of payload but only actually send 3 bytes. Before
            # the fix this would hang here until the timeout, every time.
            await client.send_raw_header(PT_DIAGNOSTIC_MESSAGE, 0xFFFFFFFF,
                                          b"\x0E\x00\x00")
            ptype, payload = await client.recv(timeout=2.0)
            assert ptype == PT_HEADER_NACK
            assert payload == b"\x02"    # Generic NACK 0x02: message too large

            # ISO 13400-2 Table 14 pairs 0x02 with "discard message", not a
            # forced close -- but we bail before reading the declared bytes,
            # so the stream is desynced. Closing is the only safe option.
            with pytest.raises((asyncio.IncompleteReadError, ConnectionResetError,
                                asyncio.TimeoutError)):
                await client.recv(timeout=1.0)
            await client.close()
            return True

        assert run(with_server(scenario, extra=self.SMALL_MAX))

    def test_message_exactly_at_the_cap_is_accepted_normally(self):
        async def scenario(port):
            client = await Client.connect(port)
            await client.activate()
            max_data = self.SMALL_MAX["doip"]["max_payload_bytes"]
            uds = b"\x22\xF1\x90" + b"\xAA" * (max_data - 3)
            assert len(uds) == max_data
            ptype, payload = await client.diagnostic(uds)
            # Must NOT be caught by the framing-level cap.
            assert ptype == PT_DIAGNOSTIC_POSITIVE_ACK
            await client.close()
            return True

        assert run(with_server(scenario, extra=self.SMALL_MAX))

    def test_message_one_byte_over_the_business_limit_still_gets_the_existing_nack(self):
        async def scenario(port):
            client = await Client.connect(port)
            await client.activate()
            max_data = self.SMALL_MAX["doip"]["max_payload_bytes"]
            uds = b"\x22\xF1\x90" + b"\xAA" * (max_data - 2)   # max_data + 1 bytes
            assert len(uds) == max_data + 1
            ptype, payload = await client.diagnostic(uds)
            # A merely-oversized (not hostile) request must still reach the
            # existing business-level "message too large" NACK, not be cut
            # off by the framing-level sanity cap this fix adds.
            assert ptype == PT_DIAGNOSTIC_NEGATIVE_ACK
            assert payload[4] == 0x04    # NACK_MESSAGE_TOO_LARGE
            await client.close()
            return True

        assert run(with_server(scenario, extra=self.SMALL_MAX))


class PumpingClient(Client):
    """
    A ``Client`` with its own background reader, so a scenario can wait on
    something else (another connection's ``activate()``, say) while this
    connection still needs to answer an incoming Alive Check Request the
    instant it arrives.

    asyncio allows only one coroutine at a time to wait on a given
    ``StreamReader``, so the background reader is the *only* thing that ever
    calls ``read_frame`` on this socket: it auto-answers Alive Check Requests
    and skips ``7F <sid> 78`` ResponsePending frames (expected noise from a
    slow handler, not a failure), and puts everything else on a queue that
    ``recv()`` reads from instead of the socket directly.
    """

    def __init__(self, reader, writer):
        super().__init__(reader, writer)
        self._queue: "asyncio.Queue[tuple]" = asyncio.Queue()
        self._pump_task = asyncio.ensure_future(self._pump())

    async def _pump(self):
        while True:
            raw = await read_frame(self.reader)
            pt = struct.unpack("!H", raw[2:4])[0]
            payload = raw[8:]
            if pt == PT_ALIVE_CHECK_REQUEST:
                await self.send(PT_ALIVE_CHECK_RESPONSE,
                                struct.pack("!H", TESTER_ADDR))
                continue
            if pt == PT_DIAGNOSTIC_MESSAGE and payload[4:5] == b"\x7F" \
                    and len(payload) >= 7 and payload[6] == 0x78:
                continue    # ResponsePending -- expected noise, not the answer
            await self._queue.put((raw[0], pt, payload))

    async def recv(self, timeout=2.0):
        _ver, pt, payload = await asyncio.wait_for(self._queue.get(), timeout=timeout)
        return pt, payload

    async def recv_version(self, timeout=2.0):
        return await asyncio.wait_for(self._queue.get(), timeout=timeout)

    async def close(self):
        self._pump_task.cancel()
        try:
            await self._pump_task
        except (asyncio.CancelledError, Exception):
            pass
        await super().close()


class TestPumpWorkerSplit:
    """
    The frame pump (``_loop``) must keep answering DoIP-layer traffic while a
    slow UDS handler is still running in the worker task.

    Baseline this beats (measured against the pre-split code): an Alive
    Check Response took 1401 ms behind a 1.5 s handler, and a competing
    Routing Activation during that handler evicted the still-alive session
    (denial code 0x10 instead of 0x03).
    """

    SLOW_HANDLER_DELAY_S = 1.5

    @staticmethod
    def _slow_plugin():
        class Slow(Plugin):
            name = "Slow"

            @on_service(0x22)
            async def read(self, req, ctx):
                await asyncio.sleep(TestPumpWorkerSplit.SLOW_HANDLER_DELAY_S)
                return req.positive(b"\x01")

        return Slow()

    def test_alive_check_is_answered_promptly_during_a_slow_handler(self):
        async def scenario(port):
            client = await PumpingClient.connect(port)
            await client.activate()

            # Kick off the slow request but don't wait for its response yet.
            await client.send(PT_DIAGNOSTIC_MESSAGE,
                              struct.pack("!HH", TESTER_ADDR, ECU_ADDR) + b"\x22\xF1\x90")
            ptype, _ = await client.recv()
            assert ptype == PT_DIAGNOSTIC_POSITIVE_ACK   # "received", sent by the pump

            # While the handler is still running, an Alive Check Request on
            # the SAME socket must get its response promptly -- well under
            # the alive-probe timeout, not after the handler finally returns.
            start = asyncio.get_event_loop().time()
            await client.send(PT_ALIVE_CHECK_REQUEST, b"")
            ptype, payload = await client.recv(timeout=2.0)
            elapsed = asyncio.get_event_loop().time() - start
            assert ptype == PT_ALIVE_CHECK_RESPONSE
            assert struct.unpack("!H", payload)[0] == ECU_ADDR
            assert elapsed < 0.2

            # The handler's own (delayed) response must still show up.
            ptype, payload = await client.recv(timeout=2.0)
            assert ptype == PT_DIAGNOSTIC_MESSAGE
            assert payload[4:] == b"\x62\x01"
            await client.close()
            return True

        assert run(with_server(scenario, plugins=[self._slow_plugin()]))

    def test_a_session_mid_handler_is_not_evicted_by_a_competing_activation(self):
        async def scenario(port):
            first = await PumpingClient.connect(port)
            ptype, payload = await first.activate()
            assert payload[4] == 0x10

            # Kick off the slow request; do not await its response yet.
            await first.send(PT_DIAGNOSTIC_MESSAGE,
                             struct.pack("!HH", TESTER_ADDR, ECU_ADDR) + b"\x22\xF1\x90")
            ptype, _ = await first.recv()
            assert ptype == PT_DIAGNOSTIC_POSITIVE_ACK

            # A second connection tries to activate the SAME tester SA while
            # the first is still mid-handler but alive (``first.recv()``
            # transparently answers the resulting probe). It must be
            # denied, not accepted at the first connection's expense.
            second = await Client.connect(port)
            ptype, payload = await second.activate(tester=TESTER_ADDR)
            assert ptype == PT_ROUTING_ACT_RESPONSE
            assert payload[4] == 0x03    # SA already registered and alive
            await second.close()

            # The first connection's slow request must still complete
            # normally -- it was never evicted.
            ptype, payload = await first.recv(timeout=2.0)
            assert ptype == PT_DIAGNOSTIC_MESSAGE
            assert payload[4:] == b"\x62\x01"
            await first.close()
            return True

        assert run(with_server(scenario, plugins=[self._slow_plugin()]))

    def test_pipelined_diagnostic_messages_are_acked_before_either_is_answered(self):
        async def scenario(port):
            client = await Client.connect(port)
            await client.activate()

            # Two requests, back to back, without waiting for either response.
            await client.send(PT_DIAGNOSTIC_MESSAGE,
                              struct.pack("!HH", TESTER_ADDR, ECU_ADDR) + b"\x3E\x00")
            await client.send(PT_DIAGNOSTIC_MESSAGE,
                              struct.pack("!HH", TESTER_ADDR, ECU_ADDR) + b"\x3E\x00")

            ptype1, _ = await client.recv()
            ptype2, _ = await client.recv()
            assert ptype1 == PT_DIAGNOSTIC_POSITIVE_ACK
            assert ptype2 == PT_DIAGNOSTIC_POSITIVE_ACK

            # Responses arrive afterwards, in request order.
            ptype3, payload3 = await client.recv()
            ptype4, payload4 = await client.recv()
            assert ptype3 == PT_DIAGNOSTIC_MESSAGE
            assert ptype4 == PT_DIAGNOSTIC_MESSAGE
            assert payload3[4:] == b"\x7E\x00"
            assert payload4[4:] == b"\x7E\x00"
            await client.close()
            return True

        assert run(with_server(scenario))

    def test_closing_mid_handler_does_not_leak_the_dispatch_task(self):
        """
        Regression test for a gap the pump/worker split itself opened:
        ``_dispatch_with_p2`` shields its inner dispatch task from the P2
        timeout on purpose, but that shield also protected it from the new
        cancellation source the split introduced -- ``_stop_uds_worker``/
        ``evict()`` cancelling the *worker* task on teardown. Before the
        fix, closing a connection mid-handler left the handler's task
        running detached until it finished on its own, able to call
        ``responder()`` (a write to an already-closed socket) well after
        the connection was gone.
        """
        async def scenario(port):
            client = await Client.connect(port)
            await client.activate()

            before = {id(t) for t in asyncio.all_tasks()}

            await client.send(PT_DIAGNOSTIC_MESSAGE,
                              struct.pack("!HH", TESTER_ADDR, ECU_ADDR) + b"\x22\xF1\x90")
            ptype, _ = await client.recv()
            assert ptype == PT_DIAGNOSTIC_POSITIVE_ACK

            # Close well before the 1.5s handler finishes.
            await asyncio.sleep(0.1)
            await client.close()

            # Give the server's teardown a moment to run, then assert
            # nothing new is still alive -- specifically, the dispatch task
            # must not survive to finish on its own ~1.4s from now.
            await asyncio.sleep(0.3)
            leaked = [t for t in asyncio.all_tasks() if id(t) not in before and not t.done()]
            assert leaked == [], "leaked task(s) after mid-handler close: %r" % leaked
            return True

        assert run(with_server(scenario, plugins=[self._slow_plugin()]))
