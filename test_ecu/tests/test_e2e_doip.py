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

from conftest import ECU_ADDR, TESTER_ADDR, make_ecu, run
from testecu.doip import (
    PT_ALIVE_CHECK_RESPONSE,
    PT_DIAGNOSTIC_MESSAGE,
    PT_DIAGNOSTIC_NEGATIVE_ACK,
    PT_DIAGNOSTIC_POSITIVE_ACK,
    PT_ENTITY_STATUS_REQUEST,
    PT_ENTITY_STATUS_RESPONSE,
    PT_HEADER_NACK,
    PT_POWER_MODE_REQUEST,
    PT_POWER_MODE_RESPONSE,
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
    async def connect(cls, port):
        reader, writer = await asyncio.open_connection("::1", port)
        return cls(reader, writer)

    async def send(self, payload_type, payload):
        self.writer.write(build_frame(payload_type, payload))
        await self.writer.drain()

    async def recv(self, timeout=2.0):
        raw = await asyncio.wait_for(read_frame(self.reader), timeout=timeout)
        return struct.unpack("!H", raw[2:4])[0], raw[8:]

    async def activate(self, tester=TESTER_ADDR):
        await self.send(PT_ROUTING_ACT_REQUEST,
                        struct.pack("!H", tester) + b"\x00" + b"\x00\x00\x00\x00")
        return await self.recv()

    async def diagnostic(self, uds, target=ECU_ADDR, tester=TESTER_ADDR):
        await self.send(PT_DIAGNOSTIC_MESSAGE,
                        struct.pack("!HH", tester, target) + uds)
        return await self.recv()

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

            ptype, payload = await client.recv()
            assert ptype == PT_DIAGNOSTIC_MESSAGE
            assert struct.unpack("!H", payload[0:2])[0] == ECU_ADDR
            assert struct.unpack("!H", payload[2:4])[0] == TESTER_ADDR
            assert payload[4:] == b"\x62\xF1\x90" + b"1HGBH41JXMN109186"
            await client.close()
            return True

        assert run(with_server(scenario))

    def test_diagnostic_before_activation_is_ignored(self):
        async def scenario(port):
            client = await Client.connect(port)
            await client.send(PT_DIAGNOSTIC_MESSAGE,
                              struct.pack("!HH", TESTER_ADDR, ECU_ADDR) + b"\x3E\x00")
            with pytest.raises(asyncio.TimeoutError):
                await client.recv(timeout=0.3)
            await client.close()
            return True

        assert run(with_server(scenario))

    def test_unknown_target_address_is_nacked(self):
        async def scenario(port):
            client = await Client.connect(port)
            await client.activate()
            ptype, payload = await client.diagnostic(b"\x3E\x00", target=0x1234)
            assert ptype == PT_DIAGNOSTIC_NEGATIVE_ACK
            assert payload[4] == 0x01                       # unknown target address
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


class TestNodeServices:
    def test_entity_status_and_power_mode(self):
        async def scenario(port):
            client = await Client.connect(port)
            await client.send(PT_ENTITY_STATUS_REQUEST, b"")
            ptype, payload = await client.recv()
            assert ptype == PT_ENTITY_STATUS_RESPONSE
            assert payload[0] == 0x01                       # node type: gateway
            assert struct.unpack("!I", payload[3:7])[0] == 4096

            await client.send(PT_POWER_MODE_REQUEST, b"")
            ptype, payload = await client.recv()
            assert ptype == PT_POWER_MODE_RESPONSE
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
