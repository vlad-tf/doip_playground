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
DoIP-layer plugin hooks (architecture roadmap P2).

Modeled on ``test_dispatcher.py``'s precedence/isolation tests, but exercised
through real sockets via ``test_e2e_doip.py``'s ``Client``/``with_server``,
since these hooks fire from ``session.py``'s connection handling and
``udp.py``'s datagram handling, not from the UDS ``Dispatcher``.

Covers, for each hook kind: a hook returning ``None`` falls through to
default behaviour; a hook returning a decision overrides it; a hook that
raises does not crash the connection or the process; ``on_frame_rx``/
``on_frame_tx`` observers run without affecting the outcome and swallow
their own exceptions.
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from conftest import ECU_ADDR, TESTER_ADDR, make_ecu, run
from testecu import (
    Plugin,
    WITHHOLD_ACK,
    on_diagnostic_ack,
    on_frame_rx,
    on_frame_tx,
    on_identification_request,
    on_routing_activation,
)
from testecu.doip import (
    PT_DIAGNOSTIC_MESSAGE,
    PT_DIAGNOSTIC_NEGATIVE_ACK,
    PT_DIAGNOSTIC_POSITIVE_ACK,
    PT_ROUTING_ACT_RESPONSE,
    PT_VEHICLE_ID_REQUEST,
    PT_VEHICLE_ID_RESPONSE,
    build_frame,
)
from testecu.server import TestEcuServer
from testecu.udp import _UDPProtocol

from test_e2e_doip import Client, with_server

CONFIG = {
    "listen": {"host": "::1", "port": 0, "interface": ""},
    "data_identifiers": {
        0xF190: {"type": "ascii", "length": 17, "value": "1HGBH41JXMN109186"},
    },
}


# ---------------------------------------------------------------------------
# on_routing_activation
# ---------------------------------------------------------------------------

class TestRoutingActivationHook:
    def test_none_falls_through_to_default_acceptance(self):
        class Passive(Plugin):
            name = "Passive"

            @on_routing_activation()
            def check(self, req, ctx):
                return None

        async def scenario(port):
            client = await Client.connect(port)
            ptype, payload = await client.activate()
            assert ptype == PT_ROUTING_ACT_RESPONSE
            assert payload[4] == 0x10   # success, unaffected by the hook
            await client.close()
            return True

        assert run(with_server(scenario, CONFIG, plugins=[Passive()]))

    def test_a_decision_denies_activation(self):
        class Denier(Plugin):
            name = "Denier"

            @on_routing_activation()
            def check(self, req, ctx):
                assert req.source_addr == TESTER_ADDR
                return 0x03   # "missing authentication" — any non-0x10 denial code

        async def scenario(port):
            client = await Client.connect(port)
            ptype, payload = await client.activate()
            assert ptype == PT_ROUTING_ACT_RESPONSE
            assert payload[4] == 0x03
            await client.close()
            return True

        assert run(with_server(scenario, CONFIG, plugins=[Denier()]))

    def test_a_raising_hook_does_not_crash_the_connection(self):
        class Buggy(Plugin):
            name = "Buggy"

            @on_routing_activation()
            def check(self, req, ctx):
                raise RuntimeError("boom")

        async def scenario(port):
            client = await Client.connect(port)
            ptype, payload = await client.activate()
            # exception isolated -> None -> falls through to normal acceptance
            assert ptype == PT_ROUTING_ACT_RESPONSE
            assert payload[4] == 0x10
            await client.close()
            return True

        assert run(with_server(scenario, CONFIG, plugins=[Buggy()]))

    def test_returning_0x10_is_ignored_not_treated_as_override(self):
        class Yes(Plugin):
            name = "Yes"

            @on_routing_activation()
            def check(self, req, ctx):
                return 0x10   # must be ignored -- see session.py's warning log

        async def scenario(port):
            client = await Client.connect(port)
            ptype, payload = await client.activate()
            assert ptype == PT_ROUTING_ACT_RESPONSE
            assert payload[4] == 0x10   # normal §9.3 path still ran underneath
            await client.close()
            return True

        assert run(with_server(scenario, CONFIG, plugins=[Yes()]))


# ---------------------------------------------------------------------------
# on_diagnostic_ack
# ---------------------------------------------------------------------------

class TestDiagnosticAckHook:
    def test_none_falls_through_to_a_normal_positive_ack(self):
        class Passive(Plugin):
            name = "Passive"

            @on_diagnostic_ack()
            def check(self, req, ctx):
                return None

        async def scenario(port):
            client = await Client.connect(port)
            await client.activate()
            ptype, payload = await client.diagnostic(b"\x22\xF1\x90")
            assert ptype == PT_DIAGNOSTIC_POSITIVE_ACK
            assert payload[4] == 0x00
            await client.close()
            return True

        assert run(with_server(scenario, CONFIG, plugins=[Passive()]))

    def test_an_int_overrides_the_ack_with_a_nack(self):
        class Nacker(Plugin):
            name = "Nacker"

            @on_diagnostic_ack()
            def check(self, req, ctx):
                assert req.source_addr == TESTER_ADDR
                return 0x04   # "unknown target address" -- any NACK code

        async def scenario(port):
            client = await Client.connect(port)
            await client.activate()
            ptype, payload = await client.diagnostic(b"\x22\xF1\x90")
            assert ptype == PT_DIAGNOSTIC_NEGATIVE_ACK
            assert payload[4] == 0x04
            await client.close()
            return True

        assert run(with_server(scenario, CONFIG, plugins=[Nacker()]))

    def test_withhold_ack_sentinel_drops_the_message_silently(self):
        class Withholder(Plugin):
            name = "Withholder"

            @on_diagnostic_ack()
            def check(self, req, ctx):
                return WITHHOLD_ACK

        async def scenario(port):
            client = await Client.connect(port)
            await client.activate()
            await client.send(
                PT_DIAGNOSTIC_MESSAGE,
                struct.pack("!HH", TESTER_ADDR, ECU_ADDR) + b"\x22\xF1\x90",
            )
            # Nothing at all should arrive -- no ACK, no NACK, no response.
            with pytest.raises(asyncio.TimeoutError):
                await client.recv(timeout=0.3)
            await client.close()
            return True

        assert run(with_server(scenario, CONFIG, plugins=[Withholder()]))

    def test_a_raising_hook_does_not_crash_the_connection(self):
        class Buggy(Plugin):
            name = "Buggy"

            @on_diagnostic_ack()
            def check(self, req, ctx):
                raise RuntimeError("boom")

        async def scenario(port):
            client = await Client.connect(port)
            await client.activate()
            ptype, payload = await client.diagnostic(b"\x22\xF1\x90")
            assert ptype == PT_DIAGNOSTIC_POSITIVE_ACK  # isolated -> normal path
            assert payload[4] == 0x00
            await client.close()
            return True

        assert run(with_server(scenario, CONFIG, plugins=[Buggy()]))


# ---------------------------------------------------------------------------
# on_frame_rx / on_frame_tx
# ---------------------------------------------------------------------------

class TestFrameObserverHooks:
    def test_rx_and_tx_observers_see_every_frame_and_do_not_alter_the_outcome(self):
        seen = {"rx": [], "tx": []}

        class Observer(Plugin):
            name = "Observer"

            @on_frame_rx()
            def rx(self, payload_type, payload, ctx):
                seen["rx"].append(payload_type)

            @on_frame_tx()
            def tx(self, payload_type, payload, ctx):
                seen["tx"].append(payload_type)

        async def scenario(port):
            client = await Client.connect(port)
            ptype, payload = await client.activate()
            assert ptype == PT_ROUTING_ACT_RESPONSE
            assert payload[4] == 0x10
            await client.close()
            return True

        assert run(with_server(scenario, CONFIG, plugins=[Observer()]))
        # The Routing Activation Request was observed on rx, the Response on tx.
        from testecu.doip import PT_ROUTING_ACT_REQUEST
        assert PT_ROUTING_ACT_REQUEST in seen["rx"]
        assert PT_ROUTING_ACT_RESPONSE in seen["tx"]

    def test_a_raising_observer_is_swallowed_and_the_connection_survives(self):
        class Buggy(Plugin):
            name = "Buggy"

            @on_frame_rx()
            def rx(self, payload_type, payload, ctx):
                raise RuntimeError("boom")

            @on_frame_tx()
            def tx(self, payload_type, payload, ctx):
                raise RuntimeError("boom too")

        async def scenario(port):
            client = await Client.connect(port)
            ptype, payload = await client.activate()
            assert ptype == PT_ROUTING_ACT_RESPONSE
            assert payload[4] == 0x10
            await client.close()
            return True

        assert run(with_server(scenario, CONFIG, plugins=[Buggy()]))


# ---------------------------------------------------------------------------
# on_identification_request (UDP side)
# ---------------------------------------------------------------------------

class _FakeTransport:
    def __init__(self) -> None:
        self.sent: list = []

    def sendto(self, data: bytes, addr) -> None:
        self.sent.append((data, addr))


def _protocol_with_hooks(doip_hooks):
    from conftest import BASE_CONFIG, merge
    from testecu.config import parse_config

    config = parse_config(merge(BASE_CONFIG, {"udp": {"announce_wait_ms": 0}}))
    protocol = _UDPProtocol(config, if_index=0, doip_hooks=doip_hooks)
    transport = _FakeTransport()
    protocol.connection_made(transport)
    return protocol, transport


ADDR = ("::1", 54321, 0, 0)


class TestIdentificationRequestHook:
    def test_none_falls_through_to_the_default_response(self):
        from testecu.core import EcuCore
        from conftest import BASE_CONFIG, merge
        from testecu.config import parse_config

        class Passive(Plugin):
            name = "Passive"

            @on_identification_request()
            def check(self, req, ctx):
                return None

        async def scenario():
            ecu = EcuCore(parse_config(merge(BASE_CONFIG, {"udp": {"announce_wait_ms": 0}})),
                         plugins=[Passive()])
            protocol, transport = _protocol_with_hooks(ecu.doip_hooks)
            protocol.datagram_received(build_frame(PT_VEHICLE_ID_REQUEST, b""), ADDR)
            await asyncio.sleep(0.05)
            assert len(transport.sent) == 1
            data, addr = transport.sent[0]
            assert struct.unpack("!H", data[2:4])[0] == PT_VEHICLE_ID_RESPONSE
            return True

        assert run(scenario())

    def test_bytes_override_replaces_the_response_payload(self):
        from testecu.core import EcuCore
        from conftest import BASE_CONFIG, merge
        from testecu.config import parse_config

        class Overrider(Plugin):
            name = "Overrider"

            @on_identification_request()
            def check(self, req, ctx):
                return b"\xAA" * 32

        async def scenario():
            ecu = EcuCore(parse_config(merge(BASE_CONFIG, {"udp": {"announce_wait_ms": 0}})),
                         plugins=[Overrider()])
            protocol, transport = _protocol_with_hooks(ecu.doip_hooks)
            protocol.datagram_received(build_frame(PT_VEHICLE_ID_REQUEST, b""), ADDR)
            await asyncio.sleep(0.05)
            assert len(transport.sent) == 1
            data, addr = transport.sent[0]
            assert struct.unpack("!H", data[2:4])[0] == PT_VEHICLE_ID_RESPONSE
            assert data[8:] == b"\xAA" * 32
            return True

        assert run(scenario())

    def test_empty_bytes_withholds_the_response(self):
        from testecu.core import EcuCore
        from conftest import BASE_CONFIG, merge
        from testecu.config import parse_config

        class Withholder(Plugin):
            name = "Withholder"

            @on_identification_request()
            def check(self, req, ctx):
                return b""

        async def scenario():
            ecu = EcuCore(parse_config(merge(BASE_CONFIG, {"udp": {"announce_wait_ms": 0}})),
                         plugins=[Withholder()])
            protocol, transport = _protocol_with_hooks(ecu.doip_hooks)
            protocol.datagram_received(build_frame(PT_VEHICLE_ID_REQUEST, b""), ADDR)
            await asyncio.sleep(0.05)
            assert len(transport.sent) == 0
            return True

        assert run(scenario())

    def test_a_raising_hook_falls_through_to_the_default_response(self):
        from testecu.core import EcuCore
        from conftest import BASE_CONFIG, merge
        from testecu.config import parse_config

        class Buggy(Plugin):
            name = "Buggy"

            @on_identification_request()
            def check(self, req, ctx):
                raise RuntimeError("boom")

        async def scenario():
            ecu = EcuCore(parse_config(merge(BASE_CONFIG, {"udp": {"announce_wait_ms": 0}})),
                         plugins=[Buggy()])
            protocol, transport = _protocol_with_hooks(ecu.doip_hooks)
            protocol.datagram_received(build_frame(PT_VEHICLE_ID_REQUEST, b""), ADDR)
            await asyncio.sleep(0.05)
            assert len(transport.sent) == 1
            data, addr = transport.sent[0]
            assert struct.unpack("!H", data[2:4])[0] == PT_VEHICLE_ID_RESPONSE
            return True

        assert run(scenario())
