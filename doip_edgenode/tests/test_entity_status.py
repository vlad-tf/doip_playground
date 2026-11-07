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

"""F16 raw status framing and live inbound socket accounting."""

import asyncio
from unittest.mock import MagicMock

import pytest

from config import ConfigError, _load_doip
from session_registry import SessionRegistry
from udp_announcer import _UDPProtocol, UDPAnnouncer
from tests.test_session import _make_app_config
from tests.test_udp_discovery import ADDR, frame
from tests.test_routing_activation import make_session


def protocol(config=None, registry=None):
    config = config or _make_app_config()
    proto = _UDPProtocol(config, registry)
    transport = MagicMock()
    proto.connection_made(transport)
    return proto, transport


@pytest.mark.parametrize("version", [2, 3])
@pytest.mark.parametrize("count", [0, 1, 8, 9])
def test_udp_status_exact_three_bytes_live_counts(version, count):
    config = _make_app_config()
    registry = SessionRegistry(8)
    writers = [object() for _ in range(count)]
    for writer in writers:
        assert registry.reserve(writer)
    proto, transport = protocol(config, registry)
    proto.datagram_received(frame(0x4001, version=version), ADDR)
    transport.sendto.assert_called_once_with(frame(0x4002, bytes((config.doip.node_type, 8, count))), ADDR)
    assert not proto._pending_responses
    transport.reset_mock()
    for writer in writers:
        registry.release(writer)
        registry.release(writer)
    proto.datagram_received(frame(0x4001), ADDR)
    transport.sendto.assert_called_once_with(frame(0x4002, bytes((config.doip.node_type, 8, 0))), ADDR)


@pytest.mark.parametrize("data,code", [
    (frame(0x4001, b"x"), 4),
    (frame(0x4001, declared=1), 4),
    (frame(0x4001) + frame(0x4001), 4),
    (frame(0x4001, declared=4097), 2),
    (frame(0x4001, version=0xFF), 0),
    (frame(0x4001, inverse=0), 0),
    (frame(0x4002, b"\0\x08\0"), 1),
    (frame(0x4002, declared=0xFFFFFFFF), 1),
])
def test_status_validation_precedence_and_response_only_matrix(data, code):
    proto, transport = protocol()
    proto.datagram_received(data, ADDR)
    transport.sendto.assert_called_once_with(frame(0, bytes((code,))), ADDR)
    assert not proto._pending_responses


@pytest.mark.parametrize("source", ["0.0.0.0", "224.0.0.1", "255.255.255.255"])
def test_status_source_filter_precedes_response(source):
    proto, transport = protocol()
    proto.datagram_received(frame(0x4001), (source, 12345))
    transport.sendto.assert_not_called()


def test_announcer_passes_shared_registry_and_standalone_reports_zero():
    config = _make_app_config()
    registry = SessionRegistry(8)
    announcer = UDPAnnouncer(config, registry)
    assert announcer._registry is registry
    proto, transport = protocol(config)
    proto.datagram_received(frame(0x4001), ADDR)
    transport.sendto.assert_called_once_with(frame(0x4002, bytes((config.doip.node_type, 8, 0))), ADDR)


def test_legacy_tcp_status_uses_shared_counts_not_registered_sa_count():
    async def scenario():
        session, writer, registry = make_session(True)
        extra = object()
        assert registry.reserve(extra)
        try:
            assert registry.count() == 0
            assert registry.open_count() == 2
            await session._handle_entity_status()
            assert writer.frames == [frame(0x4002, bytes((session.config.doip.node_type, 8, 2)))]
        finally:
            registry.release(extra)
            await session._cleanup()
        assert registry.open_count() == 0
    asyncio.run(scenario())


@pytest.mark.parametrize("value", [0, 255, -1, True, False, 1.5, None, "bad"])
def test_max_connections_invalid_loader_values(value):
    config = _make_app_config()
    raw = dict(vin=config.doip.vin, eid=config.doip.eid, gid=config.doip.gid,
               node_type=config.doip.node_type, power_mode=config.doip.power_mode,
               max_payload_bytes=config.doip.max_payload_bytes, max_connections=value)
    with pytest.raises(ConfigError, match="doip.max_connections"):
        _load_doip(raw)


@pytest.mark.parametrize("value,expected", [(1, 1), (254, 254), ("008", 8), ("0xfe", 254)])
def test_max_connections_loader_boundaries(value, expected):
    config = _make_app_config()
    raw = dict(vin=config.doip.vin, eid=config.doip.eid, gid=config.doip.gid,
               node_type=config.doip.node_type, power_mode=config.doip.power_mode,
               max_payload_bytes=config.doip.max_payload_bytes, max_connections=value)
    assert _load_doip(raw).max_connections == expected
    raw.pop("max_connections")
    assert _load_doip(raw).max_connections == 8


def test_maximum_capacity_plus_reserve_encodes_255_without_wrap():
    config = _make_app_config()
    registry = SessionRegistry(254)
    writers = [object() for _ in range(255)]
    assert all(registry.reserve(writer) for writer in writers)
    assert not registry.reserve(object())
    assert registry.status_payload(config) == bytes((config.doip.node_type, 254, 255))
