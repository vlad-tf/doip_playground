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

"""Client alive traffic uses the registered tester identity, never probes."""

import asyncio
import importlib.util
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

spec = importlib.util.spec_from_file_location(
    "pc_tester_under_test", Path(__file__).resolve().parents[1] / "tester.py"
)
tester_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tester_module)


def make_tester():
    tester = tester_module.DoIPTester("127.0.0.1", 13400, 0x0E00, 0x0003)
    tester._send = AsyncMock()
    tester._recv = AsyncMock(side_effect=AssertionError("keepalive must not receive"))
    return tester


@pytest.mark.parametrize("source", [0x0E00, 0x0E55])
def test_alive_sends_client_response_without_waiting(source):
    async def scenario():
        tester = make_tester()
        tester.activated = True
        tester.tester_addr = source
        await tester.cmd_alive()
        tester._send.assert_awaited_once_with(
            tester_module._build(8, source.to_bytes(2, "big"))
        )
        tester._recv.assert_not_awaited()

    asyncio.run(scenario())


def test_alive_before_activation_sends_nothing(capsys):
    async def scenario():
        tester = make_tester()
        await tester.cmd_alive()
        tester._send.assert_not_awaited()
        tester._recv.assert_not_awaited()
    asyncio.run(scenario())
    assert "Not activated" in capsys.readouterr().out


@pytest.mark.parametrize("code", [0x10, 0x03])
def test_activation_override_changes_identity_only_on_success(code):
    async def scenario():
        tester = make_tester()
        tester.activated = True
        payload = b"\x0e\x55\x12\x34" + bytes([code]) + bytes(4)
        tester._recv = AsyncMock(return_value=tester_module._build(6, payload))
        assert await tester.cmd_activate(0x0E55) is (code == 0x10)
        assert tester.tester_addr == (0x0E55 if code == 0x10 else 0x0E00)
        tester._send.reset_mock()
        tester._recv.reset_mock()
        await tester.cmd_alive()
        tester._send.assert_awaited_once_with(
            tester_module._build(8, tester.tester_addr.to_bytes(2, "big"))
        )
        tester._recv.assert_not_awaited()

    asyncio.run(scenario())


@pytest.mark.parametrize("payload", [b"", b"x"])
def test_background_reader_answers_only_empty_vehicle_probes(payload):
    async def scenario():
        tester = make_tester()
        tester.activated = True
        tester.tester_addr = 0x0E55
        tester._reader = asyncio.StreamReader()
        tester._recv_queue = asyncio.Queue()
        tester._reader.feed_data(tester_module._build(7, payload))
        tester._reader.feed_eof()
        await asyncio.wait_for(tester._background_reader(), 0.3)
        if payload:
            tester._send.assert_not_awaited()
        else:
            tester._send.assert_awaited_once_with(tester_module._build(8, b"\x0e\x55"))
        assert tester._recv_queue.empty()
        assert tester._closed_event.is_set()

    asyncio.run(scenario())


def test_help_describes_one_way_keepalive():
    assert "Alive Check Response keepalive" in tester_module.HELP_TEXT
    assert "no reply expected" in tester_module.HELP_TEXT
