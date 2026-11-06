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

"""F02 regressions: only the current session owner can unregister an SA."""

import asyncio
from unittest.mock import AsyncMock, Mock

import pytest

from session_registry import SessionRegistry
from tests.test_routing_activation import activate, assert_response, make_session


@pytest.mark.parametrize("registered", [False, True])
def test_unregister_is_safe_for_missing_and_owned_addresses(registered):
    registry = SessionRegistry()
    owner = Mock(peer=("127.0.0.1", 12345))
    if registered:
        registry.register(0x0E00, owner)
    registry.unregister(0x0E00, owner)
    registry.unregister(0x0E00, owner)
    assert registry.lookup(0x0E00) is None
    assert registry.count() == 0


def test_unregister_checks_identity_not_equality():
    class EqualOwner:
        peer = ("127.0.0.1", 12345)

        def __eq__(self, other):
            return True

    registry = SessionRegistry()
    old, replacement = EqualOwner(), EqualOwner()
    registry.register(0x0E00, old)
    registry.register(0x0E00, replacement)
    registry.unregister(0x0E00, old)
    assert registry.lookup(0x0E00) is replacement
    assert registry.count() == 1
    registry.unregister(0x0E00, replacement)
    assert registry.count() == 0


@pytest.mark.parametrize("first_action", ["cleanup", "evict"])
def test_evicted_session_cleanup_keeps_replacement_registered(first_action):
    async def scenario():
        old, old_writer, registry = make_session(True)
        replacement, writer, _ = make_session(False)
        replacement._registry = registry
        try:
            await activate(old, 0x0E00)
            old.probe_alive = AsyncMock(return_value=False)
            await activate(replacement, 0x0E00)
            old.probe_alive.assert_awaited_once()
            assert old_writer.closed
            assert_response(writer.frames[-1], 0x0E00, 0x10)
            timer = replacement._inactivity_task
            if first_action == "evict":
                old.evict()
                assert registry.lookup(0x0E00) is replacement
            for _ in range(2):
                await old._cleanup()
                # Repeated stale eviction must be harmless too.
                old.evict()
                assert registry.lookup(0x0E00) is replacement
                assert registry.count() == 1
                assert not writer.closed
                assert replacement._inactivity_task is timer
        finally:
            await old._cleanup()
            await replacement._cleanup()
        assert registry.count() == 0

    asyncio.run(scenario())


def test_cleanup_waiting_for_socket_close_keeps_later_replacement():
    async def scenario():
        old, old_writer, registry = make_session(True)
        replacement, writer, _ = make_session(False)
        replacement._registry = registry
        waiting, release = asyncio.Event(), asyncio.Event()

        async def delayed_wait_closed():
            waiting.set()
            await release.wait()

        old_writer.wait_closed = delayed_wait_closed
        cleanup_task = None
        try:
            await activate(old, 0x0E00)
            cleanup_task = asyncio.create_task(old._cleanup())
            await asyncio.wait_for(waiting.wait(), timeout=1)
            old.probe_alive = AsyncMock(return_value=False)
            await activate(replacement, 0x0E00)
            assert_response(writer.frames[-1], 0x0E00, 0x10)
            release.set()
            await asyncio.wait_for(cleanup_task, timeout=1)
            assert registry.lookup(0x0E00) is replacement
            assert registry.count() == 1
            assert not writer.closed
        finally:
            release.set()
            if cleanup_task is not None:
                await asyncio.wait_for(cleanup_task, timeout=1)
            await old._cleanup()
            await replacement._cleanup()
        assert registry.count() == 0

    asyncio.run(scenario())
