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
Shared fixtures.

Every async test is driven through the ``run()`` helper rather than
pytest-asyncio, the same trick ``doip_edgenode/tests/test_middleware.py`` uses:
the suite then needs nothing but pytest itself.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any, List, Optional

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from testecu.config import parse_config                      # noqa: E402
from testecu.core import EcuCore                             # noqa: E402
from testecu.session import resolve_uds                      # noqa: E402
from testecu.uds import UdsRequest                           # noqa: E402

TESTER_ADDR = 0x0E00
ECU_ADDR = 0x0002

#: Minimal config every test starts from; tests deep-merge their own bits in.
BASE_CONFIG = {
    "listen": {"host": "::1", "port": 0, "interface": ""},
    "doip": {
        "ecu_logical_addr": ECU_ADDR,
        "vin": "1HGBH41JXMN109186",
        "eid": "AABBCCDDEEFF",
        "gid": "000000000000",
        "max_payload_bytes": 4096,
    },
    "udp": {"enabled": False},
    "uds": {"p2_server_ms": 20, "p2_star_server_ms": 500, "s3_server_ms": 200},
}


def run(coro: Any) -> Any:
    """
    Run one coroutine on a fresh event loop and return its result.

    Stray tasks (an armed S3 timer, say) are cancelled and drained before the
    loop closes, so a test that leaves one behind does not print
    "Task was destroyed but it is pending" into the next test's output.
    """
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
    finally:
        pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        asyncio.set_event_loop(None)
        loop.close()


def merge(base: dict, extra: Optional[dict]) -> dict:
    """One-level-deep dict merge, so a test can override just `uds.p2_server_ms`."""
    result = {key: dict(value) if isinstance(value, dict) else value
              for key, value in base.items()}
    for key, value in (extra or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge({key: result[key]}, None)[key]
            result[key].update(value)
        else:
            result[key] = value
    return result


def make_ecu(extra: Optional[dict] = None, plugins: Optional[List[Any]] = None,
             base_dir: str = ".") -> EcuCore:
    """Build an EcuCore from BASE_CONFIG plus ``extra``, with no plugin discovery."""
    config = parse_config(merge(BASE_CONFIG, extra), base_dir)
    return EcuCore(config, plugins=plugins if plugins is not None else [])


class Probe:
    """
    Drives an ECU the way a connected tester would, without any sockets.

    ``send()`` returns the final response bytes (or None when the request is
    suppressed).  Any extra frames a handler emitted — 0x78 pending,
    ``ctx.send()`` — land in ``extra`` in the order they went out.
    """

    def __init__(self, ecu: EcuCore) -> None:
        self.ecu = ecu
        self.state = ecu.new_session("probe")
        self.extra: List[bytes] = []

    async def _responder(self, payload: bytes) -> None:
        self.extra.append(bytes(payload))

    async def asend(self, request: Any, functional: bool = False) -> Optional[bytes]:
        raw = request if isinstance(request, (bytes, bytearray)) else _hex(request)
        uds = UdsRequest(
            raw=bytes(raw),
            source_addr=TESTER_ADDR,
            target_addr=self.ecu.uds.functional_addr if functional else ECU_ADDR,
            functional=functional,
        )
        return await resolve_uds(self.ecu, self.state, uds, self._responder)

    def send(self, request: Any, functional: bool = False) -> Optional[bytes]:
        """Synchronous convenience wrapper for a single request."""
        async def once() -> Optional[bytes]:
            await self.ecu.startup()
            return await self.asend(request, functional)
        return run(once())

    def exchange(self, *requests: Any) -> List[Optional[bytes]]:
        """
        Send several requests on ONE event loop, in order.

        Use this whenever session or security state has to carry between
        requests — ``send()`` closes its loop each time, which would strand any
        S3 timer armed along the way.
        """
        async def sequence() -> List[Optional[bytes]]:
            await self.ecu.startup()
            return [await self.asend(request) for request in requests]
        return run(sequence())


def _hex(text: str) -> bytes:
    return bytes.fromhex(text.replace(" ", ""))


def probe_for(extra: Optional[dict] = None, plugins: Optional[List[Any]] = None,
              base_dir: str = ".") -> Probe:
    return Probe(make_ecu(extra, plugins, base_dir))


@pytest.fixture
def probe() -> Probe:
    """A probe against a default ECU with no plugins."""
    return probe_for()


@pytest.fixture
def hexs():
    return _hex
