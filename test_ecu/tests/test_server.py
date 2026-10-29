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

from __future__ import annotations

import socket

import pytest

from conftest import make_ecu
from testecu.server import TestEcuServer


@pytest.mark.parametrize("host", ["fe80::1", "fe90::1", "febf::1", "ff02::1"])
def test_scoped_ipv6_bind_uses_interface_scope_id(monkeypatch, host):
    captured = {}

    class FakeSocket:
        def setsockopt(self, *args):
            pass

        def bind(self, address):
            captured["address"] = address

        def listen(self, backlog):
            pass

    monkeypatch.setattr(socket, "socket", lambda *args: FakeSocket())
    monkeypatch.setattr(socket, "if_nametoindex", lambda name: 7)
    ecu = make_ecu({"listen": {"host": host, "interface": "test0"}})

    TestEcuServer(ecu)._build_socket()

    assert captured["address"] == (host, ecu.config.listen.port, 0, 7)


@pytest.mark.parametrize("host", ["2001:db8::1", "fd2e::3", "::"])
def test_unscoped_ipv6_bind_uses_zero_scope_id(monkeypatch, host):
    captured = {}

    class FakeSocket:
        def setsockopt(self, *args):
            pass

        def bind(self, address):
            captured["address"] = address

        def listen(self, backlog):
            pass

    monkeypatch.setattr(socket, "socket", lambda *args: FakeSocket())
    monkeypatch.setattr(socket, "if_nametoindex", lambda name: 7)
    ecu = make_ecu({"listen": {"host": host, "interface": "test0"}})

    TestEcuServer(ecu)._build_socket()

    assert captured["address"] == (host, ecu.config.listen.port, 0, 0)
