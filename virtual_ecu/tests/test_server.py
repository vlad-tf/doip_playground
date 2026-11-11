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
from virtecu.server import VirtualEcuServer


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

    VirtualEcuServer(ecu)._build_socket()

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

    VirtualEcuServer(ecu)._build_socket()

    assert captured["address"] == (host, ecu.config.listen.port, 0, 0)


@pytest.mark.parametrize("family", ["ipv4", "ipv6"])
@pytest.mark.parametrize("failing_step", ["bind", "listen"])
def test_build_socket_closes_the_socket_when_bind_or_listen_fails(
        monkeypatch, family, failing_step):
    closed = []
    failure = OSError("address in use")

    class FakeSocket:
        def setsockopt(self, *args):
            pass

        def bind(self, address):
            if failing_step == "bind":
                raise failure

        def listen(self, backlog):
            if failing_step == "listen":
                raise failure

        def close(self):
            closed.append(1)

    monkeypatch.setattr(socket, "socket", lambda *args: FakeSocket())
    ecu = make_ecu({"listen": {"host": "127.0.0.1" if family == "ipv4" else "::1",
                               "family": family}})

    with pytest.raises(OSError) as raised:
        VirtualEcuServer(ecu)._build_socket()

    assert raised.value is failure
    assert closed == [1]
