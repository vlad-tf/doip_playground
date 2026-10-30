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


"""Cross-platform socket helpers (Windows interface index / UDP reset handling)."""

from __future__ import annotations

import asyncio
import builtins
import socket
import sys

import pytest

import virtecu.netutil as netutil
import virtecu.udp as udp_module
from virtecu.netutil import harden_udp_socket, resolve_if_index


def test_empty_interface_is_zero():
    assert resolve_if_index("") == 0


def test_numeric_interface_is_taken_as_index(monkeypatch):
    def boom(name):
        raise AssertionError("if_nametoindex must not be called for a number")
    monkeypatch.setattr(socket, "if_nametoindex", boom)
    assert resolve_if_index("12") == 12


def test_numeric_zero_means_any_and_warns(caplog):
    with caplog.at_level("WARNING", logger="virtecu.netutil"):
        assert resolve_if_index("0") == 0
    assert "any interface" in caplog.text


def test_named_interface_uses_if_nametoindex(monkeypatch):
    monkeypatch.setattr(socket, "if_nametoindex", lambda name: 7)
    assert resolve_if_index("eth1") == 7


def test_unknown_name_falls_back_to_zero(monkeypatch, caplog):
    def fail(name):
        raise OSError("no such device")
    monkeypatch.setattr(socket, "if_nametoindex", fail)
    with caplog.at_level("WARNING", logger="virtecu.netutil"):
        assert resolve_if_index("nope") == 0
    assert "nope" in caplog.text


def test_harden_is_noop_off_windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(netutil, "_disable_udp_connreset",
                        lambda fd: pytest.fail("must not run off Windows"))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        harden_udp_socket(s)
    finally:
        s.close()


def test_harden_issues_connreset_ioctl_on_windows(monkeypatch):
    calls = []
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(netutil, "_disable_udp_connreset", calls.append)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        harden_udp_socket(s)
        assert calls == [s.fileno()]
    finally:
        s.close()


def test_harden_failure_is_logged_not_raised(monkeypatch, caplog):
    def fail(fd):
        raise OSError(10022, "invalid")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(netutil, "_disable_udp_connreset", fail)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with caplog.at_level("WARNING", logger="virtecu.netutil"):
            harden_udp_socket(s)
    finally:
        s.close()
    assert "SIO_UDP_CONNRESET" in caplog.text


def test_local_ips_survives_missing_fcntl(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "fcntl":
            raise ImportError("no fcntl on Windows")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    ips = udp_module._local_ips()
    assert {"127.0.0.1", "::1"} <= ips


def test_ipv6_discovery_binds_before_joining_multicast(monkeypatch):
    """Windows rejects IPV6_JOIN_GROUP on an unbound socket, so bind must come first."""
    from conftest import BASE_CONFIG, merge, run
    from virtecu.config import parse_config

    order = []

    class FakeSocket:
        def __init__(self, *a):
            pass

        def setsockopt(self, level, opt, value):
            if opt == socket.IPV6_JOIN_GROUP:
                order.append("join")

        def bind(self, addr):
            order.append("bind")

        def close(self):
            pass

        def fileno(self):
            return -1

        def setblocking(self, flag):
            pass

    class _StopAfterSetup(Exception):
        pass

    monkeypatch.setattr(socket, "if_nametoindex", lambda n: 3)
    config = parse_config(merge(BASE_CONFIG, {"udp": {"enabled": True}}))

    async def scenario():
        # Patch only once the loop (which builds its own socketpair) exists.
        monkeypatch.setattr(socket, "socket", FakeSocket)

        async def stop(self, factory, sock=None, **kwargs):
            raise _StopAfterSetup

        # Replace the endpoint creation so the fake socket is never used as a
        # real one; run_announcer stops deterministically after bind + join.
        monkeypatch.setattr(asyncio.get_running_loop().__class__,
                            "create_datagram_endpoint", stop)
        await udp_module.run_announcer(config)

    with pytest.raises(_StopAfterSetup):
        run(scenario())
    assert order[:2] == ["bind", "join"]


def test_harden_swallows_unexpected_ctypes_errors(monkeypatch, caplog):
    def fail(fd):
        raise TypeError("ctypes.ArgumentError stand-in")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(netutil, "_disable_udp_connreset", fail)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        harden_udp_socket(s)  # must not raise
    finally:
        s.close()
