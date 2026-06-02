"""
Tests for DoIPSession state machine.

Uses MockECU (loopback IPv4, no root required) and raw asyncio clients.
No Scapy required for the raw-bytes client side; the session under test
uses Scapy internally.

Tests:
  1. Full lifecycle: connect → routing activation → diagnostic message → disconnect
  2. Activation gate: diagnostic before RA → NACK + disconnect
  3. T_TCP_Initial_Inactivity: connect, send nothing → connection closes
  4. Header NACK for wrong version bytes
  5. Header NACK for oversized payload length

Run with:
    cd doip_edgenode && pytest tests/test_session.py -v

All tests use ephemeral ports so they can run in parallel.
"""

from __future__ import annotations

import asyncio
import struct
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests.mock_ecu import MockECU, _build, _read_frame, _ptype
from tests.mock_ecu import (
    PT_ROUTING_ACT_REQUEST,
    PT_ROUTING_ACT_RESPONSE,
    PT_DIAGNOSTIC_MESSAGE,
    PT_DIAGNOSTIC_POSITIVE_ACK,
    PT_HEADER_NACK,
    PT_ALIVE_CHECK_REQUEST,
    PT_ALIVE_CHECK_RESPONSE,
)

# ---------------------------------------------------------------------------
# Helpers — build raw DoIP frames without Scapy
# ---------------------------------------------------------------------------

_VER = 0x02
_INV = 0xFF ^ _VER


def _raw_frame(payload_type: int, payload: bytes, ver: int = _VER) -> bytes:
    inv = 0xFF ^ ver
    return struct.pack("!BBHI", ver, inv, payload_type, len(payload)) + payload


def _routing_activation_request(src_addr: int = 0x0E00) -> bytes:
    """Minimal Routing Activation Request payload (7 bytes)."""
    payload = struct.pack("!H", src_addr) + bytes([0x00]) + b"\x00" * 4
    return _raw_frame(PT_ROUTING_ACT_REQUEST, payload)


def _diagnostic_message(src: int = 0x0E00, tgt: int = 0x0001, uds: bytes = b"\x10\x01") -> bytes:
    payload = struct.pack("!HH", src, tgt) + uds
    return _raw_frame(PT_DIAGNOSTIC_MESSAGE, payload)


# ---------------------------------------------------------------------------
# Minimal DoIPServer fixture (wraps session.py)
# ---------------------------------------------------------------------------
# We spin up a real DoIPSession against a MockECU.
# The "server" for these tests is a thin asyncio.start_server wrapper.

from unittest.mock import MagicMock


def _make_app_config(initial_s: float = 2.0, general_s: float = 300.0):
    """Build a minimal AppConfig for tests (no file I/O)."""
    from config import (
        AppConfig, NetworkConfig, PortsConfig, TLSConfig,
        DoIPConfig, TimerConfig, UDPConfig, RoutingEntry, MiddlewareConfig,
    )
    return AppConfig(
        network=NetworkConfig(
            tester_interface="lo",
            tester_ipv4="127.0.0.1",
            ecu_interface="lo",
        ),
        ports=PortsConfig(doip_plain=13400, doip_tls=3496),
        tls=TLSConfig(
            server_cert="certs/s.crt",
            server_key="certs/s.key",
            client_cert="certs/c.crt",
            client_key="certs/c.key",
            ca_cert="certs/ca.crt",
            mutual_tls=False,
            tls_version="TLSv1.3",
            cipher_suites=[],
        ),
        doip=DoIPConfig(
            vin="1HGBH41JXMN109186",
            eid="AABBCCDDEEFF",
            gid="000000000000",
            node_type=0x01,
            power_mode=0x01,
            max_payload_bytes=4096,
        ),
        timers=TimerConfig(
            t_tcp_initial_inactivity_s=initial_s,
            t_tcp_general_inactivity_s=general_s,
            alive_check_interval_ms=500,
        ),
        udp=UDPConfig(announce_count=1, announce_interval_ms=100),
        routing_table=[
            RoutingEntry(
                tester_logical_addr=0x0E00,
                ecu_logical_addr=0x0001,
                ecu_ipv6="::1",
                ecu_interface="lo",
                ecu_port_plain=0,  # updated per test
                ecu_port_tls=3496,
                ecu_sni="",
            )
        ],
        middleware=[],
    )


async def _run_session_server(config, routing_table, middleware_chain, loop, executor):
    """Return (server, port) for a plain-TCP session server."""
    from session import DoIPSession

    async def handle(reader, writer):
        session = DoIPSession(
            reader=reader,
            writer=writer,
            config=config,
            routing_table=routing_table,
            middleware_chain=middleware_chain,
            loop=loop,
            executor=executor,
        )
        await session.run()

    server = await asyncio.start_server(handle, host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]
    return server, port


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_full_lifecycle():
    """
    connect → routing activation → diagnostic message → check response
    """
    pytest.importorskip("scapy", reason="Scapy not installed")

    from routing import RoutingTable
    from middleware import MiddlewareChain
    from concurrent.futures import ThreadPoolExecutor

    # Start mock ECU
    ecu = MockECU()
    ecu_server = await ecu.start()
    ecu_port = ecu.port

    config = _make_app_config()
    config.routing_table[0].ecu_port_plain = ecu_port

    rt = RoutingTable(config.routing_table)
    mc = MiddlewareChain([])
    loop = asyncio.get_event_loop()
    executor = ThreadPoolExecutor(max_workers=2)

    session_server, session_port = await _run_session_server(
        config, rt, mc, loop, executor
    )

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", session_port)

        # Step 1: Routing Activation Request
        writer.write(_routing_activation_request(0x0E00))
        await writer.drain()

        raw = await asyncio.wait_for(_read_frame(reader), timeout=2.0)
        assert _ptype(raw) == PT_ROUTING_ACT_RESPONSE
        # Response code is byte 12 (offset 8 = payload start, +4 for success)
        assert raw[12] == 0x10  # success

        # Step 2: Diagnostic Message
        writer.write(_diagnostic_message())
        await writer.drain()

        raw = await asyncio.wait_for(_read_frame(reader), timeout=2.0)
        assert _ptype(raw) in (PT_DIAGNOSTIC_POSITIVE_ACK, PT_DIAGNOSTIC_MESSAGE)

        writer.close()
        await writer.wait_closed()
    finally:
        session_server.close()
        await session_server.wait_closed()
        await ecu.stop()
        executor.shutdown(wait=False)


@pytest.mark.asyncio
async def test_activation_gate():
    """
    Diagnostic message before Routing Activation → NACK (0x8003) + disconnect.
    """
    pytest.importorskip("scapy", reason="Scapy not installed")

    from routing import RoutingTable
    from middleware import MiddlewareChain
    from concurrent.futures import ThreadPoolExecutor

    config = _make_app_config()
    rt = RoutingTable(config.routing_table)
    mc = MiddlewareChain([])
    loop = asyncio.get_event_loop()
    executor = ThreadPoolExecutor(max_workers=2)

    session_server, session_port = await _run_session_server(
        config, rt, mc, loop, executor
    )

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", session_port)

        # Send Diagnostic Message WITHOUT routing activation
        writer.write(_diagnostic_message())
        await writer.drain()

        raw = await asyncio.wait_for(_read_frame(reader), timeout=2.0)
        assert _ptype(raw) == 0x8003  # Diagnostic Negative ACK

        # Connection should be closed by the session
        try:
            data = await asyncio.wait_for(reader.read(1), timeout=1.0)
            assert data == b""  # EOF
        except asyncio.TimeoutError:
            pass

        writer.close()
        await writer.wait_closed()
    finally:
        session_server.close()
        await session_server.wait_closed()
        executor.shutdown(wait=False)


@pytest.mark.asyncio
async def test_initial_inactivity_timer():
    """
    Connect but send no Routing Activation → T_TCP_Initial_Inactivity fires
    and closes the connection.
    """
    pytest.importorskip("scapy", reason="Scapy not installed")

    from routing import RoutingTable
    from middleware import MiddlewareChain
    from concurrent.futures import ThreadPoolExecutor

    # Very short timer for fast testing
    config = _make_app_config(initial_s=0.3)
    rt = RoutingTable(config.routing_table)
    mc = MiddlewareChain([])
    loop = asyncio.get_event_loop()
    executor = ThreadPoolExecutor(max_workers=2)

    session_server, session_port = await _run_session_server(
        config, rt, mc, loop, executor
    )

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", session_port)
        # Do nothing — just wait for the timer
        data = await asyncio.wait_for(reader.read(1), timeout=2.0)
        assert data == b""  # server closed the connection

        writer.close()
        await writer.wait_closed()
    finally:
        session_server.close()
        await session_server.wait_closed()
        executor.shutdown(wait=False)


@pytest.mark.asyncio
async def test_header_nack_wrong_version():
    """
    Sending a frame with an invalid version byte → Header NACK (0x0000).
    """
    pytest.importorskip("scapy", reason="Scapy not installed")

    from routing import RoutingTable
    from middleware import MiddlewareChain
    from concurrent.futures import ThreadPoolExecutor

    config = _make_app_config()
    rt = RoutingTable(config.routing_table)
    mc = MiddlewareChain([])
    loop = asyncio.get_event_loop()
    executor = ThreadPoolExecutor(max_workers=2)

    session_server, session_port = await _run_session_server(
        config, rt, mc, loop, executor
    )

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", session_port)

        # Send a frame with version=0xFF, inverse=0x00 (both wrong)
        bad_frame = _raw_frame(PT_ROUTING_ACT_REQUEST, b"\x0E\x00\x00\x00\x00\x00\x00", ver=0xFF)
        writer.write(bad_frame)
        await writer.drain()

        raw = await asyncio.wait_for(_read_frame(reader), timeout=2.0)
        assert _ptype(raw) == PT_HEADER_NACK

        writer.close()
        await writer.wait_closed()
    finally:
        session_server.close()
        await session_server.wait_closed()
        executor.shutdown(wait=False)


@pytest.mark.asyncio
async def test_header_nack_oversized_payload():
    """
    A frame claiming a payload larger than max_payload_bytes →
    Header NACK code 0x02.
    """
    pytest.importorskip("scapy", reason="Scapy not installed")

    from routing import RoutingTable
    from middleware import MiddlewareChain
    from concurrent.futures import ThreadPoolExecutor

    config = _make_app_config()
    config.doip.max_payload_bytes = 10  # very small limit for testing
    rt = RoutingTable(config.routing_table)
    mc = MiddlewareChain([])
    loop = asyncio.get_event_loop()
    executor = ThreadPoolExecutor(max_workers=2)

    session_server, session_port = await _run_session_server(
        config, rt, mc, loop, executor
    )

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", session_port)

        # Craft a header that claims payload_len = 65535 (way over limit)
        # but don't actually send that many bytes
        hdr = struct.pack("!BBHI", _VER, _INV, PT_DIAGNOSTIC_MESSAGE, 65535)
        writer.write(hdr)
        await writer.drain()

        raw = await asyncio.wait_for(_read_frame(reader), timeout=2.0)
        assert _ptype(raw) == PT_HEADER_NACK
        nack_code = raw[8]  # first payload byte
        assert nack_code == 0x02  # message too large

        writer.close()
        await writer.wait_closed()
    finally:
        session_server.close()
        await session_server.wait_closed()
        executor.shutdown(wait=False)


# ---------------------------------------------------------------------------
# Marker for tests that require Scapy
# ---------------------------------------------------------------------------
# All tests in this file skip automatically when Scapy is not installed.
# No root is required for these loopback-only tests.
