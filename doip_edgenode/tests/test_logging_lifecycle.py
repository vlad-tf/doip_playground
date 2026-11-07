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
Logger middleware / LogSinkOwner lifecycle tests.

Exercises the per-canonical-path sink registry in middleware.logger: reference
ownership, borrowing, rotation bounds, truncation (hex and record), disabled
validation, and rollback of partially-built middleware/server sinks.  No Scapy
and no pytest-asyncio: coroutines are driven through asyncio.run() inside plain
sync test functions.  Ownership is never masked: the autouse fixture does not
pre-clear the registry, it only *reports* (and cleans up) sinks leaked by a
test after that test returns.
"""

from __future__ import annotations

import asyncio
import glob
import logging
import os

import pytest

# ---------------------------------------------------------------------------
# Fake DoIP packet — the middleware only needs payload_type/payload_length
# (via getattr) and bytes(pkt) for the hex dump.
# ---------------------------------------------------------------------------


class FakePacket:
    def __init__(self, payload_type: int = 0x8001, length=3, data: bytes = b""):
        self.payload_type = payload_type
        self.payload_length = length
        self._data = data

    def __bytes__(self) -> bytes:
        return self._data


def _process(mw, pkt=FakePacket(), direction: str = "tester_to_ecu"):
    """Run one packet through the middleware; return whatever process returns."""
    return asyncio.run(mw.process(pkt, direction, None))


def _log_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _flush(path: str) -> None:
    """Flush every handler on the canonical sink for `path`."""
    import middleware.logger as mwlogger

    lgr, _ = mwlogger._sinks[mwlogger._sink_path(path)]
    for handler in lgr.handlers:
        handler.flush()


# ---------------------------------------------------------------------------
# Fixture — surface (and clean up) leaked sinks instead of hiding them.
# No pre-clear: a test that forgets to close its owner must fail loudly.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_sink_leaks():
    import middleware.logger as mwlogger

    before = set(mwlogger._sinks)
    yield
    try:
        assert set(mwlogger._sinks) == before, _describe_leak(before, mwlogger._sinks)
    finally:
        # Clean up any newly-leaked keys even if the assertion above failed.
        for key in list(mwlogger._sinks):
            if key in before:
                continue
            lgr, _ = mwlogger._sinks.pop(key)
            for handler in list(lgr.handlers):
                lgr.removeHandler(handler)
                handler.close()


def _describe_leak(before: set, now: dict) -> str:
    leaked = sorted(set(now) - before)
    return f"LoggerMiddleware leaked sinks: {leaked}"


# ---------------------------------------------------------------------------
# Minimal AppConfig so DoIPServer can be constructed without Scapy.
# ---------------------------------------------------------------------------


def _server_config(middleware):
    from config import (
        AppConfig, NetworkConfig, PortsConfig, TLSConfig, DoIPConfig,
        TimerConfig, UDPConfig, RoutingEntry,
    )

    return AppConfig(
        network=NetworkConfig(
            tester_interface="lo", tester_ipv4="127.0.0.1", ecu_interface="lo"
        ),
        ports=PortsConfig(doip_plain=13400, doip_tls=3496),
        tls=TLSConfig(
            server_cert="certs/s.crt", server_key="certs/s.key",
            client_cert="certs/c.crt", client_key="certs/c.key",
            ca_cert="certs/ca.crt", mutual_tls=False, tls_version="TLSv1.3",
            cipher_suites=[],
        ),
        doip=DoIPConfig(
            vin="1HGBH41JXMN109186", eid="AABBCCDDEEFF", gid="000000000000",
            node_type=0x01, node_logical_addr=0x1234, power_mode=0x01,
            max_payload_bytes=4096,
        ),
        timers=TimerConfig(
            t_tcp_initial_inactivity_s=2.0, t_tcp_general_inactivity_s=300.0,
            alive_check_interval_ms=500,
        ),
        udp=UDPConfig(announce_count=1, announce_interval_ms=100),
        routing_table=[
            RoutingEntry(
                ecu_logical_addr=0x0001, ecu_ipv6="::1", ecu_interface="lo",
                ecu_port_plain=13400, ecu_port_tls=3496,
            )
        ],
        middleware=middleware,
    )


# ---------------------------------------------------------------------------
# Production policy constants
# ---------------------------------------------------------------------------


def test_production_policy_constants():
    import middleware.logger as mwlogger

    assert mwlogger._MAX_BYTES == 5 * 1024 * 1024
    assert mwlogger._BACKUP_COUNT == 3
    assert mwlogger._MAX_HEX_BYTES == 4096
    assert mwlogger._MAX_RECORD_BYTES == 16 * 1024


def test_real_rotation_backup_capped(monkeypatch, tmp_path):
    """With a tiny maxBytes, writes rotate; every retained file stays <= 512."""
    import middleware.logger as mwlogger

    cap = 512
    monkeypatch.setattr(mwlogger, "_MAX_BYTES", cap)
    path = str(tmp_path / "rot.log")
    mw = mwlogger.LoggerMiddleware(log_path=path, hex_dump=False)
    try:
        for _ in range(20):
            _process(mw, FakePacket(length=64))
        _flush(path)
    finally:
        mw.close()

    assert os.path.exists(path)
    backups = sorted(
        glob.glob(path + ".*"),
        key=lambda p: int(p.rsplit(".", 1)[1]),
    )
    assert 1 <= len(backups) <= mwlogger._BACKUP_COUNT
    for candidate in [path] + backups:
        assert os.path.getsize(candidate) <= cap


# ---------------------------------------------------------------------------
# Truncation
# ---------------------------------------------------------------------------


def test_large_hex_truncation_preserves_header(tmp_path):
    """Hex dump is capped at _MAX_HEX_BYTES; type/length and packet survive."""
    import middleware.logger as mwlogger

    path = str(tmp_path / "hex.log")
    mw = mwlogger.LoggerMiddleware(log_path=path, hex_dump=True)
    try:
        pkt = FakePacket(payload_type=0x0001, length=5000,
                         data=bytes(os.urandom(5000)))
        result = _process(mw, pkt)
        assert result is pkt  # packet passes through unchanged
        _flush(path)
    finally:
        mw.close()

    text = _log_text(path)
    assert "type=0x0001" in text
    assert "len=5000" in text
    assert "[truncated; 5000 total bytes]" in text
    assert "[record truncated]" not in text
    hex_region = text.split("\n  hex: ", 1)[1].split(" ... [truncated", 1)[0]
    assert len(hex_region.split()) == mwlogger._MAX_HEX_BYTES


def test_record_truncation_production_constants(tmp_path):
    """
    A record bloated by an oversized (unicode) payload_length field is capped
    at the real 16 KiB _MAX_RECORD_BYTES without monkeypatching any cap.
    """
    import middleware.logger as mwlogger

    path = str(tmp_path / "rec.log")
    mw = mwlogger.LoggerMiddleware(log_path=path, hex_dump=False)
    try:
        _process(mw, FakePacket(payload_type=0x8001, length="界" * 20000))
        _flush(path)
    finally:
        mw.close()

    text = _log_text(path)
    assert "type=0x8001" in text
    assert "[record truncated]" in text
    assert len(text.encode("utf-8")) <= mwlogger._MAX_RECORD_BYTES + 2


# ---------------------------------------------------------------------------
# Standalone ownership, aliasing, borrowing
# ---------------------------------------------------------------------------


def test_standalone_alias_paths_share_until_final_release(tmp_path):
    """Aliased paths share one sink; final standalone close detaches it."""
    import middleware.logger as mwlogger

    real = tmp_path / "aliased.log"
    path_a = str(real)
    path_b = str(tmp_path / "sub" / ".." / "aliased.log")

    sink_key = mwlogger._sink_path(path_a)
    assert sink_key == mwlogger._sink_path(path_b)

    mw_a = mwlogger.LoggerMiddleware(log_path=path_a)
    mw_b = mwlogger.LoggerMiddleware(log_path=path_b)
    file_h = mw_a._logger.handlers[0]
    assert mw_a._logger is mw_b._logger
    assert mwlogger._sinks[sink_key][1] == 2

    mw_a.close()
    assert sink_key in mwlogger._sinks
    assert len(mw_b._logger.handlers) == 2

    mw_b.close()
    assert sink_key not in mwlogger._sinks
    assert mw_a._logger.handlers == []
    assert file_h.stream is None  # file handle released, not leaked

    mw_c = mwlogger.LoggerMiddleware(log_path=path_a)
    try:
        assert mw_c._logger is not mw_a._logger
        assert sink_key in mwlogger._sinks
        assert len(mw_c._logger.handlers) == 2
    finally:
        mw_c.close()
    assert sink_key not in mwlogger._sinks


def test_standalone_close_idempotent(tmp_path):
    import middleware.logger as mwlogger

    path = str(tmp_path / "ido.log")
    mw = mwlogger.LoggerMiddleware(log_path=path)
    key = mwlogger._sink_path(path)
    mw.close()
    mw.close()  # must not raise
    assert key not in mwlogger._sinks
    assert mw._logger.handlers == []


def test_logger_registry_unchanged_distinct_path(tmp_path):
    """Directly-built sinks never touch logging's global logger registry."""
    import middleware.logger as mwlogger

    path = str(tmp_path / "dict.log")
    before = set(logging.Logger.manager.loggerDict)
    mw = mwlogger.LoggerMiddleware(log_path=path)
    try:
        assert mw._logger.name.startswith("doip.")
        _process(mw, FakePacket(length=7))
        _flush(path)
    finally:
        mw.close()
    assert set(logging.Logger.manager.loggerDict) == before


def test_borrower_close_does_not_close_owner(tmp_path):
    import middleware.logger as mwlogger

    path = str(tmp_path / "borrow.log")
    owner = mwlogger.LogSinkOwner()
    borrower = mwlogger.LoggerMiddleware(
        log_path=path, _sink_owner=owner, _open_sink=True
    )
    key = mwlogger._sink_path(path)
    try:
        assert not borrower._owns_sink
        assert owner._loggers[key] is borrower._logger
        borrower.close()
        assert key in mwlogger._sinks
        assert len(borrower._logger.handlers) == 2
    finally:
        owner.close()
    assert key not in mwlogger._sinks
    assert len(borrower._logger.handlers) == 0


def test_one_owner_many_borrowers_single_ref(tmp_path):
    """Borrowers never add refs; the owner holds exactly one lease."""
    import middleware.logger as mwlogger

    path = str(tmp_path / "mborrow.log")
    owner = mwlogger.LogSinkOwner()
    borrowers = [
        mwlogger.LoggerMiddleware(log_path=path, _sink_owner=owner, _open_sink=True)
        for _ in range(5)
    ]
    key = mwlogger._sink_path(path)
    try:
        assert all(b._logger is borrowers[0]._logger for b in borrowers)
        assert mwlogger._sinks[key][1] == 1
    finally:
        owner.close()
    assert key not in mwlogger._sinks
    for b in borrowers:
        assert len(b._logger.handlers) == 0


def test_closed_borrower_path_reopens_fresh_logger(tmp_path):
    """After an owner is closed, the path cannot reattach the old logger."""
    import middleware.logger as mwlogger

    path = str(tmp_path / "reopen.log")
    key = mwlogger._sink_path(path)
    owner = mwlogger.LogSinkOwner()
    borrower = mwlogger.LoggerMiddleware(
        log_path=path, _sink_owner=owner, _open_sink=True
    )
    closed = borrower._logger
    owner.close()

    assert key not in mwlogger._sinks
    assert closed.handlers == []  # old logger fully torn down

    reopened = mwlogger.LoggerMiddleware(log_path=path)
    try:
        assert reopened._logger is not closed
        assert len(reopened._logger.handlers) == 2
        assert reopened._logger.handlers[0].stream is not None
    finally:
        reopened.close()
    assert key not in mwlogger._sinks


def test_log_sink_owner_many_paths_close_empties_registry(tmp_path):
    import middleware.logger as mwlogger

    owner = mwlogger.LogSinkOwner()
    paths = [str(tmp_path / f"d{i}.log") for i in range(6)]
    loggers = [owner.acquire(p) for p in paths]
    for key, expected in zip((mwlogger._sink_path(p) for p in paths), loggers):
        assert mwlogger._sinks[key][0] is expected
    assert len(mwlogger._sinks) == len(paths)
    owner.close()
    assert mwlogger._sinks == {}
    for lgr in loggers:
        assert len(lgr.handlers) == 0


def test_close_after_close_is_noop():
    import middleware.logger as mwlogger

    owner = mwlogger.LogSinkOwner()
    owner.close()
    owner.close()  # idempotent, no handler teardown attempted
    assert mwlogger._sinks == {}


# ---------------------------------------------------------------------------
# Factory / server rollback + validation
# ---------------------------------------------------------------------------


def test_factory_disabled_opens_no_sink_but_validates(tmp_path):
    from config import MiddlewareConfig
    from server import _build_middleware
    import middleware.logger as mwlogger

    path = str(tmp_path / "never.log")
    before = set(mwlogger._sinks)
    _build_middleware([
        MiddlewareConfig("LoggerMiddleware", enabled=False,
                         params={"log_path": path}),
    ])
    assert set(mwlogger._sinks) == before
    assert not os.path.exists(path)


def test_factory_disabled_invalid_log_path_fails(tmp_path):
    from config import MiddlewareConfig
    from server import _build_middleware

    with pytest.raises(ValueError, match="log_path"):
        _build_middleware([
            MiddlewareConfig("LoggerMiddleware", enabled=False,
                             params={"log_path": "   "}),
        ])


def test_partial_factory_unknown_rollback(tmp_path):
    from config import MiddlewareConfig, ConfigError
    from server import _build_middleware
    import middleware.logger as mwlogger

    path = str(tmp_path / "rollback.log")
    with pytest.raises(ConfigError, match="unknown type"):
        _build_middleware([
            MiddlewareConfig("LoggerMiddleware", params={"log_path": path}),
            MiddlewareConfig("NoSuchMiddleware", params={}),
        ])
    assert mwlogger._sinks == {}


def test_partial_server_header_invalid_rollback(tmp_path):
    from config import MiddlewareConfig
    from server import DoIPServer
    import middleware.logger as mwlogger

    path = str(tmp_path / "srv_rollback.log")
    config = _server_config([
        MiddlewareConfig("LoggerMiddleware", params={"log_path": path}),
        MiddlewareConfig("HeaderFaultMiddleware",
                         params={"fault": "invalid_mode"}),
    ])
    with pytest.raises(ValueError, match="unknown fault"):
        DoIPServer(config)
    assert mwlogger._sinks == {}


def test_server_executor_construction_failure_releases(tmp_path, monkeypatch):
    """If the executor thread pool construction fails, owned sinks release."""
    from config import MiddlewareConfig
    from server import DoIPServer
    import middleware.logger as mwlogger

    path = str(tmp_path / "exec.log")
    config = _server_config([
        MiddlewareConfig("LoggerMiddleware", params={"log_path": path}),
    ])

    def _boom(*args, **kwargs):
        raise OSError("executor fail")

    monkeypatch.setattr("server.ThreadPoolExecutor", _boom)
    with pytest.raises(OSError, match="executor fail"):
        DoIPServer(config)
    assert mwlogger._sinks == {}


def test_server_rollback_preserves_other_owner_same_path(tmp_path, monkeypatch):
    """A failed build on a path another server owns keeps that owner intact."""
    from config import MiddlewareConfig
    from server import DoIPServer
    import middleware.logger as mwlogger

    path = str(tmp_path / "shared.log")
    config = _server_config([
        MiddlewareConfig("LoggerMiddleware", params={"log_path": path}),
    ])
    server_a = DoIPServer(config)  # acquires the path (ref=1)
    key = mwlogger._sink_path(path)
    sink_a = server_a._log_sink_owner._loggers[key]

    def _boom(*args, **kwargs):
        raise OSError("executor fail")

    monkeypatch.setattr("server.ThreadPoolExecutor", _boom)
    with pytest.raises(OSError, match="executor fail"):
        DoIPServer(config)  # bumps ref to 2, then rolls back to 1
    assert mwlogger._sinks[key][1] == 1
    assert mwlogger._sinks[key][0] is sink_a
    assert len(sink_a.handlers) == 2  # server A's sink untouched

    sink_a.debug("still alive")
    _flush(path)
    assert "still alive" in _log_text(path)
    assert set(mwlogger._sinks) == {key}

    asyncio.run(server_a.stop())
    assert key not in mwlogger._sinks


def test_repeated_servers_same_path_stop_one_preserves_other(tmp_path):
    from config import MiddlewareConfig
    from server import DoIPServer
    import middleware.logger as mwlogger

    path = str(tmp_path / "srv.log")
    config = _server_config([
        MiddlewareConfig("LoggerMiddleware", params={"log_path": path}),
    ])
    server_a = DoIPServer(config)
    server_b = DoIPServer(config)

    key = mwlogger._sink_path(path)
    shared = server_b._log_sink_owner._loggers[key]
    assert server_a._log_sink_owner._loggers[key] is shared
    assert mwlogger._sinks[key][1] == 2

    asyncio.run(server_a.stop())
    assert key in mwlogger._sinks
    assert mwlogger._sinks[key][1] == 1
    assert len(shared.handlers) == 2

    asyncio.run(server_b.stop())
    assert key not in mwlogger._sinks
    assert len(shared.handlers) == 0


def test_single_server_stop_closes_owned_sinks(tmp_path):
    from config import MiddlewareConfig
    from server import DoIPServer
    import middleware.logger as mwlogger

    path = str(tmp_path / "owned.log")
    config = _server_config([
        MiddlewareConfig("LoggerMiddleware", params={"log_path": path}),
    ])
    server = DoIPServer(config)
    key = mwlogger._sink_path(path)
    sink = server._log_sink_owner._loggers[key]
    assert key in mwlogger._sinks
    assert len(sink.handlers) == 2

    asyncio.run(server.stop())
    assert key not in mwlogger._sinks
    assert len(sink.handlers) == 0


# ---------------------------------------------------------------------------
# File/stream handler failure rollback
# ---------------------------------------------------------------------------


def test_file_handler_creation_failure_leaves_no_registry(tmp_path, monkeypatch):
    import middleware.logger as mwlogger

    class _BoomFile(logging.handlers.RotatingFileHandler):
        def __init__(self, path, maxBytes=None, backupCount=None, encoding=None):
            raise OSError("cannot open log")

    monkeypatch.setattr(
        "middleware.logger.logging.handlers.RotatingFileHandler", _BoomFile
    )
    with pytest.raises(OSError, match="cannot open log"):
        mwlogger.LoggerMiddleware(log_path=str(tmp_path / "boom.log"))
    assert mwlogger._sinks == {}


def test_stream_handler_failure_closes_created_file_handler(tmp_path, monkeypatch):
    """If StreamHandler construction fails, the already-created file handler is closed."""
    import middleware.logger as mwlogger

    created_files = []

    class _TrackingFile(logging.Handler):
        def __init__(self, path, maxBytes=None, backupCount=None, encoding=None):
            super().__init__()
            self.close_called = False
            created_files.append(self)

        def close(self):
            self.close_called = True
            super().close()

    class _FailingStream(logging.StreamHandler):
        def __init__(self, *args, **kwargs):
            raise OSError("no stream")

    monkeypatch.setattr(
        "middleware.logger.logging.handlers.RotatingFileHandler", _TrackingFile
    )
    monkeypatch.setattr("middleware.logger.logging.StreamHandler", _FailingStream)

    path = str(tmp_path / "track.log")
    with pytest.raises(OSError, match="no stream"):
        mwlogger.LoggerMiddleware(log_path=path)

    assert len(created_files) == 1
    assert created_files[0].close_called
    assert mwlogger._sinks == {}