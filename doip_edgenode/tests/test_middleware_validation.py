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

"""F11 validation and wire-level middleware regression tests."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from scapy.contrib.automotive.doip import DoIP

from config import ConfigError, MiddlewareConfig, _load_middleware
from middleware.address import AddressMiddleware
from middleware.corrupt import CorruptMiddleware
from middleware.delay import DelayMiddleware
from middleware.header_fault import HeaderFaultMiddleware
from server import DoIPServer, _build_middleware
from tests.test_session import _make_app_config


BAD_NUMBERS = [True, False, 1.5, float("nan"), float("inf"), [], "bad"]


@pytest.mark.parametrize("cls, name", [
    (CorruptMiddleware, "byte_offset"), (CorruptMiddleware, "flip_mask"),
    (AddressMiddleware, "src_override"), (AddressMiddleware, "tgt_override"),
    (DelayMiddleware, "delay_ms"), (DelayMiddleware, "jitter_ms"),
])
def test_constructor_rejects_bad_numeric_values(cls, name):
    for value in BAD_NUMBERS:
        with pytest.raises(ValueError, match=name):
            cls(**{name: value})


@pytest.mark.parametrize("cls, kwargs", [
    (CorruptMiddleware, {"byte_offset": -1}),
    (CorruptMiddleware, {"flip_mask": -1}),
    (CorruptMiddleware, {"flip_mask": 256}),
    (AddressMiddleware, {"src_override": -1}),
    (AddressMiddleware, {"tgt_override": 65536}),
    (DelayMiddleware, {"jitter_ms": -1}),
])
def test_constructor_rejects_out_of_bounds(cls, kwargs):
    with pytest.raises(ValueError, match=next(iter(kwargs))):
        cls(**kwargs)


def test_constructor_accepts_bounds_strings_and_none():
    assert CorruptMiddleware(byte_offset=None, flip_mask="0xff").flip_mask == 255
    assert CorruptMiddleware(byte_offset="0", flip_mask="255").byte_offset == 0
    assert AddressMiddleware(src_override="0", tgt_override="0xffff").tgt_override == 65535
    assert AddressMiddleware().src_override is None
    assert DelayMiddleware(delay_ms="0", jitter_ms="0x0").jitter_ms == 0


@pytest.mark.parametrize("kwargs", [
    {"inject_on_nth": True}, {"inject_on_nth": 0},
    {"inject_on_nth": 1.5}, {"inject_on_nth": float("nan")},
    {"inject_on_nth": float("inf")}, {"inject_on_nth": []},
    {"inject_on_nth": "bad"},
])
def test_header_constructor_validates_nth(kwargs):
    with pytest.raises(ValueError, match="inject_on_nth"):
        HeaderFaultMiddleware(**kwargs)


@pytest.mark.parametrize("direction", ["invalid", None, 1, True])
def test_header_constructor_validates_direction(direction):
    with pytest.raises(ValueError, match="direction"):
        HeaderFaultMiddleware(direction=direction)


def test_header_constructor_defaults_and_accepts_valid_direction():
    assert HeaderFaultMiddleware().fault == "wrong_version"
    assert HeaderFaultMiddleware(inject_on_nth="0x2", direction="both").inject_on_nth == 2


@pytest.mark.parametrize("raw", [
    {"type": "CorruptMiddleware", "byte_offset": -1},
    {"type": "CorruptMiddleware", "flip_mask": 256},
    {"type": "AddressMiddleware", "src_override": 65536},
    {"type": "DelayMiddleware", "delay_ms": -1},
    {"type": "HeaderFaultMiddleware", "inject_on_nth": 0},
    {"type": "HeaderFaultMiddleware", "direction": "nope"},
])
def test_loader_rejects_bad_input_with_index_and_parameter(raw):
    with pytest.raises(ConfigError, match=r"middleware\[3\].*(byte_offset|flip_mask|src_override|delay_ms|inject_on_nth|direction)"):
        _load_middleware([{"type": "DelayMiddleware"}] * 3 + [raw])


def test_loader_accepts_defaults_and_numeric_strings():
    result = _load_middleware([
        {"type": "HeaderFaultMiddleware"},
        {"type": "CorruptMiddleware", "byte_offset": "0x0", "flip_mask": "255"},
        {"type": "AddressMiddleware", "src_override": "0", "tgt_override": "0xffff"},
        {"type": "DelayMiddleware", "delay_ms": "0", "jitter_ms": "0x0"},
    ])
    assert result[0].params == {}
    assert result[1].params["flip_mask"] == 255


@pytest.mark.parametrize("enabled", [True, False])
def test_unknown_factory_type_is_config_error_even_when_disabled(enabled):
    with pytest.raises(ConfigError, match="middleware.*unknown"):
        _build_middleware([MiddlewareConfig("NotAMiddleware", enabled=enabled)])


def test_unknown_type_fails_doip_server_startup():
    config = _make_app_config()
    config.middleware = [MiddlewareConfig("NotAMiddleware", enabled=False)]
    with pytest.raises(ConfigError, match="middleware.*unknown"):
        DoIPServer(config)


def diagnostic_packet(source=0x0E00, target=0x0001, payload=b"\x22\xf1\x90"):
    body = source.to_bytes(2, "big") + target.to_bytes(2, "big") + payload
    return DoIP(b"\x02\xfd\x80\x01" + len(body).to_bytes(4, "big") + body)


@pytest.mark.parametrize("offset, mask", [(0, 0xFF), ("0x1", "1")])
def test_corrupt_real_scapy_bytes_preserves_header_and_flips_payload(offset, mask):
    pkt = diagnostic_packet()
    original = bytes(pkt)
    result = asyncio.run(
        CorruptMiddleware(byte_offset=offset, flip_mask=mask).process(pkt, "tester_to_ecu", None)
    )
    assert bytes(result)[:8] == original[:8]
    index = int(offset, 0) if isinstance(offset, str) else offset
    value = int(mask, 0) if isinstance(mask, str) else mask
    expected = bytearray(original)
    expected[8 + index] ^= value
    assert bytes(result) == bytes(expected)
    assert bytes(pkt) == original


def test_corrupt_positive_offset_outside_frame_skips():
    pkt = diagnostic_packet()
    with patch("middleware.corrupt.random.randint") as randint:
        result = asyncio.run(CorruptMiddleware(byte_offset=99).process(pkt, "tester_to_ecu", None))
    assert result is pkt
    randint.assert_not_called()


def test_corrupt_none_uses_random_payload_offset():
    pkt = diagnostic_packet()
    with patch("middleware.corrupt.random.randint", return_value=1) as randint:
        result = asyncio.run(CorruptMiddleware(byte_offset=None, flip_mask=1).process(pkt, "tester_to_ecu", None))
    randint.assert_called_once_with(0, 6)
    assert bytes(result)[9] == bytes(pkt)[9] ^ 1


def test_address_real_scapy_bytes_allows_reserved_zero_and_preserves_payload():
    pkt = diagnostic_packet()
    original_payload = bytes(pkt)[12:]
    result = asyncio.run(AddressMiddleware(src_override=0, tgt_override=0).process(pkt, "tester_to_ecu", None))
    raw = bytes(result)
    assert raw[8:12] == b"\x00\x00\x00\x00"
    assert raw[12:] == original_payload


def test_header_default_fault_serializes_without_mutating_original():
    pkt = diagnostic_packet()
    original = bytes(pkt)
    result = asyncio.run(HeaderFaultMiddleware().process(pkt, "tester_to_ecu", None))
    assert bytes(result)[0] == 0xFF
    assert bytes(result)[1:] == original[1:]
    assert bytes(pkt) == original


def test_delay_uses_fixed_delay_plus_patched_jitter():
    async def scenario():
        with patch("middleware.delay.random.randint", return_value=7) as randint, patch(
            "middleware.delay.asyncio.sleep", new_callable=AsyncMock
        ) as sleep:
            pkt = diagnostic_packet()
            assert await DelayMiddleware(delay_ms=10, jitter_ms=20).process(pkt, "tester_to_ecu", None) is pkt
            randint.assert_called_once_with(0, 20)
            sleep.assert_awaited_once_with(0.017)
    asyncio.run(scenario())


@pytest.mark.parametrize("mw_type,name", [
    ("CorruptMiddleware", "byte_offset"), ("CorruptMiddleware", "flip_mask"),
    ("AddressMiddleware", "src_override"), ("AddressMiddleware", "tgt_override"),
    ("DelayMiddleware", "delay_ms"), ("DelayMiddleware", "jitter_ms"),
    ("HeaderFaultMiddleware", "inject_on_nth"),
])
def test_loader_rejects_noninteger_values(mw_type, name):
    for value in BAD_NUMBERS:
        with pytest.raises(ConfigError, match=rf"middleware\[0\].*{name}"):
            _load_middleware([{"type": mw_type, name: value}])


@pytest.mark.parametrize("enabled", [True, False])
def test_unknown_loader_type_is_config_error(enabled):
    with pytest.raises(ConfigError, match=r"middleware\[0\].*unknown"):
        _load_middleware([{"type": "NotAMiddleware", "enabled": enabled}])


@pytest.mark.parametrize("mw_type,name,value", [
    ("CorruptMiddleware", "flip_mask", -1),
    ("AddressMiddleware", "src_override", -1),
    ("AddressMiddleware", "tgt_override", -1),
    ("AddressMiddleware", "tgt_override", 65536),
    ("DelayMiddleware", "jitter_ms", -1),
    ("CorruptMiddleware", "flip_mask", None),
    ("DelayMiddleware", "delay_ms", None),
    ("HeaderFaultMiddleware", "inject_on_nth", None),
])
def test_loader_rejects_remaining_bounds_and_required_nulls(mw_type, name, value):
    with pytest.raises(ConfigError, match=rf"middleware\[0\].*{name}"):
        _load_middleware([{"type": mw_type, name: value}])


@pytest.mark.parametrize("mask", [0, 255])
def test_corrupt_mask_boundaries(mask):
    pkt = diagnostic_packet()
    original = bytes(pkt)
    result = asyncio.run(CorruptMiddleware(byte_offset=6, flip_mask=mask).process(
        pkt, "tester_to_ecu", None
    ))
    assert bytes(result) == original[:-1] + bytes([original[-1] ^ mask])


def test_address_upper_bound_serializes():
    pkt = diagnostic_packet()
    result = asyncio.run(AddressMiddleware(src_override=65535, tgt_override=65535).process(
        pkt, "tester_to_ecu", None
    ))
    assert bytes(result)[8:12] == b"\xff" * 4


@pytest.mark.parametrize("value,expected", [("08", 8), ("0008", 8), ("0Xff", 255)])
def test_zero_padded_decimal_and_hex_strings(value, expected):
    assert CorruptMiddleware(flip_mask=value).flip_mask == expected
    assert AddressMiddleware(src_override=value).src_override == expected
    assert DelayMiddleware(delay_ms=value).delay_ms == expected
    assert HeaderFaultMiddleware(inject_on_nth=value).inject_on_nth == expected
    loaded = _load_middleware([{"type": "DelayMiddleware", "delay_ms": value}])
    assert loaded[0].params["delay_ms"] == expected
