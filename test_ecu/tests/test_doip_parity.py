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
Guard against drift from the echo ECU's DoIP layer.

``testecu/doip.py`` is a copy of the framing code in ``echo_ecu/echo_ecu.py``
— deliberately, because the two run as separate Docker images with separate
single-directory build contexts.  This module is the tripwire: if either side's
framing changes, these assertions fail and somebody has to decide on purpose.

Skipped when ``echo_ecu/`` is not present (it is not copied into the TestEcu
Docker image).
"""

from __future__ import annotations

import importlib.util
import os
import sys

import pytest

from testecu import doip

ECHO_ECU = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "echo_ecu", "echo_ecu.py",
)

pytestmark = pytest.mark.skipif(
    not os.path.isfile(ECHO_ECU),
    reason="echo_ecu/echo_ecu.py is not available here",
)


def load_echo_ecu():
    spec = importlib.util.spec_from_file_location("_echo_ecu_parity", ECHO_ECU)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_echo_ecu_parity"] = module
    spec.loader.exec_module(module)
    return module


PAYLOAD_TYPE_NAMES = [
    "PT_HEADER_NACK", "PT_VEHICLE_ID_REQUEST", "PT_VEHICLE_ID_RESPONSE",
    "PT_ROUTING_ACT_REQUEST", "PT_ROUTING_ACT_RESPONSE",
    "PT_ALIVE_CHECK_REQUEST", "PT_ALIVE_CHECK_RESPONSE",
    "PT_ENTITY_STATUS_REQUEST", "PT_ENTITY_STATUS_RESPONSE",
    "PT_POWER_MODE_REQUEST", "PT_POWER_MODE_RESPONSE",
    "PT_DIAGNOSTIC_MESSAGE", "PT_DIAGNOSTIC_POSITIVE_ACK",
]


def test_payload_type_constants_match():
    echo = load_echo_ecu()
    for name in PAYLOAD_TYPE_NAMES:
        assert getattr(doip, name) == getattr(echo, name), name


def test_protocol_version_matches():
    echo = load_echo_ecu()
    assert doip.VER == echo._VER
    assert doip.INV == echo._INV
    assert doip.DOIP_MCAST_ADDR == echo._DOIP_MCAST_ADDR
    assert doip.ALIVE_PROBE_TIMEOUT_S == echo._ALIVE_PROBE_TIMEOUT_S


@pytest.mark.parametrize("payload_type", [0x0000, 0x0005, 0x4001, 0x8001])
@pytest.mark.parametrize("payload", [b"", b"\x00", b"\x01\x02\x03\x04", b"\xFF" * 64])
def test_build_frame_is_byte_identical(payload_type, payload):
    echo = load_echo_ecu()
    assert doip.build_frame(payload_type, payload) == echo._build(payload_type, payload)


def test_frame_accessors_agree():
    echo = load_echo_ecu()
    raw = doip.build_frame(0x8001, b"\x0E\x00\x00\x02\x22\xF1\x90")
    assert doip.ptype(raw) == echo._ptype(raw)
    assert doip.payload(raw) == echo._payload(raw)


def test_hex_formatting_agrees():
    echo = load_echo_ecu()
    for data in (b"", b"\x00\x01", bytes(range(40))):
        assert doip.fmt_hex(data) == echo._fmt_hex(data)
