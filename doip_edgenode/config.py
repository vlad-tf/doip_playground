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
DoIP EdgeNode — Configuration loader and dataclasses.

All configuration is read from a single config.yaml file. No values are
hardcoded here; every default is documented by its yaml counterpart.
"""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass, field
from typing import Optional

import yaml


class ConfigError(Exception):
    """Raised for invalid or missing configuration values."""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class NetworkConfig:
    tester_interface: str
    tester_ipv4: str
    ecu_interface: str


@dataclass
class PortsConfig:
    doip_plain: int
    doip_tls: int


@dataclass
class TLSConfig:
    server_cert: str
    server_key: str
    client_cert: str
    client_key: str
    ca_cert: str
    mutual_tls: bool
    tls_version: str
    cipher_suites: list[str]


#: Default accepted tester (client) logical address range, used when
#: doip.tester_addr_range is absent from config.yaml. Matches VirtualEcu's
#: TESTER_ADDR_RANGE (virtecu/doip.py) — ISO 13400-2 Table 13's example
#: tester address range.
DEFAULT_TESTER_ADDR_RANGE: tuple[int, int] = (0x0E00, 0x0FFF)

#: Default for doip.node_logical_addr (EdgeNode's own address) when absent
#: from config.yaml. 0x0000 is ISO/SAE reserved (ISO 13400-2) and must never
#: be assigned to a real node, so this is a real address, not a sentinel —
#: 0x1234, a deliberately high value in the VM-specific range, distinct from
#: the low ECU addresses (0x0002/0x0003) and the tester range (0x0E00-0x0FFF).
DEFAULT_NODE_LOGICAL_ADDR = 0x1234


@dataclass
class DoIPConfig:
    vin: str
    eid: str
    gid: str
    node_type: int
    node_logical_addr: int   # EdgeNode's own logical address, used in UDP announcements
    power_mode: int
    max_payload_bytes: int
    #: Accepted tester (client) source addresses for Routing Activation (ISO
    #: 13400-2 Table 13) — a source address matching neither is denied with
    #: response code 0x00. The two combine with OR (see is_tester_allowed()):
    #:   tester_addr_range: inclusive [low, high] contiguous block
    #:   tester_addr_list:  explicit individual addresses outside that block
    tester_addr_range: tuple[int, int] = DEFAULT_TESTER_ADDR_RANGE
    tester_addr_list: tuple[int, ...] = ()

    def is_tester_allowed(self, addr: int) -> bool:
        low, high = self.tester_addr_range
        if low <= addr <= high:
            return True
        return addr in self.tester_addr_list


@dataclass
class TimerConfig:
    t_tcp_initial_inactivity_s: float
    t_tcp_general_inactivity_s: float
    alive_check_interval_ms: int
    #: Per-frame wait, including the first ECU ACK. After matching pending,
    #: retry within the total budget. Also bounds retired-leg close waits.
    ecu_response_timeout_s: float = 2.0
    #: Whole exchange budget from send (excluding connect/RA), including ACK
    #: and any matching ResponsePending chain; never reset by pending frames.
    ecu_pending_max_wait_s: float = 30.0
    #: Drop an ECU response whose service id does not answer the request that
    #: is in flight.  Without this a desynchronised stream silently delivers a
    #: well-formed response to the wrong request.
    strict_response_matching: bool = True


@dataclass
class UDPConfig:
    announce_count: int
    announce_interval_ms: int


@dataclass
class RoutingEntry:
    ecu_logical_addr: int
    ecu_ipv6: str
    ecu_interface: str
    ecu_port_plain: int
    ecu_port_tls: int
    ecu_sni: str = ""  # empty → omit SNI


@dataclass
class MiddlewareConfig:
    type: str
    enabled: bool = True
    params: dict = field(default_factory=dict)


@dataclass
class AppConfig:
    network: NetworkConfig
    ports: PortsConfig
    tls: TLSConfig
    doip: DoIPConfig
    timers: TimerConfig
    udp: UDPConfig
    routing_table: list[RoutingEntry]
    middleware: list[MiddlewareConfig]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mapping(value, path: str) -> dict:
    if not isinstance(value, dict):
        raise ConfigError(f"{path} must be a mapping; got {type(value).__name__}")
    if any(not isinstance(key, str) for key in value):
        raise ConfigError(f"{path} must contain only string keys")
    return value


def _strict_bool(value, path: str) -> bool:
    if type(value) is not bool:
        raise ConfigError(f"{path} must be a boolean; got {value!r}")
    return value


def _string(value, path: str, *, nonempty: bool = False) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{path} must be a string; got {type(value).__name__}")
    if nonempty and not value.strip():
        raise ConfigError(f"{path} must be a non-empty string")
    return value


def _to_int(value, field_name: str) -> int:
    """Convert a strict integer, accepting decimal and 0x strings."""
    if type(value) is int:
        return value
    if isinstance(value, str):
        try:
            text = value.strip()
            base = 16 if text.lstrip("+-").lower().startswith("0x") else 10
            return int(text, base)
        except (OverflowError, ValueError):
            raise ConfigError(
                f"Field '{field_name}' must be an integer or hex string, got: {value!r}"
            )
    raise ConfigError(
        f"Field '{field_name}' must be an integer or hex string, got: {type(value).__name__}"
    )


def _require(mapping: dict, key: str, section: str):
    if key not in mapping:
        raise ConfigError(f"Missing required config key '{key}' in section '{section}'")
    return mapping[key]


def _to_int_list(value, field_name: str) -> list[int]:
    """Convert a YAML list of ints/hex-strings to a list[int]."""
    if not isinstance(value, list):
        raise ConfigError(
            f"Field '{field_name}' must be a list, got: {type(value).__name__}"
        )
    return [_to_int(item, f"{field_name}[{i}]") for i, item in enumerate(value)]


def _bounded(value, path: str, minimum: int, maximum: int | None = None) -> int:
    result = _to_int(value, path)
    if result < minimum or (maximum is not None and result > maximum):
        bounds = f"[{minimum}, {maximum}]" if maximum is not None else f">= {minimum}"
        raise ConfigError(f"{path} must be {bounds}; got {value!r}")
    return result


def _positive_number(value, path: str) -> float:
    if isinstance(value, bool):
        raise ConfigError(f"{path} must be a finite positive number")
    try:
        result = float(value) if isinstance(value, (int, float, str)) else None
    except (OverflowError, TypeError, ValueError):
        result = None
    if result is None or not math.isfinite(result) or result <= 0:
        raise ConfigError(f"{path} must be a finite positive number; got {value!r}")
    return result


def _nonnegative_number(value, path: str) -> float:
    if isinstance(value, bool):
        raise ConfigError(f"{path} must be a finite nonnegative number")
    try:
        result = float(value) if isinstance(value, (int, float, str)) else None
    except (OverflowError, TypeError, ValueError):
        result = None
    if result is None or not math.isfinite(result) or result < 0:
        raise ConfigError(f"{path} must be a finite nonnegative number; got {value!r}")
    return result


def _ipv4(value, path: str) -> str:
    text = _string(value, path, nonempty=True)
    try:
        if ipaddress.ip_address(text).version != 4:
            raise ValueError
    except ValueError as exc:
        raise ConfigError(f"{path} must be an IPv4 address; got {value!r}") from exc
    return text


def _ipv6(value, path: str) -> str:
    text = _string(value, path, nonempty=True)
    try:
        ipaddress.IPv6Address(text)
    except ValueError as exc:
        raise ConfigError(f"{path} must be an IPv6 address; got {value!r}") from exc
    return text


# ---------------------------------------------------------------------------
# Loaders for each config section
# ---------------------------------------------------------------------------


def _load_network(raw: dict) -> NetworkConfig:
    sec = "network"
    return NetworkConfig(
        tester_interface=_string(
            _require(raw, "tester_interface", sec),
            "network.tester_interface",
            nonempty=True,
        ),
        tester_ipv4=_ipv4(_require(raw, "tester_ipv4", sec), "network.tester_ipv4"),
        ecu_interface=_string(
            _require(raw, "ecu_interface", sec),
            "network.ecu_interface",
            nonempty=True,
        ),
    )


def _load_ports(raw: dict) -> PortsConfig:
    return PortsConfig(
        doip_plain=_bounded(
            _require(raw, "doip_plain", "ports"), "ports.doip_plain", 1, 65535
        ),
        doip_tls=_bounded(
            _require(raw, "doip_tls", "ports"), "ports.doip_tls", 1, 65535
        ),
    )


def _load_tls(raw: dict) -> TLSConfig:
    sec = "tls"
    version = _string(_require(raw, "tls_version", sec), "tls.tls_version")
    if version != "TLSv1.3":
        raise ConfigError("tls.tls_version must be 'TLSv1.3'")

    suites = raw.get("cipher_suites", [])
    if not isinstance(suites, list):
        raise ConfigError("tls.cipher_suites must be a list")
    cipher_suites = [
        _string(value, f"tls.cipher_suites[{index}]", nonempty=True)
        for index, value in enumerate(suites)
    ]
    return TLSConfig(
        server_cert=_string(_require(raw, "server_cert", sec), "tls.server_cert", nonempty=True),
        server_key=_string(_require(raw, "server_key", sec), "tls.server_key", nonempty=True),
        client_cert=_string(_require(raw, "client_cert", sec), "tls.client_cert", nonempty=True),
        client_key=_string(_require(raw, "client_key", sec), "tls.client_key", nonempty=True),
        ca_cert=_string(_require(raw, "ca_cert", sec), "tls.ca_cert", nonempty=True),
        mutual_tls=_strict_bool(raw.get("mutual_tls", True), "tls.mutual_tls"),
        tls_version=version,
        cipher_suites=cipher_suites,
    )


def _load_doip(raw: dict) -> DoIPConfig:
    sec = "doip"
    vin = _string(_require(raw, "vin", sec), "doip.vin")
    if len(vin) != 17 or not vin.isascii():
        raise ConfigError("doip.vin must be exactly 17 ASCII characters")

    values = {}
    for name in ("eid", "gid"):
        value = _string(_require(raw, name, sec), f"doip.{name}")
        if len(value) != 12 or any(char not in "0123456789abcdefABCDEF" for char in value):
            raise ConfigError(f"doip.{name} must be exactly 12 hex characters")
        values[name] = value

    bounds = _to_int_list(
        raw.get("tester_addr_range", list(DEFAULT_TESTER_ADDR_RANGE)),
        "doip.tester_addr_range",
    )
    if len(bounds) != 2 or not 0 <= bounds[0] <= bounds[1] <= 0xFFFF:
        raise ConfigError(
            "doip.tester_addr_range must be an ascending pair in [0, 65535]"
        )
    addresses = _to_int_list(raw.get("tester_addr_list", []), "doip.tester_addr_list")
    if any(not 0 <= value <= 0xFFFF for value in addresses):
        raise ConfigError("doip.tester_addr_list values must be in [0, 65535]")

    return DoIPConfig(
        vin=vin,
        eid=values["eid"],
        gid=values["gid"],
        node_type=_bounded(_require(raw, "node_type", sec), "doip.node_type", 0, 1),
        node_logical_addr=_bounded(
            raw.get("node_logical_addr", DEFAULT_NODE_LOGICAL_ADDR),
            "doip.node_logical_addr",
            1,
            65535,
        ),
        power_mode=_bounded(_require(raw, "power_mode", sec), "doip.power_mode", 0, 2),
        max_payload_bytes=_bounded(
            _require(raw, "max_payload_bytes", sec),
            "doip.max_payload_bytes",
            1,
            0xFFFFFFFF,
        ),
        tester_addr_range=tuple(bounds),
        tester_addr_list=tuple(addresses),
    )


def _load_timers(raw: dict) -> TimerConfig:
    return TimerConfig(
        t_tcp_initial_inactivity_s=_positive_number(
            _require(raw, "t_tcp_initial_inactivity_s", "timers"),
            "timers.t_tcp_initial_inactivity_s",
        ),
        t_tcp_general_inactivity_s=_positive_number(
            _require(raw, "t_tcp_general_inactivity_s", "timers"),
            "timers.t_tcp_general_inactivity_s",
        ),
        alive_check_interval_ms=_bounded(
            raw.get("alive_check_interval_ms", 500),
            "timers.alive_check_interval_ms",
            1,
        ),
        ecu_response_timeout_s=_positive_number(
            raw.get("ecu_response_timeout_s", 2.0),
            "timers.ecu_response_timeout_s",
        ),
        ecu_pending_max_wait_s=_positive_number(
            raw.get("ecu_pending_max_wait_s", 30.0),
            "timers.ecu_pending_max_wait_s",
        ),
        strict_response_matching=_strict_bool(
            raw.get("strict_response_matching", True),
            "timers.strict_response_matching",
        ),
    )


def _load_udp(raw: dict) -> UDPConfig:
    return UDPConfig(
        announce_count=_bounded(
            _require(raw, "announce_count", "udp"), "udp.announce_count", 1
        ),
        announce_interval_ms=_bounded(
            _require(raw, "announce_interval_ms", "udp"),
            "udp.announce_interval_ms",
            1,
        ),
    )


def _load_routing_table(raw_list: list, network: NetworkConfig) -> list[RoutingEntry]:
    if not isinstance(raw_list, list):
        raise ConfigError("routing_table must be a list")

    valid_interfaces = {network.tester_interface, network.ecu_interface}
    entries = []
    seen_ecu_addrs: set[int] = set()
    for index, value in enumerate(raw_list):
        path = f"routing_table[{index}]"
        raw = _mapping(value, path)
        ecu_addr = _bounded(
            _require(raw, "ecu_logical_addr", path),
            f"{path}.ecu_logical_addr",
            1,
            65535,
        )
        iface = _string(
            _require(raw, "ecu_interface", path),
            f"{path}.ecu_interface",
            nonempty=True,
        )
        if iface not in valid_interfaces:
            raise ConfigError(
                f"{path}.ecu_interface={iface!r} is not one of the declared interfaces"
            )
        # Diagnostic routing picks the first entry matching the ECU address;
        # a duplicate would silently make the later entry dead configuration.
        if ecu_addr in seen_ecu_addrs:
            raise ConfigError(
                f"{path}.ecu_logical_addr=0x{ecu_addr:04X} duplicates an earlier entry"
            )
        seen_ecu_addrs.add(ecu_addr)
        entries.append(
            RoutingEntry(
                ecu_logical_addr=ecu_addr,
                ecu_ipv6=_ipv6(_require(raw, "ecu_ipv6", path), f"{path}.ecu_ipv6"),
                ecu_interface=iface,
                ecu_port_plain=_bounded(
                    _require(raw, "ecu_port_plain", path),
                    f"{path}.ecu_port_plain",
                    1,
                    65535,
                ),
                ecu_port_tls=_bounded(
                    _require(raw, "ecu_port_tls", path),
                    f"{path}.ecu_port_tls",
                    1,
                    65535,
                ),
                ecu_sni=_string(raw.get("ecu_sni", ""), f"{path}.ecu_sni"),
            )
        )
    return entries


_VALID_MIDDLEWARE_TYPES = {
    "LoggerMiddleware", "DropMiddleware", "DelayMiddleware", "CorruptMiddleware",
    "ReplayMiddleware", "AddressMiddleware", "HeaderFaultMiddleware", "TLSFaultMiddleware",
}
_VALID_HEADER_FAULTS = {"wrong_version", "bad_inverse", "bad_length", "unknown_type"}


def _load_middleware(raw_list: list) -> list[MiddlewareConfig]:
    if not isinstance(raw_list, list):
        raise ConfigError("middleware must be a list")

    from middleware import _bounded_int

    integer_fields = {
        "CorruptMiddleware": (
            ("byte_offset", 0, None, True),
            ("flip_mask", 0, 0xFF, False),
        ),
        "AddressMiddleware": (
            ("src_override", 0, 0xFFFF, True),
            ("tgt_override", 0, 0xFFFF, True),
        ),
        "DelayMiddleware": (
            ("delay_ms", 0, None, False),
            ("jitter_ms", 0, None, False),
        ),
        "HeaderFaultMiddleware": (("inject_on_nth", 1, None, False),),
    }
    result = []
    for index, value in enumerate(raw_list):
        path = f"middleware[{index}]"
        raw = _mapping(value, path)
        mw_type = _string(_require(raw, "type", path), f"{path}.type")
        if mw_type not in _VALID_MIDDLEWARE_TYPES:
            raise ConfigError(f"{path}.type: unknown middleware type {mw_type!r}")

        enabled = _strict_bool(raw.get("enabled", True), f"{path}.enabled")
        params = {key: value for key, value in raw.items() if key not in ("type", "enabled")}
        for name, minimum, maximum, optional in integer_fields.get(mw_type, ()):
            if name not in params:
                continue
            if optional and params[name] is None:
                continue
            try:
                params[name] = _bounded_int(
                    params[name], f"{path}.{name}", minimum, maximum
                )
            except (TypeError, ValueError) as exc:
                raise ConfigError(f"{path}.{name}: {exc}") from exc

        if mw_type == "DropMiddleware":
            if "drop_rate" in params:
                rate = _nonnegative_number(params["drop_rate"], f"{path}.drop_rate")
                if rate > 1:
                    raise ConfigError(f"{path}.drop_rate must be in [0, 1]")
                params["drop_rate"] = rate
            if "match" in params:
                _validate_match(params["match"], path, _bounded_int)

        if mw_type == "LoggerMiddleware":
            if "log_path" in params:
                params["log_path"] = _string(
                    params["log_path"], f"{path}.log_path", nonempty=True
                )
            if "hex_dump" in params:
                params["hex_dump"] = _strict_bool(
                    params["hex_dump"], f"{path}.hex_dump"
                )

        if mw_type == "ReplayMiddleware":
            if "record" in params:
                params["record"] = _strict_bool(params["record"], f"{path}.record")
            if "replay_count" in params:
                try:
                    params["replay_count"] = _bounded_int(
                        params["replay_count"], f"{path}.replay_count", 1
                    )
                except (TypeError, ValueError) as exc:
                    raise ConfigError(f"{path}.replay_count: {exc}") from exc

        if mw_type == "HeaderFaultMiddleware":
            if "fault" in params:
                fault = _string(params["fault"], f"{path}.fault", nonempty=True)
                if fault not in _VALID_HEADER_FAULTS:
                    raise ConfigError(f"{path}.fault is invalid: {fault!r}")
            if "direction" in params:
                direction = params["direction"]
                if direction not in ("tester_to_ecu", "ecu_to_tester", "both"):
                    raise ConfigError(f"{path}.direction is invalid: {direction!r}")

        if mw_type == "TLSFaultMiddleware" and "fault" in params:
            params["fault"] = _string(params["fault"], f"{path}.fault", nonempty=True)

        result.append(
            MiddlewareConfig(type=mw_type, enabled=enabled, params=params)
        )
    return result


def _validate_match(match, path: str, bounded_int) -> None:
    if match is None:
        return
    match = _mapping(match, f"{path}.match")
    if "direction" in match:
        direction = match["direction"]
        if direction not in (None, "tester_to_ecu", "ecu_to_tester"):
            raise ConfigError(f"{path}.match.direction is invalid: {direction!r}")
    if "payload_type" in match and match["payload_type"] is not None:
        try:
            match["payload_type"] = bounded_int(
                match["payload_type"], f"{path}.match.payload_type", 0, 0xFFFF
            )
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{path}.match.payload_type: {exc}") from exc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_config(path: str) -> AppConfig:
    """Load and validate config.yaml. Raises ConfigError on any issue."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except (OSError, UnicodeError) as exc:
        raise ConfigError(f"Unable to read config file {path!r}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML parse error in {path!r}: {exc}") from exc

    raw = _mapping(raw, "root")

    network = _load_network(_mapping(_require(raw, "network", "root"), "network"))
    ports = _load_ports(_mapping(_require(raw, "ports", "root"), "ports"))
    tls = _load_tls(_mapping(_require(raw, "tls", "root"), "tls"))
    doip = _load_doip(_mapping(_require(raw, "doip", "root"), "doip"))
    timers = _load_timers(_mapping(_require(raw, "timers", "root"), "timers"))
    udp = _load_udp(_mapping(_require(raw, "udp", "root"), "udp"))
    routing_table = _load_routing_table(
        _require(raw, "routing_table", "root"), network
    )
    middleware = _load_middleware(raw.get("middleware", []))

    return AppConfig(
        network=network,
        ports=ports,
        tls=tls,
        doip=doip,
        timers=timers,
        udp=udp,
        routing_table=routing_table,
        middleware=middleware,
    )
