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

import re
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


@dataclass
class DoIPConfig:
    vin: str
    eid: str
    gid: str
    node_type: int
    node_logical_addr: int   # EdgeNode's own logical address, used in UDP announcements
    power_mode: int
    max_payload_bytes: int


@dataclass
class TimerConfig:
    t_tcp_initial_inactivity_s: float
    t_tcp_general_inactivity_s: float
    alive_check_interval_ms: int
    #: How long to wait for one ECU frame after the Diagnostic Positive ACK.
    ecu_response_timeout_s: float = 2.0
    #: Total budget for one request when the ECU keeps answering
    #: requestCorrectlyReceived-ResponsePending (0x78).  A flash routine can
    #: legitimately pend for far longer than a single P2, so this is the cap
    #: on the whole exchange, not on each frame.
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
    tester_logical_addr: int
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

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _to_int(value, field_name: str) -> int:
    """Convert a value that may be a hex string or plain int to int."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)  # handles 0x prefix and plain decimal
        except ValueError:
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


# ---------------------------------------------------------------------------
# Loaders for each config section
# ---------------------------------------------------------------------------


def _load_network(raw: dict) -> NetworkConfig:
    sec = "network"
    return NetworkConfig(
        tester_interface=str(_require(raw, "tester_interface", sec)),
        tester_ipv4=str(_require(raw, "tester_ipv4", sec)),
        ecu_interface=str(_require(raw, "ecu_interface", sec)),
    )


def _load_ports(raw: dict) -> PortsConfig:
    sec = "ports"
    return PortsConfig(
        doip_plain=int(_require(raw, "doip_plain", sec)),
        doip_tls=int(_require(raw, "doip_tls", sec)),
    )


def _load_tls(raw: dict) -> TLSConfig:
    sec = "tls"
    tls_version = str(_require(raw, "tls_version", sec))
    if tls_version != "TLSv1.3":
        raise ConfigError(
            f"tls.tls_version must be 'TLSv1.3'; got {tls_version!r}. "
            "TLS 1.2 and below are not supported."
        )
    return TLSConfig(
        server_cert=str(_require(raw, "server_cert", sec)),
        server_key=str(_require(raw, "server_key", sec)),
        client_cert=str(_require(raw, "client_cert", sec)),
        client_key=str(_require(raw, "client_key", sec)),
        ca_cert=str(_require(raw, "ca_cert", sec)),
        mutual_tls=bool(raw.get("mutual_tls", True)),
        tls_version=tls_version,
        cipher_suites=list(raw.get("cipher_suites", [])),
    )


def _load_doip(raw: dict) -> DoIPConfig:
    sec = "doip"
    vin = str(_require(raw, "vin", sec))
    if len(vin) != 17:
        raise ConfigError(
            f"doip.vin must be exactly 17 characters; got {len(vin)}: {vin!r}"
        )
    eid = str(_require(raw, "eid", sec))
    if len(eid) != 12 or not _HEX_RE.match(eid):
        raise ConfigError(
            f"doip.eid must be exactly 12 hex characters; got: {eid!r}"
        )
    gid = str(_require(raw, "gid", sec))
    if len(gid) != 12 or not _HEX_RE.match(gid):
        raise ConfigError(
            f"doip.gid must be exactly 12 hex characters; got: {gid!r}"
        )
    return DoIPConfig(
        vin=vin,
        eid=eid,
        gid=gid,
        node_type=_to_int(_require(raw, "node_type", sec), "doip.node_type"),
        node_logical_addr=_to_int(
            raw.get("node_logical_addr", 0x0000), "doip.node_logical_addr"
        ),
        power_mode=_to_int(_require(raw, "power_mode", sec), "doip.power_mode"),
        max_payload_bytes=int(_require(raw, "max_payload_bytes", sec)),
    )


def _load_timers(raw: dict) -> TimerConfig:
    sec = "timers"
    return TimerConfig(
        t_tcp_initial_inactivity_s=float(
            _require(raw, "t_tcp_initial_inactivity_s", sec)
        ),
        t_tcp_general_inactivity_s=float(
            _require(raw, "t_tcp_general_inactivity_s", sec)
        ),
        alive_check_interval_ms=int(
            raw.get("alive_check_interval_ms", 500)
        ),
        ecu_response_timeout_s=float(
            raw.get("ecu_response_timeout_s", 2.0)
        ),
        ecu_pending_max_wait_s=float(
            raw.get("ecu_pending_max_wait_s", 30.0)
        ),
        strict_response_matching=bool(
            raw.get("strict_response_matching", True)
        ),
    )


def _load_udp(raw: dict) -> UDPConfig:
    sec = "udp"
    count = int(_require(raw, "announce_count", sec))
    if count < 1:
        raise ConfigError("udp.announce_count must be >= 1")
    return UDPConfig(
        announce_count=count,
        announce_interval_ms=int(_require(raw, "announce_interval_ms", sec)),
    )


def _load_routing_table(raw_list: list, network: NetworkConfig) -> list[RoutingEntry]:
    valid_interfaces = {network.tester_interface, network.ecu_interface}
    entries = []
    for i, raw in enumerate(raw_list):
        iface = str(raw.get("ecu_interface", ""))
        if iface not in valid_interfaces:
            raise ConfigError(
                f"routing_table[{i}].ecu_interface={iface!r} is not one of the "
                f"declared interfaces {valid_interfaces}"
            )
        entries.append(
            RoutingEntry(
                tester_logical_addr=_to_int(
                    _require(raw, "tester_logical_addr", f"routing_table[{i}]"),
                    f"routing_table[{i}].tester_logical_addr",
                ),
                ecu_logical_addr=_to_int(
                    _require(raw, "ecu_logical_addr", f"routing_table[{i}]"),
                    f"routing_table[{i}].ecu_logical_addr",
                ),
                ecu_ipv6=str(_require(raw, "ecu_ipv6", f"routing_table[{i}]")),
                ecu_interface=iface,
                ecu_port_plain=int(
                    _require(raw, "ecu_port_plain", f"routing_table[{i}]")
                ),
                ecu_port_tls=int(
                    _require(raw, "ecu_port_tls", f"routing_table[{i}]")
                ),
                ecu_sni=str(raw.get("ecu_sni", "")),
            )
        )
    return entries


_VALID_HEADER_FAULTS = {"wrong_version", "bad_inverse", "bad_length", "unknown_type"}


def _load_middleware(raw_list: list) -> list[MiddlewareConfig]:
    result = []
    for i, raw in enumerate(raw_list):
        mw_type = str(_require(raw, "type", f"middleware[{i}]"))
        enabled = bool(raw.get("enabled", True))
        params = {k: v for k, v in raw.items() if k not in ("type", "enabled")}

        # Validate per-type params
        if mw_type == "DropMiddleware":
            rate = params.get("drop_rate", 0.0)
            if not (0.0 <= float(rate) <= 1.0):
                raise ConfigError(
                    f"middleware[{i}] DropMiddleware.drop_rate must be in [0.0, 1.0]; "
                    f"got {rate!r}"
                )
        if mw_type == "HeaderFaultMiddleware":
            fault = params.get("fault", "")
            if fault not in _VALID_HEADER_FAULTS:
                raise ConfigError(
                    f"middleware[{i}] HeaderFaultMiddleware.fault must be one of "
                    f"{sorted(_VALID_HEADER_FAULTS)}; got {fault!r}"
                )
            nth = params.get("inject_on_nth", 1)
            if int(nth) < 1:
                raise ConfigError(
                    f"middleware[{i}] HeaderFaultMiddleware.inject_on_nth must be >= 1"
                )

        result.append(MiddlewareConfig(type=mw_type, enabled=enabled, params=params))
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_config(path: str) -> AppConfig:
    """Load and validate config.yaml. Raises ConfigError on any issue."""
    try:
        with open(path, "r") as fh:
            raw = yaml.safe_load(fh)
    except FileNotFoundError:
        raise ConfigError(f"Config file not found: {path!r}")
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML parse error in {path!r}: {exc}")

    if not isinstance(raw, dict):
        raise ConfigError("Config file must be a YAML mapping at the top level")

    network = _load_network(_require(raw, "network", "root"))
    ports = _load_ports(_require(raw, "ports", "root"))
    tls = _load_tls(_require(raw, "tls", "root"))
    doip = _load_doip(_require(raw, "doip", "root"))
    timers = _load_timers(_require(raw, "timers", "root"))
    udp = _load_udp(_require(raw, "udp", "root"))
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
