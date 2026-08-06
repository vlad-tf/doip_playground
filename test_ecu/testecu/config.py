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
Typed configuration loader for TestEcu.

Style follows ``doip_edgenode/config.py``: validating dataclasses, a single
``ConfigError``, and base-0 integer coercion so ``0xF190`` works whether YAML
parsed it as an int or left it a string.

Missing *sections* are tolerated (like ``echo_ecu._load_config``), but a
malformed entry inside a section is a hard error — a typo'd DID must fail at
startup, not silently answer requestOutOfRange forever.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

from testecu.uds import (
    NRC_NAMES,
    SESSION_DEFAULT,
)

logger = logging.getLogger("testecu.config")


class ConfigError(Exception):
    """Raised for any malformed or contradictory configuration."""


# ---------------------------------------------------------------------------
# Coercion helpers
# ---------------------------------------------------------------------------

def _to_int(value: Any, where: str) -> int:
    """Accept 4096, 0x1000 (YAML int) or "0x1000"/"4096" (string), base 0."""
    if isinstance(value, bool):
        raise ConfigError("%s: expected an integer, got a boolean" % where)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip(), 0)
        except ValueError:
            raise ConfigError("%s: %r is not an integer" % (where, value))
    raise ConfigError("%s: expected an integer, got %s" % (where, type(value).__name__))


def _to_bool(value: Any, where: str) -> bool:
    if isinstance(value, bool):
        return value
    raise ConfigError("%s: expected true/false, got %r" % (where, value))


def _to_str(value: Any, where: str) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int)):
        return str(value)
    raise ConfigError("%s: expected a string, got %s" % (where, type(value).__name__))


def _to_hex_bytes(value: Any, where: str) -> bytes:
    """Parse "DE AD BE EF" / "deadbeef" into bytes."""
    text = _to_str(value, where).replace(" ", "").replace("_", "")
    try:
        return bytes.fromhex(text)
    except ValueError:
        raise ConfigError("%s: %r is not a hex byte string" % (where, value))


def _to_int_list(value: Any, where: str) -> List[int]:
    if not isinstance(value, (list, tuple)):
        raise ConfigError("%s: expected a list, got %s" % (where, type(value).__name__))
    return [_to_int(item, "%s[%d]" % (where, i)) for i, item in enumerate(value)]


def _section(raw: dict, name: str) -> dict:
    value = raw.get(name)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError("%s: expected a mapping, got %s" % (name, type(value).__name__))
    return value


def _one_of(value: Any, allowed: tuple, where: str) -> str:
    text = _to_str(value, where).strip().lower()
    if text not in allowed:
        raise ConfigError("%s: %r is not one of %s" % (where, value, ", ".join(allowed)))
    return text


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ListenConfig:
    host: str = "::"
    port: int = 13400
    interface: str = ""


@dataclass
class DoipConfig:
    ecu_logical_addr: int = 0x0002
    node_type: int = 0x01
    power_mode: int = 0x01
    max_payload_bytes: int = 4096
    vin: str = "00000000000000000"
    eid: str = "000000000000"
    gid: str = "000000000000"


@dataclass
class UdpConfig:
    enabled: bool = True
    announce_count: int = 3
    announce_interval_ms: int = 500


@dataclass
class SecurityConfig:
    enabled: bool = True
    seed: bytes = b"\x11\x22\x33\x44"
    algorithm: str = "xor"          # none | xor | add
    key: bytes = b"\xA5\xA5\xA5\xA5"
    max_attempts: int = 3


@dataclass
class UdsConfig:
    default_session: int = SESSION_DEFAULT
    s3_server_ms: int = 5000
    p2_server_ms: int = 50
    p2_star_server_ms: int = 5000
    auto_response_pending: bool = True
    suppress_pos_rsp_bit: bool = True
    functional_addr: int = 0x1FFF
    unknown_service: str = "nrc"    # nrc | echo | silent
    unknown_did: str = "nrc"        # nrc | echo | silent
    on_handler_error: str = "nrc"   # nrc | fallthrough | silent
    reset_clears_writes: bool = True
    sessions: List[int] = field(default_factory=lambda: [0x01, 0x02, 0x03, 0x04])
    security: SecurityConfig = field(default_factory=SecurityConfig)


@dataclass
class DidSpec:
    """One entry of the YAML ``data_identifiers:`` table."""

    did: int
    name: str = ""
    type: str = "hex"                             # hex | ascii | uint | dynamic
    length: Optional[int] = None
    value: Optional[bytes] = None                 # encoded at load time
    read: bool = True
    write: bool = False
    read_sessions: Optional[List[int]] = None     # None = any session
    write_sessions: Optional[List[int]] = None
    read_security: int = 0
    write_security: int = 0
    read_nrc: Optional[int] = None                # force this NRC on read
    write_nrc: Optional[int] = None

    @property
    def dynamic(self) -> bool:
        return self.type == "dynamic"

    def label(self) -> str:
        return self.name or ("DID 0x%04X" % self.did)


@dataclass
class RoutineSpec:
    """One entry of the YAML ``routines:`` table."""

    rid: int
    name: str = ""
    start: bytes = b""
    stop: bytes = b""
    results: bytes = b""
    sessions: Optional[List[int]] = None
    security: int = 0

    def label(self) -> str:
        return self.name or ("routine 0x%04X" % self.rid)


@dataclass
class PluginSpec:
    """One plugin to load: either a file path or an importable module name."""

    label: str
    file: Optional[str] = None
    module: Optional[str] = None
    enabled: bool = True
    priority: Optional[int] = None
    params: dict = field(default_factory=dict)


@dataclass
class PluginsConfig:
    strict: bool = False
    specs: List[PluginSpec] = field(default_factory=list)


@dataclass
class EcuConfig:
    listen: ListenConfig = field(default_factory=ListenConfig)
    doip: DoipConfig = field(default_factory=DoipConfig)
    udp: UdpConfig = field(default_factory=UdpConfig)
    uds: UdsConfig = field(default_factory=UdsConfig)
    dids: Dict[int, DidSpec] = field(default_factory=dict)
    routines: Dict[int, RoutineSpec] = field(default_factory=dict)
    plugins: PluginsConfig = field(default_factory=PluginsConfig)
    raw: dict = field(default_factory=dict)
    #: Directory the config file lives in — relative plugin paths resolve here.
    base_dir: str = "."


# ---------------------------------------------------------------------------
# Section loaders
# ---------------------------------------------------------------------------

def _load_listen(raw: dict) -> ListenConfig:
    section = _section(raw, "listen")
    return ListenConfig(
        host=_to_str(section.get("host", "::"), "listen.host") or "::",
        port=_to_int(section.get("port", 13400), "listen.port"),
        interface=_to_str(section.get("interface", ""), "listen.interface"),
    )


def _load_doip(raw: dict) -> DoipConfig:
    section = _section(raw, "doip")
    cfg = DoipConfig(
        ecu_logical_addr=_to_int(section.get("ecu_logical_addr", 0x0002),
                                 "doip.ecu_logical_addr"),
        node_type=_to_int(section.get("node_type", 0x01), "doip.node_type"),
        power_mode=_to_int(section.get("power_mode", 0x01), "doip.power_mode"),
        max_payload_bytes=_to_int(section.get("max_payload_bytes", 4096),
                                  "doip.max_payload_bytes"),
        vin=_to_str(section.get("vin", "00000000000000000"), "doip.vin"),
        eid=_to_str(section.get("eid", "000000000000"), "doip.eid"),
        gid=_to_str(section.get("gid", "000000000000"), "doip.gid"),
    )
    # Fail at startup rather than when the first announcement is built.
    _to_hex_bytes(cfg.eid, "doip.eid")
    _to_hex_bytes(cfg.gid, "doip.gid")
    if not 0 <= cfg.ecu_logical_addr <= 0xFFFF:
        raise ConfigError("doip.ecu_logical_addr: 0x%X is not a 16-bit address"
                          % cfg.ecu_logical_addr)
    return cfg


def _load_udp(raw: dict) -> UdpConfig:
    section = _section(raw, "udp")
    return UdpConfig(
        enabled=_to_bool(section.get("enabled", True), "udp.enabled"),
        announce_count=_to_int(section.get("announce_count", 3), "udp.announce_count"),
        announce_interval_ms=_to_int(section.get("announce_interval_ms", 500),
                                     "udp.announce_interval_ms"),
    )


def _load_security(section: dict) -> SecurityConfig:
    if not section:
        return SecurityConfig()
    algorithm = _one_of(section.get("algorithm", "xor"), ("none", "xor", "add"),
                        "uds.security.algorithm")
    cfg = SecurityConfig(
        enabled=_to_bool(section.get("enabled", True), "uds.security.enabled"),
        seed=_to_hex_bytes(section.get("seed", "11223344"), "uds.security.seed"),
        algorithm=algorithm,
        key=_to_hex_bytes(section.get("key", "A5A5A5A5"), "uds.security.key"),
        max_attempts=_to_int(section.get("max_attempts", 3), "uds.security.max_attempts"),
    )
    if not cfg.seed:
        raise ConfigError("uds.security.seed: must not be empty")
    if cfg.algorithm != "none" and len(cfg.key) != len(cfg.seed):
        raise ConfigError(
            "uds.security.key: %d bytes but seed is %d — the %r algorithm needs "
            "them to be the same length" % (len(cfg.key), len(cfg.seed), cfg.algorithm)
        )
    return cfg


def _load_uds(raw: dict) -> UdsConfig:
    section = _section(raw, "uds")
    cfg = UdsConfig(
        default_session=_to_int(section.get("default_session", SESSION_DEFAULT),
                                "uds.default_session"),
        s3_server_ms=_to_int(section.get("s3_server_ms", 5000), "uds.s3_server_ms"),
        p2_server_ms=_to_int(section.get("p2_server_ms", 50), "uds.p2_server_ms"),
        p2_star_server_ms=_to_int(section.get("p2_star_server_ms", 5000),
                                  "uds.p2_star_server_ms"),
        auto_response_pending=_to_bool(section.get("auto_response_pending", True),
                                       "uds.auto_response_pending"),
        suppress_pos_rsp_bit=_to_bool(section.get("suppress_pos_rsp_bit", True),
                                      "uds.suppress_pos_rsp_bit"),
        functional_addr=_to_int(section.get("functional_addr", 0x1FFF),
                                "uds.functional_addr"),
        unknown_service=_one_of(section.get("unknown_service", "nrc"),
                                ("nrc", "echo", "silent"), "uds.unknown_service"),
        unknown_did=_one_of(section.get("unknown_did", "nrc"),
                            ("nrc", "echo", "silent"), "uds.unknown_did"),
        on_handler_error=_one_of(section.get("on_handler_error", "nrc"),
                                 ("nrc", "fallthrough", "silent"),
                                 "uds.on_handler_error"),
        reset_clears_writes=_to_bool(section.get("reset_clears_writes", True),
                                     "uds.reset_clears_writes"),
        security=_load_security(_section(section, "security")),
    )
    if "sessions" in section:
        cfg.sessions = _to_int_list(section["sessions"], "uds.sessions")
    if cfg.default_session not in cfg.sessions:
        raise ConfigError(
            "uds.default_session: 0x%02X is not in uds.sessions %s"
            % (cfg.default_session, ["0x%02X" % s for s in cfg.sessions])
        )
    if cfg.p2_server_ms <= 0:
        raise ConfigError("uds.p2_server_ms: must be > 0")
    return cfg


# ---------------------------------------------------------------------------
# DID / routine tables
# ---------------------------------------------------------------------------

_DID_TYPES = ("hex", "ascii", "uint", "dynamic")


def _encode_did_value(spec_type: str, value: Any, length: Optional[int],
                      where: str) -> bytes:
    """Encode a YAML DID value once, at load time."""
    if spec_type == "hex":
        encoded = _to_hex_bytes(value, where)
    elif spec_type == "ascii":
        text = _to_str(value, where)
        try:
            encoded = text.encode("ascii")
        except UnicodeEncodeError:
            raise ConfigError("%s: %r is not pure ASCII" % (where, value))
        if length is not None:
            encoded = encoded[:length].ljust(length, b"\x00")
    elif spec_type == "uint":
        number = _to_int(value, where)
        width = length if length is not None else 1
        try:
            encoded = number.to_bytes(width, "big")
        except OverflowError:
            raise ConfigError("%s: %d does not fit in %d byte(s)" % (where, number, width))
    else:  # pragma: no cover — guarded by the caller
        raise ConfigError("%s: type %r takes no value" % (where, spec_type))

    if length is not None and spec_type == "hex" and len(encoded) != length:
        raise ConfigError(
            "%s: value is %d byte(s) but length says %d"
            % (where, len(encoded), length)
        )
    return encoded


def _load_did(did: int, raw_entry: Any, where: str) -> DidSpec:
    if not isinstance(raw_entry, dict):
        raise ConfigError("%s: expected a mapping, got %s"
                          % (where, type(raw_entry).__name__))

    spec_type = _one_of(raw_entry.get("type", "hex"), _DID_TYPES, "%s.type" % where)
    length = (_to_int(raw_entry["length"], "%s.length" % where)
              if raw_entry.get("length") is not None else None)
    if length is not None and length <= 0:
        raise ConfigError("%s.length: must be > 0" % where)

    value: Optional[bytes] = None
    if spec_type == "dynamic":
        if "value" in raw_entry:
            raise ConfigError("%s: type 'dynamic' must not have a value — it is "
                              "served by the core or by a plugin" % where)
    elif "value" in raw_entry:
        value = _encode_did_value(spec_type, raw_entry["value"], length,
                                  "%s.value" % where)
    else:
        raise ConfigError("%s: missing 'value' (use type: dynamic for a "
                          "handler-provided DID)" % where)

    spec = DidSpec(
        did=did,
        name=_to_str(raw_entry.get("name", ""), "%s.name" % where),
        type=spec_type,
        length=length,
        value=value,
        read=_to_bool(raw_entry.get("read", True), "%s.read" % where),
        write=_to_bool(raw_entry.get("write", False), "%s.write" % where),
        read_security=_to_int(raw_entry.get("read_security", 0), "%s.read_security" % where),
        write_security=_to_int(raw_entry.get("write_security", 0),
                               "%s.write_security" % where),
    )
    if raw_entry.get("read_sessions") is not None:
        spec.read_sessions = _to_int_list(raw_entry["read_sessions"],
                                          "%s.read_sessions" % where)
    if raw_entry.get("write_sessions") is not None:
        spec.write_sessions = _to_int_list(raw_entry["write_sessions"],
                                           "%s.write_sessions" % where)
    for gate in ("read_nrc", "write_nrc"):
        if raw_entry.get(gate) is not None:
            code = _to_int(raw_entry[gate], "%s.%s" % (where, gate))
            if code not in NRC_NAMES:
                raise ConfigError("%s.%s: 0x%02X is not a known NRC" % (where, gate, code))
            setattr(spec, gate, code)

    if spec.write and spec.dynamic:
        raise ConfigError("%s: type 'dynamic' cannot be writable — give the DID a "
                          "@write_did handler instead" % where)
    return spec


def _load_dids(raw: dict) -> Dict[int, DidSpec]:
    section = _section(raw, "data_identifiers")
    table: Dict[int, DidSpec] = {}
    for key, entry in section.items():
        where = "data_identifiers[%s]" % key
        did = _to_int(key, where)
        if not 0 <= did <= 0xFFFF:
            raise ConfigError("%s: 0x%X is not a 16-bit identifier" % (where, did))
        if did in table:
            raise ConfigError("%s: DID 0x%04X is declared twice" % (where, did))
        table[did] = _load_did(did, entry, where)
    return table


def _load_routines(raw: dict) -> Dict[int, RoutineSpec]:
    section = _section(raw, "routines")
    table: Dict[int, RoutineSpec] = {}
    for key, entry in section.items():
        where = "routines[%s]" % key
        rid = _to_int(key, where)
        if not 0 <= rid <= 0xFFFF:
            raise ConfigError("%s: 0x%X is not a 16-bit identifier" % (where, rid))
        if not isinstance(entry, dict):
            raise ConfigError("%s: expected a mapping, got %s"
                              % (where, type(entry).__name__))
        spec = RoutineSpec(
            rid=rid,
            name=_to_str(entry.get("name", ""), "%s.name" % where),
            start=_to_hex_bytes(entry.get("start", ""), "%s.start" % where),
            stop=_to_hex_bytes(entry.get("stop", ""), "%s.stop" % where),
            results=_to_hex_bytes(entry.get("results", ""), "%s.results" % where),
            security=_to_int(entry.get("security", 0), "%s.security" % where),
        )
        if entry.get("sessions") is not None:
            spec.sessions = _to_int_list(entry["sessions"], "%s.sessions" % where)
        table[rid] = spec
    return table


# ---------------------------------------------------------------------------
# Plugins
# ---------------------------------------------------------------------------

def _scan_plugin_dir(directory: str, base_dir: str, strict: bool) -> List[PluginSpec]:
    """
    Every non-underscore ``*.py`` in ``directory``, in sorted order.

    A missing directory is a warning, not an error, unless ``plugins.strict``
    is set: the usual cause is a container started without its plugin volume
    mounted, and an ECU with no plugins is still a working ECU.
    """
    resolved = directory if os.path.isabs(directory) else os.path.join(base_dir, directory)
    if not os.path.isdir(resolved):
        if strict:
            raise ConfigError("plugins.path: %r is not a directory" % directory)
        logger.warning("plugins.path: %r is not a directory — no plugins loaded from it",
                       directory)
        return []
    specs: List[PluginSpec] = []
    for entry in sorted(os.listdir(resolved)):
        if not entry.endswith(".py") or entry.startswith("_"):
            continue
        specs.append(PluginSpec(label=os.path.join(directory, entry),
                                file=os.path.join(resolved, entry)))
    return specs


def _load_plugins(raw: dict, base_dir: str) -> PluginsConfig:
    section = _section(raw, "plugins")
    cfg = PluginsConfig(strict=_to_bool(section.get("strict", False), "plugins.strict"))

    paths = section.get("path") or []
    if not isinstance(paths, (list, tuple)):
        raise ConfigError("plugins.path: expected a list of directories")
    for directory in paths:
        cfg.specs.extend(_scan_plugin_dir(
            _to_str(directory, "plugins.path"), base_dir, cfg.strict))

    modules = section.get("modules") or []
    if not isinstance(modules, (list, tuple)):
        raise ConfigError("plugins.modules: expected a list")
    for index, entry in enumerate(modules):
        where = "plugins.modules[%d]" % index
        if not isinstance(entry, dict):
            raise ConfigError("%s: expected a mapping with 'file:' or 'module:'" % where)
        file_path = entry.get("file")
        module_name = entry.get("module")
        if bool(file_path) == bool(module_name):
            raise ConfigError("%s: give exactly one of 'file:' or 'module:'" % where)
        params = entry.get("params") or {}
        if not isinstance(params, dict):
            raise ConfigError("%s.params: expected a mapping" % where)
        resolved = None
        if file_path:
            resolved = _to_str(file_path, "%s.file" % where)
            if not os.path.isabs(resolved):
                resolved = os.path.join(base_dir, resolved)
        cfg.specs.append(PluginSpec(
            label=_to_str(file_path or module_name, where),
            file=resolved,
            module=_to_str(module_name, "%s.module" % where) if module_name else None,
            enabled=_to_bool(entry.get("enabled", True), "%s.enabled" % where),
            priority=(_to_int(entry["priority"], "%s.priority" % where)
                      if entry.get("priority") is not None else None),
            params=params,
        ))
    return cfg


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_config(raw: dict, base_dir: str = ".") -> EcuConfig:
    """Validate an already-parsed YAML mapping.  Used directly by the tests."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError("top level: expected a mapping, got %s" % type(raw).__name__)

    cfg = EcuConfig(
        listen=_load_listen(raw),
        doip=_load_doip(raw),
        udp=_load_udp(raw),
        uds=_load_uds(raw),
        dids=_load_dids(raw),
        routines=_load_routines(raw),
        plugins=_load_plugins(raw, base_dir),
        raw=raw,
        base_dir=base_dir,
    )

    # Cross-section checks
    if cfg.uds.functional_addr == cfg.doip.ecu_logical_addr:
        raise ConfigError(
            "uds.functional_addr (0x%04X) must differ from doip.ecu_logical_addr"
            % cfg.uds.functional_addr
        )
    for spec in cfg.dids.values():
        for sessions, gate in ((spec.read_sessions, "read_sessions"),
                               (spec.write_sessions, "write_sessions")):
            for session in sessions or ():
                if session not in cfg.uds.sessions:
                    raise ConfigError(
                        "data_identifiers[0x%04X].%s: session 0x%02X is not in "
                        "uds.sessions" % (spec.did, gate, session)
                    )
    return cfg


def load_config(path: str) -> EcuConfig:
    """Read and validate a YAML config file.  Raises ConfigError on any problem."""
    try:
        with open(path) as handle:
            raw = yaml.safe_load(handle)
    except FileNotFoundError:
        raise ConfigError("config file %r not found" % path)
    except yaml.YAMLError as exc:
        raise ConfigError("config file %r is not valid YAML: %s" % (path, exc))
    except OSError as exc:
        raise ConfigError("cannot read config file %r: %s" % (path, exc))

    base_dir = os.path.dirname(os.path.abspath(path)) or "."
    return parse_config(raw, base_dir)
