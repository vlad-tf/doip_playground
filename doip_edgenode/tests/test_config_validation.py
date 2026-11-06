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

"""Contract tests for the EdgeNode YAML configuration boundary (F12/F11)."""

from copy import deepcopy
from pathlib import Path
import re

import pytest
import yaml

from config import ConfigError, load_config
from udp_announcer import _announcement_payload


ROOT = Path(__file__).resolve().parents[1]
CONFIG_FILES = [ROOT / "config.yaml"]
DOCKER_CONFIG = ROOT.parent / "docker" / "edgenode.config.yaml"
if DOCKER_CONFIG.is_file():
    CONFIG_FILES.append(DOCKER_CONFIG)


def _raw_config(path):
    with path.open(encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def _write_config(tmp_path, raw):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return path


def _load_mutation(tmp_path, raw, dotted, value):
    changed = deepcopy(raw)
    keys = dotted.split(".")
    target = changed
    for key in keys[:-1]:
        target = target[int(key)] if isinstance(target, list) else target[key]
    last = keys[-1]
    target[int(last) if isinstance(target, list) else last] = value
    return load_config(_write_config(tmp_path, changed))


def _error_path_regex(dotted):
    parts = dotted.split(".")
    pattern = re.escape(parts[0])
    for part in parts[1:]:
        pattern += rf"(?:\.{re.escape(part)}|\[{re.escape(part)}\])"
    return pattern


def _assert_bad(tmp_path, raw, dotted, value):
    with pytest.raises(ConfigError, match=_error_path_regex(dotted)):
        _load_mutation(tmp_path, raw, dotted, value)


@pytest.mark.parametrize("config_path", CONFIG_FILES)
def test_repository_configurations_load_and_round_trip(config_path):
    config = load_config(config_path)
    raw = _raw_config(config_path)
    assert config.network.tester_interface == raw["network"]["tester_interface"]
    assert config.network.tester_ipv4 == raw["network"]["tester_ipv4"]
    assert config.doip.vin == raw["doip"]["vin"]
    assert config.doip.node_logical_addr == int(str(raw["doip"]["node_logical_addr"]), 0)
    assert config.doip.tester_addr_range == tuple(int(str(v), 0) for v in raw["doip"]["tester_addr_range"])
    assert config.tls.cipher_suites == raw["tls"]["cipher_suites"]
    assert config.routing_table[0].ecu_ipv6 == raw["routing_table"][0]["ecu_ipv6"]
    assert [m.type for m in config.middleware] == [m["type"] for m in raw.get("middleware", [])]


def test_optional_fields_default_when_omitted(tmp_path):
    raw = _raw_config(CONFIG_FILES[0])
    raw["doip"].pop("node_logical_addr")
    raw["doip"].pop("tester_addr_range")
    raw["doip"].pop("tester_addr_list")
    raw["timers"].pop("ecu_response_timeout_s", None)
    raw["timers"].pop("ecu_pending_max_wait_s", None)
    raw["timers"].pop("strict_response_matching", None)
    raw["timers"].pop("alive_check_interval_ms", None)
    raw["tls"].pop("mutual_tls", None)
    raw["tls"].pop("cipher_suites", None)
    raw.pop("middleware")
    config = load_config(_write_config(tmp_path, raw))
    assert config.doip.node_logical_addr == 0x1234
    assert config.doip.tester_addr_range == (0x0E00, 0x0FFF)
    assert config.doip.tester_addr_list == ()
    assert config.timers.ecu_response_timeout_s == 2.0
    assert config.timers.ecu_pending_max_wait_s == 30.0
    assert config.timers.strict_response_matching is True
    assert config.tls.mutual_tls is True
    assert config.tls.cipher_suites == []
    assert config.middleware == []


@pytest.mark.parametrize("section", ["network", "ports", "tls", "doip", "timers", "udp"])
def test_required_sections_must_be_mappings(tmp_path, section):
    raw = _raw_config(CONFIG_FILES[0])
    _assert_bad(tmp_path, raw, section, "not-a-mapping")


@pytest.mark.parametrize("section", ["routing_table", "middleware"])
def test_list_sections_must_be_lists(tmp_path, section):
    raw = _raw_config(CONFIG_FILES[0])
    _assert_bad(tmp_path, raw, section, {"type": "LoggerMiddleware"})


def test_list_entries_must_be_mappings(tmp_path):
    raw = _raw_config(CONFIG_FILES[0])
    for section in ("routing_table", "middleware"):
        changed = deepcopy(raw)
        changed[section] = ["not-an-entry"]
        with pytest.raises(ConfigError, match=section):
            load_config(_write_config(tmp_path, changed))


def test_mapping_keys_must_be_strings(tmp_path):
    raw = _raw_config(CONFIG_FILES[0])
    changed = deepcopy(raw)
    changed["network"][1] = "bad-key"
    with pytest.raises(ConfigError, match="network"):
        load_config(_write_config(tmp_path, changed))
    changed = deepcopy(raw)
    changed["routing_table"][0][1] = "bad-key"
    with pytest.raises(ConfigError, match="routing_table"):
        load_config(_write_config(tmp_path, changed))


def test_root_must_be_mapping_and_required_sections_exist(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("[]\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="root"):
        load_config(path)
    raw = _raw_config(CONFIG_FILES[0])
    raw.pop("network")
    with pytest.raises(ConfigError, match="network"):
        load_config(_write_config(tmp_path, raw))


@pytest.mark.parametrize("field", ["tester_interface", "ecu_interface"])
def test_interfaces_are_nonempty_actual_strings(tmp_path, field):
    raw = _raw_config(CONFIG_FILES[0])
    for value in [None, "", "   ", 1, [], False]:
        _assert_bad(tmp_path, raw, f"network.{field}", value)


@pytest.mark.parametrize("field", ["server_cert", "server_key", "client_cert", "client_key", "ca_cert"])
def test_certificate_paths_are_nonempty_actual_strings(tmp_path, field):
    raw = _raw_config(CONFIG_FILES[0])
    for value in [None, "", "   ", 1, [], False]:
        _assert_bad(tmp_path, raw, f"tls.{field}", value)


@pytest.mark.parametrize("field", ["tester_ipv4"])
def test_ipv4_fields_are_valid(tmp_path, field):
    raw = _raw_config(CONFIG_FILES[0])
    for value in ["999.1.1.1", "not-ip", "::1", "", None, 1]:
        _assert_bad(tmp_path, raw, f"network.{field}", value)


def test_routing_ipv6_and_interface_validation(tmp_path):
    raw = _raw_config(CONFIG_FILES[0])
    for value in ["not-ipv6", "192.0.2.1", "", None, 1, "fe80::1%x%y"]:
        changed = deepcopy(raw)
        changed["routing_table"][0]["ecu_ipv6"] = value
        with pytest.raises(ConfigError, match=r"routing_table\[0\].ecu_ipv6"):
            load_config(_write_config(tmp_path, changed))
    changed = deepcopy(raw)
    changed["routing_table"][0]["ecu_interface"] = "missing0"
    with pytest.raises(ConfigError, match=r"routing_table\[0\].ecu_interface"):
        load_config(_write_config(tmp_path, changed))
    valid = _load_mutation(tmp_path, raw, "routing_table.0.ecu_ipv6", "fe80::1%eth1")
    assert valid.routing_table[0].ecu_ipv6 == "fe80::1%eth1"


def test_tls_cipher_suites_allow_empty_list_and_reject_bad_elements(tmp_path):
    raw = _raw_config(CONFIG_FILES[0])
    config = _load_mutation(tmp_path, raw, "tls.cipher_suites", [])
    assert config.tls.cipher_suites == []
    for value in [[""], ["TLS_AES", 1], [None], "TLS_AES", None]:
        _assert_bad(tmp_path, raw, "tls.cipher_suites", value)


def test_tls_version_and_sni_types(tmp_path):
    raw = _raw_config(CONFIG_FILES[0])
    for value in ["TLSv1.2", 1, None]:
        _assert_bad(tmp_path, raw, "tls.tls_version", value)
    for value in [None, 1, False, []]:
        _assert_bad(tmp_path, raw, "routing_table.0.ecu_sni", value)
    assert _load_mutation(tmp_path, raw, "routing_table.0.ecu_sni", "")


@pytest.mark.parametrize("field", ["mutual_tls"])
def test_tls_booleans_are_actual_booleans(tmp_path, field):
    raw = _raw_config(CONFIG_FILES[0])
    for value in ["false", "true", 0, 1, None, [], ""]:
        _assert_bad(tmp_path, raw, f"tls.{field}", value)


@pytest.mark.parametrize("field", ["strict_response_matching"])
def test_timer_booleans_are_actual_booleans(tmp_path, field):
    raw = _raw_config(CONFIG_FILES[0])
    for value in ["false", "true", 0, 1, None, [], ""]:
        _assert_bad(tmp_path, raw, f"timers.{field}", value)


@pytest.mark.parametrize("field", ["enabled", "record", "hex_dump"])
def test_middleware_booleans_are_actual_booleans(tmp_path, field):
    raw = _raw_config(CONFIG_FILES[0])
    indices = [
        i for i, middleware in enumerate(raw["middleware"])
        if field == "enabled"
        or field == "record" and middleware["type"] == "ReplayMiddleware"
        or field == "hex_dump" and middleware["type"] == "LoggerMiddleware"
    ]
    for index in indices:
        for value in ["false", "true", 0, 1, None, [], ""]:
            changed = deepcopy(raw)
            changed["middleware"][index][field] = value
            with pytest.raises(ConfigError, match=rf"middleware\[{index}\].*{field}"):
                load_config(_write_config(tmp_path, changed))


@pytest.mark.parametrize("field, values", [
    ("ports.doip_plain", [0, 65536, True, 1.5, float("nan"), float("inf"), None]),
    ("ports.doip_tls", [0, 65536, True, 1.5, float("nan"), float("inf"), None]),
    ("udp.announce_interval_ms", [0, -1, True, 1.5, float("nan"), float("inf"), None]),
    ("udp.announce_count", [0, -1, True, 1.5, float("nan"), float("inf"), None]),
    ("timers.alive_check_interval_ms", [0, -1, True, 1.5, float("nan"), float("inf"), None]),
])
def test_positive_integer_fields_reject_bad_values(tmp_path, field, values):
    raw = _raw_config(CONFIG_FILES[0])
    for value in values:
        _assert_bad(tmp_path, raw, field, value)


@pytest.mark.parametrize("field", ["ports.doip_plain", "ports.doip_tls", "udp.announce_count"])
def test_integer_fields_accept_decimal_zero_padding_and_hex(tmp_path, field):
    raw = _raw_config(CONFIG_FILES[0])
    for value, expected in [("013400", 13400), ("0x3496", 0x3496), ("1", 1)]:
        config = _load_mutation(tmp_path, raw, field, value)
        section, name = field.split(".")
        assert getattr(getattr(config, section), name) == expected


@pytest.mark.parametrize("field, values", [
    ("doip.node_type", [-1, 2, True, 1.5, float("nan"), float("inf"), None]),
    ("doip.power_mode", [-1, 3, True, 1.5, float("nan"), float("inf"), None]),
    ("doip.max_payload_bytes", [0, 0x100000000, True, 1.5, float("nan"), float("inf"), None]),
    ("doip.node_logical_addr", [0, 65536, True, 1.5, float("nan"), float("inf"), None]),
])
def test_doip_integer_bounds_and_types(tmp_path, field, values):
    raw = _raw_config(CONFIG_FILES[0])
    for value in values:
        _assert_bad(tmp_path, raw, field, value)


@pytest.mark.parametrize("field", ["doip.node_type", "doip.power_mode", "doip.max_payload_bytes", "doip.node_logical_addr"])
def test_doip_integer_fields_accept_numeric_strings(tmp_path, field):
    raw = _raw_config(CONFIG_FILES[0])
    value = "0x1" if field != "doip.max_payload_bytes" else "0004096"
    config = _load_mutation(tmp_path, raw, field, value)
    section, name = field.split(".")
    assert isinstance(getattr(getattr(config, section), name), int)


def test_vin_is_ascii_exactly_17_actual_string(tmp_path):
    raw = _raw_config(CONFIG_FILES[0])
    for value in ["short", "A" * 18, "é" * 17, b"1HGBH41JXMN109186", 1, None]:
        _assert_bad(tmp_path, raw, "doip.vin", value)


@pytest.mark.parametrize("field", ["eid", "gid"])
def test_ids_are_exactly_12_hex_actual_strings_without_newline(tmp_path, field):
    raw = _raw_config(CONFIG_FILES[0])
    for value in ["AABBCCDDEEF", "AABBCCDDEEFF0", "AABBCCDDEEFF\n", "AABBCCDDEEF\n", "AABBCCDDEEGG", 1, None, b"AABBCCDDEEFF"]:
        _assert_bad(tmp_path, raw, f"doip.{field}", value)


def test_tester_ranges_and_lists_validate_shape_and_16_bit_bounds(tmp_path):
    raw = _raw_config(CONFIG_FILES[0])
    for value in [None, "not-list", [], [1], [1, 2, 3], [2, 1], [-1, 2], [0, 65536], [True, 2], [1.5, 2]]:
        _assert_bad(tmp_path, raw, "doip.tester_addr_range", value)
    for value in [None, "not-list", [65536], [-1], [True], [1.5], ["bad"]]:
        _assert_bad(tmp_path, raw, "doip.tester_addr_list", value)
    config = _load_mutation(tmp_path, raw, "doip.tester_addr_range", ["0001", "0xffff"])
    assert config.doip.tester_addr_range == (1, 65535)


@pytest.mark.parametrize("field", ["routing_table.0.ecu_logical_addr", "routing_table.0.ecu_port_plain", "routing_table.0.ecu_port_tls"])
def test_routing_address_and_ports_validate_bounds(tmp_path, field):
    raw = _raw_config(CONFIG_FILES[0])
    for value in [0, 65536, True, 1.5, float("nan"), float("inf"), None, "bad"]:
        _assert_bad(tmp_path, raw, field, value)
    value = "0xffff" if "addr" in field else "0001"
    config = _load_mutation(tmp_path, raw, field, value)
    actual = config.routing_table[0]
    if field.endswith("ecu_logical_addr"):
        assert actual.ecu_logical_addr == 0xffff
    elif field.endswith("ecu_port_plain"):
        assert actual.ecu_port_plain == 1
    else:
        assert actual.ecu_port_tls == 1


def test_routing_entries_must_have_unique_addresses(tmp_path):
    raw = _raw_config(CONFIG_FILES[0])
    raw["routing_table"].append(deepcopy(raw["routing_table"][0]))
    with pytest.raises(ConfigError, match=r"routing_table\[1\].*duplicates"):
        load_config(_write_config(tmp_path, raw))


@pytest.mark.parametrize("field", ["timers.t_tcp_initial_inactivity_s", "timers.t_tcp_general_inactivity_s", "timers.ecu_response_timeout_s", "timers.ecu_pending_max_wait_s"])
def test_seconds_must_be_finite_positive_numbers_or_numeric_strings(tmp_path, field):
    raw = _raw_config(CONFIG_FILES[0])
    for value in [0, -1, True, False, float("nan"), float("inf"), 10**400, None, "bad"]:
        _assert_bad(tmp_path, raw, field, value)
    config = _load_mutation(tmp_path, raw, field, "0002.5")
    section, name = field.split(".")
    assert getattr(getattr(config, section), name) == 2.5


def test_timer_values_have_no_ordering_constraint(tmp_path):
    raw = _raw_config(CONFIG_FILES[0])
    raw["timers"]["t_tcp_initial_inactivity_s"] = 300
    raw["timers"]["t_tcp_general_inactivity_s"] = 2
    config = load_config(_write_config(tmp_path, raw))
    assert config.timers.t_tcp_initial_inactivity_s == 300


@pytest.mark.parametrize("mw_type, field, value", [
    ("ReplayMiddleware", "replay_count", 0),
    ("ReplayMiddleware", "replay_count", -1),
    ("ReplayMiddleware", "replay_count", True),
    ("ReplayMiddleware", "replay_count", 1.5),
    ("ReplayMiddleware", "replay_count", "bad"),
    ("HeaderFaultMiddleware", "inject_on_nth", 0),
    ("HeaderFaultMiddleware", "inject_on_nth", True),
    ("HeaderFaultMiddleware", "inject_on_nth", None),
])
def test_middleware_counts_are_at_least_one(tmp_path, mw_type, field, value):
    raw = _raw_config(CONFIG_FILES[0])
    index = next(i for i, m in enumerate(raw["middleware"]) if m["type"] == mw_type)
    changed = deepcopy(raw)
    changed["middleware"][index][field] = value
    with pytest.raises(ConfigError, match=rf"middleware\[{index}\].*{field}"):
        load_config(_write_config(tmp_path, changed))


def test_drop_rate_is_finite_number_inclusive_and_not_bool(tmp_path):
    raw = _raw_config(CONFIG_FILES[0])
    index = next(i for i, m in enumerate(raw["middleware"]) if m["type"] == "DropMiddleware")
    for value in [-0.1, 1.1, float("nan"), float("inf"), 10**400, True, False, "bad", None]:
        changed = deepcopy(raw)
        changed["middleware"][index]["drop_rate"] = value
        with pytest.raises(ConfigError, match=r"middleware\[1\].*drop_rate"):
            load_config(_write_config(tmp_path, changed))
    for value in [0, 1, 0.25]:
        changed = deepcopy(raw)
        changed["middleware"][index]["drop_rate"] = value
        assert load_config(_write_config(tmp_path, changed)).middleware[index].params["drop_rate"] == value


def test_middleware_match_none_is_valid_and_match_shape_is_strict(tmp_path):
    raw = _raw_config(CONFIG_FILES[0])
    index = next(i for i, m in enumerate(raw["middleware"]) if m["type"] == "DropMiddleware")
    for value in [None, {"direction": "tester_to_ecu", "payload_type": None}]:
        changed = deepcopy(raw)
        changed["middleware"][index]["match"] = value
        assert load_config(_write_config(tmp_path, changed)).middleware[index].params["match"] == value
    for value in ["bad", [], {1: "bad"}]:
        changed = deepcopy(raw)
        changed["middleware"][index]["match"] = value
        with pytest.raises(ConfigError, match=rf"middleware\[{index}\].*match"):
            load_config(_write_config(tmp_path, changed))


@pytest.mark.parametrize("direction", [1, True, "invalid"])
def test_middleware_match_and_header_direction_validate(tmp_path, direction):
    raw = _raw_config(CONFIG_FILES[0])
    index = next(i for i, m in enumerate(raw["middleware"]) if m["type"] == "DropMiddleware")
    changed = deepcopy(raw)
    changed["middleware"][index]["match"] = {"direction": direction}
    with pytest.raises(ConfigError, match="direction"):
        load_config(_write_config(tmp_path, changed))
    changed = deepcopy(raw)
    header = next(m for m in changed["middleware"] if m["type"] == "HeaderFaultMiddleware")
    header["direction"] = direction
    with pytest.raises(ConfigError, match="direction"):
        load_config(_write_config(tmp_path, changed))


@pytest.mark.parametrize("payload_type", [-1, 0x10000, True, 1.5, "bad"])
def test_match_payload_type_rejects_invalid_values(tmp_path, payload_type):
    raw = _raw_config(CONFIG_FILES[0])
    index = next(i for i, m in enumerate(raw["middleware"]) if m["type"] == "DropMiddleware")
    changed = deepcopy(raw)
    changed["middleware"][index]["match"] = {"payload_type": payload_type}
    with pytest.raises(ConfigError, match="payload_type"):
        load_config(_write_config(tmp_path, changed))


def test_header_fault_and_replay_validation(tmp_path):
    raw = _raw_config(CONFIG_FILES[0])
    for fault in [None, 1, True, "bad"]:
        changed = deepcopy(raw)
        header = next(m for m in changed["middleware"] if m["type"] == "HeaderFaultMiddleware")
        header["fault"] = fault
        with pytest.raises(ConfigError, match="fault"):
            load_config(_write_config(tmp_path, changed))
    changed = deepcopy(raw)
    tls = next(m for m in changed["middleware"] if m["type"] == "TLSFaultMiddleware")
    tls["fault"] = None
    with pytest.raises(ConfigError, match="fault"):
        load_config(_write_config(tmp_path, changed))
    replay_index = next(i for i, m in enumerate(raw["middleware"]) if m["type"] == "ReplayMiddleware")
    for value in [0, -1, True, 1.5, "bad", None]:
        changed = deepcopy(raw)
        changed["middleware"][replay_index]["replay_count"] = value
        with pytest.raises(ConfigError, match="replay_count"):
            load_config(_write_config(tmp_path, changed))


def test_logger_path_is_nonempty_actual_string(tmp_path):
    raw = _raw_config(CONFIG_FILES[0])
    index = next(i for i, m in enumerate(raw["middleware"]) if m["type"] == "LoggerMiddleware")
    for value in [None, "", 1, False, []]:
        changed = deepcopy(raw)
        changed["middleware"][index]["log_path"] = value
        with pytest.raises(ConfigError, match="log_path"):
            load_config(_write_config(tmp_path, changed))


def test_load_config_normalizes_io_and_unicode_errors(tmp_path, monkeypatch):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_bytes(b"network:\n  tester_interface: '\xff'\n")
    with pytest.raises(ConfigError):
        load_config(bad)


def test_udp_announcement_payload_preserves_loaded_values(tmp_path):
    config = load_config(CONFIG_FILES[0])
    payload = _announcement_payload(config)
    assert payload[:17] == config.doip.vin.encode("ascii")
    assert payload[17:19] == config.doip.node_logical_addr.to_bytes(2, "big")
    assert payload[19:25] == bytes.fromhex(config.doip.eid)
    assert payload[25:31] == bytes.fromhex(config.doip.gid)


def test_load_config_normalizes_yaml_syntax_and_directory_errors(tmp_path):
    malformed = tmp_path / "malformed.yaml"
    malformed.write_text("network: [\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(malformed)
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_nested_mapping_and_entry_null_shapes_are_rejected(tmp_path):
    raw = _raw_config(CONFIG_FILES[0])
    for section in ("network", "ports", "tls", "doip", "timers", "udp"):
        changed = deepcopy(raw)
        changed[section] = None
        with pytest.raises(ConfigError, match=section):
            load_config(_write_config(tmp_path, changed))
    for section in ("routing_table", "middleware"):
        changed = deepcopy(raw)
        changed[section] = [None]
        with pytest.raises(ConfigError, match=section):
            load_config(_write_config(tmp_path, changed))


def test_numeric_string_bounds_and_payload_match_edges(tmp_path):
    raw = _raw_config(CONFIG_FILES[0])
    for field, value, expected in [
        ("doip.node_type", "0", 0),
        ("doip.power_mode", "2", 2),
        ("doip.max_payload_bytes", "0xffffffff", 0xffffffff),
        ("doip.node_logical_addr", "0xffff", 0xffff),
    ]:
        config = _load_mutation(tmp_path, raw, field, value)
        section, name = field.split(".")
        assert getattr(getattr(config, section), name) == expected
    index = next(i for i, m in enumerate(raw["middleware"]) if m["type"] == "DropMiddleware")
    changed = deepcopy(raw)
    changed["middleware"][index]["match"] = {"payload_type": "0xffff"}
    assert load_config(_write_config(tmp_path, changed)).middleware[index].params["match"]["payload_type"] == 0xffff


def test_middleware_optional_defaults_are_retained(tmp_path):
    raw = _raw_config(CONFIG_FILES[0])
    raw["middleware"] = [
        {"type": "LoggerMiddleware"},
        {"type": "DropMiddleware"},
        {"type": "ReplayMiddleware"},
        {"type": "HeaderFaultMiddleware"},
    ]
    config = load_config(_write_config(tmp_path, raw))
    assert all(m.enabled is True and m.params == {} for m in config.middleware)


def test_drop_rate_huge_integer_is_rejected_without_overflow(tmp_path):
    raw = _raw_config(CONFIG_FILES[0])
    index = next(i for i, m in enumerate(raw["middleware"]) if m["type"] == "DropMiddleware")
    changed = deepcopy(raw)
    changed["middleware"][index]["drop_rate"] = 10**400
    with pytest.raises(ConfigError, match="drop_rate"):
        load_config(_write_config(tmp_path, changed))


def test_match_and_header_valid_directions_are_preserved(tmp_path):
    raw = _raw_config(CONFIG_FILES[0])
    index = next(i for i, m in enumerate(raw["middleware"]) if m["type"] == "DropMiddleware")
    for direction in (None, "tester_to_ecu", "ecu_to_tester"):
        changed = deepcopy(raw)
        changed["middleware"][index]["match"] = {"direction": direction}
        loaded = load_config(_write_config(tmp_path, changed))
        assert loaded.middleware[index].params["match"]["direction"] == direction
    header_index = next(i for i, m in enumerate(raw["middleware"]) if m["type"] == "HeaderFaultMiddleware")
    for direction in ("tester_to_ecu", "ecu_to_tester", "both"):
        loaded = _load_mutation(tmp_path, raw, f"middleware.{header_index}.direction", direction)
        assert loaded.middleware[header_index].params["direction"] == direction
    _assert_bad(tmp_path, raw, f"middleware.{header_index}.direction", None)


def test_middleware_match_nested_keys_must_be_strings(tmp_path):
    raw = _raw_config(CONFIG_FILES[0])
    index = next(i for i, m in enumerate(raw["middleware"]) if m["type"] == "DropMiddleware")
    changed = deepcopy(raw)
    changed["middleware"][index]["match"] = {1: "tester_to_ecu"}
    with pytest.raises(ConfigError, match="match"):
        load_config(_write_config(tmp_path, changed))
