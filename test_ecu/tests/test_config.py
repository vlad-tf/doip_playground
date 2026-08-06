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

"""Config loading: coercion, encoding, and the errors that must be loud."""

from __future__ import annotations

import os

import pytest

from conftest import BASE_CONFIG, merge
from testecu.config import ConfigError, load_config, parse_config

REPO_TEST_ECU = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def cfg(extra=None):
    return parse_config(merge(BASE_CONFIG, extra))


class TestCoercion:
    def test_hex_strings_and_ints_both_work(self):
        parsed = cfg({"doip": {"ecu_logical_addr": "0x1234"}})
        assert parsed.doip.ecu_logical_addr == 0x1234
        assert cfg({"doip": {"ecu_logical_addr": 4660}}).doip.ecu_logical_addr == 0x1234

    def test_bad_integer_is_rejected(self):
        with pytest.raises(ConfigError) as exc:
            cfg({"doip": {"ecu_logical_addr": "not-a-number"}})
        assert "ecu_logical_addr" in str(exc.value)

    def test_booleans_are_not_integers(self):
        with pytest.raises(ConfigError):
            cfg({"doip": {"node_type": True}})


class TestDidTable:
    def test_ascii_pads_to_length(self):
        parsed = cfg({"data_identifiers": {
            0xF187: {"type": "ascii", "length": 10, "value": "TE-1"},
        }})
        assert parsed.dids[0xF187].value == b"TE-1" + b"\x00" * 6

    def test_ascii_truncates_to_length(self):
        parsed = cfg({"data_identifiers": {
            0xF187: {"type": "ascii", "length": 3, "value": "ABCDEF"},
        }})
        assert parsed.dids[0xF187].value == b"ABC"

    def test_uint_uses_length_as_width(self):
        parsed = cfg({"data_identifiers": {
            0x0200: {"type": "uint", "length": 2, "value": 300},
        }})
        assert parsed.dids[0x0200].value == b"\x01\x2c"

    def test_uint_overflow_is_rejected(self):
        with pytest.raises(ConfigError) as exc:
            cfg({"data_identifiers": {0x0200: {"type": "uint", "length": 1, "value": 300}}})
        assert "does not fit" in str(exc.value)

    def test_hex_length_mismatch_is_rejected(self):
        with pytest.raises(ConfigError) as exc:
            cfg({"data_identifiers": {0x0100: {"type": "hex", "length": 4,
                                               "value": "DEAD"}}})
        assert "length" in str(exc.value)

    def test_missing_value_is_rejected(self):
        with pytest.raises(ConfigError) as exc:
            cfg({"data_identifiers": {0x0100: {"type": "hex"}}})
        assert "missing 'value'" in str(exc.value)

    def test_dynamic_must_not_carry_a_value(self):
        with pytest.raises(ConfigError):
            cfg({"data_identifiers": {0xF186: {"type": "dynamic", "value": "00"}}})

    def test_dynamic_cannot_be_writable(self):
        with pytest.raises(ConfigError) as exc:
            cfg({"data_identifiers": {0xF186: {"type": "dynamic", "write": True}}})
        assert "cannot be writable" in str(exc.value)

    def test_unknown_type_is_rejected(self):
        with pytest.raises(ConfigError):
            cfg({"data_identifiers": {0x0100: {"type": "float", "value": 1}}})

    def test_unknown_nrc_is_rejected(self):
        with pytest.raises(ConfigError) as exc:
            cfg({"data_identifiers": {0x0100: {"type": "hex", "value": "00",
                                               "read_nrc": 0x99}}})
        assert "not a known NRC" in str(exc.value)

    def test_gate_session_must_be_configured(self):
        with pytest.raises(ConfigError) as exc:
            cfg({"data_identifiers": {0x0100: {"type": "hex", "value": "00",
                                               "read_sessions": [0x7F]}}})
        assert "uds.sessions" in str(exc.value)


class TestUdsSection:
    def test_policy_values_are_validated(self):
        with pytest.raises(ConfigError) as exc:
            cfg({"uds": {"unknown_service": "explode"}})
        assert "unknown_service" in str(exc.value)

    def test_default_session_must_be_offered(self):
        with pytest.raises(ConfigError) as exc:
            cfg({"uds": {"default_session": 0x03, "sessions": [0x01]}})
        assert "default_session" in str(exc.value)

    def test_security_key_length_must_match_seed(self):
        with pytest.raises(ConfigError) as exc:
            cfg({"uds": {"security": {"seed": "1122", "key": "AABBCC"}}})
        assert "same length" in str(exc.value)

    def test_functional_address_must_differ_from_the_ecu(self):
        with pytest.raises(ConfigError) as exc:
            cfg({"uds": {"functional_addr": 0x0002}})
        assert "functional_addr" in str(exc.value)


class TestPlugins:
    def test_entry_needs_exactly_one_source(self):
        with pytest.raises(ConfigError) as exc:
            cfg({"plugins": {"modules": [{"file": "a.py", "module": "b"}]}})
        assert "exactly one" in str(exc.value)

    def test_missing_directory_is_only_a_warning(self, caplog):
        """A container started without its plugin volume must still come up."""
        parsed = cfg({"plugins": {"path": ["definitely/not/here"]}})
        assert parsed.plugins.specs == []
        assert any("not a directory" in record.message for record in caplog.records)

    def test_missing_directory_is_fatal_in_strict_mode(self):
        with pytest.raises(ConfigError) as exc:
            cfg({"plugins": {"strict": True, "path": ["definitely/not/here"]}})
        assert "not a directory" in str(exc.value)

    def test_directory_scan_is_sorted_and_skips_underscores(self, tmp_path):
        for name in ("b_second.py", "a_first.py", "_private.py", "notes.txt"):
            (tmp_path / name).write_text("")
        parsed = parse_config(merge(BASE_CONFIG, {"plugins": {"path": [str(tmp_path)]}}))
        assert [os.path.basename(spec.file) for spec in parsed.plugins.specs] == \
            ["a_first.py", "b_second.py"]


class TestShippedConfig:
    def test_the_config_we_ship_loads(self):
        """The default config.yaml must always be valid — it is the example."""
        parsed = load_config(os.path.join(REPO_TEST_ECU, "config.yaml"))
        assert parsed.doip.ecu_logical_addr == 0x0002
        assert parsed.dids[0xF190].value == b"1HGBH41JXMN109186"
        assert parsed.dids[0xF186].dynamic
        assert parsed.routines[0x0201].results == b"\x00\x01"

    def test_missing_file_raises_config_error(self):
        with pytest.raises(ConfigError) as exc:
            load_config(os.path.join(REPO_TEST_ECU, "nope.yaml"))
        assert "not found" in str(exc.value)
