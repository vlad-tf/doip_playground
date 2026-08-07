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

"""The DID value store on its own, without the UDS layer on top."""

from __future__ import annotations

from conftest import BASE_CONFIG, merge
from testecu.config import parse_config
from testecu.store import DidStore

SPECS = {
    0xF190: {"type": "ascii", "length": 17, "value": "1HGBH41JXMN109186"},
    0xF186: {"type": "dynamic"},
    0x0100: {"type": "hex", "length": 4, "value": "DEADBEEF", "write": True},
    0x0200: {"type": "uint", "length": 2, "value": 300},
}


def store() -> DidStore:
    config = parse_config(merge(BASE_CONFIG, {"data_identifiers": SPECS}))
    return DidStore(config.dids)


class TestDefaults:
    def test_values_come_from_the_config(self):
        assert store().read(0xF190) == b"1HGBH41JXMN109186"
        assert store().read(0x0100) == b"\xDE\xAD\xBE\xEF"
        assert store().read(0x0200) == b"\x01\x2C"

    def test_dynamic_dids_have_no_stored_value(self):
        assert store().read(0xF186) is None
        assert 0xF186 in store()          # but the spec is known

    def test_unknown_did(self):
        assert store().read(0x9999) is None
        assert 0x9999 not in store()

    def test_iteration_is_sorted_by_identifier(self):
        assert [did for did, _spec in store()] == [0x0100, 0x0200, 0xF186, 0xF190]

    def test_len_counts_specs_not_values(self):
        assert len(store()) == 4


class TestWrites:
    def test_write_then_read_round_trips(self):
        subject = store()
        subject.write(0x0100, b"\x01\x02\x03\x04")
        assert subject.read(0x0100) == b"\x01\x02\x03\x04"

    def test_reset_restores_every_default(self):
        subject = store()
        subject.write(0x0100, b"\x00\x00\x00\x00")
        subject.write(0xF190, b"OTHER")
        subject.reset()
        assert subject.read(0x0100) == b"\xDE\xAD\xBE\xEF"
        assert subject.read(0xF190) == b"1HGBH41JXMN109186"

    def test_is_modified_tracks_divergence_from_the_default(self):
        subject = store()
        assert not subject.is_modified(0x0100)
        subject.write(0x0100, b"\x00\x00\x00\x00")
        assert subject.is_modified(0x0100)
        subject.write(0x0100, b"\xDE\xAD\xBE\xEF")
        assert not subject.is_modified(0x0100)

    def test_stored_values_are_copied_not_aliased(self):
        subject = store()
        buffer = bytearray(b"\x01\x02\x03\x04")
        subject.write(0x0100, buffer)
        buffer[0] = 0xFF
        assert subject.read(0x0100) == b"\x01\x02\x03\x04"
