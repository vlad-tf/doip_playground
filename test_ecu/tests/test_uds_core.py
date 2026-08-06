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

"""The built-in UDS core: session control, reset, security, and every NRC path."""

from __future__ import annotations

import asyncio

from conftest import probe_for, run

DIDS = {
    0xF190: {"type": "ascii", "length": 17, "value": "1HGBH41JXMN109186"},
    0xF186: {"type": "dynamic"},
    0x0100: {"type": "hex", "length": 4, "value": "DEADBEEF", "write": True,
             "write_sessions": [0x03], "write_security": 1},
    0x0200: {"type": "uint", "length": 1, "value": 85},
    0xF1A0: {"type": "hex", "value": "00", "read_nrc": 0x22},
}

CONFIG = {"data_identifiers": DIDS,
          "routines": {0x0201: {"sessions": [0x03], "start": "00", "stop": "00",
                                "results": "0001"}}}

#: seed 11223344 XOR key A5A5A5A5
GOOD_KEY = "B4 87 96 E1"


def hx(data):
    return None if data is None else data.hex(" ").upper()


class TestDiagnosticSessionControl:
    def test_switches_session_and_reports_timings(self):
        p = probe_for(CONFIG)
        # p2 = 20 ms -> 0x0014 ; p2* = 500 ms / 10 -> 0x0032
        assert hx(p.send("10 03")) == "50 03 00 14 00 32"
        assert p.state.session_type == 0x03

    def test_wrong_length_is_incorrect_message_length(self):
        assert hx(probe_for(CONFIG).send("10 03 00")) == "7F 10 13"

    def test_unconfigured_session_is_sub_function_not_supported(self):
        p = probe_for({"uds": {"sessions": [0x01, 0x03]}})
        assert hx(p.send("10 02")) == "7F 10 12"

    def test_switching_session_relocks_security(self):
        p = probe_for(CONFIG)
        p.exchange("10 03", "27 01", "27 02 " + GOOD_KEY)
        assert p.state.security_level == 1
        p.exchange("10 01")
        assert p.state.security_level == 0


class TestTesterPresent:
    def test_plain_request_is_answered(self):
        assert hx(probe_for().send("3E 00")) == "7E 00"

    def test_suppress_bit_silences_the_positive_response(self):
        assert probe_for().send("3E 80") is None

    def test_suppress_bit_does_not_silence_a_negative_response(self):
        # sub-function 0x01 does not exist, so 3E 81 must still answer 7F 3E 12
        assert hx(probe_for().send("3E 81")) == "7F 3E 12"

    def test_wrong_length(self):
        assert hx(probe_for().send("3E")) == "7F 3E 13"


class TestEcuReset:
    def test_restores_defaults_and_relocks(self):
        p = probe_for(CONFIG)
        p.exchange("10 03", "27 01", "27 02 " + GOOD_KEY, "2E 01 00 11 22 33 44")
        assert hx(p.send("22 01 00")) == "62 01 00 11 22 33 44"

        assert hx(p.send("11 01")) == "51 01"
        assert p.state.session_type == 0x01
        assert p.state.security_level == 0
        assert hx(p.send("22 01 00")) == "62 01 00 DE AD BE EF"

    def test_keeps_writes_when_configured_to(self):
        p = probe_for(dict(CONFIG, uds={"reset_clears_writes": False}))
        p.exchange("10 03", "27 01", "27 02 " + GOOD_KEY,
                   "2E 01 00 11 22 33 44", "11 01")
        assert hx(p.send("22 01 00")) == "62 01 00 11 22 33 44"

    def test_unsupported_sub_function(self):
        assert hx(probe_for().send("11 05")) == "7F 11 12"


class TestReadDataByIdentifier:
    def test_reads_a_static_did(self):
        assert hx(probe_for(CONFIG).send("22 F1 90")).startswith("62 F1 90 31 48")

    def test_reads_several_dids_in_request_order(self):
        assert hx(probe_for(CONFIG).send("22 02 00 01 00")) == \
            "62 02 00 55 01 00 DE AD BE EF"

    def test_dynamic_did_reports_the_active_session(self):
        p = probe_for(CONFIG)
        assert hx(p.send("22 F1 86")) == "62 F1 86 01"
        assert hx(p.exchange("10 03", "22 F1 86")[1]) == "62 F1 86 03"

    def test_did_high_byte_is_not_mistaken_for_a_suppress_bit(self):
        """0xF1 has bit 7 set — 0x22 has no sub-function, so it must not suppress."""
        assert probe_for(CONFIG).send("22 F1 90") is not None

    def test_unknown_did_is_request_out_of_range(self):
        assert hx(probe_for(CONFIG).send("22 99 99")) == "7F 22 31"

    def test_odd_length_is_incorrect_message_length(self):
        assert hx(probe_for(CONFIG).send("22 F1")) == "7F 22 13"
        assert hx(probe_for(CONFIG).send("22")) == "7F 22 13"

    def test_forced_nrc_from_config(self):
        assert hx(probe_for(CONFIG).send("22 F1 A0")) == "7F 22 22"

    def test_oversize_response_is_rejected(self):
        p = probe_for(dict(CONFIG, doip={"max_payload_bytes": 8}))
        assert hx(p.send("22 F1 90")) == "7F 22 14"

    def test_echo_policy_answers_with_the_identifier(self):
        p = probe_for(dict(CONFIG, uds={"unknown_did": "echo"}))
        assert hx(p.send("22 99 99")) == "62 99 99 99 99"

    def test_silent_policy_sends_nothing(self):
        p = probe_for(dict(CONFIG, uds={"unknown_did": "silent"}))
        assert p.send("22 99 99") is None


class TestWriteDataByIdentifier:
    def test_session_gate(self):
        assert hx(probe_for(CONFIG).send("2E 01 00 11 22 33 44")) == "7F 2E 31"

    def test_security_gate(self):
        p = probe_for(CONFIG)
        assert hx(p.exchange("10 03", "2E 01 00 11 22 33 44")[1]) == "7F 2E 33"

    def test_accepted_write_round_trips(self):
        p = probe_for(CONFIG)
        responses = p.exchange("10 03", "27 01", "27 02 " + GOOD_KEY,
                               "2E 01 00 11 22 33 44", "22 01 00")
        assert hx(responses[3]) == "6E 01 00"
        assert hx(responses[4]) == "62 01 00 11 22 33 44"

    def test_wrong_value_length(self):
        p = probe_for(CONFIG)
        responses = p.exchange("10 03", "27 01", "27 02 " + GOOD_KEY, "2E 01 00 11 22")
        assert hx(responses[3]) == "7F 2E 13"

    def test_read_only_did_is_rejected(self):
        assert hx(probe_for(CONFIG).send("2E F1 90 41")) == "7F 2E 31"

    def test_too_short(self):
        assert hx(probe_for(CONFIG).send("2E 01 00")) == "7F 2E 13"


class TestSecurityAccess:
    def test_seed_then_key_unlocks(self):
        p = probe_for(CONFIG)
        responses = p.exchange("27 01", "27 02 " + GOOD_KEY)
        assert hx(responses[0]) == "67 01 11 22 33 44"
        assert hx(responses[1]) == "67 02"
        assert p.state.security_level == 1

    def test_seed_is_deterministic_across_ecus(self):
        assert probe_for(CONFIG).send("27 01") == probe_for(CONFIG).send("27 01")

    def test_wrong_key_is_invalid_key(self):
        p = probe_for(CONFIG)
        assert hx(p.exchange("27 01", "27 02 DE AD BE EF")[1]) == "7F 27 35"
        assert p.state.security_level == 0

    def test_attempts_are_counted(self):
        p = probe_for(dict(CONFIG, uds={"security": {"max_attempts": 2}}))
        responses = p.exchange("27 01", "27 02 00 00 00 00",
                               "27 01", "27 02 00 00 00 00")
        assert hx(responses[1]) == "7F 27 35"      # attempt 1 of 2
        assert hx(responses[3]) == "7F 27 36"      # exceeded

    def test_key_without_seed_is_a_sequence_error(self):
        assert hx(probe_for(CONFIG).send("27 02 " + GOOD_KEY)) == "7F 27 24"

    def test_key_of_the_wrong_length(self):
        p = probe_for(CONFIG)
        assert hx(p.exchange("27 01", "27 02 AA")[1]) == "7F 27 13"

    def test_already_unlocked_returns_a_zero_seed(self):
        p = probe_for(CONFIG)
        responses = p.exchange("27 01", "27 02 " + GOOD_KEY, "27 01")
        assert hx(responses[2]) == "67 01 00 00 00 00"

    def test_disabled_falls_through_to_service_not_supported(self):
        p = probe_for(dict(CONFIG, uds={"security": {"enabled": False}}))
        assert hx(p.send("27 01")) == "7F 27 11"

    def test_add_algorithm(self):
        p = probe_for(dict(CONFIG, uds={"security": {"algorithm": "add",
                                                     "seed": "01 02",
                                                     "key": "10 20"}}))
        assert hx(p.exchange("27 01", "27 02 11 22")[1]) == "67 02"


class TestRoutineControl:
    def test_start_stop_results_from_yaml(self):
        p = probe_for(CONFIG)
        responses = p.exchange("10 03", "31 01 02 01", "31 03 02 01", "31 02 02 01")
        assert hx(responses[1]) == "71 01 02 01 00"
        assert hx(responses[2]) == "71 03 02 01 00 01"
        assert hx(responses[3]) == "71 02 02 01 00"

    def test_results_before_start_is_conditions_not_correct(self):
        p = probe_for(CONFIG)
        assert hx(p.exchange("10 03", "31 03 02 01")[1]) == "7F 31 22"

    def test_stop_before_start_is_a_sequence_error(self):
        p = probe_for(CONFIG)
        assert hx(p.exchange("10 03", "31 02 02 01")[1]) == "7F 31 24"

    def test_session_gate(self):
        assert hx(probe_for(CONFIG).send("31 01 02 01")) == "7F 31 31"

    def test_unknown_routine(self):
        assert hx(probe_for(CONFIG).send("31 01 99 99")) == "7F 31 31"

    def test_bad_sub_function(self):
        assert hx(probe_for(CONFIG).send("31 07 02 01")) == "7F 31 12"

    def test_too_short(self):
        assert hx(probe_for(CONFIG).send("31 01 02")) == "7F 31 13"


class TestUnknownService:
    def test_default_policy_is_service_not_supported(self):
        assert hx(probe_for().send("99 11 22")) == "7F 99 11"

    def test_echo_policy_is_deterministic(self):
        p = probe_for({"uds": {"unknown_service": "echo"}})
        first = p.send("99 11 22")
        assert hx(first) == "D9 11 22"
        assert probe_for({"uds": {"unknown_service": "echo"}}).send("99 11 22") == first

    def test_silent_policy(self):
        assert probe_for({"uds": {"unknown_service": "silent"}}).send("99") is None


class TestFunctionalAddressing:
    def test_suppressed_nrcs_are_dropped(self):
        p = probe_for(CONFIG)
        # serviceNotSupported (0x11) must not be answered functionally
        assert run(_functional(p, "99")) is None

    def test_other_nrcs_are_still_sent(self):
        p = probe_for(CONFIG)
        # conditionsNotCorrect (0x22) is not in the suppressed set
        assert hx(run(_functional(p, "22 F1 A0"))) == "7F 22 22"

    def test_positive_responses_are_sent(self):
        p = probe_for(CONFIG)
        assert hx(run(_functional(p, "22 F1 86"))) == "62 F1 86 01"


async def _functional(probe, request):
    await probe.ecu.startup()
    return await probe.asend(request, functional=True)


class TestS3Timer:
    def test_non_default_session_expires_back_to_default(self):
        p = probe_for(dict(CONFIG, uds={"s3_server_ms": 60}))

        async def scenario():
            await p.ecu.startup()
            await p.asend("10 03")
            assert p.state.session_type == 0x03
            await asyncio.sleep(0.15)
            return p.state.session_type, p.state.security_level

        assert scenario_result(scenario) == (0x01, 0)

    def test_requests_keep_the_session_alive(self):
        p = probe_for(dict(CONFIG, uds={"s3_server_ms": 120}))

        async def scenario():
            await p.ecu.startup()
            await p.asend("10 03")
            for _ in range(4):
                await asyncio.sleep(0.05)
                await p.asend("22 F1 90")
            return p.state.session_type

        assert scenario_result(scenario) == 0x03


def scenario_result(scenario):
    return run(scenario())
