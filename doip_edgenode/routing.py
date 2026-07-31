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
DoIP EdgeNode — Routing table.

Wraps the list of RoutingEntry objects (loaded from config.yaml) and
provides O(n) lookup by tester or ECU logical address.  For a PoC with
a small routing table, linear scan is perfectly adequate.
"""

from __future__ import annotations

from config import RoutingEntry


class RoutingTable:
    def __init__(self, entries: list[RoutingEntry]) -> None:
        self._entries: list[RoutingEntry] = list(entries)

    def lookup_by_tester_addr(self, addr: int) -> RoutingEntry | None:
        """Return the entry whose tester_logical_addr matches, or None."""
        for entry in self._entries:
            if entry.tester_logical_addr == addr:
                return entry
        return None

    def lookup_by_ecu_addr(self, addr: int) -> RoutingEntry | None:
        """Return the entry whose ecu_logical_addr matches, or None."""
        for entry in self._entries:
            if entry.ecu_logical_addr == addr:
                return entry
        return None

    def all_entries(self) -> list[RoutingEntry]:
        """Return a copy of all routing entries."""
        return list(self._entries)
