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
The DID value store: YAML defaults plus anything written at runtime.

Writes persist for the process lifetime so a WriteDataByIdentifier followed by
a ReadDataByIdentifier round-trips — which is what makes the simulator useful
for testing tester-side write flows.  ECUReset restores the defaults when
``uds.reset_clears_writes`` is true.
"""

from __future__ import annotations

from typing import Dict, Iterator, Optional, Tuple

from testecu.config import DidSpec


class DidStore:
    """Current value of every statically declared DID."""

    def __init__(self, specs: Dict[int, DidSpec]) -> None:
        self._specs = specs
        self._values: Dict[int, bytes] = {}
        self.reset()

    # -- lookup ------------------------------------------------------------

    def spec(self, did: int) -> Optional[DidSpec]:
        return self._specs.get(did)

    def __contains__(self, did: int) -> bool:
        return did in self._specs

    def __iter__(self) -> Iterator[Tuple[int, DidSpec]]:
        return iter(sorted(self._specs.items()))

    def __len__(self) -> int:
        return len(self._specs)

    # -- values ------------------------------------------------------------

    def read(self, did: int) -> Optional[bytes]:
        """Current value, or None for an unknown or dynamic DID."""
        return self._values.get(did)

    def write(self, did: int, value: bytes) -> None:
        """Overwrite a DID value.  The caller has already checked permissions."""
        self._values[did] = bytes(value)

    def is_modified(self, did: int) -> bool:
        spec = self._specs.get(did)
        if spec is None or spec.value is None:
            return did in self._values
        return self._values.get(did) != spec.value

    def reset(self) -> None:
        """Restore every DID to its YAML default (ECUReset)."""
        self._values = {
            did: spec.value
            for did, spec in self._specs.items()
            if spec.value is not None
        }
