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
TestEcu — an extensible DoIP/UDS ECU simulator.

Everything a plugin author needs is importable from this package::

    from testecu import Plugin, read_did, write_did, routine, on_service
    from testecu import NRC_CONDITIONS_NOT_CORRECT, NO_RESPONSE

See ``test_ecu/README.md`` for the full plugin guide.
"""

from __future__ import annotations

from testecu.plugin import (
    ANY_SERVICE,
    Context,
    Plugin,
    on_request,
    on_service,
    read_did,
    routine,
    write_did,
)
from testecu.uds import (
    DID_ACTIVE_DIAGNOSTIC_SESSION,
    FUNCTIONAL_SUPPRESSED_NRCS,
    NO_RESPONSE,
    NRC_BUSY_REPEAT_REQUEST,
    NRC_CONDITIONS_NOT_CORRECT,
    NRC_EXCEEDED_NUMBER_OF_ATTEMPTS,
    NRC_GENERAL_REJECT,
    NRC_INCORRECT_MESSAGE_LENGTH,
    NRC_INVALID_KEY,
    NRC_NAMES,
    NRC_REQUEST_OUT_OF_RANGE,
    NRC_REQUEST_SEQUENCE_ERROR,
    NRC_RESPONSE_PENDING,
    NRC_RESPONSE_TOO_LONG,
    NRC_SECURITY_ACCESS_DENIED,
    NRC_SERVICE_NOT_SUPPORTED,
    NRC_SERVICE_NOT_SUPPORTED_IN_SESSION,
    NRC_SUB_FUNCTION_NOT_SUPPORTED,
    SESSION_DEFAULT,
    SESSION_EXTENDED,
    SESSION_PROGRAMMING,
    SESSION_SAFETY,
    SUB_FUNCTION_SERVICES,
    NegativeResponse,
    UdsRequest,
    nrc_name,
    sid_name,
)

__version__ = "1.0.0"

__all__ = [
    # Plugin API
    "Plugin", "Context", "on_service", "on_request",
    "read_did", "write_did", "routine", "ANY_SERVICE",
    # Control flow
    "NegativeResponse", "NO_RESPONSE", "UdsRequest",
    # Sessions
    "SESSION_DEFAULT", "SESSION_PROGRAMMING", "SESSION_EXTENDED", "SESSION_SAFETY",
    "DID_ACTIVE_DIAGNOSTIC_SESSION", "SUB_FUNCTION_SERVICES",
    # NRCs
    "NRC_GENERAL_REJECT",
    "NRC_SERVICE_NOT_SUPPORTED",
    "NRC_SUB_FUNCTION_NOT_SUPPORTED",
    "NRC_INCORRECT_MESSAGE_LENGTH",
    "NRC_RESPONSE_TOO_LONG",
    "NRC_BUSY_REPEAT_REQUEST",
    "NRC_CONDITIONS_NOT_CORRECT",
    "NRC_REQUEST_SEQUENCE_ERROR",
    "NRC_REQUEST_OUT_OF_RANGE",
    "NRC_SECURITY_ACCESS_DENIED",
    "NRC_INVALID_KEY",
    "NRC_EXCEEDED_NUMBER_OF_ATTEMPTS",
    "NRC_RESPONSE_PENDING",
    "NRC_SERVICE_NOT_SUPPORTED_IN_SESSION",
    "NRC_NAMES", "FUNCTIONAL_SUPPRESSED_NRCS",
    "nrc_name", "sid_name",
    "__version__",
]
