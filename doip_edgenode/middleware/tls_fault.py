"""
DoIP EdgeNode — TLS fault middleware placeholder.

TLS fault injection requires operating at the handshake layer, before
any DoIP frame exists.  This middleware slot is therefore a no-op
pass-through in v1.  Future implementation will wire the TLSFaultPolicy
fields into the Scapy TLS automaton callbacks in tls_bridge.py.

See tls_bridge.TLSFaultPolicy for the planned fault fields.
"""

from __future__ import annotations

import logging
from typing import Literal, TYPE_CHECKING

from middleware import Middleware

if TYPE_CHECKING:
    from session import DoIPSession

logger = logging.getLogger(__name__)


class TLSFaultMiddleware(Middleware):
    """No-op placeholder.  Logs a warning and passes every packet through."""

    def __init__(self, fault: str = "wrong_cipher", **kwargs) -> None:
        self.fault = fault
        self.enabled = kwargs.get("enabled", False)

    async def process(
        self,
        pkt,
        direction: Literal["tester_to_ecu", "ecu_to_tester"],
        session: "DoIPSession",
    ):
        if self.enabled:
            logger.warning(
                "TLSFaultMiddleware: fault '%s' is configured but NOT yet implemented. "
                "Passing packet through unchanged. See TLSFaultPolicy in tls_bridge.py.",
                self.fault,
            )
        return pkt
