"""
DoIP PC Tester — simple command-line DoIP client for testing the EdgeNode.

Connects to a DoIP node over plain TCP (no TLS).
No Scapy required — pure Python stdlib only.

Usage:
    python3 tester.py [--config config.yaml] [--log-level INFO]

Interactive commands:
    activate [src_addr_hex]      Send Routing Activation Request
                                 (default: tester_logical_addr from config)
    diag [hex bytes...]          Send Diagnostic Message
                                 e.g.  diag 10 01   or  diag 1001
    alive                        Send Alive Check Request
    status                       Send Entity Status Request
    power                        Send Power Mode Info Request
    help                         Show this list
    quit / exit / q              Disconnect and exit

Examples:
    diag 10 01          DiagnosticSessionControl — switch to default session
    diag 22 F1 90       ReadDataByIdentifier — VIN
    diag 3E 00          TesterPresent

DoIP header format (ISO 13400-2):
    byte 0   : protocol version (0x02)
    byte 1   : inverse version  (0xFD)
    bytes 2-3: payload type
    bytes 4-7: payload length (big-endian uint32)
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import struct
import sys
from typing import Optional

import yaml

logger = logging.getLogger("tester")

# ---------------------------------------------------------------------------
# DoIP constants
# ---------------------------------------------------------------------------

_VER = 0x02
_INV = 0xFF ^ _VER

PT_HEADER_NACK              = 0x0000
PT_ROUTING_ACT_REQUEST      = 0x0005
PT_ROUTING_ACT_RESPONSE     = 0x0006
PT_ALIVE_CHECK_REQUEST      = 0x0007
PT_ALIVE_CHECK_RESPONSE     = 0x0008
PT_ENTITY_STATUS_REQUEST    = 0x4001
PT_ENTITY_STATUS_RESPONSE   = 0x4002
PT_POWER_MODE_REQUEST       = 0x4003
PT_POWER_MODE_RESPONSE      = 0x4004
PT_DIAGNOSTIC_MESSAGE       = 0x8001
PT_DIAGNOSTIC_POSITIVE_ACK  = 0x8002
PT_DIAGNOSTIC_NEGATIVE_ACK  = 0x8003

PTYPE_NAMES = {
    PT_HEADER_NACK:             "Header NACK",
    PT_ROUTING_ACT_REQUEST:     "Routing Activation Request",
    PT_ROUTING_ACT_RESPONSE:    "Routing Activation Response",
    PT_ALIVE_CHECK_REQUEST:     "Alive Check Request",
    PT_ALIVE_CHECK_RESPONSE:    "Alive Check Response",
    PT_ENTITY_STATUS_REQUEST:   "Entity Status Request",
    PT_ENTITY_STATUS_RESPONSE:  "Entity Status Response",
    PT_POWER_MODE_REQUEST:      "Power Mode Info Request",
    PT_POWER_MODE_RESPONSE:     "Power Mode Info Response",
    PT_DIAGNOSTIC_MESSAGE:      "Diagnostic Message",
    PT_DIAGNOSTIC_POSITIVE_ACK: "Diagnostic Message Positive ACK",
    PT_DIAGNOSTIC_NEGATIVE_ACK: "Diagnostic Message Negative ACK",
}

RA_RESPONSE_CODES = {
    0x00: "Denied — unknown source address",
    0x01: "Denied — all sockets registered and active",
    0x02: "Denied — SA different from already registered SA",
    0x03: "Denied — SA already registered on different socket",
    0x04: "Denied — authentication missing",
    0x05: "Denied — confirmation rejected",
    0x06: "Denied — unsupported routing activation type",
    0x10: "Successfully activated",
    0x11: "Activated, confirmation pending",
}

DIAG_NACK_CODES = {
    0x02: "Invalid source address",
    0x03: "Target unreachable",
    0x04: "Message too large",
    0x05: "Out of memory",
    0x06: "Target unknown",
    0x07: "Message transmitted, positive ACK timeout",
    0x08: "Message transmitted, negative ACK timeout",
    0x09: "Network link failure",
}


# ---------------------------------------------------------------------------
# Frame helpers
# ---------------------------------------------------------------------------

def _build(payload_type: int, payload: bytes) -> bytes:
    return struct.pack("!BBHI", _VER, _INV, payload_type, len(payload)) + payload


async def _read_frame(reader: asyncio.StreamReader) -> bytes:
    hdr = await reader.readexactly(8)
    plen = struct.unpack("!I", hdr[4:8])[0]
    if plen == 0:
        return hdr
    payload = await reader.readexactly(plen)
    return hdr + payload


def _ptype(raw: bytes) -> int:
    return struct.unpack("!H", raw[2:4])[0]


def _plen(raw: bytes) -> int:
    return struct.unpack("!I", raw[4:8])[0]


def _payload(raw: bytes) -> bytes:
    return raw[8:]


def _fmt_hex(data: bytes, max_bytes: int = 64) -> str:
    if not data:
        return "(empty)"
    h = data[:max_bytes].hex(" ").upper()
    return h + (" …" if len(data) > max_bytes else "")


def _parse_hex_input(parts: list[str]) -> bytes:
    """Parse hex bytes from user input.  Accepts '10 01', '1001', '0x10 0x01'."""
    joined = "".join(p.replace("0x", "").replace("0X", "") for p in parts)
    if len(joined) % 2:
        raise ValueError(f"Odd number of hex nibbles: {joined!r}")
    return bytes.fromhex(joined)


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

class DoIPTester:
    """
    DoIP tester with a background reader task.

    The background reader runs concurrently with the REPL and handles
    unsolicited frames from the EdgeNode:

      - Alive Check Request (0x0007): reply immediately with Alive Check
        Response (0x0008) containing our tester logical address.  This is
        critical: the EdgeNode sends this probe to the old connection when
        a new tester tries to activate with the same SA.  Without an
        automatic reply the EdgeNode would always consider us dead and
        evict the session.

      - All other frames: placed on _recv_queue for the REPL to consume
        via _recv().

    The background task exits cleanly when the connection is closed.
    """

    def __init__(
        self,
        host: str,
        port: int,
        tester_addr: int,
        ecu_addr: int,
        timeout: float = 5.0,
    ) -> None:
        self.host = host
        self.port = port
        self.tester_addr = tester_addr
        self.ecu_addr = ecu_addr
        self.timeout = timeout

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self.activated = False

        # Background reader feeds responses here; REPL consumes via _recv()
        self._recv_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._reader_task: asyncio.Task | None = None
        # Set when the background reader exits (connection closed or error)
        self._closed_event: asyncio.Event = asyncio.Event()

    async def connect(self) -> None:
        logger.info("Connecting to %s:%d …", self.host, self.port)
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port),
            timeout=self.timeout,
        )
        self._closed_event.clear()
        self._reader_task = asyncio.create_task(
            self._background_reader(), name="tester-reader"
        )
        logger.info("TCP connected.")

    async def disconnect(self) -> None:
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
        self._reader = None
        self._writer = None
        self.activated = False
        logger.info("Disconnected.")

    async def _background_reader(self) -> None:
        """
        Continuously read frames from the EdgeNode.

        - Alive Check Request → reply immediately (transparent to REPL).
        - Everything else     → enqueue for _recv().
        """
        assert self._reader is not None
        try:
            while True:
                raw = await _read_frame(self._reader)
                pt = _ptype(raw)

                if pt == PT_ALIVE_CHECK_REQUEST:
                    # ISO 13400-2: reply with our tester logical address
                    logger.debug(
                        "background: received Alive Check Request — replying"
                    )
                    resp_payload = struct.pack("!H", self.tester_addr)
                    await self._send(_build(PT_ALIVE_CHECK_RESPONSE, resp_payload))
                    print(
                        "\n  [EdgeNode sent Alive Check Request — replied automatically]"
                        "\ndoip> ",
                        end="",
                        flush=True,
                    )
                else:
                    await self._recv_queue.put(raw)

        except asyncio.IncompleteReadError:
            logger.info("background: connection closed by remote.")
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.debug("background: reader error: %s", exc)
        finally:
            self._closed_event.set()

    async def _send(self, raw: bytes) -> None:
        assert self._writer is not None, "Not connected"
        self._writer.write(raw)
        await self._writer.drain()

    async def _recv(self) -> bytes:
        """
        Get the next response frame queued by the background reader.
        Raises asyncio.TimeoutError if nothing arrives within self.timeout.
        Raises ConnectionResetError if the connection was closed.
        """
        try:
            return await asyncio.wait_for(
                self._recv_queue.get(), timeout=self.timeout
            )
        except asyncio.TimeoutError:
            if self._closed_event.is_set():
                raise ConnectionResetError("Connection closed by remote")
            raise

    def _print_response(self, raw: bytes) -> None:
        pt = _ptype(raw)
        name = PTYPE_NAMES.get(pt, f"unknown (0x{pt:04X})")
        payload = _payload(raw)
        print(f"  ← {name}  (0x{pt:04X})  {len(payload)} bytes payload")

        if pt == PT_ROUTING_ACT_RESPONSE and len(payload) >= 5:
            code = payload[4]
            desc = RA_RESPONSE_CODES.get(code, f"unknown (0x{code:02X})")
            print(f"       response code: 0x{code:02X} — {desc}")

        elif pt == PT_DIAGNOSTIC_POSITIVE_ACK and len(payload) >= 5:
            src = struct.unpack("!H", payload[0:2])[0]
            tgt = struct.unpack("!H", payload[2:4])[0]
            code = payload[4]
            print(f"       src=0x{src:04X}  tgt=0x{tgt:04X}  ack_code=0x{code:02X}")

        elif pt == PT_DIAGNOSTIC_NEGATIVE_ACK and len(payload) >= 5:
            code = payload[4]
            desc = DIAG_NACK_CODES.get(code, f"unknown (0x{code:02X})")
            print(f"       NACK code: 0x{code:02X} — {desc}")

        elif pt == PT_DIAGNOSTIC_MESSAGE and len(payload) >= 5:
            src = struct.unpack("!H", payload[0:2])[0]
            tgt = struct.unpack("!H", payload[2:4])[0]
            uds = payload[4:]
            print(f"       src=0x{src:04X}  tgt=0x{tgt:04X}")
            print(f"       UDS: {_fmt_hex(uds)}")

        elif pt == PT_ENTITY_STATUS_RESPONSE and len(payload) >= 7:
            node_type   = payload[0]
            max_sockets = payload[1]
            open_sockets = payload[2]
            max_data = struct.unpack("!I", payload[3:7])[0]
            print(f"       node_type=0x{node_type:02X}  "
                  f"max_sockets={max_sockets}  "
                  f"open={open_sockets}  "
                  f"max_data={max_data}")

        elif pt == PT_POWER_MODE_RESPONSE and len(payload) >= 1:
            modes = {0x00: "not ready", 0x01: "ready", 0x02: "not supported"}
            mode = payload[0]
            print(f"       power_mode=0x{mode:02X} — {modes.get(mode, 'unknown')}")

        elif pt == PT_HEADER_NACK and len(payload) >= 1:
            codes = {
                0x00: "incorrect pattern", 0x01: "unknown type",
                0x02: "message too large", 0x03: "out of memory",
                0x04: "invalid payload length",
            }
            code = payload[0]
            print(f"       NACK code: 0x{code:02X} — {codes.get(code, 'unknown')}")

        elif pt == PT_ALIVE_CHECK_RESPONSE:
            if len(payload) >= 2:
                src = struct.unpack("!H", payload[0:2])[0]
                print(f"       src=0x{src:04X}  (alive)")
            else:
                print("       (alive)")

        else:
            if payload:
                print(f"       payload: {_fmt_hex(payload)}")

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    async def cmd_activate(self, src_addr: int | None = None) -> bool:
        addr = src_addr if src_addr is not None else self.tester_addr
        # Routing Activation Request payload (7 bytes):
        #   bytes 0-1: tester logical address
        #   byte  2:   activation type (0x00 = default)
        #   bytes 3-6: reserved
        payload = struct.pack("!HB", addr, 0x00) + b"\x00\x00\x00\x00"
        raw = _build(PT_ROUTING_ACT_REQUEST, payload)
        print(f"  → Routing Activation Request  src=0x{addr:04X}")
        await self._send(raw)
        resp = await self._recv()
        self._print_response(resp)
        pt = _ptype(resp)
        p = _payload(resp)
        if pt == PT_ROUTING_ACT_RESPONSE and len(p) >= 5 and p[4] == 0x10:
            self.activated = True
            return True
        return False

    async def cmd_diag(self, uds_payload: bytes) -> None:
        if not self.activated:
            print("  ! Not activated. Run 'activate' first.")
            return
        payload = struct.pack("!HH", self.tester_addr, self.ecu_addr) + uds_payload
        raw = _build(PT_DIAGNOSTIC_MESSAGE, payload)
        print(f"  → Diagnostic Message  "
              f"src=0x{self.tester_addr:04X}  tgt=0x{self.ecu_addr:04X}  "
              f"UDS: {_fmt_hex(uds_payload)}")
        await self._send(raw)
        # Receive one or two responses (ACK + possible UDS response)
        resp1 = await self._recv()
        self._print_response(resp1)
        # If ACK, try to receive the UDS response too (with a short timeout)
        if _ptype(resp1) == PT_DIAGNOSTIC_POSITIVE_ACK:
            try:
                resp2 = await asyncio.wait_for(_read_frame(self._reader), timeout=2.0)
                self._print_response(resp2)
            except asyncio.TimeoutError:
                pass  # no follow-up message

    async def cmd_alive(self) -> None:
        # Alive Check Request has no payload (0x0007); the EdgeNode replies
        # with Alive Check Response (0x0008) + its own logical address (2 bytes).
        raw = _build(PT_ALIVE_CHECK_REQUEST, b"")
        print("  → Alive Check Request")
        await self._send(raw)
        resp = await self._recv()
        self._print_response(resp)

    async def cmd_status(self) -> None:
        raw = _build(PT_ENTITY_STATUS_REQUEST, b"")
        print("  → Entity Status Request")
        await self._send(raw)
        resp = await self._recv()
        self._print_response(resp)

    async def cmd_power(self) -> None:
        raw = _build(PT_POWER_MODE_REQUEST, b"")
        print("  → Power Mode Info Request")
        await self._send(raw)
        resp = await self._recv()
        self._print_response(resp)


# ---------------------------------------------------------------------------
# Interactive REPL
# ---------------------------------------------------------------------------

HELP_TEXT = """\
Commands:
  activate [addr_hex]    Routing Activation (addr optional, default from config)
  diag <hex bytes>       Diagnostic Message  e.g. 'diag 10 01' or 'diag 1001'
  alive                  Alive Check Request
  status                 Entity Status Request
  power                  Power Mode Info Request
  help                   Show this help
  quit / exit / q        Disconnect and exit
"""


async def repl(tester: DoIPTester, auto_activate: bool = True) -> None:
    print(f"\nConnected to {tester.host}:{tester.port}")

    # A real DoIP tester sends Routing Activation immediately after TCP connect.
    # The EdgeNode's T_TCP_Initial_Inactivity timer (default 2 s) will fire and
    # close the connection if no RA Request arrives in time.
    if auto_activate:
        ok = await tester.cmd_activate()
        if not ok:
            print("  ! Routing Activation failed — check tester/ECU logical addresses in config.")
            await tester.disconnect()
            return

    print("Type 'help' for commands.\n")

    loop = asyncio.get_running_loop()

    while True:
        try:
            line = await loop.run_in_executor(None, lambda: input("doip> "))
        except (EOFError, KeyboardInterrupt):
            print()
            break

        line = line.strip()
        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()

        try:
            if cmd in ("quit", "exit", "q"):
                break

            elif cmd == "help":
                print(HELP_TEXT)

            elif cmd == "activate":
                addr = int(parts[1], 0) if len(parts) > 1 else None
                await tester.cmd_activate(addr)

            elif cmd == "diag":
                if len(parts) < 2:
                    print("  Usage: diag <hex bytes>   e.g. diag 10 01")
                    continue
                uds = _parse_hex_input(parts[1:])
                await tester.cmd_diag(uds)

            elif cmd == "alive":
                await tester.cmd_alive()

            elif cmd == "status":
                await tester.cmd_status()

            elif cmd == "power":
                await tester.cmd_power()

            else:
                print(f"  Unknown command: {cmd!r}  (type 'help')")

        except asyncio.TimeoutError:
            print("  ! Timeout waiting for response.")
        except asyncio.IncompleteReadError:
            print("  ! Connection closed by remote.")
            break
        except ConnectionResetError:
            print("  ! Connection reset.")
            break
        except ValueError as exc:
            print(f"  ! Input error: {exc}")
        except Exception as exc:
            logger.debug("Command error", exc_info=True)
            print(f"  ! Error: {exc}")

    await tester.disconnect()


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _load_config(path: str) -> dict:
    try:
        with open(path) as f:
            cfg = yaml.safe_load(f)
        assert isinstance(cfg, dict)
        return cfg
    except FileNotFoundError:
        print(f"Config file not found: {path!r}  — using defaults.")
        return {}
    except Exception as exc:
        print(f"Config error: {exc}  — using defaults.")
        return {}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="DoIP PC Tester")
    parser.add_argument("--config",    default="config.yaml")
    parser.add_argument("--log-level", default="WARNING",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument(
        "--no-auto-activate", action="store_true",
        help="Do not send Routing Activation automatically on connect "
             "(you must type 'activate' manually before the EdgeNode's "
             "T_TCP_Initial_Inactivity timer fires)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)-8s %(name)s: %(message)s",
    )

    cfg = _load_config(args.config)
    target  = cfg.get("target",  {})
    doip    = cfg.get("doip",    {})

    host         = target.get("host",  "192.168.1.1")
    port         = int(target.get("port",  13400))
    timeout      = float(target.get("timeout_s", 5.0))
    tester_addr  = int(str(doip.get("tester_logical_addr", "0x0E00")), 0)
    ecu_addr     = int(str(doip.get("ecu_logical_addr",    "0x0001")), 0)

    tester = DoIPTester(
        host=host,
        port=port,
        tester_addr=tester_addr,
        ecu_addr=ecu_addr,
        timeout=timeout,
    )

    async def run():
        try:
            await tester.connect()
        except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as exc:
            print(f"Could not connect to {host}:{port}: {exc}")
            sys.exit(1)
        await repl(tester, auto_activate=not args.no_auto_activate)

    asyncio.run(run())


if __name__ == "__main__":
    main()
