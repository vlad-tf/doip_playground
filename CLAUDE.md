
# DoIP EdgeNode — Code Agent Instructions

## Your role

You are implementing the **DoIP EdgeNode** from scratch in Python. You are a code-writing agent. Do not ask clarifying questions — all decisions are made in the requirements document. If you encounter an ambiguity, resolve it in the most conservative, standards-compliant way and leave a `# TODO:` comment explaining your choice.

Your output is a complete, runnable Python project in the `doip_edgenode/` directory. Every file listed in the requirements must exist and be non-empty. The project must start without errors on a Raspberry Pi 4 running Python 3.11+ (aarch64, Raspberry Pi OS).

**Primary reference:** `doip_edgenode_requirements.md` in this folder. Read it fully before writing a single line of code.

---

## Before you start — mandatory inspection steps

Run these commands first. Do not skip them; the results will affect your implementation.

### 1. Verify Scapy DoIP field names

```bash
python3 -c "
from scapy.contrib.automotive.doip import DoIP
p = DoIP()
print(p.fields_desc)
print(p.show())
"
```

The field names printed here are the canonical names you must use throughout the codebase. Do **not** assume names like `payload_type`, `length`, `version` — verify them. Common Scapy naming variations you may find:

- Version byte may be `ver`, `version`, or `proto_ver`
- Inverse byte may be `inv_ver`, `reserved`, or `inverse_version`
- Payload type may be `payload_type` or `type`
- Length may be `length` or `payload_length`

Record the actual names in a comment block at the top of `session.py`:

```python
# Scapy DoIP field names (verified at implementation time):
# version byte  : <name>
# inverse byte  : <name>
# payload type  : <name>
# payload length: <name>
```

### 2. Verify Scapy TLS automaton API

```bash
python3 -c "
from scapy.layers.tls.automaton_srv import TLSServerAutomaton
from scapy.layers.tls.automaton_cli import TLSClientAutomaton
import inspect
print('=== TLSServerAutomaton.__init__ ===')
print(inspect.signature(TLSServerAutomaton.__init__))
print()
print('=== TLSClientAutomaton.__init__ ===')
print(inspect.signature(TLSClientAutomaton.__init__))
"
```

The automaton constructor signatures vary between Scapy versions. Record the actual parameter names before writing `tls_bridge.py`.

### 3. Verify Scapy version

```bash
python3 -c "import scapy; print(scapy.__version__)"
```

Scapy 2.5.x and 2.6.x have minor API differences in the TLS automaton. Note the version and adapt accordingly.

### 4. Verify available network interfaces

```bash
ip link show
```

Confirm `eth0` and `eth1` exist (or note their actual names if different). The implementation must read interface names from `config.yaml`, never hardcode them — but this tells you what to put in the example config.

---

## Implementation order

Build in this exact sequence. Each phase must be fully working and tested before proceeding. Do not write all files first and test later.

---

### Phase 1 — Configuration and data model

**Files:** `config.py`, `config.yaml`, `routing.py`

Start here because everything else depends on it.

**`config.py`:**
- Define dataclasses for every section in `config.yaml`: `NetworkConfig`, `PortsConfig`, `TLSConfig`, `DoIPConfig`, `TimerConfig`, `UDPConfig`, `RoutingEntry`, `MiddlewareConfig`, `AppConfig`
- Write a `load_config(path: str) -> AppConfig` function using `pyyaml`
- Validate required fields on load; raise `ConfigError` (define it) with a descriptive message for missing or invalid values
- Validate VIN is exactly 17 characters
- Validate EID and GID are exactly 12 hex characters
- Validate `tls_version` is `"TLSv1.3"`; raise `ConfigError` if any other value is set
- All integer fields for logical addresses in the routing table must accept both hex strings (`"0x0E00"`) and plain integers

**`routing.py`:**
- `RoutingTable` class wrapping a list of `RoutingEntry`
- `lookup_by_tester_addr(addr: int) -> RoutingEntry | None`
- `lookup_by_ecu_addr(addr: int) -> RoutingEntry | None`
- `all_entries() -> list[RoutingEntry]`

**Verify:** Write a standalone test script (not pytest) that loads `config.yaml` and prints the routing table. Run it. Fix any issues before continuing.

---

### Phase 2 — Middleware base and all middleware classes

**Files:** `middleware/__init__.py`, and all seven middleware files

Write the base classes first, then each middleware in priority order.

**`middleware/__init__.py`:**

```python
from __future__ import annotations
import asyncio
from typing import Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from session import DoIPSession

class DoIPFaultInjectionError(Exception):
    """Raised by middleware to inject a synthetic error response instead of forwarding."""
    def __init__(self, nack_code: int, message: str = ""):
        self.nack_code = nack_code
        super().__init__(message)

class Middleware:
    enabled: bool = True

    async def process(
        self,
        pkt,                    # DoIP packet (Scapy)
        direction: Literal["tester_to_ecu", "ecu_to_tester"],
        session: "DoIPSession",
    ):
        return pkt              # default: pass through unchanged

class MiddlewareChain:
    def __init__(self, middlewares: list[Middleware]):
        self._chain = [m for m in middlewares if getattr(m, "enabled", True)]

    async def run(self, pkt, direction: str, session: "DoIPSession"):
        for mw in self._chain:
            if pkt is None:
                return None
            pkt = await mw.process(pkt, direction, session)
        return pkt
```

**`middleware/logger.py` — implement first:**
- Log to both file and stdout
- Each log entry: ISO 8601 timestamp, direction, payload type (hex + name if known), payload length, full hex dump if `hex_dump: true`
- Keep a lookup dict of payload type codes → human-readable names (cover all types from the requirements table)
- Use Python's `logging` module; configure a `FileHandler` + `StreamHandler`
- Must not throw exceptions for any valid DoIP packet

**`middleware/drop.py`:**
- `drop_rate` is a float 0.0–1.0; use `random.random() < drop_rate` to decide
- `match` dict can specify `direction` and/or `payload_type` (int); drop only when both match (AND logic)
- Return `None` to drop; log the drop event via Python logging at DEBUG level

**`middleware/delay.py`:**
- `await asyncio.sleep((delay_ms + random.randint(0, jitter_ms)) / 1000.0)`
- Delay is applied before returning the packet (packet is not dropped)

**`middleware/corrupt.py`:**
- Access the raw bytes of the DoIP payload (not header) for corruption
- If `byte_offset` is `None`, pick a random byte within the payload
- XOR the target byte with `flip_mask`
- Rebuild the Scapy packet from the modified bytes using `DoIP(modified_bytes)`
- If payload is empty, log a warning and pass through unchanged

**`middleware/replay.py`:**
- When `record: true`: store copies of all packets seen in `direction == "tester_to_ecu"` in a list
- When triggered (for now: trigger immediately after recording the first `replay_count` packets), inject the recorded packets back into the tester-to-ECU path
- Injection means calling the ECU connection's `send()` method directly — the session must expose a `send_to_ecu(pkt)` coroutine for this purpose
- This is the most complex middleware; if unsure, implement a simple version that records but does not auto-replay, and adds a `# TODO: replay trigger` comment

**`middleware/address.py`:**
- Overwrite source logical address field if `src_override` is not `None`
- Overwrite target logical address field if `tgt_override` is not `None`
- Use the verified Scapy field names from Phase 1

**`middleware/header_fault.py` — implement fully, this is priority:**

```python
FAULT_MODES = {
    "wrong_version":  # set version byte to 0xFF
    "bad_inverse":    # set inverse byte to 0x00
    "bad_length":     # set payload length to 0xFFFFFFFF
    "unknown_type":   # set payload type to 0xDEAD
}
```

- `inject_on_nth: int` — maintain a counter per instance; only inject on every Nth call (counter resets after injection)
- `direction` controls which traffic direction is faulted
- After injecting the fault, log it at WARNING level with the fault mode and direction
- Rebuild the packet from scratch using Scapy field assignment, do not do raw byte manipulation

**`middleware/tls_fault.py` — placeholder only:**

```python
import logging
logger = logging.getLogger(__name__)

class TLSFaultMiddleware(Middleware):
    def __init__(self, fault: str = "wrong_cipher", **kwargs):
        self.fault = fault
        self.enabled = kwargs.get("enabled", False)

    async def process(self, pkt, direction, session):
        if self.enabled:
            logger.warning(
                "TLSFaultMiddleware: fault '%s' is configured but NOT yet implemented. "
                "Passing packet through unchanged. See TLSFaultPolicy in tls_bridge.py.",
                self.fault,
            )
        return pkt
```

**Verify Phase 2:** Write `tests/test_middleware.py` using pytest. Each middleware must have at least one test that passes a synthetic DoIP packet and verifies the expected behaviour. Run `pytest tests/test_middleware.py -v`. All must pass before continuing.

---

### Phase 3 — TLS bridge and ECU client

**Files:** `tls_bridge.py`, `ecu_client.py`

**`tls_bridge.py`:**

Define `TLSFaultPolicy` first (the placeholder dataclass from the requirements — all fields default to `False`).

Then implement `TLSBridge`. The critical design constraint is **two concurrent executor tasks** to avoid deadlock:

```
asyncio event loop
  │
  ├── writer_task (executor thread A)
  │     loop: get bytes from tx_queue → write to TLS automaton socket
  │
  └── reader_task (executor thread B)
        loop: read decrypted bytes from TLS automaton → put into rx_queue
              use loop.call_soon_threadsafe(rx_queue.put_nowait, data)
```

The automaton itself runs in a third thread (its own `run()` call).

Concretely:

```python
import asyncio
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

@dataclass
class TLSFaultPolicy:
    wrong_cipher: bool = False
    expired_cert: bool = False
    bad_mac: bool = False
    no_cert: bool = False
    tls_version_downgrade: bool = False
    # Future fields go here

class TLSBridge:
    def __init__(self, sock, automaton_cls, tls_config, fault_policy, loop, executor):
        self._sock = sock
        self._automaton_cls = automaton_cls
        self._tls_config = tls_config
        self._fault_policy = fault_policy
        self._loop = loop
        self._executor = executor
        self._rx_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._tx_queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._automaton = None
        self._closed = False

    async def handshake(self) -> None:
        """Start the TLS automaton and complete the handshake. Raises on failure."""
        # Start automaton in executor
        # Start reader and writer threads
        # Block until handshake complete (use an asyncio.Event)
        ...

    async def send(self, data: bytes) -> None:
        await self._tx_queue.put(data)

    async def recv(self) -> bytes:
        return await self._rx_queue.get()

    async def close(self) -> None:
        self._closed = True
        await self._tx_queue.put(None)  # sentinel to stop writer thread
        self._sock.close()
```

**Important TLS configuration notes:**
- When creating the Scapy TLS automaton, pass the TLS version constraint so it refuses TLS 1.2. The exact parameter name depends on the Scapy version you found in Phase 1 — check `TLSServerAutomaton.__init__` signature again.
- Certificate loading: Scapy uses its own cert loading functions. Check `from scapy.layers.tls.cert import Cert, PrivKey` — use these, not the `ssl` module.
- mTLS on server side: the automaton must be configured to request a client certificate and verify it. Look for `request_client_certificate` or similar parameter.

**`ecu_client.py`:**

```python
class ECUConnection:
    """Single IPv6 TCP connection to one ECU. Manages TLS if configured."""

    def __init__(self, entry: RoutingEntry, tls_config: TLSConfig, loop, executor):
        ...

    async def connect(self) -> None:
        """Establish TCP + optional TLS connection to ECU using IPv6 link-local."""
        # Use get_if_index() for scope_id (see requirements)
        # If ecu_port == tls_port: create TLSBridge and call handshake()
        # Otherwise: plain asyncio streams
        ...

    async def send(self, data: bytes) -> None: ...
    async def recv(self) -> bytes: ...
    async def close(self) -> None: ...
```

IPv6 link-local connect pattern (copy exactly — scope_id is mandatory):

```python
scope_id = socket.if_nametoindex(entry.ecu_interface)
sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
sock.setblocking(False)
await loop.sock_connect(sock, (entry.ecu_ipv6, port, 0, scope_id))
```

---

### Phase 4 — Session state machine

**File:** `session.py`

This is the heart of the system. Implement it as a class, not a collection of functions.

```python
class DoIPSession:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        config: AppConfig,
        routing_table: RoutingTable,
        middleware_chain: MiddlewareChain,
        loop: asyncio.AbstractEventLoop,
        executor: ThreadPoolExecutor,
    ):
        self.activated: bool = False
        self.tester_logical_addr: int | None = None
        ...
```

Implement the lifecycle exactly as described in the requirements:

**Timer management:** Use `asyncio.Task` for both timers. Cancel and restart `T_TCP_General_Inactivity` on every received message. Cancel `T_TCP_Initial_Inactivity` immediately upon receiving a Routing Activation Request (before validating it).

**Frame reading:** Read the 8-byte DoIP header first, parse payload length from bytes 4–7 (big-endian), then read exactly that many payload bytes. Do not use `reader.read()` without a length argument — it can return partial data.

```python
DOIP_HEADER_LEN = 8

async def _read_frame(self) -> bytes:
    header = await asyncio.wait_for(
        self.reader.readexactly(DOIP_HEADER_LEN),
        timeout=self._remaining_inactivity(),
    )
    # Validate version and inverse bytes here; send NACK and raise on failure
    payload_len = int.from_bytes(header[4:8], "big")
    if payload_len > self.config.doip.max_payload_bytes:
        await self._send_header_nack(0x02)  # message too large
        raise DoIPProtocolError("payload too large")
    payload = await asyncio.wait_for(
        self.reader.readexactly(payload_len),
        timeout=self._remaining_inactivity(),
    )
    return header + payload
```

**Activation gate:** The `_dispatch()` method (or equivalent) must check `self.activated` before calling the middleware chain:

```python
async def _dispatch(self, pkt) -> None:
    payload_type = pkt.<payload_type_field>
    if payload_type == 0x8001 and not self.activated:
        await self._send_diag_nack(0x02)  # invalid source address
        raise DoIPProtocolError("diagnostic message before activation")
    ...
```

**Sending back to tester:** Always send through the middleware chain in the `"ecu_to_tester"` direction before writing to the tester socket.

**`send_to_ecu(pkt)` coroutine:** Expose this so `ReplayMiddleware` can inject packets without going through the full receive path.

---

### Phase 5 — UDP announcer

**File:** `udp_announcer.py`

```python
class UDPAnnouncer:
    """Handles Vehicle Announcement on startup and Vehicle Identification Request/Response."""

    async def start(self) -> None:
        """Send announce_count announcements at announce_interval_ms intervals, then listen."""
        ...

    async def _listen(self) -> None:
        """Listen for Vehicle Identification Requests (0x0001) and respond."""
        ...
```

- Bind to `0.0.0.0:13400` UDP
- Vehicle Identification Response (0x0004) payload: VIN (17 bytes), EID (6 bytes), GID (6 bytes), further action byte (0x00 = no further action), sync status byte (0x00)
- Broadcast address: `255.255.255.255` or the subnet broadcast for `eth0`; also send unicast to the requester's address
- Use `asyncio.DatagramProtocol` (not blocking sockets) so it runs in the event loop

---

### Phase 6 — Server and entry point

**Files:** `server.py`, `main.py`

**`server.py`:**

```python
class DoIPServer:
    def __init__(self, config: AppConfig, ...):
        self._active_session: DoIPSession | None = None

    async def start(self) -> None:
        # Start plain TCP server on port 13400
        # Start TLS TCP server on port 3496
        # Start UDPAnnouncer
        ...

    async def _handle_connection(self, reader, writer, use_tls: bool) -> None:
        if self._active_session is not None:
            # PoC: reject second connection immediately
            writer.close()
            return
        session = DoIPSession(reader, writer, ...)
        self._active_session = session
        try:
            await session.run()
        finally:
            self._active_session = None
```

**`main.py`:**

```python
import asyncio
import argparse
import logging
import sys
from config import load_config
from server import DoIPServer

def main():
    parser = argparse.ArgumentParser(description="DoIP EdgeNode")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level)

    config = load_config(args.config)
    server = DoIPServer(config)

    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("Shutting down.")
        sys.exit(0)

if __name__ == "__main__":
    main()
```

---

### Phase 7 — Tests

**Files:** `tests/mock_ecu.py`, `tests/test_session.py`, `tests/test_middleware.py`

**`mock_ecu.py`:**

Minimal DoIP server that runs on loopback (127.0.0.1:13400). It must handle:
- Incoming TCP connection
- Routing Activation Request → respond `0x10`
- Diagnostic Message → echo it back with a Positive ACK
- Alive Check Request → respond immediately

```python
class MockECU:
    def __init__(self, host="127.0.0.1", port=13400):
        ...

    async def start(self) -> asyncio.Server: ...
    async def stop(self) -> None: ...

    # Useful for tests:
    received_packets: list  # all packets received
    sent_packets: list      # all packets sent
```

**`test_session.py`:** Use `MockECU` and connect a raw `asyncio` client. Test:
1. Full session lifecycle: connect → routing activation → diagnostic message → disconnect
2. Activation gate: send diagnostic message before routing activation → expect NACK + disconnect
3. `T_TCP_Initial_Inactivity`: connect but do not send routing activation → after timeout, connection closes
4. Header NACK for wrong version bytes
5. Header NACK for oversized payload length

**`test_middleware.py`:** Each middleware tested with synthetic packets. Do not require network access. Tag any test requiring root with `@pytest.mark.requires_root`.

---

## Scapy-specific pitfalls

### Building DoIP packets

Always use Scapy field assignment, not raw bytes, when constructing packets:

```python
from scapy.contrib.automotive.doip import DoIP
# Good:
pkt = DoIP()
pkt.<version_field> = 0x02
pkt.<type_field> = 0x8001
pkt.<payload> = uds_bytes

# Bad (fragile, breaks on Scapy update):
raw = b'\x02\xfd\x80\x01' + len_bytes + uds_bytes
```

### Dissecting received bytes

```python
pkt = DoIP(raw_bytes)
if not pkt.haslayer(DoIP):
    # Scapy couldn't parse it — send Header NACK 0x01 (unknown payload type)
    ...
```

### Payload access

The UDS payload inside a Diagnostic Message is a nested layer in Scapy. After dissecting, access it via the appropriate sublayer. If Scapy doesn't have a layer for that payload type, it will be accessible as `bytes(pkt.payload)`. Test this for the specific Scapy version installed.

### `bind_layers` must be called at import time

Put `bind_layers` calls in a module-level `_init()` function that runs when `server.py` is first imported, before any sockets are created. Do not put them inside coroutines.

### Raw socket permissions

`CAP_NET_RAW` is required for Scapy packet crafting on a live interface. For unit tests using loopback TCP sockets, this is not needed.

---

## asyncio patterns to follow

### Reading exactly N bytes (never use bare `read()`)

```python
data = await reader.readexactly(n)
# Raises asyncio.IncompleteReadError if connection closes before n bytes arrive
```

### Cancellable timers

```python
self._inactivity_task = asyncio.create_task(self._inactivity_timeout())

async def _inactivity_timeout(self):
    try:
        await asyncio.sleep(self.config.timers.t_tcp_general_inactivity_s)
        await self._close("inactivity timeout")
    except asyncio.CancelledError:
        pass  # timer was reset; normal

def _reset_inactivity_timer(self):
    if self._inactivity_task:
        self._inactivity_task.cancel()
    self._inactivity_task = asyncio.create_task(self._inactivity_timeout())
```

### Exception handling in sessions

Wrap the entire session loop in a `try/except` that catches `ConnectionResetError`, `asyncio.IncompleteReadError`, `DoIPProtocolError`, and bare `Exception` (log + close). Never let an exception in one session crash the server.

---

## Error handling rules

- **Malformed DoIP header** (wrong version, wrong inverse, too large): send `DoIP Header NACK (0x0000)` with the appropriate NACK code, close the TCP connection, log at WARNING
- **Unknown payload type**: send Header NACK `0x01`, close connection, log at WARNING
- **Diagnostic message before activation**: send `Diagnostic Message Negative ACK (0x8003)` with code `0x02`, close connection, log at WARNING
- **TLS handshake failure**: log the Scapy exception at ERROR, close the socket, do not send any DoIP message (TLS layer handles the alert)
- **ECU unreachable**: log at ERROR, send `Diagnostic Message Negative ACK (0x8003)` with code `0x03` (target unreachable) back to tester, keep session open waiting for retry
- **Unhandled exception in session**: log full traceback at CRITICAL, close connection, allow server to accept new connection

---

## Logging conventions

Use Python's standard `logging` module throughout. Logger names follow the module path:

```python
import logging
logger = logging.getLogger(__name__)
```

Log levels:
- `DEBUG` — every DoIP frame (direction, type, length), middleware decisions
- `INFO` — session lifecycle events (connect, activate, disconnect), timer events
- `WARNING` — protocol violations, NACK sent, fault injected
- `ERROR` — TLS failures, ECU unreachable
- `CRITICAL` — unhandled exceptions

---

## Configuration validation checklist

`load_config()` must raise `ConfigError` for:

- [ ] `tls_version` is not `"TLSv1.3"`
- [ ] VIN length ≠ 17
- [ ] EID or GID not exactly 12 hex characters
- [ ] `drop_rate` outside `[0.0, 1.0]`
- [ ] `header_fault.fault` not one of `"wrong_version"`, `"bad_inverse"`, `"bad_length"`, `"unknown_type"`
- [ ] `inject_on_nth` < 1
- [ ] Any routing entry references an interface not present in `network.*_interface` fields
- [ ] `announce_count` < 1

---

## Delivery checklist

Before considering the implementation complete, verify every item:

**Functional:**
- [ ] `python3 main.py --config config.yaml` starts without errors
- [ ] UDP Vehicle Announcement is sent 3 times on startup (verify with `tcpdump`)
- [ ] A DoIP-capable tester can connect and complete Routing Activation on port 13400
- [ ] A Diagnostic Message is forwarded to the ECU and the response relayed back
- [ ] `T_TCP_Initial_Inactivity` fires and closes the connection if no RA Request arrives
- [ ] `T_TCP_General_Inactivity` fires after 300 s of inactivity
- [ ] `LoggerMiddleware` writes to `logs/doip.log` and stdout
- [ ] `HeaderFaultMiddleware` with `wrong_version` causes the peer to return a Header NACK

**Tests:**
- [ ] `pytest tests/test_middleware.py -v` — all pass, no root required
- [ ] `pytest tests/test_session.py -v` — all pass (may need root for some; check markers)

**Code quality:**
- [ ] No hardcoded IP addresses, ports, VIN, or certificate paths anywhere
- [ ] No `import ssl` anywhere
- [ ] No bare `threading.Thread(target=...)` for TLS automatons
- [ ] Every `config.yaml` value is actually used (no orphaned config keys)
- [ ] `TLSFaultMiddleware.process()` logs a warning and passes through — does not raise
- [ ] `TLSFaultPolicy` fields are present in `tls_bridge.py` but all default to `False`

---

## Known limitations to document in code

Add this block to `main.py` docstring:

```
Known limitations (PoC scope):
- Single tester connection only; second connection is rejected immediately.
- TLS fault injection is not functional; TLSFaultPolicy fields are placeholders.
- No certificate revocation check (CRL/OCSP).
- Config changes require restart (no SIGHUP hot-reload).
- OEM-specific routing activation types (0x02+) are passed through without
  interpretation.
```

---

## What you must not do

- Do not use the `ssl` module as the primary TLS handler
- Do not fall back to TLS 1.2 — reject it
- Do not hardcode any address, port, VIN, or path
- Do not parse UDS service IDs — payload is always opaque bytes
- Do not call `MiddlewareChain.run()` on unauthenticated sessions
- Do not use `threading.Thread` directly for TLS automatons
- Do not swap protocol version byte and inverse version byte (version is byte 0)
- Do not implement TLS fault injection logic — only the placeholder structure
- Do not create a REST API or web interface
- Do not use `reader.read()` without an exact length — always use `readexactly()`
