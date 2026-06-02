
# DoIP EdgeNode — Code Agent Requirements & Context

## Project summary

Build a **DoIP (ISO 13400-2/3) EdgeNode** running on a Raspberry Pi 4.
The EdgeNode sits between a PC-based tester and a real automotive ECU, acting as a transparent proxy with full visibility into the DoIP protocol layer for testing and fault injection.

```
Tester (PC) ──[IPv4 · eth0]──► RPi EdgeNode ──[IPv6 · eth1]──► Real ECU
             DoIP/TLS port 3496                DoIP/TLS port 3496
             DoIP plain  port 13400            DoIP plain  port 13400
             UDP announce port 13400           UDP announce port 13400
```

**Scope:** Proof-of-Concept. A single simultaneous tester connection is sufficient; no connection pooling or multi-tester concurrency is required.

---

## Hardware target

- **Platform**: Raspberry Pi 4 (Linux, aarch64)
- **OS**: Raspberry Pi OS (Debian-based), Python 3.11+
- **Network interfaces**:
  - `eth0` — tester-facing, static IPv4 (e.g. `192.168.1.1/24`)
  - `eth1` — ECU-facing (IVN), IPv6 only, link-local (`fe80::…`)
    - USB-Ethernet adapter or HAT; interface index required for IPv6 scope
- **Privileges**: runs as root or with `CAP_NET_RAW` + `CAP_NET_BIND_SERVICE`

---

## Technology stack

| Layer | Library | Notes |
|---|---|---|
| DoIP parsing & crafting | `scapy` — `scapy.contrib.automotive.doip` | Primary packet library |
| TLS state machine | `scapy.layers.tls` — `TLSServerAutomaton`, `TLSClientAutomaton` | Full handshake, not just header |
| Async I/O | `asyncio` | Concurrency for tester connection + ECU connection |
| TLS↔asyncio bridge | `loop.run_in_executor()` | Scapy automatons run in thread pool |
| UDS payload | Raw `bytes` | Treat as opaque; no UDS library needed |

**Do not use** the Python `ssl` module as the primary TLS handler. Scapy's TLS stack is used because it allows inspection and fault injection at the TLS handshake layer itself.

---

## Protocol scope

### In scope (implement fully)

**DoIP over TCP (ISO 13400-2):**

| Message type | Payload type code | Direction | Must handle |
|---|---|---|---|
| DoIP Header NACK | `0x0000` | EdgeNode → Tester | Send on malformed/unknown header |
| Routing Activation Request | `0x0005` | Tester → EdgeNode | Parse, validate, respond |
| Routing Activation Response | `0x0006` | EdgeNode → Tester | Generate (see response codes below) |
| Alive Check Request | `0x0007` | Either direction | Respond immediately |
| Alive Check Response | `0x0008` | Either direction | Generate |
| Diagnostic Message | `0x8001` | Bidirectional | Intercept, route, forward |
| Diagnostic Message Positive ACK | `0x8002` | ECU → Tester | Relay |
| Diagnostic Message Negative ACK | `0x8003` | ECU → Tester | Relay |
| Entity Status Request | `0x4001` | Tester → EdgeNode | Respond |
| Entity Status Response | `0x4002` | EdgeNode → Tester | Generate |
| Power Mode Info Request | `0x4003` | Tester → EdgeNode | Respond (static value from config) |
| Power Mode Info Response | `0x4004` | EdgeNode → Tester | Generate |

**Routing Activation Response codes (payload byte 7):**

| Code | Meaning |
|---|---|
| `0x00` | Denied — unknown source address |
| `0x01` | Denied — all sockets registered and active |
| `0x02` | Denied — SA different from already registered SA |
| `0x03` | Denied — SA already registered on different socket |
| `0x04` | Denied — authentication missing |
| `0x05` | Denied — confirmation rejected |
| `0x06` | Denied — unsupported routing activation type |
| `0x10` | Successfully activated |
| `0x11` | Activated, confirmation pending |

**DoIP Header NACK codes (payload byte 0):**

| Code | Meaning |
|---|---|
| `0x00` | Incorrect pattern format |
| `0x01` | Unknown payload type |
| `0x02` | Message too large |
| `0x03` | Out of memory |
| `0x04` | Invalid payload length |

**DoIP over UDP (ISO 13400-2):**

| Message type | Code | Notes |
|---|---|---|
| Vehicle Identification Request | `0x0001` | Respond with VIN/EID/GID |
| Vehicle Identification Response | `0x0004` | Broadcast + unicast |
| Vehicle Announcement | `0x0004` | Send on startup (configurable count and interval) |

**TLS (ISO 13400-3):**
- Port `3496` for TLS connections (both tester-facing and ECU-facing)
- Port `13400` for plaintext TCP and all UDP (UDP never uses TLS)
- **TLS version: 1.3 exclusively.** TLS 1.2 and below must be rejected.
- Mutual TLS (mTLS): both sides present certificates signed by the shared CA
- EdgeNode holds: server cert, client cert, CA cert (configurable paths)
- See TLS section below for cipher suite and SNI requirements

**IPv4 ↔ IPv6 translation:**
- Tester connects over IPv4 (`eth0`)
- ECU connects over IPv6 (`eth1`, link-local `fe80::` with interface scope ID)
- EdgeNode rewrites network layer transparently; DoIP logical addresses remain unchanged unless routing table says otherwise

### Out of scope

- UDS (ISO 14229) parsing or interpretation — payload is always opaque bytes
- OBD-II, CAN, or any non-DoIP protocol
- DHCP / IP address management — assume static configuration
- Web UI or REST API (configuration via file only)
- TLS fault injection (placeholder only — see TLS fault injection section)

---

## DoIP header structure (ISO 13400-2)

```
 0       1       2       3       4       5       6       7
┌───────────────┬───────────────┬───────────────────────────────┐
│ proto version │ inverse ver.  │  payload type  │ payload len  │
│  0x02 or 0x03 │ 0xFF XOR ver  │   (2 bytes)    │  (4 bytes)   │
└───────────────┴───────────────┴───────────────────────────────┘
```

- **Protocol version byte (byte 0):** `0x02` = ISO 13400-2:2012, `0x03` = 2019 revision. EdgeNode must accept both.
- **Inverse version byte (byte 1):** `0xFF XOR version`. For v2: `0xFD`. For v3: `0xFC`. Validate on every received frame; send Header NACK `0x00` on mismatch.
- **Payload length (bytes 4–7):** big-endian uint32. Enforce a maximum value (configurable, default 4096 bytes); send Header NACK `0x02` if exceeded.

---

## TLS 1.3 requirements

### Version enforcement

The EdgeNode must negotiate **TLS 1.3 only**. If a client or ECU offers only TLS 1.2 or earlier, the handshake must be aborted with a `protocol_version` alert. Configure the Scapy `TLSServerAutomaton` and `TLSClientAutomaton` accordingly; do not fall back silently.

### Cipher suites (TLS 1.3)

TLS 1.3 cipher suites are negotiated separately from the key exchange. Support and prefer in this order:

| Suite | Notes |
|---|---|
| `TLS_AES_128_GCM_SHA256` | Required — primary suite per ISO 13400-3:2022 |
| `TLS_AES_256_GCM_SHA384` | Supported |
| `TLS_CHACHA20_POLY1305_SHA256` | Supported |

### Mutual TLS

Both the tester-facing server role and the ECU-facing client role use mTLS:
- **Server role (tester-facing):** present `server_cert`; request and verify client certificate against `ca_cert`
- **Client role (ECU-facing):** present `client_cert`; verify ECU server certificate against `ca_cert`

Certificate validation must check: signature chain, not-before/not-after validity, and key usage extension. Revocation (CRL/OCSP) is **not required** for this PoC — document this as a known limitation.

### SNI (Server Name Indication)

When acting as TLS client toward the ECU, the EdgeNode must set the SNI extension. The expected SNI hostname for each ECU is configurable in the routing table (`ecu_sni` field). If `ecu_sni` is omitted, do not send SNI. Do not rely on reverse DNS from the IPv6 address.

### TLS fault injection (placeholder only)

TLS fault injection requires operating at the handshake layer, **before** any DoIP frame exists. It therefore cannot be implemented as a middleware (which operates on decrypted DoIP frames). A `TLSFaultPolicy` object is defined in `tls_bridge.py` as a placeholder for future implementation:

```python
class TLSFaultPolicy:
    """
    Placeholder: hook point for TLS-layer fault injection.
    Pass an instance to TLSBridge. All fields default to no-fault.
    Future implementation will wire these into the Scapy automaton callbacks.
    """
    wrong_cipher: bool = False        # offer only unsupported cipher suites
    expired_cert: bool = False        # present an expired certificate
    bad_mac: bool = False             # corrupt a record MAC after handshake
    no_cert: bool = False             # skip client certificate in mTLS
    tls_version_downgrade: bool = False  # offer TLS 1.2 only
```

`TLSFaultMiddleware` is **not implemented** in v1. The middleware slot is reserved in `config.yaml` but loads a no-op pass-through if configured.

---

## Architecture

### Process model

```
main()
  ├── UDPAnnouncer          — sends vehicle announcements, handles UDP discovery
  ├── DoIPServer (IPv4)     — asyncio TCP server on eth0:13400 and eth0:3496
  │     └── single active connection: DoIPSession
  │           ├── TLSBridge (thread pool, port 3496 only)
  │           │     └── TLSServerAutomaton + TLSFaultPolicy (placeholder)
  │           ├── DoIP frame parser (Scapy)
  │           └── MiddlewareChain → ECUConnection
  └── ECUConnection         — single IPv6 connection to ECU
        ├── TLSBridge (thread pool, port 3496 only)
        │     └── TLSClientAutomaton + TLSFaultPolicy (placeholder)
        └── DoIP frame crafter (Scapy)
```

**PoC connection limit:** the server accepts exactly one TCP connection at a time. If a second connection arrives while one is active, close it immediately with a Routing Activation Response code `0x01` (all sockets registered) before teardown, or simply close the socket.

### DoIPSession lifecycle

1. TCP connect from tester
2. Start `T_TCP_Initial_Inactivity` timer (default 2 s); if it fires before step 3, close connection
3. If port 3496: TLS 1.3 handshake via `TLSBridge` (thread pool); abort on version or cert failure
4. Receive Routing Activation Request
   - Validate: source logical address is in routing table; activation type is `0x00` (default) or `0x01` (OEM-specific, pass through)
   - On success: respond `0x10`, cancel `T_TCP_Initial_Inactivity`, mark session as **activated**, start `T_TCP_General_Inactivity` timer (default 300 s)
   - On failure: respond with appropriate code from table above, close connection
5. **Gate:** any `0x8001` Diagnostic Message received on a non-activated session must be rejected with a Diagnostic Message Negative ACK (`0x8003`, NACK code `0x02` = invalid source address), then close the connection
6. For each Diagnostic Message on an activated session:
   a. Reset `T_TCP_General_Inactivity` timer
   b. Dissect with Scapy: `DoIP(raw_bytes)`
   c. Pass through `MiddlewareChain`
   d. If not dropped: rewrite addresses per routing table, forward to ECU
   e. Relay ECU response back through middleware, back to tester
7. Alive Check Request (0x0007) received at any time: respond immediately with `0x0008`; reset `T_TCP_General_Inactivity` timer
8. On `T_TCP_General_Inactivity` expiry, tester disconnect, or ECU disconnect: tear down session, log reason, accept new connections

### Inactivity timers

| Timer | Default | Scope | Behaviour on expiry |
|---|---|---|---|
| `T_TCP_Initial_Inactivity` | 2 s | From TCP connect until Routing Activation received | Close TCP connection, log |
| `T_TCP_General_Inactivity` | 300 s | From successful Routing Activation; reset by any received message | Close TCP connection, log |

Both timers are configurable in `config.yaml`.

### Routing table

```python
# config.yaml structure
routing_table:
  - tester_logical_addr: 0x0E00   # source addr seen from tester
    ecu_logical_addr:    0x0001   # target addr on ECU side
    ecu_ipv6:            "fe80::aabb:ccdd:eeff:0011"
    ecu_interface:       "eth1"
    ecu_port_plain:      13400
    ecu_port_tls:        3496
    ecu_sni:             "ecu-gateway.local"   # optional; omit to skip SNI
```

---

## Middleware chain

The middleware chain is the **primary hook point for DoIP fault injection and testing**. It operates on **decrypted DoIP frames** — after TLS termination, before re-encryption toward the ECU.

### Interface

```python
class Middleware:
    """Base class. Override process() to implement behaviour."""
    async def process(
        self,
        pkt: DoIP,
        direction: Literal["tester_to_ecu", "ecu_to_tester"],
        session: "DoIPSession",
    ) -> DoIP | None:
        """
        Return modified packet to forward, or None to drop.
        Raise DoIPFaultInjectionError to inject a protocol error response instead.
        """
        return pkt

class MiddlewareChain:
    def __init__(self, middlewares: list[Middleware]): ...
    async def run(self, pkt: DoIP, direction: str, session: DoIPSession) -> DoIP | None: ...
```

### Built-in middleware

**Observability (implement first):**

| Class | Behaviour | Key config params |
|---|---|---|
| `LoggerMiddleware` | Log every frame: direction, timestamp, hex dump, decoded fields | `log_path`, `hex_dump: bool` |

**DoIP fault injection (priority — implement fully):**

| Class | Behaviour | Key config params |
|---|---|---|
| `DropMiddleware` | Drop packets matching a predicate (simulate lost message) | `drop_rate: float [0.0–1.0]`, `match: dict` (payload type, direction) |
| `DelayMiddleware` | Add fixed or random delay before forwarding (simulate timing faults) | `delay_ms: int`, `jitter_ms: int` |
| `CorruptMiddleware` | Flip bits in the DoIP payload (simulate data corruption) | `byte_offset: int \| None`, `flip_mask: int` |
| `ReplayMiddleware` | Record frames and replay on trigger (simulate duplicate messages) | `record: bool`, `replay_count: int` |
| `AddressMiddleware` | Rewrite DoIP source/target logical address (simulate wrong SA/TA) | `src_override: int \| None`, `tgt_override: int \| None` |
| `HeaderFaultMiddleware` | Corrupt DoIP header fields: wrong version, wrong inverse, bad payload length, unknown payload type | `fault: Literal["wrong_version","bad_inverse","bad_length","unknown_type"]` |

**TLS fault injection (placeholder only — do not implement logic in v1):**

| Class | Behaviour |
|---|---|
| `TLSFaultMiddleware` | No-op pass-through. Logs a warning that TLS fault injection is not yet implemented. Config field `fault` is parsed and stored but ignored. |

Middleware is configured via `config.yaml` and loaded at startup.

---

## `HeaderFaultMiddleware` — DoIP header fault injection detail

This middleware crafts malformed DoIP headers to test how the peer handles protocol errors. It operates by **replacing** the DoIP header fields of the outgoing packet before forwarding:

| Fault mode | What it does | Expected peer reaction |
|---|---|---|
| `wrong_version` | Sets protocol version byte to `0xFF` | Peer sends Header NACK `0x00` |
| `bad_inverse` | Sets inverse version byte to `0x00` (always wrong) | Peer sends Header NACK `0x00` |
| `bad_length` | Sets payload length field to `0xFFFFFFFF` | Peer sends Header NACK `0x02` or drops |
| `unknown_type` | Sets payload type to `0xDEAD` | Peer sends Header NACK `0x01` |

Additional config params:
- `direction: "tester_to_ecu" | "ecu_to_tester" | "both"` — which direction to inject
- `inject_on_nth: int` — inject only on every Nth message (1 = every message, 5 = every 5th, etc.)

---

## Configuration

Single `config.yaml` file. All paths relative to working directory.

```yaml
network:
  tester_interface: "eth0"
  tester_ipv4: "192.168.1.1"
  ecu_interface: "eth1"

ports:
  doip_plain: 13400
  doip_tls: 3496

tls:
  server_cert: "certs/edgenode-server.crt"
  server_key:  "certs/edgenode-server.key"
  client_cert: "certs/edgenode-client.crt"
  client_key:  "certs/edgenode-client.key"
  ca_cert:     "certs/ca.crt"
  mutual_tls:  true
  # TLS 1.3 only — no fallback to 1.2
  tls_version: "TLSv1.3"
  # Cipher preference order (TLS 1.3 suites)
  cipher_suites:
    - "TLS_AES_128_GCM_SHA256"
    - "TLS_AES_256_GCM_SHA384"
    - "TLS_CHACHA20_POLY1305_SHA256"

doip:
  vin:       "1HGBH41JXMN109186"   # 17-char VIN
  eid:       "AABBCCDDEEFF"        # 6-byte entity ID (hex string)
  gid:       "000000000000"        # 6-byte group ID
  node_type: 0x01                  # DoIP node type: gateway
  power_mode: 0x01                 # 0x00 = not ready, 0x01 = ready, 0x02 = not supported
  max_payload_bytes: 4096          # reject DoIP payloads larger than this

timers:
  t_tcp_initial_inactivity_s: 2
  t_tcp_general_inactivity_s: 300
  alive_check_interval_ms: 500

udp:
  announce_count:    3
  announce_interval_ms: 500

routing_table:
  - tester_logical_addr: 0x0E00
    ecu_logical_addr:    0x0001
    ecu_ipv6:            "fe80::1"
    ecu_interface:       "eth1"
    ecu_port_plain:      13400
    ecu_port_tls:        3496
    ecu_sni:             ""        # leave empty to omit SNI

middleware:
  - type: LoggerMiddleware
    log_path: "logs/doip.log"
    hex_dump: true

  - type: DropMiddleware
    enabled: false
    drop_rate: 0.0
    match:
      direction: "tester_to_ecu"

  - type: DelayMiddleware
    enabled: false
    delay_ms: 0
    jitter_ms: 0

  - type: CorruptMiddleware
    enabled: false
    byte_offset: null
    flip_mask: 0x01

  - type: ReplayMiddleware
    enabled: false
    record: false
    replay_count: 1

  - type: AddressMiddleware
    enabled: false
    src_override: null
    tgt_override: null

  - type: HeaderFaultMiddleware
    enabled: false
    fault: "wrong_version"
    direction: "tester_to_ecu"
    inject_on_nth: 1

  - type: TLSFaultMiddleware
    enabled: false
    fault: "wrong_cipher"   # parsed, stored, not yet acted on
```

---

## Key implementation constraints

### DoIP header byte order

Protocol version is **byte 0**; inverse version is **byte 1**. Do not swap them. Scapy's `DoIP` dissector is authoritative — follow its field names, not the diagram in any external document.

### Routing activation state gate

A `DoIPSession` has an `activated: bool` flag, initially `False`. It is set to `True` only after a successful Routing Activation Response `0x10` is sent. The `MiddlewareChain.run()` method must not be called until `activated` is `True`. Any `0x8001` Diagnostic Message arriving before activation results in a NACK and connection close.

### Scapy TLS automaton and asyncio

`TLSServerAutomaton` and `TLSClientAutomaton` are blocking state machines. They must not run on the asyncio event loop thread. The `TLSBridge` class in `tls_bridge.py` manages the thread↔asyncio boundary:

```python
class TLSBridge:
    """
    Wraps a Scapy TLS automaton in a thread-pool executor.
    Exposes async send() / recv() to the asyncio layer.
    Two executor tasks run concurrently:
      - _reader_task: automaton → rx_queue (asyncio-safe via call_soon_threadsafe)
      - _writer_task: tx_queue → automaton
    This avoids the deadlock that results from a single blocking run_in_executor call.
    """
    def __init__(
        self,
        sock: socket.socket,
        automaton_cls,           # TLSServerAutomaton or TLSClientAutomaton
        tls_config: dict,
        fault_policy: TLSFaultPolicy,
        loop: asyncio.AbstractEventLoop,
        executor: ThreadPoolExecutor,
    ): ...

    async def handshake(self) -> None: ...
    async def send(self, data: bytes) -> None: ...
    async def recv(self) -> bytes: ...
    async def close(self) -> None: ...
```

The two-task pattern (separate reader and writer threads) is **required** to prevent deadlock when the automaton blocks waiting for a response while the asyncio layer is also trying to write.

### Scapy layer binding

Register DoIP on both ports so Scapy dissects automatically:

```python
from scapy.layers.inet import TCP
from scapy.layers.tls.record import TLS
from scapy.contrib.automotive.doip import DoIP
from scapy.packet import bind_layers

bind_layers(TCP, TLS,  dport=3496)
bind_layers(TCP, TLS,  sport=3496)
bind_layers(TCP, DoIP, dport=13400)
bind_layers(TCP, DoIP, sport=13400)
```

### IPv6 link-local scope

IPv6 link-local addresses require an interface scope index for `connect()`:

```python
import socket

def get_if_index(ifname: str) -> int:
    return socket.if_nametoindex(ifname)

sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
scope_id = get_if_index("eth1")
sock.connect(("fe80::1", 3496, 0, scope_id))
```

---

## File structure

```
doip_edgenode/
├── main.py                  # Entry point, config load, startup
├── config.yaml              # Runtime configuration
├── config.py                # Config dataclass, YAML loader
├── server.py                # asyncio TCP/UDP server, connection accept loop
├── session.py               # DoIPSession: per-connection state machine + timer management
├── ecu_client.py            # ECU-facing connection (IPv6, single connection for PoC)
├── tls_bridge.py            # TLSBridge class + TLSFaultPolicy placeholder
├── routing.py               # Routing table lookup
├── middleware/
│   ├── __init__.py          # Middleware base class, MiddlewareChain, DoIPFaultInjectionError
│   ├── logger.py            # LoggerMiddleware
│   ├── drop.py              # DropMiddleware
│   ├── delay.py             # DelayMiddleware
│   ├── corrupt.py           # CorruptMiddleware
│   ├── replay.py            # ReplayMiddleware
│   ├── address.py           # AddressMiddleware
│   ├── header_fault.py      # HeaderFaultMiddleware
│   └── tls_fault.py         # TLSFaultMiddleware (no-op placeholder)
├── udp_announcer.py         # Vehicle announcement, UDP discovery handler
├── certs/                   # TLS certificates (not committed to git)
│   ├── edgenode-server.crt
│   ├── edgenode-server.key
│   ├── edgenode-client.crt
│   ├── edgenode-client.key
│   └── ca.crt
├── logs/                    # Runtime logs
├── tests/
│   ├── test_session.py
│   ├── test_middleware.py
│   └── mock_ecu.py          # Minimal DoIP ECU stub for unit tests
└── requirements.txt
```

---

## Requirements.txt baseline

```
scapy>=2.5.0
pyyaml>=6.0
```

No other runtime dependencies. Scapy includes `scapy.contrib.automotive.doip` and `scapy.layers.tls` in its standard distribution.

---

## Testing expectations

- `mock_ecu.py` must implement a minimal DoIP server on loopback (IPv4, plaintext) sufficient to test the full session lifecycle without real hardware
- Unit tests must not require root; use loopback sockets where possible
- Integration tests that require raw sockets are tagged `@pytest.mark.requires_root`
- All middleware classes must be unit-testable by passing synthetic `DoIP` packets directly to `process()`
- `HeaderFaultMiddleware` must have tests verifying each of the four fault modes produces the correct malformed frame

---

## Known limitations (PoC scope)

| Item | Status |
|---|---|
| Single tester connection only | By design — extend for multi-tester later |
| TLS fault injection not functional | Placeholder only; `TLSFaultPolicy` fields are parsed but not wired |
| No certificate revocation (CRL/OCSP) | Out of scope for PoC |
| No SIGHUP hot-reload | Config requires restart to apply changes |
| No OEM routing activation types beyond pass-through | Type `0x01` is forwarded; OEM-specific logic not implemented |

---

## What the Code Agent must NOT do

- Do not implement UDS service parsing (0x10, 0x22, 0x2E, etc.) — payload is always opaque bytes
- Do not implement IP routing / NAT at the OS level — Python socket code only
- Do not use the Python `ssl` module as the primary TLS handler (use Scapy TLS automaton via `TLSBridge`)
- Do not fall back to TLS 1.2 — TLS 1.3 only; abort the handshake on version mismatch
- Do not assume a single ECU — routing table may have multiple entries even in PoC
- Do not hardcode any IP addresses, ports, VIN, or certificate paths
- Do not use `threading.Thread` directly for TLS automatons — use `TLSBridge` with `run_in_executor()`
- Do not call `MiddlewareChain.run()` before the session is activated (after successful Routing Activation Response)
- Do not swap the protocol version and inverse version bytes — version is byte 0, inverse is byte 1
