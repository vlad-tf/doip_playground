# EdgeNode — Code Agent Instructions

## Scope

This file governs `doip_edgenode/` only. It is the Scapy-based DoIP proxy that
runs on the Raspberry Pi between the PC Tester and an ECU. Do not apply these
conventions to `virtual_ecu/`, `echo_ecu/`, or `pc_tester/` — each has its own
style; see `../CLAUDE.md` for why.

**Primary reference:** `../doip_edgenode_requirements.md`. Read it before
changing behaviour, not just this file.

**Status:** implemented PoC. TLS handshake is not functional (port 3496
accepts but does not negotiate), and TLS conformance is unclaimed. The tester-facing
capacity defaults to `max_connections: 8` active routing-activated SAs, with one
additional reserve socket for setup; no SIGHUP reload — see "Known limitations"
in `main.py`'s docstring and `../README.md` before treating these as bugs.

---

## Stack & dependencies

- Python 3.10+ (aarch64 Raspberry Pi OS target; 3.11 is what that OS ships, but nothing
  requires it), `asyncio`, `scapy`, `pyyaml`.
- DoIP framing and TLS automaton come from Scapy
  (`scapy.contrib.automotive.doip`, `scapy.layers.tls.automaton_*`). Field
  names and automaton constructor signatures vary across Scapy versions —
  **verify them for the installed version before writing code that depends
  on them**:

  ```bash
  python3 -c "
  from scapy.contrib.automotive.doip import DoIP
  p = DoIP(); print(p.fields_desc)"
  python3 -c "
  from scapy.layers.tls.automaton_srv import TLSServerAutomaton
  import inspect; print(inspect.signature(TLSServerAutomaton.__init__))"
  python3 -c "import scapy; print(scapy.__version__)"
  ```

  The verified field names live in a comment block at the top of
  `session.py` — keep it up to date if you touch DoIP field access.

---

## Layout

```
doip_edgenode/
├── config.py            # dataclasses + load_config(), raises ConfigError
├── config.yaml
├── routing.py            # RoutingTable: lookup by tester/ECU logical addr
├── middleware/            # LoggerMiddleware, DropMiddleware, DelayMiddleware,
│                           # CorruptMiddleware, HeaderFaultMiddleware,
│                           # TLSFaultMiddleware, ReplayMiddleware
├── session.py             # DoIPSession — the connection state machine
├── session_registry.py    # SessionRegistry — tester_logical_addr → DoIPSession,
│                           # used for SA-conflict Alive Check probing
├── ecu_client.py          # ECUConnection — outbound leg to the ECU (IPv6);
│                           # runs its own background reader task once RA succeeds
├── tls_bridge.py          # TLSBridge wrapping Scapy's TLS automatons
├── udp_announcer.py       # Vehicle Announcement / Identification and node-management
├── server.py              # DoIPServer: binds sockets, dispatches sessions,
│                           # owns the single shared SessionRegistry instance
├── main.py                # CLI entry point
└── tests/
    ├── mock_ecu.py         # loopback ECU stub for test_session.py
    ├── test_session.py
    └── test_middleware.py
```

## Conventions actually in use here (match these, do not "improve" them)

- License header on every `.py` file — see `../CLAUDE.md` for the exact
  text; it's a repo-wide rule, not specific to this component.
- Logger name = module path: `logger = logging.getLogger(__name__)`.
- Config: dataclasses per YAML section, `load_config(path) -> AppConfig`,
  `ConfigError` on anything invalid (bad TLS version, wrong VIN/EID/GID
  length, `drop_rate` outside `[0,1]`, unknown routing interface, etc. — see
  the validation checklist below).
- Middleware chain: `Middleware.process(pkt, direction, session) -> pkt |
  None`; returning `None` stops the chain (packet dropped).
  `DoIPFaultInjectionError` lets a middleware inject a synthetic NACK instead
  of forwarding.
- Middleware instances are owned by one accepted TCP connection, not shared
  across sessions. Replay buffers and header-fault counters reset on reconnect;
  both directions of a connection use its same chain. Logger output shares a
  canonical-path sink leased by its server; sessions must not close the sink.
  Server shutdown releases its leases after draining sessions; other servers or
  standalone owners on that path retain theirs. Standalone LoggerMiddleware
  users must call its idempotent `close()`. Disabled logger entries validate
  parameters without opening files.
- Middleware parameter bounds: corrupt offsets are nonnegative or `None`, XOR
  masks are `0..255`, address overrides are `0..65535` or `None`, and delay/jitter
  are nonnegative integer milliseconds. Numeric strings (decimal or `0x`) are
  accepted; booleans/floats are not integers. Reserved addresses remain available
  for deliberate fault injection. Unknown middleware types are configuration
  errors even when disabled; do not silently skip them.
- When adding middleware, update both `config.py`'s `_VALID_MIDDLEWARE_TYPES`
  and `server.py`'s `_CLASS_MAP`; loader validation and factory support must
  agree without instantiating middleware during configuration loading.
- Middleware constructors run once for startup validation and again for each
  accepted connection. Limit them to parameter validation and local state
  initialization: no background tasks, sockets, or per-instance file handles.
  The intentionally reused path-scoped logger is the exception. Middleware
  needing owned external resources requires an explicit lifecycle design
  before being added to this construction path.

### TCP framing boundary

- Validate listener-supported type and configured cap, then type-specific payload
  length before Scapy/handlers, independent of activation. Routing requests are
  7/11 bytes, Header NACKs 1, alive requests/responses 0/2, legacy TCP status/power
  requests 0, and diagnostic messages at least 5. Response-only and UDP discovery
  types remain unsupported on the tester TCP listener.
- Valid received Header NACKs are ignored on both legs, never answered or relayed.
  ECU setup retains its three-frame budget; malformed ECU input fails that leg
  without emitting a client Header NACK.
- TCP errors `0x00`/`0x04` close; `0x01`/`0x02` discard the declared body then
  continue. Discard reads at most 4096 bytes per chunk, yields between chunks and
  has one 2-second deadline. EOF or deadline expiry closes because the next header
  cannot safely be identified. This bounds application discard memory/time, not
  aggregate traffic, transport buffering or warning-log rate (separate backlog).

### UDP discovery boundary

- `udp_announcer.py` validates one complete datagram before dispatch: version/
  inverse, listener-supported type, configured payload cap, fixed payload shape
  and exact declared/actual length. Never allocate buffers from declared size.
- Discovery requests `0x0001`/`0x0002`/`0x0003` accept the default version `0xFF`
  with inverse `0x00`; other requests accept `0x02`/`0x03`. Responses remain `0x02`.
- EID/VIN-qualified discovery replies only on exact byte matches. Power request
  `0x4003` is empty and returns `0x4004` with one configured power-mode byte.
- Valid received NACKs and announcements are ignored. Short headers are silently
  discarded; invalid complete messages receive Header NACK without closing the
  shared listener. UDP has no per-peer stream to drain or connection to close.
- UDP uses a portable wildcard IPv4 bind (`0.0.0.0:13400`) on Windows/Linux/macOS,
  with IPv4 mandatory and IPv6 tester-facing support left untouched/deferred. It
  does not use device binding or primary-address queries. `tester_interface` and
  `tester_ipv4` do not restrict UDP; TCP's configured address bind is unchanged.
  Announcements use limited broadcast; egress and reply source selection follow
  OS routing, not guaranteed per-adapter fan-out. Firewall/network policy controls
  access. Interface isolation remains deferred by user choice for portability.
- Multicast, unspecified and limited-broadcast source addresses are silently
  filtered before validation or replies. Directed-broadcast filtering is deferred
  because local interface netmasks are not collected. Off-subnet unicast is allowed;
  this is not a tester ACL or authentication mechanism.
- Initial announcements and each matching identification response have independent
  random waits of 0–500 ms. Configured announcement count/interval remain supported.
  At most 256 discovery replies are pending; excess requests are silently dropped
  without new timers/logs. Stop/transport loss cancels pending replies. Power/NACK
  replies are immediate. Per-rejection WARNING flooding remains separate backlog.
- Entity Status `0x4001`/`0x4002` is supported on TCP and UDP with the mandatory
  three-byte payload only: existing `node_type`, configured MCTS `n`, and live
  NCTS (all open initialized/reserve inbound sockets). Do not add the optional
  MDS field because this payload-cap profile is not verified as a logical MDS.
  UDP status requests are immediate; incoming UDP `0x4002` remains unsupported
  and receives Header NACK `0x01`, not a discovery response. Standalone UDP
  protocol instances use a zero-count independent registry.

### asyncio patterns

- Never use bare `reader.read()` — always `readexactly(n)` for a known
  length; the DoIP header is 8 bytes, payload length is big-endian in bytes
  4–7.
- Timers (`T_TCP_Initial_Inactivity`, `T_TCP_General_Inactivity`) are
  `asyncio.Task`s created with `asyncio.create_task`, cancelled and
  recreated on activity, and swallow `asyncio.CancelledError` silently (that
  is the normal "timer was reset" path, not an error).
- Wrap the session loop in `try/except` covering `ConnectionResetError`,
  `asyncio.IncompleteReadError`, `DoIPProtocolError`, and bare `Exception`
  (log + close). One session's exception must never crash the server.

### Capacity, routing activation, and SA conflicts

`doip.max_connections` is a strict integer in `1..254` and defaults to 8. It is
the maximum number of active registered SAs (MCTS); the server admits at most
`n + 1` open initialized/reserve inbound sockets so NCTS cannot exceed 255.
The same registry is shared by both current TCP listeners, including the TLS
listener (TLS remains a plaintext placeholder and TLS conformance is unclaimed).
Pre-RA status counts include initialized/reserve inbound sockets, never outbound
ECU sockets, and the listening socket; UDP uses the shared registry when owned by
the server. An overflow connection is closed immediately without a Routing
Activation response, since its SA is not known.

For a new unassigned SA, capacity decisions probe all registered active owners
concurrently, with a 0.5 s Alive Check wait. If all owners are dead, close/evict
them and accept the new RA; if all are alive, deny with RA code `0x01` and close
the contender. A same-SA conflict is resolved first: probe only that existing
owner, deny a live owner with `0x03`, or evict a dead owner and accept with
`0x10`. Capacity probing must not evict a changed owner or a waiting client.

**`evict()` must stay synchronous — never replace it with `await
existing._cleanup()`.** Eviction initiates tester close, releases capacity and
owner-safe registration immediately, and schedules that session's single cleanup
owner without joining it from the competing session. Timer expiry likewise
schedules cleanup rather than awaiting it from a task cleanup will cancel.
`close()`/`_cleanup()` join the owner with shielding: repeated caller cancellation
cannot abandon teardown, and is propagated only after the owner finishes.
Cancelled/replaced timers and owned ECU setup/receive tasks must be retained until
drained. Never cancel or await `run()` from session cleanup: `run()`'s `finally`
joins cleanup, which would create an ownership cycle. The server owns and drains
connection handlers, including blocked pre-RA setup. Closing guards prevent late
ECU caching and new timers/sends/replay. ECU-close waits use the existing response
timeout; tester-close waits use two seconds, assuming cooperative cancellation.

Server startup is single-use and transactional across both current TCP listeners
and UDP. Stop rejects late accepts, drains startup acquisitions and owned handlers,
joins session cleanup, and shuts down the executor once. CLI signal callbacks use
`signal.signal()` for SIGINT/SIGTERM, not Windows-unsupported loop signal APIs;
only the first signal cancels the lifetime task and previous handlers are restored.
Neither this lifecycle fix nor mocked signals certify native Windows execution.

Current general inactivity reset remains accepted complete inbound frames after
activation. ISO 13400-2:2019 §12.6.2 / 3.DoIP-080 calls for established-socket RX/TX
activity semantics; partial input, discarded bodies and outbound activity remain
a separate conformance gap, not silently changed during teardown work.

This exact pattern (registry + `probe_alive()` + synchronous `evict()`)
is mirrored in `echo_ecu.py`'s `ECUSessionRegistry`/`ECUSession` for the
ECU-facing leg — keep them consistent if you change one.

### Background reader in `ecu_client.py`

Once Routing Activation toward the ECU succeeds, `ECUConnection` starts a
background `asyncio.Task` (`_background_reader`) that continuously reads
frames from the ECU socket. This exists so the ECU's own unsolicited Alive
Check Request (sent when *it* is probing this connection for an SA conflict)
gets answered immediately, without waiting for `DoIPSession` to call
`recv()`. Everything that isn't an Alive Check Request is placed on
`_recv_queue` for `recv()` to consume. Do not read directly from
`self._reader` anywhere except inside `_background_reader` — it will race
with the background task and drop frames.

### Self-addressed diagnostics (EdgeNode as a pseudo-ECU)

`_handle_diagnostic()` first checks whether `target_address` (read directly
from raw bytes at offset 10–11 of the DoIP frame — **not** via
`getattr(pkt, "target_address", None)`, which Scapy's ConditionalField
returns `None` for even on well-formed frames) equals
`config.doip.node_logical_addr`. If so, the message is answered locally by
`_handle_self_diagnostic()` / `_build_uds_response()` and never forwarded to
the ECU:

- `22 F1 90` (ReadDataByIdentifier — VIN) → `62 F1 90` + the 17-byte VIN from
  `config.doip.vin`.
- Any other UDS request → `SID | 0x40` (reply bit set) + echoed sub-bytes +
  4 random trailer bytes.

Both a Positive ACK (`0x8002`) and the Diagnostic Message response are sent,
matching real ECU behaviour. This exists purely to let a tester verify DoIP
connectivity to the EdgeNode itself without a downstream ECU — extend
`_build_uds_response()` (not `_handle_self_diagnostic()`) if you add more
supported DIDs/services.

### Diagnostic routing is resolved by target address, not tester SA

`_handle_diagnostic()` picks the ECU connection via
`routing_table.lookup_by_ecu_addr(target_address)` — the Diagnostic
Message's own target address (read from the post-middleware bytes, so
`AddressMiddleware`'s `tgt_override` is honored) — **not** by the activated
tester SA. This means one tester session can reach every ECU listed in
`routing_table` just by addressing a `diag` request to that ECU's logical
address; no separate Routing Activation per target ECU is needed.
`RoutingEntry` carries no tester address at all — which tester SAs are
accepted is a separate, unrelated check in `_handle_routing_activation()`:
`config.doip.is_tester_allowed(src_addr)`, driven by `doip.tester_addr_range`
(inclusive `[low, high]`) and/or `doip.tester_addr_list` (individual extra
SAs), both in `config.yaml`. A session opens ECU
connections lazily and caches them in `self._ecu_conns`, keyed by target
ecu_logical_addr (one dict per `DoIPSession` instance — never shared across
tester sessions, so a reply read on one session's `ECUConnection` can never
be confused with another tester's request; see `send_to_ecu()` and
`_cleanup()` for the same per-target bookkeeping). If no routing entry
matches the target at all, send Diag Negative ACK `0x03` (unknown target
address); if an entry exists but the TCP connect to the ECU fails, send
`0x06` (target unreachable) — do not collapse these into a single code, ISO
13400-2 Table 26 distinguishes them and the two cases need different
operator-facing diagnostics (bad config vs. network/ECU down).

### Two-frame ECU response relay

Real ECUs (and `echo_ecu.py`) send **two** frames per Diagnostic Message:
Positive ACK (`0x8002`) first, then the actual Diagnostic Message (`0x8001`)
response. `_handle_diagnostic()` must call the target's `ecu_conn.recv()`
once, relay it, then — only if that first frame's payload type was
`PT_DIAGNOSTIC_POSITIVE_ACK` — call `_recv_ecu_frame(target_ecu_addr,
ecu_conn, timeout)` again for the follow-up response and relay that too via
the shared `_relay_ecu_frame()` helper. Do not assume a single `recv()` is
sufficient; a previous bug silently returned the *previous* request's queued
response instead of the current one because only one `recv()` was performed
per diagnostic request.

### Alive Check roles and payload

On the tester-facing leg, EdgeNode sends empty Alive Check Requests to
registered clients. The tester's Alive Check Response contains its **2-byte
registered tester SA**, not EdgeNode's node address. Only a matching response
to an outstanding probe completes that probe. A valid unsolicited response
is a client keepalive and does not create probe state. Alive traffic before
routing activation is ignored; tester-originated requests receive no reply.

On the ECU-facing leg, EdgeNode is the client. Both the early routing-activation
compatibility reply and the background reader's reply in `ecu_client.py` use
the two-byte tester/client SA requested for that ECU connection. Never send
an empty response or substitute the ECU or EdgeNode node address.

### Scapy-specific pitfalls

- Build packets via field assignment (`pkt.<field> = value`), never raw byte
  concatenation — it breaks silently across Scapy versions.
- After `DoIP(raw_bytes)`, check `pkt.haslayer(DoIP)` before trusting the
  dissection; a failed parse means Header NACK `0x01`.
- `bind_layers(...)` calls belong in a module-level init function that runs
  at import time (before any socket is created), never inside a coroutine.
- `CAP_NET_RAW` is required for live-interface packet crafting; loopback TCP
  tests do not need it.

### Error handling (send this exact NACK/response for each case)

| Condition | Response | Then |
|---|---|---|
| Bad TCP version/inverse | Header NACK `0x00` | close, log WARNING |
| Invalid supported TCP payload length | Header NACK `0x04` | close, log WARNING |
| Unsupported TCP payload type | Header NACK `0x01` | bounded body discard, keep socket if successful |
| Supported TCP payload exceeds configured cap | Header NACK `0x02` | bounded body discard, keep socket if successful |
| Valid received Header NACK | none | ignore; no reply/relay |
| Diagnostic message before Routing Activation | Diag Negative ACK `0x8003` code `0x02` | close, log WARNING |
| TLS handshake failure | (TLS layer sends its own alert) | close, log ERROR, no DoIP message |
| No routing entry for the message's target ecu_logical_addr | Diag Negative ACK `0x8003` code `0x03` (unknown target address) | keep tester session open |
| Routing entry exists but TCP connect to the ECU fails, or `send()`/`recv()` errors on an established ECU connection | Diag Negative ACK `0x8003` code `0x06` (target unreachable) | keep tester session open |
| RA request SA already active & old session alive | RA Response `0x0006` code `0x03` | keep both — new socket closes, old stays |
| RA request SA already active & old session dead | RA Response `0x0006` code `0x10` (after evicting old) | old session's own cleanup runs; new session activates |
| Unhandled exception in session | — | log CRITICAL with traceback, close, server keeps accepting |

### Logging levels

`DEBUG` every frame + middleware decisions · `INFO` session lifecycle/timers ·
`WARNING` protocol violations/NACKs/injected faults · `ERROR` TLS/ECU
failures · `CRITICAL` unhandled exceptions.

Logger middleware uses stdlib rotation at 5 MiB with three backups (roughly
20 MiB retained per canonical path, allowing bounded UTF-8/newline record
overshoot). Optional hex shows at most 4096 raw bytes and marks truncation;
records are capped at 16 KiB. These are product logging defaults, not protocol
limits or YAML settings. Sinks are private logging.Logger objects, removed from
our live registry on final release; unrelated/global logging handlers are not
closed. Ownership assumes construction/teardown on one event-loop thread; this
is not multiprocess or cross-thread rotation coordination. Existing oversized
files rotate on the next write, not during construction. Full packet
serialization, synchronous I/O, console output rate and module/root WARNING
flooding remain unbounded/deferred; F18 rotation does not fix those concerns.

### Config validation checklist (`load_config` must reject all of these)

- `tls_version` not `"TLSv1.3"`
- VIN must be an actual string of exactly 17 ASCII bytes; EID/GID must be
  actual strings of exactly 12 hexadecimal characters
- Probabilities must be finite numbers in `[0.0, 1.0]`; replay count must be
  an integer `>=1`. Drop filters accept `None` or a mapping with supported
  direction and optional `0..65535` payload type.
- Boolean settings require YAML booleans (`true`/`false`), not quoted strings,
  integers or null. This includes TLS, response matching and middleware flags.
- Sections/entries must be mappings with string keys; routing and middleware
  sections must be lists. Invalid input raises `ConfigError` with its field path.
- Ports and normal node/route addresses must be integers in `1..65535`;
  `max_connections` must be a strict integer in `1..254` (default 8); it is the
  active registered-SA capacity, with one additional reserve initialized socket.
  node type is `0..1`, power mode `0..2`, payload cap `1..4294967295`.
  Tester allow-list/range policy and fault-injection address bounds are unchanged.
- Timer seconds must be finite and positive; intervals/counts are integers `>=1`.
  Decimal/hex integer strings and numeric timer strings remain supported.
- Interfaces, certificate paths, log paths and cipher-list elements must be
  nonempty strings. Empty cipher lists retain defaults; empty SNI omits SNI.
  Tester IPv4 and routing IPv6 must be syntactically valid addresses.
- Validation does not check file existence, interface availability or cipher
  support, impose timer ordering, or validate manually constructed dataclasses.
- `header_fault.fault` not one of `wrong_version`/`bad_inverse`/`bad_length`/`unknown_type`
- `inject_on_nth` < 1 · `announce_count` < 1
- routing entry referencing an interface not present in `network.*_interface`
- two routing entries with the same `ecu_logical_addr` (would silently make
  the second one dead config — routing picks the first match)
- `doip.tester_addr_range` not a `[low, high]` pair, or `low > high`, or
  either value outside `0x0000`-`0xFFFF`
- any `doip.tester_addr_list` value outside `0x0000`-`0xFFFF`
- `doip.node_logical_addr == 0x0000` — ISO/SAE reserved (ISO 13400-2), never
  a valid node address; the Docker testbed uses `0x1234` (see the address
  table in `../docker/README.md`)

`node_logical_addr` (EdgeNode's own logical address) is optional and
defaults to `0x1234` if absent — it is used both in UDP Vehicle Announcements
and as the source address in Routing Activation Responses and self-diagnostic
replies. Alive Check Responses instead identify the registered tester/client
SA. `0x0000` is ISO/SAE reserved (ISO
13400-2) and rejected by `load_config()`, so if a Wireshark capture shows
`0x0000` as the EdgeNode's source address, check this config value before
assuming a code bug.

---

## What you must not do

- Do not use the stdlib `ssl` module as the primary TLS handler, and do not
  fall back to TLS 1.2 — reject it.
- Do not hardcode any address, port, VIN, or certificate path — everything
  comes from `config.yaml`.
- Do not parse UDS service IDs here — the diagnostic payload is always
  opaque bytes as far as EdgeNode is concerned (VirtualEcu/Echo ECU parse UDS,
  not EdgeNode).
- Do not call `MiddlewareChain.run()` on an unauthenticated/unactivated
  session.
- Do not use `threading.Thread` directly for TLS automatons — go through
  `TLSBridge`.
- Do not replace `evict()` with an `await`ed call to the target session's
  `_cleanup()` — see the CancelledError propagation note above; it silently
  kills the wrong session.
- Do not read from `ECUConnection._reader` anywhere except
  `_background_reader` — it will race with the background task's read loop.
- Do not read `source_address`/`target_address` off a dissected DoIP packet
  via `getattr(pkt, ...)` and trust `None` as "field absent" — Scapy's
  ConditionalFields can return `None` on valid frames. Read the 2-byte
  addresses directly from `bytes(pkt)` at their fixed offsets (8–9 and
  10–11) instead.
- Do not implement real TLS fault injection logic; `TLSFaultMiddleware` is a
  placeholder that logs and passes through by design.
- Do not build a REST API or web UI for this component.

## Tests

```bash
cd doip_edgenode
pytest tests/test_middleware.py -v   # no root, no live network
pytest tests/test_session.py -v      # uses tests/mock_ecu.py over loopback
```

No `pytest-asyncio` — coroutines are driven through `asyncio.run()` inside
each test or a small helper, matching the pattern used by
`virtual_ecu/tests/conftest.py:run`. Do not add `pytest-asyncio` as a dependency.

## Backlog (known gaps, not yet implemented — do not silently build these)

Raised 2026-11-07 by the user:

- **Tester-facing IPv6 availability — deferred; IPv4 is the current priority.**
  EdgeNode should eventually accept tester connections over IPv6 as well as IPv4
  and support IPv6 UDP discovery/announcements using multicast, with correct
  interface membership, egress and link-local scope handling. Existing ECU-facing
  IPv6 TCP support does not provide tester-facing IPv6 availability. Preserve
  Windows compatibility and current IPv4 behavior; design configuration/socket
  policy and verify native Windows/Linux IPv6 behavior when this item is taken up.
  No IPv6 implementation is authorized by this backlog entry.

Raised 2026-10-02 while reworking diagnostic routing (see "Diagnostic
routing is resolved by target address, not tester SA" above). Each of these
is a real gap, intentionally deferred; a future task should pick one at a
time rather than bundling them, since each has its own protocol-correctness
tradeoffs to think through:

- **Serialize concurrent testers against one ECU.** Now that routing can
  send two different tester sessions' Diagnostic Messages to the same
  physical ECU (e.g. both land on VirtualEcu via two separate ECUConnections),
  nothing stops EdgeNode from forwarding tester A's request and tester B's
  request to that ECU back-to-back before the ECU has answered the first —
  the ECU itself may not tolerate interleaved requests on separate sockets.
  Need a per-ECU (not per-session) mutex/queue in front of
  `ECUConnection.send()`/the ACK+response wait, so a second tester's request
  to the same ecu_logical_addr blocks until the first exchange (ACK through
  final response, including any `0x78` ResponsePending chain) completes.
  Open questions to resolve when this is picked up: what EdgeNode sends
  tester 2 while it's waiting (hold the socket silently vs. some interim
  signal — DoIP itself has no "busy" NACK, so this likely means tester 2's
  request simply isn't ACKed until its turn), and what timeout applies to
  that wait (distinct from `ecu_pending_max_wait_s`, which is scoped to one
  already-admitted request).
- **TesterPresent (`3E`) serialization.** Same mutual-exclusion problem
  applies to keep-alive TesterPresent traffic from one tester interleaving
  with another tester's real diagnostic exchange on the same ECU.
- **Functional (broadcast) addressing.** DoIP functional requests must reach
  every ECU behind the gateway, not just the one routing entry currently
  matched by `lookup_by_ecu_addr()`. This likely needs EdgeNode to hold a
  connection open to every configured ECU proactively (rather than today's
  lazy, first-diag-message connect) so a functional request can fan out
  without incurring a connect delay per target, and to merge/relay however
  many responses come back.

Raised 2026-10-03 during code review of the routing rework above — confirmed
present at HEAD before that change too, so none of these are regressions,
but they block trusting `pytest tests/` results and should be fixed before
relying on CI here:

- **`tests/test_session.py`'s `_make_app_config()` omitted `node_logical_addr`**
  (no default on that `DoIPConfig` field) — every test in the file failed to
  even construct the fixture. Fixed as part of this review pass (added
  `node_logical_addr=0x1234` — not `0x0000`, which is now rejected by
  `load_config()` as ISO/SAE reserved; see the 2026-10-03 address
  renumbering above).
- **`test_full_lifecycle` — resolved.** The test now starts its `MockECU` on
  IPv6 loopback (`::1`, via the mock's optional `host`/`logical_addr`
  arguments) so it matches the IPv6 routing entry, and it skips only itself
  when `::1` is unavailable on the machine. `ecu_client.py`'s
  `ECUConnection.connect()` is unchanged: it still opens an `AF_INET6` socket
  with a scope id from `socket.if_nametoindex(entry.ecu_interface)` (and
  `"lo"` does not exist on macOS, only `"lo0"`).
- **`test_middleware.py` seam failures — resolved.** The five tests that patched
  a module-level `DoIP` in the middleware modules were removed; the Scapy
  header-fault and corrupt behaviour is now covered in
  `tests/test_middleware_validation.py` with real Scapy and hand-written byte
  literals. The lazy Scapy import in `header_fault.py` is unchanged.
- **`pytest-asyncio` policy contradiction**: this file and the root
  `CLAUDE.md` both say "no `pytest-asyncio`", and `requirements.txt` doesn't
  list it, but `pytest.ini` sets `asyncio_mode = auto` and every test in
  `test_session.py` carries `@pytest.mark.asyncio` — both of which require
  `pytest-asyncio` to be installed to run at all (`conftest.py`'s own
  try/except around importing it is dead code: the `pytest_ini_options`
  variable it sets on import success is never read by pytest, so it doesn't
  actually make the plugin optional). A clean `pip install -r
  requirements.txt && pytest` fails as a result. Either add `pytest-asyncio`
  to `requirements.txt` and fix the docs (reverses the stated policy), or
  rewrite `test_session.py` to use the `run()`-helper pattern this file
  prescribes (matching `virtual_ecu/tests/conftest.py:run`) and remove
  `pytest.ini`'s `asyncio_mode` / the `@pytest.mark.asyncio` decorators —
  pick one deliberately rather than leaving the contradiction.

None of this is implemented yet. Flag it rather than building it
speculatively — each needs its own design pass on the wire-level contract
(what EdgeNode actually sends a waiting tester) before writing code.
