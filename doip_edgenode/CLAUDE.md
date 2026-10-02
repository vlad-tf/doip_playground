# EdgeNode — Code Agent Instructions

## Scope

This file governs `doip_edgenode/` only. It is the Scapy-based DoIP proxy that
runs on the Raspberry Pi between the PC Tester and an ECU. Do not apply these
conventions to `test_ecu/`, `echo_ecu/`, or `pc_tester/` — each has its own
style; see `../CLAUDE.md` for why.

**Primary reference:** `../doip_edgenode_requirements.md`. Read it before
changing behaviour, not just this file.

**Status:** implemented PoC. TLS handshake is not functional (port 3496
accepts but does not negotiate), single tester connection only, no
SIGHUP reload — see "Known limitations" in `main.py`'s docstring and
`../README.md` §10 before "fixing" any of these as if they were bugs.

---

## Stack & dependencies

- Python 3.11+ (aarch64 Raspberry Pi OS target), `asyncio`, `scapy`, `pyyaml`.
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
├── udp_announcer.py       # Vehicle Announcement / Identification
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

### Second-connection / SA-conflict handling (ISO 13400-2 §9.3)

A second TCP connection is **not** rejected at the transport level. It is
accepted, and the conflict is resolved only when its Routing Activation
Request arrives with a source address (SA) already registered on another
active session (tracked by `SessionRegistry`, one shared instance owned by
`DoIPServer` and passed into every `DoIPSession`):

1. Probe the existing session with `await existing.probe_alive(timeout=0.5)` —
   this sends an Alive Check Request to the *old* tester and awaits its
   Alive Check Response.
2. Old session responds (still alive) → deny the new RA with code `0x03`
   ("SA already registered on different socket").
3. Old session times out (dead) → call `existing.evict()`, then accept the
   new RA with `0x10`.

**`evict()` must stay synchronous — never replace it with `await
existing._cleanup()`.** `_cleanup()` awaits `writer.wait_closed()`; if the old
session's own inactivity-timeout task is concurrently mid-cleanup and gets
cancelled, the injected `CancelledError` is a `BaseException` and is not
caught by `_cleanup()`'s `except Exception: pass` guards — it propagates
through the awaiting caller (the *new* session's `_handle_routing_activation`)
and kills the new session instead of the old one. `evict()` only cancels
timers, closes the writer, and unregisters — all non-blocking — and lets the
old session's own `run()`/`finally` block finish its own `_cleanup()` in its
own task context.

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

### Alive Check Response payload

Both `_handle_alive_check()` (self.config.doip.node_logical_addr for the
tester-facing leg) and the ECU-facing Alive Check auto-reply in
`ecu_client.py`'s background reader must send the **2-byte logical address of
the responder** as the payload (ISO 13400-2 Table 22) — never an empty
payload. An empty Alive Check Response payload was a real bug found via
Wireshark (`Length: 0` where `Length: 2` was expected).

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
| Malformed header (bad version/inverse/too large) | Header NACK `0x0000` | close, log WARNING |
| Unknown payload type | Header NACK `0x01` | close, log WARNING |
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

### Config validation checklist (`load_config` must reject all of these)

- `tls_version` not `"TLSv1.3"`
- VIN length ≠ 17; EID/GID not exactly 12 hex chars
- `drop_rate` outside `[0.0, 1.0]`
- `header_fault.fault` not one of `wrong_version`/`bad_inverse`/`bad_length`/`unknown_type`
- `inject_on_nth` < 1 · `announce_count` < 1
- routing entry referencing an interface not present in `network.*_interface`
- two routing entries with the same `ecu_logical_addr` (would silently make
  the second one dead config — routing picks the first match)
- `doip.tester_addr_range` not a `[low, high]` pair, or `low > high`, or
  either value outside `0x0000`-`0xFFFF`
- any `doip.tester_addr_list` value outside `0x0000`-`0xFFFF`

`node_logical_addr` (EdgeNode's own logical address) is optional and
defaults to `0x0000` if absent — it is used both in UDP Vehicle Announcements
and as the source address in Routing Activation Responses / Alive Check
Responses / self-diagnostic replies. If a Wireshark capture shows `0x0000`
as the EdgeNode's source address where a distinct address was expected,
check this config value before assuming a code bug.

---

## What you must not do

- Do not use the stdlib `ssl` module as the primary TLS handler, and do not
  fall back to TLS 1.2 — reject it.
- Do not hardcode any address, port, VIN, or certificate path — everything
  comes from `config.yaml`.
- Do not parse UDS service IDs here — the diagnostic payload is always
  opaque bytes as far as EdgeNode is concerned (TestEcu/Echo ECU parse UDS,
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
`test_ecu/tests/conftest.py:run`. Do not add `pytest-asyncio` as a dependency.

## Backlog (known gaps, not yet implemented — do not silently build these)

Raised 2026-10-02 while reworking diagnostic routing (see "Diagnostic
routing is resolved by target address, not tester SA" above). Each of these
is a real gap, intentionally deferred; a future task should pick one at a
time rather than bundling them, since each has its own protocol-correctness
tradeoffs to think through:

- **Serialize concurrent testers against one ECU.** Now that routing can
  send two different tester sessions' Diagnostic Messages to the same
  physical ECU (e.g. both land on TestEcu via two separate ECUConnections),
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
  `node_logical_addr=0x0000`).
- **`test_full_lifecycle` still can't complete**: `tests/mock_ecu.py`'s
  `MockECU` binds plain IPv4 (`127.0.0.1`), but `_make_app_config()`'s
  routing entry points `ecu_client.py`'s `ECUConnection.connect()` at IPv6
  (`ecu_ipv6="::1"`) — and `connect()` always opens an `AF_INET6` socket
  with a scope id from `socket.if_nametoindex(entry.ecu_interface)`
  regardless of whether the address is link-local or loopback, so it can
  never reach an IPv4-only `MockECU`. (The interface-name part is also
  platform-specific: `"lo"` doesn't exist on macOS, only `"lo0"`.) Needs
  either an IPv6-capable `MockECU`, or a `connect()` path that skips the
  scope-id lookup for non-link-local addresses — not decided here.
- **5 `test_middleware.py` failures**: `patch.object(header_fault, "DoIP",
  ...)` fails because `header_fault.py` imports Scapy's `DoIP` lazily inside
  a method rather than at module scope, so there's no module-level `DoIP`
  attribute for `patch.object` to replace. Fix is either to patch at the
  import site actually used, or hoist the import to module scope if nothing
  about the lazy-import rationale (if any) depends on deferring it.
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
  prescribes (matching `test_ecu/tests/conftest.py:run`) and remove
  `pytest.ini`'s `asyncio_mode` / the `@pytest.mark.asyncio` decorators —
  pick one deliberately rather than leaving the contradiction.

None of this is implemented yet. Flag it rather than building it
speculatively — each needs its own design pass on the wire-level contract
(what EdgeNode actually sends a waiting tester) before writing code.
