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

### Two-frame ECU response relay

Real ECUs (and `echo_ecu.py`) send **two** frames per Diagnostic Message:
Positive ACK (`0x8002`) first, then the actual Diagnostic Message (`0x8001`)
response. `_handle_diagnostic()` must call `_ecu_conn.recv()` once, relay it,
then — only if that first frame's payload type was `PT_DIAGNOSTIC_POSITIVE_ACK`
— call `recv()` again (with a short timeout) for the follow-up response and
relay that too via the shared `_relay_ecu_frame()` helper. Do not assume a
single `recv()` is sufficient; a previous bug silently returned the *previous*
request's queued response instead of the current one because only one `recv()`
was performed per diagnostic request.

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
| ECU unreachable | Diag Negative ACK `0x8003` code `0x03` | keep tester session open |
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
