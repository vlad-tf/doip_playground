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
├── ecu_client.py          # ECUConnection — outbound leg to the ECU (IPv6)
├── tls_bridge.py          # TLSBridge wrapping Scapy's TLS automatons
├── udp_announcer.py       # Vehicle Announcement / Identification
├── server.py              # DoIPServer: binds sockets, dispatches sessions
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
