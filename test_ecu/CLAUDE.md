# TestEcu — Code Agent Instructions

## Scope

This file governs `test_ecu/` only. TestEcu is the extensible DoIP/UDS ECU
simulator: a real UDS service layer (sessions, security access, NRCs) plus a
plugin API, replacing `echo_ecu/`'s 23-line canned echo. Do not apply these
conventions to `doip_edgenode/`, `echo_ecu/`, or `pc_tester/` — see
`../CLAUDE.md` for why the components differ.

**Primary reference:** `test_ecu/README.md` for behaviour and the plugin API;
this file is for *how to write code here*, not what the code does.

**Dependencies: PyYAML, full stop.** No Scapy, no `udsoncan`/`py-uds`, no
`pytest-asyncio`. Do not add a dependency without a strong reason — the whole
point of this component is that it runs anywhere with `pip3 install pyyaml`.

**Python 3.10+ is the supported floor** (Ubuntu 22.04 test server, Debian
bookworm / Raspberry Pi OS 3.11 deployment target and Docker base). It still
imports on 3.9 thanks to `from __future__ import annotations`, but 3.9 is not
tested and nothing should be held back for it — don't add compatibility
shims for it.

---

## Layout

```
test_ecu/
├── main.py                  # `python3 main.py` shim; canonical is `python3 -m testecu`
├── config.yaml               # annotated default config
├── testecu/
│   ├── doip.py               # DoIP constants + frame helpers (ported from echo_ecu — see below)
│   ├── udp.py                 # vehicle announcements
│   ├── uds.py                 # SIDs, NRCs, UdsRequest, NegativeResponse, NO_RESPONSE
│   ├── plugin.py               # >>> the plugin API: decorators, Plugin, Context <<<
│   ├── config.py               # typed YAML loader
│   ├── store.py                # DID values (YAML defaults + runtime writes)
│   ├── loader.py                # importlib discovery + error isolation
│   ├── dispatcher.py            # the precedence ladder (see below)
│   ├── services/                 # built-in UDS core (session control, security, DID, routine, reset)
│   ├── core.py                   # EcuCore (process-wide) + SessionState (per connection)
│   ├── session.py                # DoIP connection state machine
│   └── server.py                 # TCP listener
├── plugins/                  # user business logic — never core code
├── tools/uds_probe.py         # one-shot DoIP client for manual testing
└── tests/                     # pytest; nothing but pytest itself required
```

`testecu/__init__.py` is the plugin author's whole public surface — if you
add something a plugin needs, export it there too, not just from the
internal module.

---

## Conventions to follow (match existing files exactly)

- License header on every `.py` file (see `../CLAUDE.md` for the exact
  text — it applies repo-wide, not just here). It goes above the module
  docstring.
- `from __future__ import annotations` at the top of every module.
- Module docstring explaining the "why", not a restatement of the class
  list — see `store.py`, `dispatcher.py`, `doip.py` for the tone to match.
- Config: dataclasses + `parse_config()`/`load_config()` + single
  `ConfigError`, integers accept both hex strings and plain ints via a
  shared `_to_int(value, where)` helper (base 0). Missing *sections* are
  tolerated; a malformed *entry* inside a present section is a hard error —
  a typo'd DID must fail at startup, not silently misbehave forever.
- Logger names are dotted under `testecu.*`
  (`logging.getLogger("testecu.dispatcher")`, `"testecu.core"`, ...), not
  `__name__` — follow the existing per-module logger name, don't invent a
  new naming scheme.

### The dispatcher precedence ladder — do not reorder without reading `dispatcher.py`'s module docstring

For each UDS request, the first candidate to return something other than
`None` wins:

```
0. @on_request observers     — always run, return ignored, exceptions swallowed
1. @on_service(<sid>) hooks  — ordered by (priority, load_index, name)
2. @on_service() catch-alls  — same ordering
3. the built-in core service for that SID
     0x22 -> @read_did  -> YAML data_identifiers -> unknown_did policy
     0x2E -> @write_did -> YAML writable entry   -> unknown_did policy
     0x31 -> @routine   -> YAML routines         -> NRC 0x31
4. uds.unknown_service policy (nrc 0x11 | echo | silent)
```

A per-SID `@on_service` hook deliberately shadows the `@read_did`/`@write_did`/
`@routine` sugar for that SID — that's what lets a plugin take over a whole
service. Returning `None` from any handler always means "not handled, keep
going", never "handled with nothing to say" (that's what `NO_RESPONSE` is
for).

### Handler isolation is load-bearing — never remove it

Every hook call goes through `Dispatcher._call()`, which:
- re-raises `NegativeResponse` and `SuppressResponse`/`CancelledError` as-is
  (those are a handler telling us what to do),
- catches anything else, logs it with `.exception(...)` (full traceback),
  and converts it per `uds.on_handler_error` (`nrc` / `fallthrough` /
  `silent`) — **a plugin exception must never take down the connection or
  the process.** Same pattern in `EcuCore.startup()`/`shutdown()` for plugin
  `setup()`/`teardown()`. Preserve this whenever you touch dispatch or
  plugin lifecycle code.

### Plugin API stability

`testecu/plugin.py` (`Plugin`, `Context`, `@on_service`, `@on_request`,
`@read_did`, `@write_did`, `@routine`) is the external contract documented in
`README.md` and `plugins/README.md`. Treat signature changes here as
breaking changes: update both READMEs and `plugins/example_*.py` in the same
change, and check `test_ecu/tests/test_plugin_loader.py` still describes the
real behaviour.

### Deliberate ECU-simulator deviations from a real ECU — do not "fix" these

- `ECUReset` (0x11) keeps the TCP socket open (a real ECU would drop off the
  bus; that would just force reconnects on every test client).
- Nothing here is random: the security seed comes from config, and the
  `unknown_service: echo` fallback echoes with **no** trailer bytes
  (`echo_ecu` appends four random bytes — TestEcu never does).
  `tests/test_dispatcher.py` enforces this at the source level; don't add
  randomness back in.
- `suppress_pos_rsp` is only honoured for services with an actual
  sub-function (`uds.py: SUB_FUNCTION_SERVICES`) — for `0x22`
  ReadDataByIdentifier, byte 1 is the DID high byte, not a sub-function bit.

### Relationship to `echo_ecu/` — read before touching `doip.py`

`testecu/doip.py`, `session.py`, and `server.py` are a **deliberate port**
of `echo_ecu/echo_ecu.py`'s framing, not a shared library — each ECU builds
as its own single-directory Docker context, and `echo_ecu/` is meant to stay
frozen. `tests/test_doip_parity.py` imports the real `echo_ecu.py` and
asserts byte-identical framing (constants, `build_frame`, `ptype`/`payload`
accessors, hex formatting). If you change DoIP framing in either file, run
that test and expect it to fail — that's the point, not a bug to work
around. Do not "deduplicate" the two by importing across component
boundaries; that breaks the independent-Docker-build-context design.

Separately: `doip_edgenode/session.py` still carries its own copy of a UDS
response builder for self-addressed diagnostics. Wiring that to this
dispatcher is a plausible future task, but it is out of scope unless
explicitly asked for.

---

## Tests

```bash
cd test_ecu
pip3 install --user pytest         # the whole dev dependency, nothing else
python3 -m pytest tests -v
```

- No `pytest-asyncio` (see `pytest.ini` and `tests/conftest.py`): async code
  is driven through the `run(coro)` helper in `conftest.py` — new event
  loop, run to completion, cancel and drain any stray tasks (e.g. an armed
  S3 timer) before closing. Use `Probe`/`probe_for()` from `conftest.py` for
  new dispatcher/plugin tests rather than opening real sockets; reserve
  `tests/test_e2e_doip.py`-style real-socket tests for end-to-end coverage.
- `tests/test_doip_parity.py` is skipped automatically if `echo_ecu/` is not
  present alongside this checkout — don't "fix" the skip, it's intentional
  for standalone Docker build contexts.
- Manual smoke test before any config/plugin change ships:
  ```bash
  python3 -m testecu --config config.yaml --check
  ```
  This loads config + plugins and prints the resolved hook table; it is the
  fastest way to catch a broken plugin or a config typo without starting a
  server.

## What you must not do

- Do not add a UDS/diagnostics library dependency (`udsoncan`, `py-uds`,
  etc.) — the point of this component is that it needs none.
- Do not make `@on_request` observers able to affect the response — they are
  strictly side-effect/logging-only by contract.
- Do not change `unknown_service: echo` to add random trailer bytes, or
  otherwise make TestEcu's behaviour non-deterministic — a simulator you
  cannot assert against is not useful for testing.
- Do not put business logic in `testecu/core.py`, `dispatcher.py`, or
  `services/` — that belongs in `plugins/` or the YAML `data_identifiers:`
  table. Core stays generic.
- Do not remove or weaken the try/except isolation around plugin
  `setup()`/`teardown()`/handler calls.
