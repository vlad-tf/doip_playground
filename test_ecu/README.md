# TestEcu — an extensible DoIP/UDS ECU simulator

TestEcu speaks DoIP (ISO 13400-2) and UDS (ISO 14229-1) and lets **you** supply the
business logic — either as a YAML table of data identifiers, or as Python plugins, or
both.

It is a sibling of [`echo_ecu/`](../echo_ecu/), not a replacement: the echo node still
exists and still works. TestEcu reuses its (proven) DoIP layer and replaces its 23-line
canned-echo UDS handler with a real service layer you can extend.

**Dependencies: PyYAML. That is the whole list.** No `udsoncan`, no `py-uds`, no Scapy.
Python 3.9 or newer.

---

## Quick start

```bash
cd test_ecu

# 1. Check the config and print the resolved hook table
python3 -m testecu --config config.yaml --check

# 2. Run it on IPv6 loopback.
#    --no-udp is required on macOS: joining ff02::1 on lo0 fails, and there is no eth0.
python3 -m testecu --config config.yaml --host ::1 --interface "" --no-udp --log-level DEBUG

# 3. In another terminal, talk to it
python3 tools/uds_probe.py --host ::1 --uds "22 F1 90"
```

```
routing activation -> 0x10 (success)

-> 22 F1 90
   ack 0x8002
<- 62 F1 90 31 48 47 42 48 34 31 4A 58 4D 4E 31 30 39 31 38 36
```

Run the tests with `pip3 install --user pytest && python3 -m pytest tests -v`.

---

## Two ways to add behaviour

### 1. Static data — YAML only, no code

Most of what a tester needs to read is a fixed value. Declare it and you are done:

```yaml
data_identifiers:
  0xF190:
    name:   VIN
    type:   ascii          # hex | ascii | uint | dynamic
    length: 17
    value:  "1HGBH41JXMN109186"
    read:   true

  0x0100:
    name:   CalibrationBlock
    type:   hex
    length: 4
    value:  "DEADBEEF"
    read:   true
    write:  true
    write_sessions: [0x03]   # not writable in the default session -> 7F 2E 31
    write_security: 1        # needs SecurityAccess level 1        -> 7F 2E 33
```

Writes land in an in-memory store, so `2E 01 00 11 22 33 44` followed by `22 01 00`
returns the value you just wrote. `ECUReset` (0x11) puts the defaults back.

### 2. Real logic — a Python plugin

A plugin module is any `.py` file that defines one or more `Plugin` subclasses:

```python
# plugins/my_ecu.py
from testecu import Plugin, read_did, write_did, routine, on_service
from testecu import NRC_CONDITIONS_NOT_CORRECT

class MyEcu(Plugin):
    name = "MyEcu"
    priority = 50                      # lower runs first

    def __init__(self, gain: int = 1, **params):
        super().__init__(gain=gain, **params)   # `gain` comes from YAML params:
        self.counter = 0

    @read_did(0xF200)                  # -> 62 F2 00 <your bytes>
    def uptime(self, req, ctx):
        self.counter += 1
        return self.counter.to_bytes(2, "big")

    @write_did(0xF201)
    def set_mode(self, value, req, ctx):
        if value not in (b"\x00", b"\x01"):
            raise ctx.nrc(NRC_CONDITIONS_NOT_CORRECT, "mode must be 0 or 1")
        ctx.store.write(0xF201, value)
        return True                    # -> 6E F2 01
```

Point the config at it:

```yaml
plugins:
  modules:
    - file: "plugins/my_ecu.py"
      params: {gain: 3}
```

---

## The five decorators

| Decorator | Handler signature | Return |
|---|---|---|
| `@on_service(sid)` | `(self, req, ctx)` | the **complete** UDS response bytes, incl. response SID |
| `@on_service()` | `(self, req, ctx)` | same, but sees **every** service (catch-all) |
| `@on_request()` | `(self, req, ctx)` | ignored — an observer for logging/metrics |
| `@read_did(did)` | `(self, req, ctx)` | the DID **value only**; `62 <did>` is prepended |
| `@write_did(did)` | `(self, value, req, ctx)` | `True` to accept; `6E <did>` is sent |
| `@routine(rid[, control])` | `(self, control, data, req, ctx)` | routineStatusRecord; `71 <control> <rid>` is prepended |

Every handler may be `def` **or** `async def`. Sync handlers run on the event loop — if
yours blocks, wrap the slow part in `asyncio.to_thread`.

### What a handler returns

| Return | Effect |
|---|---|
| `bytes` | that is the response (see the table above for what is prepended) |
| `None` | **not handled** — fall through to the next candidate |
| `True` (write handlers) | accepted |
| `NO_RESPONSE` | handled, but send nothing at all |
| `raise ctx.nrc(NRC_X, "why")` | `7F <sid> <nrc>` |
| `raise NegativeResponse(NRC_X)` | same, for code that has no `ctx` at hand |

`None` meaning *fall through* is the single most important rule. It is what lets a
plugin claim a DID conditionally, or take over a whole service and hand parts of it back.

### The context object

```python
ctx.ecu             # EcuCore — process-wide
ctx.session         # SessionState — this TCP connection
ctx.request         # the UdsRequest (same object as `req`)
ctx.store           # DidStore: read(did) / write(did, value) / reset()
ctx.data            # free-form dict, shared across connections, yours to use
ctx.config          # the raw parsed YAML
ctx.log             # a logger

ctx.session_type    # 0x01 default, 0x03 extended, ...
ctx.security_level  # 0 = locked
ctx.source_addr     # tester logical address
ctx.target_addr     # the address that was addressed
ctx.functional      # True if this was a functional request

await ctx.send(b"...")          # emit an extra response frame right now
await ctx.response_pending()    # emit 7F <sid> 78 by hand
ctx.nrc(code, "reason")         # build a NegativeResponse — `raise` it
```

And on the request:

```python
req.sid              req.data              # everything after the SID
req.sub_function     req.suppress_pos_rsp  # None/False for services without one
req.did              req.dids()            # for 0x22 / 0x2E
req.positive(body)   req.negative(nrc)     # response builders
req.describe()                             # "ReadDataByIdentifier (0x22)"
```

Plugin lifecycle hooks: `async def setup(self, ecu)` runs once before the socket binds,
`async def teardown(self, ecu)` runs on shutdown.

---

## Precedence — who answers first

For each request, the first candidate that returns anything other than `None` wins:

```
0.  @on_request observers        always run; return ignored, exceptions swallowed
1.  @on_service(<sid>) hooks     ordered by (priority, load order, plugin name)
2.  @on_service() catch-alls     same ordering
3.  the built-in core service
      0x22  ->  @read_did   ->  YAML data_identifiers  ->  uds.unknown_did policy
      0x2E  ->  @write_did  ->  YAML writable entry    ->  uds.unknown_did policy
      0x31  ->  @routine    ->  YAML routines          ->  NRC 0x31
4.  uds.unknown_service policy   nrc (7F <sid> 11) | echo | silent
```

Two consequences worth internalising:

- **A per-SID hook shadows the per-DID sugar for that SID.** If you write
  `@on_service(0x22)` you own DID routing for reads — return `None` to hand it back.
  This is deliberate: the alternative would make a catch-all 0x22 interceptor impossible.
- **A `@read_did` handler beats the YAML entry for the same DID**, and returning `None`
  from it falls back to YAML. That is how you make a DID dynamic only under some
  condition.

If two plugins claim the same DID or SID, both are registered, the lower `priority` runs
first, and a warning naming both is logged at startup. Nothing is silently dropped.

---

## What is built in, and what is yours

Implemented by the core, all of it overridable by `@on_service`:

| SID | Service | Notes |
|---|---|---|
| `0x10` | DiagnosticSessionControl | `50 <sub> P2 P2*`; relocks security, re-arms S3 |
| `0x11` | ECUReset | restores DID defaults; **does not drop the TCP connection** (see below) |
| `0x22` | ReadDataByIdentifier | multi-DID; serves `0xF186` = active session |
| `0x27` | SecurityAccess | fixed seed + `none`/`xor`/`add` key; attempt counter |
| `0x2E` | WriteDataByIdentifier | length-checked against the YAML `length:` |
| `0x31` | RoutineControl | start/stop/results, with sequence checks |
| `0x3E` | TesterPresent | honours the suppress bit, refreshes S3 |

Deliberately **not** built in, because they are OEM-shaped and are exactly what the
plugin system is for: `0x14`, `0x19` (ReadDTCInformation), `0x23`/`0x3D` (memory),
`0x28`, `0x2C`, `0x2F`, `0x34`–`0x37` (transfer), `0x85`.
[`plugins/example_faults.py`](plugins/example_faults.py) implements `0x19` as a worked
example in about fifteen lines.

### Deliberate deviations from a real ECU

- **ECUReset keeps the socket open.** A real ECU would vanish off the bus. Dropping the
  connection would force every test client to reconnect and re-activate routing after
  each reset, which makes the simulator much less useful.
- **Nothing is random.** The security seed comes from the config, and the `echo`
  fallback echoes the request with no random trailer (the echo node appends four random
  bytes). A simulator you cannot write an assertion against is not worth much.
  `tests/test_dispatcher.py` enforces this at the source level.
- **`suppress_pos_rsp` is only honoured for services that actually have a sub-function**
  (`testecu/uds.py: SUB_FUNCTION_SERVICES`). For ReadDataByIdentifier, byte 1 is the DID
  high byte — without this, `22 F1 90` would look like a suppressed request and the VIN
  would never be sent.

---

## Configuration reference

Sections `listen`, `doip` and `udp` are identical to
[`echo_ecu/config.yaml`](../echo_ecu/config.yaml). The rest:

### `uds:`

| Key | Default | Meaning |
|---|---|---|
| `default_session` | `0x01` | session at connect and after ECUReset |
| `sessions` | `[1,2,3,4]` | sub-functions 0x10 accepts |
| `s3_server_ms` | `5000` | non-default session falls back after this idle time |
| `p2_server_ms` | `50` | emit `7F xx 78` if a handler takes longer |
| `p2_star_server_ms` | `5000` | and again every 90% of this |
| `auto_response_pending` | `true` | set false to never emit 0x78 automatically |
| `suppress_pos_rsp_bit` | `true` | honour sub-function bit 7 |
| `functional_addr` | `0x1FFF` | target address that means "functional request" |
| `unknown_service` | `nrc` | `nrc` → `7F <sid> 11`, `echo`, `silent` |
| `unknown_did` | `nrc` | `nrc` → `7F <sid> 31`, `echo` (returns the DID), `silent` |
| `on_handler_error` | `nrc` | `nrc` → `7F <sid> 22`, `fallthrough`, `silent` |
| `reset_clears_writes` | `true` | ECUReset restores YAML DID defaults |
| `security.*` | | `enabled`, `seed`, `algorithm`, `key`, `max_attempts` |

`unknown_service: echo` reproduces the echo node's behaviour if you want a drop-in
replacement rather than a strict ECU.

### `data_identifiers:`

`name`, `type` (`hex`/`ascii`/`uint`/`dynamic`), `length`, `value`, `read`, `write`,
`read_sessions`, `write_sessions`, `read_security`, `write_security`, `read_nrc`,
`write_nrc`.

`type: dynamic` declares a DID with no static value — the core serves `0xF186`, and any
other dynamic DID needs a `@read_did` handler. `read_nrc`/`write_nrc` force a specific
negative response, which is handy for exercising a tester's error handling.

Values are encoded once, at load time, so a typo fails at startup rather than on the
hundredth request.

### `plugins:`

```yaml
plugins:
  strict: false           # true = a plugin that fails to load aborts startup (use in CI)
  path:  ["plugins"]      # auto-discovery: every *.py, sorted, _* skipped, no params
  modules:                # explicit, ordered, can carry params
    - file:   "plugins/my_ecu.py"
      enabled: true
      priority: 50
      params:  {gain: 3}
    - module: "mycompany.brake_ecu"    # any importable module name
```

Do not list the same file under both `path` and `modules` — it would load twice.
`priority:` here overrides the class attribute for **every** `Plugin` subclass defined in
that file.

**Error isolation.** A plugin that fails to import is logged with a full traceback and
skipped; the ECU still starts. A handler that raises is logged and converted per
`on_handler_error`; the connection survives and the next request is served normally. Set
`strict: true` when you would rather a broken plugin fail the build.

---

## CLI

```
--config PATH        default config.yaml
--log-level LEVEL    DEBUG | INFO | WARNING | ERROR
--host / --port / --interface    override the listen section
--no-udp             skip the UDP announcer
--plugin PATH        load an extra plugin file; repeatable, runs first
--check              load config + plugins, print the hook table, exit 0/1
```

`--check` is the smoke test to run in CI and after editing a plugin:

```
Static DIDs         : 7
Plugins             : 3
Hooks               : 8
  observer                 EngineEcu.trace              priority=50
  service 0x19             SimpleDtcs.read_dtc          priority=10
  service <any>            RawFaults.intercept          priority=10
  read_did 0xF40C          EngineEcu.read_engine_speed  priority=50
  ...
```

---

## Docker

```bash
cd ..                                  # repo root
docker compose build doip-testecu
docker compose up -d
docker compose logs -f doip-testecu    # the hook table is printed at INFO
```

TestEcu runs alongside the echo node: echo node keeps `fd2e:646f:6970::2` /
logical address `0x0001`, TestEcu takes `fd2e:646f:6970::3` / `0x0002`. To reach it
through the EdgeNode from the PC tester, set `ecu_logical_addr: 0x0002` in
[`docker/pctester.config.yaml`](../docker/pctester.config.yaml).

Your own plugins go in without a rebuild — `./test_ecu/plugins` is mounted at
`/app/plugins`, so drop a `.py` in and `docker compose restart doip-testecu`. Point the
volume somewhere else to use a directory outside this repo:

```yaml
volumes:
  - /path/to/my_plugins:/app/plugins:ro
```

---

## Layout

```
test_ecu/
├── main.py                  # `python3 main.py` shim; canonical is `python3 -m testecu`
├── config.yaml              # the annotated default config
├── testecu/
│   ├── doip.py              # DoIP constants + frame helpers (ported from echo_ecu)
│   ├── udp.py               # vehicle announcements
│   ├── uds.py               # SIDs, NRCs, UdsRequest, NegativeResponse, NO_RESPONSE
│   ├── plugin.py            # >>> the plugin API: decorators, Plugin, Context <<<
│   ├── config.py            # typed YAML loader
│   ├── store.py             # DID values (YAML defaults + runtime writes)
│   ├── loader.py            # importlib discovery + error isolation
│   ├── dispatcher.py        # the precedence ladder
│   ├── services/            # the built-in UDS core
│   ├── core.py              # EcuCore + SessionState
│   ├── session.py           # the DoIP connection state machine
│   └── server.py            # the TCP listener
├── plugins/                 # your business logic lives here
├── tools/uds_probe.py       # one-shot DoIP client
└── tests/                   # pytest; no plugins needed beyond pytest itself
```

### Known duplication

`testecu/doip.py`, `session.py` and `server.py` are a port of `echo_ecu/echo_ecu.py`
rather than a shared library. That is on purpose: each ECU is built as its own Docker
image from its own single-directory build context, and sharing code would mean changing
the echo node — which is meant to stay frozen and working.
`tests/test_doip_parity.py` imports the real `echo_ecu.py` and asserts the framing is
byte-identical, so the two cannot drift silently.

Separately, `doip_edgenode/session.py:506` still carries its own copy of the old
`_build_uds_response` for self-addressed diagnostics. Wiring that up to this dispatcher
is a sensible follow-up, but it is out of scope here.
