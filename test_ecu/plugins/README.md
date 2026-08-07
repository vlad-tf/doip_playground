# Your plugins go here

Copy the starter below to `plugins/my_ecu.py`, edit it, and register it in `config.yaml`:

```yaml
plugins:
  modules:
    - file: "plugins/my_ecu.py"
      params: {}
```

Then check it loaded, and try it:

```bash
python3 -m testecu --config config.yaml --check
python3 -m testecu --config config.yaml --host ::1 --interface "" --no-udp &
python3 tools/uds_probe.py --host ::1 --uds "22 F2 00"
```

## Starter

```python
from testecu import (
    NRC_CONDITIONS_NOT_CORRECT,
    NRC_REQUEST_OUT_OF_RANGE,
    Plugin,
    on_service,
    read_did,
    routine,
    write_did,
)


class MyEcu(Plugin):
    """One sentence about what this ECU pretends to be."""

    name = "MyEcu"
    priority = 100                     # lower runs first

    def __init__(self, **params):
        super().__init__(**params)     # anything under `params:` in YAML lands on self
        self.counter = 0

    async def setup(self, ecu):
        """Runs once, before the socket binds."""
        ecu.log.info("MyEcu ready")

    # 22 F2 00  ->  62 F2 00 <2 bytes>
    @read_did(0xF200)
    def read_counter(self, req, ctx):
        self.counter += 1
        return self.counter.to_bytes(2, "big")

    # 2E F2 01 xx  ->  6E F2 01
    @write_did(0xF201)
    def write_mode(self, value, req, ctx):
        if len(value) != 1:
            raise ctx.nrc(NRC_REQUEST_OUT_OF_RANGE, "mode is one byte")
        if ctx.security_level < 1:
            raise ctx.nrc(NRC_CONDITIONS_NOT_CORRECT, "unlock first")
        ctx.data["mode"] = value[0]
        return True

    # 31 01 F2 02  ->  71 01 F2 02 <record>
    @routine(0xF202)
    def calibrate(self, control, data, req, ctx):
        if control != 0x01:            # only startRoutine
            return None                # fall through
        return b"\x00"

    # Any service TestEcu has no core support for
    @on_service(0x2F)                  # InputOutputControlByIdentifier
    def io_control(self, req, ctx):
        return None                    # return None until you implement it
```

## Rules worth remembering

- `None` means **not handled** — the request falls through to the next candidate, then
  to the YAML tables, then to the built-in core.
- `raise ctx.nrc(CODE, "reason")` sends `7F <sid> <nrc>`; the reason ends up in the log.
- Handlers may be `def` or `async def`. If yours takes longer than `p2_server_ms`,
  TestEcu emits `7F <sid> 78` automatically — you do not need to.
- If your handler raises anything else, it is logged with a traceback and turned into
  `7F <sid> 22`. The connection stays up. One bad plugin never takes the ECU down.
- Purely static data does not need a plugin at all — put it in `data_identifiers:` in
  `config.yaml`.

See [`../README.md`](../README.md) for the full guide, and
[`example_engine.py`](example_engine.py) / [`example_faults.py`](example_faults.py) for
working examples.
