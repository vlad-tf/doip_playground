# DoIP EdgeNode — Repo Guide for Code Agents

This repo is four independent Python components that talk DoIP/UDS to each other.
Each one is its own Docker build context and its own dependency set — **do not**
assume something true in one applies to another. Before touching a file, read the
`CLAUDE.md` in that component's directory; it has the conventions that actually
apply there. This file only covers what is shared or what you need to know before
picking a component.

| Component | Dir | CLAUDE.md | Status |
|---|---|---|---|
| EdgeNode | `doip_edgenode/` | [`doip_edgenode/CLAUDE.md`](doip_edgenode/CLAUDE.md) | Implemented (PoC), Scapy-based |
| Echo ECU | `echo_ecu/` | [`echo_ecu/CLAUDE.md`](echo_ecu/CLAUDE.md) | Frozen — do not modify casually |
| TestEcu | `test_ecu/` | [`test_ecu/CLAUDE.md`](test_ecu/CLAUDE.md) | Active, actively extended |
| PC Tester | `pc_tester/` | [`pc_tester/CLAUDE.md`](pc_tester/CLAUDE.md) | Implemented (PoC) |

The full protocol/behaviour spec for the whole system is
[`doip_edgenode_requirements.md`](doip_edgenode_requirements.md) and the top-level
[`README.md`](README.md). Read those for *what the system does*; the per-component
`CLAUDE.md` files are for *how to write code in that directory*.

---

## Why per-component instructions, not one shared style

EdgeNode and TestEcu were built at different times with different goals and
**do not share a coding style on purpose**:

- **EdgeNode** (`doip_edgenode/`) was generated from a single big implementation
  prompt (phase-by-phase, "build this from scratch"). It depends on Scapy for
  packet framing and TLS, has no license headers, and its own docstring style.
- **TestEcu** (`test_ecu/`) was built later as a hand-designed plugin
  architecture (hook precedence ladder, typed config, Apache-2.0 license
  headers, zero dependencies beyond PyYAML, no Scapy). It is the style to
  imitate for **new** components in this repo.
- **Echo ECU** (`echo_ecu/`) predates both and is deliberately frozen: TestEcu's
  DoIP framing is a verified byte-for-byte port of it
  (`test_ecu/tests/test_doip_parity.py`), so changing `echo_ecu/echo_ecu.py`
  risks breaking that guarantee silently.

**Rule of thumb:** when adding a new component or a substantial new module,
follow the TestEcu conventions (typed config + `ConfigError`, license header,
dependency-light, precedence-ladder-style dispatch, README with a "Quick
start"). When fixing a bug inside an existing component, match *that
component's* existing style, not TestEcu's — do not silently reformat
`doip_edgenode/` files to TestEcu conventions as a side effect of a bug fix.

---

## Cross-component invariants (do not break these silently)

- **DoIP framing must round-trip identically across `echo_ecu/`,
  `test_ecu/testecu/doip.py`, and `doip_edgenode/`**: version `0x02`/inverse
  `0xFD`, 8-byte header, big-endian payload length. `test_ecu`'s parity test
  is the only thing enforcing this for TestEcu vs Echo ECU — there is no
  equivalent check against `doip_edgenode/session.py`.
- **Logical addresses / Docker network layout** are documented in
  [`docker/README.md`](docker/README.md) — EchoNode is `0x0001`, TestEcu is
  `0x0002`. If you add a new simulated ECU, give it its own logical address and
  update that table, `docker-compose.yml`, and `docker/edgenode.config.yaml`.
- **IPv6 link-local requires an explicit scope id everywhere** (`eth1`,
  `%eth1`, `socket.if_nametoindex`). Do not "simplify" this away — it is
  mandatory for `AF_INET6` connect on link-local addresses.
- **TLS on port 3496 is not implemented anywhere in this repo.** All four
  components either skip it or treat it as a placeholder. Do not assume any
  component can be used as a working TLS reference for another.

## Shared testing convention

None of the four components use `pytest-asyncio`. Async tests are driven
through a small `run(coro)` helper (new event loop, run to completion, drain
stray tasks) defined once per test suite
(`test_ecu/tests/conftest.py:run`, mirrored by `doip_edgenode/tests/test_middleware.py`).
Keep using this pattern rather than adding `pytest-asyncio` as a dependency —
it is a deliberate choice to keep `pip install pytest` sufficient.

## License headers

`test_ecu/` files carry an Apache-2.0 header (see any file under
`test_ecu/testecu/`). `doip_edgenode/`, `echo_ecu/`, and `pc_tester/` do not.
Match whichever convention the file you are editing already uses; do not add
headers to `doip_edgenode/`/`echo_ecu/`/`pc_tester/` files as a drive-by change.
