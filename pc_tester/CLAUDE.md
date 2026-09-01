# PC Tester — Code Agent Instructions

## Scope

This file governs `pc_tester/` only — a single-file (`tester.py`), stdlib-only
interactive DoIP client used to exercise EdgeNode/TestEcu/Echo ECU manually.
See `../CLAUDE.md` for why this differs from `test_ecu/`.

## Conventions

- Pure Python stdlib only (`asyncio`, `struct`) plus `pyyaml` for config — no
  Scapy, no third-party DoIP/UDS libraries. Keep it dependency-light; this is
  meant to run on a plain Windows or Linux PC with no setup beyond
  `pip install pyyaml`.
- License header at the top of `tester.py` (see `../CLAUDE.md` — it's a
  repo-wide rule); already present, keep it when editing.
- Mirrors DoIP constant names and NACK/response code tables from
  `echo_ecu/echo_ecu.py` (`PT_*`, `RA_RESPONSE_CODES`, `DIAG_NACK_CODES`) —
  keep new payload types/response codes consistent with those tables rather
  than inventing a different naming scheme.
- Sends the Routing Activation Request **automatically, immediately after TCP
  connect**, before showing the prompt — this matches real tester tools
  (CANoe, ETAS) and is required so EdgeNode's
  `T_TCP_Initial_Inactivity` timer doesn't fire. Do not make this a manual
  step in the default flow (an explicit `activate` command exists for
  re-activation, but the auto-activation on connect must stay).
- Interactive REPL commands (`activate`, `diag`, `alive`, `status`, `power`,
  `help`, `quit`) are documented in the module docstring — update it if you
  add or change a command.
- **Background reader task is mandatory, not optional.** `DoIPTester` runs a
  `_background_reader` task (started in `connect()`) that reads continuously
  from the socket and auto-replies to unsolicited Alive Check Requests
  (`PT_ALIVE_CHECK_REQUEST`) with the tester's logical address as payload.
  Everything else is placed on `_recv_queue`; the REPL's `_recv()` reads from
  that queue, never from the socket directly. Do not revert to a
  synchronous "REPL blocks on `input()`, then reads the socket" model — the
  EdgeNode sends an unsolicited Alive Check to probe this tester's liveness
  whenever a second tester tries to activate the same SA (see
  `doip_edgenode/CLAUDE.md`'s SA-conflict section), and if nothing is reading
  the socket while the REPL waits on `input()`, the probe times out and the
  EdgeNode wrongly evicts this (still-alive) session.
- Alive Check Response payload (both the auto-reply above and `cmd_alive`'s
  expected response) carries a 2-byte logical address, per ISO 13400-2 Table
  22 — `_print_response` decodes and displays it; don't treat it as an empty
  payload.

## What you must not do

- Do not add Scapy or a UDS/diagnostics library dependency.
- Do not remove the auto-activation-on-connect behaviour.
- Do not remove or bypass `_background_reader` / `_recv_queue` — see above;
  this is what lets the tester answer unsolicited Alive Check probes while
  the REPL is blocked on `input()`.
- Do not couple this file to `test_ecu/` or `doip_edgenode/` internals via
  imports — it only ever talks to them over the wire (DoIP/TCP), matching
  the "own Docker build context" rule in `../CLAUDE.md`.
