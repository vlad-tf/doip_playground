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

## What you must not do

- Do not add Scapy or a UDS/diagnostics library dependency.
- Do not remove the auto-activation-on-connect behaviour.
- Do not couple this file to `test_ecu/` or `doip_edgenode/` internals via
  imports — it only ever talks to them over the wire (DoIP/TCP), matching
  the "own Docker build context" rule in `../CLAUDE.md`.
