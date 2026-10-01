# DoIP EdgeNode

A DoIP (ISO 13400-2) proxy that sits between a tester and an ECU so you can log,
delay, drop, or corrupt diagnostic traffic in flight — without touching the tester
or the ECU. This repo has four pieces: the **EdgeNode** (the proxy itself), two ECU
simulators (**Echo ECU** — fixed canned answers, and **TestEcu** — real UDS with
pluggable business logic), and a **PC Tester** REPL for driving diagnostic sessions.

```
PC Tester  ───►  EdgeNode  ───►  ECU (Echo ECU or TestEcu)
```

There are two ways to run it. Docker is the fast path and is what most people
want. Bare metal (a Raspberry Pi as the EdgeNode, talking to a separate ECU
machine over a real link) is for when you need the actual hardware topology.

---

## Quick start — Docker

```bash
git clone https://github.com/vlad-tf/doip_playground.git "DoIP EdgeNode"
cd "DoIP EdgeNode"
docker compose up --build -d          # builds and starts EdgeNode + EchoNode + a tester
docker attach doip-pc-tester           # drop into the tester REPL
```

Inside the REPL:

```
doip> diag 10 01
```

Detach without killing the tester with `Ctrl-P Ctrl-Q`. Stop everything with
`docker compose down`.

That's the whole quick start. For the network topology, running TestEcu instead of
(or alongside) the Echo ECU, loading your own TestEcu plugins, and attaching your
own test project to the Docker networks, see **[`docker/README.md`](docker/README.md)**.

---

## Running on real hardware (multiple PCs / Raspberry Pi)

Docker simulates the topology on one machine with virtual networks. On real
hardware the same roles are split across physical boxes — typically because you
want the EdgeNode on an actual Raspberry Pi sitting on a real in-vehicle network
link, with the tester and ECU as separate machines either side of it:

```
PC Tester (IPv4)  ───────►  Raspberry Pi 4 "EdgeNode"  ───────►  ECU machine (IPv6 link-local)
   eth0 side                  eth0 (tester) / eth1 (ECU)           eth0
```

This path is more involved: static IPv4 on the tester-facing interface, IPv6
link-local addressing on the ECU-facing interface (with explicit scope IDs), root
or capability-based privileges on the Pi for raw sockets, and a one-time check that
Scapy's DoIP field names match what the code expects. It is the same four
components as the Docker setup — just installed with `pip` on three separate
machines and wired to real interfaces instead of Docker networks.

Full step-by-step instructions (network config, per-machine installs, fault
injection, troubleshooting) are in
**[`RASPBERRY_PI_SETUP.md`](RASPBERRY_PI_SETUP.md)**.

---

## Repo layout

| Component | Dir | Status | Docs |
|---|---|---|---|
| EdgeNode | `doip_edgenode/` | Implemented (PoC), Scapy-based | [`doip_edgenode/CLAUDE.md`](doip_edgenode/CLAUDE.md) |
| Echo ECU | `echo_ecu/` | Frozen — fixed canned answers | [`echo_ecu/CLAUDE.md`](echo_ecu/CLAUDE.md) |
| TestEcu | `test_ecu/` | Active — pluggable UDS logic | [`test_ecu/README.md`](test_ecu/README.md) |
| PC Tester | `pc_tester/` | Implemented (PoC) | [`pc_tester/CLAUDE.md`](pc_tester/CLAUDE.md) |

**Echo ECU or TestEcu?** Echo ECU answers every UDS request with a canned echo and
one hardcoded VIN — use it when you just need something on the far end of the wire.
TestEcu speaks real UDS (sessions, security access, negative response codes) and
lets you supply the business logic as YAML data identifiers, Python plugins, or
both — use it when the tester under test actually cares what the ECU says.

The full protocol/behaviour spec is
[`doip_edgenode_requirements.md`](doip_edgenode_requirements.md).
Known PoC limitations (single tester connection, no TLS handshake, etc.) are
listed at the end of [`RASPBERRY_PI_SETUP.md`](RASPBERRY_PI_SETUP.md#10--known-limitations-poc)
and apply to both the Docker and bare-metal setups.

---

## License

This project is licensed under the Apache License, Version 2.0.
See the [LICENSE](./LICENSE) file for details.

Copyright © 2026 Vladislav Vostrykh, Technica Engineering GmbH. All rights reserved under the terms of the license above.
