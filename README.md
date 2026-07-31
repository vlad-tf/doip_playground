# DoIP EdgeNode — Setup & Quick Start

## What is this

A Raspberry Pi 4 sits between a PC-based tester and a real (or simulated) ECU and acts as a transparent DoIP proxy. You can inject faults, log every frame, delay or corrupt messages, and replay diagnostics — all without modifying the tester or the ECU.

This repository contains three tools:

| Component | Location | Runs on |
|---|---|---|
| **EdgeNode** | `doip_edgenode/` | Raspberry Pi 4 |
| **Echo ECU** | `echo_ecu/` | Linux machine (simulates the ECU) |
| **PC Tester** | `pc_tester/` | Windows or Linux PC |

---

## Network layout

```
PC Tester                  Raspberry Pi 4                 Echo ECU (Linux)
─────────────────────────────────────────────────────────────────────────
[10.250.250.1]             eth0  [10.250.250.11]
       │                    │
       └──── IPv4 ──────────┘
                                 eth1  [fe80::RPi%eth1]
                                  │
                                  └──── IPv6 link-local ────[fe80::ECU%eth0]
                                                             [Linux machine]

Ports used (plain DoIP, no TLS):
  TCP 13400  — diagnostic traffic (tester ↔ EdgeNode ↔ ECU)
  UDP 13400  — vehicle announcement / identification
```

---

## How sessions work

Understanding the two-stage activation avoids most configuration mistakes.

### Tester → EdgeNode (tester-facing side)

When the PC Tester connects, the EdgeNode starts a 2-second `T_TCP_Initial_Inactivity` timer (ISO 13400-2 §8). If no Routing Activation Request arrives within that window, the EdgeNode closes the connection. The PC Tester therefore sends the Routing Activation Request **automatically, immediately after TCP connect** — before showing the prompt. This matches real tester behaviour (CANoe, ETAS, etc.).

### EdgeNode → ECU (ECU-facing side)

The EdgeNode does not connect to the ECU at startup. It connects lazily — on the first Diagnostic Message from the tester. Before forwarding any diagnostic traffic it performs its own Routing Activation handshake toward the ECU, using the tester's logical address as the source (transparent proxy: the ECU sees the same address it would see from a direct tester connection). Only after the ECU responds with code `0x10` (success) does the EdgeNode forward the Diagnostic Message.

```
Tester ──RA(0x0E00)──► EdgeNode ──RA(0x0E00)──► ECU
       ◄──RA resp 0x10──          ◄──RA resp 0x10──
       ──diag(0x0E00)──►          ──diag(0x0E00)──►
       ◄──ACK + echo────          ◄──ACK + echo────
```

---

## Requirements

### Raspberry Pi 4 (EdgeNode)
- Raspberry Pi OS (Debian Bookworm or Bullseye), 64-bit recommended
- Python 3.11 or newer
- Two network interfaces: `eth0` (onboard, tester side) and `eth1` (USB-Ethernet adapter or HAT, ECU/IVN side)
- Run as root or with `CAP_NET_RAW` + `CAP_NET_BIND_SERVICE`

### Echo ECU (Linux machine)
- Any Linux machine with Python 3.9+
- One network interface connected to the RPi `eth1` network

### PC Tester
- Windows 10/11 or Linux
- Python 3.9+
- No special privileges needed

---

## 1 — Raspberry Pi setup (EdgeNode)

### 1.1 Configure network interfaces

Set `eth0` to a static IPv4 address. Edit `/etc/dhcpcd.conf` (or use NetworkManager):

```
interface eth0
static ip_address=10.250.250.11/24
```

`eth1` uses IPv6 link-local automatically — no configuration needed.
Confirm both interfaces are up after a reboot:

```bash
ip addr show eth0    # should show 10.250.250.11/24
ip addr show eth1    # should show a fe80:: address
```

If `eth1` is a USB-Ethernet adapter it may appear as `enx...` instead of `eth1`.
Update `network.ecu_interface` in `doip_edgenode/config.yaml` to match the actual name.

### 1.2 Install Python dependencies

```bash
cd doip_edgenode
sudo pip3 install -r requirements.txt --break-system-packages
```

Scapy needs the `libpcap` library. Install it if not already present:

```bash
sudo apt-get install -y libpcap-dev
```

### 1.3 Verify Scapy DoIP field names

Run this once to confirm Scapy's field names match what the EdgeNode code expects:

```bash
python3 -c "
from scapy.contrib.automotive.doip import DoIP
p = DoIP()
print('DoIP fields:')
for f in p.fields_desc:
    print(' ', f.name)
"
```

Expected field names:
- `protocol_version`
- `inverse_version`
- `payload_type`
- `payload_length`

If the printed names differ, update the constants at the top of `session.py` and `middleware/header_fault.py` before running.

### 1.4 Edit the configuration

Open `doip_edgenode/config.yaml`. The minimum you need to change:

```yaml
network:
  tester_interface: "eth0"
  tester_ipv4: "10.250.250.11"   # static IP from step 1.1
  ecu_interface: "eth1"           # update if your adapter has a different name

routing_table:
  - tester_logical_addr: 0x0E00
    ecu_logical_addr:    0x0001
    ecu_ipv6:            "fe80::XXXX:XXXX:XXXX:XXXX"   # ← ECU link-local address (see §2.1)
    ecu_interface:       "eth1"
    ecu_port_plain:      13400
    ecu_port_tls:        3496
    ecu_sni:             ""
```

Leave all other values at their defaults for the first run.

### 1.5 Start the EdgeNode

```bash
cd doip_edgenode
sudo python3 main.py --config config.yaml --log-level INFO
```

Expected output:
```
INFO  server: plain TCP listening on 10.250.250.11:13400
INFO  server: TLS TCP listening on 10.250.250.11:3496
INFO  udp_announcer: listening on 0.0.0.0:13400
INFO  udp_announcer: sent Vehicle Announcement 1/3
INFO  udp_announcer: sent Vehicle Announcement 2/3
INFO  udp_announcer: sent Vehicle Announcement 3/3
```

---

## 2 — Echo ECU setup (Linux machine)

The Echo ECU simulates a real ECU. It listens for IPv6 TCP connections from the EdgeNode, handles Routing Activation, and echoes back every UDS payload it receives. It also sends UDP Vehicle Announcements on startup.

### 2.1 Find the ECU machine's link-local IPv6 address

On the Linux ECU machine, find the IPv6 address of the interface connected to the RPi:

```bash
ip addr show eth0
```

Look for a line like:
```
inet6 fe80::a1b2:c3d4:e5f6:0001/64 scope link
```

Copy the address (`fe80::a1b2:c3d4:e5f6:0001`) — you need it in the EdgeNode `config.yaml` as `ecu_ipv6` (step 1.4).

### 2.2 Install dependencies

```bash
cd echo_ecu
pip3 install pyyaml
```

### 2.3 Edit the configuration

Open `echo_ecu/config.yaml`:

```yaml
listen:
  host:      "::"       # accept on all IPv6 interfaces
  port:      13400
  interface: "eth0"     # interface connected to RPi eth1 — update if different

doip:
  ecu_logical_addr: 0x0001   # must match ecu_logical_addr in EdgeNode routing table
```

### 2.4 Start the Echo ECU

```bash
cd echo_ecu
python3 echo_ecu.py --config config.yaml --log-level INFO
```

Expected output:
```
INFO  echo_ecu: UDP: listening on [::]::13400  interface=eth0
INFO  echo_ecu: UDP: sent Vehicle Announcement 1/3
INFO  echo_ecu: UDP: sent Vehicle Announcement 2/3
INFO  echo_ecu: UDP: sent Vehicle Announcement 3/3
INFO  echo_ecu: UDP: announcements done; listening for Vehicle Identification Requests
Echo ECU ready — listening on [::]:13400
Press Ctrl+C to stop.
```

---

## 3 — PC Tester setup

### 3.1 Install dependencies

```bash
cd pc_tester
pip install pyyaml
```

### 3.2 Edit the configuration

Open `pc_tester/config.yaml`:

```yaml
target:
  host: "10.250.250.11"   # EdgeNode eth0 IP
  port: 13400

doip:
  tester_logical_addr: 0x0E00
  ecu_logical_addr:    0x0001
```

Make sure your PC's Ethernet adapter is in the `10.250.250.x` subnet (e.g. `10.250.250.1/24`).

### 3.3 Run the tester

```bash
cd pc_tester
python3 tester.py
```

The tester **automatically sends a Routing Activation Request immediately after TCP connect**, before showing the interactive prompt. You will see the activation result printed, then the `doip>` prompt:

```
Connected to 10.250.250.11:13400
  → Routing Activation Request  src=0x0E00
  ← Routing Activation Response  (0x0006)  13 bytes payload
       response code: 0x10 — Successfully activated

Type 'help' for commands.

doip>
```

This is intentional: the EdgeNode's `T_TCP_Initial_Inactivity` timer (2 seconds, ISO 13400-2 §8) closes the connection if no Routing Activation Request arrives in time. Auto-activation ensures the handshake completes before you type anything.

If activation fails (wrong logical address, connection refused, etc.), the tester prints the error and exits cleanly rather than leaving you with a broken session.

To suppress auto-activation — for example, to deliberately test the inactivity timer:

```bash
python3 tester.py --no-auto-activate
# You then have ~2 seconds to type 'activate' before the EdgeNode closes the connection
```

---

## 4 — First test walkthrough

Start components in this order: **Echo ECU → EdgeNode → PC Tester**

**Connect (activation is automatic)**
```
$ python3 tester.py

Connected to 10.250.250.11:13400
  → Routing Activation Request  src=0x0E00
  ← Routing Activation Response  (0x0006)  13 bytes payload
       response code: 0x10 — Successfully activated

Type 'help' for commands.

doip>
```

At this point, behind the scenes the EdgeNode has also performed its own Routing Activation toward the Echo ECU (on the first Diagnostic Message — see below).

**Send a diagnostic message**
```
doip> diag 10 01
  → Diagnostic Message  src=0x0E00  tgt=0x0001  UDS: 10 01
  ← Diagnostic Message Positive ACK  (0x8002)
       src=0x0E00  tgt=0x0001  ack_code=0x00
  ← Diagnostic Message  (0x8001)
       src=0x0001  tgt=0x0E00
       UDS: 10 01
```

On the first `diag`, the EdgeNode connects to the Echo ECU and runs its own Routing Activation handshake. You will see this in the EdgeNode log:

```
INFO  ecu_client: ECUConnection: connecting to [fe80::...%eth1]:13400
INFO  ecu_client: ECUConnection: Routing Activation successful (ECU src=0x0E00)
```

Subsequent diagnostics reuse the existing ECU connection — no reconnection overhead.

**Check entity status**
```
doip> status
  → Entity Status Request
  ← Entity Status Response  (0x4002)
       node_type=0x01  max_sockets=1  open=1  max_data=4096
```

**Alive check**
```
doip> alive
  → Alive Check Request
  ← Alive Check Response
       (alive)
```

**Quit**
```
doip> quit
```

---

## 5 — Fault injection

Fault injection is configured in `doip_edgenode/config.yaml` under the `middleware:` section. Enable a middleware by setting `enabled: true` and restarting the EdgeNode.

**Drop 30% of tester→ECU diagnostic messages:**
```yaml
- type: DropMiddleware
  enabled: true
  drop_rate: 0.3
  match:
    direction: "tester_to_ecu"
```

**Add 200 ms ± 50 ms delay to all messages:**
```yaml
- type: DelayMiddleware
  enabled: true
  delay_ms: 200
  jitter_ms: 50
```

**Inject a bad DoIP header on every 5th message:**
```yaml
- type: HeaderFaultMiddleware
  enabled: true
  fault: "wrong_version"
  direction: "tester_to_ecu"
  inject_on_nth: 5
```

Available `HeaderFaultMiddleware` fault modes:

| `fault` value | What it corrupts | Expected peer reaction |
|---|---|---|
| `wrong_version` | Protocol version byte → `0xFF` | Header NACK `0x00` |
| `bad_inverse` | Inverse version byte → `0x00` | Header NACK `0x00` |
| `bad_length` | Payload length → `0xFFFFFFFF` | Header NACK `0x02` or drop |
| `unknown_type` | Payload type → `0xDEAD` | Header NACK `0x01` |

---

## 6 — Logs

The EdgeNode writes a frame-level log to `doip_edgenode/logs/doip.log` (configured by `LoggerMiddleware` in `config.yaml`). Each entry includes timestamp, direction, payload type, length, and a full hex dump.

```bash
tail -f doip_edgenode/logs/doip.log
```

Use `--log-level DEBUG` for timer events, middleware decisions, and ECU connection detail.

---

## 7 — Running the unit tests

No hardware or root required. Run from the `doip_edgenode/` directory:

```bash
cd doip_edgenode
pip3 install pytest pytest-asyncio --break-system-packages   # first time only
pytest tests/test_middleware.py -v                            # no Scapy needed
pytest tests/test_session.py -v                              # Scapy required
```

---

## 8 — Minimal test without ECU hardware

If you only have the Raspberry Pi, use the built-in `mock_ecu.py` for a loopback test. The mock ECU handles Routing Activation and echoes Diagnostic Messages, so the full EdgeNode session lifecycle can be exercised on one machine.

```bash
# Terminal 1 — start the mock ECU on loopback port 13401
cd doip_edgenode
python3 -c "
import asyncio
from tests.mock_ecu import MockECU

async def main():
    ecu = MockECU(host='127.0.0.1', port=13401)
    await ecu.start()
    print('Mock ECU on 127.0.0.1:13401 — Ctrl+C to stop')
    await asyncio.Event().wait()

asyncio.run(main())
"

# In config.yaml, point the routing table at loopback:
#   ecu_ipv6:        "::1"
#   ecu_interface:   "lo"
#   ecu_port_plain:  13401

# Terminal 2 — start the EdgeNode
cd doip_edgenode
sudo python3 main.py --config config.yaml --log-level DEBUG

# Terminal 3 — run the tester
cd pc_tester
# config.yaml: host = 10.250.250.11 (or 127.0.0.1 if tester is also on the RPi)
python3 tester.py
```

---

## 9 — Troubleshooting

**"Could not connect" from the PC Tester**
- Confirm the PC is in the `10.250.250.x` subnet and can `ping 10.250.250.11`
- Check the EdgeNode is running: `ss -tlnp | grep 13400` on the RPi
- Check no firewall is blocking port 13400: `sudo ufw status`

**Routing Activation denied (code 0x00 — unknown source address)**
- `tester_logical_addr` in the EdgeNode `config.yaml` routing table must match what the tester sends (default `0x0E00`)

**`T_TCP_Initial_Inactivity` fires before activation**
- This means the Routing Activation Request arrived more than 2 seconds after TCP connect
- With the auto-activating tester (`tester.py`) this should not happen
- If using a different tester tool, check its connection settings or increase `t_tcp_initial_inactivity_s` in `config.yaml` for development

**Diagnostic Message NACK code 0x03 (target unreachable / unknown target address)**
- The EdgeNode could not connect to the ECU, or the ECU-facing Routing Activation failed
- Check the Echo ECU is running: `ss -tlnp | grep 13400` on the ECU machine
- Verify `ecu_ipv6` in the routing table matches the ECU machine's actual link-local address (§2.1)
- Test connectivity from the RPi: `ping6 fe80::XXXX%eth1`
- Check `ecu_interface` in the routing table matches the RPi's interface name exactly

**Echo ECU log shows "Diagnostic Message before activation — ignoring"**
- The EdgeNode is not sending a Routing Activation Request to the ECU before forwarding diagnostics
- Ensure you are running the latest `ecu_client.py` which performs the ECU-facing RA in `_do_routing_activation()`

**"No module named scapy"**
```bash
sudo pip3 install scapy --break-system-packages
```

**"No module named yaml"**
```bash
pip3 install pyyaml          # PC or ECU machine
sudo pip3 install pyyaml --break-system-packages   # Raspberry Pi
```

**Wireshark shows Vehicle Announcement payload error**
- Ensure you are running the latest `udp_announcer.py` which includes the 2-byte logical address field (ISO 13400-2 Table 24). Correct payload is 33 bytes; older versions produced 31 bytes.

**DoIP field name mismatch (faults not injecting)**
- Run the Scapy field name check in §1.3 and update the constants in `session.py` and `middleware/header_fault.py`

**TLS port 3496**
- TLS server-side handshake is not yet implemented (PoC). Port 3496 accepts connections but treats them as plaintext. Do not use until the TLS bridge is fully wired up.

---

## 10 — Known limitations (PoC)

| Limitation | Notes |
|---|---|
| Single tester connection at a time | Second connection is rejected immediately |
| TLS handshake not implemented | Port 3496 accepts but does not negotiate TLS |
| No certificate revocation (CRL/OCSP) | Planned for post-PoC |
| Config reload requires restart | No SIGHUP hot-reload |
| TLS fault injection is a placeholder | `TLSFaultMiddleware` passes through unchanged |

## License

This project is licensed under the Apache License, Version 2.0.
See the [LICENSE](./LICENSE) file for details.

Copyright © 2026 Vladislav Vostrykh, Technica Engineering GmbH. All rights reserved under the terms of the license above.
