# Raspberry Pi Verification Plan

Run every step in order on the Raspberry Pi 4 before declaring the
implementation complete.  Steps 1–4 are mandatory inspection steps that
may require code changes.  Steps 5–10 are runtime checks.

---

## 1. Install dependencies

```bash
cd ~/doip_edgenode
pip3 install -r requirements.txt
# Also install pytest-asyncio for async tests:
pip3 install pytest-asyncio
```

---

## 2. Verify Scapy DoIP field names  ← CRITICAL

Run:
```bash
python3 -c "
from scapy.contrib.automotive.doip import DoIP
p = DoIP()
print('=== fields_desc ===')
for f in p.fields_desc:
    print(f'  {f.name!r}  type={type(f).__name__}')
print()
p.show()
"
```

**Expected field names** (assumed in this implementation):

| Role             | Assumed name | Actual name           |
|------------------|-------------|----------------------|
| version byte     | `ver`        | ✅ `protocol_version` |
| inverse byte     | `inv_ver`    | ✅ `inverse_version`  |
| payload type     | `type`       | ✅ `payload_type`     |
| payload length   | `len`        | ✅ `payload_length`   |

**All constants updated in code. Step complete.**

If any name differs from the assumed name, update the following
constants in each affected file:

| File                              | Constant                     |
|-----------------------------------|------------------------------|
| `session.py`                      | `_VER_FIELD`, `_INV_VER_FIELD`, `_TYPE_FIELD`, `_LEN_FIELD` |
| `middleware/header_fault.py`      | `_VER_FIELD`, `_INV_VER_FIELD`, `_TYPE_FIELD`, `_LEN_FIELD` |
| `middleware/logger.py`            | `_DOIP_TYPE_FIELD`, `_DOIP_LEN_FIELD` |
| `middleware/drop.py`              | `_DOIP_TYPE_FIELD`           |
| `middleware/corrupt.py`           | (no field name constants — uses raw bytes) |
| `middleware/address.py`           | `_SRC_FIELD`, `_TGT_FIELD`  |

Also update the comment block at the top of `session.py`.

---

## 3. Verify Scapy TLS automaton API  ← CRITICAL for TLS port

```bash
python3 -c "
from scapy.layers.tls.automaton_srv import TLSServerAutomaton
from scapy.layers.tls.automaton_cli import TLSClientAutomaton
import inspect
print('=== TLSServerAutomaton.__init__ ===')
print(inspect.signature(TLSServerAutomaton.__init__))
print()
print('=== TLSClientAutomaton.__init__ ===')
print(inspect.signature(TLSClientAutomaton.__init__))
"
```

Update `tls_bridge._build_server_kwargs()` and
`tls_bridge._build_client_kwargs()` to match the actual parameter names.

Key parameters to identify:
- Certificate path parameter (`mycert`, `server_certs`, or similar)
- Private key parameter (`mykey`, `server_key`, or similar)
- Client auth / mTLS parameter (`client_auth`, `require_client_certificate`, etc.)
- TLS version constraint parameter (`tls_version`, `version`, etc.)
- SNI parameter (`server_name`, `sni`, etc.)

---

## 4. Verify Scapy version

```bash
python3 -c "import scapy; print(scapy.__version__)"
```

If version is **2.6.x**, also check for API changes in:
- `TLSServerAutomaton` / `TLSClientAutomaton` constructor
- `scapy.layers.tls.cert.Cert` / `PrivKey` class names

---

## 5. Verify network interfaces

```bash
ip link show
```

Confirm `eth0` (tester-facing) and `eth1` (ECU-facing) exist.
If they have different names (e.g., `enp3s0`), update `config.yaml`:

```yaml
network:
  tester_interface: "eth0"   # update if needed
  ecu_interface:   "eth1"    # update if needed
```

Also verify the IPv6 link-local address on `eth1`:
```bash
ip -6 addr show eth1
# Should show fe80::... address
```

---

## 6. Phase 1 smoke test

```bash
cd ~/doip_edgenode
python3 verify_config.py
```

Expected output:
```
Loaded config OK
  VIN       : 1HGBH41JXMN109186
  ...
Routing table:
  tester 0x0E00 -> ECU 0x0001  [fe80::1%eth1]  plain=13400  tls=3496  sni=''
```

---

## 7. Middleware unit tests

```bash
cd ~/doip_edgenode
pytest tests/test_middleware.py -v
```

All tests should pass without root.  If any fail due to changed Scapy
field names, apply fixes from Step 2 first.

---

## 8. Session integration tests

```bash
pytest tests/test_session.py -v
```

These tests use real Scapy packets over loopback.  They do **not** require
root or raw sockets.

If `T_TCP_Initial_Inactivity` test is flaky, increase the timer tolerance
(the test uses 0.3 s; the Pi may need 0.5 s).

---

## 9. UDP announcement verification

Start the EdgeNode:
```bash
sudo python3 main.py --log-level DEBUG
```

On a second terminal, capture UDP traffic:
```bash
sudo tcpdump -i eth0 udp port 13400 -n -X
```

Expected: 3 UDP packets from `192.168.1.1:13400` to `255.255.255.255:13400`
within the first second of startup.

---

## 10. End-to-end DoIP session

With a DoIP-capable tester (or a second Python script using raw sockets):

```bash
# Connect to plain port, send RA request, send a diagnostic message
python3 -c "
import socket, struct, time

VER = 0x02
INV = 0xFF ^ VER

def frame(ptype, payload):
    return struct.pack('!BBHI', VER, INV, ptype, len(payload)) + payload

s = socket.create_connection(('192.168.1.1', 13400))

# Routing Activation Request
ra = frame(0x0005, struct.pack('!H', 0x0E00) + bytes([0x00]) + b'\x00'*4)
s.sendall(ra)
resp = s.recv(1024)
print('RA response type:', hex(struct.unpack('!H', resp[2:4])[0]))
print('RA response code:', hex(resp[12]))   # byte 12 = response code

# Diagnostic Message
diag = frame(0x8001, struct.pack('!HH', 0x0E00, 0x0001) + b'\x10\x01')
s.sendall(diag)
time.sleep(0.5)
resp = s.recv(1024)
print('Diag response type:', hex(struct.unpack('!H', resp[2:4])[0]))
s.close()
"
```

Expected:
- RA response type: `0x6` (Routing Activation Response)
- RA response code: `0x10` (success)
- Diag response type: `0x8002` (Positive ACK) or `0x8003` (NACK with code 0x03 = ECU unreachable if no real ECU)

---

## 11. HeaderFaultMiddleware verification

Edit `config.yaml` to enable:
```yaml
  - type: HeaderFaultMiddleware
    enabled: true
    fault: "wrong_version"
    direction: "tester_to_ecu"
    inject_on_nth: 1
```

Restart EdgeNode and send a Diagnostic Message from the tester.
The ECU (or MockECU) should receive a frame with `ver=0xFF` and
respond with a Header NACK `0x00`.

Check logs:
```
WARNING ... HeaderFaultMiddleware: injecting fault=wrong_version dir=tester_to_ecu
```

---

## Address field fix checklist

After running Step 2, if `address.py` field names need updating:

```bash
python3 -c "
from scapy.contrib.automotive.doip import DoIP
# Find what Scapy calls the Diagnostic Message sub-layer
from scapy.contrib.automotive.doip import DoIPRoutingActivationRequest
# or look for DiagnosticMessage class:
import scapy.contrib.automotive.doip as dm
print(dir(dm))
"
```

The source/target logical address fields may be on a sub-layer
(e.g., `DiagnosticMessage`) or directly on `DoIP` — depends on
the Scapy version's modelling choices.

---

## Known issues to address before production

1. **TLS server handshake** (`server.py:_do_tls_handshake`): currently
   a placeholder that accepts port 3496 as plaintext.  Full TLS
   integration requires creating the raw socket server manually
   and passing the accepted socket into `TLSBridge`.

2. **Scapy DoIP field names**: update constants after Pi verification.

3. **TLS automaton kwargs**: update `_build_server_kwargs` /
   `_build_client_kwargs` after Step 3 above.

4. **Address middleware field names**: verify sub-layer field names for
   source/target logical address in Diagnostic Messages.
