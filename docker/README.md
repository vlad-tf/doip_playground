# DoIP stack in Docker

Runs the four components in two isolated networks:

```
                 doip_frontend (IPv4)            doip_backend (IPv6)
 PC-Tester  ───────────────────────────►  EdgeNode  ─────┬─────────────────►  EchoNode
 172.30.100.20                            172.30.100.10  │   fd2e:646f:6970::10 / ::2
                                                         └─────────────────►  TestEcu
                                                                     fd2e:646f:6970::3
```

| Component | Container | Frontend (IPv4) | Backend (IPv6) | Logical addr | Ports |
|---|---|---|---|---|---|
| EdgeNode | `doip-edgenode` | `172.30.100.10` (eth0) | `fd2e:646f:6970::10` (eth1) | — | 13400/tcp, 3496/tcp, 13400/udp |
| EchoNode | `doip-echonode` | — | `fd2e:646f:6970::2` | `0x0001` | 13400/tcp, 13400/udp |
| TestEcu | `doip-testecu` | — | `fd2e:646f:6970::3` | `0x0002` | 13400/tcp, 13400/udp |
| PC-Tester | `doip-pc-tester` | `172.30.100.20` | — | — | — |

The tester talks DoIP plain (TCP 13400) to the EdgeNode over IPv4. The EdgeNode
proxies to a backend ECU over IPv6. TLS (3496) is exposed but not yet negotiated
(PoC — see the repo README §10).

**Which ECU you reach is decided by the tester logical address.** The EdgeNode resolves
routes with `lookup_by_tester_addr()` and takes the first match, so each backend ECU has
its own tester SA in `docker/edgenode.config.yaml`:

| Activate with SA | Reaches | ECU logical addr |
|---|---|---|
| `0x0E00` | `doip-echonode` | `0x0001` |
| `0x0E01` | `doip-testecu` | `0x0002` |

To point the bundled tester at TestEcu, set both lines in `docker/pctester.config.yaml`
to `tester_logical_addr: 0x0E01` / `ecu_logical_addr: 0x0002` and
`docker compose restart doip-pc-tester`.

## Address ranges (chosen to avoid overlap)

Picked to stay clear of the real bench nets (`10.250.250.0/24`, `192.168.1.0/24`)
and Docker's default bridge (`172.17.0.0/16`):

- `doip_frontend` — `172.30.100.0/24`
- `doip_backend`  — `fd2e:646f:6970::/64` (IPv6 ULA) plus `172.30.101.0/24` (auxiliary; DoIP traffic here is IPv6-only)

To change a range, edit `docker-compose.yml` **and** the matching addresses in
`docker/edgenode.config.yaml` and `docker/pctester.config.yaml`.

## Requirements

Docker Engine 27+ (for user-defined IPv6 networks out of the box). On older
daemons, enable IPv6 in `/etc/docker/daemon.json`:

```json
{ "experimental": true, "ip6tables": true }
```

## Run

```bash
docker compose up --build -d          # start Echo + Edge (+ tester)
docker compose logs -f doip-edgenode  # watch the proxy
```

Interact with the tester REPL:

```bash
docker attach doip-pc-tester
# doip> diag 10 01
# doip> status
# (Ctrl-P Ctrl-Q to detach without killing it)
```

Or run a throwaway tester instead of the bundled one:

```bash
docker compose run --rm doip-pc-tester
```

Stop:

```bash
docker compose down
```

## Loading your own plugins into TestEcu

`doip-testecu` mounts a plugin directory read-only at `/app/plugins` and loads every
`*.py` in it at startup (sorted, files starting with `_` skipped). No rebuild is needed
— drop a file in and restart the container:

```bash
cp my_ecu.py test_ecu/plugins/
docker compose restart doip-testecu
docker compose logs doip-testecu | head -20     # the resolved hook table is at INFO
```

To use a plugin directory outside this repo, repoint the volume in `docker-compose.yml`:

```yaml
  doip-testecu:
    volumes:
      - ./docker/testecu.config.yaml:/app/config.yaml:ro
      - /path/to/my_plugins:/app/plugins:ro
```

A plugin that fails to import is logged with a full traceback and skipped — the ECU
still starts and still serves everything else. Set `plugins.strict: true` in
`docker/testecu.config.yaml` if you would rather the container refuse to start.

`docker/testecu.config.yaml` also holds the static `data_identifiers:` table, so simple
canned values need no Python at all. See [`../test_ecu/README.md`](../test_ecu/README.md).

## Running your DoIP Tests project against this stack

The two networks have fixed names (`doip_frontend`, `doip_backend`), so any
other container or compose project can attach to them.

### Option A — your tests act as the tester (IPv4, most common)

In your DoIP Tests `docker-compose.yml`:

```yaml
services:
  doip-tests:
    build: .
    networks:
      - doip_frontend
    # reach the EdgeNode by IP or by name:
    #   host = 172.30.100.10   (or "doip-edgenode")
    #   port = 13400

networks:
  doip_frontend:
    external: true
    name: doip_frontend
```

### Option B — tests also need the EchoNode directly (IPv6)

Attach to the backend as well:

```yaml
services:
  doip-tests:
    build: .
    networks:
      - doip_frontend
      - doip_backend
    # EchoNode:  [fd2e:646f:6970::2]:13400  (or "doip-echonode")

networks:
  doip_frontend:
    external: true
    name: doip_frontend
  doip_backend:
    external: true
    name: doip_backend
```

### Option C — one-off `docker run`

```bash
docker run --rm -it --network doip_frontend your-doip-tests \
    pytest --edge-host 172.30.100.10 --edge-port 13400
```

Containers on the same network resolve each other by container name
(`doip-edgenode`, `doip-echonode`) via Docker's embedded DNS, so you can use
names instead of hardcoded IPs.

> Start this stack first (`docker compose up`) so the networks exist before the
> tests project references them as `external`.

## Notes

- The EdgeNode is single-session (PoC): only one tester connection at a time.
  Don't leave the bundled tester attached while running your test suite against
  the same EdgeNode.
- EdgeNode frame logs are written to `docker/logs/doip.log` on the host.
- `priority` on the EdgeNode networks pins the tester side to `eth0` and the ECU
  side to `eth1`, matching `ecu_interface: eth1` in `edgenode.config.yaml`.
- Both ECUs send UDP Vehicle Announcements to `ff02::1` on the backend network, so a
  tester doing vehicle discovery there will see two entities (`0x0001` and `0x0002`).
- `doip-echonode` and `doip-testecu` are independent: stopping one does not affect the
  other, and TestEcu changes never touch `echo_ecu/`.
