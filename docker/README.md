# DoIP stack in Docker

Runs the three components in two isolated networks:

```
                 doip_frontend (IPv4)            doip_backend (IPv6)
 PC-Tester  ───────────────────────────►  EdgeNode  ───────────────────────►  EchoNode
 172.30.100.20                            172.30.100.10        fd2e:646f:6970::10 / ::2
```

| Component | Container | Frontend (IPv4) | Backend (IPv6) | Ports |
|---|---|---|---|---|
| EdgeNode | `doip-edgenode` | `172.30.100.10` (eth0) | `fd2e:646f:6970::10` (eth1) | 13400/tcp, 3496/tcp, 13400/udp |
| EchoNode | `doip-echonode` | — | `fd2e:646f:6970::2` | 13400/tcp, 13400/udp |
| PC-Tester | `doip-pc-tester` | `172.30.100.20` | — | — |

The tester talks DoIP plain (TCP 13400) to the EdgeNode over IPv4. The EdgeNode
proxies to the EchoNode over IPv6. TLS (3496) is exposed but not yet negotiated
(PoC — see the repo README §10).

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
