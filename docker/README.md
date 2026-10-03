# DoIP stack in Docker

Runs the four components in two isolated networks:

```
                 doip_frontend (IPv4)            doip_backend (IPv6)
 PC-Tester  ───────────────────────────►  EdgeNode  ─────┬─────────────────►  EchoNode
 172.30.100.20                            172.30.100.10  │   fd2e:646f:6970::2
                                      fd2e:646f:6970::10  └─────────────────►  TestEcu
                                                                     fd2e:646f:6970::3
```

| Component | Container | Frontend (IPv4) | Backend (IPv6) | Logical addr | Ports |
|---|---|---|---|---|---|
| EdgeNode | `doip-edgenode` | `172.30.100.10` (eth0) | `fd2e:646f:6970::10` (eth1) | `0x1234` | 13400/tcp, 3496/tcp, 13400/udp |
| EchoNode | `doip-echonode` | — | `fd2e:646f:6970::2` | `0x0002` | 13400/tcp, 13400/udp |
| TestEcu | `doip-testecu` | — | `fd2e:646f:6970::3` | `0x0003` | 13400/tcp, 13400/udp |
| PC-Tester | `doip-pc-tester` | `172.30.100.20` | — | — | — |

ECU logical addresses match each node's IPv6 suffix (`::2` → `0x0002`, `::3`
→ `0x0003`) for easy cross-reference; EdgeNode's own address (`0x1234`) is
unrelated to its IP and is just a high value in the VM-specific range, kept
clear of the ECUs and the tester range (`0x0E00`-`0x0FFF`). `0x0000` is never
used — ISO/SAE reserved (ISO 13400-2), rejected by EdgeNode's config loader.

The tester talks DoIP plain (TCP 13400) to the EdgeNode over IPv4. The EdgeNode
proxies to a backend ECU over IPv6. TLS (3496) is exposed but not yet negotiated
(PoC — see the repo README §10).

**Which ECU you reach is decided by the Diagnostic Message's own target address**,
not by the activated tester SA. The EdgeNode resolves routes with
`lookup_by_ecu_addr()` against `docker/edgenode.config.yaml`'s `routing_table`
(one entry per physical ECU) and takes the first match:

| Diag target address | Reaches |
|---|---|
| `0x0002` | `doip-echonode` |
| `0x0003` | `doip-testecu` |

Any tester SA the EdgeNode accepts (`doip.tester_addr_range`/`tester_addr_list`
in `edgenode.config.yaml`, default `0x0E00`-`0x0FFF`) can reach either ECU in the
same session — no separate Routing Activation per ECU. With the bundled
`pc_tester` (default diag target: `0x0003`, TestEcu), just use the
interactive REPL's `target <addr_hex>` command (e.g. `target 0x0002`) to
switch which ECU your next `diag` goes to; no config edit or container
restart needed.

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

## Running as non-root

All four containers run their Python process as a dedicated, unprivileged
`doip` user (UID/GID `10001`), not root, set directly via `USER doip` in each
Dockerfile. None of the services need raw sockets or a privileged port
(everything is 13400/udp, 13400/tcp or 3496/tcp, all well above 1024), so this
was a drop-in change — no `cap_add`, `privileged`, or kernel capabilities are
required anywhere in `docker-compose.yml`, and none of the containers need to
start as root at any point.

```bash
docker compose exec doip-edgenode id      # uid=10001(doip) gid=10001(doip)
```

`doip-edgenode`'s frame log (`/app/logs/doip.log`) is container-internal only
— it's not bind-mounted to the host, so there's no host-owned directory to
fight over permissions with. The logger middleware also writes every frame to
stdout, so `docker compose logs -f doip-edgenode` (or `docker logs
doip-edgenode`) gets you the same stream live; the in-container file just
adds a bonus copy that lives and dies with the container. If you want the log
file to persist across container recreation, mount a named volume instead of
a host bind mount (`docker volume create edgenode-logs`, then
`edgenode-logs:/app/logs`) — Docker initializes named volumes with the
image's existing ownership (already `doip:doip` here), unlike host bind
mounts which show up as `root:root`.

If you need the container UID to line up with a specific host UID for some
other mount, override it at build time:

```bash
docker compose build --build-arg APP_UID=$(id -u) --build-arg APP_GID=$(id -g)
```

## Notes

- The EdgeNode is single-session (PoC): only one tester connection at a time.
  Don't leave the bundled tester attached while running your test suite against
  the same EdgeNode.
- EdgeNode frame logs go to stdout (`docker logs doip-edgenode` / `docker compose
  logs -f doip-edgenode`) and to `/app/logs/doip.log` inside the container;
  neither is persisted on the host.
- `priority` on the EdgeNode networks pins the tester side to `eth0` and the ECU
  side to `eth1`, matching `ecu_interface: eth1` in `edgenode.config.yaml`.
- Both ECUs send UDP Vehicle Announcements to `ff02::1` on the backend network, so a
  tester doing vehicle discovery there will see two entities (`0x0002` and `0x0003`).
- `doip-echonode` and `doip-testecu` are independent: stopping one does not affect the
  other, and TestEcu changes never touch `echo_ecu/`.
