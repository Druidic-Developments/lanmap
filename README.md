# lanmap

Self-hosted LAN scanner with a web dashboard. Finds every device on your network,
records what ports are open and what's running on them, draws a map, and tracks what
changed between scans.

Built on **nmap** + **FastAPI** + **SQLite**. One container, no external services.

## What it does

| Tab | What you get |
|---|---|
| **Devices** | Every host seen: IP, MAC, vendor, hostname, OS guess, open-port count, last seen. Click a row to expand it. Click a name or type to edit it in place. Per-device quick/deep/custom port scans. |
| **Ports** | Every open port across the LAN in one sortable table — port, service, product/version nmap fingerprinted, which device. |
| **Map** | Interactive graph: gateway in the middle, devices around it, grouped by subnet. Click a node for details. |
| **Changes** | Feed of new devices, devices going offline/online, ports opening/closing, service version changes, IP/hostname/MAC changes. |
| **This host** | Listening sockets on the machine running lanmap, mapped to the **process** that owns them. |

### What "what's using the port" means

- For **other devices** on the LAN it's nmap's service fingerprint (`22/tcp OpenSSH 9.2p1`, `8096/tcp Jellyfin`). No scanner can see remote process names.
- For **the host running lanmap** it's the actual process (`ss -lptn`), shown on the *This host* tab. In Docker this needs root, `pid: host` and the `SYS_PTRACE` capability (all set in the compose file). If the tab still shows `unknown` for every process, AppArmor is blocking `/proc` access — uncomment the `security_opt: apparmor=unconfined` lines in the compose file. The tab tells you which of these is missing.

## Quick start

```bash
git clone <this repo> lanmap && cd lanmap
docker compose up -d --build
```

Open `http://<docker-host-ip>:8080`. A discovery sweep starts on boot; the subnet and
gateway are autodetected from the default route. Hit **Scan all ports** for the first
port inventory (a few minutes for ~30 devices). The database persists in the
`lanmap-data` Docker volume.

### Why host networking

With Docker's default bridge network the container lives on `172.x` and can only see
your LAN through NAT — no ARP, no MACs, no vendors. `network_mode: host` puts it
directly on your LAN. `NET_RAW` enables ARP/SYN scans, `NET_ADMIN` enables OS detection.

**Run it on a Linux Docker host** (Raspberry Pi, TrueNAS SCALE, Proxmox LXC/VM, any
Linux box). A Raspberry Pi 4 is plenty: the image builds natively on arm64 and armv7
(all dependencies ship ARM wheels), and a quick port scan of ~30 devices takes a few
minutes. Docker Desktop on Windows or macOS runs containers inside a VM, so
`network_mode: host` only reaches that VM's private network, not your LAN — discovery
will find nothing, or only the VM itself. If Windows is all you have, run it in a VM
with a **bridged** network adapter, or natively under WSL2 with
[mirrored networking mode](https://learn.microsoft.com/en-us/windows/wsl/networking#mirrored-mode-networking)
(`sudo python -m lanmap`, no Docker).

### Portainer

A stack pasted into Portainer's web editor can't `build:` (it has no Dockerfile to
build from), so pick one of these:

**A. Git repository stack** (builds on the Pi, redeploys on push)

1. Push this repo to GitHub / Gitea / wherever.
2. Portainer → *Stacks* → *Add stack* → *Repository*.
3. Repository URL = your repo, Compose path = `docker-compose.yml`, name it `lanmap`.
4. *Deploy the stack*. First build takes a few minutes on a Pi 4.

Later, *Pull and redeploy* on the stack picks up new commits.

**B. Pre-build the image, then paste the stack**

On the Pi over SSH:

```bash
git clone <repo> lanmap && cd lanmap
docker build -t lanmap:latest .
```

Then in Portainer → *Stacks* → *Add stack* → *Web editor*, paste `docker-compose.yml`
with the `build: .` line removed (keep `image: lanmap:latest`). To update, rebuild the
image and *Update the stack* with *Re-pull image and redeploy* **off**.

Either way the database lives in the named volume `lanmap-data`, visible under
Portainer → *Volumes*. Set environment variables in the stack's *Environment
variables* section or by editing the compose text.

### Running without Docker

```bash
pip install -r requirements.txt
sudo LANMAP_DB=./lanmap.db LANMAP_SUBNETS=192.168.1.0/24 python -m lanmap
```

Needs `nmap` and `iproute2` installed. Without root it falls back to TCP connect scans and
ICMP/TCP ping instead of ARP, which still works but misses MACs and some quiet devices.

## Configuration

All via environment variables (see `docker-compose.yml`):

| Variable | Default | Meaning |
|---|---|---|
| `LANMAP_SUBNETS` | autodetect | Comma-separated CIDRs to sweep |
| `LANMAP_GATEWAY` | autodetect | Gateway IP (centre of the map) |
| `LANMAP_INTERFACE` | autodetect | NIC to scan from |
| `LANMAP_PORT` | `8080` | Dashboard port |
| `LANMAP_DB` | `/data/lanmap.db` | SQLite path |
| `LANMAP_SCAN_INTERVAL` | `30` | Minutes between discovery sweeps (`0` = manual) |
| `LANMAP_PORT_SCAN_INTERVAL` | `360` | Minutes between automatic quick port scans (`0` = manual) |
| `LANMAP_QUICK_PORTS` | `top1000` | Port spec for quick scans (`topN` or nmap syntax) |
| `LANMAP_DEEP_PORTS` | `1-65535` | Port spec for deep scans |
| `LANMAP_VERSION_DETECTION` | `true` | Run `-sV` service fingerprinting |
| `LANMAP_TIMING` | `T4` | nmap timing template |
| `LANMAP_HOST_TIMEOUT` | `300` | Seconds per host before nmap gives up |
| `LANMAP_PARALLEL` | `4` | Hosts scanned concurrently |
| `LANMAP_OFFLINE_AFTER` | `2` | Missed sweeps before a device is marked offline |
| `LANMAP_SKIP_HOSTS` | | IPs never to port-scan (fragile IoT, printers) |

You can also flag a device as *exclude from port scans* in the UI — that's stored in
the database and survives restarts.

## Scan types

| | Discovery | Quick | Deep |
|---|---|---|---|
| nmap | `-sn -PR` (ARP) | `-sS --top-ports 1000 -sV --version-light` | `-sS -p- -sV -O` |
| When | every 30 min + boot | every 6 h, or per device | per device, on demand |
| Time/host | seconds | ~10-60 s | 5-30 min |
| Gives you | IP, MAC, vendor, hostname, up/down | open ports + service names/versions | all 65535 ports + OS guess |

Deep scans can upset cheap IoT gear (old printers, cameras, smart plugs). Flag those
devices as excluded, or set `LANMAP_SKIP_HOSTS`.

## Multiple VLANs / subnets

The scanner only sees the subnet(s) its host sits on. To cover a second VLAN either
give the Docker host an interface on it (trunk port + VLAN sub-interface) and list both
CIDRs in `LANMAP_SUBNETS`, or run a second lanmap instance there. Scanning a remote
subnet through the router works for ports but won't return MACs or vendors.

## API

Everything the dashboard does is plain JSON under `/api` — see `/docs` for the
OpenAPI UI. Useful bits:

```
GET  /api/devices                 all devices
GET  /api/devices/{id}            device + ports + recent events
PATCH /api/devices/{id}           {"label": "...", "device_type": "...", "notes": "...", "skip_ports": true}
GET  /api/ports                   every open port on the LAN
GET  /api/events?kinds=port_opened,device_new&limit=100
GET  /api/map                     nodes + edges
POST /api/scan/discovery
POST /api/scan/ports              {"device_ids": [3], "deep": false, "ports": "1-1024"}
POST /api/scan/ports              {"all_online": true}
GET  /api/localports              listening sockets on this host
```

## Development

```bash
pip install -r requirements-dev.txt
pytest
```

Tests run entirely against canned nmap XML — no network or root needed.

## Project layout

```
lanmap/
  config.py      env settings + subnet/gateway autodetect
  scanner.py     nmap command builder, runner, XML parser
  localports.py  `ss` wrapper for the host's own listening sockets
  differ.py      pure change detection (device + port diffs)
  db.py          SQLite store: devices, ports, scans, events, map data
  manager.py     background worker + scheduler
  app.py         FastAPI routes
  static/        dashboard (vanilla JS + vendored vis-network)
tests/
```
