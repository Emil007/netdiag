# netdiag

Multi-day private LAN diagnostics for Docker / Portainer.

Run one **coordinator** for a few days. Optionally add lightweight **satellites** on other Docker hosts (wired at the router, and/or on Wi‑Fi). Open `data/reports/report.html` when you want answers — no live web UI.

## What you get

| Output | Path |
|--------|------|
| Aggregate HTML report | `data/reports/report.html` |
| Per-fault HTML pages | `data/reports/incidents/` |
| Machine-readable summary | `data/reports/report.json` |
| Human event log | `data/logs/EVENTS.log` |
| Live status snapshot | `data/logs/STATUS.txt` |
| Ping / NIC CSVs | `data/logs/*.csv` |
| Rotating pcaps | `data/captures/` |

## Quick start (coordinator)

1. Clone this repo on a **Linux** Docker host (NAS, Pi, Proxmox VM). Host networking does not work for real LAN sniffing on Docker Desktop (Windows/Mac).

2. Configure:

```bash
cp config.example.yaml config.yaml
cp .env.example .env
# edit config.yaml — see docs/MAPPING.md
```

3. Deploy:

```bash
docker compose up -d --build
```

Or in **Portainer**: Stacks → Add stack → paste `docker-compose.yml`, upload/edit `config.yaml`, set the bind mounts for `./data` and `./config.yaml` to real host paths.

4. After hours/days, open `data/reports/report.html` (and skim `EVENTS.log`).

## Satellites (optional but powerful)

Use the **same image** on another host:

```bash
cp config.satellite.example.yaml config.satellite.yaml
# set vantage.id, vantage.link (ethernet|wifi), coordinator.url + token
docker compose -f docker-compose.satellite.yml up -d --build
```

Recommended for a typical home layout:

- Coordinator on a NAS/server behind a switch (`link: ethernet`)
- Satellite on a PC plugged into the router (`link: ethernet`)
- Satellite on a Wi‑Fi Docker host (`link: wifi`)

List expected satellites under `satellites:` on the coordinator so silence is interpreted (especially Wi‑Fi → `WIFI_PATH`).

Token in satellite `coordinator.token` must match coordinator `ingest.token`.

## Configuration mental model

You do **not** list every device. You list a handful of **always-on canaries** in named groups. Classification is “which canaries went dark together?”

Read **[docs/MAPPING.md](docs/MAPPING.md)** and **[docs/FINDINGS.md](docs/FINDINGS.md)**.

## Requirements

- Linux + Docker (Compose v2)
- `network_mode: host`
- Capabilities `NET_RAW` and `NET_ADMIN`
- An interface name that sees your LAN (`ip -br link`)

## Image

- Build locally: `docker compose build`
- Published (after CI): `ghcr.io/emil007/netdiag:latest`

## License

MIT — use at your own risk on networks you own or are authorized to monitor.
