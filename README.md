# netdiag

Multi-day private LAN diagnostics for Docker / Portainer.

The image is **built on GitHub Actions** and published as `ghcr.io/emil007/netdiag:latest`. Deploy with compose — **no local build**, **no `.env` file**. Edit settings in the compose `environment:` block.

## What you get

| Output | Path |
|--------|------|
| Aggregate HTML report | `data/reports/report.html` |
| Per-fault HTML pages | `data/reports/incidents/` |
| JSON summary | `data/reports/report.json` |
| Event log | `data/logs/EVENTS.log` |
| Status snapshot | `data/logs/STATUS.txt` |
| CSVs / pcaps | `data/logs/`, `data/captures/` |

## Coordinator (Portainer / compose)

1. On a **Linux** Docker host (NAS, Pi, Proxmox — not Docker Desktop).
2. Stacks → Add stack → paste [`docker-compose.yml`](docker-compose.yml) (or Git deploy this repo).
3. Edit environment values in that file: `IFACE`, canary `NETDIAG_GROUPS`, `NETDIAG_INGEST_TOKEN`, satellites list, etc.
4. Set the `./data` volume to a persistent host path if needed.
5. Deploy (`docker compose up -d` pulls the GHCR image).

First GHCR pull may need the package to be public, or a Portainer/registry login to `ghcr.io`.

## Satellites

Paste [`docker-compose.satellite.yml`](docker-compose.satellite.yml) on another host. Set:

- `NETDIAG_VANTAGE_ID` / `NETDIAG_VANTAGE_LINK` (`ethernet` or `wifi`)
- `NETDIAG_COORDINATOR_URL` (e.g. `http://<nas-ip>:8787/ingest`)
- `NETDIAG_COORDINATOR_TOKEN` (same as coordinator `NETDIAG_INGEST_TOKEN`)
- `IFACE` and `NETDIAG_GROUPS`

## Configuration

All runtime settings are compose environment variables (see the compose files). Important ones:

| Variable | Purpose |
|----------|---------|
| `IFACE` | Capture/probe NIC |
| `NETDIAG_GROUPS` | JSON canary groups |
| `NETDIAG_SATELLITES` | Expected satellite id + link |
| `NETDIAG_VANTAGE_*` | This host’s id / ethernet\|wifi |
| `NETDIAG_INGEST_*` | Coordinator ingest |
| `NETDIAG_COORDINATOR_*` | Satellite push target |

Optional: mount a `config.yaml` at `/app/config.yaml` if you prefer a file; env vars still override. Examples remain in `config.example.yaml` / `config.satellite.example.yaml`.

Read **[docs/MAPPING.md](docs/MAPPING.md)** and **[docs/FINDINGS.md](docs/FINDINGS.md)**.

## Requirements

- Linux + Docker Compose v2
- `network_mode: host`
- `NET_RAW` + `NET_ADMIN`

## Image

`ghcr.io/emil007/netdiag:latest` — built by CI on push to `main`. Do not use `build:` on the NAS.

## License

MIT — use only on networks you own or are authorized to monitor.
