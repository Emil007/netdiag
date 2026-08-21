# netdiag

Home-LAN diagnostics as a **Docker Compose** stack. Run for a few days on a Linux host with Docker Engine, then open the HTML report.

Image (multi-arch amd64/arm64): `ghcr.io/emil007/netdiag:latest` — built on GitHub Actions. Pull it; do not `build:` on the Docker host unless you are developing.

## Quick start

```bash
cp config.example.yaml config.yaml
# edit config.yaml (canaries, token, optional satellites) — every key is commented
# edit docker-compose.yml (IFACE, TZ, volume path, matching token)
docker compose up -d
```

Reports appear under `data/reports/report.html`. Also see `data/logs/STATUS.txt` and `EVENTS.log`.

If `docker pull` fails: `docker login ghcr.io`, or set the GHCR package visibility to public.

Ingest will **not** start until `ingest.token` is set to something other than `change-me` (unless `NETDIAG_ALLOW_INSECURE_INGEST=1` for a lab).

**Portainer (optional):** paste the same `docker-compose.yml` into a stack. Some UIs need an absolute path for `./data`.

## Satellites (optional)

A wired satellite on the **router** side of a suspect unmanaged switch is what confirms local-switch vs uplink vs router. Wi‑Fi satellites are for air-path issues and should use `availability: intermittent` (sleeping laptops must not become `WIFI_PATH`).

```bash
cp config.satellite.example.yaml config.satellite.yaml
# edit vantage id/link/availability, coordinator URL http://<coordinator-ip>:8787/ingest, token
docker compose -f docker-compose.satellite.yml up -d
```

List the satellite under `satellites:` in the coordinator `config.yaml` (default list is empty).

## Docs

- [docs/MAPPING.md](docs/MAPPING.md) — canaries, dumb switches, placement
- [docs/FINDINGS.md](docs/FINDINGS.md) — how to read classes / Where sentences

## Requirements

- Linux + Docker Compose v2
- `network_mode: host`
- `NET_RAW` + `NET_ADMIN`

## License

MIT — only on networks you own or are authorized to monitor.
