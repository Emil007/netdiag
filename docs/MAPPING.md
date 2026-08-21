# Mapping your network into netdiag

netdiag is **not** an inventory. With ~100 devices you still only configure **~5–15 always-on canaries**.

## Checklist

1. `capture.iface` — NIC on the Docker host (`ip -br link`)
2. One `gateway` canary — usually `192.168.1.1` / `192.168.0.1`
3. One canary per mesh/AP node you care about (`role: mesh`)
4. If the coordinator sits behind a dumb switch: **another always-on device on that same switch** (`role: same_segment`) — not the probe host itself
5. Optional branch / Wi‑Fi canaries
6. `external` canaries (`1.1.1.1`, `8.8.8.8`)
7. Optional satellites with `vantage.link: ethernet` or `wifi`

## Dumb switches

They have **no IP**. Never put the switch in the config. Put 1–2 stable devices *behind* it. If those die together while the router answers, the report blames that **branch**.

## Probe behind the switch (NAS case)

If netdiag runs on a host plugged into a switch that uplinks to the router:

| Pattern | Meaning |
|---------|---------|
| `same_segment` up, router/mesh/internet down | `UPLINK_DOWN` — wall cable / router LAN port |
| `same_segment` + router down (or NIC carrier down) | `PROBE_ISOLATED` — local switch / NIC / cable |
| Only one group down | `BRANCH` / `SINGLE_HOST` |

A wired satellite on the **router** side makes this much clearer.

## Wi‑Fi satellite

Set `vantage.link: wifi` on that host and list it under coordinator `satellites:`. If the Wi‑Fi satellite goes **silent or lossy** while ethernet vantages stay healthy, expect **`WIFI_PATH`**. Silence is evidence — the satellite may drop exactly when Wi‑Fi fails.

## Roles

| Role | Meaning |
|------|---------|
| `gateway` | Main router |
| `mesh` | Mesh node / AP |
| `branch` | Devices representing a wired spur |
| `same_segment` | Other device on the probe's local switch |
| `wifi` | Optional Wi‑Fi client canary |
| `external` | Internet targets |
| `other` | Anything else |

Group `id` values are labels you invent (`mesh_a`, `wired_office`, …).
