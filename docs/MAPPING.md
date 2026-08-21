# Mapping your home LAN into netdiag

You do **not** list every device. Pick **~5–15 always-on canaries**. Classification answers: which canaries went dark together?

Phones and sleep-prone laptops are bad **canaries**. A laptop may run an intermittent **satellite**; that is different.

Mesh/AP **management IPs must answer ping**.

## Checklist

1. `IFACE` on the Docker host (`ip -br link`)
2. Router canary (`role: gateway`)
3. Optional mesh/AP canaries
4. If the probe sits behind an unmanaged switch: **same_segment** = another always-on box on that same switch (not the probe host)
5. Optional named room/spur groups (`role: branch`) — the group `id` appears in “Where”
6. External canaries (`1.1.1.1` / `8.8.8.8`); ICMP may be blocked while HTTPS works
7. Optional satellites (default none). Wired on the router side for switch localization; Wi‑Fi = `intermittent`

## Unmanaged switches

No IP → never in config. Put 1–2 always-on devices **behind** each switch you care about, each in its own group id.

## Probe behind a dumb switch

| Pattern | Meaning |
|---------|---------|
| same_segment up, router down | Uplink cable / path from that switch to the router |
| same_segment + router down (or NIC carrier down) | Local switch / NIC / cable |
| Only one named group down | That spur’s switch/cable |

A **wired satellite on the router** turns those guesses into **confirmed** locations. Wi‑Fi satellites do not localize dumb switches.

## Satellite presence

| State | Meaning |
|-------|---------|
| never_seen | Listed but never checked in — ignored |
| online | Fresh sample |
| stale | Recently silent — may be a path fault if `always` or corroborated |
| offline | Graceful goodbye or long silence — parked, not WIFI_PATH |

## Roles

`gateway`, `mesh`, `branch` (room/spur), `same_segment`, `wifi`, `external`, `other`.
