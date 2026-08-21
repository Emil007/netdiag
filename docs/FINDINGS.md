# Reading findings

## Classes

| Class | Typical cause |
|-------|----------------|
| `INTERNET` | ISP/WAN or ICMP blocked to external targets |
| `UPLINK_DOWN` | Path from local unmanaged switch toward the router |
| `PROBE_ISOLATED` | Local switch / NIC / cable on the probe’s side |
| `WIFI_PATH` | Wi‑Fi/mesh path (never from never_seen/offline intermittent sats) |
| `TOTAL_OUTAGE` | Router/ISP or wide L2 failure |
| `BRANCH` / `SINGLE_HOST` | Named spur or one canary |
| `MIXED` | Overlapping faults |
| `ROGUE_DHCP` / `IP_CONFLICT` / `DNS_FAILURE` / `LINK_ERRORS` / `BCAST_STORM` / `PATH_CHANGE` | As named |

Each incident page has a **Where** sentence and a **vantage × group** table. If the confirming satellite is offline/never_seen, confidence is **single vantage**.

## Workflow

1. Open `report.html` — hottest weighted class.
2. Read **Where**, then the matrix.
3. Confirm with `EVENTS.log` / CSVs / linked pcap name.

## Limits

- Views from probe + optional satellites only.
- Unmanaged switches are inferred, not discovered by SNMP.
- Only monitor networks you own or are authorized to diagnose.
