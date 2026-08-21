# Reading findings

## Incident classes

| Class | Typical cause |
|-------|----------------|
| `INTERNET` | ISP/WAN — LAN path to router looked fine |
| `UPLINK_DOWN` | Cable/path from local switch to router |
| `PROBE_ISOLATED` | Local switch, power, probe NIC/cable |
| `WIFI_PATH` | Mesh/Wi‑Fi path (wifi vantage bad/silent, ethernet ok) |
| `TOTAL_OUTAGE` | Router restart, loop/storm, wide L2 failure |
| `BRANCH` | One named group/segment |
| `SINGLE_HOST` | One canary device/port/cable |
| `MIXED` | Overlapping faults, DHCP/IP conflict, short storm |
| `ROGUE_DHCP` | Unexpected DHCP server MAC |
| `IP_CONFLICT` | Same IP claimed by changing MACs |
| `LINK_ERRORS` | CRC/receive errors on probe NIC |
| `DNS_FAILURE` | Resolver checks all failed |
| `BCAST_STORM` | Extreme broadcast/multicast with loss |

## How to use the reports

1. Open `report.html` — hottest class first.
2. Open linked incident pages for timing + canaries + pcap name.
3. Confirm with `EVENTS.log` and CSVs if you want raw proof.
4. Match pcap filenames under `data/captures/` around the incident time.

## Limitations

- Views the network **from the probe’s place** in the topology (plus satellites).
- Dumb switches are inferred via canaries, not SNMP.
- Wi‑Fi radio metrics (RSSI, etc.) are not collected — use `WIFI_PATH` + mesh canaries.
- Only monitor networks you own or are authorized to diagnose.
