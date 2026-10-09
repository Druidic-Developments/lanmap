# TODO

## Done (v0.1.0)
- [x] nmap discovery sweep (ARP when root, ping fallback) with XML parsing
- [x] Quick / deep / custom port scans with service version detection and OS guess
- [x] SQLite store: devices, open ports, scan runs, change events
- [x] Change detection: new device, online/offline, ip/hostname/mac change, port opened/closed, service changed
- [x] Background worker + scheduler (discovery every 30 min, quick port scan every 6 h, both configurable)
- [x] Dashboard: devices table with in-place editing (name, type, notes, skip flag), expandable detail rows
- [x] Dashboard: all-ports table, change feed with kind filter, scan history
- [x] Dashboard: vis-network map grouped by subnet with gateway at centre (vendored, works offline)
- [x] "This host" tab: listening sockets → process via `ss`
- [x] Dockerfile + compose with host networking, NET_RAW/NET_ADMIN, pid: host
- [x] Test suite on canned nmap XML (no network needed)

## Next
- [ ] UDP scan option (`-sU` on a short list: 53, 67, 123, 161, 1900, 5353) — slow, so opt-in per device
- [ ] mDNS / NetBIOS / SSDP name resolution for devices with no PTR record (most phones/IoT)
- [ ] Randomized-MAC detection (locally-administered bit set) so phones don't pile up as "new device" each day
- [ ] Notifications: webhook (Discord / ntfy) on new device, port opened, device offline
- [ ] Map: switch-port topology via SNMP/LLDP for managed switches (UniFi API as a first target)
- [ ] Map: remember node positions (localStorage) so a refresh doesn't reshuffle
- [ ] Device detail: port history timeline (when each port was first/last seen open)
- [ ] Export: CSV of devices and ports; JSON backup/restore of labels + notes
- [ ] Auth: optional basic-auth / token so the dashboard isn't open to the whole LAN
- [ ] Multi-subnet: per-subnet scan settings; second-instance aggregation
- [ ] Cancel the running scan from the UI (kill nmap)
- [ ] Dark/light theme toggle

## Known limitations
- Process names are only available for the host running lanmap; other devices show nmap's fingerprint.
- Topology is a star around the gateway unless switch data is added (see Next).
- Discovery uses the container's default route only; other VLANs need an interface on them.
- Deep scans of 65535 ports can take 5-30 min per host and may hang fragile IoT devices — use the skip flag.
