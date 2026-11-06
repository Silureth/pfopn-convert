# Changelog

## v0.2.0 (2026-11-06)

First release of this fork of [sheridans/pfopn-convert](https://github.com/sheridans/pfopn-convert), focused on **pfSense CE 2.8 / 2.9 → OPNsense 26.7**. It was used for a real pfSense 2.9.0 → OPNsense 26.7.8 migration; see [Tested migration](https://github.com/Silureth/pfopn-convert#tested-migration) for what that covered and what it did not.

### OPNsense 26.7 rule model

- Firewall rules, outbound NAT, 1:1 NAT and NPt are written in OPNsense 26.7's new rule format, so they can be edited in the GUI. `--legacy-rules` keeps firewall and outbound NAT rules in the old format.
- Converted rules can be saved in the GUI: rules with ports but protocol `any` become `TCP/UDP`, ICMP on IPv6 becomes `IPV6-ICMP`, ICMP type `any` is written as empty, and the outbound NAT address family is taken from the addresses.
- A "This Firewall, no gateway" rule is added in front of each policy-routing rule to `any`, so traffic to the firewall itself is not sent to the gateway.

### Fixes that changed firewall behaviour silently

- Empty pfSense flags (`<disabled></disabled>`, `<log></log>`, `<not></not>`) were read as off by OPNsense: disabled rules became active, inverted matches were flipped. They are now written as `1`.
- "Block private/bogon networks" was switched off on interfaces where pfSense had it on.
- DHCP was switched on for interfaces where pfSense had it off.
- Aliases arrived empty; they are now mapped to OPNsense's alias fields.
- Gateways stayed in the legacy section, which OPNsense no longer reads; they are moved into `OPNsense/Gateways` with the right default gateway.
- Disabled static routes came up enabled on 26.7.
- IPsec, Swanctl and WireGuard sections lost their model versions, so OPNsense re-ran old migrations at boot.
- The web GUI certificate was replaced by a new self-signed one.
- The baseline's `system/firmware` (update settings, configured plugins) and "Shared forwarding" (`pf_share_forward`) were lost.
- Smaller fixes: Kea pools and reservations, WireGuard tunnel addresses, an invalid empty bridge, HTML-encoded descriptions, pfSense's NTP pool.

### New conversions

- DNS Resolver (Unbound): general settings, host and domain overrides, access lists.
- Remote syslog destinations.
- Plugins, when installed in the baseline: Zabbix Agent 6/7 (including PSK and user parameters), node_exporter, and the Shellcmd QEMU guest agent → `os-qemu-guest-agent`. `convert` prints a `plugins:` report.
- pfBlockerNG IP lists: `--pfblocker-feeds` points the `pfB_*` aliases at the original feed URLs (dead feeds are skipped). Without it, a warning says the aliases will stay empty. The DNSBL is not converted; use Unbound DNS blocklists.

### Tools

- New `verify` checks for each of the problems above, including rules OPNsense's model would refuse to save (`rule_model_invalid`). Run `verify --strict` on every output.
- `tools/sanitize_config.py` anonymizes config backups before sharing them.

## v0.1.0 (2026-02-18)

Initial release by the original author.
