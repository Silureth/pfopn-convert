# Command reference

The three commands used for the [tested migrations](tested-migrations.md), for the pfSense → OPNsense direction. For the order of the steps, see the [README](../README.md#migration-workflow).

## `scan`

Readiness report for the source config, before converting it.

```bash
pfopn-convert scan source-pfsense.xml --to opnsense
```

- Detected platform, config version and DHCP backend.
- Top-level sections that `convert` converts, and those that need a manual review.
- Packages: known ones (see [Plugins](../README.md#plugins)) and those with no OPNsense equivalent.
- `--format json` for machine-readable output.

## `convert`

Builds the OPNsense config from the source config and the baseline (a config export of the fresh OPNsense install).

```bash
pfopn-convert convert source-pfsense.xml --from pfsense --to opnsense \
  --target-file opnsense-baseline.xml --output converted.xml
```

- Interfaces are matched by their logical names (`wan`, `lan`, `opt1`, …). The baseline decides the device names (`igb0` on the source can become `vtnet0`). `convert` stops if an interface the source needs is not assigned in the baseline; VLAN, WireGuard and OpenVPN interfaces are created from the source.
- `info:` and `warning:` lines list everything that was converted differently, kept in the old format or dropped. A `plugins:` report lists each package as `converted`, `NOT INSTALLED` (not in the baseline, settings not converted) or `no equivalent`.
- `--pfblocker-feeds`: points pfBlockerNG's `pfB_*` IP aliases at the original feed URLs, turns its GeoIP aliases into OPNsense GeoIP aliases and its DNSBL into an Unbound DNS blocklist (see [Known limitations](../README.md#known-limitations)).
- `--legacy-rules`: on OPNsense 26.7+ baselines, keeps firewall and outbound NAT rules in the old format instead of the new rule model (see [OPNsense 26.7 targets](../README.md#opnsense-267-targets)).
- `--no-separator-categories`: drops pfSense's rule and port-forward separators instead of turning them into rule categories (see [Separators](../README.md#separators)).
- DHCP is switched on for an interface only if the source has it on. On OPNsense 26.x baselines, ISC DHCP is converted to Kea; pfSense client IDs are not transferred to Kea reservations (the MAC address is used).

## `verify`

Checks a converted config before the restore. Run it on every output.

```bash
pfopn-convert verify converted.xml --to opnsense --strict
```

It exits non-zero on errors; with `--strict` also on warnings. `--format json` gives machine-readable output.

Checks this fork added, for problems that OPNsense does not report or only reports after the restore:

| Check | Severity | Finds |
|---|---|---|
| `rule_flag_empty` | error | empty pfSense-style flags (`disabled`, `log`, `not`, …) in filter or NAT rules, which OPNsense reads as off |
| `rule_model_invalid` | error | a 26.7 firewall or outbound NAT rule that OPNsense's rule model refuses to save (for example ports without TCP/UDP) |
| `alias_legacy_fields` | error | an alias still using pfSense's fields (`address`, `url`, `descr`) instead of `content` |
| `interface_flag_empty` | error | empty `blockpriv`/`blockbogons` (and DHCPv6 flags) on an interface, which OPNsense reads as off |
| `gateway_legacy_ignored` | error | gateways in the legacy `<gateways>` section, which OPNsense no longer reads |
| `nat_legacy_ignored` | error | 1:1 NAT or NPt in the old `<nat>` section on 26.7+, where they are ignored |
| `outbound_nat_family_mismatch` | error | an IPv4 outbound NAT rule with an IPv6 address or the reverse; pf rejects the whole ruleset |
| `icmp_type_any` | error | ICMP type `any` on a rule; pf rejects the whole ruleset |
| `staticroute_disabled_ignored` | error | a disabled route using `<disabled>` where 26.7 reads `<enabled>` |
| `kea_pool_separator` | error | Kea pools joined with commas |
| `kea_reservation_mac_and_client_id` | error | a Kea reservation with both a MAC address and a client ID |
| `mvc_section_missing_version` | warning | an OPNsense section without a `version` attribute, so OPNsense re-runs all of its migrations at boot |
| `pfsense_match_rule`, `pfsense_nat64_rule` | warning | pfSense-only rule types that stay in the old format |

`verify` also runs the original tool's checks: missing interface, alias, gateway and schedule references; duplicate interface assignments and rule signatures (`duplicate_firewall_rule` is a warning; on a converted pfSense config it usually means the source had the same rule twice); bridges; NAT interfaces; WireGuard interface assignments; and the expected sections and fields per platform version.
