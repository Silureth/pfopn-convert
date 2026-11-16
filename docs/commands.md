# Command reference

The three commands used for the [tested migrations](tested-migrations.md), for the pfSense → OPNsense direction, and the [on-box wizard](#wizard) that runs them on the OPNsense box. For the order of the steps, see the [README](../README.md#migration-workflow).

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
| `port_forward_protocol_any` | error | a port forward with protocol `any`, which OPNsense writes to pf as `proto any`; pf rejects the whole ruleset |
| `user_password_missing` | error | a user without `password` (pfSense's `bcrypt-hash`/`sha512-hash` are not read); OPNsense rejects every save of the user list |
| `staticroute_disabled_ignored` | error | a disabled route using `<disabled>` where 26.7 reads `<enabled>` |
| `kea_pool_separator` | error | Kea pools joined with commas |
| `kea_reservation_mac_and_client_id` | error | a Kea reservation with both a MAC address and a client ID |
| `mvc_section_missing_version` | warning | an OPNsense section without a `version` attribute, so OPNsense re-runs all of its migrations at boot |
| `interface_address_with_vips` | warning | "interface address" in a port forward or rule on an interface with virtual IPs; OPNsense matches all of them, pfSense only the interface's own IP |
| `adaptive_timeouts_half_set` | warning | only one of adaptive start/end set; OPNsense refuses to save Firewall > Settings > Advanced |
| `pfsense_match_rule`, `pfsense_nat64_rule` | warning | pfSense-only rule types that stay in the old format |

`verify` also runs the original tool's checks: missing interface, alias, gateway and schedule references; duplicate interface assignments and rule signatures (`duplicate_firewall_rule` is a warning naming the interface and the rules; on a converted pfSense config it usually means the source had the same rule twice, most often the filter rules of several port forwards to the same internal host and port); bridges; NAT interfaces; WireGuard interface assignments; and the expected sections and fields per platform version.

## `wizard`

The [on-box wizard](../README.md#on-box-wizard): a menu on the new OPNsense box that checks the interface assignment, updates OPNsense, installs the plugins, runs `convert` and `verify` with the box's live config as the baseline, and starts OPNsense's console restore. Design and details are in [wizard.md](wizard.md).

```sh
/mnt/pfopn-convert wizard                      # first start, from the CD or USB stick
/root/pfopn-convert/pfopn-convert wizard       # later starts, for example after a reboot
```

- `[SOURCE]`: the pfSense config to convert. Default: the pfSense configs in the work directory, which the first start copies there from next to the binary; with more than one, the wizard asks.
- `--work-dir <dir>` (default `/root/pfopn-convert`): where the wizard copies itself and the pfSense configs on its first start, and where each conversion writes its files (`<dir>/<timestamp>/`: `baseline.xml`, `converted.xml`, `convert.log`, `verify.log`, `report.txt`).
- `--no-relocate`: run from where the binary is, without copying it to the work directory.
- `--dry-run`: print the OPNsense commands (firmware update, plugin install, restore) instead of running them.
- `--box-root <dir>` (default `/`): read the OPNsense config from `<dir>/conf/config.xml` and write backups to `<dir>/conf/backup/`. With `--dry-run`, this tries the wizard on a workstation against a config export:

  ```bash
  mkdir -p box/conf && cp opnsense-baseline.xml box/conf/config.xml
  pfopn-convert wizard source-pfsense.xml --box-root box --work-dir work --dry-run
  ```

`verify` runs without `--strict`: the duplicate-rule warnings every tested box had would otherwise block the restore. Errors from `convert` or `verify`, or a change to the box's config after the conversion (for example a plugin installed since), block the restore.
