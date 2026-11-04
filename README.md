# pfopn-convert

![CI](https://github.com/sheridans/pfopn-convert/actions/workflows/ci.yml/badge.svg)
![Release](https://img.shields.io/github/v/release/sheridans/pfopn-convert?display_name=tag)

CLI for migrating firewall configs between pfSense and OPNsense, with section-aware diff analysis and pre-restore validation.

> This is a fork of [sheridans/pfopn-convert](https://github.com/sheridans/pfopn-convert) focused on **pfSense CE 2.8 / 2.9 → OPNsense 26.7**. It fixes several conversion bugs that changed firewall behaviour silently, adds support for OPNsense 26.7's new rule format, and converts the DNS Resolver, remote syslog and common plugins. It has been used for a real pfSense 2.9.0 → OPNsense 26.7.8 cutover; see [Tested migration](#tested-migration), [Changes in this fork](#changes-in-this-fork) and [OPNsense 26.7 targets](#opnsense-267-targets).

> WARNING: This tool can break network connectivity or lock you out if used incorrectly. It is intended for restore/migration onto fresh destination installs. Do not restore to production systems unless you fully understand the generated changes and have rollback access.

## Build

Requires a Rust toolchain (for example via [rustup](https://rustup.rs)).

```bash
cargo build --release
```

Add `target/release/pfopn-convert` to your PATH, or run it directly from that path.

## Safe Migration Workflow

`convert` is baseline-merge by design. You need:

1. `source` export: live config from the platform you are migrating from.
2. `target baseline` export: fresh/default config export from the destination platform/version.

Then:

1. run `convert` with `--target-file <target-baseline.xml>` to generate a new output XML.
2. run `verify` and `migrate-check` on that output.
3. restore/import the generated output on the destination firewall.

The order that worked for a real cutover (pfSense → OPNsense, both as VMs):

1. Install OPNsense in the **exact version** you will run, and update it fully.
2. Give it one network port per source interface, **in the same order**, and assign them all (`wan`, `lan`, `opt1`, … including interfaces that are disabled on the source). Skip the setup wizard.
3. Install the OPNsense plugins the source needs (see [Plugins](#plugins)), without configuring them.
4. Export this config as the baseline and take a VM snapshot.
5. `convert`, then `verify --strict`. Read every `warning:` line and the `plugins:` report.
6. Restore the output on the destination **while only an isolated network is connected**: the output carries the source's IP addresses. Disconnect (or move) every other port first.
7. After the reboot, check the ruleset from the shell: `pfctl -nf /tmp/rules.debug`. A single invalid line stops pf from loading the whole ruleset, and the GUI only shows the first error.
8. Check the GUI (rules, NAT, gateways, services). If something is wrong, roll back to the snapshot, fix, convert again.
9. Cut over: shut the source down, move the destination's ports to the real networks. Optionally copy the source's WAN MAC addresses so upstream ARP caches keep working; then never run both at once.

## Quick Start (Do This)

`pfSense -> OPNsense`:

```bash
pfopn-convert convert /path/source-pfsense.xml \
  --from pfsense \
  --to opnsense \
  --target-file /path/opnsense-fresh.xml \
  --output /tmp/converted-opnsense.xml

pfopn-convert verify /tmp/converted-opnsense.xml --to opnsense --strict
```

`OPNsense -> pfSense`:

```bash
pfopn-convert convert /path/source-opnsense.xml \
  --from opnsense \
  --to pfsense \
  --target-file /path/pfsense-fresh.xml \
  --output /tmp/converted-pfsense.xml

pfopn-convert verify /tmp/converted-pfsense.xml --to pfsense --strict
```

Then restore the generated XML on destination.
Optional flags for initial migration:
- `--lan-ip <IPv4>` only if you want to change the LAN IP/subnet in the output.
- `--disable-dhcp` only if you want DHCP services off in the generated output.
- `--legacy-rules` only if you want to keep firewall/outbound NAT rules in the old format on an OPNsense 26.7+ target (see [OPNsense 26.7 targets](#opnsense-267-targets)).

Read the `info:` and `warning:` lines that `convert` prints. They list everything that was converted differently, kept in the old format, or dropped.

## Prerequisites

- Before you run this, set up the destination firewall and give its network ports the right names (like `wan` and `lan`).
- If the hardware is different, the port device names will change (for example `igb0` becomes `vtnet0`).
- The tool matches by the logical names (`wan`, `lan`, `opt1`), not by device names. The destination baseline decides the rename.
- This is intentional so configs still work when hardware device names change during migration.
- If a required physical port isn’t assigned in the destination baseline, the convert step will fail.
- Assign **every** physical port the source uses, including interfaces that are disabled on the source. For example, a pfSense box with WAN, LAN and OPT1–OPT4 needs six assigned ports on the destination, even if OPT3 is disabled.
- Export the baseline from the **same OPNsense version** you will restore onto. Several conversions depend on the model versions in the baseline (see [OPNsense 26.7 targets](#opnsense-267-targets)).

## Tested migration

This fork was used to migrate a production pfSense firewall to OPNsense. Every problem found on the way was fixed in the converter and got a `verify` check (see [Changes in this fork](#changes-in-this-fork)).

**Source:** pfSense CE 2.9.0 (config version 24.6), Proxmox VM, 6 virtio interfaces (3 WANs, one of them disabled, and 3 internal networks; VLANs tagged on the hypervisor).
The config had about 100 firewall rules (floating rules, policy routing over two gateways), hybrid outbound NAT with 43 rules, 58 port forwards, 44 aliases, 13 IP-alias virtual IPs, 4 gateways, DNS Resolver host and domain overrides, remote syslog, and the packages Zabbix Agent 7, node_exporter, Shellcmd and pfBlockerNG-devel.

**Destination:** OPNsense 26.7.8 (installed as 25.7, upgraded through 26.1), Proxmox VM (x86-64-v2-AES, 4 vCPU, 4 GB RAM, virtio NICs), plugins `os-zabbix7-agent`, `os-node_exporter` and `os-qemu-guest-agent` installed before the baseline export.

Verified on the destination after the restore and the cutover:

| Area | Result |
|---|---|
| Firewall ruleset | loads (`pfctl -nf` clean); rules and outbound NAT are in the 26.7 rule model |
| Interfaces, virtual IPs | all addresses up; disabled interface stays disabled; "Block private/bogon networks" kept |
| Gateways | all 4 present with the correct default gateway; the gateways of the enabled interfaces answer |
| Port forwards | forwarded services (monitoring stack) are reachable through the firewall |
| DNS Resolver | host override answers; recursive resolution works |
| Remote syslog, node_exporter | logs and metrics reach the monitoring stack |
| Zabbix agent | reachable from the Zabbix server with PSK encryption |
| QEMU guest agent | enabled |
| Web GUI certificate | the pfSense certificate is kept (same fingerprint) |

Converted and visible in the GUI, but not tested separately: policy routing and outbound NAT for client traffic, DNS Resolver query forwarding (domain override), DNSSEC and hardening options.

Not exercised by this migration (the source had none configured): OpenVPN, IPsec, WireGuard, DHCP (ISC/Kea), static routes, bridges, the OPNsense → pfSense direction. Those conversions are covered by unit tests and `verify` only.

## Changes in this fork

These fixes apply to every pfSense → OPNsense conversion, not only 26.7:

| Problem in the original tool | Effect on the firewall | Now |
|---|---|---|
| pfSense writes flags as empty elements (`<disabled></disabled>`, `<log></log>`, `<not></not>`); OPNsense reads an empty value as "off" | **disabled rules became active**, logging was lost, inverted (NOT) matches were flipped | flags are written as `1`; also covers NAT rules, IPsec tunnels/phase 2 and user accounts |
| A DHCP block without `<enable>` was treated as enabled | **DHCP was switched on** on interfaces where pfSense had it off | DHCP is only enabled where pfSense had `<enable>` |
| Aliases were copied with pfSense field names | every alias arrived **empty** | mapped to OPNsense fields (`content`, `description`, …) following OPNsense's own migration |
| Kea pools were joined with commas | interfaces with several DHCP ranges got one invalid pool | one pool per line |
| Kea reservations carried both MAC and client ID | OPNsense 26.7 refuses to save them | MAC only |
| Static routes kept `<disabled>` on 26.7 | disabled routes came up **enabled** | `<enabled>` is written for 26.7 baselines |
| IPsec/Swanctl/WireGuard sections had no `version` attribute | OPNsense re-ran old migrations at boot (e.g. duplicate pre-shared keys) | baseline model versions are kept |
| A pfSense `<ipsec>` with no tunnels replaced OPNsense's IPsec section | OPNsense IPsec settings were wiped | baseline IPsec section is kept |
| WireGuard tunnel address was read as plain text | empty tunnel address | addresses are built as CIDRs |
| `verify` treated `enc0` (IPsec) in NAT rules as missing, and dynamic (DHCP) gateways as incomplete | false errors/warnings | both accepted |
| Interface flags `blockpriv`/`blockbogons` were copied as empty elements; OPNsense reads them with `!empty()` | **"Block private/bogon networks" was switched off** on interfaces where pfSense had it on | interface flags are written as `1` |
| pfSense gateways stayed in the legacy `<gateways>` section, which OPNsense no longer reads (its own migration only runs on older models) | interfaces and policy-routing rules pointed at **gateways that did not exist**; the baseline's default gateway stayed | gateways are moved into `OPNsense/Gateways`, default gateway from `defaultgw4/6`, pfSense empty-element flags (`monitor_disable`) kept |
| OPNsense's empty `<bridged/>` placeholder (no bridges) was given a UUID | an **invalid bridge with no interface and no members** | the placeholder is left alone |
| The web GUI certificate was only carried over when a VPN used it | OPNsense **generated a new self-signed certificate** at boot | the referenced certificate (and its CA) is copied; otherwise the baseline's is kept |
| pfSense stores descriptions HTML-encoded, sometimes twice (`kifel&amp;eacute;`, `serp-&gt;z7`) | entities showed literally in the OPNsense GUI | descriptions are decoded to plain text (`kifelé`, `serp->z7`) |
| The merged `system` section (from pfSense) dropped OPNsense's `system/firmware` | update settings and the configured-plugin list were lost | the baseline's `system/firmware` is kept and the needed plugins are added to it |

New features:

- converts firewall rules, outbound NAT, 1:1 NAT and NPt to OPNsense 26.7's new rule format (see below)
- new `verify` checks that catch each of the problems above (see [`verify`](#verify))
- [`tools/sanitize_config.py`](#sharing-configs-safely) to anonymize config backups before sharing them

## OPNsense 26.7 targets

OPNsense 26.7 moved firewall rules, outbound NAT, 1:1 NAT and NPt into a new rule model and removed the old rule editors. Rules left in the old `<filter>`/`<nat>` sections are still enforced, but cannot be edited in the GUI, and 1:1 NAT/NPt in the old sections are **ignored**.

When the baseline is OPNsense 26.7 or newer (Filter model version 1.0.5+), `convert` writes the new format:

- **Firewall rules** go to `OPNsense/Firewall/Filter/rules`, using the same field mapping as OPNsense's Firewall → Migration assistant. Rule order follows OPNsense's legacy ordering: floating rules first, then WAN, LAN, then other interfaces in natural order. Sequence numbers are 1, 11, 21, …
- **Outbound NAT** goes to `OPNsense/Firewall/Filter/snatrules`. pfSense's `<if>ip` target becomes OPNsense's "interface address"; `target`/`target_subnet` and `source_hash_key` are mapped. The outbound NAT mode is kept. pfSense outbound rules carry no address family; it is taken from the addresses (pfSense's auto-created `::1/128` localhost rules become IPv6), because OPNsense only accepts IPv4 or IPv6 and a mismatch stops the whole ruleset from loading.
- **ICMP type `any`** (pfSense's "all types") is written as an empty ICMP type, which is how OPNsense expresses it; `any` itself is a pf syntax error.
- **1:1 NAT and NPt** go to `OPNsense/Firewall/Filter/onetoone` and `npt`. A 1:1 rule whose external address is not a fixed IP (for example pfSense's `wanip`) cannot be expressed in OPNsense and is skipped with a warning.
- **Default rules are replaced.** A fresh 26.7 install ships "Default allow LAN to any" rules in the new format. They are replaced by the converted ruleset, so the result matches the source exactly (pfSense configs carry their own LAN rules).
- **Port-forward links are cleared.** OPNsense 26.7 drops a port forward's link to its filter rule (`associated-rule-id`) on load, except for "pass". The converter does the same; the filter rule itself stays as an ordinary rule.
- **Some rules stay in the old format.** pfSense `match` rules and NAT64 rules have no equivalent in the new format. They are kept in the old section (still enforced) and listed as warnings.
- **Some fields are dropped.** Fields with no OPNsense equivalent (limiters `dnpipe`/`pdnpipe`, queues, OS fingerprint, DSCP, categories) are listed per rule as warnings.

With `--legacy-rules`, firewall and outbound NAT rules stay in the old format. Run Firewall → Migration assistant on the box after the restore to make them editable. 1:1 NAT and NPt are converted either way, because 26.7 ignores them in the old format.

With an older baseline (Filter model before 1.0.5), rules are left in the old format as before.

## Plugins

pfSense packages map to OPNsense plugins. A plugin's settings can only be converted when the plugin is **installed in the baseline**: its configuration model (and version) only exists then.

| pfSense package | OPNsense plugin | Converted |
|---|---|---|
| Zabbix Agent 6/7 | `os-zabbix6-agent` / `os-zabbix7-agent` | servers, active checks, hostname, listen address/port, tuning, PSK encryption (identity and key), user parameters. Certificate TLS is not supported by the plugin. |
| node_exporter | `os-node_exporter` | enabled, listen interface (as its IP address), port, collectors. `boottime`, `textfile` and extra flags have no equivalent. |
| Shellcmd `service qemu-guest-agent start` | `os-qemu-guest-agent` | enabled. Other Shellcmd commands are listed; use `/usr/local/etc/rc.syshook.d/` scripts. |
| pfBlockerNG | none | not converted; use Unbound DNS blocklists and URL table aliases |

After `convert`, a `plugins:` report lists each plugin as `converted`, `NOT INSTALLED` (not in the baseline, settings not converted) or `no equivalent`. The plugins the source needs are also added to the configured-plugin list (`system/firmware/plugins`), so after a restore OPNsense shows missing ones under System → Firmware → Plugins and can install them.

To convert plugin settings: install the plugins on the destination, export the baseline, then run `convert`.

The DNS Resolver and remote syslog conversions follow OPNsense's own legacy migrations, but read pfSense's empty-element flags as set (the migrations would turn DNSSEC and the hardening options off) and keep domain-override domains (OPNsense's import drops them).

## Before Restore

- Take a full config backup of the destination firewall before any restore.
- If testing in VM/lab, take a VM snapshot before first import.
- Install the plugins the source needs **before** exporting the baseline, or their settings are not converted (the `plugins:` report shows `NOT INSTALLED`).
- The output contains the source's IP addresses: restore it with only an isolated network connected.
- After the reboot, run `pfctl -nf /tmp/rules.debug` in the shell. It lists every ruleset error, not just the first one the GUI shows.
- If restore reports interface assignment warnings, reboot the destination and restore the same generated XML a second time.
- This appears to be an intermittent OPNsense interface/apply behavior.

This is intended for safe migration to a different system first (for example lab/VM hardware), so
you do not risk your live source firewall during initial validation.
Use a fresh/default destination install for the baseline export whenever possible. Existing
destination config state (especially bridges, prior interface assignments, gateways, or
plugin-managed objects) can conflict with imported assignments and break post-restore behavior.

Example (`pfSense -> OPNsense`):

```bash
pfopn-convert convert pfsense-live.xml \
  --to opnsense \
  --target-file opnsense-fresh.xml \
  --output converted-opnsense.xml
```

## Commands

### `diff`
Compare two XML files and emit differences plus action analysis.

```bash
pfopn-convert diff <FILE1> <FILE2> [OPTIONS]
```

Options:

- `--section <name>`: focus on one logical section (`system`, `interfaces`, `firewall`, `services`, `vpn`, `packages`)
- `--ignore <path-or-tag>`: ignore path/tag (repeatable)
- `--format <text|json>`: output format
- `--summary`: print only counts
- `--section-summary`: print per-section counts sorted by conflict density
- `--plan <file>`: write action plan JSON
- `--output <file>`: write merged XML using safe insert-only actions
- `--merge-to <left|right>`: destination side for merge output (default `right`)
- default `--output` behavior also transfers OpenVPN dependencies required for migration:
  - referenced system users
  - referenced certs
  - referenced CAs
  - and transfers missing WireGuard config sections (pfSense `<wireguard>` / OPNsense `<OPNsense><wireguard>`)
- opt-out flags:
  - `--no-transfer-users`
  - `--no-transfer-certs`
  - `--no-transfer-cas`
- `--strict`: fail if any manual conflicts remain
- `-v, --verbose`: include identical entries
- `-q, --quiet`: minimal output

### `inspect`
Show parsed structure and optional config detection.

```bash
pfopn-convert inspect <FILE> [--detect] [--plugins] [--section <name>] [--depth <N>]
```

- `--plugins`: show common plugin state detection (`declared`, `configured`, `enabled`) for migration planning.
  - includes `wireguard`, `openvpn`, `ipsec`, `kea-dhcp`, `isc-dhcp`, and `tailscale`.

### `convert`
Convert one file toward a target platform.

```bash
pfopn-convert convert <INPUT> --output <FILE> --from <auto|pfsense|opnsense> --to <pfsense|opnsense> --target-file <FILE> [--backend <auto|kea|isc>]
```

- `--from auto` detects source from root tag; `--to` must be explicit.
- `--target-file` is required: provide a fresh/default config export from the destination platform.
- `--output` is required: path for the generated XML.
- `--backend auto|kea|isc` controls DHCP backend policy; `auto` defaults to Kea for OPNsense 26.x targets.
- `--lan-ip <IPv4>` is optional; use it only if you want to change LAN IP/subnet and remap LAN DHCP ranges.
- `--disable-dhcp` is optional; use it only if you want DHCP services off in the generated output.
- `--legacy-rules` is optional; for OPNsense 26.7+ targets it keeps firewall and outbound NAT rules in the old format instead of converting them to the new rule model.
- DHCP is enabled on an interface only if the source has `<enable>` for it. Ranges and static mappings of disabled interfaces are not turned on.
- pfSense DHCP client IDs (`cid`) are not transferred to Kea reservations; the MAC address is used.
- The tool lines up interfaces by names like `wan` and `lan`. The baseline tells it which device name (`igb0`, `vtnet0`) to use.
- preflight fails if required physical-interface-backed logical assignments are missing from the target baseline; virtual-backed interfaces (VLAN, WireGuard, OpenVPN) can be created from source.

### `sections`
List top-level sections in both files, plus mapping hints.

```bash
pfopn-convert sections <FILE1> <FILE2> [--format <text|json>] [--extras] [--extras-json] [--verbose] [--mappings-file <path> | --mappings-dir <dir>]
```

- `--extras`: enable heuristic hints for likely moved/renamed sections by scanning nested paths.
  - also emits OpenVPN migration checks:
  - `vpn_disabled_config_present` when disabled OpenVPN instances exist
  - `vpn_dependency_gap` when referenced users/certs/CAs are missing on target
  - also emits WireGuard migration checks:
  - `wireguard_dependency_gap` when WireGuard config exists on one side only
  - `wireguard_disabled_config_present` when config exists but no enabled entries are detected
  - and plugin compatibility checks:
  - `plugin_support_gap` when plugin presence differs between sides
  - and IPsec dependency checks:
  - `ipsec_dependency_gap` when referenced certs/CAs/interfaces are missing on the opposite side
- `--extras-json`: emit grouped extras plus unmatched section lists as JSON.
- `--mappings-file <path>`: load known section mappings from TOML file.
- `--mappings-dir <dir>`: load mappings from `<dir>/sections.toml`.
- defaults are embedded; `--mappings-file` and `--mappings-dir` are mutually exclusive.
- `--verbose`: show mapping source (`Using mappings: ...` in text mode).

### `scan`
Quick migration-readiness scan for a single config.

```bash
pfopn-convert scan <FILE> [--to <pfsense|opnsense>] [--target-version <VERSION>] [--format <text|json>] [--verbose] [--mappings-dir <dir>]
```

- reports detected platform/version/backend
- lists supported vs review-required top-level sections
- shows known plugins present and unsupported plugin packages (from plugin matrix + unknown package detection)
- with `--to`, includes target compatibility hints for detected plugins
- with `--target-version`, includes target schema version metadata in scan output (informational only)
- `--mappings-dir <dir>`: load plugin matrix from `<dir>/plugins.toml`.
- `--verbose`: show mapping source (`Using mappings: ...` in text mode).
- plugin matrix: embedded by default; can be overridden in future (no CLI flag yet)

### `verify`
Pre-restore validation gate for a single config.

```bash
pfopn-convert verify <FILE> [--to <pfsense|opnsense>] [--target-version <VERSION>] [--format <text|json>] [--strict] [--verbose]
```

- exits non-zero when hard errors are found
- checks required sections and internal reference integrity for OpenVPN/IPsec dependencies
- checks interface/bridge integrity:
  - missing interface references in rules/gateways/static routes
  - empty bridge members
- checks rule reference integrity:
  - missing alias references in filter rules
  - missing gateway references in filter/static route entries
  - missing schedule references in filter rules (warning)
- checks firewall rule signature collisions:
  - duplicate rule signatures (warning)
  - default-rule overlaps with custom signatures (warning)
- checks WireGuard readiness:
  - errors if WireGuard appears enabled but no `wireguard`/`tun_wg*` interface assignment exists
- rule checks (references, interfaces, duplicates) cover both old-format rules and OPNsense 26.7 new-format rules
- OPNsense import-compatibility checks (OPNsense configs only):
  - `rule_flag_empty` (error): empty pfSense-style flags (`disabled`, `log`, `not`, …) in filter/NAT rules, which OPNsense reads as off
  - `alias_legacy_fields` (error): an alias still using pfSense fields (`address`, `url`, `descr`) instead of `content`
  - `kea_pool_separator` (error): Kea pools joined with commas
  - `kea_reservation_mac_and_client_id` (error): a Kea reservation with both a MAC and a client ID
  - `nat_legacy_ignored` (error): 1:1 NAT/NPt left in the old `<nat>` section on OPNsense 26.7+, where they are ignored
  - `staticroute_disabled_ignored` (error): a disabled route using `<disabled>` where the route model reads `<enabled>`
  - `interface_flag_empty` (error): empty `blockpriv`/`blockbogons` (and DHCPv6 flags) on an interface, which OPNsense reads as off
  - `gateway_legacy_ignored` (error): gateways in the legacy `<gateways>` section while the Gateways model exists
  - `outbound_nat_family_mismatch` (error): an IPv4 outbound NAT rule with an IPv6 address or the reverse; pf rejects the whole ruleset
  - `icmp_type_any` (error): ICMP type `any` on a rule; pf rejects the whole ruleset
  - `mvc_section_missing_version` (warning): an OPNsense section without a `version` attribute, so OPNsense re-runs all of its migrations
  - `pfsense_match_rule`, `pfsense_nat64_rule` (warning): pfSense-only rule types
- dynamic (DHCP) gateways with an empty or `dynamic` gateway address are accepted
- warns on unsupported plugins and target compatibility gaps
- `--target-version` overrides profile selection for expected-schema checks
  (`<exact>.toml` -> `<major>.toml` -> `default.toml`)
- `--strict` also fails on warnings
- `--profiles-dir <path>`: override embedded profiles with files from `<path>/<platform>/<version>.toml`
- `--verbose`: show profile source (`Using profiles: ...` in text mode).

### `migrate-check`
Go/no-go pre-restore check with explicit PASS/FAIL items.

```bash
pfopn-convert migrate-check <FILE> --to <pfsense|opnsense> [--target-version <VERSION>] [--format <text|json>] [--strict] [--verbose]
```

- combines scan + verify checks into one report
- fails non-zero when required checks fail
- reports conversion-style counts (`interfaces`, `bridges`, `aliases`, `rules`, `routes`, `vpns`)
- includes advisory expected-schema baseline checks from profiles:
  - `pfopn-convert/profiles/pfsense/default.toml`
  - `pfopn-convert/profiles/opnsense/default.toml`
- `--target-version` overrides profile selection (`<exact>.toml` -> `<major>.toml` -> `default.toml`)
- `--strict` also fails when warnings exist
- `--profiles-dir <path>`: override embedded profiles with files from `<path>/<platform>/<version>.toml`
- `--verbose`: show profile + mapping sources (`Using profiles: ...`, `Using mappings: ...` in text mode).

## Support Status

Current support level by area:

| Area | Status |
|---|---|
| `system` | partial |
| `interfaces` | supported-with-checks |
| `filter` / `nat` | supported-with-checks (OPNsense 26.7+: converted to the new rule model) |
| `aliases` | supported-with-checks |
| `dhcpd` / `dhcpdv6` | supported-with-checks |
| `openvpn` | supported-with-checks |
| `ipsec` | supported-with-checks |
| `wireguard` | supported-with-checks |
| `tailscale` | supported-with-checks |
| `gateways` | supported-with-checks |
| `staticroutes` | supported-with-checks |
| `ifgroups` | supported-with-checks |
| `unbound` (DNS Resolver) | supported-with-checks (pfSense → OPNsense: general/advanced settings, host overrides and aliases, domain overrides, access lists) |
| `syslog` (remote logging) | supported (pfSense → OPNsense: remote servers become Syslog destinations) |
| Zabbix agent, node_exporter, QEMU guest agent | supported when the OPNsense plugin is installed in the baseline (see [Plugins](#plugins)) |
| pfBlockerNG | not supported (no OPNsense equivalent; its floating rules are removed) |
| packages/plugins (general) | partial |

`scan` is the authoritative first-run readiness report for what is supported vs requires manual review in a given file.

Source and target versions this fork was developed against:

- pfSense CE 2.8.1 (config version 24.0) and 2.9.0 (config version 24.6)
- OPNsense 26.1 and 26.7 baselines (checked against OPNsense 26.7.8 source)

A pfSense 2.9.0 config was converted, restored and taken into production on OPNsense 26.7.8; see [Tested migration](#tested-migration) for what was verified. Test in a VM first.

### Known limitations

- **pfBlockerNG** is not converted. Its floating rules are removed; other rules that reference `pfB_*` aliases will point to aliases that do not exist on OPNsense.
- **pfSense `match` and NAT64 rules** stay in the old rule format on 26.7 targets (still enforced, not editable in the GUI).
- **Limiters, queues, OS fingerprint and DSCP** settings on rules are dropped (a warning is printed for each).
- **1:1 NAT with a dynamic external address** (`wanip` and similar) is skipped.
- **Alias per-entry descriptions** (pfSense `detail`) are dropped, and `url_ports`/`urltable_ports` aliases become empty port aliases, as in OPNsense's own migration.
- **Port forwards** lose their link to the filter rule on 26.7 (the rule stays).
- **IPsec phase 2** uses OPNsense's default ESP proposals; pfSense's per-tunnel encryption settings are not mapped.
- **Kea client IDs** from pfSense static mappings are not transferred.
- **pfSense-only `system` settings** (for example `earlyshellcmd`, `pkg_repo_conf_path`) are carried over; OPNsense ignores them. Time server names are kept as they are (for example `0.pfsense.pool.ntp.org`).
- **DNS Resolver:** custom options, the Python module (pfBlockerNG DNSBL) and the DNS over TLS service for clients are not converted (warnings are printed).
- **Remote syslog:** pfSense's per-category selection becomes "all programs" (a warning is printed); the source address is not converted.
- **Shellcmd** commands other than starting the QEMU guest agent are not converted; use `/usr/local/etc/rc.syshook.d/` scripts.

## Sharing configs safely

Config backups contain password hashes, private keys, pre-shared keys, public IP addresses and domain names. Before sharing a backup (for example to report a conversion problem), anonymize it with `tools/sanitize_config.py` (Python 3, no dependencies):

```bash
python3 tools/sanitize_config.py \
  --out-dir sanitized/ \
  --salt-file .sanitize-salt \
  --term mycompany --term customername \
  config-*.xml
```

- Replaces secrets (passwords, hashes, certificates and keys, OpenVPN/IPsec/WireGuard keys, PSKs, SNMP communities, API keys and tokens) with fake values of the same format.
- Replaces public IPv4 addresses (with a `198.18.0.0/15` address) and public IPv6 addresses (with a `2001:db8::/32` address), keeping subnets consistent; the domains from `<system><domain>`, every `--term` word, and e-mail addresses are replaced as well.
- Each value always maps to the same replacement, so references between sections still match. Use `--salt-file` to keep the mapping identical across runs.
- Base64-encoded package text (for example HAProxy, Zabbix and Suricata settings, and DHCP lease backups) is redacted; Unbound custom options and pfBlockerNG lists are decoded, anonymized and re-encoded.
- Prints only tag names and counts, never values, and ends with a leak check that fails if any original secret, public IP, domain or term is still present.

Third-party domain names (for example customer domains in rule descriptions) are only replaced if you pass them with `--term`. Review the output before sharing it.

Mappings and plugin matrix are embedded by default.
You can override section mappings with `--mappings-file` or `--mappings-dir`.
`--mappings-file` and `--mappings-dir` are mutually exclusive.
Profiles can be overridden with `--profiles-dir`.

Plain English:
- “Mappings” are just a small list that tells the tool how section names line up between pfSense and OPNsense.
- “Profiles” are simple rules for what sections/fields must exist for a given platform/version.

## Example Workflow

1. Inventory sections and naming gaps:
```bash
pfopn-convert sections pfsense.xml opnsense.xml
```

2. Get high-level and per-section counts:
```bash
pfopn-convert diff pfsense.xml opnsense.xml --summary --section-summary
```

3. Export machine-readable report and plan:
```bash
pfopn-convert diff pfsense.xml opnsense.xml --format json --plan /tmp/plan.json > /tmp/report.json
```

4. Produce safe insert-only merged output for review:
```bash
pfopn-convert diff pfsense.xml opnsense.xml --output /tmp/merged.xml --merge-to right
```

## Output Semantics

Diff counts:

- `modified`: same path exists in both, values differ
- `only_left`: path exists only in first file
- `only_right`: path exists only in second file
- `structural`: structure/tag mismatch

Analysis counts:

- `insert_left_to_right`: safe insert candidate
- `insert_right_to_left`: safe insert candidate
- `conflict_manual`: requires manual or handler-driven mapping
- `noop`: no action required

Backend metadata:

- summary output includes `left_backend`, `right_backend`, and `backend_transition`
- `inspect --detect` includes `version_source`, `version_confidence`, `dhcp_backend`, and `backend_reason`

## Support

If this tool saves you time, feel free to buy me a coffee:

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-support-yellow?style=flat&logo=buy-me-a-coffee)](https://buymeacoffee.com/sheridans)
