# pfopn-convert

![CI](https://github.com/Silureth/pfopn-convert/actions/workflows/ci.yml/badge.svg)
![Release](https://img.shields.io/github/v/release/Silureth/pfopn-convert?display_name=tag)

Converts a pfSense CE config backup into an OPNsense 26.7 config that can be restored on a fresh OPNsense install, and checks it before the restore.

> This is a fork of [sheridans/pfopn-convert](https://github.com/sheridans/pfopn-convert) by Sheridan Computers Limited, who wrote the converter this fork builds on (see [Credits](#credits)). This fork covers **pfSense CE (config version 24.6) → OPNsense 26.7** only. It fixes conversion bugs that changed firewall behaviour silently, writes OPNsense 26.7's new rule format, and converts OpenVPN servers, IPsec site-to-site tunnels, the DNS Resolver, remote syslog and common plugins. It was used for three production cutovers to OPNsense 26.7.8; see [Tested migration](#tested-migration).
>
> Report problems with this fork [here](https://github.com/Silureth/pfopn-convert/issues), not to the original project.

> WARNING: A restore replaces the destination's whole configuration and can cut you off from the network. Restore only onto a fresh OPNsense install, and keep a way back (a VM snapshot, or the old firewall ready to start).

## Install

Prebuilt binaries for Linux (x86_64, aarch64), FreeBSD, macOS and Windows are on the [Releases](https://github.com/Silureth/pfopn-convert/releases) page, with a `SHA256SUMS` file. Changes per version are in [CHANGELOG.md](CHANGELOG.md).

To build from source, you need a Rust toolchain (for example via [rustup](https://rustup.rs)):

```bash
cargo build --release
```

The binary is `target/release/pfopn-convert`.

## Migration workflow

`convert` takes two config exports: the **source** (the pfSense box) and a **baseline** (a fresh OPNsense install of the version you will run). It writes the source's settings into the baseline, so the output carries OPNsense's model versions and installed plugins.

The order used for the tested migrations:

1. Install OPNsense in the **exact version** you will run, and update it fully. Don't configure anything else on it: existing interfaces, bridges or gateways in the baseline can conflict with the converted ones.
2. Give it one network port per source interface, **in the same order**, and assign them all (`wan`, `lan`, `opt1`, …, including interfaces that are disabled on the source). Interfaces are matched by these names, not by device names (`igb0` on the source can become `vtnet0`); `convert` stops if one is missing from the baseline. Skip the setup wizard.
3. Install the OPNsense plugins the source needs (see [Plugins](#plugins)), without configuring them.
4. Export this config as the baseline, and take a snapshot (or a config backup) to roll back to.
5. Convert and check:

   ```bash
   pfopn-convert scan source-pfsense.xml --to opnsense
   pfopn-convert convert source-pfsense.xml --from pfsense --to opnsense \
     --target-file opnsense-baseline.xml --output converted.xml
   pfopn-convert verify converted.xml --to opnsense --strict
   ```

   Read every `info:` and `warning:` line `convert` prints and its `plugins:` report: they list everything that was converted differently, kept in the old format, or dropped. Options: `--pfblocker-feeds` for pfBlockerNG IP lists (see [Known limitations](#known-limitations)), `--legacy-rules` to keep the old rule format (see [OPNsense 26.7 targets](#opnsense-267-targets)), `--no-separator-categories` to drop separators instead of converting them (see [Separators](#separators)).
6. Restore the output **while only an isolated network is connected**: it carries the source's IP addresses. Disconnect (or move) every other port first.
7. After the reboot, check the ruleset from the shell: `pfctl -nf /tmp/rules.debug`. A single invalid line stops pf from loading the whole ruleset, and the GUI only shows the first error.
8. Check the GUI (rules, NAT, gateways, VPNs, services). If something is wrong, roll back to the snapshot, fix, convert again.
9. Cut over: shut the source down and move the destination's ports to the real networks. Copying the source's MAC addresses keeps upstream ARP caches working; then never run both at once.
10. After the first boot on the real networks, **reset the firewall states** once (Diagnostics → States → Reset, or `pfctl -F states`). Devices that send UDP without pause (syslog, NetFlow, SNMP traps) can create states while the boot ruleset is still active, before the port forwards load. Those states never expire while the traffic continues, so the forward is never applied: the packets go to the firewall itself and are dropped, and restarting the sender doesn't help. To clear single senders: `pfctl -k <sender-ip>`.
11. Check the URL table aliases (pfBlockerNG lists with `--pfblocker-feeds`, or your own): `pfctl -t <alias> -T show | wc -l` must not be 0. Their first download can run at boot before DNS works, and OPNsense only tries again when the alias's refresh interval runs out (up to a day). To fetch them now, delete the alias's files in `/var/db/aliastables/` (`<alias>.txt`, `<alias>.self.txt`, `<alias>.md5.txt`) and run `configctl filter refresh_aliases`.
12. Check the VPNs: site-to-site tunnels come up, VPN clients can log in. If the VPN peers cannot be reached from the isolated network in step 6, this is only possible after the cutover; keep the old firewall ready to start again.

## Tested migration

This fork was used to migrate three production pfSense CE (config version 24.6) firewalls to OPNsense 26.7.8:

- **multi-WAN box:** policy routing, about 100 rules, 58 port forwards, virtual IPs, DNS Resolver, remote syslog, Zabbix agent and node_exporter;
- **VPN box:** an OpenVPN server with LDAP users, two IKEv2 site-to-site tunnels and a Zabbix proxy;
- **two-WAN box:** port forwards grouped by separators, a static route, OpenVPN and IPsec, SNMP, pfBlockerNG IP lists, Zabbix proxy.

What was verified on each box, and what was not exercised, is in [docs/tested-migrations.md](docs/tested-migrations.md).

## Changes in this fork

- **Fixes for silent behaviour changes** in the original converter: disabled rules that became active, flipped NOT matches, empty aliases, DHCP or "Block private/bogon networks" switched the wrong way, missing gateways, a replaced GUI certificate, and more. The full list, with the effect of each on the firewall, is in [docs/fixes.md](docs/fixes.md).
- **pfSense behaviour OPNsense does not reproduce on its own:** automatic IPsec firewall rules, outbound NAT for OpenVPN tunnel networks, "NAT + proxy" reflection, IPsec keep-alive, reply-to for hosts in an interface's own subnet. Also in [docs/fixes.md](docs/fixes.md).
- **OPNsense 26.7 rule model:** firewall rules, outbound NAT, 1:1 NAT and NPt in the new format (see [OPNsense 26.7 targets](#opnsense-267-targets)).
- **New conversions:** OpenVPN servers and IPsec tunnels in full, LDAP servers, DNS Resolver, remote syslog and plugins (see [Plugins](#plugins)).
- **`verify` checks** for most of the problems above (see [`verify`](docs/commands.md#verify)).
- [`tools/sanitize_config.py`](#sharing-configs-safely) to anonymize config backups before sharing them.

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
| Zabbix Proxy 6/7 | `os-zabbix6-proxy` / `os-zabbix7-proxy` | enabled, active/passive mode, server and port, hostname, listen address/port, source address, config frequency, trappers, PSK encryption. TrapperTimeout, the SNMP trapper, advanced parameters and certificate TLS have no plugin setting (warnings). |
| SNMP daemon (built into pfSense) | `os-net-snmp` | enabled, read-only community, location, contact, bind address (an interface becomes its IPv4 address). Always port 161; no read-write community, no traps. pfSense's pf, netgraph and regex MIB modules have no equivalent, so items that read them (for example pf states) stop working (warning). |
| OpenVPN Client Export | built in (VPN → OpenVPN → Client Export) | nothing to convert |
| node_exporter | `os-node_exporter` | enabled, listen interface (as its IP address), port, collectors. `boottime`, `textfile` and extra flags have no equivalent. |
| Shellcmd `service qemu-guest-agent start` | `os-qemu-guest-agent` | enabled. Other Shellcmd commands are listed; use `/usr/local/etc/rc.syshook.d/` scripts. |
| pfBlockerNG | none | DNSBL not converted, use Unbound DNS blocklists. IP lists: with `--pfblocker-feeds`, their `pfB_*` aliases download the original feeds |

After `convert`, a `plugins:` report lists each plugin as `converted`, `NOT INSTALLED` (not in the baseline, settings not converted) or `no equivalent`. The plugins the source needs are also added to the configured-plugin list (`system/firmware/plugins`), so after a restore OPNsense shows missing ones under System → Firmware → Plugins and can install them.

To convert plugin settings: install the plugins on the destination, export the baseline, then run `convert`.

The DNS Resolver and remote syslog conversions follow OPNsense's own legacy migrations, but read pfSense's empty-element flags as set (the migrations would turn DNSSEC and the hardening options off) and keep domain-override domains (OPNsense's import drops them).

## Separators

OPNsense has no rule separators. `convert` turns pfSense's separators into OPNsense **rule categories**, with the separator's text as the name and its colour; `--no-separator-categories` turns this off. On OPNsense 26.7, switch the rule pages to the **tree view** to see the rules grouped under their category, as under a separator.

The rule:

1. pfSense keeps separators per list: one per firewall rule tab (each interface, and floating rules) and one for the port-forward list. A separator sits above a rule position in its list, counted among that list's own rules.
2. A separator gives its category to every rule below it, down to the next separator in the same list. Rules above the first separator get no category.
3. A separator with no rules below it (another separator follows directly, or it is below the last rule) creates no category; `convert` lists it.
4. A port forward's category is also given to the filter rule linked to it (pfSense's "associated filter rule"), unless a separator on the rule's own tab already gave it one. OPNsense 26.7 drops that link, so the category keeps the two together.
5. Separators with the same text share one category, also across lists. The first one sets the colour: blue (info), orange (warning), red (danger), green (success).
6. Commas in the text are replaced by spaces, because OPNsense stores a port forward's categories as a comma-separated list. A separator without text is named after its list and position, for example `lan section 2`. A category that already exists in the baseline is reused.
7. Rules the converter adds next to a rule are copies of it and keep its category (the reply-to copies and the "no policy routing to this firewall" rules). The IPsec rules it adds at the top get none.

`convert` prints each category with its number of rules per list. A separator that was only a visual break, or a "rest of the rules" marker, becomes a category like any other; delete or rename it in Firewall → Categories after the restore.

## Commands

| Command | What it does |
|---|---|
| [`scan`](docs/commands.md#scan) | readiness report for the source config: platform, version, sections that are converted or need a manual review, packages |
| [`convert`](docs/commands.md#convert) | builds the OPNsense config from the source and the baseline |
| [`verify`](docs/commands.md#verify) | checks a converted config before the restore; `--strict` also fails on warnings |

Options and checks are in [docs/commands.md](docs/commands.md).

The binary also still contains the original tool's `diff`, `sections`, `inspect` and `migrate-check` commands and its OPNsense → pfSense direction. This fork does not document, test or support them; they are described in the [original project's README](https://github.com/sheridans/pfopn-convert/blob/c074efc3a212f6ae7a55efb229bc11652a748fbf/README.md).

## Support status

pfSense → OPNsense, by area. "Used live" means the area was in one of the three [tested migrations](#tested-migration) and was checked after the cutover. The other areas are covered by unit tests and `verify` only.

| Area | Converted | Used live |
|---|---|---|
| System settings | partial: general settings, users, certificates, NTP; pfSense-only settings are carried over and ignored | yes |
| Interfaces, virtual IPs | yes; VLANs, bridges and interface groups too | yes (no VLANs, bridges or groups) |
| Firewall rules, port forwards, outbound NAT | yes; on 26.7+ in the new rule model | yes |
| 1:1 NAT, NPt | yes; on 26.7+ in the new rule model | no |
| Aliases, gateways | yes | yes |
| Static routes | yes | yes |
| DHCP (ISC → Kea or ISC) | yes | no |
| DNS Resolver (Unbound) | general and advanced settings, host and domain overrides, access lists | yes |
| Remote syslog | remote servers become Syslog destinations | yes |
| LDAP authentication servers | yes | yes |
| OpenVPN | servers and client-specific overrides; not clients or shared-key servers | yes (server with LDAP users) |
| IPsec | site-to-site tunnels; not mobile tunnels or VTI | yes (IKEv2 tunnels, also with split connections) |
| WireGuard | yes | no |
| Tailscale | yes (the original converter's code, unchanged) | no |
| Zabbix agent and proxy, node_exporter, QEMU guest agent | when the plugin is installed in the baseline (see [Plugins](#plugins)) | yes |
| SNMP | to `os-net-snmp`, when the plugin is installed in the baseline (see [Plugins](#plugins)) | starts and listens; not polled (unused on the tested box) |
| pfBlockerNG | IP lists only, with `--pfblocker-feeds`; DNSBL and its floating rules are not | yes (IP lists) |
| Rule and port-forward separators | as categories (see [Separators](#separators)) | restored, not checked in the GUI |
| Other packages | no; `scan` and `convert` list them | |

Versions:

- **Source:** pfSense CE configs with config version 24.6 (pfSense 2.9.0 on the first box). pfSense's behaviour was checked against its public source, which ends at 2.7.2.
- **Destination:** OPNsense 26.7, checked against OPNsense 26.7.8's source; all three migrations went to 26.7.8. With an older baseline, rules stay in the old format (see [OPNsense 26.7 targets](#opnsense-267-targets)).

### Known limitations

- **pfBlockerNG** is not converted. Its floating rules are removed. Its IP lists become `pfB_<list>_v4|v6` URL table aliases that download from pfBlockerNG on the pfSense box (`https://127.0.0.1/pfblockerng/pfblockerng.php?...`), so on OPNsense they stay empty and the interface rules that use them match nothing (a warning is printed). With `--pfblocker-feeds`, each alias gets the feed URLs of its list instead and refreshes on the list's schedule. Disabled rows, GeoIP/ASN sources, gzip files and feeds known to be dead are skipped, and DShield and Spamhaus EDROP are swapped for their current URLs; each change is printed. An alias left without a feed is disabled. This is opt-in because the block rules start blocking once the aliases fill. The DNSBL part (Unbound Python module) is not converted; set up Services → Unbound DNS → Blocklist.
- **pfSense `match` and NAT64 rules** stay in the old rule format on 26.7 targets (still enforced, not editable in the GUI).
- **Limiters, queues, OS fingerprint and DSCP** settings on rules are dropped (a warning is printed for each).
- **1:1 NAT with a dynamic external address** (`wanip` and similar) is skipped.
- **Alias per-entry descriptions** (pfSense `detail`) are dropped, and `url_ports`/`urltable_ports` aliases become empty port aliases, as in OPNsense's own migration.
- **Port forwards** lose their link to the filter rule on 26.7 (the rule stays).
- **IPsec:** mobile (remote access) tunnels and route-based (VTI) phase 2 entries are not converted; they stay in the legacy section (warnings). Proposals OPNsense does not list (for example 3DES, GCM with short ICVs, a separate PRF) are dropped with a warning, keep-alive ping hosts are not converted (tunnels that had one start immediately instead, so they stay up as on pfSense), phase 2 NAT/BINAT is not converted, and AH phase 2 entries fall back to ESP.
- **OpenVPN:** clients and shared-key servers are not converted (they stay in the legacy section; warnings). Custom options, NetBIOS/WINS, compression and per-client connection limits have no instance setting (warnings).
- **Kea client IDs** from pfSense static mappings are not transferred.
- **pfSense-only `system` settings** (for example `earlyshellcmd`, `pkg_repo_conf_path`) are carried over; OPNsense ignores them. pfSense's NTP pool (`*.pfsense.pool.ntp.org`) is replaced by OPNsense's.
- **DNS Resolver:** custom options, the Python module (pfBlockerNG DNSBL) and the DNS over TLS service for clients are not converted (warnings are printed).
- **Remote syslog:** pfSense's per-category selection becomes "all programs" (a warning is printed); the source address is not converted.
- **Accented letters lost by pfSense:** pfSense stores some accented letters that are not in Latin-1 (for example Hungarian ő and ű) as a plain `?`, so a separator "Külsők" is "Kuls?k" in the backup, and the letter cannot be recovered from it. `convert` warns about every description, separator text and alias detail with a `?` between two letters. Fix them on pfSense or in the exported XML before converting, or in OPNsense after the restore.
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

## Credits

pfopn-convert was written by **Sheridan Computers Limited** ([sheridans/pfopn-convert](https://github.com/sheridans/pfopn-convert), v0.1.0). This fork keeps its architecture: the XML diff and merge engine (`xml-diff-core`), the baseline-merge `convert` pipeline and interface mapping, the section mappings and validation profiles, the `scan`, `verify`, `diff`, `sections`, `inspect` and `migrate-check` commands, and the conversions this fork did not change (for example Tailscale and the OPNsense → pfSense direction). The original documentation is the [original project's README](https://github.com/sheridans/pfopn-convert/blob/c074efc3a212f6ae7a55efb229bc11652a748fbf/README.md). The changes made in this fork are listed in [CHANGELOG.md](CHANGELOG.md) and [docs/fixes.md](docs/fixes.md).

The original code (copyright Sheridan Computers Limited) and this fork's changes (copyright Herczeg Szilard, [Silureth](https://github.com/Silureth)) are distributed under the original BSD 2-clause license ([LICENSE](LICENSE)), which release archives from v0.4.0 on contain next to the binary.

To support the original author:

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-support-yellow?style=flat&logo=buy-me-a-coffee)](https://buymeacoffee.com/sheridans)
