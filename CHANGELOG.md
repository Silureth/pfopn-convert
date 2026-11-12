# Changelog

## v0.5.0 (2026-11-12)

Fixes from a third production migration (two WANs, OpenVPN with LDAP, IPsec, SNMP, pfBlockerNG IP lists, separators). The most important one: LDAP bind passwords with special characters arrived encoded.

### Fixes

- Values pfSense stores in CDATA (LDAP bind DN and password, base DN, extended query, user names, passwords, ...) are HTML-decoded once, as pfSense's own config reader does. Before, a bind password with `<`, `>`, `&` or `"` arrived encoded (`&lt;`), and LDAP logins (OpenVPN, GUI) failed with "Invalid credentials". **Check LDAP logins on boxes migrated with earlier versions**; entering the bind password again under System > Access > Servers fixes them.
- reply-to: on the default gateway's interface, rules whose source cannot be resolved (host names, URL tables) get "Disable reply-to" instead of a warning. Without reply-to their replies take the default route, which is the same gateway, or go directly to hosts in the subnet, as on pfSense. Not done when default gateway switching is on.

### Conversion

- pfSense's SNMP daemon is converted to the `os-net-snmp` plugin when it is installed in the baseline: community, location, contact and bind address. A warning lists the pfSense MIB modules Net-SNMP has no equivalent for (pf, netgraph, regex). `scan` and `verify` know the plugin.

### Documentation

- `docs/tested-migrations.md` and the README describe the third production migration.
- README workflow: check URL table aliases after the first boot on the real network; their first download can fail before DNS works, and OPNsense only retries after the refresh interval.

## v0.4.0 (2026-11-12)

pfSense's rule separators are kept as OPNsense rule categories, `convert` warns about accented letters pfSense lost in the backup, and the README now describes only this fork.

### Conversion

- pfSense's rule and port-forward separators become OPNsense rule categories, shown as groups in the 26.7 rule pages' tree view; a port forward's category also goes to its linked filter rule. The exact rule is in the README's [Separators](https://github.com/Silureth/pfopn-convert#separators) section. `--no-separator-categories` turns this off. Before, the separators were copied into a section OPNsense ignores.
- `convert` warns about descriptions, separator texts and alias details in which pfSense stored an accented letter as `?` (letters outside Latin-1, such as ő and ű, are lost when pfSense saves them).
- `scan` lists the DNS Resolver (`unbound`) and remote syslog (`syslog`) of a pfSense config as supported; it asked for a manual review although `convert` converts both.

### Documentation and releases

- The README only describes this fork and credits the original project in detail. The fix list, the tested migrations and the reference for `scan`, `convert` and `verify` moved to `docs/`. The original tool's other commands and its OPNsense → pfSense direction are left to the [original project's README](https://github.com/sheridans/pfopn-convert/blob/c074efc3a212f6ae7a55efb229bc11652a748fbf/README.md). The support table says which areas were used in a production migration.
- Release archives contain the `LICENSE` file next to the binary, as the original project's BSD license requires.

## v0.3.0 (2026-11-11)

VPN conversions, checked against pfSense's and OPNsense 26.7.8's code, and fixes from a second production migration: a pfSense box with an OpenVPN server (LDAP users), two IKEv2 site-to-site tunnels and a Zabbix proxy, converted to OPNsense 26.7.8 and verified live (see [Tested migration](https://github.com/Silureth/pfopn-convert#tested-migration)). OPNsense 26.7 only runs legacy OpenVPN servers and IPsec tunnels with the os-openvpn-legacy / os-strongswan-legacy plugins, so both are now converted completely and the legacy copies removed.

Boxes already migrated with v0.2.0 do not need a new conversion. Check them for the two firewall problems fixed here (reply-to for hosts in a gateway interface's own subnet, and "NAT + proxy" reflection on port forwards); both can be fixed by hand.

### OpenVPN

- Servers become complete instances: LDAP/local user authentication with the client-certificate mode pfSense used, the TLS key (auth or crypt) as an OPNsense static key, data ciphers and digest (checked against OPNsense's lists), bind address, redirect-gateway, client-to-client, duplicate CN, float, keepalive, CRL, IPv6 tunnel and routes.
- Client-specific overrides are converted as OPNsense's own migration does.
- Fields OPNsense's model does not have (custom options, NetBIOS) are no longer written; they are reported instead. `register-dns` is no longer pushed twice.
- Clients and shared-key servers are not converted (warning; they stay in the legacy section).
- Outbound NAT rules are added for each server's tunnel network on every gateway interface, as pfSense's automatic outbound NAT did; OPNsense's automatic rules only cover legacy servers. Automatic mode becomes hybrid; manual mode is left alone.

### IPsec

- Tunnels are converted the way pfSense builds them: IKE and ESP proposals per encryption item (renamed to OPNsense's spelling and checked against its list), IKE version, rekey/reauth/over time, DPD, start/close/DPD actions, IKE IDs, interface subnets as traffic selectors (`lan` used to become an empty selector), one merged child per IKEv2 tunnel unless "split connections" is set.
- Pre-shared keys are bound to the peer's ID; previously every key had an empty ID.
- `<ipsec><enable>` is set; without it OPNsense stops strongSwan.
- Firewall rules for IKE, NAT-T and ESP from each peer are added, as pfSense did automatically.
- The baseline's IPsec and Swanctl settings are kept instead of being replaced.
- Tunnels with a keep-alive ping host start immediately (start action "start"). pfSense pinged them up as soon as IPsec started; on demand, they stayed down after a cutover until traffic or a manual connect.
- Mobile tunnels and VTI phase 2 entries are not converted (warning).

### Firewall

- pfSense's kernel sends replies to hosts in an interface's own subnet directly, even on rules with reply-to; OPNsense's sends them to the gateway, which drops them if it is a stateful firewall. Pass rules on gateway interfaces get a copy with "Disable reply-to" for the sources in that subnet (mixed aliases are split into an `<alias>_<if>_local` alias); rules whose source lies entirely in the subnet get "Disable reply-to" themselves. Aliases that cannot be resolved and DHCP interfaces are reported.

### Other

- Zabbix Proxy 6/7 → `os-zabbix6-proxy` / `os-zabbix7-proxy`.
- LDAP servers: pfSense's "STARTTLS Encrypt" is mapped to OPNsense's StartTLS (it became LDAPS); a disabled extended query is cleared.
- Port forwards with pfSense's "NAT + proxy" reflection are set to pure NAT (OPNsense's model only offers that), and "Automatic outbound NAT for Reflection" is switched on when an active rule used proxy mode, so clients in the target's own subnet keep working.
- `scan` knows Zabbix Proxy and the OpenVPN Client Export package.
- A baseline exported before its setup wizard was finished no longer makes the converted box open the wizard after every login (`trigger_initial_wizard` is dropped).

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
