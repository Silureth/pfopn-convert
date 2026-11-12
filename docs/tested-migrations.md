# Tested migrations

Three production pfSense firewalls were migrated to OPNsense with this fork. The problems found on the way are in [fixes.md](fixes.md).

## First box: multi-WAN, port forwards, plugins (v0.2.0)

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

Found after the cutover: TCP connections from hosts in one WAN's own subnet to services behind the firewall failed (see the reply-to row in [fixes.md](fixes.md)); v0.3.0 fixes this.

## Second box: OpenVPN, IPsec, Zabbix proxy (v0.3.0)

**Source:** pfSense CE (config version 24.6), Proxmox VM, 3 interfaces (WAN, LAN, one internal network). About 40 firewall rules, manual outbound NAT, port forwards with "NAT + proxy" reflection, an OpenVPN server with LDAP authentication (group restriction via extended query) and a TLS key, two IKEv2 site-to-site tunnels with keep-alive ping hosts (one of them to a pfSense box), and the packages Zabbix Agent 7, Zabbix Proxy 7, node_exporter, Shellcmd and OpenVPN Client Export.

**Destination:** OPNsense 26.7.8, plugins `os-openvpn-legacy`, `os-strongswan-legacy`, `os-zabbix7-agent`, `os-zabbix7-proxy`, `os-node_exporter` and `os-qemu-guest-agent` installed before the baseline export. The converted config was restored and cut over directly, with the old pfSense VM as rollback.

| Area | Result |
|---|---|
| OpenVPN | a client connects with its existing pfSense profile and an LDAP user |
| IPsec | both tunnels come up and pass traffic (after the start-action fix: they now start immediately) |
| Zabbix proxy | connects to the server with PSK; data arrives |
| Firewall, services | ruleset loads (`pfctl -nf` clean); all services start |

## Third box: two WANs, SNMP, pfBlockerNG, separators (v0.4.0 and later)

**Source:** pfSense CE (config version 24.6), Proxmox VM, 4 interfaces (2 WANs, LAN, one internal network). About 50 firewall rules (2 with policy routing), hybrid outbound NAT, 31 port forwards grouped by separators (7 with "NAT + proxy" reflection), 7 virtual IPs, a static route through a LAN gateway, an OpenVPN server with LDAP authentication and redirect-gateway, two IKEv2 site-to-site tunnels (one with split connections, one to the second box, already on OPNsense), the SNMP daemon, and the packages pfBlockerNG-devel (two IP lists), Zabbix Agent 7, Zabbix Proxy 7, node_exporter, Shellcmd, FreeRADIUS (installed, not configured) and OpenVPN Client Export.

**Destination:** OPNsense 26.7.8, plugins `os-net-snmp`, `os-node_exporter`, `os-qemu-guest-agent`, `os-zabbix7-agent` and `os-zabbix7-proxy` installed before the baseline export. Converted with `--pfblocker-feeds`; `verify` reported only rules that were already duplicated on pfSense. The converted config was restored and cut over directly, with the old pfSense VM as rollback.

| Area | Result |
|---|---|
| Firewall, routing | ruleset loads (`pfctl -nf` clean); default route and the static route are in place, so the firewall's own traffic to the remote office uses its LAN address and the tunnel |
| OpenVPN | the client connects; LDAP logins failed until the bind password was entered again (pfSense stored its `<` HTML-encoded, see [fixes.md](fixes.md); fixed in the converter) |
| IPsec | both tunnels come up and pass traffic; the split-connection tunnel's children are installed |
| Port forwards | forwarded services are reachable |
| Zabbix proxy and agent | the proxy receives its configuration from the server and polls agents, also through the tunnel |
| Remote syslog | logs arrive in Elasticsearch |
| pfBlockerNG IP lists | load (thousands of entries) after a manual refresh; their first download at boot ran before DNS worked, see the README's migration workflow |
| SNMP, node_exporter | listen on the converted addresses |

Converted, but not checked separately: separators as categories in the GUI. SNMP was enabled on pfSense but nothing polled it, so the converted service only shows that it starts and listens.

## Not exercised

Not exercised by these migrations: OpenVPN clients and shared-key servers, mobile IPsec, WireGuard, DHCP (ISC/Kea), bridges, 1:1 NAT and NPt, the OPNsense → pfSense direction. Those conversions are covered by unit tests and `verify` only.
