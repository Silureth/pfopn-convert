//! pfSense settings that OPNsense reads with a different meaning.

use std::net::IpAddr;

use xml_diff_core::XmlNode;

/// Outcome of [`interface_address_refs`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct InterfaceAddressStats {
    /// "rule 'x': opt2 address -> 198.51.100.10"
    pub replaced: Vec<String>,
    /// References left as they are although the interface has virtual IPs
    /// (no static address to use).
    pub kept: Vec<String>,
}

/// "opt2 address" (`<network>opt2ip</network>`) in port forwards and
/// firewall rules.
///
/// pfSense writes it into pf as the interface's own address
/// (`get_interface_ip()`), OPNsense as `(vtnet3)`, which pf expands to every
/// address on the interface, virtual IPs (IP aliases, CARP) included. A port
/// forward to "opt2 address" then also catches traffic to every virtual IP on
/// opt2 and, being first, sends it to the wrong host.
///
/// On interfaces with IP alias or CARP virtual IPs the reference is replaced
/// by the interface's static address (IPv4, or IPv6 for inet6 rules).
/// Interfaces without virtual IPs keep the reference: there both mean the
/// same.
pub fn interface_address_refs(out: &mut XmlNode) -> InterfaceAddressStats {
    let mut stats = InterfaceAddressStats::default();
    let interfaces_with_vips = interfaces_with_vips(out);
    if interfaces_with_vips.is_empty() {
        return stats;
    }
    let addresses: Vec<(String, Option<String>, Option<String>)> = interfaces_with_vips
        .iter()
        .map(|name| {
            let iface = out.get_child("interfaces").and_then(|i| i.get_child(name));
            let static_ip = |tag: &str| {
                iface
                    .and_then(|i| i.get_text(&[tag]))
                    .map(str::trim)
                    .filter(|v| v.parse::<IpAddr>().is_ok())
                    .map(str::to_string)
            };
            (name.clone(), static_ip("ipaddr"), static_ip("ipaddrv6"))
        })
        .collect();

    for (section, kind) in [("nat", "port forward"), ("filter", "rule")] {
        let Some(parent) = out.children.iter_mut().find(|c| c.tag == section) else {
            continue;
        };
        for rule in parent.children.iter_mut().filter(|c| c.tag == "rule") {
            let family = rule
                .get_text(&["ipprotocol"])
                .map(str::trim)
                .unwrap_or("inet")
                .to_string();
            let descr = rule
                .get_text(&["descr"])
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            for side in ["source", "destination"] {
                let Some(end) = rule.children.iter_mut().find(|c| c.tag == side) else {
                    continue;
                };
                let Some(network) = end.children.iter_mut().find(|c| c.tag == "network") else {
                    continue;
                };
                let value = network.text.as_deref().map(str::trim).unwrap_or("");
                let Some(name) = value.strip_suffix("ip") else {
                    continue;
                };
                let Some((_, v4, v6)) = addresses.iter().find(|(n, _, _)| n == name) else {
                    continue;
                };
                let label = format!("{kind} '{descr}' ({side} {name} address)");
                let ip = match family.as_str() {
                    "inet" => v4,
                    "inet6" => v6,
                    _ => &None,
                };
                match ip {
                    Some(ip) => {
                        network.tag = "address".to_string();
                        network.text = Some(ip.clone());
                        stats.replaced.push(format!("{label} -> {ip}"));
                    }
                    None => stats.kept.push(label),
                }
            }
        }
    }
    stats
}

/// Interfaces that carry IP alias or CARP virtual IPs.
fn interfaces_with_vips(root: &XmlNode) -> Vec<String> {
    let mut names: Vec<String> = root
        .get_child("virtualip")
        .map(|v| v.get_children("vip"))
        .unwrap_or_default()
        .into_iter()
        .filter(|vip| {
            matches!(
                vip.get_text(&["mode"]).map(str::trim),
                Some("ipalias") | Some("carp")
            )
        })
        .filter_map(|vip| vip.get_text(&["interface"]).map(|i| i.trim().to_string()))
        .filter(|i| !i.is_empty())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Adaptive state timeouts with only one of start/end set.
///
/// pfSense applies them only when both are set (`filter.inc`), so one value
/// alone did nothing. OPNsense refuses to save Firewall → Settings → Advanced
/// until both or neither are set. Removes the lone value; returns it as
/// "adaptiveend=185000".
pub fn half_set_adaptive_timeouts(out: &mut XmlNode) -> Option<String> {
    let system = out.children.iter_mut().find(|c| c.tag == "system")?;
    let value = |system: &XmlNode, tag: &str| {
        system
            .get_text(&[tag])
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    };
    let start = value(system, "adaptivestart");
    let end = value(system, "adaptiveend");
    let lone = match (&start, &end) {
        (Some(v), None) => format!("adaptivestart={v}"),
        (None, Some(v)) => format!("adaptiveend={v}"),
        _ => return None,
    };
    system
        .children
        .retain(|c| c.tag != "adaptivestart" && c.tag != "adaptiveend");
    Some(lone)
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::{half_set_adaptive_timeouts, interface_address_refs};

    const CONFIG: &[u8] = br#"<opnsense>
        <interfaces>
          <opt2><ipaddr>198.51.100.10</ipaddr><subnet>27</subnet></opt2>
          <opt3><ipaddr>192.0.2.1</ipaddr></opt3>
          <wan><ipaddr>dhcp</ipaddr></wan>
        </interfaces>
        <virtualip>
          <vip><mode>ipalias</mode><interface>opt2</interface><subnet>198.51.100.12</subnet></vip>
          <vip><mode>ipalias</mode><interface>wan</interface><subnet>203.0.113.5</subnet></vip>
          <vip><mode>proxyarp</mode><interface>opt3</interface><subnet>192.0.2.9</subnet></vip>
        </virtualip>
        <nat>
          <rule><descr>web 2</descr><destination><network>opt2ip</network><port>443</port></destination></rule>
          <rule><descr>dyn</descr><destination><network>wanip</network><port>80</port></destination></rule>
        </nat>
        <filter>
          <rule><descr>sync</descr><destination><network>opt3ip</network></destination></rule>
          <rule><descr>v6</descr><ipprotocol>inet6</ipprotocol><destination><network>opt2ip</network></destination></rule>
        </filter>
        <system><adaptiveend>185000</adaptiveend><adaptivestart></adaptivestart></system>
    </opnsense>"#;

    #[test]
    fn interface_address_becomes_static_ip_where_vips_exist() {
        let mut out = parse(CONFIG).expect("parse");
        let stats = interface_address_refs(&mut out);
        let nat = out.get_child("nat").unwrap().get_children("rule");
        assert_eq!(
            nat[0].get_text(&["destination", "address"]),
            Some("198.51.100.10")
        );
        assert!(nat[0]
            .get_child("destination")
            .unwrap()
            .get_child("network")
            .is_none());
        // DHCP interface: nothing static to use.
        assert_eq!(nat[1].get_text(&["destination", "network"]), Some("wanip"));
        let filter = out.get_child("filter").unwrap().get_children("rule");
        // Only a proxy ARP VIP: the address means the same in both.
        assert_eq!(
            filter[0].get_text(&["destination", "network"]),
            Some("opt3ip")
        );
        // inet6 rule, no static IPv6 address.
        assert_eq!(
            filter[1].get_text(&["destination", "network"]),
            Some("opt2ip")
        );
        assert_eq!(stats.replaced.len(), 1);
        assert_eq!(stats.kept.len(), 2);
    }

    #[test]
    fn lone_adaptive_value_is_removed() {
        let mut out = parse(CONFIG).expect("parse");
        assert_eq!(
            half_set_adaptive_timeouts(&mut out).as_deref(),
            Some("adaptiveend=185000")
        );
        let system = out.get_child("system").unwrap();
        assert!(system.get_child("adaptiveend").is_none());
        assert!(system.get_child("adaptivestart").is_none());

        let mut both = parse(
            b"<opnsense><system><adaptivestart>1</adaptivestart><adaptiveend>2</adaptiveend></system></opnsense>",
        )
        .expect("parse");
        assert_eq!(half_set_adaptive_timeouts(&mut both), None);
        assert!(both
            .get_child("system")
            .unwrap()
            .get_child("adaptiveend")
            .is_some());
    }
}
