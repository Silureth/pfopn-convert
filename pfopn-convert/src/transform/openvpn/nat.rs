//! Outbound NAT for converted OpenVPN servers.
//!
//! pfSense's automatic outbound NAT covers every enabled OpenVPN server's
//! tunnel network on each interface with a gateway
//! (`filter_nat_rules_automatic_tonathosts()`). OPNsense 26.7 only adds the
//! tunnel networks of *legacy* servers (`openvpn_get_default_nat_outbound_networks()`);
//! servers in the `OPNsense/OpenVPN` model are not covered unless their
//! device is assigned as an interface. Without a rule, clients that send all
//! traffic through the tunnel (redirect-gateway) lose internet access.
//!
//! In automatic or hybrid mode, one outbound rule per tunnel network and
//! gateway interface is added, the same rule pfSense generated. Automatic
//! mode is switched to hybrid, which keeps OPNsense's automatic rules and
//! also applies these. Manual mode is left alone: pfSense did not add
//! anything there either.

use xml_diff_core::XmlNode;

#[derive(Debug, Default)]
pub struct OutboundNatReport {
    /// "network -> interface" for each rule added.
    pub added: Vec<String>,
    pub switched_to_hybrid: bool,
}

pub fn outbound_nat_for_tunnels(out: &mut XmlNode) -> OutboundNatReport {
    let mut report = OutboundNatReport::default();

    let tunnels: Vec<(String, String)> = out
        .get_child("OPNsense")
        .and_then(|o| o.get_child("OpenVPN"))
        .and_then(|o| o.get_child("Instances"))
        .map(|instances| {
            instances
                .get_children("Instance")
                .into_iter()
                .filter(|i| text(i, "role") == "server" && text(i, "enabled") == "1")
                .filter_map(|i| {
                    let network = text(i, "server");
                    is_ipv4_cidr(&network).then(|| (network, text(i, "description")))
                })
                .collect()
        })
        .unwrap_or_default();
    if tunnels.is_empty() {
        return report;
    }

    let gateway_ifaces: Vec<(String, String)> = out
        .get_child("interfaces")
        .map(|ifaces| {
            ifaces
                .children
                .iter()
                .filter(|i| has_gateway(i))
                .map(|i| {
                    let descr = text(i, "descr");
                    let label = if descr.is_empty() {
                        i.tag.to_ascii_uppercase()
                    } else {
                        descr
                    };
                    (i.tag.clone(), label)
                })
                .collect()
        })
        .unwrap_or_default();
    if gateway_ifaces.is_empty() {
        return report;
    }

    let nat = ensure_child_mut(out, "nat");
    let outbound = ensure_child_mut(nat, "outbound");
    let mode = text(outbound, "mode");
    match mode.as_str() {
        "" | "automatic" => {
            set_text(outbound, "mode", "hybrid");
            report.switched_to_hybrid = true;
        }
        "hybrid" => {}
        _ => return report,
    }

    for (network, label) in &tunnels {
        for (iface, iface_label) in &gateway_ifaces {
            let exists = outbound.get_children("rule").iter().any(|r| {
                text(r, "interface") == *iface
                    && r.get_text(&["source", "network"]).map(str::trim) == Some(network.as_str())
            });
            if exists {
                continue;
            }
            let name = if label.is_empty() {
                "OpenVPN server".to_string()
            } else {
                format!("OpenVPN {label}")
            };
            outbound.children.push(nat_rule(
                iface,
                network,
                &format!("{name} to {iface_label} (pfSense automatic rule)"),
            ));
            report.added.push(format!("{network} -> {iface}"));
        }
    }
    report
}

/// pfSense's `interface_has_gateway()` for the cases that matter here.
fn has_gateway(iface: &XmlNode) -> bool {
    let enabled = iface
        .get_child("enable")
        .map(|e| !matches!(e.text.as_deref().map(str::trim), Some("0")))
        .unwrap_or(false);
    if !enabled {
        return false;
    }
    let device = text(iface, "if");
    if device.starts_with("ovpn") || device.starts_with("ipsec") {
        return false;
    }
    !text(iface, "gateway").is_empty()
        || matches!(
            text(iface, "ipaddr").as_str(),
            "dhcp" | "pppoe" | "pptp" | "l2tp" | "ppp"
        )
}

/// Same shape as pfSense's "Auto created rule"; the empty target means the
/// interface address.
fn nat_rule(iface: &str, network: &str, descr: &str) -> XmlNode {
    let mut rule = XmlNode::new("rule");
    push(&mut rule, "interface", iface);
    let mut source = XmlNode::new("source");
    push(&mut source, "network", network);
    rule.children.push(source);
    push(&mut rule, "sourceport", "");
    let mut destination = XmlNode::new("destination");
    destination.children.push(XmlNode::new("any"));
    rule.children.push(destination);
    push(&mut rule, "target", "");
    push(&mut rule, "natport", "");
    push(&mut rule, "descr", descr);
    rule
}

fn is_ipv4_cidr(value: &str) -> bool {
    value
        .split_once('/')
        .map(|(ip, bits)| {
            ip.parse::<std::net::Ipv4Addr>().is_ok()
                && bits.parse::<u8>().map(|b| b <= 32).unwrap_or(false)
        })
        .unwrap_or(false)
}

fn text(node: &XmlNode, tag: &str) -> String {
    node.get_text(&[tag])
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

fn push(parent: &mut XmlNode, tag: &str, value: &str) {
    let mut child = XmlNode::new(tag);
    child.text = Some(value.to_string());
    parent.children.push(child);
}

fn set_text(node: &mut XmlNode, tag: &str, value: &str) {
    match node.children.iter_mut().find(|c| c.tag == tag) {
        Some(child) => child.text = Some(value.to_string()),
        None => push(node, tag, value),
    }
}

fn ensure_child_mut<'a>(node: &'a mut XmlNode, tag: &str) -> &'a mut XmlNode {
    let idx = match node.children.iter().position(|c| c.tag == tag) {
        Some(idx) => idx,
        None => {
            node.children.push(XmlNode::new(tag));
            node.children.len() - 1
        }
    };
    &mut node.children[idx]
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::outbound_nat_for_tunnels;

    const INSTANCES: &str = r#"<OPNsense><OpenVPN><Instances>
        <Instance uuid="a"><role>server</role><enabled>1</enabled><server>10.8.0.0/24</server><description>RA</description></Instance>
        <Instance uuid="b"><role>server</role><enabled>0</enabled><server>10.9.0.0/24</server></Instance>
      </Instances></OpenVPN></OPNsense>"#;
    const INTERFACES: &str = r#"<interfaces>
        <wan><enable>1</enable><if>vtnet0</if><ipaddr>203.0.113.2</ipaddr><gateway>WANGW</gateway></wan>
        <lan><enable>1</enable><if>vtnet1</if><ipaddr>10.0.0.1</ipaddr></lan>
        <opt1><enable>1</enable><if>vtnet2</if><descr>WAN2</descr><ipaddr>dhcp</ipaddr></opt1>
        <opt2><if>vtnet3</if><ipaddr>dhcp</ipaddr></opt2>
      </interfaces>"#;

    fn config(nat: &str) -> xml_diff_core::XmlNode {
        parse(format!("<opnsense>{INTERFACES}{INSTANCES}{nat}</opnsense>").as_bytes()).unwrap()
    }

    #[test]
    fn hybrid_gets_one_rule_per_gateway_interface() {
        let mut out = config(
            "<nat><outbound><mode>hybrid</mode><rule><interface>wan</interface><source><network>10.0.0.0/24</network></source></rule></outbound></nat>",
        );
        let report = outbound_nat_for_tunnels(&mut out);
        assert_eq!(
            report.added,
            vec!["10.8.0.0/24 -> wan", "10.8.0.0/24 -> opt1"]
        );
        assert!(!report.switched_to_hybrid);
        let rules = out
            .get_child("nat")
            .unwrap()
            .get_child("outbound")
            .unwrap()
            .get_children("rule");
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[2].get_text(&["interface"]), Some("opt1"));
        assert_eq!(
            rules[2].get_text(&["source", "network"]),
            Some("10.8.0.0/24")
        );
        assert!(rules[2]
            .get_child("destination")
            .unwrap()
            .get_child("any")
            .is_some());

        // Running again adds nothing.
        assert!(outbound_nat_for_tunnels(&mut out).added.is_empty());
    }

    #[test]
    fn automatic_becomes_hybrid_and_manual_is_untouched() {
        let mut out = config("");
        let report = outbound_nat_for_tunnels(&mut out);
        assert!(report.switched_to_hybrid);
        assert_eq!(report.added.len(), 2);
        assert_eq!(out.get_text(&["nat", "outbound", "mode"]), Some("hybrid"));

        let mut manual = config("<nat><outbound><mode>advanced</mode></outbound></nat>");
        let report = outbound_nat_for_tunnels(&mut manual);
        assert!(report.added.is_empty());
        assert!(manual
            .get_child("nat")
            .unwrap()
            .get_child("outbound")
            .unwrap()
            .get_children("rule")
            .is_empty());
    }
}
