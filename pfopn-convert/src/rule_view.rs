//! A single view over firewall rules in both storage formats.
//!
//! Legacy rules live in `<filter><rule>`; OPNsense 26.7+ keeps them in the MVC
//! model (`<OPNsense><Firewall><Filter><rules><rule>`), which the converter
//! now writes. Verification checks were written against the legacy layout, so
//! this module presents MVC rules translated back into that layout (`type`,
//! `descr`, `<source><address|network|any|port|not>`, presence flags), letting
//! every check cover both formats without duplicating its logic.

use std::collections::BTreeSet;

use xml_diff_core::XmlNode;

use crate::verify_interfaces::collect_defined_interface_names;

/// All filter rules: legacy ones as-is, followed by MVC rules in legacy shape.
pub fn filter_rules(root: &XmlNode) -> Vec<XmlNode> {
    let mut out: Vec<XmlNode> = root
        .get_child("filter")
        .map(|f| f.get_children("rule").into_iter().cloned().collect())
        .unwrap_or_default();
    let mvc = root
        .get_child("OPNsense")
        .and_then(|n| n.get_child("Firewall"))
        .and_then(|n| n.get_child("Filter"))
        .and_then(|n| n.get_child("rules"))
        .map(|n| n.get_children("rule"))
        .unwrap_or_default();
    if mvc.is_empty() {
        return out;
    }
    let interfaces = collect_defined_interface_names(root);
    out.extend(
        mvc.into_iter()
            .map(|rule| mvc_to_legacy_shape(rule, &interfaces)),
    );
    out
}

fn mvc_to_legacy_shape(rule: &XmlNode, interfaces: &BTreeSet<String>) -> XmlNode {
    let text = |tag: &str| {
        rule.get_text(&[tag])
            .map(str::trim)
            .unwrap_or("")
            .to_string()
    };
    let flag = |tag: &str| text(tag) == "1";
    let mut node = XmlNode::new("rule");
    node.attributes = rule.attributes.clone();

    if let Some(uuid) = rule.attributes.get("uuid") {
        push(&mut node, "tracker", uuid);
    }
    push(&mut node, "type", &text("action"));
    push(&mut node, "interface", &text("interface"));
    push(&mut node, "ipprotocol", &text("ipprotocol"));
    let protocol = text("protocol").to_ascii_lowercase();
    if protocol != "any" && !protocol.is_empty() {
        push(&mut node, "protocol", &protocol);
    }
    push(&mut node, "direction", &text("direction"));
    for tag in ["gateway", "sched"] {
        let value = text(tag);
        if !value.is_empty() {
            push(&mut node, tag, &value);
        }
    }
    push(&mut node, "descr", &text("description"));
    if text("enabled") == "0" {
        push(&mut node, "disabled", "1");
    }
    if flag("quick") {
        push(&mut node, "quick", "1");
    }
    if flag("log") {
        push(&mut node, "log", "1");
    }
    // MVC has no floating flag; rules on several (or no) interfaces are
    // evaluated in the floating priority group.
    let iface = text("interface");
    if iface.is_empty() || iface.contains(',') {
        push(&mut node, "floating", "yes");
    }

    for side in ["source", "destination"] {
        let mut block = XmlNode::new(side);
        let net = text(&format!("{side}_net"));
        if net.is_empty() || net == "any" {
            block.children.push(XmlNode::new("any"));
        } else if is_network_token(&net, interfaces) {
            push(&mut block, "network", &net);
        } else {
            push(&mut block, "address", &net);
        }
        let port = text(&format!("{side}_port"));
        if !port.is_empty() {
            push(&mut block, "port", &port);
        }
        if flag(&format!("{side}_not")) {
            push(&mut block, "not", "1");
        }
        node.children.push(block);
    }
    node
}

/// Interface networks/addresses (`lan`, `opt1ip`, `(self)`) as opposed to
/// aliases or literal addresses.
fn is_network_token(value: &str, interfaces: &BTreeSet<String>) -> bool {
    let v = value.trim().to_ascii_lowercase();
    if v == "(self)" || interfaces.contains(&v) {
        return true;
    }
    v.strip_suffix("ip")
        .map(|base| interfaces.contains(base))
        .unwrap_or(false)
}

fn push(parent: &mut XmlNode, tag: &str, value: &str) {
    let mut child = XmlNode::new(tag);
    child.text = Some(value.to_string());
    parent.children.push(child);
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::filter_rules;

    #[test]
    fn presents_mvc_rules_in_legacy_shape_after_legacy_rules() {
        let root = parse(
            br#"<opnsense>
                <interfaces><wan/><lan/><opt1/></interfaces>
                <filter><rule><type>block</type><interface>wan</interface></rule></filter>
                <OPNsense><Firewall><Filter><rules>
                  <rule uuid="u1"><enabled>0</enabled><action>pass</action><quick>1</quick><interface>lan</interface><protocol>TCP</protocol>
                    <source_net>lan</source_net><source_not>0</source_not>
                    <destination_net>web_hosts</destination_net><destination_not>1</destination_not><destination_port>443</destination_port>
                    <gateway>WAN_GW</gateway><description>web</description></rule>
                  <rule uuid="u2"><enabled>1</enabled><action>block</action><interface>lan,opt1</interface><protocol>any</protocol>
                    <source_net>opt1ip</source_net><destination_net>any</destination_net></rule>
                </rules></Filter></Firewall></OPNsense>
            </opnsense>"#,
        )
        .expect("parse");

        let rules = filter_rules(&root);
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].get_text(&["type"]), Some("block"));

        let web = &rules[1];
        assert_eq!(web.get_text(&["type"]), Some("pass"));
        assert_eq!(web.get_text(&["descr"]), Some("web"));
        assert_eq!(web.get_text(&["protocol"]), Some("tcp"));
        assert!(web.get_child("disabled").is_some());
        assert_eq!(web.get_text(&["source", "network"]), Some("lan"));
        assert_eq!(web.get_text(&["destination", "address"]), Some("web_hosts"));
        assert_eq!(web.get_text(&["destination", "port"]), Some("443"));
        assert!(web
            .get_child("destination")
            .unwrap()
            .get_child("not")
            .is_some());
        assert_eq!(web.get_text(&["gateway"]), Some("WAN_GW"));

        let floating = &rules[2];
        assert!(floating.get_child("floating").is_some());
        assert!(floating.get_child("protocol").is_none());
        assert_eq!(floating.get_text(&["source", "network"]), Some("opt1ip"));
        assert!(floating
            .get_child("destination")
            .unwrap()
            .get_child("any")
            .is_some());
    }
}
