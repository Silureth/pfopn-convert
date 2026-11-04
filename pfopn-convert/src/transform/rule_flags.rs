use xml_diff_core::XmlNode;

/// Rule flags whose meaning differs between pfSense and OPNsense when empty.
///
/// pfSense treats these as set when the element is present (`isset()`), and
/// writes them as empty elements: `<disabled></disabled>`, `<log></log>`.
/// OPNsense's legacy rule parsers (`Rule::parseIsComment`, `Rule::parseBool`,
/// `FilterRule::isSourceInverted`, ...) test them with `!empty()`, so an empty
/// element reads as *false*: disabled rules become active, logging is dropped
/// and inverted ("not") matches are silently un-inverted.
///
/// `any` is deliberately absent: OPNsense checks it with `isset()`, matching
/// pfSense semantics.
pub(crate) const RULE_FLAGS: &[&str] = &[
    "disabled",
    "log",
    "quick",
    "allowopts",
    "disablereplyto",
    "nopfsync",
    "nosync",
    "nordr",
    "nonat",
    "staticnatport",
    "pass",
];

/// Interface flags pfSense writes as empty elements when set.
///
/// OPNsense reads `blockpriv`/`blockbogons` with `!empty()` when generating the
/// block rules (`filter.lib.inc`), so an empty element silently turns "Block
/// private networks" / "Block bogon networks" off on that interface. The DHCPv6
/// flags are read with a mix of `isset()` and `!empty()`. `enable` is read with
/// `isset()`, but is written as `1` too so the result matches what OPNsense
/// itself writes.
pub(crate) const INTERFACE_FLAGS: &[&str] = &[
    "enable",
    "blockpriv",
    "blockbogons",
    "dhcp6prefixonly",
    "dhcp6-ia-pd-send-hint",
    "adv_dhcp6_interface_statement_information_only_enable",
    "adv_dhcp6_id_assoc_statement_address_enable",
    "adv_dhcp6_id_assoc_statement_prefix_enable",
];

/// Address blocks inside a rule that may carry a `<not>` flag.
const ADDRESS_BLOCKS: &[&str] = &["source", "destination"];

/// Rewrite present-but-empty pfSense rule flags to `1` so OPNsense reads them
/// as set. Covers filter rules and all legacy NAT rule kinds.
///
/// Returns the number of flags rewritten.
pub fn normalize_empty_flags_for_opnsense(root: &mut XmlNode) -> usize {
    let mut changed = 0;
    if let Some(filter) = child_mut(root, "filter") {
        changed += normalize_rules(filter, "rule");
    }
    if let Some(nat) = child_mut(root, "nat") {
        changed += normalize_rules(nat, "rule");
        changed += normalize_rules(nat, "onetoone");
        changed += normalize_rules(nat, "npt");
        if let Some(outbound) = child_mut(nat, "outbound") {
            changed += normalize_rules(outbound, "rule");
        }
    }
    changed
}

/// Rewrite present-but-empty pfSense interface flags (`blockpriv`,
/// `blockbogons`, `enable`, ...) to `1` so OPNsense reads them as set.
///
/// Returns `(flags rewritten, interfaces that had block-private/bogon flags
/// rewritten)`; the latter are the ones whose protection would have been lost.
pub fn normalize_interface_flags_for_opnsense(root: &mut XmlNode) -> (usize, Vec<String>) {
    let mut changed = 0;
    let mut block_fixed = Vec::new();
    let Some(interfaces) = child_mut(root, "interfaces") else {
        return (0, block_fixed);
    };
    for iface in interfaces.children.iter_mut() {
        let had_empty_block = ["blockpriv", "blockbogons"].iter().any(|tag| {
            iface
                .get_child(tag)
                .map(|c| c.children.is_empty() && c.text.as_deref().map(str::trim).unwrap_or("").is_empty())
                .unwrap_or(false)
        });
        changed += set_empty_flags(iface, INTERFACE_FLAGS);
        if had_empty_block {
            let descr = iface.get_text(&["descr"]).map(str::trim).unwrap_or("");
            block_fixed.push(if descr.is_empty() {
                iface.tag.clone()
            } else {
                format!("{} ({descr})", iface.tag)
            });
        }
    }
    (changed, block_fixed)
}

fn normalize_rules(container: &mut XmlNode, rule_tag: &str) -> usize {
    let mut changed = 0;
    for rule in container.children.iter_mut().filter(|c| c.tag == rule_tag) {
        changed += set_empty_flags(rule, RULE_FLAGS);
        for block in rule
            .children
            .iter_mut()
            .filter(|c| ADDRESS_BLOCKS.contains(&c.tag.as_str()))
        {
            changed += set_empty_flags(block, &["not"]);
        }
    }
    changed
}

fn set_empty_flags(node: &mut XmlNode, flags: &[&str]) -> usize {
    let mut changed = 0;
    for child in node
        .children
        .iter_mut()
        .filter(|c| flags.contains(&c.tag.as_str()) && c.children.is_empty())
    {
        if child
            .text
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .is_empty()
        {
            child.text = Some("1".to_string());
            changed += 1;
        }
    }
    changed
}

/// pfSense flag semantics: the flag is set when the element is present
/// (pfSense writes `true` as an empty element), unless it is explicitly "0".
pub(crate) fn pf_flag_is_set(node: &XmlNode, tag: &str) -> bool {
    node.get_child(tag)
        .map(|c| c.text.as_deref().map(str::trim).unwrap_or("") != "0")
        .unwrap_or(false)
}

fn child_mut<'a>(parent: &'a mut XmlNode, tag: &str) -> Option<&'a mut XmlNode> {
    parent.children.iter_mut().find(|c| c.tag == tag)
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::{normalize_empty_flags_for_opnsense, normalize_interface_flags_for_opnsense};

    #[test]
    fn rewrites_empty_interface_flags() {
        let mut root = parse(
            br#"<opnsense><interfaces>
                <wan><enable></enable><if>vtnet0</if><blockpriv/><blockbogons></blockbogons><ipaddrv6></ipaddrv6><spoofmac/></wan>
                <opt1><descr>DMZ</descr><if>vtnet2</if><blockpriv/></opt1>
                <lan><enable>1</enable><if>vtnet1</if></lan>
            </interfaces></opnsense>"#,
        )
        .expect("parse");

        let (changed, block_fixed) = normalize_interface_flags_for_opnsense(&mut root);
        assert_eq!(changed, 4);
        assert_eq!(block_fixed, vec!["wan".to_string(), "opt1 (DMZ)".to_string()]);

        let ifaces = root.get_child("interfaces").unwrap();
        assert_eq!(ifaces.get_text(&["wan", "enable"]), Some("1"));
        assert_eq!(ifaces.get_text(&["wan", "blockpriv"]), Some("1"));
        assert_eq!(ifaces.get_text(&["wan", "blockbogons"]), Some("1"));
        // Non-flag empty values keep their meaning ("none").
        assert_eq!(ifaces.get_text(&["wan", "ipaddrv6"]).unwrap_or(""), "");
        assert_eq!(ifaces.get_text(&["wan", "spoofmac"]).unwrap_or(""), "");
        // A disabled interface (no <enable>) stays disabled.
        assert!(ifaces.get_child("opt1").unwrap().get_child("enable").is_none());
        assert_eq!(ifaces.get_text(&["opt1", "blockpriv"]), Some("1"));
    }

    #[test]
    fn rewrites_empty_flags_in_filter_and_nat_rules() {
        let mut root = parse(
            br#"<opnsense>
                <filter>
                  <rule><type>pass</type><disabled></disabled><log/><source><any></any><not></not></source><destination><network>lan</network><not/></destination></rule>
                  <rule><type>block</type><log>1</log></rule>
                </filter>
                <nat>
                  <rule><disabled></disabled><nordr></nordr></rule>
                  <onetoone><disabled/></onetoone>
                  <outbound><mode>hybrid</mode><rule><nonat></nonat><staticnatport/></rule></outbound>
                </nat>
            </opnsense>"#,
        )
        .expect("parse");

        let changed = normalize_empty_flags_for_opnsense(&mut root);
        assert_eq!(changed, 9);

        let rules = root.get_child("filter").unwrap().get_children("rule");
        assert_eq!(rules[0].get_text(&["disabled"]), Some("1"));
        assert_eq!(rules[0].get_text(&["log"]), Some("1"));
        assert_eq!(rules[0].get_text(&["source", "not"]), Some("1"));
        assert_eq!(rules[0].get_text(&["destination", "not"]), Some("1"));
        // `any` keeps pfSense semantics in OPNsense (isset), so it is untouched.
        assert_eq!(
            rules[0]
                .get_child("source")
                .and_then(|s| s.get_child("any"))
                .and_then(|a| a.text.clone())
                .unwrap_or_default(),
            ""
        );
        // Already-valued flags are not modified.
        assert_eq!(rules[1].get_text(&["log"]), Some("1"));
        assert!(rules[1].get_child("disabled").is_none());

        let nat = root.get_child("nat").unwrap();
        assert_eq!(nat.get_text(&["rule", "disabled"]), Some("1"));
        assert_eq!(nat.get_text(&["rule", "nordr"]), Some("1"));
        assert_eq!(nat.get_text(&["onetoone", "disabled"]), Some("1"));
        assert_eq!(nat.get_text(&["outbound", "rule", "nonat"]), Some("1"));
        assert_eq!(
            nat.get_text(&["outbound", "rule", "staticnatport"]),
            Some("1")
        );
        // Non-flag elements stay as they were.
        assert_eq!(nat.get_text(&["outbound", "mode"]), Some("hybrid"));
    }
}
