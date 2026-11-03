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
const RULE_FLAGS: &[&str] = &[
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

fn child_mut<'a>(parent: &'a mut XmlNode, tag: &str) -> Option<&'a mut XmlNode> {
    parent.children.iter_mut().find(|c| c.tag == tag)
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::normalize_empty_flags_for_opnsense;

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
