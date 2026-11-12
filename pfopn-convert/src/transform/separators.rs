//! pfSense rule separators -> OPNsense rule categories.
//!
//! pfSense draws coloured separator bars between rules: per interface tab in
//! `<filter><separator><if>` (floating rules under `floatingrules`) and for the
//! port-forward list in `<nat><separator>`. A separator's `row` is `fr<N>`:
//! it is shown above the N-th rule of that list, counted from 0 among the
//! rules of that tab in config order (`firewall_rules.php`,
//! `firewall_nat.php`). Several separators on the same row are shown in
//! config order. Outbound NAT, 1:1 and NPt have no separators.
//!
//! OPNsense has no separators. Its equivalent is rule categories
//! (`OPNsense/Firewall/Category`, a name and a colour): the 26.7 rule pages
//! group consecutive rules with the same category under a coloured header in
//! their tree view. Conversion rule:
//!
//! - A separator labels the rules below it, down to the next separator in the
//!   same list. Rules above the first separator get no category.
//! - A separator with no rules under it (another separator follows directly,
//!   or it is below the last rule) creates no category; it is reported.
//! - A port forward's category is also given to its linked filter rule
//!   (`associated-rule-id`), unless a filter separator already labels it.
//! - The category is named after the separator text (HTML entities decoded,
//!   commas replaced, as OPNsense stores port-forward categories as a
//!   comma-separated list). Equal names share one category. A separator
//!   without text is named after its list and position (`lan section 2`).
//! - pfSense's colour classes map to hex colours; the first separator of a
//!   name sets its colour.
//!
//! The rules are tagged with a pfSense-style `<category>` (names) on the
//! source config, before the merge, so rules the converter adds or removes
//! later (IPsec auto rules, pfBlockerNG floating rules, reply-to copies) don't
//! shift the positions. Port forwards keep `<category>` as names, which is
//! what OPNsense's DNat model stores; `filter_mvc` turns the names of filter
//! rules into category UUIDs.

use std::collections::BTreeMap;

use xml_diff_core::XmlNode;

use crate::transform::filter_mvc::stable_uuid;
use crate::transform::html_entities;

const COLORS: &[(&str, &str)] = &[
    ("bg-info", "5bc0de"),
    ("bg-warning", "f0ad4e"),
    ("bg-danger", "d9534f"),
    ("bg-success", "5cb85c"),
    ("bg-primary", "337ab7"),
];

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Category {
    pub name: String,
    /// Six hex digits, or empty.
    pub color: String,
    /// Rules tagged with it, per list ("lan: 3", "port forwards: 8").
    pub rules: BTreeMap<String, usize>,
}

/// What `tag_rules` found, used to create the categories and to report.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SeparatorPlan {
    pub categories: Vec<Category>,
    /// Separators with no rules under them ("port forwards: Old service").
    pub empty: Vec<String>,
    /// Separator texts that had to be changed ("a, b" -> "a b").
    pub renamed: Vec<String>,
    /// Filter rules that got the category of their linked port forward.
    pub linked: usize,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SeparatorReport {
    /// Categories created in the output (others already existed in the baseline).
    pub created: usize,
    /// `<separator>` blocks removed from the output (OPNsense ignores them).
    pub removed: usize,
}

struct Separator {
    row: usize,
    name: String,
    color: String,
}

/// Tag the source's rules with the category of the separator above them.
pub fn tag_rules(source: &mut XmlNode) -> SeparatorPlan {
    let mut plan = SeparatorPlan::default();

    // Filter rules, per pfSense rule tab.
    let filter_seps: Vec<(String, Vec<Separator>)> = source
        .get_child("filter")
        .and_then(|f| f.get_child("separator"))
        .map(|s| {
            s.children
                .iter()
                .map(|list| {
                    let key = list.tag.to_ascii_lowercase();
                    let label = list_label(&key);
                    (key, read_separators(list, &label, &mut plan))
                })
                .filter(|(_, seps)| !seps.is_empty())
                .collect()
        })
        .unwrap_or_default();
    if let Some(filter) = source.children.iter_mut().find(|c| c.tag == "filter") {
        for (key, seps) in &filter_seps {
            let label = list_label(key);
            let rules: Vec<&mut XmlNode> = filter
                .children
                .iter_mut()
                .filter(|c| c.tag == "rule" && rule_tab(c) == *key)
                .collect();
            tag_list(rules, seps, &label, &mut plan);
        }
    }

    // Port forwards: one list across all interfaces.
    let nat_seps: Vec<Separator> = source
        .get_child("nat")
        .and_then(|n| n.get_child("separator"))
        .map(|s| read_separators(s, "port forwards", &mut plan))
        .unwrap_or_default();
    let mut linked: BTreeMap<String, String> = BTreeMap::new();
    if let Some(nat) = source.children.iter_mut().find(|c| c.tag == "nat") {
        let rules: Vec<&mut XmlNode> = nat
            .children
            .iter_mut()
            .filter(|c| c.tag == "rule")
            .collect();
        tag_list(rules, &nat_seps, "port forwards", &mut plan);
        for rule in nat.children.iter().filter(|c| c.tag == "rule") {
            let id = rule.get_text(&["associated-rule-id"]).unwrap_or("").trim();
            let category = rule.get_text(&["category"]).unwrap_or("").trim();
            if !id.is_empty() && id != "pass" && !category.is_empty() {
                linked.insert(id.to_string(), category.to_string());
            }
        }
    }

    // Filter rules linked to a port forward inherit its category.
    if !linked.is_empty() {
        if let Some(filter) = source.children.iter_mut().find(|c| c.tag == "filter") {
            for rule in filter.children.iter_mut().filter(|c| c.tag == "rule") {
                if !rule.get_text(&["category"]).unwrap_or("").trim().is_empty() {
                    continue;
                }
                let id = rule.get_text(&["associated-rule-id"]).unwrap_or("").trim();
                if let Some(name) = linked.get(id) {
                    let label = list_label(&rule_tab(rule));
                    set_text(rule, "category", name);
                    count(&mut plan, name, &label);
                    plan.linked += 1;
                }
            }
        }
    }

    plan.categories.retain(|c| !c.rules.is_empty());
    plan
}

/// Create the plan's categories in the output and remove the `<separator>`
/// blocks, which OPNsense does not read.
pub fn create_categories(out: &mut XmlNode, plan: &SeparatorPlan) -> SeparatorReport {
    let mut report = SeparatorReport::default();
    for section in ["filter", "nat"] {
        if let Some(node) = out.children.iter_mut().find(|c| c.tag == section) {
            let before = node.children.len();
            node.children.retain(|c| c.tag != "separator");
            report.removed += before - node.children.len();
        }
    }
    if plan.categories.is_empty() {
        return report;
    }
    let category = ensure_child(
        ensure_child(ensure_child(out, "OPNsense"), "Firewall"),
        "Category",
    );
    if !category.attributes.contains_key("version") {
        category
            .attributes
            .insert("version".to_string(), "1.0.0".to_string());
    }
    let list = ensure_child(category, "categories");
    for wanted in &plan.categories {
        let exists = list
            .get_children("category")
            .iter()
            .any(|c| c.get_text(&["name"]).unwrap_or("") == wanted.name);
        if exists {
            continue;
        }
        let mut node = XmlNode::new("category");
        node.attributes.insert(
            "uuid".to_string(),
            stable_uuid(&format!("separator-category|{}", wanted.name)),
        );
        push(&mut node, "name", &wanted.name);
        push(&mut node, "auto", "0");
        push(&mut node, "color", &wanted.color);
        list.children.push(node);
        report.created += 1;
    }
    report
}

/// Category name -> UUID, from the output's Category model.
pub fn category_ids(out: &XmlNode) -> BTreeMap<String, String> {
    out.get_child("OPNsense")
        .and_then(|o| o.get_child("Firewall"))
        .and_then(|f| f.get_child("Category"))
        .and_then(|c| c.get_child("categories"))
        .map(|list| {
            list.get_children("category")
                .iter()
                .filter_map(|c| {
                    let name = c.get_text(&["name"])?.to_string();
                    let uuid = c.attributes.get("uuid")?.clone();
                    Some((name, uuid))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn read_separators(list: &XmlNode, label: &str, plan: &mut SeparatorPlan) -> Vec<Separator> {
    let mut seps: Vec<Separator> = Vec::new();
    for sep in &list.children {
        let Some(row) = sep
            .get_text(&["row"])
            .and_then(|r| r.trim().strip_prefix("fr"))
            .and_then(|n| n.parse::<usize>().ok())
        else {
            continue;
        };
        let text = html_entities::decode(sep.get_text(&["text"]).unwrap_or(""));
        let cleaned = text.replace(',', " ");
        let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
        let name = if cleaned.is_empty() {
            format!("{label} section {}", seps.len() + 1)
        } else {
            if cleaned != text.trim() {
                plan.renamed.push(format!("{} -> {cleaned}", text.trim()));
            }
            cleaned
        };
        let class = sep.get_text(&["color"]).unwrap_or("").trim();
        let color = COLORS
            .iter()
            .find(|(c, _)| *c == class)
            .map(|(_, hex)| hex.to_string())
            .unwrap_or_default();
        seps.push(Separator { row, name, color });
    }
    // Stable: separators on the same row keep their config order.
    seps.sort_by_key(|s| s.row);
    seps
}

/// Tag the rules of one list; the governing separator of rule N is the last
/// one with row <= N.
fn tag_list(
    mut rules: Vec<&mut XmlNode>,
    seps: &[Separator],
    label: &str,
    plan: &mut SeparatorPlan,
) {
    if seps.is_empty() {
        return;
    }
    for sep in seps {
        if !plan.categories.iter().any(|c| c.name == sep.name) {
            plan.categories.push(Category {
                name: sep.name.clone(),
                color: sep.color.clone(),
                rules: BTreeMap::new(),
            });
        }
    }
    let mut used = vec![false; seps.len()];
    for (pos, rule) in rules.iter_mut().enumerate() {
        let Some(idx) = seps.iter().rposition(|s| s.row <= pos) else {
            continue;
        };
        used[idx] = true;
        set_text(rule, "category", &seps[idx].name);
        count(plan, &seps[idx].name, label);
    }
    for (sep, used) in seps.iter().zip(used) {
        if !used {
            plan.empty.push(format!("{label}: {}", sep.name));
        }
    }
}

fn count(plan: &mut SeparatorPlan, name: &str, label: &str) {
    if let Some(category) = plan.categories.iter_mut().find(|c| c.name == name) {
        *category.rules.entry(label.to_string()).or_default() += 1;
    }
}

/// The pfSense rule tab a filter rule is listed on.
fn rule_tab(rule: &XmlNode) -> String {
    if rule.get_child("floating").is_some() {
        "floatingrules".to_string()
    } else {
        rule.get_text(&["interface"])
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
    }
}

fn list_label(key: &str) -> String {
    if key == "floatingrules" {
        "floating".to_string()
    } else {
        key.to_string()
    }
}

fn ensure_child<'a>(parent: &'a mut XmlNode, tag: &str) -> &'a mut XmlNode {
    let idx = match parent.children.iter().position(|c| c.tag == tag) {
        Some(idx) => idx,
        None => {
            parent.children.push(XmlNode::new(tag));
            parent.children.len() - 1
        }
    };
    &mut parent.children[idx]
}

fn set_text(node: &mut XmlNode, tag: &str, value: &str) {
    match node.children.iter_mut().find(|c| c.tag == tag) {
        Some(child) => {
            child.children.clear();
            child.text = Some(value.to_string());
        }
        None => push(node, tag, value),
    }
}

fn push(parent: &mut XmlNode, tag: &str, value: &str) {
    let mut child = XmlNode::new(tag);
    child.text = Some(value.to_string());
    parent.children.push(child);
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::{category_ids, create_categories, tag_rules};

    fn source() -> xml_diff_core::XmlNode {
        parse(
            br#"<pfsense>
              <filter>
                <rule><interface>lan</interface><descr>l0</descr></rule>
                <rule><interface>wan</interface><descr>w0</descr><associated-rule-id>nat_1</associated-rule-id></rule>
                <rule><interface>lan</interface><descr>l1</descr></rule>
                <rule><interface>wan</interface><descr>w1</descr><associated-rule-id>nat_2</associated-rule-id></rule>
                <rule><floating>yes</floating><interface>wan,lan</interface><descr>f0</descr></rule>
                <rule><interface>lan</interface><descr>l2</descr></rule>
                <separator>
                  <lan>
                    <sep0><row>fr2</row><text>Second, part</text><color>bg-danger</color><if>lan</if></sep0>
                    <sep1><row>fr1</row><text><![CDATA[Web &amp; mail]]></text><color>bg-info</color><if>lan</if></sep1>
                    <sep2><row>fr3</row><text>Below the last</text><color>bg-info</color><if>lan</if></sep2>
                  </lan>
                  <wan>
                    <sep0><row>fr1</row><text>WAN own</text><color>bg-success</color><if>wan</if></sep0>
                  </wan>
                  <floatingrules>
                    <sep0><row>fr0</row><text></text><color>bg-warning</color><if>floatingrules</if></sep0>
                  </floatingrules>
                </separator>
              </filter>
              <nat>
                <rule><interface>wan</interface><descr>p0</descr></rule>
                <rule><interface>wan</interface><descr>p1</descr><associated-rule-id>nat_1</associated-rule-id></rule>
                <rule><interface>opt1</interface><descr>p2</descr><associated-rule-id>nat_2</associated-rule-id></rule>
                <separator>
                  <sep0><row>fr1</row><text>Servers</text><color>bg-info</color><if></if></sep0>
                  <sep1><row>fr2</row><text>EMPTY</text><color>bg-info</color><if></if></sep1>
                  <sep2><row>fr2</row><text>WAN own</text><color>bg-info</color><if></if></sep2>
                </separator>
              </nat>
            </pfsense>"#,
        )
        .expect("parse")
    }

    fn categories(root: &xml_diff_core::XmlNode, section: &str) -> Vec<(String, String)> {
        root.get_child(section)
            .unwrap()
            .get_children("rule")
            .iter()
            .map(|r| {
                (
                    r.get_text(&["descr"]).unwrap_or("").to_string(),
                    r.get_text(&["category"]).unwrap_or("").to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn separators_label_the_rules_below_them() {
        let mut src = source();
        let plan = tag_rules(&mut src);
        let pairs = |v: &[(&str, &str)]| -> Vec<(String, String)> {
            v.iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect()
        };
        // lan: l0 above the first separator, l1 under "Web & mail" (row 1),
        // l2 under "Second part" (row 2); "Below the last" has no rules.
        // wan: w0 inherits Servers from its port forward, w1 has its own
        // separator. Floating: unnamed separator.
        assert_eq!(
            categories(&src, "filter"),
            pairs(&[
                ("l0", ""),
                ("w0", "Servers"),
                ("l1", "Web & mail"),
                ("w1", "WAN own"),
                ("f0", "floating section 1"),
                ("l2", "Second part"),
            ])
        );
        // Port forwards: two separators on row 2; the last one is right
        // above p2, so "EMPTY" heads an empty section.
        assert_eq!(
            categories(&src, "nat"),
            pairs(&[("p0", ""), ("p1", "Servers"), ("p2", "WAN own")])
        );
        assert_eq!(plan.linked, 1);
        assert_eq!(
            plan.empty,
            vec![
                "lan: Below the last".to_string(),
                "port forwards: EMPTY".to_string()
            ]
        );
        assert_eq!(
            plan.renamed,
            vec!["Second, part -> Second part".to_string()]
        );
        let names: Vec<(&str, &str)> = plan
            .categories
            .iter()
            .map(|c| (c.name.as_str(), c.color.as_str()))
            .collect();
        assert_eq!(
            names,
            vec![
                ("Web & mail", "5bc0de"),
                ("Second part", "d9534f"),
                ("WAN own", "5cb85c"),
                ("floating section 1", "f0ad4e"),
                ("Servers", "5bc0de"),
            ]
        );
        let wan_own = plan
            .categories
            .iter()
            .find(|c| c.name == "WAN own")
            .unwrap();
        assert_eq!(wan_own.rules.get("wan"), Some(&1));
        assert_eq!(wan_own.rules.get("port forwards"), Some(&1));
    }

    #[test]
    fn creates_categories_once_and_removes_separators() {
        let mut src = source();
        let plan = tag_rules(&mut src);
        let mut out = parse(
            br#"<opnsense>
              <filter><separator><lan/></separator></filter>
              <nat><separator/></nat>
              <OPNsense><Firewall><Category version="1.0.0"><categories>
                <category uuid="existing-uuid"><name>Servers</name><auto>0</auto><color>000000</color></category>
              </categories></Category></Firewall></OPNsense>
            </opnsense>"#,
        )
        .expect("parse");
        let report = create_categories(&mut out, &plan);
        assert_eq!(report.removed, 2);
        assert_eq!(report.created, 4);
        let ids = category_ids(&out);
        assert_eq!(ids.len(), 5);
        assert_eq!(
            ids.get("Servers").map(String::as_str),
            Some("existing-uuid")
        );
        assert!(out
            .get_child("filter")
            .unwrap()
            .get_child("separator")
            .is_none());
        // Running it again changes nothing.
        let again = create_categories(&mut out, &plan);
        assert_eq!(again.created, 0);
    }

    #[test]
    fn no_separators_no_changes() {
        let mut src = parse(
            br#"<pfsense><filter><rule><interface>lan</interface></rule>
                <separator><lan/><wan/></separator></filter></pfsense>"#,
        )
        .expect("parse");
        let plan = tag_rules(&mut src);
        assert!(plan.categories.is_empty());
        assert!(src
            .get_child("filter")
            .unwrap()
            .get_child("rule")
            .unwrap()
            .get_child("category")
            .is_none());
    }
}
