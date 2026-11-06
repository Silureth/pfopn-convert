use xml_diff_core::XmlNode;

use crate::transform::mvc_util::{node_at, text};

/// Remove pfBlockerNG floating firewall rules when converting to OPNsense.
///
/// pfBlockerNG is a popular pfSense package for blocking ads, malware, and geographic
/// regions. It creates "floating" firewall rules that apply to all interfaces and
/// contain special alias references like "pfB_Top_v4", "pfB_Top_v6", or custom
/// "pfB_*" aliases.
///
/// Since OPNsense doesn't have pfBlockerNG (it has its own alternatives like
/// os-firewall and os-ips), these floating rules would be invalid and potentially
/// break the firewall config. This function identifies and removes them.
///
/// Regular (non-floating) rules that happen to reference pfBlocker aliases are
/// also problematic, but this function specifically targets floating rules since
/// those are the most common and most problematic.
pub fn prune_pfblocker_floating_rules_for_opnsense(root: &mut XmlNode) {
    let Some(filter) = child_mut(root, "filter") else {
        return;
    };

    // Remove any <rule> children that are pfBlocker floating rules.
    // Keep everything else (separator rules, non-pfBlocker rules, etc.)
    filter.children.retain(|child| {
        if child.tag != "rule" {
            return true; // Keep non-rule elements
        }
        !is_pfblocker_floating_rule(child) // Remove if it's a pfBlocker floating rule
    });
}

/// Check if a firewall rule is both floating AND contains pfBlocker markers.
///
/// A rule is considered a pfBlocker floating rule if:
/// 1. It has <floating>yes</floating>
/// 2. Anywhere in the rule's XML tree there's text matching pfBlocker patterns
///    (pfB_Top_v4, pfB_Top_v6, or anything starting with pfb_)
fn is_pfblocker_floating_rule(rule: &XmlNode) -> bool {
    // First check: is this a floating rule?
    let is_floating = rule
        .get_text(&["floating"])
        .map(|v| v.trim().eq_ignore_ascii_case("yes"))
        .unwrap_or(false);

    if !is_floating {
        return false; // Not floating, so definitely not a pfBlocker floating rule
    }

    // Second check: does this rule contain any pfBlocker markers?
    // Collect all text content from anywhere in the rule's XML subtree
    let mut texts = Vec::new();
    collect_text(rule, &mut texts);

    // Check if any of those text snippets look like pfBlocker identifiers
    texts.into_iter().any(is_pfblocker_marker)
}

/// Recursively walk an XML node and collect all non-empty text content.
///
/// This is used to scan a firewall rule for any mention of pfBlocker aliases,
/// which could appear in <source>, <destination>, <descr>, or other fields.
fn collect_text(node: &XmlNode, out: &mut Vec<String>) {
    if let Some(text) = node.text.as_deref() {
        let v = text.trim();
        if !v.is_empty() {
            out.push(v.to_string());
        }
    }
    // Recurse into all children to catch text at any depth
    for child in &node.children {
        collect_text(child, out);
    }
}

/// Check if a string looks like a pfBlockerNG alias or identifier.
///
/// pfBlocker uses these naming conventions:
/// - "pfB_Top_v4" and "pfB_Top_v6" — special top-priority rule aliases
/// - "pfB_*" — custom aliases created by the user (e.g. "pfB_Ads", "pfB_Russia")
fn is_pfblocker_marker(s: String) -> bool {
    let t = s.trim();
    t.eq_ignore_ascii_case("pfB_Top_v4")
        || t.eq_ignore_ascii_case("pfB_Top_v6")
        || t.to_ascii_lowercase().starts_with("pfb_")
}

/// Path pfBlockerNG uses for the URL its auto aliases (`pfB_<list>_v4|v6`)
/// download from. It is served by pfBlockerNG on the pfSense box itself, so
/// on OPNsense these URL tables stay empty.
const LOCAL_FEED_MARKER: &str = "/pfblockerng/pfblockerng.php?pfb=";

/// Feeds that no longer publish usable data.
const DEAD_FEEDS: &[(&str, &str)] = &[
    (
        "ransomwaretracker.abuse.ch",
        "Ransomware Tracker was shut down in 2019",
    ),
    (
        "sslbl.abuse.ch/blacklist/sslipblacklist",
        "abuse.ch deprecated the SSLBL IP list in January 2025",
    ),
    (
        "reputation.alienvault.com",
        "the AlienVault reputation feed has not been updated since 2021",
    ),
    (
        "talosintelligence.com/documents/ip-blacklist",
        "Talos no longer publishes this list",
    ),
];

/// Feeds whose data is still published, but at another URL or in a format
/// OPNsense can read. OPNsense URL tables take only the first column of each
/// line, so DShield's "start end mask" format would block single addresses.
const REPLACED_FEEDS: &[(&str, &str, &str)] = &[
    (
        "isc.sans.edu/block.txt",
        "https://iplists.firehol.org/files/dshield.netset",
        "OPNsense reads only the first column of DShield's start/end/mask format; FireHOL publishes the same list as CIDRs",
    ),
    (
        "dshield.org/block.txt",
        "https://iplists.firehol.org/files/dshield.netset",
        "OPNsense reads only the first column of DShield's start/end/mask format; FireHOL publishes the same list as CIDRs",
    ),
    (
        "spamhaus.org/drop/edrop.txt",
        "https://www.spamhaus.org/drop/drop.txt",
        "Spamhaus merged EDROP into DROP",
    ),
];

/// Result of [`rewrite_feed_aliases_for_opnsense`].
#[derive(Debug, Default)]
pub struct FeedAliasReport {
    /// Aliases pointed at their original feeds: (name, number of feed URLs).
    pub rewritten: Vec<(String, usize)>,
    /// Aliases still pointing at pfBlockerNG's local endpoint (switch off, or
    /// no matching pfBlockerNG list in the source).
    pub left_local: Vec<String>,
    /// Aliases disabled because none of their feeds is usable.
    pub disabled: Vec<String>,
    /// Per-feed notes: dropped or replaced URLs, unmatched lists.
    pub warnings: Vec<String>,
}

/// pfBlockerNG's IP lists become URL table aliases that download from
/// pfBlockerNG on the pfSense box (`https://127.0.0.1/pfblockerng/...`).
/// OPNsense has no such endpoint, so the aliases stay empty and every rule
/// that uses them matches nothing.
///
/// With `apply`, each such alias is pointed at the feed URLs of its
/// pfBlockerNG list (`installedpackages/pfblockernglistsv4|v6`), skipping
/// disabled rows, dead feeds and formats OPNsense cannot read, and its refresh
/// interval follows the list's update schedule. An alias without any usable
/// feed is disabled. Without `apply`, nothing changes and the aliases are
/// only reported, because filling them makes their block rules effective.
pub fn rewrite_feed_aliases_for_opnsense(
    out: &mut XmlNode,
    source: &XmlNode,
    apply: bool,
) -> FeedAliasReport {
    let mut report = FeedAliasReport::default();
    let Some(aliases) = aliases_mut(out) else {
        return report;
    };

    for alias in aliases.children.iter_mut().filter(|c| c.tag == "alias") {
        let content = text(alias, "content");
        let Some(pos) = content.find(LOCAL_FEED_MARKER) else {
            continue;
        };
        let name = text(alias, "name");
        if !apply {
            report.left_local.push(name);
            continue;
        }
        let feed_alias = content[pos + LOCAL_FEED_MARKER.len()..]
            .split(['&', '\n'])
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        let Some(list) = find_pfblocker_list(source, &feed_alias) else {
            report.warnings.push(format!(
                "{name}: no pfBlockerNG IP list found for {feed_alias}; left unchanged"
            ));
            report.left_local.push(name);
            continue;
        };

        let mut feeds: Vec<String> = Vec::new();
        for row in list.get_children("row") {
            if text(row, "state").eq_ignore_ascii_case("disabled") {
                continue;
            }
            let url = text(row, "url");
            let lower = url.to_ascii_lowercase();
            if !(lower.starts_with("http://") || lower.starts_with("https://")) {
                if !url.is_empty() {
                    report.warnings.push(format!(
                        "{name}: skipped {url} (not a URL; GeoIP/ASN/local sources are not converted)"
                    ));
                }
                continue;
            }
            match classify_feed(&lower) {
                FeedStatus::Keep => push_unique(&mut feeds, url),
                FeedStatus::Replace(new_url, reason) => {
                    report
                        .warnings
                        .push(format!("{name}: replaced {url} with {new_url} ({reason})"));
                    push_unique(&mut feeds, new_url.to_string());
                }
                FeedStatus::Drop(reason) => {
                    report
                        .warnings
                        .push(format!("{name}: dropped {url} ({reason})"));
                }
            }
        }

        if feeds.is_empty() {
            set_child_text(alias, "enabled", "0");
            report.disabled.push(name);
            continue;
        }
        set_child_text(alias, "content", &feeds.join("\n"));
        if let Some(freq) = updatefreq_from_cron(&text(list, "cron")) {
            set_child_text(alias, "updatefreq", &freq);
        }
        report.rewritten.push((name, feeds.len()));
    }
    report
}

enum FeedStatus {
    Keep,
    Replace(&'static str, &'static str),
    Drop(&'static str),
}

fn classify_feed(lower_url: &str) -> FeedStatus {
    if let Some((_, reason)) = DEAD_FEEDS.iter().find(|(p, _)| lower_url.contains(p)) {
        return FeedStatus::Drop(reason);
    }
    if let Some((_, new_url, reason)) = REPLACED_FEEDS.iter().find(|(p, _, _)| lower_url.contains(p)) {
        return FeedStatus::Replace(new_url, reason);
    }
    if lower_url.split(['?', '#']).next().unwrap_or("").ends_with(".gz") {
        return FeedStatus::Drop("OPNsense URL tables cannot read gzip files");
    }
    FeedStatus::Keep
}

/// The pfBlockerNG list behind an auto alias: `pfB_<aliasname>_v4` lives in
/// `pfblockernglistsv4`, `_v6` in `pfblockernglistsv6`.
fn find_pfblocker_list<'a>(source: &'a XmlNode, feed_alias: &str) -> Option<&'a XmlNode> {
    let lower = feed_alias.to_ascii_lowercase();
    let (stem, section) = if let Some(stem) = lower.strip_suffix("_v4") {
        (stem, "pfblockernglistsv4")
    } else if let Some(stem) = lower.strip_suffix("_v6") {
        (stem, "pfblockernglistsv6")
    } else {
        return None;
    };
    let stem = stem.strip_prefix("pfb_").unwrap_or(stem);
    node_at(source, &["installedpackages", section])?
        .get_children("config")
        .into_iter()
        .find(|c| normalize_list_name(&text(c, "aliasname")) == stem)
}

/// pfBlockerNG builds alias names from the list name with anything other
/// than letters, digits and `_` replaced by `_`.
fn normalize_list_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// pfBlockerNG's update schedule (`01hour` … `12hours`, `EveryDay`, `Weekly`)
/// as OPNsense's alias refresh frequency in days (hours are fractions, as
/// the GUI stores them).
fn updatefreq_from_cron(cron: &str) -> Option<String> {
    match cron.trim() {
        "EveryDay" => Some("1".to_string()),
        "Weekly" => Some("7".to_string()),
        c => {
            let hours: u32 = c
                .strip_suffix("hours")
                .or_else(|| c.strip_suffix("hour"))?
                .parse()
                .ok()?;
            if hours == 0 {
                return None;
            }
            Some(format!("{}", f64::from(hours) / 24.0))
        }
    }
}

fn push_unique(list: &mut Vec<String>, url: String) {
    if !list.iter().any(|u| u.eq_ignore_ascii_case(&url)) {
        list.push(url);
    }
}

fn set_child_text(node: &mut XmlNode, tag: &str, value: &str) {
    if let Some(child) = node.children.iter_mut().find(|c| c.tag == tag) {
        child.text = Some(value.to_string());
    } else {
        let mut child = XmlNode::new(tag);
        child.text = Some(value.to_string());
        node.children.push(child);
    }
}

fn aliases_mut(out: &mut XmlNode) -> Option<&mut XmlNode> {
    let opn = child_mut(out, "OPNsense")?;
    let fw = child_mut(opn, "Firewall")?;
    let alias = child_mut(fw, "Alias")?;
    child_mut(alias, "aliases")
}

/// Helper to get a mutable reference to a direct child node by tag name.
fn child_mut<'a>(node: &'a mut XmlNode, tag: &str) -> Option<&'a mut XmlNode> {
    let idx = node.children.iter().position(|c| c.tag == tag)?;
    Some(&mut node.children[idx])
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::{prune_pfblocker_floating_rules_for_opnsense, rewrite_feed_aliases_for_opnsense};

    const SOURCE: &[u8] = br#"<pfsense><installedpackages>
        <pfblockernglistsv4>
            <config>
                <aliasname>PRI1</aliasname>
                <row><format>auto</format><state>Enabled</state><url>https://feeds.example.org/a.txt</url></row>
                <row><format>auto</format><state>Disabled</state><url>https://feeds.example.org/off.txt</url></row>
                <row><format>auto</format><state>Enabled</state><url>https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt</url></row>
                <row><format>auto</format><state>Enabled</state><url>https://isc.sans.edu/block.txt</url></row>
                <row><format>auto</format><state>Enabled</state><url>https://www.spamhaus.org/drop/drop.txt</url></row>
                <row><format>auto</format><state>Enabled</state><url>https://www.spamhaus.org/drop/edrop.txt</url></row>
                <cron>01hour</cron>
            </config>
            <config>
                <aliasname>PRI2</aliasname>
                <row><format>auto</format><state>Enabled</state><url>https://reputation.alienvault.com/reputation.snort.gz</url></row>
                <cron>01hour</cron>
            </config>
            <config>
                <aliasname>Geo List</aliasname>
                <row><format>geoip</format><state>Enabled</state><url>/usr/local/share/GeoIP/cc/XX_v4.txt</url></row>
                <row><format>auto</format><state>Enabled</state><url>https://feeds.example.org/b.txt</url></row>
                <cron>EveryDay</cron>
            </config>
        </pfblockernglistsv4>
    </installedpackages></pfsense>"#;

    const OUT: &[u8] = br#"<opnsense><OPNsense><Firewall><Alias><aliases>
        <alias><enabled>1</enabled><name>pfB_PRI1_v4</name><type>urltable</type><updatefreq>32</updatefreq><content>https://127.0.0.1:443/pfblockerng/pfblockerng.php?pfb=pfB_PRI1_v4</content></alias>
        <alias><enabled>1</enabled><name>pfB_PRI2_v4</name><type>urltable</type><updatefreq>32</updatefreq><content>https://127.0.0.1:443/pfblockerng/pfblockerng.php?pfb=pfB_PRI2_v4</content></alias>
        <alias><enabled>1</enabled><name>pfB_Geo_List_v4</name><type>urltable</type><updatefreq>32</updatefreq><content>https://127.0.0.1:443/pfblockerng/pfblockerng.php?pfb=pfB_Geo_List_v4</content></alias>
        <alias><enabled>1</enabled><name>other</name><type>urltable</type><content>https://lists.example.org/x.txt</content></alias>
    </aliases></Alias></Firewall></OPNsense></opnsense>"#;

    fn alias<'a>(root: &'a xml_diff_core::XmlNode, name: &str) -> &'a xml_diff_core::XmlNode {
        root.get_child("OPNsense")
            .and_then(|n| n.get_child("Firewall"))
            .and_then(|n| n.get_child("Alias"))
            .and_then(|n| n.get_child("aliases"))
            .expect("aliases")
            .get_children("alias")
            .into_iter()
            .find(|a| a.get_text(&["name"]) == Some(name))
            .expect("alias")
    }

    #[test]
    fn feed_aliases_point_at_original_feeds() {
        let source = parse(SOURCE).expect("parse");
        let mut out = parse(OUT).expect("parse");
        let report = rewrite_feed_aliases_for_opnsense(&mut out, &source, true);

        let pri1 = alias(&out, "pfB_PRI1_v4");
        assert_eq!(
            pri1.get_text(&["content"]),
            Some(
                "https://feeds.example.org/a.txt\nhttps://iplists.firehol.org/files/dshield.netset\nhttps://www.spamhaus.org/drop/drop.txt"
            )
        );
        assert_eq!(pri1.get_text(&["updatefreq"]), Some("0.041666666666666664"));
        assert_eq!(pri1.get_text(&["enabled"]), Some("1"));

        let geo = alias(&out, "pfB_Geo_List_v4");
        assert_eq!(geo.get_text(&["content"]), Some("https://feeds.example.org/b.txt"));
        assert_eq!(geo.get_text(&["updatefreq"]), Some("1"));

        let pri2 = alias(&out, "pfB_PRI2_v4");
        assert_eq!(pri2.get_text(&["enabled"]), Some("0"));
        assert!(pri2.get_text(&["content"]).unwrap_or("").contains("pfblockerng.php"));

        assert_eq!(
            alias(&out, "other").get_text(&["content"]),
            Some("https://lists.example.org/x.txt")
        );
        assert_eq!(report.rewritten.len(), 2);
        assert_eq!(report.disabled, vec!["pfB_PRI2_v4".to_string()]);
        assert!(report.left_local.is_empty());
        assert!(report.warnings.iter().any(|w| w.contains("ransomwaretracker")));
        assert!(report.warnings.iter().any(|w| w.contains("gzip") || w.contains("AlienVault")));
        assert!(report.warnings.iter().any(|w| w.contains("XX_v4.txt")));
    }

    #[test]
    fn feed_aliases_only_reported_without_switch() {
        let source = parse(SOURCE).expect("parse");
        let mut out = parse(OUT).expect("parse");
        let before = out.clone();
        let report = rewrite_feed_aliases_for_opnsense(&mut out, &source, false);

        assert_eq!(out, before);
        assert_eq!(report.left_local.len(), 3);
        assert!(report.rewritten.is_empty());
    }

    #[test]
    fn feed_alias_without_matching_list_is_left_alone() {
        let source = parse(br#"<pfsense><installedpackages/></pfsense>"#).expect("parse");
        let mut out = parse(OUT).expect("parse");
        let report = rewrite_feed_aliases_for_opnsense(&mut out, &source, true);

        assert_eq!(report.left_local.len(), 3);
        assert!(alias(&out, "pfB_PRI1_v4")
            .get_text(&["content"])
            .unwrap_or("")
            .contains("pfblockerng.php"));
    }

    #[test]
    fn prunes_pfblocker_floating_rules() {
        let mut root = parse(
            br#"<opnsense><filter>
                <rule><floating>yes</floating><source><address>pfB_Top_v4</address></source></rule>
                <rule><floating>yes</floating><source><address>LAN_NET</address></source></rule>
                <rule><interface>lan</interface><source><address>pfB_Top_v6</address></source></rule>
            </filter></opnsense>"#,
        )
        .expect("parse");
        prune_pfblocker_floating_rules_for_opnsense(&mut root);
        let filter = root.get_child("filter").expect("filter");
        assert_eq!(
            filter.children.iter().filter(|c| c.tag == "rule").count(),
            2
        );
    }
}
