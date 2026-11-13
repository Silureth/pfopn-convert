//! pfBlockerNG DNSBL to OPNsense's Unbound DNS blocklist
//! (`OPNsense/unboundplus/dnsbl/blocklist`).
//!
//! pfBlockerNG applies all its DNSBL groups to every client, so they become a
//! single blocklist policy without source networks. OPNsense's reader keeps
//! the last word of each line before a `#` and drops anything that is not a
//! plain domain, so hosts files and domain lists work, adblock-format lists
//! (`||example.com^`) load nothing. Its allowlist entries are regular
//! expressions matched from the start of the queried name.

use xml_diff_core::XmlNode;

use crate::transform::filter_mvc::stable_uuid;
use crate::transform::mvc_util::{decode_base64, ensure_path, model_mut, node_at, push, text};

const UNBOUND_MODEL: &[&str] = &["OPNsense", "unboundplus"];
const CRON_MODEL: &[&str] = &["OPNsense", "cron"];

/// DNSBL feeds that no longer publish usable data (checked November 2026).
const DEAD_FEEDS: &[(&str, &str)] = &[
    (
        "cyberthreatcoalition.org",
        "the COVID-19 Cyber Threat Coalition list is no longer published",
    ),
    (
        "kriskintel.com",
        "the KRISK Intel COVID-19 list is no longer published",
    ),
    (
        "malwaredomains.com",
        "the malwaredomains.com lists are no longer published",
    ),
    ("malwaredomainlist.com", "Malware Domain List is offline"),
    (
        "stamparm/aux/master/maltrail-malware-domains",
        "the file was removed from the Maltrail repository",
    ),
    (
        "juniper.net/security/auto/spam",
        "the URL returns an empty list",
    ),
    (
        "zerodot1.gitlab.io/coinblockerlists",
        "CoinBlockerLists is no longer served",
    ),
];

/// Adblock-format feeds OPNsense cannot read, with the predefined OPNsense
/// list (domain-only copy of the same list) to use instead.
const PREDEFINED_FEEDS: &[(&str, &str, &str)] = &[
    ("easylist.to/easylist/easylist.txt", "el", "EasyList"),
    ("adblockplus.org/easylist", "el", "EasyList"),
    ("easylist.to/easylist/easyprivacy.txt", "ep", "EasyPrivacy"),
    ("adblockplus.org/easyprivacy", "ep", "EasyPrivacy"),
];

#[derive(Debug, Default)]
pub struct DnsblReport {
    /// pfBlockerNG DNSBL is enabled in the source.
    pub present: bool,
    /// Groups that went into the blocklist policy.
    pub groups: Vec<String>,
    /// Custom feed URLs kept.
    pub feeds: usize,
    /// OPNsense predefined lists used instead of adblock-format feeds.
    pub predefined: Vec<String>,
    pub allowlist: usize,
    pub blocklist: usize,
    /// Cron schedule of the added "Update Unbound DNSBLs" job.
    pub cron: Option<String>,
    pub warnings: Vec<String>,
}

/// Convert pfBlockerNG's DNSBL groups, suppression list and custom domains
/// into one Unbound blocklist policy. Without `apply`, only reports whether
/// there is anything to convert.
pub fn to_unbound_blocklist(
    out: &mut XmlNode,
    source: &XmlNode,
    baseline: &XmlNode,
    apply: bool,
) -> DnsblReport {
    let mut report = DnsblReport::default();
    let Some(packages) = source.get_child("installedpackages") else {
        return report;
    };
    let general_on = node_at(packages, &["pfblockerng", "config"])
        .is_some_and(|c| text(c, "enable_cb").eq_ignore_ascii_case("on"));
    let Some(settings) = node_at(packages, &["pfblockerngdnsblsettings", "config"]) else {
        return report;
    };
    if !general_on || !text(settings, "pfb_dnsbl").eq_ignore_ascii_case("on") {
        return report;
    }
    let groups: Vec<&XmlNode> = packages
        .get_child("pfblockerngdnsbl")
        .map(|n| n.get_children("config"))
        .unwrap_or_default()
        .into_iter()
        .filter(|g| !text(g, "action").eq_ignore_ascii_case("disabled"))
        .collect();
    report.present = true;
    if !apply {
        return report;
    }

    let mut lists: Vec<String> = Vec::new();
    let mut types: Vec<&'static str> = Vec::new();
    let mut blocklist: Vec<String> = Vec::new();
    let mut crons: Vec<String> = Vec::new();
    for group in &groups {
        let name = text(group, "aliasname");
        report.groups.push(name.clone());
        crons.push(text(group, "cron"));
        for row in group.get_children("row") {
            if text(row, "state").eq_ignore_ascii_case("disabled") {
                continue;
            }
            let url = text(row, "url");
            let lower = url.to_ascii_lowercase();
            if !(lower.starts_with("http://") || lower.starts_with("https://")) {
                if !url.is_empty() {
                    report.warnings.push(format!(
                        "DNSBL {name}: skipped {url} (not a URL; local files are not converted)"
                    ));
                }
                continue;
            }
            if let Some((_, reason)) = DEAD_FEEDS.iter().find(|(p, _)| lower.contains(p)) {
                report
                    .warnings
                    .push(format!("DNSBL {name}: dropped {url} ({reason})"));
                continue;
            }
            if let Some((_, code, label)) =
                PREDEFINED_FEEDS.iter().find(|(p, _, _)| lower.contains(p))
            {
                report.warnings.push(format!(
                    "DNSBL {name}: replaced {url} with OPNsense's predefined {label} list (the feed is in adblock format, which OPNsense's blocklist reader skips)"
                ));
                if !types.contains(code) {
                    types.push(code);
                    report.predefined.push((*label).to_string());
                }
                continue;
            }
            if !lists.iter().any(|u| u.eq_ignore_ascii_case(&url)) {
                lists.push(url);
            }
        }
        for line in decoded_lines(&text(group, "custom")) {
            match plain_domain(&line) {
                Some(domain) => {
                    if !blocklist.contains(&domain) {
                        blocklist.push(domain);
                    }
                }
                None => report.warnings.push(format!(
                    "DNSBL {name}: custom entry '{line}' is not a domain; skipped"
                )),
            }
        }
    }
    report.feeds = lists.len();
    report.blocklist = blocklist.len();

    let mut allowlist: Vec<String> = Vec::new();
    for line in decoded_lines(&text(settings, "suppression")) {
        match allowlist_pattern(&line) {
            Some(p) => {
                if !allowlist.contains(&p) {
                    allowlist.push(p);
                }
            }
            None => report.warnings.push(format!(
                "DNSBL suppression entry '{line}' is not a domain; skipped"
            )),
        }
    }
    report.allowlist = allowlist.len();

    if text(settings, "pfb_tld").eq_ignore_ascii_case("on") {
        report.warnings.push(
            "DNSBL: TLD wildcard blocking not converted; OPNsense blocks subdomains only for list entries written as *.domain and for Wildcard Domains".to_string(),
        );
    }
    if node_at(packages, &["pfblockerngsafesearch", "config"]).is_some_and(|c| {
        c.children.iter().any(|f| {
            let v = f.text.as_deref().unwrap_or("").trim();
            v.eq_ignore_ascii_case("enable") || v.eq_ignore_ascii_case("on")
        })
    }) {
        report
            .warnings
            .push("DNSBL: SafeSearch settings not converted".to_string());
    }

    if lists.is_empty() && types.is_empty() && blocklist.is_empty() {
        report.warnings.push(
            "DNSBL: no usable feed or custom domain left; no Unbound blocklist created".to_string(),
        );
        return report;
    }

    let interval = shortest_interval_hours(&crons);
    let Some(model) = model_mut(out, baseline, UNBOUND_MODEL) else {
        report
            .warnings
            .push("DNSBL: the baseline has no Unbound model; blocklist not converted".to_string());
        return report;
    };
    let description: String = format!("pfBlockerNG DNSBL: {}", report.groups.join(", "))
        .chars()
        .take(255)
        .collect();
    let mut entry = XmlNode::new("blocklist");
    entry
        .attributes
        .insert("uuid".to_string(), stable_uuid("unbound-dnsbl|pfblockerng"));
    push(&mut entry, "enabled", "1");
    push(&mut entry, "type", &types.join(","));
    push(&mut entry, "lists", &lists.join(","));
    push(&mut entry, "allowlists", &allowlist.join(","));
    push(&mut entry, "blocklists", &blocklist.join(","));
    push(&mut entry, "wildcards", "");
    push(&mut entry, "source_nets", "");
    push(&mut entry, "address", "");
    push(&mut entry, "nxdomain", "0");
    push(&mut entry, "cache_ttl", &cache_ttl(interval).to_string());
    push(&mut entry, "description", &description);
    let dnsbl = ensure_path(model, &["dnsbl"]);
    dnsbl.text = None;
    dnsbl.children.retain(|c| {
        c.tag != "blocklist" || c.attributes.get("uuid") != entry.attributes.get("uuid")
    });
    dnsbl.children.push(entry);

    // OPNsense downloads the lists when Unbound starts and when the
    // "Update Unbound DNSBLs" action runs; pfBlockerNG refreshed on its own
    // schedule, so add a cron job for it.
    let (minutes, hours, weekdays) = cron_schedule(interval);
    match model_mut(out, baseline, CRON_MODEL) {
        Some(cron) => {
            let jobs = ensure_path(cron, &["jobs"]);
            jobs.text = None;
            let mut job = XmlNode::new("job");
            job.attributes
                .insert("uuid".to_string(), stable_uuid("cron|unbound dnsbl|pfblockerng"));
            let uuid = job.attributes.get("uuid").cloned();
            push(&mut job, "origin", "cron");
            push(&mut job, "enabled", "1");
            push(&mut job, "minutes", &minutes);
            push(&mut job, "hours", &hours);
            push(&mut job, "days", "*");
            push(&mut job, "months", "*");
            push(&mut job, "weekdays", &weekdays);
            push(&mut job, "who", "root");
            push(&mut job, "command", "unbound dnsbl");
            push(&mut job, "parameters", "");
            push(&mut job, "description", "Update Unbound DNSBLs (from pfBlockerNG)");
            jobs.children
                .retain(|c| c.tag != "job" || c.attributes.get("uuid") != uuid.as_ref());
            jobs.children.push(job);
            report.cron = Some(format!("{minutes} {hours} * * {weekdays}"));
        }
        None => report.warnings.push(
            "DNSBL: the baseline has no cron model; add a cron job for \"Update Unbound DNSBLs\" in System > Settings > Cron".to_string(),
        ),
    }
    report
}

/// Lines of a pfBlockerNG textarea (base64, sometimes plain), without
/// comments and blank lines.
fn decoded_lines(raw: &str) -> Vec<String> {
    if raw.trim().is_empty() {
        return Vec::new();
    }
    let decoded = decode_base64(raw).unwrap_or_else(|| raw.to_string());
    decoded
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// A lower-case domain name, or `None` if `s` is not one.
fn plain_domain(s: &str) -> Option<String> {
    let d = s.trim().trim_end_matches('.').to_ascii_lowercase();
    let ok = !d.is_empty()
        && d.contains('.')
        && d.split('.').all(|label| {
            !label.is_empty()
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        });
    ok.then_some(d)
}

/// A pfBlockerNG suppression entry as an OPNsense allowlist regex.
/// `example.com` allows only that name; `.example.com` also its subdomains.
/// OPNsense matches the pattern from the start of the name, so the end is
/// anchored here.
fn allowlist_pattern(entry: &str) -> Option<String> {
    let (wildcard, name) = match entry.strip_prefix('.') {
        Some(rest) => (true, rest),
        None => (false, entry),
    };
    let domain = plain_domain(name)?;
    let escaped = domain.replace('.', "\\.");
    Some(if wildcard {
        format!("(.*\\.)?{escaped}$")
    } else {
        format!("{escaped}$")
    })
}

/// Shortest pfBlockerNG update interval of the groups, in hours.
fn shortest_interval_hours(crons: &[String]) -> u32 {
    crons
        .iter()
        .filter_map(|c| match c.trim() {
            "EveryDay" => Some(24),
            "Weekly" => Some(168),
            c => c
                .strip_suffix("hours")
                .or_else(|| c.strip_suffix("hour"))
                .and_then(|h| h.parse::<u32>().ok())
                .filter(|h| *h > 0),
        })
        .min()
        .unwrap_or(24)
}

/// Seconds OPNsense keeps a downloaded list: a bit shorter than the update
/// interval, so every scheduled update downloads fresh data.
fn cache_ttl(interval_hours: u32) -> u32 {
    if interval_hours >= 24 {
        72000 * (interval_hours / 24)
    } else {
        interval_hours * 3600 - 600
    }
}

/// (minutes, hours, weekdays) of the cron job for the update interval.
fn cron_schedule(interval_hours: u32) -> (String, String, String) {
    match interval_hours {
        168.. => ("0".into(), "1".into(), "0".into()),
        24.. => ("0".into(), "1".into(), "*".into()),
        1 => ("0".into(), "*".into(), "*".into()),
        h => ("0".into(), format!("*/{h}"), "*".into()),
    }
}

/// Remove what pfBlockerNG's DNSBL leaves behind in the converted config: the
/// virtual IP its block page web server listens on (`pfb_dnsvip`, usually
/// 10.10.10.1 on lo0) and the `pfB_DNSBL_*` port alias of its (already
/// removed) floating rules. Returns the removed items.
pub fn remove_dnsbl_leftovers(out: &mut XmlNode, source: &XmlNode) -> Vec<String> {
    let mut removed = Vec::new();
    let vip_addr = node_at(
        source,
        &["installedpackages", "pfblockerngdnsblsettings", "config"],
    )
    .map(|c| text(c, "pfb_dnsvip"))
    .unwrap_or_default();
    if let Some(vips) = out.children.iter_mut().find(|c| c.tag == "virtualip") {
        vips.children.retain(|vip| {
            if vip.tag != "vip" {
                return true;
            }
            let descr = text(vip, "descr").to_ascii_lowercase();
            let subnet = text(vip, "subnet");
            let is_dnsbl = descr.starts_with("pfb dnsbl")
                || (!vip_addr.is_empty()
                    && subnet == vip_addr
                    && text(vip, "interface").eq_ignore_ascii_case("lo0"));
            if is_dnsbl {
                removed.push(format!("virtual IP {subnet} ({})", text(vip, "interface")));
            }
            !is_dnsbl
        });
    }
    if let Some(aliases) = node_mut(out, &["OPNsense", "Firewall", "Alias", "aliases"]) {
        aliases.children.retain(|alias| {
            let name = text(alias, "name");
            let is_dnsbl =
                alias.tag == "alias" && name.to_ascii_lowercase().starts_with("pfb_dnsbl");
            if is_dnsbl {
                removed.push(format!("alias {name}"));
            }
            !is_dnsbl
        });
    }
    removed
}

fn node_mut<'a>(root: &'a mut XmlNode, path: &[&str]) -> Option<&'a mut XmlNode> {
    let mut node = root;
    for tag in path {
        let idx = node.children.iter().position(|c| c.tag == *tag)?;
        node = &mut node.children[idx];
    }
    Some(node)
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::{allowlist_pattern, remove_dnsbl_leftovers, to_unbound_blocklist};

    // "s3.amazonaws.com\n.github.com # comment\nnot a domain!\n" in base64
    const SOURCE: &str = r#"<pfsense><installedpackages>
        <pfblockerng><config><enable_cb>on</enable_cb></config></pfblockerng>
        <pfblockerngdnsblsettings><config>
            <pfb_dnsbl>on</pfb_dnsbl>
            <pfb_dnsvip>10.10.10.1</pfb_dnsvip>
            <suppression>SUPPRESSION</suppression>
        </config></pfblockerngdnsblsettings>
        <pfblockerngdnsbl>
            <config>
                <aliasname>EasyList</aliasname>
                <action>unbound</action>
                <cron>EveryDay</cron>
                <row><format>auto</format><state>Enabled</state><url>https://easylist-downloads.adblockplus.org/easylist_noelemhide.txt</url></row>
                <row><format>auto</format><state>Enabled</state><url>https://easylist.to/easylist/easyprivacy.txt</url></row>
            </config>
            <config>
                <aliasname>Malicious</aliasname>
                <action>unbound</action>
                <cron>EveryDay</cron>
                <row><format>auto</format><state>Enabled</state><url>https://someonewhocares.org/hosts/hosts</url></row>
                <row><format>auto</format><state>Disabled</state><url>https://feeds.example.org/off.txt</url></row>
                <row><format>auto</format><state>Enabled</state><url>https://mirror1.malwaredomains.com/files/justdomains</url></row>
                <custom>CUSTOM</custom>
            </config>
            <config>
                <aliasname>Off</aliasname>
                <action>Disabled</action>
                <row><format>auto</format><state>Enabled</state><url>https://feeds.example.org/group-off.txt</url></row>
            </config>
        </pfblockerngdnsbl>
    </installedpackages></pfsense>"#;

    const BASELINE: &[u8] = br#"<opnsense><OPNsense>
        <unboundplus version="1.0.15"><dnsbl/></unboundplus>
        <cron version="1.0.4"><jobs/></cron>
    </OPNsense></opnsense>"#;

    fn b64(s: &str) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in s.as_bytes().chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    fn source() -> xml_diff_core::XmlNode {
        let xml = SOURCE
            .replace(
                "SUPPRESSION",
                &b64("s3.amazonaws.com\r\n.github.com # comment\r\nnot a domain!\r\n"),
            )
            .replace("CUSTOM", &b64("bad.example.net\n"));
        parse(xml.as_bytes()).expect("parse")
    }

    #[test]
    fn dnsbl_becomes_one_unbound_blocklist() {
        let source = source();
        let baseline = parse(BASELINE).expect("baseline");
        let mut out = parse(BASELINE).expect("out");
        let report = to_unbound_blocklist(&mut out, &source, &baseline, true);

        let bl = out
            .get_child("OPNsense")
            .and_then(|n| n.get_child("unboundplus"))
            .and_then(|n| n.get_child("dnsbl"))
            .and_then(|n| n.get_child("blocklist"))
            .expect("blocklist");
        assert_eq!(bl.get_text(&["enabled"]), Some("1"));
        assert_eq!(bl.get_text(&["type"]), Some("el,ep"));
        assert_eq!(
            bl.get_text(&["lists"]),
            Some("https://someonewhocares.org/hosts/hosts")
        );
        assert_eq!(
            bl.get_text(&["allowlists"]),
            Some("s3\\.amazonaws\\.com$,(.*\\.)?github\\.com$")
        );
        assert_eq!(bl.get_text(&["blocklists"]), Some("bad.example.net"));
        assert_eq!(bl.get_text(&["source_nets"]), Some(""));
        assert_eq!(bl.get_text(&["cache_ttl"]), Some("72000"));
        assert_eq!(
            bl.get_text(&["description"]),
            Some("pfBlockerNG DNSBL: EasyList, Malicious")
        );

        let job = out
            .get_child("OPNsense")
            .and_then(|n| n.get_child("cron"))
            .and_then(|n| n.get_child("jobs"))
            .and_then(|n| n.get_child("job"))
            .expect("cron job");
        assert_eq!(job.get_text(&["command"]), Some("unbound dnsbl"));
        assert_eq!(job.get_text(&["hours"]), Some("1"));
        assert_eq!(report.cron.as_deref(), Some("0 1 * * *"));

        assert!(report.present);
        assert_eq!(report.feeds, 1);
        assert_eq!(report.allowlist, 2);
        assert!(report.warnings.iter().any(|w| w.contains("malwaredomains")));
        assert!(report.warnings.iter().any(|w| w.contains("not a domain!")));
        assert!(!report.warnings.iter().any(|w| w.contains("off.txt")));
    }

    #[test]
    fn dnsbl_only_reported_without_switch() {
        let source = source();
        let baseline = parse(BASELINE).expect("baseline");
        let mut out = parse(BASELINE).expect("out");
        let before = out.clone();
        let report = to_unbound_blocklist(&mut out, &source, &baseline, false);
        assert!(report.present);
        assert_eq!(out, before);
    }

    #[test]
    fn dnsbl_switched_off_is_ignored() {
        let source = parse(
            br#"<pfsense><installedpackages>
                <pfblockerng><config><enable_cb>on</enable_cb></config></pfblockerng>
                <pfblockerngdnsblsettings><config><pfb_dnsbl></pfb_dnsbl></config></pfblockerngdnsblsettings>
            </installedpackages></pfsense>"#,
        )
        .expect("parse");
        let baseline = parse(BASELINE).expect("baseline");
        let mut out = parse(BASELINE).expect("out");
        let report = to_unbound_blocklist(&mut out, &source, &baseline, true);
        assert!(!report.present);
    }

    #[test]
    fn allowlist_patterns_are_anchored() {
        assert_eq!(
            allowlist_pattern("www.Example.com").as_deref(),
            Some("www\\.example\\.com$")
        );
        assert_eq!(
            allowlist_pattern(".example.com").as_deref(),
            Some("(.*\\.)?example\\.com$")
        );
        assert_eq!(allowlist_pattern("localhost"), None);
        assert_eq!(allowlist_pattern("a b.com"), None);
    }

    #[test]
    fn removes_dnsbl_vip_and_alias() {
        let source = source();
        let mut out = parse(
            br#"<opnsense>
                <virtualip version="1.0.1">
                    <vip><interface>lo0</interface><descr>pfB DNSBL - DO NOT EDIT</descr><subnet>10.10.10.1</subnet></vip>
                    <vip><interface>lan</interface><descr>web</descr><subnet>192.0.2.10</subnet></vip>
                </virtualip>
                <OPNsense><Firewall><Alias><aliases>
                    <alias><name>pfB_DNSBL_Ports</name><type>port</type></alias>
                    <alias><name>pfB_PRI1_v4</name><type>urltable</type></alias>
                </aliases></Alias></Firewall></OPNsense>
            </opnsense>"#,
        )
        .expect("parse");
        let removed = remove_dnsbl_leftovers(&mut out, &source);
        assert_eq!(removed.len(), 2);
        let vips = out.get_child("virtualip").expect("vips");
        assert_eq!(vips.get_children("vip").len(), 1);
        let aliases = out
            .get_child("OPNsense")
            .and_then(|n| n.get_child("Firewall"))
            .and_then(|n| n.get_child("Alias"))
            .and_then(|n| n.get_child("aliases"))
            .expect("aliases");
        assert_eq!(aliases.get_children("alias").len(), 1);
    }
}
