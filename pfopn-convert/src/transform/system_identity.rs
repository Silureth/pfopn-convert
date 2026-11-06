use xml_diff_core::XmlNode;

/// Copy system identity and network settings to OPNsense output.
///
/// Transfers hostname, domain, DNS servers, NTP servers, and DNS settings from
/// the source config to the output. These settings are platform-agnostic and
/// work the same way in both pfSense and OPNsense.
pub fn to_opnsense(out: &mut XmlNode, source: &XmlNode, destination_baseline: &XmlNode) {
    copy_identity_fields(out, source);
    rebrand_vendor_pool(out, destination_baseline, "pfsense", "opnsense");
    keep_baseline_only_keys(out, destination_baseline, OPNSENSE_ONLY_SYSTEM_KEYS);
}

/// OPNsense `system` settings with no pfSense counterpart, kept from the
/// baseline so the result matches a fresh install:
/// - `pf_share_forward`: share policy-routing decisions with the traffic
///   shaper and captive portal (Firewall > Settings > Advanced > Shared
///   forwarding; on by default).
const OPNSENSE_ONLY_SYSTEM_KEYS: &[&str] = &["pf_share_forward"];

/// Copy `keys` from the baseline's `system` when the output has none.
fn keep_baseline_only_keys(out: &mut XmlNode, baseline: &XmlNode, keys: &[&str]) {
    let Some(base_system) = baseline.get_child("system") else {
        return;
    };
    let Some(system) = out.children.iter_mut().find(|n| n.tag == "system") else {
        return;
    };
    for key in keys {
        if system.get_child(key).is_some() {
            continue;
        }
        if let Some(node) = base_system.get_child(key) {
            system.children.push(node.clone());
        }
    }
}

/// Copy system identity and network settings to pfSense output.
///
/// Transfers hostname, domain, DNS servers, NTP servers, and DNS settings from
/// the source config to the output. These settings are platform-agnostic and
/// work the same way in both pfSense and OPNsense.
pub fn to_pfsense(out: &mut XmlNode, source: &XmlNode, destination_baseline: &XmlNode) {
    copy_identity_fields(out, source);
    rebrand_vendor_pool(out, destination_baseline, "opnsense", "pfsense");
}

/// Replace the source vendor's NTP pool (`N.<from>.pool.ntp.org`) with the
/// destination vendor's.
///
/// If every time server is the source vendor's pool (the factory default), the
/// destination baseline's list is used instead, so the result matches a fresh
/// install. Otherwise each vendor pool entry is renamed and the rest is kept.
fn rebrand_vendor_pool(out: &mut XmlNode, baseline: &XmlNode, from: &str, to: &str) {
    let from_suffix = format!(".{from}.pool.ntp.org");
    let Some(system) = out.children.iter_mut().find(|n| n.tag == "system") else {
        return;
    };
    let Some(current) = system.get_text(&["timeservers"]).map(str::to_string) else {
        return;
    };
    let servers: Vec<&str> = current.split_whitespace().collect();
    let is_vendor = |s: &str| s.to_ascii_lowercase().ends_with(&from_suffix);
    if !servers.iter().any(|s| is_vendor(s)) {
        return;
    }

    let baseline_servers = baseline
        .get_text(&["system", "timeservers"])
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let new_value = match baseline_servers {
        Some(b) if servers.iter().all(|s| is_vendor(s)) => b.to_string(),
        _ => servers
            .iter()
            .map(|s| {
                if is_vendor(s) {
                    let host = &s[..s.len() - from_suffix.len()];
                    format!("{host}.{to}.pool.ntp.org")
                } else {
                    (*s).to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(" "),
    };
    set_or_insert_text_child(system, "timeservers", &new_value);
}

/// Copy system identity fields from source to output.
///
/// Fields copied:
/// - hostname: The firewall's hostname (e.g., "fw-prod")
/// - domain: The DNS domain (e.g., "example.com")
/// - timeservers: Space-separated NTP server list (e.g., "0.pool.ntp.org 1.pool.ntp.org")
/// - dnsserver: DNS resolver addresses (can have multiple <dnsserver> elements)
/// - dnsallowoverride: Whether to allow DNS servers from DHCP/PPP to override static config
/// - dns1gw through dns8gw: Which gateway each DNS server should use (multi-WAN routing)
fn copy_identity_fields(out: &mut XmlNode, source: &XmlNode) {
    let Some(src_system) = source.get_child("system") else {
        return;
    };
    let Some(dst_system) = out.children.iter_mut().find(|n| n.tag == "system") else {
        return;
    };

    // Copy simple single-value fields
    for field in ["hostname", "domain", "timeservers"] {
        let Some(value) = src_system.get_text(&[field]).map(str::trim) else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        set_or_insert_text_child(dst_system, field, value);
    }

    // Copy DNS-related settings (these can appear multiple times or have complex structure)
    for field in [
        "dnsallowoverride",         // Allow DNS override from DHCP/PPP
        "dnsallowoverride_exclude", // Interfaces to exclude from DNS override
        "dns1gw",                   // Gateway for first DNS server
        "dns2gw",                   // Gateway for second DNS server
        "dns3gw",
        "dns4gw",
        "dns5gw",
        "dns6gw",
        "dns7gw",
        "dns8gw",
    ] {
        sync_all_children_by_tag(dst_system, src_system, field);
    }

    // Copy all <dnsserver> elements (there can be multiple)
    sync_all_children_by_tag(dst_system, src_system, "dnsserver");
}

/// Set or insert a text child element in a node.
///
/// If a child with the given tag already exists, update its text content.
/// Otherwise, create a new child element with that tag and text.
fn set_or_insert_text_child(node: &mut XmlNode, tag: &str, value: &str) {
    if let Some(child) = node.children.iter_mut().find(|c| c.tag == tag) {
        child.text = Some(value.to_string());
        return;
    }
    let mut child = XmlNode::new(tag);
    child.text = Some(value.to_string());
    node.children.push(child);
}

/// Copy all children with a given tag from src to dst, replacing any existing ones.
///
/// This is used for fields that can appear multiple times (like <dnsserver>) or
/// fields where we want to ensure the destination exactly matches the source.
fn sync_all_children_by_tag(dst: &mut XmlNode, src: &XmlNode, tag: &str) {
    // Remove all existing children with this tag
    dst.children.retain(|c| c.tag != tag);

    // Copy all matching children from source
    for child in &src.children {
        if child.tag == tag {
            dst.children.push(child.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::{to_opnsense, to_pfsense};

    #[test]
    fn copies_hostname_and_domain_to_opnsense() {
        let source = parse(
            br#"<pfsense><system><hostname>gw-a</hostname><domain>example.net</domain></system></pfsense>"#,
        )
        .expect("parse");
        let mut out = parse(
            br#"<opnsense><system><hostname>dst</hostname><domain>dst.local</domain></system></opnsense>"#,
        )
        .expect("parse");
        let baseline = out.clone();

        to_opnsense(&mut out, &source, &baseline);
        assert_eq!(out.get_text(&["system", "hostname"]), Some("gw-a"));
        assert_eq!(out.get_text(&["system", "domain"]), Some("example.net"));
    }

    #[test]
    fn copies_timeservers() {
        let source = parse(
            br#"<pfsense><system><timeservers>1.1.1.1 2.2.2.2</timeservers></system></pfsense>"#,
        )
        .expect("parse");
        let mut out = parse(
            br#"<opnsense><system><timeservers>0.pool.ntp.org</timeservers></system></opnsense>"#,
        )
        .expect("parse");
        let baseline = out.clone();

        to_opnsense(&mut out, &source, &baseline);
        assert_eq!(
            out.get_text(&["system", "timeservers"]),
            Some("1.1.1.1 2.2.2.2")
        );
    }

    #[test]
    fn default_vendor_pool_uses_baseline_servers() {
        let source = parse(
            br#"<pfsense><system><timeservers>0.pfsense.pool.ntp.org</timeservers></system></pfsense>"#,
        )
        .expect("parse");
        let mut out = parse(
            br#"<opnsense><system><timeservers>0.opnsense.pool.ntp.org 1.opnsense.pool.ntp.org</timeservers></system></opnsense>"#,
        )
        .expect("parse");
        let baseline = out.clone();

        to_opnsense(&mut out, &source, &baseline);
        assert_eq!(
            out.get_text(&["system", "timeservers"]),
            Some("0.opnsense.pool.ntp.org 1.opnsense.pool.ntp.org")
        );
    }

    #[test]
    fn mixed_list_renames_only_vendor_pool() {
        let source = parse(
            br#"<pfsense><system><timeservers>ntp.example.org 2.pfsense.pool.ntp.org 198.51.100.1</timeservers></system></pfsense>"#,
        )
        .expect("parse");
        let mut out = parse(
            br#"<opnsense><system><timeservers>0.opnsense.pool.ntp.org</timeservers></system></opnsense>"#,
        )
        .expect("parse");
        let baseline = out.clone();

        to_opnsense(&mut out, &source, &baseline);
        assert_eq!(
            out.get_text(&["system", "timeservers"]),
            Some("ntp.example.org 2.opnsense.pool.ntp.org 198.51.100.1")
        );
    }

    #[test]
    fn vendor_pool_renamed_when_baseline_has_none() {
        let source = parse(
            br#"<pfsense><system><timeservers>0.pfsense.pool.ntp.org</timeservers></system></pfsense>"#,
        )
        .expect("parse");
        let mut out = parse(br#"<opnsense><system></system></opnsense>"#).expect("parse");
        let baseline = out.clone();

        to_opnsense(&mut out, &source, &baseline);
        assert_eq!(
            out.get_text(&["system", "timeservers"]),
            Some("0.opnsense.pool.ntp.org")
        );
    }

    #[test]
    fn keeps_shared_forwarding_from_baseline() {
        let source = parse(br#"<pfsense><system><hostname>gw</hostname></system></pfsense>"#)
            .expect("parse");
        let baseline = parse(
            br#"<opnsense><system><pf_share_forward>1</pf_share_forward></system></opnsense>"#,
        )
        .expect("parse");
        let mut out = parse(br#"<opnsense><system><hostname>gw</hostname></system></opnsense>"#)
            .expect("parse");

        to_opnsense(&mut out, &source, &baseline);
        assert_eq!(out.get_text(&["system", "pf_share_forward"]), Some("1"));

        // Without it in the baseline, nothing is added.
        let mut out = parse(br#"<opnsense><system/></opnsense>"#).expect("parse");
        let empty = parse(br#"<opnsense><system/></opnsense>"#).expect("parse");
        to_opnsense(&mut out, &source, &empty);
        assert!(out
            .get_child("system")
            .and_then(|s| s.get_child("pf_share_forward"))
            .is_none());
    }

    #[test]
    fn opnsense_pool_becomes_pfsense_pool() {
        let source = parse(
            br#"<opnsense><system><timeservers>0.opnsense.pool.ntp.org 1.opnsense.pool.ntp.org</timeservers></system></opnsense>"#,
        )
        .expect("parse");
        let mut out = parse(
            br#"<pfsense><system><timeservers>2.pfsense.pool.ntp.org</timeservers></system></pfsense>"#,
        )
        .expect("parse");
        let baseline = out.clone();

        to_pfsense(&mut out, &source, &baseline);
        assert_eq!(
            out.get_text(&["system", "timeservers"]),
            Some("2.pfsense.pool.ntp.org")
        );
    }

    #[test]
    fn copies_hostname_and_domain_to_pfsense() {
        let source = parse(
            br#"<opnsense><system><hostname>fw-opn</hostname><domain>corp.example</domain></system></opnsense>"#,
        )
        .expect("parse");
        let mut out = parse(
            br#"<pfsense><system><hostname>dst</hostname><domain>dst.local</domain></system></pfsense>"#,
        )
        .expect("parse");
        let baseline = out.clone();

        to_pfsense(&mut out, &source, &baseline);
        assert_eq!(out.get_text(&["system", "hostname"]), Some("fw-opn"));
        assert_eq!(out.get_text(&["system", "domain"]), Some("corp.example"));
    }

    #[test]
    fn copies_dns_general_settings_and_servers() {
        let source = parse(
            br#"<pfsense><system>
                <dnsallowoverride>1</dnsallowoverride>
                <dnsallowoverride_exclude/>
                <dnsserver>1.1.1.1</dnsserver>
                <dnsserver>8.8.8.8</dnsserver>
                <dns1gw>none</dns1gw>
                <dns2gw>wan</dns2gw>
            </system></pfsense>"#,
        )
        .expect("parse");
        let mut out = parse(
            br#"<opnsense><system>
                <dnsallowoverride>0</dnsallowoverride>
                <dnsserver>9.9.9.9</dnsserver>
                <dns1gw>foo</dns1gw>
            </system></opnsense>"#,
        )
        .expect("parse");
        let baseline = out.clone();

        to_opnsense(&mut out, &source, &baseline);
        assert_eq!(out.get_text(&["system", "dnsallowoverride"]), Some("1"));
        assert_eq!(out.get_text(&["system", "dns1gw"]), Some("none"));
        assert_eq!(out.get_text(&["system", "dns2gw"]), Some("wan"));
        let dnsservers: Vec<String> = out
            .get_child("system")
            .expect("system")
            .children
            .iter()
            .filter(|c| c.tag == "dnsserver")
            .map(|c| c.text.clone().unwrap_or_default())
            .collect();
        assert_eq!(
            dnsservers,
            vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]
        );
    }
}
