//! OPNsense import-compatibility checks.
//!
//! Each check guards against a specific way a pfSense-derived config is
//! silently misread by OPNsense (mostly 26.7+). They exist so converter
//! regressions are caught by `verify`/`migrate-check` instead of on the box.
//!
//! Errors (the config would behave differently than intended):
//! - `rule_flag_empty`: pfSense-style empty `<disabled/>`, `<log/>`, `<not/>`,
//!   ... in filter/NAT rules. OPNsense tests these with `!empty()`, so a
//!   disabled rule becomes active and inverted matches flip.
//! - `interface_flag_empty`: empty `<blockpriv/>`, `<blockbogons/>`, ... on an
//!   interface. OPNsense reads them with `!empty()`, so "Block private/bogon
//!   networks" is silently off.
//! - `gateway_legacy_ignored`: gateways left in the legacy `<gateways>`
//!   section while the Gateways model exists (OPNsense reads only the model,
//!   so interfaces and policy routes point at gateways that do not exist).
//! - `rule_model_invalid`: a 26.7 firewall/outbound NAT rule that OPNsense's
//!   Filter model rejects on save (ports without TCP/UDP, ICMP types without
//!   ICMP, ...). pf may still load it, but every GUI save of rules fails.
//! - `icmp_type_any`: a firewall rule with ICMP type `any` (pfSense's "all
//!   types"); OPNsense writes it to pf verbatim, a syntax error.
//! - `outbound_nat_family_mismatch`: an IPv4 outbound NAT rule with an IPv6
//!   address (or the reverse); pf rejects the whole ruleset.
//! - `alias_legacy_fields`: an MVC alias still using pfSense's `address`/`url`
//!   fields instead of `content` (alias would be empty).
//! - `kea_pool_separator`: Kea pools joined with `,` (OPNsense splits on newlines).
//! - `kea_reservation_mac_and_client_id`: rejected by OPNsense 26.7 on save.
//! - `nat_legacy_ignored`: legacy `<nat><onetoone>`/`<nat><npt>` while the
//!   Filter model already owns them (OPNsense 26.7 ignores the legacy entries).
//! - `staticroute_disabled_ignored`: `<disabled>` on routes whose model uses
//!   `<enabled>` (the route would come up enabled).
//!
//! Warnings:
//! - `mvc_section_missing_version`: a populated MVC section without a
//!   `version` attribute, so OPNsense re-runs every old migration on it.
//! - `pfsense_match_rule` / `pfsense_nat64_rule`: pfSense-only rule features
//!   OPNsense cannot show or edit.

use xml_diff_core::XmlNode;

use crate::transform::rule_flags::{INTERFACE_FLAGS, RULE_FLAGS};
use crate::transform::version::{model_version, version_at_least};
use crate::verify_interfaces::{FindingSeverity, VerifyFinding};

/// Run all OPNsense compatibility checks. Returns nothing for non-OPNsense roots.
pub fn opnsense_compat_findings(root: &XmlNode) -> Vec<VerifyFinding> {
    if root.tag != "opnsense" {
        return Vec::new();
    }
    let mut out = Vec::new();
    rule_flag_findings(root, &mut out);
    interface_flag_findings(root, &mut out);
    gateway_findings(root, &mut out);
    outbound_family_findings(root, &mut out);
    icmp_any_findings(root, &mut out);
    rule_model_findings(root, &mut out);
    pfsense_rule_feature_findings(root, &mut out);
    alias_findings(root, &mut out);
    kea_findings(root, &mut out);
    legacy_nat_findings(root, &mut out);
    static_route_findings(root, &mut out);
    missing_version_findings(root, &mut out);
    out
}

fn rule_flag_findings(root: &XmlNode, out: &mut Vec<VerifyFinding>) {
    let nat = root.get_child("nat");
    let groups: [(&str, Vec<&XmlNode>); 5] = [
        ("filter rule", children(root.get_child("filter"), "rule")),
        ("port forward", children(nat, "rule")),
        (
            "outbound NAT rule",
            children(nat.and_then(|n| n.get_child("outbound")), "rule"),
        ),
        ("1:1 NAT rule", children(nat, "onetoone")),
        ("NPt rule", children(nat, "npt")),
    ];
    for (kind, rules) in groups {
        for (idx, rule) in rules.iter().enumerate() {
            let mut empty: Vec<String> = RULE_FLAGS
                .iter()
                .filter(|flag| is_empty_leaf(rule.get_child(flag)))
                .map(|flag| flag.to_string())
                .collect();
            for block in ["source", "destination"] {
                if is_empty_leaf(rule.get_child(block).and_then(|b| b.get_child("not"))) {
                    empty.push(format!("{block}/not"));
                }
            }
            if !empty.is_empty() {
                out.push(error(
                    "rule_flag_empty",
                    format!(
                        "{kind} #{} {}has empty flag(s) {}; OPNsense reads them as off",
                        idx + 1,
                        describe(rule),
                        empty.join(", ")
                    ),
                ));
            }
        }
    }
}

fn interface_flag_findings(root: &XmlNode, out: &mut Vec<VerifyFinding>) {
    let Some(interfaces) = root.get_child("interfaces") else {
        return;
    };
    for iface in &interfaces.children {
        // `enable` is read with isset() for interfaces, so an empty one is harmless.
        let empty: Vec<&str> = INTERFACE_FLAGS
            .iter()
            .copied()
            .filter(|flag| *flag != "enable" && is_empty_leaf(iface.get_child(flag)))
            .collect();
        if !empty.is_empty() {
            out.push(error(
                "interface_flag_empty",
                format!(
                    "interface {} {}has empty flag(s) {}; OPNsense reads them as off",
                    iface.tag,
                    describe(iface),
                    empty.join(", ")
                ),
            ));
        }
    }
}

fn gateway_findings(root: &XmlNode, out: &mut Vec<VerifyFinding>) {
    if path(root, &["OPNsense", "Gateways"]).is_none() {
        return;
    }
    let legacy: Vec<String> = children(root.get_child("gateways"), "gateway_item")
        .iter()
        .map(|g| g.get_text(&["name"]).unwrap_or("").trim().to_string())
        .collect();
    if !legacy.is_empty() {
        out.push(error(
            "gateway_legacy_ignored",
            format!(
                "gateway(s) {} are in the legacy <gateways> section; OPNsense only reads OPNsense/Gateways",
                legacy.join(", ")
            ),
        ));
    }
}

/// Mirrors the rule checks in OPNsense's `Filter::performValidation` (26.7).
fn rule_model_findings(root: &XmlNode, out: &mut Vec<VerifyFinding>) {
    const PORT_PROTOS: [&str; 3] = ["TCP", "UDP", "TCP/UDP"];
    for (section, kind) in [
        ("rules", "firewall rule"),
        ("snatrules", "outbound NAT rule"),
    ] {
        let rules = children(
            path(root, &["OPNsense", "Firewall", "Filter", section]),
            "rule",
        );
        for (idx, rule) in rules.iter().enumerate() {
            let get = |f: &str| rule.get_text(&[f]).map(str::trim).unwrap_or("").to_string();
            let protocol = get("protocol");
            let mut problems = Vec::new();
            for port in ["source_port", "destination_port", "target_port"] {
                if !get(port).is_empty() && !PORT_PROTOS.contains(&protocol.as_str()) {
                    problems.push(format!("{port} with protocol '{protocol}'"));
                }
            }
            if !get("icmptype").is_empty() && protocol != "ICMP" {
                problems.push(format!("ICMP type with protocol '{protocol}'"));
            }
            if !get("icmp6type").is_empty() && protocol != "IPV6-ICMP" {
                problems.push(format!("ICMPv6 type with protocol '{protocol}'"));
            }
            for net in ["source_net", "destination_net"] {
                let value = get(net);
                if value.contains(',') && value.split(',').any(|v| v.trim() == "any") {
                    problems.push(format!("{net} combines 'any' with other values"));
                }
            }
            if section == "snatrules" {
                if get("target") == "any" {
                    problems.push("target is 'any'".to_string());
                }
                if !get("poolopts_sourcehashkey").is_empty() && get("poolopts") != "source-hash" {
                    problems.push("source hash key without source-hash pool option".to_string());
                }
            }
            if !problems.is_empty() {
                let descr = get("description");
                out.push(error(
                    "rule_model_invalid",
                    format!(
                        "{kind} #{} {}is rejected by OPNsense on save: {}",
                        idx + 1,
                        if descr.is_empty() {
                            String::new()
                        } else {
                            format!("('{descr}') ")
                        },
                        problems.join("; ")
                    ),
                ));
            }
        }
    }
}

fn icmp_any_findings(root: &XmlNode, out: &mut Vec<VerifyFinding>) {
    let rules = children(
        path(root, &["OPNsense", "Firewall", "Filter", "rules"]),
        "rule",
    );
    for (idx, rule) in rules.iter().enumerate() {
        let has_any = ["icmptype", "icmp6type"].iter().any(|f| {
            rule.get_text(&[f])
                .map(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("any")))
                .unwrap_or(false)
        });
        if has_any {
            let descr = rule.get_text(&["description"]).map(str::trim).unwrap_or("");
            out.push(error(
                "icmp_type_any",
                format!(
                    "firewall rule #{} {}has ICMP type 'any'; pf rejects the whole ruleset (leave the field empty for all types)",
                    idx + 1,
                    if descr.is_empty() { String::new() } else { format!("('{descr}') ") },
                ),
            ));
        }
    }
}

fn outbound_family_findings(root: &XmlNode, out: &mut Vec<VerifyFinding>) {
    let rules = children(
        path(root, &["OPNsense", "Firewall", "Filter", "snatrules"]),
        "rule",
    );
    for (idx, rule) in rules.iter().enumerate() {
        let family = rule.get_text(&["ipprotocol"]).unwrap_or("inet").trim();
        let mismatched: Vec<&str> = ["source_net", "destination_net", "target"]
            .iter()
            .filter_map(|f| rule.get_text(&[f]).map(str::trim))
            .filter(|v| {
                let addr = v.split('/').next().unwrap_or("");
                match family {
                    "inet" => addr.parse::<std::net::Ipv6Addr>().is_ok(),
                    "inet6" => addr.parse::<std::net::Ipv4Addr>().is_ok(),
                    _ => false,
                }
            })
            .collect();
        if !mismatched.is_empty() {
            let descr = rule.get_text(&["description"]).map(str::trim).unwrap_or("");
            out.push(error(
                "outbound_nat_family_mismatch",
                format!(
                    "outbound NAT rule #{} {}is {family} but uses {}; pf rejects the whole ruleset",
                    idx + 1,
                    if descr.is_empty() {
                        String::new()
                    } else {
                        format!("('{descr}') ")
                    },
                    mismatched.join(", ")
                ),
            ));
        }
    }
}

fn pfsense_rule_feature_findings(root: &XmlNode, out: &mut Vec<VerifyFinding>) {
    for (idx, rule) in children(root.get_child("filter"), "rule")
        .iter()
        .enumerate()
    {
        let kind = rule.get_text(&["type"]).map(str::trim).unwrap_or("");
        if kind.eq_ignore_ascii_case("match") {
            out.push(warning(
                "pfsense_match_rule",
                format!(
                    "filter rule #{} {}is a pfSense 'match' rule; OPNsense passes it to pf but cannot show or edit it",
                    idx + 1,
                    describe(rule)
                ),
            ));
        }
        if rule.get_child("nat").is_some() {
            out.push(warning(
                "pfsense_nat64_rule",
                format!(
                    "filter rule #{} {}uses pfSense NAT64; OPNsense does not support it in filter rules, recreate it manually",
                    idx + 1,
                    describe(rule)
                ),
            ));
        }
    }
}

fn alias_findings(root: &XmlNode, out: &mut Vec<VerifyFinding>) {
    let aliases = path(root, &["OPNsense", "Firewall", "Alias", "aliases"]);
    for alias in children(aliases, "alias") {
        let legacy = ["address", "url", "aliasurl", "descr"]
            .iter()
            .any(|tag| alias.get_child(tag).is_some());
        if alias.get_child("content").is_none() && legacy {
            out.push(error(
                "alias_legacy_fields",
                format!(
                    "alias '{}' uses pfSense fields (address/url/descr) instead of OPNsense 'content'; it would be empty",
                    alias.get_text(&["name"]).unwrap_or("?")
                ),
            ));
        }
    }
}

fn kea_findings(root: &XmlNode, out: &mut Vec<VerifyFinding>) {
    for family in ["dhcp4", "dhcp6"] {
        let Some(kea) = path(root, &["OPNsense", "Kea", family]) else {
            continue;
        };
        let subnet_tag = if family == "dhcp4" {
            "subnet4"
        } else {
            "subnet6"
        };
        for subnet in children(kea.get_child("subnets"), subnet_tag) {
            if subnet
                .get_text(&["pools"])
                .map(|p| p.contains(','))
                .unwrap_or(false)
            {
                out.push(error(
                    "kea_pool_separator",
                    format!(
                        "Kea {family} subnet {} has comma-separated pools; OPNsense expects one pool per line",
                        subnet.get_text(&["subnet"]).unwrap_or("?")
                    ),
                ));
            }
        }
        for res in children(kea.get_child("reservations"), "reservation") {
            let has = |tag: &str| {
                res.get_text(&[tag])
                    .map(|v| !v.trim().is_empty())
                    .unwrap_or(false)
            };
            if has("hw_address") && has("client_id") {
                out.push(error(
                    "kea_reservation_mac_and_client_id",
                    format!(
                        "Kea {family} reservation {} has both a MAC and a client ID; OPNsense rejects this",
                        res.get_text(&["ip_address"]).unwrap_or("?")
                    ),
                ));
            }
        }
    }
}

fn legacy_nat_findings(root: &XmlNode, out: &mut Vec<VerifyFinding>) {
    let Some(version) = model_version(root, &["OPNsense", "Firewall", "Filter"]) else {
        return;
    };
    let nat = root.get_child("nat");
    for (tag, min, label) in [
        ("onetoone", [1, 0, 4], "1:1 NAT"),
        ("npt", [1, 0, 3], "NPt"),
    ] {
        let count = children(nat, tag).len();
        if count > 0 && version_at_least(version, &min) {
            out.push(error(
                "nat_legacy_ignored",
                format!(
                    "{count} legacy {label} rule(s) in <nat><{tag}>; this OPNsense version only reads them from the Filter model"
                ),
            ));
        }
    }
}

fn static_route_findings(root: &XmlNode, out: &mut Vec<VerifyFinding>) {
    let Some(routes) = root.get_child("staticroutes") else {
        return;
    };
    let uses_enabled = routes
        .attributes
        .get("version")
        .map(|v| version_at_least(v, &[1, 0, 1]))
        .unwrap_or(false);
    if !uses_enabled {
        return;
    }
    for route in routes.get_children("route") {
        // <disabled>0</disabled> is harmless: the route defaults to enabled anyway.
        if crate::transform::rule_flags::pf_flag_is_set(route, "disabled")
            && route.get_child("enabled").is_none()
        {
            out.push(error(
                "staticroute_disabled_ignored",
                format!(
                    "static route {} uses <disabled> but this route model reads <enabled>; it would come up enabled",
                    route.get_text(&["network"]).unwrap_or("?")
                ),
            ));
        }
    }
}

fn missing_version_findings(root: &XmlNode, out: &mut Vec<VerifyFinding>) {
    let sections: &[&[&str]] = &[
        &["OPNsense", "IPsec"],
        &["OPNsense", "Swanctl"],
        &["OPNsense", "Kea", "dhcp4"],
        &["OPNsense", "Kea", "dhcp6"],
        &["OPNsense", "wireguard", "client"],
        &["OPNsense", "wireguard", "server"],
        &["OPNsense", "wireguard", "general"],
        &["OPNsense", "Firewall", "Alias"],
        &["OPNsense", "Firewall", "Filter"],
    ];
    for section in sections {
        let Some(node) = path(root, section) else {
            continue;
        };
        if !node.children.is_empty() && !node.attributes.contains_key("version") {
            out.push(warning(
                "mvc_section_missing_version",
                format!(
                    "{} has no version attribute; OPNsense will re-run all of its migrations on import",
                    section.join("/")
                ),
            ));
        }
    }
}

fn children<'a>(parent: Option<&'a XmlNode>, tag: &str) -> Vec<&'a XmlNode> {
    parent.map(|p| p.get_children(tag)).unwrap_or_default()
}

fn path<'a>(root: &'a XmlNode, tags: &[&str]) -> Option<&'a XmlNode> {
    tags.iter().try_fold(root, |node, tag| node.get_child(tag))
}

fn is_empty_leaf(node: Option<&XmlNode>) -> bool {
    node.map(|n| n.children.is_empty() && n.text.as_deref().map(str::trim).unwrap_or("").is_empty())
        .unwrap_or(false)
}

fn describe(rule: &XmlNode) -> String {
    match rule.get_text(&["descr"]).map(str::trim) {
        Some(d) if !d.is_empty() => format!("('{d}') "),
        _ => String::new(),
    }
}

fn error(code: &str, message: String) -> VerifyFinding {
    VerifyFinding {
        severity: FindingSeverity::Error,
        code: code.to_string(),
        message,
    }
}

fn warning(code: &str, message: String) -> VerifyFinding {
    VerifyFinding {
        severity: FindingSeverity::Warning,
        code: code.to_string(),
        message,
    }
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::opnsense_compat_findings;

    fn codes(xml: &[u8]) -> Vec<String> {
        let root = parse(xml).expect("parse");
        let mut codes: Vec<String> = opnsense_compat_findings(&root)
            .into_iter()
            .map(|f| f.code)
            .collect();
        codes.sort();
        codes
    }

    #[test]
    fn clean_config_has_no_findings() {
        assert!(codes(
            br#"<opnsense>
                <filter><rule><type>pass</type><disabled>1</disabled><source><any/></source></rule></filter>
                <staticroutes version="1.0.1"><route><network>10.0.0.0/8</network><enabled>0</enabled></route></staticroutes>
                <OPNsense>
                  <Firewall><Alias version="1.0.1"><aliases><alias><name>a</name><content>10.0.0.1</content></alias></aliases></Alias></Firewall>
                  <Kea><dhcp4 version="1.0.7"><subnets><subnet4><subnet>10.0.0.0/24</subnet><pools>10.0.0.10-10.0.0.20
10.0.0.30-10.0.0.40</pools></subnet4></subnets><reservations><reservation><hw_address>aa:bb:cc:dd:ee:ff</hw_address></reservation></reservations></dhcp4></Kea>
                </OPNsense>
            </opnsense>"#
        )
        .is_empty());
    }

    #[test]
    fn flags_each_known_regression() {
        let found = codes(
            br#"<opnsense>
                <interfaces><wan><enable/><if>vtnet0</if><blockpriv/></wan></interfaces>
                <gateways><gateway_item><name>GW_WAN</name></gateway_item></gateways>
                <filter>
                  <rule><type>pass</type><disabled></disabled><source><not/></source></rule>
                  <rule><type>match</type></rule>
                  <rule><type>pass</type><nat><destination>64:ff9b::/96</destination></nat></rule>
                </filter>
                <nat><onetoone><external>203.0.113.1</external></onetoone></nat>
                <staticroutes version="1.0.1"><route><network>10.0.0.0/8</network><disabled></disabled></route></staticroutes>
                <OPNsense>
                  <Firewall>
                    <Alias version="1.0.1"><aliases><alias><name>a</name><address>10.0.0.1 10.0.0.2</address></alias></aliases></Alias>
                    <Filter version="1.0.6"><onetoone/><rules><rule><protocol>ICMP</protocol><icmptype>any</icmptype></rule></rules><snatrules><rule><ipprotocol>inet</ipprotocol><source_net>::1/128</source_net><description>localhost</description></rule><rule><ipprotocol>inet</ipprotocol><protocol>any</protocol><destination_port>500</destination_port></rule></snatrules></Filter>
                  </Firewall>
                  <Gateways version="1.0.0"/>
                  <IPsec><general/></IPsec>
                  <Kea><dhcp4 version="1.0.7"><subnets><subnet4><subnet>10.0.0.0/24</subnet><pools>10.0.0.10-10.0.0.20,10.0.0.30-10.0.0.40</pools></subnet4></subnets><reservations><reservation><hw_address>aa:bb:cc:dd:ee:ff</hw_address><client_id>01:aa</client_id></reservation></reservations></dhcp4></Kea>
                </OPNsense>
            </opnsense>"#,
        );
        for expected in [
            "alias_legacy_fields",
            "gateway_legacy_ignored",
            "interface_flag_empty",
            "outbound_nat_family_mismatch",
            "icmp_type_any",
            "rule_model_invalid",
            "kea_pool_separator",
            "kea_reservation_mac_and_client_id",
            "mvc_section_missing_version",
            "nat_legacy_ignored",
            "pfsense_match_rule",
            "pfsense_nat64_rule",
            "rule_flag_empty",
            "staticroute_disabled_ignored",
        ] {
            assert!(
                found.iter().any(|c| c == expected),
                "missing {expected}: {found:?}"
            );
        }
    }

    #[test]
    fn ignores_pfsense_configs() {
        assert!(codes(
            br#"<pfsense><filter><rule><disabled></disabled></rule></filter></pfsense>"#
        )
        .is_empty());
    }
}
