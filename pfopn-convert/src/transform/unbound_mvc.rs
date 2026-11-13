//! pfSense DNS Resolver (`<unbound>`) to OPNsense's Unbound model
//! (`OPNsense/unboundplus`).
//!
//! OPNsense once used the same legacy `<unbound>` layout and still ships the
//! migrations that import it (`Unbound/Migrations/M1_0_1`, `M1_0_3`, `M1_0_5`,
//! `M1_0_6`), but they only run on models older than the baseline. This
//! transform follows their mapping with two corrections:
//! - pfSense's empty-element booleans (`<dnssec></dnssec>`) are read as set;
//!   the migrations read them with `!empty()` and would turn them off.
//! - domain overrides keep their domain (`M1_0_1` reads it from an undefined
//!   variable, so OPNsense's own import produces forwards without a domain).

use std::collections::BTreeSet;

use xml_diff_core::XmlNode;

use crate::transform::filter_mvc::stable_uuid;
use crate::transform::mvc_util::{
    bool01, decode_base64, ensure_path, model_mut, push, set_path, text,
};
use crate::transform::rule_flags::pf_flag_is_set;

const MODEL_PATH: &[&str] = &["OPNsense", "unboundplus"];

/// pfSense boolean -> OPNsense `general` field.
const GENERAL_FLAGS: &[(&str, &str)] = &[
    ("dnssec", "dnssec"),
    ("regdhcp", "regdhcp"),
    ("regdhcpstatic", "regdhcpstatic"),
    ("txtsupport", "txtsupport"),
];

/// pfSense boolean -> OPNsense `advanced` field (`M1_0_3`).
const ADVANCED_FLAGS: &[(&str, &str)] = &[
    ("hideidentity", "hideidentity"),
    ("hideversion", "hideversion"),
    ("prefetch", "prefetch"),
    ("prefetchkey", "prefetchkey"),
    ("dnssecstripped", "dnssecstripped"),
    ("serveexpired", "serveexpired"),
    ("qnameminstrict", "qnameminstrict"),
    ("extended_statistics", "extendedstatistics"),
    ("log_queries", "logqueries"),
];

/// pfSense value -> OPNsense `advanced` field (`M1_0_3`); empty values keep
/// the baseline default.
const ADVANCED_VALUES: &[(&str, &str)] = &[
    ("outgoing_num_tcp", "outgoingnumtcp"),
    ("incoming_num_tcp", "incomingnumtcp"),
    ("num_queries_per_thread", "numqueriesperthread"),
    ("jostle_timeout", "jostletimeout"),
    ("cache_max_ttl", "cachemaxttl"),
    ("cache_min_ttl", "cacheminttl"),
    ("infra_host_ttl", "infrahostttl"),
    ("infra_cache_numhosts", "infracachenumhosts"),
    ("unwanted_reply_threshold", "unwantedreplythreshold"),
    ("log_verbosity", "logverbosity"),
];

/// pfSense ACL actions -> OPNsense (`M1_0_6`).
const ACL_ACTIONS: &[(&str, &str)] = &[
    ("allow", "allow"),
    ("deny", "deny"),
    ("refuse", "refuse"),
    ("allow snoop", "allow_snoop"),
    ("deny nonlocal", "deny_non_local"),
    ("refuse nonlocal", "refuse_non_local"),
];

#[derive(Debug, Default)]
pub struct UnboundStats {
    pub converted: bool,
    pub hosts: usize,
    pub aliases: usize,
    pub forwards: usize,
    pub acls: usize,
    pub warnings: Vec<String>,
}

pub fn from_pfsense(out: &mut XmlNode, source: &XmlNode, baseline: &XmlNode) -> UnboundStats {
    let mut stats = UnboundStats::default();
    let Some(src) = source.get_child("unbound") else {
        return stats;
    };
    let known_ifaces: BTreeSet<String> = out
        .get_child("interfaces")
        .map(|i| {
            i.children
                .iter()
                .map(|c| c.tag.to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();
    let Some(model) = model_mut(out, baseline, MODEL_PATH) else {
        stats.warnings.push(
            "DNS Resolver: the baseline has no Unbound model; settings not converted".to_string(),
        );
        return stats;
    };
    stats.converted = true;

    // --- general -----------------------------------------------------------
    set_path(
        model,
        &["general", "enabled"],
        bool01(pf_flag_is_set(src, "enable")),
    );
    let port = text(src, "port");
    set_path(
        model,
        &["general", "port"],
        if port.is_empty() { "53" } else { &port },
    );
    for (pf, opn) in GENERAL_FLAGS {
        set_path(model, &["general", opn], bool01(pf_flag_is_set(src, pf)));
    }
    for (pf, opn) in [
        ("active_interface", "active_interface"),
        ("outgoing_interface", "outgoing_interface"),
    ] {
        let value = interface_list(&text(src, pf), &known_ifaces, pf, &mut stats.warnings);
        set_path(model, &["general", opn], &value);
    }
    let zone = text(src, "system_domain_local_zone_type");
    if !zone.is_empty() {
        set_path(model, &["general", "local_zone_type"], &zone);
    }
    set_path(
        model,
        &["forwarding", "enabled"],
        bool01(pf_flag_is_set(src, "forwarding")),
    );

    // --- advanced ----------------------------------------------------------
    for (pf, opn) in ADVANCED_FLAGS {
        set_path(model, &["advanced", opn], bool01(pf_flag_is_set(src, pf)));
    }
    for (pf, opn) in ADVANCED_VALUES {
        let value = text(src, pf);
        if !value.is_empty() {
            set_path(model, &["advanced", opn], &value);
        }
    }
    if let Ok(queries) = text(src, "num_queries_per_thread").parse::<u64>() {
        set_path(
            model,
            &["advanced", "outgoingrange"],
            &(queries * 2).to_string(),
        );
    }
    if let Ok(size) = text(src, "msgcachesize").parse::<u64>() {
        set_path(model, &["advanced", "msgcachesize"], &format!("{size}m"));
        set_path(
            model,
            &["advanced", "rrsetcachesize"],
            &format!("{}m", size * 2),
        );
    }

    // --- host overrides + aliases --------------------------------------------
    let mut hosts = Vec::new();
    let mut aliases = Vec::new();
    for entry in src.get_children("hosts") {
        convert_host(entry, &mut hosts, &mut aliases, &mut stats);
    }
    stats.hosts = hosts.len();
    stats.aliases = aliases.len();
    replace_items(model, "hosts", "host", hosts);
    replace_items(model, "aliases", "alias", aliases);

    // --- domain overrides -> query forwarding -------------------------------
    let forwards: Vec<XmlNode> = src
        .get_children("domainoverrides")
        .into_iter()
        .filter_map(|o| convert_domain_override(o, &mut stats.warnings))
        .collect();
    stats.forwards = forwards.len();
    replace_items(model, "dots", "dot", forwards);

    // --- access lists --------------------------------------------------------
    let acls: Vec<XmlNode> = src
        .get_children("acls")
        .into_iter()
        .flat_map(|a| convert_acl(a, &mut stats.warnings))
        .collect();
    stats.acls = acls.len();
    if !acls.is_empty() {
        replace_items(model, "acls", "acl", acls);
    }

    // --- not convertible ----------------------------------------------------
    let custom =
        decode_base64(&text(src, "custom_options")).unwrap_or_else(|| text(src, "custom_options"));
    // pfBlockerNG's DNSBL adds an include of its own zone files; it has no
    // meaning on OPNsense (DNSBL is converted separately).
    let custom: String = custom
        .lines()
        .filter(|l| !(l.contains("include:") && l.contains("pfb_")))
        .collect::<Vec<_>>()
        .join("\n");
    if !custom.trim().is_empty() {
        stats.warnings.push(
            "DNS Resolver: custom options not converted; put them in a .conf file under /usr/local/etc/unbound.opnsense.d/".to_string(),
        );
    }
    if pf_flag_is_set(src, "python") {
        let script = text(src, "python_script");
        stats.warnings.push(format!(
            "DNS Resolver: Python module{} not converted{}",
            if script.is_empty() {
                String::new()
            } else {
                format!(" '{script}'")
            },
            if script.starts_with("pfb_") {
                " (pfBlockerNG DNSBL; use Unbound DNS blocklists)"
            } else {
                ""
            }
        ));
    }
    if pf_flag_is_set(src, "enablessl") {
        stats
            .warnings
            .push("DNS Resolver: DNS over TLS service for clients not converted".to_string());
    }
    stats
}

/// pfSense interface list ("all", "", or "lan,opt1,lo0") as OPNsense expects
/// it: empty means all; names that are not interfaces (VIPs) are dropped.
fn interface_list(
    value: &str,
    known: &BTreeSet<String>,
    field: &str,
    warnings: &mut Vec<String>,
) -> String {
    let mut kept = Vec::new();
    for token in value.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        if token.eq_ignore_ascii_case("all") {
            return String::new();
        }
        let lower = token.to_ascii_lowercase();
        if known.contains(&lower) || lower == "lo0" {
            kept.push(lower);
        } else {
            warnings.push(format!(
                "DNS Resolver: {field} '{token}' is not an interface on the target; dropped"
            ));
        }
    }
    kept.join(",")
}

fn convert_host(
    entry: &XmlNode,
    hosts: &mut Vec<XmlNode>,
    aliases: &mut Vec<XmlNode>,
    stats: &mut UnboundStats,
) {
    let hostname = text(entry, "host");
    let domain = text(entry, "domain");
    let descr: String = text(entry, "descr").chars().take(255).collect();
    let ips: Vec<String> = text(entry, "ip")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if ips.is_empty() {
        stats.warnings.push(format!(
            "DNS Resolver: host override '{hostname}.{domain}' has no address; skipped"
        ));
        return;
    }
    // OPNsense's HostnameField rejects underscores; M1_0_1 disables such records.
    let invalid = hostname.contains('_');
    if invalid {
        stats.warnings.push(format!(
            "DNS Resolver: host override '{hostname}.{domain}' has an underscore, which OPNsense does not accept; converted disabled"
        ));
    }
    for ip in &ips {
        let uuid = stable_uuid(&format!("unbound-host|{hostname}|{domain}|{ip}"));
        let mut host = XmlNode::new("host");
        host.attributes.insert("uuid".to_string(), uuid.clone());
        push(&mut host, "enabled", bool01(!invalid));
        push(&mut host, "hostname", &hostname);
        push(&mut host, "domain", &domain);
        push(&mut host, "rr", if ip.contains(':') { "AAAA" } else { "A" });
        push(&mut host, "mxprio", "");
        push(&mut host, "mx", "");
        push(&mut host, "ttl", "");
        push(&mut host, "server", ip);
        push(&mut host, "txtdata", "");
        push(&mut host, "addptr", "1");
        push(&mut host, "description", &descr);
        hosts.push(host);

        for item in entry
            .get_child("aliases")
            .map(|a| a.get_children("item"))
            .unwrap_or_default()
        {
            let alias_host = text(item, "host");
            let alias_domain = text(item, "domain");
            if alias_host.is_empty() && alias_domain.is_empty() {
                continue;
            }
            let mut alias = XmlNode::new("alias");
            alias.attributes.insert(
                "uuid".to_string(),
                stable_uuid(&format!("unbound-alias|{uuid}|{alias_host}|{alias_domain}")),
            );
            push(&mut alias, "enabled", "1");
            push(&mut alias, "host", &uuid);
            push(&mut alias, "hostname", &alias_host);
            push(&mut alias, "domain", &alias_domain);
            let alias_descr: String = text(item, "description").chars().take(255).collect();
            push(&mut alias, "description", &alias_descr);
            aliases.push(alias);
        }
    }
}

fn convert_domain_override(entry: &XmlNode, warnings: &mut Vec<String>) -> Option<XmlNode> {
    let domain = text(entry, "domain");
    let target = text(entry, "ip");
    if domain.is_empty() || target.is_empty() {
        warnings.push(format!(
            "DNS Resolver: domain override '{domain}' has no domain or server; skipped"
        ));
        return None;
    }
    let (server, port) = match target.split_once('@') {
        Some((s, p)) => (s.to_string(), p.to_string()),
        None => (target.clone(), String::new()),
    };
    let tls = pf_flag_is_set(entry, "forward_tls_upstream");
    let mut dot = XmlNode::new("dot");
    dot.attributes.insert(
        "uuid".to_string(),
        stable_uuid(&format!("unbound-forward|{domain}|{target}")),
    );
    push(&mut dot, "enabled", "1");
    push(&mut dot, "type", if tls { "dot" } else { "forward" });
    push(&mut dot, "domain", &domain);
    push(&mut dot, "server", &server);
    push(&mut dot, "port", &port);
    let verify = if tls {
        text(entry, "tls_hostname")
    } else {
        String::new()
    };
    push(&mut dot, "verify", &verify);
    push(&mut dot, "forward_tcp_upstream", "0");
    push(&mut dot, "forward_first", "0");
    let descr: String = text(entry, "descr").chars().take(255).collect();
    push(&mut dot, "description", &descr);
    Some(dot)
}

fn convert_acl(entry: &XmlNode, warnings: &mut Vec<String>) -> Vec<XmlNode> {
    let name = {
        let n = text(entry, "aclname");
        if n.is_empty() {
            "Unnamed ACL".to_string()
        } else {
            n
        }
    };
    let pf_action = text(entry, "aclaction");
    let Some((_, action)) = ACL_ACTIONS.iter().find(|(pf, _)| *pf == pf_action) else {
        warnings.push(format!(
            "DNS Resolver: access list '{name}' has unknown action '{pf_action}'; skipped"
        ));
        return Vec::new();
    };
    let description = text(entry, "description");
    // Like M1_0_6: rows with a description become their own ACL.
    let mut out = Vec::new();
    let mut shared = Vec::new();
    for row in entry.get_children("row") {
        let network = text(row, "acl_network");
        let mask = text(row, "mask");
        if network.is_empty() || mask.is_empty() {
            continue;
        }
        let cidr = format!("{network}/{mask}");
        let row_descr = text(row, "description");
        if row_descr.is_empty() {
            shared.push(cidr);
        } else {
            out.push(acl_node(
                &format!("{name}-{row_descr}"),
                action,
                &cidr,
                &description,
            ));
        }
    }
    if !shared.is_empty() {
        out.push(acl_node(&name, action, &shared.join(","), &description));
    }
    out
}

fn acl_node(name: &str, action: &str, networks: &str, description: &str) -> XmlNode {
    let mut acl = XmlNode::new("acl");
    acl.attributes.insert(
        "uuid".to_string(),
        stable_uuid(&format!("unbound-acl|{name}|{networks}")),
    );
    push(&mut acl, "enabled", "1");
    push(&mut acl, "name", name);
    push(&mut acl, "action", action);
    push(&mut acl, "networks", networks);
    push(&mut acl, "description", description);
    acl
}

/// Replace all `item_tag` entries in `model/container` with `items`.
fn replace_items(model: &mut XmlNode, container: &str, item_tag: &str, items: Vec<XmlNode>) {
    let node = ensure_path(model, &[container]);
    node.children.retain(|c| c.tag != item_tag);
    node.text = None;
    node.children.extend(items);
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::from_pfsense;

    const BASELINE: &[u8] = br#"<opnsense><interfaces><lan/><opt1/></interfaces><OPNsense><unboundplus version="1.0.15"><general><enabled>1</enabled><port>53</port><dnssec>0</dnssec></general><advanced><hideidentity>0</hideidentity></advanced><acls><default_action>allow</default_action></acls><forwarding><enabled>0</enabled></forwarding></unboundplus></OPNsense></opnsense>"#;

    #[test]
    fn converts_pfsense_resolver() {
        let baseline = parse(BASELINE).expect("parse");
        let mut out = baseline.clone();
        let source = parse(
            br#"<pfsense><unbound>
                <enable></enable><dnssec></dnssec><active_interface>all</active_interface><outgoing_interface>lan,_vip5e8a,opt1</outgoing_interface>
                <custom_options></custom_options><hideidentity></hideidentity><hideversion></hideversion><dnssecstripped></dnssecstripped>
                <msgcachesize>4</msgcachesize><num_queries_per_thread>512</num_queries_per_thread>
                <hosts><host>app-server</host><domain>example.net</domain><ip>10.0.21.200</ip><descr>APP</descr>
                  <aliases><item><host>elk</host><domain>example.net</domain><description></description></item><item><host>elastic</host><domain>example.net</domain><description></description></item></aliases></hosts>
                <hosts><host>dual</host><domain>example.net</domain><ip>10.0.0.1,2001:db8::1</ip><descr></descr></hosts>
                <hosts><host>bad_name</host><domain>example.net</domain><ip>10.0.0.2</ip></hosts>
                <domainoverrides><domain>example.net</domain><ip>192.168.1.1</ip><descr></descr><tls_hostname></tls_hostname></domainoverrides>
                <domainoverrides><domain>corp.example</domain><ip>10.1.1.1@5353</ip><descr>corp</descr></domainoverrides>
                <acls><aclname>lan</aclname><aclaction>allow</aclaction><row><acl_network>10.0.0.0</acl_network><mask>8</mask></row><row><acl_network>192.168.0.0</acl_network><mask>16</mask><description>home</description></row></acls>
                <port></port><system_domain_local_zone_type>transparent</system_domain_local_zone_type>
                <python></python><python_script>pfb_unbound</python_script>
            </unbound></pfsense>"#,
        )
        .expect("parse");

        let stats = from_pfsense(&mut out, &source, &baseline);
        assert!(stats.converted);
        assert_eq!(stats.hosts, 4);
        assert_eq!(stats.aliases, 2);
        assert_eq!(stats.forwards, 2);
        assert_eq!(stats.acls, 2);

        let m = out
            .get_child("OPNsense")
            .unwrap()
            .get_child("unboundplus")
            .unwrap();
        assert_eq!(
            m.attributes.get("version").map(String::as_str),
            Some("1.0.15")
        );
        let t = |p: &[&str]| m.get_text(p).unwrap_or("").to_string();
        assert_eq!(t(&["general", "enabled"]), "1");
        assert_eq!(t(&["general", "dnssec"]), "1", "empty pfSense element = on");
        assert_eq!(t(&["general", "port"]), "53");
        assert_eq!(t(&["general", "active_interface"]), "");
        assert_eq!(t(&["general", "outgoing_interface"]), "lan,opt1");
        assert_eq!(t(&["advanced", "hideidentity"]), "1");
        assert_eq!(t(&["advanced", "prefetch"]), "0");
        assert_eq!(t(&["advanced", "msgcachesize"]), "4m");
        assert_eq!(t(&["advanced", "rrsetcachesize"]), "8m");
        assert_eq!(t(&["advanced", "outgoingrange"]), "1024");

        let hosts = m.get_child("hosts").unwrap().get_children("host");
        assert_eq!(hosts[0].get_text(&["hostname"]), Some("app-server"));
        assert_eq!(hosts[0].get_text(&["server"]), Some("10.0.21.200"));
        assert_eq!(hosts[0].get_text(&["rr"]), Some("A"));
        assert_eq!(hosts[2].get_text(&["rr"]), Some("AAAA"));
        assert_eq!(hosts[3].get_text(&["enabled"]), Some("0"));
        let aliases = m.get_child("aliases").unwrap().get_children("alias");
        let host_uuid = hosts[0].attributes.get("uuid").unwrap();
        assert!(aliases
            .iter()
            .all(|a| a.get_text(&["host"]) == Some(host_uuid.as_str())));

        let dots = m.get_child("dots").unwrap().get_children("dot");
        assert_eq!(dots[0].get_text(&["domain"]), Some("example.net"));
        assert_eq!(dots[0].get_text(&["type"]), Some("forward"));
        assert_eq!(dots[1].get_text(&["server"]), Some("10.1.1.1"));
        assert_eq!(dots[1].get_text(&["port"]), Some("5353"));

        let acls = m.get_child("acls").unwrap();
        assert_eq!(acls.get_text(&["default_action"]), Some("allow"));
        let acl = acls.get_children("acl");
        assert_eq!(acl[0].get_text(&["name"]), Some("lan-home"));
        assert_eq!(acl[1].get_text(&["networks"]), Some("10.0.0.0/8"));

        assert!(stats.warnings.iter().any(|w| w.contains("_vip5e8a")));
        assert!(stats.warnings.iter().any(|w| w.contains("pfBlockerNG")));
        assert!(stats.warnings.iter().any(|w| w.contains("bad_name")));
    }

    #[test]
    fn pfblocker_include_is_not_a_custom_option() {
        let baseline = parse(BASELINE).expect("parse");
        let custom = |opts: &str| {
            let mut out = baseline.clone();
            let xml = format!(
                "<pfsense><unbound><enable></enable><custom_options>{opts}</custom_options></unbound></pfsense>"
            );
            let source = parse(xml.as_bytes()).expect("parse");
            from_pfsense(&mut out, &source, &baseline)
                .warnings
                .iter()
                .any(|w| w.contains("custom options"))
        };
        assert!(!custom("server:include: /var/unbound/pfb_dnsbl.*conf"));
        assert!(custom(
            "server:include: /var/unbound/pfb_dnsbl.*conf\nserver:\n  do-ip6: no"
        ));
    }

    #[test]
    fn no_source_section_leaves_baseline_alone() {
        let baseline = parse(BASELINE).expect("parse");
        let mut out = baseline.clone();
        let stats = from_pfsense(&mut out, &parse(b"<pfsense/>").unwrap(), &baseline);
        assert!(!stats.converted);
        assert_eq!(out, baseline);
    }
}
