//! Move legacy firewall rules into OPNsense's MVC Filter model.
//!
//! OPNsense 26.7 removed the legacy rule editors (`firewall_rules.php`,
//! `firewall_nat_out.php`). Legacy `<filter><rule>` and `<nat><outbound><rule>`
//! entries are still enforced, but can only be edited after running
//! Firewall -> Migration assistant on the box. This transform performs the same
//! conversion at convert time so the imported ruleset is editable and can be
//! checked by `verify` before import.
//!
//! The field mapping mirrors OPNsense's own exporters used by the assistant
//! (`scripts/filter/list_legacy_rules.php`, `list_legacy_outbound_nat.php`,
//! 26.7.8), adapted to pfSense field names (`statepolicy`, `target_subnet`,
//! `source_hash_key`, `<if>ip` NAT targets). Rule order follows
//! `filter_rules_sort()` and the exporter's sequence numbering (1, 11, 21, ...).
//!
//! A fresh 26.7 install ships "Default allow LAN" rules in the MVC model; they
//! are replaced, so the imported ruleset matches the source exactly.
//!
//! Rules that cannot be expressed faithfully (pfSense `match` rules, NAT64
//! rules, unknown option values) stay in the legacy section, where OPNsense
//! still enforces them, and are reported.

use std::cmp::Ordering;

use xml_diff_core::XmlNode;

use super::rule_flags::pf_flag_is_set;
use super::version::{model_version, version_at_least};

/// Filter model version that ships with OPNsense 26.7 (legacy editors removed).
const MIN_FILTER_VERSION: [u32; 3] = [1, 0, 5];

/// Outcome of the conversion, for reporting.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FilterMvcStats {
    pub rules_moved: usize,
    pub outbound_moved: usize,
    /// MVC rules from the baseline (e.g. default allow LAN) that were replaced.
    pub baseline_rules_replaced: usize,
    /// Legacy rules left in place, with the reason.
    pub kept_legacy: Vec<String>,
    /// Source fields that have no OPNsense equivalent and were dropped.
    pub dropped_fields: Vec<String>,
    /// Port forwards whose link to a (now converted) filter rule was cleared.
    pub nat_links_cleared: usize,
    /// "To this firewall, no gateway" rules added in front of policy-routing rules.
    pub self_bypass_added: usize,
}

/// Convert legacy filter and outbound NAT rules into the MVC Filter model when
/// the baseline is OPNsense 26.7 or newer. Returns default stats otherwise.
pub fn move_legacy_rules_to_mvc(out: &mut XmlNode, baseline: &XmlNode) -> FilterMvcStats {
    let mut stats = FilterMvcStats::default();
    let applies = model_version(baseline, &["OPNsense", "Firewall", "Filter"])
        .map(|v| version_at_least(v, &MIN_FILTER_VERSION))
        .unwrap_or(false);
    if !applies {
        return stats;
    }
    convert_filter_rules(out, &mut stats);
    convert_outbound_rules(out, &mut stats);
    stats
}

// ---------------------------------------------------------------------------
// Filter rules
// ---------------------------------------------------------------------------

const ACTIONS: &[&str] = &["pass", "block", "reject"];
const STATETYPES: &[&str] = &["keep", "sloppy", "modulate", "synproxy", "none"];
const DIRECTIONS: &[&str] = &["in", "out", "any"];
const IPPROTOCOLS: &[&str] = &["inet", "inet6", "inet46"];
const STATE_POLICIES: &[&str] = &["if-bound", "floating"];

/// Optional legacy fields copied verbatim when non-empty (MVC name, legacy name).
const PASSTHROUGH: &[(&str, &str)] = &[
    ("gateway", "gateway"),
    ("replyto", "reply-to"),
    ("statetimeout", "statetimeout"),
    ("max-src-nodes", "max-src-nodes"),
    ("max-src-states", "max-src-states"),
    ("max-src-conn", "max-src-conn"),
    ("max", "max"),
    ("max-src-conn-rate", "max-src-conn-rate"),
    ("max-src-conn-rates", "max-src-conn-rates"),
    ("adaptivestart", "adaptivestart"),
    ("adaptiveend", "adaptiveend"),
    ("prio", "prio"),
    ("set-prio", "set-prio"),
    ("set-prio-low", "set-prio-low"),
    ("tag", "tag"),
    ("tagged", "tagged"),
    ("tcpflags1", "tcpflags1"),
    ("tcpflags2", "tcpflags2"),
    ("sched", "sched"),
];

/// Legacy fields that are handled explicitly or are bookkeeping only.
const HANDLED: &[&str] = &[
    "tracker",
    "id",
    "created",
    "updated",
    "associated-rule-id",
    "type",
    "interface",
    "interfacenot",
    "ipprotocol",
    "protocol",
    "source",
    "destination",
    "descr",
    "disabled",
    "log",
    "quick",
    "floating",
    "direction",
    "statetype",
    "statepolicy",
    "state-policy",
    "disablereplyto",
    "allowopts",
    "nosync",
    "nopfsync",
    "icmptype",
    "icmp6-type",
    "tcpflags_any",
    "category",
    // pfSense writes <enabled>on</enabled> on some generated rules; it has no
    // meaning for the ruleset (disabled state is <disabled>).
    "enabled",
];

/// ICMPv6 type names as used by legacy configs, mapped to the MVC option values
/// (`list_legacy_rules.php`).
const ICMP6_TYPES: &[(&str, &str)] = &[
    ("unreach", "1"),
    ("toobig", "2"),
    ("timex", "3"),
    ("paramprob", "4"),
    ("echoreq", "128"),
    ("echorep", "129"),
    ("listqry", "130"),
    ("listenrep", "131"),
    ("listendone", "132"),
    ("routersol", "133"),
    ("routeradv", "134"),
    ("neighbrsol", "135"),
    ("neighbradv", "136"),
    ("redir", "137"),
    ("routrrenum", "138"),
    ("niqry", "139"),
    ("nirep", "140"),
    ("mtraceresp", "200"),
    ("mtrace", "201"),
];

fn convert_filter_rules(out: &mut XmlNode, stats: &mut FilterMvcStats) {
    let legacy: Vec<XmlNode> = out
        .get_child("filter")
        .map(|f| f.get_children("rule").into_iter().cloned().collect())
        .unwrap_or_default();

    let mut ordered: Vec<(usize, &XmlNode)> = legacy.iter().enumerate().collect();
    ordered.sort_by(legacy_rule_order);

    let mut converted = Vec::new();
    let mut keep = Vec::new();
    let mut sequence = 1u32;
    for (idx, rule) in ordered {
        let label = rule_label("filter rule", idx, rule);
        match map_filter_rule(rule, sequence, &label, stats) {
            Ok(mut node) => {
                if let Some(bypass) = self_bypass_rule(&node) {
                    converted.push(bypass);
                    sequence += 10;
                    set_child_text(&mut node, "sequence", &sequence.to_string());
                    stats.self_bypass_added += 1;
                }
                converted.push(node);
                sequence += 10;
            }
            Err(reason) => {
                stats.kept_legacy.push(format!("{label}: {reason}"));
                keep.push(idx);
            }
        }
    }

    // Keep only the rules that could not be converted, in original order.
    if let Some(filter) = out.children.iter_mut().find(|c| c.tag == "filter") {
        let mut pos = 0usize;
        filter.children.retain(|c| {
            if c.tag != "rule" {
                return true;
            }
            let keep_it = keep.contains(&pos);
            pos += 1;
            keep_it
        });
    }

    stats.nat_links_cleared = clear_moved_nat_links(out);

    let rules = ensure_path(out, &["OPNsense", "Firewall", "Filter", "rules"]);
    stats.baseline_rules_replaced = rules.get_children("rule").len();
    rules.children.retain(|c| c.tag != "rule");
    stats.rules_moved = converted.len();
    rules.children.extend(converted);
}

/// For a policy-routing pass rule to "any", the same rule with destination
/// "This Firewall" and no gateway, to be placed directly in front of it.
///
/// On OPNsense a `route-to` rule also catches traffic addressed to the
/// firewall's own addresses (for example a monitoring server polling the
/// firewall's WAN address from an internal network) and sends it to the
/// gateway, where it is lost. The same pfSense rules delivered that traffic
/// locally. OPNsense's documented fix is a rule to "This Firewall" without a
/// gateway above the policy-routing rules; it only passes what the gateway
/// rule below it would pass anyway.
fn self_bypass_rule(rule: &XmlNode) -> Option<XmlNode> {
    let field = |tag: &str| text(rule, tag);
    let routes = !field("gateway").is_empty()
        && field("action") == "pass"
        && field("direction") == "in"
        && field("destination_net") == "any"
        && field("destination_not") != "1";
    if !routes {
        return None;
    }
    let mut bypass = rule.clone();
    let uuid = rule.attributes.get("uuid").cloned().unwrap_or_default();
    bypass.attributes.insert(
        "uuid".to_string(),
        stable_uuid(&format!("self-bypass|{uuid}")),
    );
    bypass.children.retain(|c| c.tag != "gateway");
    set_child_text(&mut bypass, "destination_net", "(self)");
    let descr = field("description");
    set_child_text(
        &mut bypass,
        "description",
        &format!(
            "pfopn-convert: no policy routing to this firewall{}",
            if descr.is_empty() {
                String::new()
            } else {
                format!(" ({descr})")
            }
        )
        .chars()
        .take(255)
        .collect::<String>(),
    );
    Some(bypass)
}

fn set_child_text(node: &mut XmlNode, tag: &str, value: &str) {
    match node.children.iter_mut().find(|c| c.tag == tag) {
        Some(child) => {
            child.children.clear();
            child.text = Some(value.to_string());
        }
        None => push(node, tag, value),
    }
}

/// Drop port-forward `associated-rule-id` links that no longer point at a
/// legacy filter rule. OPNsense 26.7 does the same on load
/// (`DNatAssociatedRuleField` keeps only "pass"); the linked rule itself has
/// been converted and stays in place as an ordinary rule.
fn clear_moved_nat_links(out: &mut XmlNode) -> usize {
    let remaining: Vec<String> = out
        .get_child("filter")
        .map(|f| {
            f.get_children("rule")
                .iter()
                .filter_map(|r| r.get_text(&["associated-rule-id"]))
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let Some(nat) = out.children.iter_mut().find(|c| c.tag == "nat") else {
        return 0;
    };
    let mut cleared = 0;
    for rule in nat.children.iter_mut().filter(|c| c.tag == "rule") {
        let before = rule.children.len();
        rule.children.retain(|c| {
            if c.tag != "associated-rule-id" {
                return true;
            }
            let id = c.text.as_deref().map(str::trim).unwrap_or("");
            id.is_empty() || id == "pass" || remaining.iter().any(|r| r == id)
        });
        cleared += before - rule.children.len();
    }
    cleared
}

/// `filter_rules_sort()`: floating first (in order), then per interface with
/// wan, lan, then natural order; original order within an interface.
fn legacy_rule_order(a: &(usize, &XmlNode), b: &(usize, &XmlNode)) -> Ordering {
    let (ai, ar) = a;
    let (bi, br) = b;
    let af = ar.get_child("floating").is_some();
    let bf = br.get_child("floating").is_some();
    let aif = text(ar, "interface");
    let bif = text(br, "interface");
    match (af, bf) {
        (true, true) => ai.cmp(bi),
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ if aif == bif => ai.cmp(bi),
        _ if aif == "wan" => Ordering::Less,
        _ if bif == "wan" => Ordering::Greater,
        _ if aif == "lan" => Ordering::Less,
        _ if bif == "lan" => Ordering::Greater,
        _ => natural_cmp(&aif, &bif),
    }
}

fn map_filter_rule(
    rule: &XmlNode,
    sequence: u32,
    label: &str,
    stats: &mut FilterMvcStats,
) -> Result<XmlNode, String> {
    let action = non_empty(text(rule, "type")).unwrap_or_else(|| "pass".to_string());
    if action.eq_ignore_ascii_case("match") {
        return Err("pfSense 'match' rule has no OPNsense equivalent".to_string());
    }
    if rule.get_child("nat").is_some() {
        return Err("pfSense NAT64 rule has no OPNsense equivalent".to_string());
    }
    if !ACTIONS.contains(&action.as_str()) {
        return Err(format!("unknown action '{action}'"));
    }
    let statetype = non_empty(text(rule, "statetype"))
        .map(|s| s.split_whitespace().next().unwrap_or("keep").to_string())
        .unwrap_or_else(|| "keep".to_string());
    if !STATETYPES.contains(&statetype.as_str()) {
        return Err(format!("unknown state type '{statetype}'"));
    }
    let direction = non_empty(text(rule, "direction")).unwrap_or_else(|| "in".to_string());
    if !DIRECTIONS.contains(&direction.as_str()) {
        return Err(format!("unknown direction '{direction}'"));
    }
    let ipprotocol = non_empty(text(rule, "ipprotocol")).unwrap_or_else(|| "inet".to_string());
    if !IPPROTOCOLS.contains(&ipprotocol.as_str()) {
        return Err(format!("unknown IP protocol '{ipprotocol}'"));
    }
    let state_policy = non_empty(text(rule, "state-policy"))
        .or_else(|| non_empty(text(rule, "statepolicy")))
        .unwrap_or_default();
    if !state_policy.is_empty() && !STATE_POLICIES.contains(&state_policy.as_str()) {
        stats.dropped_fields.push(format!(
            "{label}: state policy '{state_policy}' not supported, using default"
        ));
    }

    let floating = rule.get_child("floating").is_some();
    let quick = if rule.get_child("quick").is_some() {
        pf_flag_is_set(rule, "quick")
    } else {
        !floating
    };

    let mut node = XmlNode::new("rule");
    let uuid = rule
        .attributes
        .get("uuid")
        .cloned()
        .unwrap_or_else(|| stable_uuid(&format!("filter|{label}|{}", text(rule, "tracker"))));
    node.attributes.insert("uuid".to_string(), uuid);

    push(
        &mut node,
        "enabled",
        bool01(!pf_flag_is_set(rule, "disabled")),
    );
    push(&mut node, "statetype", &statetype);
    push(
        &mut node,
        "state-policy",
        if STATE_POLICIES.contains(&state_policy.as_str()) {
            &state_policy
        } else {
            ""
        },
    );
    push(&mut node, "sequence", &sequence.to_string());
    push(&mut node, "action", &action);
    push(&mut node, "quick", bool01(quick));
    push(
        &mut node,
        "interfacenot",
        bool01(pf_flag_is_set(rule, "interfacenot")),
    );
    push(&mut node, "interface", &text(rule, "interface"));
    push(&mut node, "direction", &direction);
    push(&mut node, "ipprotocol", &ipprotocol);
    let has_ports = ["source", "destination"]
        .iter()
        .any(|b| !address_fields(rule.get_child(b)).2.is_empty());
    let protocol = model_protocol(&text(rule, "protocol"), &ipprotocol, has_ports);
    push(&mut node, "protocol", &protocol);

    // pfSense stores "all ICMP types" as `any`; OPNsense passes the field to pf
    // verbatim (`icmp-type {any}`), which is a syntax error that stops the whole
    // ruleset from loading. OPNsense's "any" is an empty field.
    let icmp = icmp_types_or_any(&text(rule, "icmptype"));
    let icmp6_legacy = icmp_types_or_any(&text(rule, "icmp6-type"));
    if ipprotocol == "inet6" && !icmp.is_empty() {
        // pfSense keeps ICMPv6 types in <icmptype>; the MVC model has a
        // separate numeric icmp6type field.
        push(&mut node, "icmp6type", &icmp6_numbers(&icmp, label, stats));
    } else {
        push(&mut node, "icmptype", &icmp);
        if !icmp6_legacy.is_empty() {
            push(
                &mut node,
                "icmp6type",
                &icmp6_numbers(&icmp6_legacy, label, stats),
            );
        }
    }

    for block in ["source", "destination"] {
        let (net, not, port) = address_fields(rule.get_child(block));
        push(&mut node, &format!("{block}_net"), &net);
        push(&mut node, &format!("{block}_not"), bool01(not));
        if !port.is_empty() {
            push(&mut node, &format!("{block}_port"), &port);
        }
    }

    push(
        &mut node,
        "disablereplyto",
        bool01(pf_flag_is_set(rule, "disablereplyto")),
    );
    push(&mut node, "log", bool01(pf_flag_is_set(rule, "log")));
    push(
        &mut node,
        "allowopts",
        bool01(pf_flag_is_set(rule, "allowopts")),
    );
    push(&mut node, "nosync", bool01(pf_flag_is_set(rule, "nosync")));
    push(
        &mut node,
        "nopfsync",
        bool01(pf_flag_is_set(rule, "nopfsync")),
    );
    for (mvc, legacy) in PASSTHROUGH {
        if let Some(value) = non_empty(text(rule, legacy)) {
            push(&mut node, mvc, &value);
        }
    }
    push(
        &mut node,
        "tcpflags_any",
        bool01(pf_flag_is_set(rule, "tcpflags_any")),
    );
    if non_empty(text(rule, "category")).is_some() {
        stats.dropped_fields.push(format!(
            "{label}: category not transferred (OPNsense categories are referenced by id)"
        ));
    }
    push(&mut node, "description", &text(rule, "descr"));

    report_unmapped(rule, label, stats);
    Ok(node)
}

/// `source`/`destination` -> (net, not, port), as in `list_legacy_rules.php`.
fn address_fields(block: Option<&XmlNode>) -> (String, bool, String) {
    let Some(block) = block else {
        return ("any".to_string(), false, String::new());
    };
    let not = pf_flag_is_set(block, "not");
    let net = if block.get_child("any").is_some() {
        "any".to_string()
    } else if let Some(network) = non_empty(text(block, "network")) {
        network
    } else {
        non_empty(text(block, "address")).unwrap_or_else(|| "any".to_string())
    };
    let port = text(block, "port")
        .replace("-any", "-65535")
        .replace("any-", "1-");
    (net, not, port)
}

/// Protocol as the OPNsense Filter model accepts it (`Filter::performValidation`):
/// - ports are only valid for TCP, UDP or TCP/UDP. pfSense allows ports with
///   protocol "any" (its auto-created ISAKMP outbound NAT rules use port 500),
///   and pf only applies ports to TCP/UDP anyway, so "any" with ports becomes
///   "TCP/UDP". Left as "any", every save of the rule model fails.
/// - ICMP on an IPv6 rule is `IPV6-ICMP` (required for ICMPv6 types).
fn model_protocol(pf_protocol: &str, ipprotocol: &str, has_ports: bool) -> String {
    let protocol = if pf_protocol.is_empty() {
        "any".to_string()
    } else {
        pf_protocol.to_ascii_uppercase()
    };
    match protocol.as_str() {
        "ANY" | "any" if has_ports => "TCP/UDP".to_string(),
        "ANY" => "any".to_string(),
        "ICMP" if ipprotocol == "inet6" => "IPV6-ICMP".to_string(),
        _ => protocol,
    }
}

/// Empty when the ICMP type list includes pfSense's `any` (all types).
fn icmp_types_or_any(types: &str) -> String {
    if types
        .split(',')
        .any(|t| t.trim().eq_ignore_ascii_case("any"))
    {
        String::new()
    } else {
        types.to_string()
    }
}

fn icmp6_numbers(names: &str, label: &str, stats: &mut FilterMvcStats) -> String {
    let mut out = Vec::new();
    for name in names.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        match ICMP6_TYPES.iter().find(|(n, _)| *n == name) {
            Some((_, num)) => out.push(*num),
            None => stats.dropped_fields.push(format!(
                "{label}: ICMPv6 type '{name}' has no OPNsense equivalent"
            )),
        }
    }
    out.join(",")
}

fn report_unmapped(rule: &XmlNode, label: &str, stats: &mut FilterMvcStats) {
    for child in &rule.children {
        let tag = child.tag.as_str();
        if HANDLED.contains(&tag) || PASSTHROUGH.iter().any(|(_, legacy)| *legacy == tag) {
            continue;
        }
        let has_value = !child.children.is_empty()
            || child
                .text
                .as_deref()
                .map(|t| !t.trim().is_empty())
                .unwrap_or(false);
        if has_value {
            stats.dropped_fields.push(format!(
                "{label}: field '{tag}' has no OPNsense equivalent, dropped"
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Outbound NAT
// ---------------------------------------------------------------------------

const POOLOPTS: &[&str] = &[
    "round-robin",
    "round-robin sticky-address",
    "random",
    "random sticky-address",
    "source-hash",
    "bitmask",
];

fn convert_outbound_rules(out: &mut XmlNode, stats: &mut FilterMvcStats) {
    let legacy: Vec<XmlNode> = out
        .get_child("nat")
        .and_then(|n| n.get_child("outbound"))
        .map(|o| o.get_children("rule").into_iter().cloned().collect())
        .unwrap_or_default();
    if legacy.is_empty() {
        return;
    }

    let mut converted = Vec::new();
    let mut sequence = 1u32;
    for (idx, rule) in legacy.iter().enumerate() {
        let label = rule_label("outbound NAT rule", idx, rule);
        converted.push(map_outbound_rule(rule, sequence, &label, stats));
        sequence += 10;
    }

    if let Some(outbound) = out
        .children
        .iter_mut()
        .find(|c| c.tag == "nat")
        .and_then(|n| n.children.iter_mut().find(|c| c.tag == "outbound"))
    {
        // <mode> stays: OPNsense 26.7 still reads nat/outbound/mode.
        outbound.children.retain(|c| c.tag != "rule");
    }

    let rules = ensure_path(out, &["OPNsense", "Firewall", "Filter", "snatrules"]);
    rules.children.retain(|c| c.tag != "rule");
    stats.outbound_moved = converted.len();
    rules.children.extend(converted);
}

fn map_outbound_rule(
    rule: &XmlNode,
    sequence: u32,
    label: &str,
    stats: &mut FilterMvcStats,
) -> XmlNode {
    let interface = non_empty(text(rule, "interface")).unwrap_or_else(|| "lan".to_string());
    let source = rule.get_child("source");
    let destination = rule.get_child("destination");

    let mut node = XmlNode::new("rule");
    let uuid = rule
        .attributes
        .get("uuid")
        .cloned()
        .unwrap_or_else(|| stable_uuid(&format!("snat|{label}")));
    node.attributes.insert("uuid".to_string(), uuid);

    push(
        &mut node,
        "enabled",
        bool01(!pf_flag_is_set(rule, "disabled")),
    );
    push(&mut node, "nonat", bool01(pf_flag_is_set(rule, "nonat")));
    push(&mut node, "nosync", bool01(pf_flag_is_set(rule, "nosync")));
    push(&mut node, "sequence", &sequence.to_string());
    push(&mut node, "interface", &interface);
    let source_net = outbound_network(source);
    let destination_net = outbound_network(destination);
    let target = outbound_target(rule, &interface);
    let ipprotocol =
        outbound_ipprotocol(rule, [&source_net, &destination_net, &target], label, stats);
    push(&mut node, "ipprotocol", ipprotocol);
    let has_ports = ["sourceport", "dstport", "natport"]
        .iter()
        .any(|p| !text(rule, p).is_empty());
    push(
        &mut node,
        "protocol",
        &model_protocol(&text(rule, "protocol"), ipprotocol, has_ports),
    );
    push(&mut node, "source_net", &source_net);
    push(
        &mut node,
        "source_not",
        bool01(source.map(|s| pf_flag_is_set(s, "not")).unwrap_or(false)),
    );
    push(
        &mut node,
        "source_port",
        &normalize_port(&text(rule, "sourceport")),
    );
    push(&mut node, "destination_net", &destination_net);
    push(
        &mut node,
        "destination_not",
        bool01(
            destination
                .map(|d| pf_flag_is_set(d, "not"))
                .unwrap_or(false),
        ),
    );
    push(
        &mut node,
        "destination_port",
        &normalize_port(&text(rule, "dstport")),
    );
    push(&mut node, "target", &target);
    push(
        &mut node,
        "target_port",
        &normalize_port(&text(rule, "natport")),
    );

    let poolopts = text(rule, "poolopts");
    if !poolopts.is_empty() && !POOLOPTS.contains(&poolopts.as_str()) {
        stats.dropped_fields.push(format!(
            "{label}: pool option '{poolopts}' not supported, using default"
        ));
        push(&mut node, "poolopts", "");
    } else {
        push(&mut node, "poolopts", &poolopts);
    }
    let hash_key = non_empty(text(rule, "poolopts_sourcehashkey"))
        .or_else(|| non_empty(text(rule, "source_hash_key")))
        .unwrap_or_default();
    push(&mut node, "poolopts_sourcehashkey", &hash_key);
    push(
        &mut node,
        "staticnatport",
        bool01(pf_flag_is_set(rule, "staticnatport")),
    );
    push(&mut node, "log", bool01(pf_flag_is_set(rule, "log")));
    push(&mut node, "tag", &text(rule, "tag"));
    push(&mut node, "tagged", &text(rule, "tagged"));
    push(&mut node, "description", &text(rule, "descr"));
    node
}

/// Address family for an outbound NAT rule. OPNsense's `snatrules` only accept
/// `inet` or `inet6`. pfSense outbound rules usually carry no `<ipprotocol>`
/// (pf infers the family from the addresses), and its auto-created rules
/// include an IPv6 localhost (`::1/128`) entry. Writing those as `inet` makes
/// pf reject the whole ruleset ("rule expands to no valid combination"), so
/// when the family is missing (or `inet46`) it is taken from the addresses:
/// any literal IPv6 address/network means `inet6`, otherwise `inet`.
fn outbound_ipprotocol(
    rule: &XmlNode,
    addresses: [&str; 3],
    label: &str,
    stats: &mut FilterMvcStats,
) -> &'static str {
    let explicit = text(rule, "ipprotocol");
    match explicit.as_str() {
        "inet" => return "inet",
        "inet6" => return "inet6",
        _ => {}
    }
    let inferred = if addresses.iter().any(|a| is_ipv6_literal(a)) {
        "inet6"
    } else {
        "inet"
    };
    if !explicit.is_empty() {
        stats.dropped_fields.push(format!(
            "{label}: IP version '{explicit}' not supported for outbound NAT, using {inferred}"
        ));
    }
    inferred
}

/// True for an IPv6 address or network (`::1`, `2001:db8::/32`).
fn is_ipv6_literal(value: &str) -> bool {
    let addr = value.split('/').next().unwrap_or("");
    addr.parse::<std::net::Ipv6Addr>().is_ok()
}

fn outbound_network(block: Option<&XmlNode>) -> String {
    let Some(block) = block else {
        return "any".to_string();
    };
    if block.get_child("any").is_some() {
        return "any".to_string();
    }
    non_empty(text(block, "network"))
        .or_else(|| non_empty(text(block, "address")))
        .unwrap_or_else(|| "any".to_string())
}

/// NAT target, following `legacy_target_to_network()` plus pfSense's layout:
/// pfSense stores the interface address as `<if>ip` and the address/mask as
/// `<target>` + `<target_subnet>`.
fn outbound_target(rule: &XmlNode, interface: &str) -> String {
    let target = text(rule, "target");
    if target.is_empty() || target == format!("{interface}ip") {
        // Empty target is OPNsense's "Interface address".
        return String::new();
    }
    let (address, subnet) = if target == "other-subnet" {
        let ip = text(rule, "targetip");
        if ip.is_empty() {
            return format!("{interface}ip");
        }
        (ip, text(rule, "targetip_subnet"))
    } else {
        let subnet = non_empty(text(rule, "targetip_subnet"))
            .or_else(|| non_empty(text(rule, "target_subnet")))
            .unwrap_or_default();
        (target, subnet)
    };
    let is_ip = address.parse::<std::net::IpAddr>().is_ok();
    if is_ip && !matches!(subnet.as_str(), "" | "0" | "32" | "128") {
        format!("{address}/{subnet}")
    } else {
        address
    }
}

/// Legacy port ranges use a colon, the MVC PortField expects a dash.
fn normalize_port(port: &str) -> String {
    port.replace(':', "-")
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn rule_label(kind: &str, idx: usize, rule: &XmlNode) -> String {
    match non_empty(text(rule, "descr")) {
        Some(d) => format!("{kind} #{} ('{d}')", idx + 1),
        None => format!("{kind} #{}", idx + 1),
    }
}

fn text(node: &XmlNode, tag: &str) -> String {
    node.get_text(&[tag])
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

fn non_empty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn bool01(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}

fn push(parent: &mut XmlNode, tag: &str, value: &str) {
    let mut child = XmlNode::new(tag);
    child.text = Some(value.to_string());
    parent.children.push(child);
}

fn ensure_path<'a>(root: &'a mut XmlNode, path: &[&str]) -> &'a mut XmlNode {
    let mut node = root;
    for tag in path {
        let idx = match node.children.iter().position(|c| c.tag == *tag) {
            Some(idx) => idx,
            None => {
                node.children.push(XmlNode::new(*tag));
                node.children.len() - 1
            }
        };
        node = &mut node.children[idx];
    }
    node
}

/// PHP `strnatcmp`-style comparison: digit runs compare numerically.
fn natural_cmp(a: &str, b: &str) -> Ordering {
    let (mut ai, mut bi) = (a.chars().peekable(), b.chars().peekable());
    loop {
        match (ai.peek().copied(), bi.peek().copied()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) if x.is_ascii_digit() && y.is_ascii_digit() => {
                let mut na = String::new();
                while let Some(c) = ai.peek().copied().filter(char::is_ascii_digit) {
                    na.push(c);
                    ai.next();
                }
                let mut nb = String::new();
                while let Some(c) = bi.peek().copied().filter(char::is_ascii_digit) {
                    nb.push(c);
                    bi.next();
                }
                let ord = na
                    .trim_start_matches('0')
                    .len()
                    .cmp(&nb.trim_start_matches('0').len())
                    .then_with(|| na.trim_start_matches('0').cmp(nb.trim_start_matches('0')));
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            (Some(x), Some(y)) => {
                if x != y {
                    return x.cmp(&y);
                }
                ai.next();
                bi.next();
            }
        }
    }
}

/// Deterministic, RFC 4122-shaped UUID from a seed string.
pub(crate) fn stable_uuid(seed: &str) -> String {
    let fnv = |offset: u64| {
        seed.bytes().fold(offset, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
        })
    };
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&fnv(0xcbf2_9ce4_8422_2325).to_be_bytes());
    bytes[8..].copy_from_slice(&fnv(0x6c62_272e_07bb_0142).to_be_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let h: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use xml_diff_core::parse;

    use super::{move_legacy_rules_to_mvc, natural_cmp};

    const BASELINE_26_7: &[u8] = br#"<opnsense><OPNsense><Firewall><Filter version="1.0.6"><rules><rule uuid="d1"><action>pass</action><interface>lan</interface><description>Default allow LAN to any rule</description></rule></rules><snatrules/></Filter></Firewall></OPNsense></opnsense>"#;

    fn mvc_rules(root: &xml_diff_core::XmlNode, container: &str) -> Vec<xml_diff_core::XmlNode> {
        root.get_child("OPNsense")
            .and_then(|n| n.get_child("Firewall"))
            .and_then(|n| n.get_child("Filter"))
            .and_then(|n| n.get_child(container))
            .map(|n| n.get_children("rule").into_iter().cloned().collect())
            .unwrap_or_default()
    }

    #[test]
    fn converts_rules_in_legacy_sort_order_and_replaces_defaults() {
        let baseline = parse(BASELINE_26_7).expect("parse");
        let mut out = parse(
            br#"<opnsense>
              <filter>
                <rule><tracker>1</tracker><type>block</type><interface>opt2</interface><ipprotocol>inet</ipprotocol><source><any/></source><destination><any/></destination><descr>opt2 block</descr></rule>
                <rule><tracker>2</tracker><interface>lan</interface><ipprotocol>inet</ipprotocol><statetype>keep state</statetype><protocol>tcp/udp</protocol><source><network>lan</network></source><destination><address>web_hosts</address><port>80-443</port></destination><descr>lan web</descr><disabled>1</disabled><log>1</log><gateway>WAN_GW</gateway></rule>
                <rule><tracker>3</tracker><type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol><source><any/><not>1</not></source><destination><network>wanip</network><port>any-1024</port></destination><descr>wan in</descr></rule>
                <rule><tracker>4</tracker><type>pass</type><floating>yes</floating><interface>lan,opt1</interface><direction>any</direction><ipprotocol>inet</ipprotocol><source><any/></source><destination><any/></destination><descr>floating</descr></rule>
                <rule><tracker>5</tracker><type>pass</type><interface>opt10</interface><ipprotocol>inet</ipprotocol><source><any/></source><destination><any/></destination></rule>
              </filter>
              <OPNsense><Firewall><Filter version="1.0.6"><rules><rule uuid="d1"><action>pass</action></rule></rules></Filter></Firewall></OPNsense>
            </opnsense>"#,
        )
        .expect("parse");

        let stats = move_legacy_rules_to_mvc(&mut out, &baseline);
        assert_eq!(stats.rules_moved, 5);
        assert_eq!(stats.baseline_rules_replaced, 1);
        assert!(stats.kept_legacy.is_empty());
        assert!(out.get_child("filter").unwrap().get_child("rule").is_none());

        let rules = mvc_rules(&out, "rules");
        let order: Vec<_> = rules
            .iter()
            .map(|r| r.get_text(&["description"]).unwrap_or("").to_string())
            .collect();
        // floating, wan, lan, then natural interface order (opt2 < opt10)
        assert_eq!(order, ["floating", "wan in", "lan web", "opt2 block", ""]);
        let seqs: Vec<_> = rules
            .iter()
            .map(|r| r.get_text(&["sequence"]).unwrap())
            .collect();
        assert_eq!(seqs, ["1", "11", "21", "31", "41"]);

        let floating = &rules[0];
        assert_eq!(
            floating.get_text(&["quick"]),
            Some("0"),
            "floating without quick"
        );
        assert_eq!(floating.get_text(&["interface"]), Some("lan,opt1"));
        assert_eq!(floating.get_text(&["direction"]), Some("any"));

        let wan = &rules[1];
        assert_eq!(wan.get_text(&["quick"]), Some("1"));
        assert_eq!(wan.get_text(&["source_not"]), Some("1"));
        assert_eq!(wan.get_text(&["destination_net"]), Some("wanip"));
        assert_eq!(wan.get_text(&["destination_port"]), Some("1-1024"));
        assert_eq!(wan.get_text(&["protocol"]), Some("TCP"));

        let lan = &rules[2];
        assert_eq!(lan.get_text(&["enabled"]), Some("0"));
        assert_eq!(lan.get_text(&["log"]), Some("1"));
        assert_eq!(
            lan.get_text(&["action"]),
            Some("pass"),
            "missing type = pass"
        );
        assert_eq!(lan.get_text(&["statetype"]), Some("keep"));
        assert_eq!(lan.get_text(&["protocol"]), Some("TCP/UDP"));
        assert_eq!(lan.get_text(&["source_net"]), Some("lan"));
        assert_eq!(lan.get_text(&["destination_net"]), Some("web_hosts"));
        assert_eq!(lan.get_text(&["destination_port"]), Some("80-443"));
        assert_eq!(lan.get_text(&["gateway"]), Some("WAN_GW"));
        assert!(lan.attributes.contains_key("uuid"));

        assert_eq!(rules[3].get_text(&["action"]), Some("block"));
    }

    #[test]
    fn clears_port_forward_links_to_converted_rules() {
        let baseline = parse(BASELINE_26_7).expect("parse");
        let mut out = parse(
            br#"<opnsense>
                <filter>
                  <rule><type>pass</type><interface>wan</interface><associated-rule-id>nat_1</associated-rule-id><source><any/></source><destination><address>10.0.0.5</address></destination></rule>
                  <rule><type>match</type><interface>wan</interface><associated-rule-id>nat_2</associated-rule-id><source><any/></source><destination><any/></destination></rule>
                </filter>
                <nat>
                  <rule><interface>wan</interface><associated-rule-id>nat_1</associated-rule-id></rule>
                  <rule><interface>wan</interface><associated-rule-id>nat_2</associated-rule-id></rule>
                  <rule><interface>wan</interface><associated-rule-id>pass</associated-rule-id></rule>
                </nat>
            </opnsense>"#,
        )
        .expect("parse");

        let stats = move_legacy_rules_to_mvc(&mut out, &baseline);
        assert_eq!(stats.nat_links_cleared, 1);
        let nat = out.get_child("nat").unwrap().get_children("rule");
        assert!(nat[0].get_child("associated-rule-id").is_none());
        assert_eq!(
            nat[1].get_text(&["associated-rule-id"]),
            Some("nat_2"),
            "rule kept legacy"
        );
        assert_eq!(nat[2].get_text(&["associated-rule-id"]), Some("pass"));
    }

    #[test]
    fn keeps_match_and_nat64_rules_legacy() {
        let baseline = parse(BASELINE_26_7).expect("parse");
        let mut out = parse(
            br#"<opnsense><filter>
                <rule><type>match</type><interface>lan</interface><source><any/></source><destination><any/></destination><descr>m</descr></rule>
                <rule><type>pass</type><interface>lan</interface><ipprotocol>inet6</ipprotocol><source><any/></source><destination><address>64:ff9b::/96</address></destination><nat><source>x</source></nat></rule>
                <rule><type>pass</type><interface>lan</interface><source><any/></source><destination><any/></destination></rule>
            </filter></opnsense>"#,
        )
        .expect("parse");

        let stats = move_legacy_rules_to_mvc(&mut out, &baseline);
        assert_eq!(stats.rules_moved, 1);
        assert_eq!(stats.kept_legacy.len(), 2);
        let legacy = out.get_child("filter").unwrap().get_children("rule");
        assert_eq!(legacy.len(), 2);
        assert_eq!(legacy[0].get_text(&["type"]), Some("match"));
    }

    #[test]
    fn maps_icmpv6_types_and_reports_dropped_fields() {
        let baseline = parse(BASELINE_26_7).expect("parse");
        let mut out = parse(
            br#"<opnsense><filter>
                <rule><type>pass</type><interface>lan</interface><ipprotocol>inet6</ipprotocol><protocol>icmp</protocol><icmptype>echoreq,neighbrsol,bogus</icmptype><source><any/></source><destination><any/></destination><dnpipe>limiter1</dnpipe><os></os></rule>
            </filter></opnsense>"#,
        )
        .expect("parse");

        let stats = move_legacy_rules_to_mvc(&mut out, &baseline);
        let rule = &mvc_rules(&out, "rules")[0];
        assert_eq!(rule.get_text(&["icmp6type"]), Some("128,135"));
        assert_eq!(rule.get_text(&["protocol"]), Some("IPV6-ICMP"));
        assert!(rule.get_child("icmptype").is_none());
        assert!(stats.dropped_fields.iter().any(|d| d.contains("bogus")));
        assert!(stats.dropped_fields.iter().any(|d| d.contains("dnpipe")));
        assert!(
            !stats.dropped_fields.iter().any(|d| d.contains("'os'")),
            "empty fields are silent"
        );
    }

    #[test]
    fn maps_icmp_type_any_to_empty() {
        let baseline = parse(BASELINE_26_7).expect("parse");
        let mut out = parse(
            br#"<opnsense><filter>
                <rule><type>pass</type><interface>opt2</interface><ipprotocol>inet</ipprotocol><protocol>icmp</protocol><icmptype>any</icmptype><source><network>opt2</network></source><destination><network>opt4</network></destination><descr>ping</descr></rule>
                <rule><type>pass</type><interface>opt2</interface><ipprotocol>inet</ipprotocol><protocol>icmp</protocol><icmptype>unreach</icmptype><source><any/></source><destination><any/></destination></rule>
                <rule><type>pass</type><interface>opt2</interface><ipprotocol>inet6</ipprotocol><protocol>icmp</protocol><icmptype>any</icmptype><source><any/></source><destination><any/></destination></rule>
            </filter></opnsense>"#,
        )
        .expect("parse");

        let stats = move_legacy_rules_to_mvc(&mut out, &baseline);
        let rules = mvc_rules(&out, "rules");
        assert_eq!(rules[0].get_text(&["icmptype"]).unwrap_or(""), "");
        assert_eq!(rules[1].get_text(&["icmptype"]), Some("unreach"));
        assert!(rules[2].get_text(&["icmp6type"]).unwrap_or("").is_empty());
        assert!(!stats.dropped_fields.iter().any(|d| d.contains("any")));
    }

    #[test]
    fn converts_pfsense_outbound_nat() {
        let baseline = parse(BASELINE_26_7).expect("parse");
        let mut out = parse(
            br#"<opnsense><nat><outbound><mode>hybrid</mode>
                <rule><interface>wan</interface><source><network>10.0.0.0/24</network></source><destination><any/></destination><target>wanip</target><descr>lan out</descr></rule>
                <rule><interface>wan</interface><source><network>10.0.1.0/24</network></source><destination><network>elastic_local</network></destination><target>203.0.113.5</target><target_subnet>32</target_subnet><dstport>9000:9100</dstport><staticnatport/></rule>
                <rule><interface>opt1</interface><source><network>10.0.2.0/24</network></source><destination><any/></destination><target>203.0.113.16</target><target_subnet>29</target_subnet><disabled/><source_hash_key>0xabc</source_hash_key><poolopts>source-hash</poolopts></rule>
            </outbound></nat></opnsense>"#,
        )
        .expect("parse");

        let stats = move_legacy_rules_to_mvc(&mut out, &baseline);
        assert_eq!(stats.outbound_moved, 3);
        let outbound = out.get_child("nat").unwrap().get_child("outbound").unwrap();
        assert_eq!(outbound.get_text(&["mode"]), Some("hybrid"));
        assert!(outbound.get_child("rule").is_none());

        let rules = mvc_rules(&out, "snatrules");
        assert_eq!(
            rules[0].get_text(&["target"]),
            Some(""),
            "<if>ip = interface address"
        );
        assert_eq!(rules[0].get_text(&["sequence"]), Some("1"));
        assert_eq!(rules[1].get_text(&["target"]), Some("203.0.113.5"));
        assert_eq!(rules[1].get_text(&["destination_port"]), Some("9000-9100"));
        assert_eq!(rules[1].get_text(&["staticnatport"]), Some("1"));
        assert_eq!(rules[2].get_text(&["target"]), Some("203.0.113.16/29"));
        assert_eq!(rules[2].get_text(&["enabled"]), Some("0"));
        assert_eq!(rules[2].get_text(&["poolopts"]), Some("source-hash"));
        assert_eq!(
            rules[2].get_text(&["poolopts_sourcehashkey"]),
            Some("0xabc")
        );
    }

    #[test]
    fn adds_self_bypass_before_policy_routing_to_any() {
        let baseline = parse(BASELINE_26_7).expect("parse");
        let mut out = parse(
            br#"<opnsense><filter>
                <rule><type>pass</type><interface>opt4</interface><ipprotocol>inet</ipprotocol><source><any/></source><destination><network>opt4</network></destination></rule>
                <rule><type>pass</type><interface>opt4</interface><ipprotocol>inet</ipprotocol><protocol>tcp/udp</protocol><source><any/></source><destination><any/></destination><gateway>WAN2_GW</gateway></rule>
                <rule><type>pass</type><interface>opt4</interface><ipprotocol>inet</ipprotocol><source><any/></source><destination><network>opt2</network></destination><gateway>MGMT_GW</gateway></rule>
            </filter></opnsense>"#,
        )
        .expect("parse");
        let stats = move_legacy_rules_to_mvc(&mut out, &baseline);
        assert_eq!(stats.self_bypass_added, 1);
        let rules = mvc_rules(&out, "rules");
        let summary: Vec<String> = rules
            .iter()
            .map(|r| {
                format!(
                    "{}:{}:{}",
                    r.get_text(&["sequence"]).unwrap(),
                    r.get_text(&["destination_net"]).unwrap(),
                    r.get_text(&["gateway"]).unwrap_or("-")
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                "1:opt4:-",
                "11:(self):-",
                "21:any:WAN2_GW",
                "31:opt2:MGMT_GW"
            ]
        );
        assert_eq!(rules[1].get_text(&["protocol"]), Some("TCP/UDP"));
        assert_ne!(
            rules[1].attributes.get("uuid"),
            rules[2].attributes.get("uuid")
        );
    }

    #[test]
    fn ports_with_protocol_any_become_tcp_udp() {
        let baseline = parse(BASELINE_26_7).expect("parse");
        let mut out = parse(
            br#"<opnsense>
                <filter><rule><type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol><source><any/></source><destination><any/><port>53</port></destination></rule></filter>
                <nat><outbound><mode>hybrid</mode>
                  <rule><interface>wan</interface><source><network>127.0.0.0/8</network></source><destination><any/></destination><dstport>500</dstport><staticnatport/><descr>Auto created rule for ISAKMP - localhost to WAN</descr></rule>
                  <rule><interface>wan</interface><source><network>10.0.0.0/24</network></source><destination><any/></destination><descr>no ports</descr></rule>
                </outbound></nat></opnsense>"#,
        )
        .expect("parse");
        move_legacy_rules_to_mvc(&mut out, &baseline);
        assert_eq!(
            mvc_rules(&out, "rules")[0].get_text(&["protocol"]),
            Some("TCP/UDP")
        );
        let snat = mvc_rules(&out, "snatrules");
        assert_eq!(snat[0].get_text(&["protocol"]), Some("TCP/UDP"));
        assert_eq!(snat[0].get_text(&["destination_port"]), Some("500"));
        assert_eq!(snat[1].get_text(&["protocol"]), Some("any"));
    }

    #[test]
    fn infers_outbound_nat_address_family() {
        let baseline = parse(BASELINE_26_7).expect("parse");
        let mut out = parse(
            br#"<opnsense><nat><outbound><mode>hybrid</mode>
                <rule><interface>wan</interface><source><network>127.0.0.0/8</network></source><destination><any/></destination><target>wanip</target><descr>Auto created rule - localhost to WAN</descr></rule>
                <rule><interface>wan</interface><source><network>::1/128</network></source><destination><any/></destination><target>wanip</target><descr>Auto created rule - localhost to WAN</descr></rule>
                <rule><interface>wan</interface><source><network>lan_hosts</network></source><destination><network>2001:db8::/32</network></destination></rule>
                <rule><interface>wan</interface><ipprotocol>inet6</ipprotocol><source><network>lan_v6</network></source><destination><any/></destination></rule>
                <rule><interface>wan</interface><ipprotocol>inet46</ipprotocol><source><network>10.0.0.0/8</network></source><destination><any/></destination></rule>
            </outbound></nat></opnsense>"#,
        )
        .expect("parse");

        let stats = move_legacy_rules_to_mvc(&mut out, &baseline);
        let families: Vec<_> = mvc_rules(&out, "snatrules")
            .iter()
            .map(|r| r.get_text(&["ipprotocol"]).unwrap_or("").to_string())
            .collect();
        assert_eq!(families, ["inet", "inet6", "inet6", "inet6", "inet"]);
        assert!(stats.dropped_fields.iter().any(|d| d.contains("inet46")));
    }

    #[test]
    fn leaves_rules_alone_for_pre_26_7_baseline() {
        let baseline = parse(
            br#"<opnsense><OPNsense><Firewall><Filter version="1.0.4"/></Firewall></OPNsense></opnsense>"#,
        )
        .expect("parse");
        let mut out =
            parse(br#"<opnsense><filter><rule><type>pass</type></rule></filter></opnsense>"#)
                .expect("parse");
        let stats = move_legacy_rules_to_mvc(&mut out, &baseline);
        assert_eq!(stats, Default::default());
        assert!(out.get_child("filter").unwrap().get_child("rule").is_some());
    }

    #[test]
    fn natural_order_matches_strnatcmp() {
        assert_eq!(natural_cmp("opt2", "opt10"), Ordering::Less);
        assert_eq!(natural_cmp("opt10", "opt9"), Ordering::Greater);
        assert_eq!(natural_cmp("opt1", "opt1"), Ordering::Equal);
        assert_eq!(natural_cmp("ipsec", "opt1"), Ordering::Less);
    }
}
