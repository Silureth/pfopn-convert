//! pfSense's reply-to exemption for directly connected hosts.
//!
//! Both platforms add `reply-to (<if> <gateway>)` to pass rules on interfaces
//! with a gateway (pfSense `filter.inc`, OPNsense `FilterRule::convertReplyTo`),
//! so replies leave through the interface the request came in on. pfSense's
//! patched kernel then skips reply-to when the reply goes to a host in a
//! subnet directly connected to that interface (`pf_route()` in pfSense's
//! `pf.c`), and the reply goes straight to that host. OPNsense's kernel has no
//! such exemption and sends it to the gateway. When the gateway is a stateful
//! firewall that never saw the request, it drops the reply: TCP from hosts in
//! the firewall's own WAN subnet breaks after a migration.
//!
//! OPNsense's equivalent is a rule with "Disable reply-to" for those hosts.
//! For every pass rule on an interface with a gateway (no policy-routing
//! gateway, reply-to not already disabled):
//!
//! - source entirely inside the interface's subnets: reply-to is disabled on
//!   the rule itself;
//! - source `any`: a copy restricted to the interface's network, with reply-to
//!   disabled, is inserted directly above the rule;
//! - alias or network partly inside: a network alias with only the members in
//!   the interface's subnets (`<alias>_<if>_local`) is created, and a copy of
//!   the rule using it, with reply-to disabled, is inserted above. The other
//!   sources keep reply-to, as on pfSense.
//!
//! Sources that cannot be resolved (URL tables, GeoIP, host names) are a
//! special case. On the interface of the default IPv4 gateway (with gateway
//! switching off), reply-to is disabled on the whole rule: replies to hosts
//! outside the subnet then follow the default route, which is the same
//! gateway, and replies to hosts inside go straight to them, as on pfSense.
//! On other interfaces they are reported, as are inverted matches and
//! interfaces whose subnet is only known at runtime (DHCP).
//!
//! Runs on pfSense-format `<filter>` rules, before they are moved into the
//! OPNsense rule model, and on aliases already in the OPNsense alias model.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use xml_diff_core::XmlNode;

use crate::transform::filter_mvc::stable_uuid;
use crate::transform::rule_flags::pf_flag_is_set;

#[derive(Debug, Default)]
pub struct ReplyToReport {
    /// Rules whose source is entirely local; reply-to disabled on the rule.
    pub disabled_on_rule: usize,
    /// Copies inserted for the local part of the source.
    pub twins_added: usize,
    /// Aliases created for the local members of an alias.
    pub aliases_added: Vec<String>,
    /// Rules on the default gateway's interface with sources that cannot be
    /// resolved, on which reply-to was disabled ("label (entries)").
    pub disabled_unresolved: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn exempt_local_subnets(out: &mut XmlNode) -> ReplyToReport {
    let mut report = ReplyToReport::default();
    let (subnets, dynamic) = gateway_interface_subnets(out);
    if subnets.is_empty() && dynamic.is_empty() {
        return report;
    }
    let aliases = read_aliases(out);
    let mut alias_names: BTreeSet<String> =
        aliases.keys().map(|n| n.to_ascii_lowercase()).collect();
    // (alias, interface, family) -> generated alias name
    let mut generated: BTreeMap<(String, String, String), String> = BTreeMap::new();
    let mut new_aliases: Vec<XmlNode> = Vec::new();
    let mut dynamic_warned: BTreeSet<String> = BTreeSet::new();
    let default_iface = default_gateway_interface(out);

    let Some(filter) = out.children.iter_mut().find(|c| c.tag == "filter") else {
        return report;
    };
    let rules = std::mem::take(&mut filter.children);
    let mut result = Vec::with_capacity(rules.len());
    for (idx, mut rule) in rules.into_iter().enumerate() {
        if rule.tag != "rule" || !reply_to_applies(&rule) {
            result.push(rule);
            continue;
        }
        let iface = text(&rule, "interface");
        let label = rule_label(&rule);
        if dynamic.contains(&iface) {
            if dynamic_warned.insert(iface.clone()) {
                report.warnings.push(format!(
                    "interface '{iface}' gets its address by DHCP/PPP, so its subnet is unknown here; pfSense sent replies to hosts in that subnet directly, OPNsense sends them to the gateway (add rules with \"Disable reply-to\" for those hosts if needed)"
                ));
            }
            result.push(rule);
            continue;
        }
        let Some(local) = subnets.get(&iface) else {
            result.push(rule);
            continue;
        };
        let family = text(&rule, "ipprotocol");
        let local: Vec<Net> = local
            .iter()
            .copied()
            .filter(|n| match family.as_str() {
                "inet6" => n.v6,
                "inet46" => true,
                _ => !n.v6,
            })
            .collect();
        if local.is_empty() {
            result.push(rule);
            continue;
        }
        let Some(source) = rule.get_child("source") else {
            result.push(rule);
            continue;
        };
        if pf_flag_is_set(source, "not") {
            report.warnings.push(format!(
                "rule {label}: inverted source; pfSense sent replies to hosts in the '{iface}' subnet directly, OPNsense sends them to the gateway; check whether such hosts match"
            ));
            result.push(rule);
            continue;
        }

        let coverage = if source.get_child("any").is_some() {
            Coverage::Any
        } else if let Some(network) = source.get_text(&["network"]).map(str::trim) {
            if network == iface {
                Coverage::All
            } else {
                Coverage::None
            }
        } else if let Some(address) = source.get_text(&["address"]).map(str::trim) {
            let (coverage, unknown) = classify_address(address, &local, &aliases);
            if unknown.is_empty() {
                coverage
            } else if family != "inet6"
                && family != "inet46"
                && default_iface.as_deref() == Some(iface.as_str())
            {
                set_flag(&mut rule, "disablereplyto");
                report
                    .disabled_unresolved
                    .push(format!("{label} ({})", unknown.join(", ")));
                result.push(rule);
                continue;
            } else {
                report.warnings.push(format!(
                    "rule {label}: alias '{address}' has entries that cannot be checked against the interface subnet ({}); pfSense sent replies to hosts in that subnet directly, OPNsense sends them to the gateway",
                    unknown.join(", ")
                ));
                coverage
            }
        } else {
            Coverage::None
        };

        match coverage {
            Coverage::None => result.push(rule),
            Coverage::All => {
                set_flag(&mut rule, "disablereplyto");
                report.disabled_on_rule += 1;
                result.push(rule);
            }
            Coverage::Any => {
                let mut src = XmlNode::new("source");
                push(&mut src, "network", &iface);
                result.push(twin(&rule, src, idx));
                report.twins_added += 1;
                result.push(rule);
            }
            Coverage::Partial { alias, members } => {
                let key = (alias.clone(), iface.clone(), family.clone());
                let name = match generated.get(&key) {
                    Some(name) => name.clone(),
                    None => {
                        let name = unique_alias_name(&alias, &iface, &mut alias_names);
                        new_aliases.push(alias_node(&name, &alias, &iface, &members));
                        report.aliases_added.push(name.clone());
                        generated.insert(key, name.clone());
                        name
                    }
                };
                let mut src = XmlNode::new("source");
                push(&mut src, "address", &name);
                result.push(twin(&rule, src, idx));
                report.twins_added += 1;
                result.push(rule);
            }
            Coverage::PartialNetwork(net) => {
                let mut src = XmlNode::new("source");
                push(&mut src, "address", &net);
                result.push(twin(&rule, src, idx));
                report.twins_added += 1;
                result.push(rule);
            }
        }
    }
    filter.children = result;

    if !new_aliases.is_empty() {
        let container = ensure_path(out, &["OPNsense", "Firewall", "Alias", "aliases"]);
        container.children.extend(new_aliases);
    }
    report
}

enum Coverage {
    /// No source address is in the interface's subnets.
    None,
    /// Every source address is in the interface's subnets.
    All,
    /// Source `any`.
    Any,
    /// A plain network containing the interface's subnet: the twin uses that subnet.
    PartialNetwork(String),
    /// An alias with some members in the interface's subnets.
    Partial { alias: String, members: Vec<String> },
}

/// pfSense: reply-to on non-floating pass rules without a gateway, unless
/// disabled (`filter.inc`, `filter_generate_user_rule()`).
fn reply_to_applies(rule: &XmlNode) -> bool {
    let kind = text(rule, "type");
    (kind.is_empty() || kind == "pass")
        && rule.get_child("floating").is_none()
        && text(rule, "gateway").is_empty()
        && !pf_flag_is_set(rule, "disablereplyto")
}

/// The coverage of a source address or alias, and the alias entries that
/// cannot be resolved.
fn classify_address(
    address: &str,
    local: &[Net],
    aliases: &BTreeMap<String, AliasDef>,
) -> (Coverage, Vec<String>) {
    if let Some(net) = Net::parse(address) {
        if local.iter().any(|l| l.contains(&net)) {
            return (Coverage::All, Vec::new());
        }
        let inner: Vec<String> = local
            .iter()
            .filter(|l| net.contains(l))
            .map(|n| n.to_string())
            .collect();
        let coverage = match inner.len() {
            0 => Coverage::None,
            1 => Coverage::PartialNetwork(inner[0].clone()),
            _ => Coverage::Partial {
                alias: address.replace(['.', ':', '/'], "_"),
                members: inner,
            },
        };
        return (coverage, Vec::new());
    }
    if !aliases.contains_key(address) {
        return (Coverage::None, Vec::new());
    }
    let mut entries = Vec::new();
    let mut unknown = Vec::new();
    resolve_alias(address, aliases, &mut entries, &mut unknown, 0);
    let mut members = Vec::new();
    let mut all_local = unknown.is_empty() && !entries.is_empty();
    for entry in &entries {
        let inside = match entry {
            Entry::Net(net) => {
                if local.iter().any(|l| l.contains(net)) {
                    members.push(net.to_string());
                    true
                } else {
                    for l in local.iter().filter(|l| net.contains(l)) {
                        members.push(l.to_string());
                    }
                    false
                }
            }
            Entry::Range(raw, lo, hi) => {
                if local.iter().any(|l| l.contains(lo) && l.contains(hi)) {
                    members.push(raw.clone());
                    true
                } else {
                    false
                }
            }
        };
        all_local &= inside;
    }
    // Numeric order; ranges ("a-b") sort by their first address.
    members.sort_by_key(|m| {
        Net::parse(m.split('-').next().unwrap_or(m))
            .map(|n| (n.v6, n.addr, n.prefix))
            .unwrap_or((true, u128::MAX, 0))
    });
    members.dedup();
    let coverage = if members.is_empty() {
        Coverage::None
    } else if all_local {
        Coverage::All
    } else {
        Coverage::Partial {
            alias: address.to_string(),
            members,
        }
    };
    (coverage, unknown)
}

/// The interface of the default IPv4 gateway, unless OPNsense may switch the
/// default gateway (then replies without reply-to could leave elsewhere).
/// Reads the Gateways model (`gateways_mvc` has run) or pfSense's legacy
/// `defaultgw4`.
fn default_gateway_interface(out: &XmlNode) -> Option<String> {
    let system = out.get_child("system");
    if system.is_some_and(|s| s.get_child("gw_switch_default").is_some()) {
        return None;
    }
    let mvc = out
        .get_child("OPNsense")
        .and_then(|o| o.get_child("Gateways"))
        .map(|g| g.get_children("gateway_item"))
        .unwrap_or_default();
    let legacy = out
        .get_child("gateways")
        .map(|g| g.get_children("gateway_item"))
        .unwrap_or_default();
    let legacy_default = out
        .get_child("gateways")
        .map(|g| text(g, "defaultgw4"))
        .unwrap_or_default();
    let item = mvc
        .iter()
        .find(|g| text(g, "defaultgw") == "1" && text(g, "ipprotocol") != "inet6")
        .or_else(|| {
            legacy
                .iter()
                .find(|g| !legacy_default.is_empty() && text(g, "name") == legacy_default)
        })?;
    let name = text(item, "name");
    // Only when that interface's own gateway is the default gateway.
    out.get_child("interfaces")?
        .children
        .iter()
        .find(|i| text(i, "gateway") == name)
        .map(|i| i.tag.clone())
}

struct AliasDef {
    kind: String,
    entries: Vec<String>,
}

enum Entry {
    Net(Net),
    Range(String, Net, Net),
}

fn read_aliases(out: &XmlNode) -> BTreeMap<String, AliasDef> {
    let mut map = BTreeMap::new();
    let Some(container) = out
        .get_child("OPNsense")
        .and_then(|o| o.get_child("Firewall"))
        .and_then(|f| f.get_child("Alias"))
        .and_then(|a| a.get_child("aliases"))
    else {
        return map;
    };
    for alias in container.get_children("alias") {
        let name = text(alias, "name");
        if name.is_empty() {
            continue;
        }
        let entries = text(alias, "content")
            .split(['\n', ' '])
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .map(str::to_string)
            .collect();
        map.insert(
            name,
            AliasDef {
                kind: text(alias, "type"),
                entries,
            },
        );
    }
    map
}

fn resolve_alias(
    name: &str,
    aliases: &BTreeMap<String, AliasDef>,
    entries: &mut Vec<Entry>,
    unknown: &mut Vec<String>,
    depth: usize,
) {
    let Some(def) = aliases.get(name) else {
        unknown.push(name.to_string());
        return;
    };
    if depth > 8 || !matches!(def.kind.as_str(), "host" | "network" | "networkgroup") {
        unknown.push(format!("{name} ({})", def.kind));
        return;
    }
    for entry in &def.entries {
        if let Some(net) = Net::parse(entry) {
            entries.push(Entry::Net(net));
        } else if let Some((lo, hi)) = entry
            .split_once('-')
            .and_then(|(a, b)| Some((Net::parse(a.trim())?, Net::parse(b.trim())?)))
        {
            entries.push(Entry::Range(entry.clone(), lo, hi));
        } else if aliases.contains_key(entry.as_str()) {
            resolve_alias(entry, aliases, entries, unknown, depth + 1);
        } else {
            unknown.push(entry.clone());
        }
    }
}

/// Interfaces where reply-to applies: static subnets (interface address and
/// virtual IPs), and the names of those with a dynamic address.
fn gateway_interface_subnets(out: &XmlNode) -> (BTreeMap<String, Vec<Net>>, BTreeSet<String>) {
    let mut subnets: BTreeMap<String, Vec<Net>> = BTreeMap::new();
    let mut dynamic = BTreeSet::new();
    let Some(interfaces) = out.get_child("interfaces") else {
        return (subnets, dynamic);
    };
    for iface in &interfaces.children {
        let enabled = iface
            .get_child("enable")
            .map(|e| e.text.as_deref().map(str::trim) != Some("0"))
            .unwrap_or(false);
        if !enabled {
            continue;
        }
        let name = iface.tag.clone();
        let ipaddr = text(iface, "ipaddr");
        let gw4 = !text(iface, "gateway").is_empty();
        let gw6 = !text(iface, "gatewayv6").is_empty();
        let mut nets = Vec::new();
        if gw4 {
            match Net::parse(&format!("{ipaddr}/{}", text(iface, "subnet"))) {
                Some(net) => nets.push(net.network()),
                None => {
                    dynamic.insert(name.clone());
                }
            }
        } else if matches!(ipaddr.as_str(), "dhcp" | "pppoe" | "pptp" | "l2tp" | "ppp") {
            dynamic.insert(name.clone());
        }
        if gw6 {
            if let Some(net) = Net::parse(&format!(
                "{}/{}",
                text(iface, "ipaddrv6"),
                text(iface, "subnetv6")
            )) {
                nets.push(net.network());
            }
        }
        if !nets.is_empty() {
            subnets.insert(name, nets);
        }
    }
    if let Some(vips) = out.get_child("virtualip") {
        for vip in vips.get_children("vip") {
            let iface = text(vip, "interface");
            if let Some(nets) = subnets.get_mut(&iface) {
                if let Some(net) = Net::parse(&format!(
                    "{}/{}",
                    text(vip, "subnet"),
                    text(vip, "subnet_bits")
                )) {
                    let net = net.network();
                    if !nets.iter().any(|n| n.contains(&net)) {
                        nets.push(net);
                    }
                }
            }
        }
    }
    (subnets, dynamic)
}

fn twin(rule: &XmlNode, source: XmlNode, idx: usize) -> XmlNode {
    let mut copy = rule.clone();
    copy.children
        .retain(|c| !matches!(c.tag.as_str(), "tracker" | "associated-rule-id" | "source"));
    let pos = copy
        .children
        .iter()
        .position(|c| c.tag == "destination")
        .unwrap_or(copy.children.len());
    copy.children.insert(pos, source);
    set_flag(&mut copy, "disablereplyto");
    // Descriptions repeat; the tracker and position keep the UUID unique.
    let seed = rule
        .attributes
        .get("uuid")
        .cloned()
        .unwrap_or_else(|| format!("{}|{}|{idx}", text(rule, "tracker"), rule_label(rule)));
    copy.attributes.insert(
        "uuid".to_string(),
        stable_uuid(&format!("reply-to-local|{seed}")),
    );
    let descr = text(rule, "descr");
    let descr = if descr.is_empty() {
        "own subnet, no reply-to (pfSense behaviour)".to_string()
    } else {
        format!("{descr} (own subnet, no reply-to)")
    };
    match copy.children.iter_mut().find(|c| c.tag == "descr") {
        Some(d) => d.text = Some(descr),
        None => push(&mut copy, "descr", &descr),
    }
    copy
}

fn alias_node(name: &str, base: &str, iface: &str, members: &[String]) -> XmlNode {
    let mut node = XmlNode::new("alias");
    node.attributes.insert(
        "uuid".to_string(),
        stable_uuid(&format!("reply-to-alias|{name}")),
    );
    push(&mut node, "enabled", "1");
    push(&mut node, "name", name);
    push(&mut node, "type", "network");
    push(&mut node, "content", &members.join("\n"));
    push(
        &mut node,
        "description",
        &format!("Members of {base} in the {iface} subnet, for rules without reply-to"),
    );
    node
}

/// `<base>_<iface>_local`, shortened to OPNsense's limit (under 32 characters).
fn unique_alias_name(base: &str, iface: &str, taken: &mut BTreeSet<String>) -> String {
    let clean: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let suffix = format!("_{iface}_local");
    let mut n = 0;
    loop {
        let extra = if n == 0 { String::new() } else { n.to_string() };
        let room = 31usize.saturating_sub(suffix.len() + extra.len());
        let head: String = clean.chars().take(room).collect();
        let head = if head.starts_with(|c: char| c.is_ascii_digit()) || head.is_empty() {
            format!("a{}", &head[..head.len().saturating_sub(1)])
        } else {
            head
        };
        let candidate = format!("{head}{suffix}{extra}");
        if taken.insert(candidate.to_ascii_lowercase()) {
            return candidate;
        }
        n += 1;
    }
}

fn rule_label(rule: &XmlNode) -> String {
    let descr = text(rule, "descr");
    let tracker = text(rule, "tracker");
    match (descr.is_empty(), tracker.is_empty()) {
        (false, _) => format!("'{descr}' on {}", text(rule, "interface")),
        (true, false) => format!("#{tracker} on {}", text(rule, "interface")),
        _ => format!("on {}", text(rule, "interface")),
    }
}

/// IPv4 or IPv6 network, address bits in the low end of a u128.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Net {
    addr: u128,
    prefix: u8,
    v6: bool,
}

impl Net {
    fn parse(value: &str) -> Option<Net> {
        let (ip, prefix) = match value.split_once('/') {
            Some((ip, bits)) => (ip, Some(bits.parse::<u8>().ok()?)),
            None => (value, None),
        };
        match ip.parse::<IpAddr>().ok()? {
            IpAddr::V4(v4) => {
                let prefix = prefix.unwrap_or(32);
                (prefix <= 32).then_some(Net {
                    addr: u128::from(u32::from(v4)),
                    prefix,
                    v6: false,
                })
            }
            IpAddr::V6(v6) => {
                let prefix = prefix.unwrap_or(128);
                (prefix <= 128).then_some(Net {
                    addr: u128::from(v6),
                    prefix,
                    v6: true,
                })
            }
        }
    }

    fn width(&self) -> u8 {
        if self.v6 {
            128
        } else {
            32
        }
    }

    fn mask(&self, prefix: u8) -> u128 {
        let width = self.width();
        if prefix == 0 {
            return 0;
        }
        let ones = if width == 128 {
            u128::MAX
        } else {
            (1u128 << width) - 1
        };
        ones & !((1u128 << (width - prefix)) - 1)
    }

    fn network(&self) -> Net {
        Net {
            addr: self.addr & self.mask(self.prefix),
            ..*self
        }
    }

    /// `other` lies entirely inside `self`.
    fn contains(&self, other: &Net) -> bool {
        self.v6 == other.v6
            && self.prefix <= other.prefix
            && (other.addr & self.mask(self.prefix)) == (self.addr & self.mask(self.prefix))
    }
}

impl std::fmt::Display for Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ip = if self.v6 {
            IpAddr::from(std::net::Ipv6Addr::from(self.addr))
        } else {
            IpAddr::from(std::net::Ipv4Addr::from(self.addr as u32))
        };
        if self.prefix == self.width() {
            write!(f, "{ip}")
        } else {
            write!(f, "{ip}/{}", self.prefix)
        }
    }
}

fn set_flag(rule: &mut XmlNode, tag: &str) {
    match rule.children.iter_mut().find(|c| c.tag == tag) {
        Some(child) => {
            child.text = Some("1".to_string());
            child.children.clear();
        }
        None => push(rule, tag, "1"),
    }
}

fn text(node: &XmlNode, tag: &str) -> String {
    node.get_text(&[tag])
        .map(str::trim)
        .unwrap_or("")
        .to_string()
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

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::exempt_local_subnets;

    fn config(rules: &str) -> xml_diff_core::XmlNode {
        parse(
            format!(
                r#"<opnsense>
                  <interfaces>
                    <wan><enable>1</enable><if>vtnet0</if><ipaddr>203.0.113.20</ipaddr><subnet>27</subnet><gateway>WANGW</gateway></wan>
                    <lan><enable>1</enable><if>vtnet1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>
                    <opt1><enable>1</enable><if>vtnet2</if><ipaddr>dhcp</ipaddr></opt1>
                  </interfaces>
                  <OPNsense><Firewall><Alias><aliases>
                    <alias><name>mixed</name><type>host</type><content>203.0.113.5
198.51.100.7
nested</content></alias>
                    <alias><name>nested</name><type>network</type><content>203.0.113.8/29</content></alias>
                    <alias><name>remote</name><type>host</type><content>198.51.100.7</content></alias>
                    <alias><name>feed</name><type>urltable</type><content>https://example.invalid/list</content></alias>
                  </aliases></Alias></Firewall></OPNsense>
                  <filter>{rules}</filter>
                </opnsense>"#
            )
            .as_bytes(),
        )
        .expect("parse")
    }

    fn rules(out: &xml_diff_core::XmlNode) -> Vec<(String, String, bool)> {
        out.get_child("filter")
            .unwrap()
            .get_children("rule")
            .iter()
            .map(|r| {
                let src = r.get_child("source").unwrap();
                let source = if src.get_child("any").is_some() {
                    "any".to_string()
                } else {
                    src.get_text(&["network"])
                        .or_else(|| src.get_text(&["address"]))
                        .unwrap_or("")
                        .to_string()
                };
                (
                    r.get_text(&["descr"]).unwrap_or("").to_string(),
                    source,
                    r.get_text(&["disablereplyto"]) == Some("1"),
                )
            })
            .collect()
    }

    #[test]
    fn any_source_gets_an_own_subnet_twin() {
        let mut out = config(
            "<rule><tracker>1</tracker><type>pass</type><interface>wan</interface><source><any/></source><destination><any/></destination><descr>web</descr></rule>",
        );
        let report = exempt_local_subnets(&mut out);
        assert_eq!(report.twins_added, 1);
        assert_eq!(
            rules(&out),
            vec![
                ("web (own subnet, no reply-to)".into(), "wan".into(), true),
                ("web".into(), "any".into(), false),
            ]
        );
        let twin = &out.get_child("filter").unwrap().get_children("rule")[0];
        assert!(twin.get_child("tracker").is_none());
        assert!(twin.attributes.contains_key("uuid"));
    }

    #[test]
    fn twins_of_rules_with_the_same_description_get_distinct_uuids() {
        let rule = "<rule><type>pass</type><interface>wan</interface><source><any/></source><destination><any/></destination><descr>smtp</descr></rule>";
        let mut out = config(&format!("{rule}{rule}"));
        exempt_local_subnets(&mut out);
        let uuids: std::collections::BTreeSet<_> = out
            .get_child("filter")
            .unwrap()
            .get_children("rule")
            .iter()
            .filter_map(|r| r.attributes.get("uuid").cloned())
            .collect();
        assert_eq!(uuids.len(), 2);
    }

    #[test]
    fn mixed_alias_is_split_and_local_peer_is_flagged() {
        let mut out = config(
            "<rule><type>pass</type><interface>wan</interface><source><address>mixed</address></source><destination><any/></destination><descr>zbx</descr></rule>\
             <rule><type>pass</type><interface>wan</interface><source><address>203.0.113.4</address></source><destination><any/></destination><descr>ipsec peer</descr></rule>\
             <rule><type>pass</type><interface>wan</interface><source><address>remote</address></source><destination><any/></destination><descr>remote only</descr></rule>\
             <rule><type>pass</type><interface>wan</interface><source><address>mixed</address></source><destination><any/></destination><descr>zbx 2</descr></rule>",
        );
        let report = exempt_local_subnets(&mut out);
        assert_eq!(report.aliases_added, vec!["mixed_wan_local"]);
        assert_eq!(report.disabled_on_rule, 1);
        assert_eq!(report.twins_added, 2);
        assert_eq!(
            rules(&out),
            vec![
                (
                    "zbx (own subnet, no reply-to)".into(),
                    "mixed_wan_local".into(),
                    true
                ),
                ("zbx".into(), "mixed".into(), false),
                ("ipsec peer".into(), "203.0.113.4".into(), true),
                ("remote only".into(), "remote".into(), false),
                (
                    "zbx 2 (own subnet, no reply-to)".into(),
                    "mixed_wan_local".into(),
                    true
                ),
                ("zbx 2".into(), "mixed".into(), false),
            ]
        );
        let alias = out
            .get_child("OPNsense")
            .unwrap()
            .get_child("Firewall")
            .unwrap()
            .get_child("Alias")
            .unwrap()
            .get_child("aliases")
            .unwrap()
            .get_children("alias")
            .into_iter()
            .find(|a| a.get_text(&["name"]) == Some("mixed_wan_local"))
            .expect("generated alias");
        assert_eq!(alias.get_text(&["type"]), Some("network"));
        assert_eq!(
            alias.get_text(&["content"]),
            Some("203.0.113.5\n203.0.113.8/29")
        );
    }

    #[test]
    fn leaves_lan_gateway_and_disabled_reply_to_rules_alone() {
        let mut out = config(
            "<rule><type>pass</type><interface>lan</interface><source><any/></source><destination><any/></destination><descr>lan</descr></rule>\
             <rule><type>pass</type><interface>wan</interface><gateway>GW2</gateway><source><any/></source><destination><any/></destination><descr>pbr</descr></rule>\
             <rule><type>pass</type><interface>wan</interface><disablereplyto>1</disablereplyto><source><any/></source><destination><any/></destination><descr>done</descr></rule>\
             <rule><type>block</type><interface>wan</interface><source><any/></source><destination><any/></destination><descr>block</descr></rule>",
        );
        let report = exempt_local_subnets(&mut out);
        assert_eq!(report.twins_added + report.disabled_on_rule, 0);
        assert_eq!(rules(&out).len(), 4);
    }

    #[test]
    fn warns_for_unresolvable_aliases_and_dynamic_interfaces() {
        let mut out = config(
            "<rule><type>pass</type><interface>wan</interface><source><address>feed</address></source><destination><any/></destination><descr>feed</descr></rule>\
             <rule><type>pass</type><interface>opt1</interface><source><any/></source><destination><any/></destination><descr>dyn</descr></rule>",
        );
        let report = exempt_local_subnets(&mut out);
        assert_eq!(report.twins_added, 0);
        assert_eq!(report.warnings.len(), 2, "{:?}", report.warnings);
    }

    #[test]
    fn unresolvable_source_on_the_default_gateway_interface_disables_reply_to() {
        let rule = "<rule><type>pass</type><interface>wan</interface><source><address>feed</address></source><destination><any/></destination><descr>feed</descr></rule>";
        let gateways = parse(
            br#"<Gateways><gateway_item><name>WANGW</name><interface>wan</interface><ipprotocol>inet</ipprotocol><defaultgw>1</defaultgw></gateway_item></Gateways>"#,
        )
        .expect("parse");
        let with_gateways = |switching: bool| {
            let mut out = config(rule);
            let opn = out
                .children
                .iter_mut()
                .find(|c| c.tag == "OPNsense")
                .unwrap();
            opn.children.push(gateways.clone());
            if switching {
                out.children.push(
                    parse(b"<system><gw_switch_default>1</gw_switch_default></system>")
                        .expect("parse"),
                );
            }
            out
        };

        // Replies to hosts outside the subnet follow the default route, which
        // is the same gateway; hosts inside are answered directly.
        let mut out = with_gateways(false);
        let report = exempt_local_subnets(&mut out);
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert_eq!(report.disabled_on_rule, 0);
        assert_eq!(report.disabled_unresolved.len(), 1);
        assert!(report.disabled_unresolved[0].contains("feed"));
        assert_eq!(
            rules(&out),
            vec![("feed".to_string(), "feed".to_string(), true)]
        );

        // With default gateway switching the default route may move: warn.
        let mut out = with_gateways(true);
        let report = exempt_local_subnets(&mut out);
        assert!(report.disabled_unresolved.is_empty());
        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
    }
}
