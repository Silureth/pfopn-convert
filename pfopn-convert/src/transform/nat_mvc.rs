use std::net::IpAddr;

use xml_diff_core::XmlNode;

use super::version::{model_version, version_at_least};

const FILTER_PATH: &[&str] = &["OPNsense", "Firewall", "Filter"];

/// Outcome of moving legacy NAT entries into the OPNsense Filter model.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct NatMvcStats {
    pub onetoone_moved: usize,
    pub npt_moved: usize,
    /// Human-readable reasons for entries that could not be converted.
    pub skipped: Vec<String>,
}

/// Move legacy `<nat><onetoone>` and `<nat><npt>` entries into the OPNsense
/// MVC Filter model (`OPNsense/Firewall/Filter/{onetoone,npt}/rule`).
///
/// OPNsense 26.7 only reads these from the MVC model (`pf.inc`). Its own
/// migrations (`MFP1_0_3` for NPt, `MFP1_0_4` for 1:1) never run on import
/// because the baseline's Filter model is already newer, so the converter does
/// the same mapping. Unlike `MFP1_0_4`, `<any>` is evaluated with pfSense
/// semantics (present = any): pfSense writes it as an empty element, which the
/// OPNsense migration would treat as missing and drop the rule.
///
/// Only runs when the baseline Filter model is new enough to hold the entries
/// (1.0.3 for NPt, 1.0.4 for 1:1); older targets keep the legacy layout.
pub fn move_legacy_nat_to_mvc(out: &mut XmlNode, baseline: &XmlNode) -> NatMvcStats {
    let mut stats = NatMvcStats::default();
    let Some(version) = model_version(baseline, FILTER_PATH).map(str::to_string) else {
        return stats;
    };
    let do_npt = version_at_least(&version, &[1, 0, 3]);
    let do_onetoone = version_at_least(&version, &[1, 0, 4]);
    if !do_npt && !do_onetoone {
        return stats;
    }

    let Some(nat) = out.children.iter_mut().find(|c| c.tag == "nat") else {
        return stats;
    };
    let mut onetoone = Vec::new();
    let mut npt = Vec::new();
    nat.children.retain(|c| match c.tag.as_str() {
        "onetoone" if do_onetoone => {
            onetoone.push(c.clone());
            false
        }
        "npt" if do_npt => {
            npt.push(c.clone());
            false
        }
        _ => true,
    });

    if !onetoone.is_empty() {
        let container = ensure_path(out, &["OPNsense", "Firewall", "Filter", "onetoone"]);
        let mut seq = max_sequence(container);
        for (idx, legacy) in onetoone.iter().enumerate() {
            match onetoone_rule(legacy) {
                Ok(mut rule) => {
                    seq += 1;
                    finish_rule(&mut rule, "onetoone", idx, seq);
                    container.children.push(rule);
                    stats.onetoone_moved += 1;
                }
                Err(reason) => stats
                    .skipped
                    .push(format!("1:1 NAT #{}: {reason}", idx + 1)),
            }
        }
    }
    if !npt.is_empty() {
        let container = ensure_path(out, &["OPNsense", "Firewall", "Filter", "npt"]);
        let mut seq = max_sequence(container);
        for (idx, legacy) in npt.iter().enumerate() {
            match npt_rule(legacy) {
                Ok(mut rule) => {
                    seq += 1;
                    finish_rule(&mut rule, "npt", idx, seq);
                    container.children.push(rule);
                    stats.npt_moved += 1;
                }
                Err(reason) => stats.skipped.push(format!("NPt #{}: {reason}", idx + 1)),
            }
        }
    }
    stats
}

/// Map one pfSense/legacy `<onetoone>` entry (see `MFP1_0_4.php`).
fn onetoone_rule(legacy: &XmlNode) -> Result<XmlNode, String> {
    let source = address_of(legacy.get_child("source"))
        .ok_or_else(|| "no internal (source) address".to_string())?;
    let destination = address_of(legacy.get_child("destination"))
        .ok_or_else(|| "no destination address".to_string())?;
    let mut external = text(legacy, "external");
    if external.is_empty() {
        return Err("no external address".to_string());
    }
    if !is_ip(&external) && !is_subnet(&external) {
        return Err(format!(
            "external address '{external}' is not an IP or network; OPNsense 1:1 NAT needs a fixed address"
        ));
    }
    if !external.contains('/') {
        if let Some((_, bits)) = source.split_once('/') {
            external = format!("{external}/{bits}");
        }
    }
    let kind = match text(legacy, "type").as_str() {
        "" => "binat".to_string(),
        other => other.to_string(),
    };

    let mut rule = XmlNode::new("rule");
    push(
        &mut rule,
        "enabled",
        if is_set(legacy, "disabled") { "0" } else { "1" },
    );
    push(
        &mut rule,
        "log",
        if is_set(legacy, "log") { "1" } else { "0" },
    );
    push(&mut rule, "interface", &text(legacy, "interface"));
    push(&mut rule, "type", &kind);
    push(&mut rule, "source_net", &source);
    push(
        &mut rule,
        "source_not",
        flag(legacy.get_child("source"), "not"),
    );
    push(&mut rule, "destination_net", &destination);
    push(
        &mut rule,
        "destination_not",
        flag(legacy.get_child("destination"), "not"),
    );
    push(&mut rule, "external", &external);
    let reflection = text(legacy, "natreflection");
    if !reflection.is_empty() {
        push(&mut rule, "natreflection", &reflection);
    }
    push(&mut rule, "description", &text(legacy, "descr"));
    Ok(rule)
}

/// Map one legacy `<npt>` entry (see `MFP1_0_3.php`).
fn npt_rule(legacy: &XmlNode) -> Result<XmlNode, String> {
    let source = legacy
        .get_child("source")
        .map(|s| text(s, "address"))
        .unwrap_or_default();
    if !is_ip(&source) && !is_subnet(&source) {
        return Err(format!("source prefix '{source}' is not an IP or network"));
    }
    let mut destination = legacy
        .get_child("destination")
        .map(|s| text(s, "address"))
        .unwrap_or_default();
    if !destination.is_empty() && !is_ip(&destination) && !is_subnet(&destination) {
        return Err(format!(
            "destination prefix '{destination}' is not an IP or network"
        ));
    }
    if !destination.is_empty() && !destination.contains('/') {
        let bits = format!("{source}/128")
            .split('/')
            .nth(1)
            .unwrap_or("128")
            .to_string();
        destination = format!("{destination}/{bits}");
    }

    let mut rule = XmlNode::new("rule");
    push(
        &mut rule,
        "enabled",
        if is_set(legacy, "disabled") { "0" } else { "1" },
    );
    push(
        &mut rule,
        "log",
        if is_set(legacy, "log") { "1" } else { "0" },
    );
    push(&mut rule, "interface", &text(legacy, "interface"));
    push(&mut rule, "source_net", &source);
    push(&mut rule, "destination_net", &destination);
    push(&mut rule, "description", &text(legacy, "descr"));
    Ok(rule)
}

/// Resolve a pfSense address block (`<source>`/`<destination>`) to a model value.
fn address_of(block: Option<&XmlNode>) -> Option<String> {
    let block = block?;
    if block.get_child("any").is_some() {
        return Some("any".to_string());
    }
    let address = text(block, "address");
    if !address.is_empty() {
        if is_ip(&address) {
            let bits = if address.contains(':') { 128 } else { 32 };
            return Some(format!("{address}/{bits}"));
        }
        return Some(address);
    }
    let network = text(block, "network");
    (!network.is_empty()).then_some(network)
}

fn finish_rule(rule: &mut XmlNode, kind: &str, idx: usize, seq: u64) {
    let seed = format!(
        "{kind}|{idx}|{}|{}",
        rule.get_text(&["source_net"]).unwrap_or_default(),
        rule.get_text(&["interface"]).unwrap_or_default()
    );
    rule.attributes
        .insert("uuid".to_string(), stable_uuid(&seed));
    // The model orders children as declared; sequence follows log.
    let pos = rule
        .children
        .iter()
        .position(|c| c.tag == "log")
        .map(|p| p + 1)
        .unwrap_or(0);
    let mut node = XmlNode::new("sequence");
    node.text = Some(seq.to_string());
    rule.children.insert(pos, node);
}

fn max_sequence(container: &XmlNode) -> u64 {
    container
        .get_children("rule")
        .iter()
        .filter_map(|r| r.get_text(&["sequence"]))
        .filter_map(|s| s.trim().parse::<u64>().ok())
        .max()
        .unwrap_or(0)
}

/// pfSense flag semantics: present means set, unless explicitly "0".
fn is_set(node: &XmlNode, tag: &str) -> bool {
    node.get_child(tag)
        .map(|c| c.text.as_deref().map(str::trim).unwrap_or("") != "0")
        .unwrap_or(false)
}

fn flag(block: Option<&XmlNode>, tag: &str) -> &'static str {
    if block.map(|b| is_set(b, tag)).unwrap_or(false) {
        "1"
    } else {
        "0"
    }
}

fn text(node: &XmlNode, tag: &str) -> String {
    node.get_text(&[tag])
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

fn is_ip(value: &str) -> bool {
    value.parse::<IpAddr>().is_ok()
}

fn is_subnet(value: &str) -> bool {
    let Some((ip, bits)) = value.split_once('/') else {
        return false;
    };
    let Ok(ip) = ip.parse::<IpAddr>() else {
        return false;
    };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    bits.parse::<u8>().map(|b| b <= max).unwrap_or(false)
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

/// Deterministic, RFC 4122-shaped UUID from a seed string.
fn stable_uuid(seed: &str) -> String {
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
    use xml_diff_core::parse;

    use super::move_legacy_nat_to_mvc;

    const BASELINE_26_7: &[u8] = br#"<opnsense><OPNsense><Firewall><Filter version="1.0.6"><rules/><snatrules/><npt/><onetoone/></Filter></Firewall></OPNsense></opnsense>"#;

    #[test]
    fn moves_onetoone_into_filter_model() {
        let baseline = parse(BASELINE_26_7).expect("parse");
        let mut out = parse(
            br#"<opnsense>
                <nat>
                  <outbound><mode>automatic</mode></outbound>
                  <onetoone><external>203.0.113.10</external><descr>web</descr><interface>wan</interface><ipprotocol>inet</ipprotocol><source><address>10.0.0.10</address></source><destination><any></any></destination></onetoone>
                  <onetoone><external>203.0.113.0/28</external><interface>opt2</interface><source><address>10.0.1.0/28</address><not/></source><destination><network>lan</network></destination><disabled></disabled><log/></onetoone>
                </nat>
                <OPNsense><Firewall><Filter version="1.0.6"><rules/><snatrules/><npt/><onetoone/></Filter></Firewall></OPNsense>
            </opnsense>"#,
        )
        .expect("parse");

        let stats = move_legacy_nat_to_mvc(&mut out, &baseline);
        assert_eq!(stats.onetoone_moved, 2);
        assert!(stats.skipped.is_empty());
        assert!(out
            .get_child("nat")
            .unwrap()
            .get_child("onetoone")
            .is_none());
        assert!(out
            .get_child("nat")
            .unwrap()
            .get_child("outbound")
            .is_some());

        let rules = out
            .get_child("OPNsense")
            .and_then(|n| n.get_child("Firewall"))
            .and_then(|n| n.get_child("Filter"))
            .and_then(|n| n.get_child("onetoone"))
            .unwrap()
            .get_children("rule");
        assert_eq!(rules.len(), 2);
        let first = rules[0];
        assert!(first.attributes.contains_key("uuid"));
        assert_eq!(first.get_text(&["enabled"]), Some("1"));
        assert_eq!(first.get_text(&["sequence"]), Some("1"));
        assert_eq!(first.get_text(&["type"]), Some("binat"));
        assert_eq!(first.get_text(&["source_net"]), Some("10.0.0.10/32"));
        assert_eq!(first.get_text(&["destination_net"]), Some("any"));
        assert_eq!(first.get_text(&["external"]), Some("203.0.113.10/32"));
        assert_eq!(first.get_text(&["description"]), Some("web"));
        assert!(first.get_child("ipprotocol").is_none());

        let second = rules[1];
        assert_eq!(second.get_text(&["enabled"]), Some("0"));
        assert_eq!(second.get_text(&["log"]), Some("1"));
        assert_eq!(second.get_text(&["sequence"]), Some("2"));
        assert_eq!(second.get_text(&["source_not"]), Some("1"));
        assert_eq!(second.get_text(&["destination_net"]), Some("lan"));
        assert_eq!(second.get_text(&["external"]), Some("203.0.113.0/28"));
        assert_ne!(first.attributes["uuid"], second.attributes["uuid"]);
    }

    #[test]
    fn skips_onetoone_with_dynamic_external_address() {
        let baseline = parse(BASELINE_26_7).expect("parse");
        let mut out = parse(
            br#"<opnsense><nat><onetoone><external>wanip</external><interface>wan</interface><source><network>opt3ip</network></source><destination><any/></destination></onetoone></nat></opnsense>"#,
        )
        .expect("parse");

        let stats = move_legacy_nat_to_mvc(&mut out, &baseline);
        assert_eq!(stats.onetoone_moved, 0);
        assert_eq!(stats.skipped.len(), 1);
        assert!(stats.skipped[0].contains("wanip"));
        // The legacy entry is removed either way: 26.7 ignores it.
        assert!(out
            .get_child("nat")
            .unwrap()
            .get_child("onetoone")
            .is_none());
    }

    #[test]
    fn moves_npt_and_completes_destination_prefix() {
        let baseline = parse(BASELINE_26_7).expect("parse");
        let mut out = parse(
            br#"<opnsense><nat><npt><interface>wan</interface><source><address>fd00:1::/64</address></source><destination><address>2001:db8:1::</address></destination><descr>v6</descr></npt></nat></opnsense>"#,
        )
        .expect("parse");

        let stats = move_legacy_nat_to_mvc(&mut out, &baseline);
        assert_eq!(stats.npt_moved, 1);
        let rule = out
            .get_child("OPNsense")
            .and_then(|n| n.get_child("Firewall"))
            .and_then(|n| n.get_child("Filter"))
            .and_then(|n| n.get_child("npt"))
            .and_then(|n| n.get_child("rule"))
            .unwrap();
        assert_eq!(rule.get_text(&["source_net"]), Some("fd00:1::/64"));
        assert_eq!(rule.get_text(&["destination_net"]), Some("2001:db8:1::/64"));
        assert_eq!(rule.get_text(&["enabled"]), Some("1"));
    }

    #[test]
    fn leaves_legacy_nat_for_old_filter_model() {
        let baseline = parse(
            br#"<opnsense><OPNsense><Firewall><Filter version="1.0.2"/></Firewall></OPNsense></opnsense>"#,
        )
        .expect("parse");
        let mut out = parse(
            br#"<opnsense><nat><onetoone><external>203.0.113.10</external><source><address>10.0.0.10</address></source><destination><any/></destination></onetoone></nat></opnsense>"#,
        )
        .expect("parse");

        let stats = move_legacy_nat_to_mvc(&mut out, &baseline);
        assert_eq!(stats, Default::default());
        assert!(out
            .get_child("nat")
            .unwrap()
            .get_child("onetoone")
            .is_some());
    }
}
