use std::collections::BTreeSet;

use xml_diff_core::XmlNode;

/// Converts pfSense aliases to OPNsense format.
///
/// pfSense uses a flat `<aliases><alias>...</alias></aliases>` structure,
/// whereas OPNsense nests them under `<OPNsense><Firewall><Alias><aliases>`.
/// Alias names are compared case-insensitively to prevent duplicates.
pub fn to_opnsense(out: &mut XmlNode, source: &XmlNode, target: &XmlNode) {
    let Some(src_aliases) = source.get_child("aliases") else {
        return;
    };
    let src_items = src_aliases
        .children
        .iter()
        .filter(|c| c.tag == "alias")
        .cloned()
        .collect::<Vec<_>>();
    let dst_aliases = ensure_opnsense_aliases_node(out);
    dst_aliases.children.retain(|c| c.tag != "alias");
    let mut existing = collect_alias_names(dst_aliases);
    for (idx, alias) in src_items.into_iter().enumerate() {
        if should_insert_alias(&alias, &mut existing) {
            dst_aliases.children.push(pf_alias_to_opnsense(&alias, idx));
        }
    }

    let _ = target;
}

/// Map one pfSense `<alias>` onto OPNsense's `Firewall/Alias` model.
///
/// Mirrors OPNsense's own legacy migration (`Firewall/Migrations/M1_0_0.php`),
/// which never runs on import because the baseline's Alias model is already
/// at a newer version:
/// - `descr` -> `description` (unsupported characters replaced, max 255 chars)
/// - `url` (single) / `aliasurl` (repeated) / `address` (space-separated)
///   -> `content` (newline-separated)
/// - `url_ports` / `urltable_ports` are unsupported and become an empty `port`
///   alias (with a warning), as OPNsense does
/// - `proto`, `updatefreq` are carried over; `enabled` is set to `1`
///
/// Per-entry descriptions (pfSense `detail`) have no OPNsense equivalent and
/// are dropped. Aliases that already use the OPNsense layout are kept as-is.
fn pf_alias_to_opnsense(alias: &XmlNode, idx: usize) -> XmlNode {
    if alias.get_child("content").is_some() {
        let mut kept = alias.clone();
        kept.attributes
            .entry("uuid".to_string())
            .or_insert_with(|| alias_uuid(alias, idx));
        return kept;
    }

    let text = |tag: &str| {
        alias
            .get_text(&[tag])
            .map(str::trim)
            .unwrap_or("")
            .to_string()
    };
    let name = text("name");
    let mut alias_type = text("type");
    let mut content = String::new();
    if alias_type == "url_ports" || alias_type == "urltable_ports" {
        eprintln!(
            "warning: alias '{name}' has type '{alias_type}', which OPNsense does not support; imported as an empty port alias"
        );
        alias_type = "port".to_string();
    } else if !text("url").is_empty() {
        content = text("url");
    } else if !alias.get_children("aliasurl").is_empty() {
        content = alias
            .get_children("aliasurl")
            .iter()
            .filter_map(|n| n.text.as_deref().map(str::trim))
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
    } else {
        content = text("address")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join("\n");
    }

    let mut node = XmlNode::new("alias");
    node.attributes
        .insert("uuid".to_string(), alias_uuid(alias, idx));
    push_text(&mut node, "enabled", "1");
    push_text(&mut node, "name", &name);
    push_text(&mut node, "type", &alias_type);
    let proto = text("proto");
    if !proto.is_empty() {
        push_text(&mut node, "proto", &proto);
    }
    let updatefreq = text("updatefreq");
    if !updatefreq.is_empty() {
        push_text(&mut node, "updatefreq", &updatefreq);
    }
    push_text(&mut node, "content", &content);
    push_text(
        &mut node,
        "description",
        &sanitize_description(&text("descr")),
    );
    node
}

/// Replace characters OPNsense's alias description field rejects, as the
/// OPNsense migration does, and cap the length at 255 characters.
fn sanitize_description(descr: &str) -> String {
    descr
        .chars()
        .map(|c| {
            let allowed = c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '\t' | '\n' | '\x0b' | '\x0c' | '\r' | ' ' | '.' | '-' | ',' | '_'
                )
                || ('\u{00A0}'..='\u{FFFF}').contains(&c);
            if allowed {
                c
            } else {
                ' '
            }
        })
        .take(255)
        .collect()
}

fn push_text(parent: &mut XmlNode, tag: &str, value: &str) {
    let mut child = XmlNode::new(tag);
    child.text = Some(value.to_string());
    parent.children.push(child);
}

/// Deterministic, RFC 4122-shaped UUID derived from the alias name and position.
fn alias_uuid(alias: &XmlNode, idx: usize) -> String {
    let seed = format!(
        "alias|{}|{}",
        alias.get_text(&["name"]).unwrap_or_default(),
        idx
    );
    // Two FNV-1a passes with different offsets give 128 bits.
    let fnv = |offset: u64| {
        seed.bytes().fold(offset, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
        })
    };
    let hi = fnv(0xcbf2_9ce4_8422_2325);
    let lo = fnv(0x6c62_272e_07bb_0142);
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&hi.to_be_bytes());
    bytes[8..].copy_from_slice(&lo.to_be_bytes());
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

/// Converts OPNsense aliases to pfSense format.
///
/// The reverse of `to_opnsense`: OPNsense's nested `<OPNsense><Firewall><Alias><aliases>`
/// becomes pfSense's flat `<aliases>` structure.
/// Case-insensitive deduplication is applied.
pub fn to_pfsense(out: &mut XmlNode, source: &XmlNode, target: &XmlNode) {
    let Some(src_aliases) = source
        .get_child("OPNsense")
        .and_then(|opn| opn.get_child("Firewall"))
        .and_then(|fw| fw.get_child("Alias"))
        .and_then(|alias| alias.get_child("aliases"))
    else {
        return;
    };
    let src_items = src_aliases
        .children
        .iter()
        .filter(|c| c.tag == "alias")
        .cloned()
        .collect::<Vec<_>>();
    let dst_aliases = ensure_child_mut(out, "aliases");
    dst_aliases.children.retain(|c| c.tag != "alias");
    let mut existing = collect_alias_names(dst_aliases);
    for alias in src_items {
        if should_insert_alias(&alias, &mut existing) {
            dst_aliases.children.push(alias);
        }
    }

    let _ = target;
}

/// Determines whether an alias should be inserted, based on name uniqueness.
///
/// Alias names are compared case-insensitively; "Mullvad_Hosts" and "mullvad_hosts"
/// are considered duplicates.
fn should_insert_alias(alias: &XmlNode, existing: &mut BTreeSet<String>) -> bool {
    let Some(name) = alias_name(alias) else {
        return true;
    };
    existing.insert(name)
}

/// Extracts the name field from an alias node, normalising to lowercase.
/// Returns `None` if the name is empty or missing.
fn alias_name(alias: &XmlNode) -> Option<String> {
    let value = alias.get_text(&["name"])?.trim().to_ascii_lowercase();
    if value.is_empty() {
        return None;
    }
    Some(value)
}

/// Collects all alias names from an aliases container node.
fn collect_alias_names(aliases_node: &XmlNode) -> BTreeSet<String> {
    aliases_node
        .children
        .iter()
        .filter(|c| c.tag == "alias")
        .filter_map(alias_name)
        .collect()
}

/// Ensures the OPNsense nested structure exists: `OPNsense > Firewall > Alias > aliases`.
fn ensure_opnsense_aliases_node(out: &mut XmlNode) -> &mut XmlNode {
    let opn = ensure_child_mut(out, "OPNsense");
    let fw = ensure_child_mut(opn, "Firewall");
    let alias = ensure_child_mut(fw, "Alias");
    ensure_child_mut(alias, "aliases")
}

/// Gets or creates a child element with the given tag name.
fn ensure_child_mut<'a>(parent: &'a mut XmlNode, tag: &str) -> &'a mut XmlNode {
    if let Some(idx) = parent.children.iter().position(|c| c.tag == tag) {
        return &mut parent.children[idx];
    }
    parent.children.push(XmlNode::new(tag));
    let last = parent.children.len() - 1;
    &mut parent.children[last]
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::{to_opnsense, to_pfsense};

    #[test]
    fn transfers_pfsense_aliases_into_opnsense_nested_aliases() {
        let source = parse(
            br#"<pfsense><aliases><alias><name>mullvad_hosts</name></alias></aliases></pfsense>"#,
        )
        .expect("source parse");
        let target = parse(br#"<opnsense><system/></opnsense>"#).expect("target parse");
        let mut out = target.clone();

        to_opnsense(&mut out, &source, &target);

        let aliases = out
            .get_child("OPNsense")
            .and_then(|opn| opn.get_child("Firewall"))
            .and_then(|fw| fw.get_child("Alias"))
            .and_then(|alias| alias.get_child("aliases"))
            .expect("nested aliases");
        assert_eq!(aliases.get_children("alias").len(), 1);
    }

    #[test]
    fn maps_pfsense_alias_fields_to_opnsense_model() {
        let source = parse(
            br#"<pfsense><aliases>
                <alias><name>web_hosts</name><type>host</type><address>10.0.0.1 10.0.0.2  web.example.com</address><descr>Web &amp; app (prod)</descr><detail>a||b||c</detail></alias>
                <alias><name>blocklist</name><type>urltable</type><url>https://example.com/list.txt</url><updatefreq>2</updatefreq><descr></descr></alias>
                <alias><name>feeds</name><type>url</type><aliasurl>https://a.example/x</aliasurl><aliasurl>https://b.example/y</aliasurl></alias>
                <alias><name>uport</name><type>urltable_ports</type><url>https://example.com/ports</url></alias>
            </aliases></pfsense>"#,
        )
        .expect("source parse");
        let target = parse(br#"<opnsense><system/></opnsense>"#).expect("target parse");
        let mut out = target.clone();

        to_opnsense(&mut out, &source, &target);

        let aliases = out
            .get_child("OPNsense")
            .and_then(|opn| opn.get_child("Firewall"))
            .and_then(|fw| fw.get_child("Alias"))
            .and_then(|alias| alias.get_child("aliases"))
            .expect("nested aliases");
        let items = aliases.get_children("alias");
        assert_eq!(items.len(), 4);

        let web = items[0];
        assert!(web.attributes.contains_key("uuid"));
        assert_eq!(web.get_text(&["enabled"]), Some("1"));
        assert_eq!(web.get_text(&["type"]), Some("host"));
        assert_eq!(
            web.get_text(&["content"]),
            Some("10.0.0.1\n10.0.0.2\nweb.example.com")
        );
        assert_eq!(web.get_text(&["description"]), Some("Web   app  prod "));
        assert!(web.get_child("address").is_none());
        assert!(web.get_child("descr").is_none());
        assert!(web.get_child("detail").is_none());

        assert_eq!(
            items[1].get_text(&["content"]),
            Some("https://example.com/list.txt")
        );
        assert_eq!(items[1].get_text(&["updatefreq"]), Some("2"));
        assert_eq!(
            items[2].get_text(&["content"]),
            Some("https://a.example/x\nhttps://b.example/y")
        );
        assert_eq!(items[3].get_text(&["type"]), Some("port"));
        assert_eq!(items[3].get_text(&["content"]), Some(""));

        let uuids: std::collections::BTreeSet<_> =
            items.iter().map(|a| a.attributes["uuid"].clone()).collect();
        assert_eq!(uuids.len(), 4, "uuids must be unique");
    }

    #[test]
    fn does_not_duplicate_existing_alias_name() {
        let source = parse(
            br#"<pfsense><aliases><alias><name>mullvad_hosts</name></alias></aliases></pfsense>"#,
        )
        .expect("source parse");
        let target = parse(
            br#"<opnsense><OPNsense><Firewall><Alias><aliases><alias><name>mullvad_hosts</name></alias></aliases></Alias></Firewall></OPNsense></opnsense>"#,
        )
        .expect("target parse");
        let mut out = target.clone();

        to_opnsense(&mut out, &source, &target);

        let aliases = out
            .get_child("OPNsense")
            .and_then(|opn| opn.get_child("Firewall"))
            .and_then(|fw| fw.get_child("Alias"))
            .and_then(|alias| alias.get_child("aliases"))
            .expect("nested aliases");
        assert_eq!(aliases.get_children("alias").len(), 1);
    }

    #[test]
    fn transfers_opnsense_nested_aliases_to_pfsense_top_level() {
        let source = parse(
            br#"<opnsense><OPNsense><Firewall><Alias><aliases><alias><name>remote_sites</name></alias></aliases></Alias></Firewall></OPNsense></opnsense>"#,
        )
        .expect("source parse");
        let target = parse(br#"<pfsense><system/></pfsense>"#).expect("target parse");
        let mut out = target.clone();

        to_pfsense(&mut out, &source, &target);

        let aliases = out.get_child("aliases").expect("top-level aliases");
        assert_eq!(aliases.get_children("alias").len(), 1);
    }
}
