use xml_diff_core::XmlNode;

/// Transform certificate and CA entries for OPNsense output.
///
/// OPNsense requires `uuid` attributes on `<ca>` and `<cert>` elements.
/// pfSense does not use them. This generates deterministic UUIDs for any
/// entries that are missing one, seeded from the refid or description so
/// the same input always produces the same UUID.
pub fn to_opnsense(out: &mut XmlNode, source: &XmlNode, destination_baseline: &XmlNode) {
    keep_webgui_certificate(out, source, destination_baseline);
    normalize_uuid_attrs(out, "ca");
    normalize_uuid_attrs(out, "cert");
}

/// The merged `system/webgui/ssl-certref` comes from the source, but certificates
/// are only carried over when a VPN references them. When the web GUI cert is
/// missing from the output, OPNsense generates a new self-signed one at boot
/// (browsers then see a new certificate). Copy the source's cert (and its CA)
/// into the output; if the source does not have it either, point the web GUI
/// back at the baseline's certificate.
fn keep_webgui_certificate(out: &mut XmlNode, source: &XmlNode, baseline: &XmlNode) {
    let Some(certref) = out
        .get_text(&["system", "webgui", "ssl-certref"])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    else {
        return;
    };
    if find_by_refid(out, "cert", &certref).is_some() {
        return;
    }
    if let Some(cert) = find_by_refid(source, "cert", &certref).cloned() {
        if let Some(caref) = cert
            .get_text(&["caref"])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            if find_by_refid(out, "ca", &caref).is_none() {
                if let Some(ca) = find_by_refid(source, "ca", &caref).cloned() {
                    insert_after_last(out, ca);
                }
            }
        }
        insert_after_last(out, cert);
        return;
    }
    if let Some(base_ref) = baseline
        .get_text(&["system", "webgui", "ssl-certref"])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        if let Some(node) = out
            .children
            .iter_mut()
            .find(|c| c.tag == "system")
            .and_then(|s| s.children.iter_mut().find(|c| c.tag == "webgui"))
            .and_then(|w| w.children.iter_mut().find(|c| c.tag == "ssl-certref"))
        {
            node.text = Some(base_ref);
        }
    }
}

fn find_by_refid<'a>(root: &'a XmlNode, tag: &str, refid: &str) -> Option<&'a XmlNode> {
    root.children
        .iter()
        .filter(|c| c.tag == tag)
        .find(|c| c.get_text(&["refid"]).map(str::trim) == Some(refid))
}

/// Insert `node` after the last top-level sibling with the same tag (or at the end).
fn insert_after_last(root: &mut XmlNode, node: XmlNode) {
    match root.children.iter().rposition(|c| c.tag == node.tag) {
        Some(idx) => root.children.insert(idx + 1, node),
        None => root.children.push(node),
    }
}

/// Transform certificate and CA entries for pfSense output.
///
/// pfSense does not use `uuid` attributes on `<ca>` and `<cert>` elements,
/// so we strip them to keep the output clean.
pub fn to_pfsense(out: &mut XmlNode, _source: &XmlNode, _destination_baseline: &XmlNode) {
    strip_uuid_attrs(out, "ca");
    strip_uuid_attrs(out, "cert");
}

/// Ensure every `<{tag}>` child of `root` has a `uuid` attribute.
///
/// Nodes that already have a uuid are left untouched. For nodes without one,
/// a deterministic UUID is generated using the node's `<refid>` as the primary
/// seed, falling back to `<descr>`, and finally to `"{tag}:{ordinal}"` if
/// neither is present. The ordinal counter tracks position so that nodes with
/// identical seeds still get unique UUIDs.
fn normalize_uuid_attrs(root: &mut XmlNode, tag: &str) {
    let mut ordinal = 0usize;
    for node in root.children.iter_mut().filter(|n| n.tag == tag) {
        // Skip nodes that already carry a uuid.
        if node.attributes.contains_key("uuid") {
            ordinal += 1;
            continue;
        }
        // Build a seed string: prefer refid, then descr, then a positional fallback.
        let seed = node
            .get_text(&["refid"])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                node.get_text(&["descr"])
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| format!("{tag}:{ordinal}"));
        node.attributes
            .insert("uuid".to_string(), stable_uuid(seed.as_bytes(), ordinal));
        ordinal += 1;
    }
}

/// Remove the `uuid` attribute from every `<{tag}>` child of `root`.
fn strip_uuid_attrs(root: &mut XmlNode, tag: &str) {
    for node in root.children.iter_mut().filter(|n| n.tag == tag) {
        node.attributes.remove("uuid");
    }
}

/// Generate a deterministic UUID-formatted string from a byte seed and index.
///
/// The first segment is derived from a CRC-32 of the seed XORed with the index,
/// giving each entry a unique but reproducible identifier. The trailing segment
/// encodes the 1-based index. Middle segments are zeroed since we only need
/// uniqueness within a single config file, not RFC 4122 compliance.
fn stable_uuid(seed: &[u8], idx: usize) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        crc32(seed) ^ (idx as u32),
        0,
        0,
        0,
        (idx as u64) + 1
    )
}

/// Compute the CRC-32 (ISO 3309 / ITU-T V.42) checksum of `input`.
///
/// Uses the standard polynomial 0xEDB88320 (bit-reversed representation).
fn crc32(input: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for b in input {
        crc ^= *b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg(); // all-ones if LSB set, else all-zeros
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc // final inversion
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::{to_opnsense, to_pfsense};

    #[test]
    fn carries_webgui_certificate_and_ca_over() {
        let source = parse(
            br#"<pfsense><ca><refid>ca1</refid><descr>CA</descr></ca><cert><refid>pfcert</refid><descr>webConfigurator default</descr><caref>ca1</caref><crt>AAA</crt><prv>BBB</prv></cert></pfsense>"#,
        )
        .expect("parse");
        let baseline = parse(
            br#"<opnsense><system><webgui><ssl-certref>opncert</ssl-certref></webgui></system><cert uuid="u"><refid>opncert</refid></cert></opnsense>"#,
        )
        .expect("parse");
        let mut out = parse(
            br#"<opnsense><system><webgui><ssl-certref>pfcert</ssl-certref></webgui></system><cert uuid="u"><refid>opncert</refid></cert></opnsense>"#,
        )
        .expect("parse");
        to_opnsense(&mut out, &source, &baseline);
        let refids: Vec<_> = out
            .children
            .iter()
            .filter(|c| c.tag == "cert" || c.tag == "ca")
            .map(|c| format!("{}:{}", c.tag, c.get_text(&["refid"]).unwrap()))
            .collect();
        assert!(refids.contains(&"cert:pfcert".to_string()));
        assert!(refids.contains(&"ca:ca1".to_string()));
        assert_eq!(
            out.get_text(&["system", "webgui", "ssl-certref"]),
            Some("pfcert")
        );
    }

    #[test]
    fn falls_back_to_baseline_webgui_certificate() {
        let source = parse(br#"<pfsense/>"#).expect("parse");
        let baseline = parse(
            br#"<opnsense><system><webgui><ssl-certref>opncert</ssl-certref></webgui></system></opnsense>"#,
        )
        .expect("parse");
        let mut out = parse(
            br#"<opnsense><system><webgui><ssl-certref>gone</ssl-certref></webgui></system><cert><refid>opncert</refid></cert></opnsense>"#,
        )
        .expect("parse");
        to_opnsense(&mut out, &source, &baseline);
        assert_eq!(
            out.get_text(&["system", "webgui", "ssl-certref"]),
            Some("opncert")
        );
    }

    #[test]
    fn adds_uuid_to_ca_and_cert_for_opnsense() {
        let source = parse(br#"<pfsense><system/></pfsense>"#).expect("parse");
        let baseline = parse(br#"<opnsense><system/></opnsense>"#).expect("parse");
        let mut out = parse(
            br#"<opnsense><ca><refid>ca1</refid><descr>CA1</descr></ca><cert><refid>cert1</refid><descr>CERT1</descr></cert></opnsense>"#,
        )
        .expect("parse");

        to_opnsense(&mut out, &source, &baseline);
        let ca = out.children.iter().find(|n| n.tag == "ca").expect("ca");
        let cert = out.children.iter().find(|n| n.tag == "cert").expect("cert");
        assert!(ca.attributes.contains_key("uuid"));
        assert!(cert.attributes.contains_key("uuid"));
    }

    #[test]
    fn strips_uuid_from_ca_and_cert_for_pfsense() {
        let source = parse(br#"<opnsense><system/></opnsense>"#).expect("parse");
        let baseline = parse(br#"<pfsense><system/></pfsense>"#).expect("parse");
        let mut out = parse(
            br#"<pfsense><ca uuid="abc"><refid>ca1</refid></ca><cert uuid="def"><refid>cert1</refid></cert></pfsense>"#,
        )
        .expect("parse");

        to_pfsense(&mut out, &source, &baseline);
        let ca = out.children.iter().find(|n| n.tag == "ca").expect("ca");
        let cert = out.children.iter().find(|n| n.tag == "cert").expect("cert");
        assert!(!ca.attributes.contains_key("uuid"));
        assert!(!cert.attributes.contains_key("uuid"));
    }
}
