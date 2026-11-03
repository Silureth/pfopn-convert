use xml_diff_core::XmlNode;

/// Compare a dotted version string (e.g. "1.0.1") against a minimum.
///
/// Missing or non-numeric components count as `0`.
pub(crate) fn version_at_least(version: &str, min: &[u32]) -> bool {
    let parts: Vec<u32> = version
        .trim()
        .split('.')
        .map(|p| p.parse().unwrap_or(0))
        .collect();
    for (i, want) in min.iter().enumerate() {
        let have = parts.get(i).copied().unwrap_or(0);
        if have != *want {
            return have > *want;
        }
    }
    true
}

/// Return the `version` attribute of the node at `path` (tags from the root).
pub(crate) fn model_version<'a>(root: &'a XmlNode, path: &[&str]) -> Option<&'a str> {
    let mut node = root;
    for tag in path {
        node = node.get_child(tag)?;
    }
    node.attributes.get("version").map(String::as_str)
}

/// Give a generated MVC section the baseline's model attributes (`version`,
/// `persisted_at`, `description`) when it has no `version` of its own.
///
/// OPNsense runs every model migration newer than a section's `version`
/// attribute at boot, and a missing attribute counts as 0.0.0. Sections the
/// converter builds in the target's current format must therefore carry the
/// baseline's version, or old migrations re-run against them (for IPsec this
/// re-imports legacy pre-shared keys on top of the converted ones).
pub(crate) fn inherit_model_attrs(node: &mut XmlNode, baseline: Option<&XmlNode>) {
    if node.attributes.contains_key("version") {
        return;
    }
    let Some(baseline) = baseline else {
        return;
    };
    for (key, value) in &baseline.attributes {
        node.attributes
            .entry(key.clone())
            .or_insert_with(|| value.clone());
    }
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::{inherit_model_attrs, version_at_least};

    #[test]
    fn inherits_baseline_attrs_only_without_own_version() {
        let baseline = parse(br#"<IPsec version="1.0.6" persisted_at="1"/>"#).expect("parse");
        let mut generated = parse(br#"<IPsec><general/></IPsec>"#).expect("parse");
        inherit_model_attrs(&mut generated, Some(&baseline));
        assert_eq!(
            generated.attributes.get("version").map(String::as_str),
            Some("1.0.6")
        );

        let mut versioned = parse(br#"<IPsec version="1.0.2"/>"#).expect("parse");
        inherit_model_attrs(&mut versioned, Some(&baseline));
        assert_eq!(
            versioned.attributes.get("version").map(String::as_str),
            Some("1.0.2")
        );
        assert!(!versioned.attributes.contains_key("persisted_at"));
    }

    #[test]
    fn compares_dotted_versions() {
        assert!(version_at_least("1.0.1", &[1, 0, 1]));
        assert!(version_at_least("1.0.6", &[1, 0, 4]));
        assert!(version_at_least("1.1", &[1, 0, 4]));
        assert!(!version_at_least("1.0.0", &[1, 0, 1]));
        assert!(!version_at_least("", &[1, 0, 1]));
    }
}
