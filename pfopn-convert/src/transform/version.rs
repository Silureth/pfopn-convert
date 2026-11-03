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

#[cfg(test)]
mod tests {
    use super::version_at_least;

    #[test]
    fn compares_dotted_versions() {
        assert!(version_at_least("1.0.1", &[1, 0, 1]));
        assert!(version_at_least("1.0.6", &[1, 0, 4]));
        assert!(version_at_least("1.1", &[1, 0, 4]));
        assert!(!version_at_least("1.0.0", &[1, 0, 1]));
        assert!(!version_at_least("", &[1, 0, 1]));
    }
}
