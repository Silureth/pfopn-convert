//! Small helpers shared by the transforms that write OPNsense MVC models.

use xml_diff_core::XmlNode;

use crate::transform::version::inherit_model_attrs;

/// Trimmed text of a direct child, or "" when missing.
pub(crate) fn text(node: &XmlNode, tag: &str) -> String {
    node.get_text(&[tag])
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

pub(crate) fn bool01(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}

/// Append a text child.
pub(crate) fn push(parent: &mut XmlNode, tag: &str, value: &str) {
    let mut child = XmlNode::new(tag);
    child.text = Some(value.to_string());
    parent.children.push(child);
}

/// Walk `path` below `root`, creating missing elements.
pub(crate) fn ensure_path<'a>(root: &'a mut XmlNode, path: &[&str]) -> &'a mut XmlNode {
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

/// Set the text of the element at `path` below `root`, creating it if needed.
pub(crate) fn set_path(root: &mut XmlNode, path: &[&str], value: &str) {
    let node = ensure_path(root, path);
    node.children.clear();
    node.text = Some(value.to_string());
}

pub(crate) fn node_at<'a>(root: &'a XmlNode, path: &[&str]) -> Option<&'a XmlNode> {
    path.iter().try_fold(root, |node, tag| node.get_child(tag))
}

/// The output's copy of an MVC model at `path`, but only when the baseline has
/// that model (so it exists on the target, at a known version). The output node
/// is created if missing and inherits the baseline's `version` attribute, so
/// OPNsense does not replay old migrations over the converted values.
pub(crate) fn model_mut<'a>(
    out: &'a mut XmlNode,
    baseline: &XmlNode,
    path: &[&str],
) -> Option<&'a mut XmlNode> {
    let baseline_model = node_at(baseline, path)?;
    let model = ensure_path(out, path);
    inherit_model_attrs(model, Some(baseline_model));
    Some(model)
}

/// Decode standard base64 (as pfSense stores package textareas). Whitespace is
/// ignored. Returns `None` for invalid input or non-UTF-8 content.
pub(crate) fn decode_base64(input: &str) -> Option<String> {
    let mut bits: u32 = 0;
    let mut nbits = 0;
    let mut bytes = Vec::new();
    for c in input.chars().filter(|c| !c.is_whitespace()) {
        if c == '=' {
            break;
        }
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return None,
        };
        bits = (bits << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            bytes.push((bits >> nbits) as u8);
            bits &= (1 << nbits) - 1;
        }
    }
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::decode_base64;

    #[test]
    fn decodes_base64() {
        assert_eq!(
            decode_base64("aGVsbG8gd29ybGQ=").as_deref(),
            Some("hello world")
        );
        assert_eq!(decode_base64("YWI=\n").as_deref(), Some("ab"));
        assert_eq!(decode_base64("").as_deref(), Some(""));
        assert!(decode_base64("not*base64").is_none());
    }
}
