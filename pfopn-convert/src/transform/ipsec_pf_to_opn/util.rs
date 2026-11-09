use xml_diff_core::XmlNode;

/// Convert pfSense's `<disabled>` field to OPNsense's `<enabled>` field.
///
/// pfSense uses presence of `<disabled>` to indicate disabled state.
/// OPNsense uses `<enabled>` with "1" for enabled, "0" for disabled.
///
/// Returns "1" if the node has no `<disabled>` child (enabled in pfSense).
/// Returns "0" if the node has a `<disabled>` child (disabled in pfSense),
/// including pfSense's usual empty `<disabled></disabled>` form.
pub(super) fn enabled_from_disabled(node: &XmlNode) -> &'static str {
    if crate::transform::rule_flags::pf_flag_is_set(node, "disabled") {
        "0"
    } else {
        "1"
    }
}

/// Extract trimmed text from a child element, or return a default value.
///
/// Helper to safely access XML text content with a fallback.
pub(super) fn text_or<'a>(node: &'a XmlNode, child: &str, default: &'a str) -> &'a str {
    node.get_text(&[child]).map(str::trim).unwrap_or(default)
}

/// Create and append a text-only child element to a parent node.
///
/// Helper to reduce boilerplate when building XML structures.
pub(super) fn push_text_child(parent: &mut XmlNode, tag: &str, value: &str) {
    let mut child = XmlNode::new(tag);
    child.text = Some(value.to_string());
    parent.children.push(child);
}

/// Generate a deterministic UUID v4 from a prefix, index, and seed string.
///
/// Creates stable UUIDs for IPsec config elements so that the same pfSense
/// configuration always produces the same OPNsense UUIDs. This is important
/// for:
/// - Idempotent conversions (converting twice produces identical output)
/// - Linking related elements (Connection → local/remote/child via UUID references)
/// - Diff stability (unchanged tunnels keep the same UUIDs)
///
/// The algorithm:
/// 1. Mix prefix and seed bytes into a 16-byte accumulator with position-dependent rotation
/// 2. Fold in the index to ensure different elements with the same seed get unique UUIDs
/// 3. Set UUID version 4 bits and RFC 4122 variant bits for format compliance
///
/// # Example
/// ```ignore
/// stable_uuid("conn", 0, "1") // -> "abc12345-6789-4...-8...-..."
/// stable_uuid("conn", 0, "1") // -> same UUID (deterministic)
/// stable_uuid("conn", 1, "1") // -> different UUID (different index)
/// stable_uuid("local", 0, "1") // -> different UUID (different prefix)
/// ```
pub(super) fn stable_uuid(prefix: &str, idx: usize, seed: &str) -> String {
    let mut bytes = [0u8; 16];
    // Mix prefix and seed bytes into the accumulator with position-dependent rotation
    for (i, b) in prefix.bytes().chain(seed.bytes()).enumerate() {
        bytes[i % 16] = bytes[i % 16].wrapping_add(b).rotate_left((i % 7) as u32);
    }
    // Fold in the index so that elements with identical seeds but different positions
    // still produce distinct UUIDs
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = b.wrapping_add(((idx + i) as u8).rotate_left((idx % 5) as u32));
    }
    // Set UUID version 4 nibble (0x40) and RFC 4122 variant bits (0x80-0xBF)
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10xx
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}
