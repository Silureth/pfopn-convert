//! OpenVPN configuration conversion between pfSense and OPNsense.
//!
//! This module handles bidirectional conversion of OpenVPN server and client
//! configurations, which have significantly different structures between the
//! two platforms.
//!
//! ## Platform Differences
//!
//! **pfSense OpenVPN structure:**
//! - Config lives in `<openvpn>` at the root level
//! - Uses `<openvpn-server>` for server instances
//! - Uses `<openvpn-client>` for client instances
//! - Each instance is a separate XML element with its own configuration
//! - Uses `<vpnid>` to uniquely identify instances
//! - Interface references use "ovpnsN" naming (e.g., ovpns1, ovpns2)
//!
//! **OPNsense OpenVPN structure:**
//! - Config lives in `<OPNsense><OpenVPN><Instances>`
//! - Uses `<Instance>` elements for both servers and clients
//! - Distinguished by `<role>` field: "server" or "client"
//! - Each instance has a UUID attribute for identification
//! - More structured with nested containers
//! - Interface references also use "ovpnsN" naming
//!
//! ## pfSense → OPNsense
//!
//! OPNsense 26.7 only runs legacy `<openvpn-server>`/`<openvpn-client>`
//! entries when the os-openvpn-legacy plugin is installed. Servers and
//! client-specific overrides are therefore converted into the OPNsense model
//! (`Instances`, `StaticKeys`, `Overwrites`; see `pf_to_opn`), and removed from
//! the legacy `<openvpn>` section so nothing runs twice. What cannot be
//! converted (clients, shared-key servers) stays there, with a warning.
//!
//! ## Round-Trip Preservation
//!
//! OPNsense → pfSense conversions store each instance's UUID in
//! `<opnsense_instance_uuid>`, which is reused when converting back.

use xml_diff_core::XmlNode;

mod common;
mod opn_to_pf;
mod pf_to_opn;

#[cfg(test)]
mod tests;

/// Convert OpenVPN configuration to OPNsense format.
///
/// - Source already in OPNsense's model (`<OPNsense><OpenVPN><Instances>`):
///   copied as-is; the legacy `<openvpn>` section is emptied.
/// - pfSense source: servers and client-specific overrides are mapped onto
///   OPNsense's model (see [`pf_to_opn::map_pfsense_openvpn`]); converted
///   entries are removed from the legacy `<openvpn>` section, the rest
///   (clients, shared-key servers) stays there. Warnings are printed for
///   settings that could not be converted.
pub fn to_opnsense(out: &mut XmlNode, source: &XmlNode, _target: &XmlNode) {
    // Source already in OPNsense's model (round trip): use its instances as-is.
    if let Some(instances) = common::source_opnsense_instances(source) {
        if instances.children.is_empty() {
            return;
        }
        let opn = common::ensure_child_mut(out, "OPNsense");
        let openvpn = common::ensure_child_mut(opn, "OpenVPN");
        common::upsert_child(openvpn, instances);
        common::normalize_top_level_openvpn_for_opnsense(out);
        common::dedupe_top_level_openvpn(out);
        return;
    }

    let mapping = pf_to_opn::map_pfsense_openvpn(source);
    for warning in &mapping.warnings {
        eprintln!("warning: {warning}");
    }
    if mapping.instances.children.is_empty() && mapping.overwrites.is_empty() {
        if let Some(legacy) = common::source_pfsense_servers(source) {
            // Nothing convertible (e.g. only clients): keep the legacy section.
            common::upsert_child(out, legacy);
            common::dedupe_top_level_openvpn(out);
        }
        return;
    }
    eprintln!(
        "info: converted {} OpenVPN server(s) to OPNsense instances ({} TLS key(s), {} client override(s))",
        mapping.instances.children.len(),
        mapping.static_keys.len(),
        mapping.overwrites.len()
    );

    let opn = common::ensure_child_mut(out, "OPNsense");
    let openvpn = common::ensure_child_mut(opn, "OpenVPN");
    if !mapping.instances.children.is_empty() {
        common::upsert_child(openvpn, mapping.instances.clone());
    }
    for (container, items) in [
        ("StaticKeys", mapping.static_keys.clone()),
        ("Overwrites", mapping.overwrites.clone()),
    ] {
        if items.is_empty() {
            continue;
        }
        let node = common::ensure_child_mut(openvpn, container);
        for item in items {
            let uuid = item.attributes.get("uuid").cloned();
            node.children
                .retain(|c| uuid.is_none() || c.attributes.get("uuid") != uuid.as_ref());
            node.children.push(item);
        }
    }

    // Keep only what was not converted in the legacy <openvpn> section, so
    // nothing runs twice if the os-openvpn-legacy plugin is installed later.
    let mut legacy = source
        .get_child("openvpn")
        .cloned()
        .unwrap_or_else(|| XmlNode::new("openvpn"));
    legacy.children.retain(|c| match c.tag.as_str() {
        "openvpn-server" => {
            let vpnid = c.get_text(&["vpnid"]).map(str::trim).unwrap_or("1");
            !mapping.converted_vpnids.iter().any(|v| v == vpnid)
        }
        "openvpn-csc" => !mapping.csc_converted,
        _ => true,
    });
    common::upsert_child(out, legacy);
    common::dedupe_top_level_openvpn(out);
}

/// Convert OpenVPN configuration to pfSense format.
///
/// Handles two input cases:
/// 1. Source already has pfSense OpenVPN config → use it directly
/// 2. Source has OPNsense nested OpenVPN config → map instances to servers/clients
///
/// The output contains pfSense-style `<openvpn>` at the root level with
/// `<openvpn-server>` and `<openvpn-client>` children.
///
/// ## Instance to Server/Client Mapping
///
/// OPNsense instances are converted based on their `<role>` field:
/// - `role="server"` → `<openvpn-server>`
/// - `role="client"` → `<openvpn-client>`
///
/// Each instance's UUID is preserved in the output as `<opnsense_instance_uuid>`
/// to enable round-trip conversion back to OPNsense format.
///
/// # Arguments
///
/// * `out` - The output XML tree being constructed
/// * `source` - The source configuration (pfSense or OPNsense)
/// * `_target` - The target template (unused for pfSense conversion)
pub fn to_pfsense(out: &mut XmlNode, source: &XmlNode, _target: &XmlNode) {
    // Get pfSense servers — either from source if already pfSense format,
    // or by mapping OPNsense instances to servers/clients
    let servers = common::source_pfsense_servers(source)
        .unwrap_or_else(|| opn_to_pf::map_opnsense_instances_to_pfsense(source));
    if servers.children.is_empty() {
        return;
    }

    // Insert at root level
    common::upsert_child(out, servers);
    // Ensure only one <openvpn> element exists
    common::dedupe_top_level_openvpn(out);
}
