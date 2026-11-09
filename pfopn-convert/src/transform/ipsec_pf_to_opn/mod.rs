//! pfSense IPsec to OPNsense IPsec/Swanctl conversion.
//!
//! This module handles the conversion of IPsec VPN configurations from pfSense's
//! phase1/phase2 structure to OPNsense's Swanctl (strongSwan) format.
//!
//! ## Platform Differences
//!
//! **pfSense IPsec structure:**
//! - Uses `<phase1>` for IKE (Internet Key Exchange) tunnel configuration
//! - Uses `<phase2>` for ESP (Encapsulating Security Payload) child SA configuration
//! - Pre-shared keys embedded in phase1 entries
//! - Simpler, flatter structure based on racoon/charon legacy format
//!
//! **OPNsense IPsec structure:**
//! - Uses strongSwan's swanctl configuration model
//! - Splits into two top-level sections:
//!   - `<OPNsense><IPsec>` — General settings and pre-shared keys
//!   - `<OPNsense><Swanctl>` — Connection definitions, locals, remotes, children
//! - More granular control with separate local/remote authentication config
//! - Each connection has associated local, remote, and child elements linked by UUID
//!
//! ## Mapping Overview
//!
//! For each pfSense `<phase1>`:
//! - Creates an OPNsense `<Swanctl><Connection>` (IKE SA config)
//! - Creates a `<Swanctl><local>` (local endpoint auth)
//! - Creates a `<Swanctl><remote>` (remote endpoint auth)
//! - Extracts pre-shared key into `<OPNsense><IPsec><preSharedKeys>`
//!
//! For each matching pfSense `<phase2>` (matched by ikeid):
//! - Creates an OPNsense `<Swanctl><child>` (ESP child SA)
//! - Links it to the parent Connection via UUID
//!
//! All elements are assigned deterministic UUIDs based on their ikeid and index
//! to ensure stable identifiers across repeated conversions.

use xml_diff_core::XmlNode;

mod base;
mod mapper;
mod proposals;
mod util;

pub use mapper::IpsecMapping;

/// Convert pfSense IPsec tunnels (`<ipsec><phase1>/<phase2>` in `source`) to
/// OPNsense's IPsec/Swanctl model, starting from the baseline's sections.
/// See [`mapper::map_pf_ipsec_to_opnsense`].
pub fn map_pf_ipsec_to_opnsense(
    source: &XmlNode,
    baseline_ipsec: Option<&XmlNode>,
    baseline_swanctl: Option<&XmlNode>,
) -> IpsecMapping {
    mapper::map_pf_ipsec_to_opnsense(source, baseline_ipsec, baseline_swanctl)
}
