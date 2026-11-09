//! pfSense LDAP authentication servers (`system/authserver`) for OPNsense.
//!
//! Both keep auth servers in `system/authserver` with mostly the same field
//! names, and the section comes over with pfSense's `system`. Two values
//! differ in meaning (OPNsense `Auth/LDAP.php::setProperties()`):
//!
//! - `ldap_urltype`: OPNsense tests for the substrings "Standard" and
//!   "StartTLS" and treats everything else as LDAPS. pfSense's
//!   "STARTTLS Encrypt" would therefore become LDAPS. The values are mapped
//!   to OPNsense's own ("TCP - Standard", "StartTLS", "SSL - Encrypted"),
//!   which also selects the right entry in the GUI.
//! - `ldap_extended_query`: pfSense only applies it when
//!   `ldap_extended_enabled` is set; OPNsense always applies it.

use xml_diff_core::XmlNode;

use crate::transform::mvc_util::text;

#[derive(Debug, Default)]
pub struct AuthServerReport {
    pub converted: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn ldap_for_opnsense(out: &mut XmlNode) -> AuthServerReport {
    let mut report = AuthServerReport::default();
    let Some(system) = out.children.iter_mut().find(|c| c.tag == "system") else {
        return report;
    };
    for server in system
        .children
        .iter_mut()
        .filter(|c| c.tag == "authserver" && text(c, "type") == "ldap")
    {
        let name = text(server, "name");
        let urltype = text(server, "ldap_urltype");
        let mapped = match urltype.as_str() {
            "Standard TCP" | "TCP - Standard" => "TCP - Standard",
            "STARTTLS Encrypt" | "StartTLS" => "StartTLS",
            "SSL/TLS Encrypted" | "SSL - Encrypted" => "SSL - Encrypted",
            other => {
                report.warnings.push(format!(
                    "LDAP server '{name}': transport '{other}' not recognised; check it under System > Access > Servers"
                ));
                continue;
            }
        };
        set_text(server, "ldap_urltype", mapped);

        let extended_on = matches!(
            text(server, "ldap_extended_enabled").as_str(),
            "yes" | "on" | "1"
        );
        if !extended_on && !text(server, "ldap_extended_query").is_empty() {
            set_text(server, "ldap_extended_query", "");
        }
        server.children.retain(|c| c.tag != "ldap_extended_enabled");

        let caref = text(server, "ldap_caref");
        if mapped != "TCP - Standard" && !caref.is_empty() && caref != "global" {
            report.warnings.push(format!(
                "LDAP server '{name}': OPNsense checks the server certificate against the system trust store, not a per-server CA; make sure its CA is trusted (System > Trust > Authorities)"
            ));
        }
        report.converted.push(name);
    }
    report
}

fn set_text(node: &mut XmlNode, tag: &str, value: &str) {
    if let Some(child) = node.children.iter_mut().find(|c| c.tag == tag) {
        child.text = Some(value.to_string());
        child.children.clear();
    } else {
        let mut child = XmlNode::new(tag);
        child.text = Some(value.to_string());
        node.children.push(child);
    }
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::ldap_for_opnsense;

    #[test]
    fn maps_transport_and_extended_query() {
        let mut out = parse(
            br#"<opnsense><system>
                <authserver><type>ldap</type><name>A</name><ldap_urltype>Standard TCP</ldap_urltype>
                  <ldap_extended_enabled></ldap_extended_enabled><ldap_extended_query>memberOf=CN=x</ldap_extended_query></authserver>
                <authserver><type>ldap</type><name>B</name><ldap_urltype>STARTTLS Encrypt</ldap_urltype>
                  <ldap_extended_enabled>yes</ldap_extended_enabled><ldap_extended_query>memberOf=CN=y</ldap_extended_query><ldap_caref>ca1</ldap_caref></authserver>
                <authserver><type>radius</type><name>R</name></authserver>
            </system></opnsense>"#,
        )
        .expect("parse");
        let report = ldap_for_opnsense(&mut out);
        let servers = out.get_child("system").unwrap().get_children("authserver");
        assert_eq!(
            servers[0].get_text(&["ldap_urltype"]),
            Some("TCP - Standard")
        );
        assert_eq!(servers[0].get_text(&["ldap_extended_query"]), Some(""));
        assert!(servers[0].get_child("ldap_extended_enabled").is_none());
        assert_eq!(servers[1].get_text(&["ldap_urltype"]), Some("StartTLS"));
        assert_eq!(
            servers[1].get_text(&["ldap_extended_query"]),
            Some("memberOf=CN=y")
        );
        assert_eq!(report.converted, vec!["A", "B"]);
        assert_eq!(report.warnings.len(), 1);
    }
}
