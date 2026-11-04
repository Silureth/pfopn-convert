use std::collections::BTreeSet;

use xml_diff_core::XmlNode;

use crate::profile::ExpectedProfile;
use crate::verify_interfaces::{FindingSeverity, VerifyFinding};

pub fn profile_findings(root: &XmlNode, profile: &ExpectedProfile) -> Vec<VerifyFinding> {
    let mut out = Vec::new();
    out.extend(required_section_findings(root, profile));
    out.extend(deprecated_section_findings(root, profile));
    out.extend(rule_field_findings(root, profile));
    out.extend(rule_order_findings(root, profile));
    out.extend(gateway_field_findings(root, profile));
    out.extend(route_field_findings(root, profile));
    out.extend(bridge_findings(root, profile));
    out
}

fn required_section_findings(root: &XmlNode, profile: &ExpectedProfile) -> Vec<VerifyFinding> {
    profile
        .required_sections
        .iter()
        .filter(|section| root.get_child(section.as_str()).is_none())
        .map(|section| VerifyFinding {
            severity: FindingSeverity::Warning,
            code: "profile_missing_required_section".to_string(),
            message: format!("expected section '{section}' is missing"),
        })
        .collect()
}

fn deprecated_section_findings(root: &XmlNode, profile: &ExpectedProfile) -> Vec<VerifyFinding> {
    profile
        .deprecated_sections
        .iter()
        .filter(|section| root.get_child(section.as_str()).is_some())
        .map(|section| VerifyFinding {
            severity: FindingSeverity::Warning,
            code: "profile_deprecated_section_present".to_string(),
            message: format!("deprecated section '{section}' is present"),
        })
        .collect()
}

fn rule_field_findings(root: &XmlNode, profile: &ExpectedProfile) -> Vec<VerifyFinding> {
    let Some(filter) = root.get_child("filter") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (idx, rule) in filter
        .children
        .iter()
        .filter(|c| c.tag == "rule")
        .enumerate()
    {
        for field in &profile.rule_required_fields {
            let ok = rule
                .get_text(&[field.as_str()])
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false);
            if !ok {
                out.push(VerifyFinding {
                    severity: FindingSeverity::Warning,
                    code: "profile_rule_missing_required_field".to_string(),
                    message: format!("filter rule #{idx} is missing required field '{field}'"),
                });
            }
        }
    }
    out
}

fn rule_order_findings(root: &XmlNode, profile: &ExpectedProfile) -> Vec<VerifyFinding> {
    let Some(order_key) = &profile.firewall_order_key else {
        return Vec::new();
    };
    let Some(filter) = root.get_child("filter") else {
        return Vec::new();
    };
    let rules = filter
        .children
        .iter()
        .filter(|c| c.tag == "rule")
        .collect::<Vec<_>>();
    let any_has_order_key = rules
        .iter()
        .any(|rule| rule.get_text(&[order_key.as_str()]).is_some());
    if !any_has_order_key {
        return Vec::new();
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for (idx, rule) in rules.into_iter().enumerate() {
        let Some(value) = rule.get_text(&[order_key.as_str()]) else {
            out.push(VerifyFinding {
                severity: FindingSeverity::Warning,
                code: "profile_rule_missing_order_key".to_string(),
                message: format!("filter rule #{idx} is missing order key '{order_key}'"),
            });
            continue;
        };
        let value = value.trim().to_string();
        if value.is_empty() {
            out.push(VerifyFinding {
                severity: FindingSeverity::Warning,
                code: "profile_rule_missing_order_key".to_string(),
                message: format!("filter rule #{idx} has empty order key '{order_key}'"),
            });
            continue;
        }
        if !seen.insert(value.clone()) {
            out.push(VerifyFinding {
                severity: FindingSeverity::Warning,
                code: "profile_rule_duplicate_order_key".to_string(),
                message: format!("duplicate firewall order key '{value}'"),
            });
        }
    }
    out
}

fn gateway_field_findings(root: &XmlNode, profile: &ExpectedProfile) -> Vec<VerifyFinding> {
    let Some(gateways) = root.get_child("gateways") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (idx, gw) in gateways.children.iter().enumerate() {
        if !has_any_field(gw, &profile.gateway_required_fields) {
            continue;
        }
        for field in &profile.gateway_required_fields {
            let ok = if field == "gateway" {
                // An empty <gateway> (or "dynamic") is a dynamic/DHCP gateway on
                // both pfSense and OPNsense (Routing/Gateways.php), not a gap.
                gw.get_child("gateway").is_some()
            } else {
                gw.get_text(&[field.as_str()])
                    .map(|v| !v.trim().is_empty())
                    .unwrap_or(false)
            };
            if !ok {
                let name = gw
                    .get_text(&["name"])
                    .map(str::trim)
                    .filter(|n| !n.is_empty())
                    .map(|n| format!(" ({n})"))
                    .unwrap_or_default();
                out.push(VerifyFinding {
                    severity: FindingSeverity::Warning,
                    code: "profile_gateway_missing_required_field".to_string(),
                    message: format!(
                        "gateway #{}{name} is missing required field '{field}'",
                        idx + 1
                    ),
                });
            }
        }
    }
    out
}

fn route_field_findings(root: &XmlNode, profile: &ExpectedProfile) -> Vec<VerifyFinding> {
    let Some(routes) = root.get_child("staticroutes") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (idx, route) in routes.children.iter().enumerate() {
        for field in &profile.route_required_fields {
            let ok = route
                .get_text(&[field.as_str()])
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false);
            if !ok {
                out.push(VerifyFinding {
                    severity: FindingSeverity::Warning,
                    code: "profile_route_missing_required_field".to_string(),
                    message: format!("static route #{idx} is missing required field '{field}'"),
                });
            }
        }
        if !profile.route_required_any_fields.is_empty() {
            let has_any = profile.route_required_any_fields.iter().any(|field| {
                route
                    .get_text(&[field.as_str()])
                    .map(|v| !v.trim().is_empty())
                    .unwrap_or(false)
            });
            if !has_any {
                out.push(VerifyFinding {
                    severity: FindingSeverity::Warning,
                    code: "profile_route_missing_any_required_field".to_string(),
                    message: format!(
                        "static route #{idx} is missing one of [{}]",
                        profile.route_required_any_fields.join(", ")
                    ),
                });
            }
        }
    }
    out
}

fn bridge_findings(root: &XmlNode, profile: &ExpectedProfile) -> Vec<VerifyFinding> {
    if !profile.bridge_require_members {
        return Vec::new();
    }
    let Some(bridges) = root.get_child("bridges") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (idx, bridge) in bridges
        .children
        .iter()
        .filter(|c| c.tag == "bridged" && !crate::transform::bridges::is_empty_placeholder(c))
        .enumerate()
    {
        let members = bridge
            .get_text(&["members"])
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        let bridgeif = bridge
            .get_text(&["bridgeif"])
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        if !members && !bridgeif {
            out.push(VerifyFinding {
                severity: FindingSeverity::Warning,
                code: "profile_bridge_missing_members".to_string(),
                message: format!("bridge #{idx} has no members according to profile"),
            });
        }
    }
    out
}

fn has_any_field(node: &XmlNode, fields: &[String]) -> bool {
    fields
        .iter()
        .any(|field| node.get_text(&[field.as_str()]).is_some())
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::gateway_field_findings;
    use crate::profile::ExpectedProfile;

    #[test]
    fn treats_empty_gateway_as_dynamic_but_flags_missing_one() {
        let profile: ExpectedProfile =
            toml::from_str(r#"gateway_required_fields = ["name", "interface", "gateway"]"#)
                .expect("profile");
        let root = parse(
            br#"<opnsense><gateways>
                <gateway_item><name>WAN_DHCP6</name><interface>wan</interface><gateway></gateway></gateway_item>
                <gateway_item><name>WAN_DYN</name><interface>wan</interface><gateway>dynamic</gateway></gateway_item>
                <gateway_item><name>BROKEN</name><interface>wan</interface></gateway_item>
            </gateways></opnsense>"#,
        )
        .expect("parse");

        let findings = gateway_field_findings(&root, &profile);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(
            findings[0].message,
            "gateway #3 (BROKEN) is missing required field 'gateway'"
        );
    }
}
