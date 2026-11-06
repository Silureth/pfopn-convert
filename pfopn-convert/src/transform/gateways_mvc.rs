//! Move pfSense gateways into OPNsense's Gateways model.
//!
//! OPNsense reads gateways only from `OPNsense/Gateways/gateway_item`. Its own
//! migration from the legacy `<gateways><gateway_item>` layout
//! (`Routing/Migrations/M1_0_0.php`) only runs when the model is older than
//! 1.0.0, which is never the case for a current baseline. Without this
//! transform the pfSense gateways stay in the legacy section, where nothing
//! reads them: interfaces and policy-routing rules then point at gateway names
//! that do not exist, and the baseline's default gateway stays in place.
//!
//! The field mapping follows `M1_0_0`, except that pfSense's empty-element
//! booleans (`<monitor_disable></monitor_disable>`) are read as set, which is
//! what pfSense means by them. Gateway groups stay where they are: OPNsense
//! still mounts them at `/gateways/gateway_group`.

use xml_diff_core::XmlNode;

use crate::transform::filter_mvc::stable_uuid;
use crate::transform::rule_flags::pf_flag_is_set;
use crate::transform::version::inherit_model_attrs;

const MODEL_PATH: &[&str] = &["OPNsense", "Gateways"];

/// Fields copied unchanged (name in both formats).
const COPIED: &[&str] = &[
    "name",
    "descr",
    "interface",
    "monitor",
    "priority",
    "latencylow",
    "latencyhigh",
    "losslow",
    "losshigh",
    "interval",
    "time_period",
    "loss_interval",
    "data_length",
];

/// Boolean fields with the same name in both formats.
const FLAGS: &[&str] = &[
    "disabled",
    "fargw",
    "monitor_disable",
    "monitor_noroute",
    "force_down",
    "nosync",
];

/// pfSense fields that are handled explicitly or carry no meaning on OPNsense.
const HANDLED: &[&str] = &[
    "gateway",
    "ipprotocol",
    "weight",
    "defaultgw",
    "nonlocalgateway",
    "dpinger_dont_add_static_route",
    "data_payload",
    "gw_down_kill_states",
    "action_disable",
    "alert_interval",
];

#[derive(Debug, Default)]
pub struct GatewayMvcStats {
    pub moved: usize,
    pub baseline_replaced: usize,
    pub default_gateways: Vec<String>,
    pub dropped_fields: Vec<String>,
}

/// Move legacy `<gateways><gateway_item>` entries into the Gateways model when
/// the baseline has that model. The baseline's own gateways are replaced, the
/// same way the converted firewall rules replace the baseline defaults.
pub fn move_legacy_gateways_to_mvc(out: &mut XmlNode, baseline: &XmlNode) -> GatewayMvcStats {
    let mut stats = GatewayMvcStats::default();
    let baseline_model = MODEL_PATH
        .iter()
        .try_fold(baseline, |node, tag| node.get_child(tag));
    if baseline_model.is_none() {
        return stats;
    }

    let Some(legacy) = out.children.iter_mut().find(|c| c.tag == "gateways") else {
        return stats;
    };
    if !legacy.children.iter().any(|c| c.tag == "gateway_item") {
        return stats;
    }
    let default_names: Vec<String> = ["defaultgw4", "defaultgw6"]
        .iter()
        .filter_map(|tag| legacy.get_text(&[tag]))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect();
    let items: Vec<XmlNode> = legacy
        .children
        .iter()
        .filter(|c| c.tag == "gateway_item")
        .cloned()
        .collect();
    // OPNsense does not use defaultgw4/6; the default is a per-gateway flag.
    legacy
        .children
        .retain(|c| !matches!(c.tag.as_str(), "gateway_item" | "defaultgw4" | "defaultgw6"));

    let converted: Vec<XmlNode> = items
        .iter()
        .map(|item| map_gateway(item, &default_names, &mut stats))
        .collect();

    let model = ensure_path(out, MODEL_PATH);
    inherit_model_attrs(model, baseline_model);
    let before = model.children.len();
    model.children.retain(|c| c.tag != "gateway_item");
    stats.baseline_replaced = before - model.children.len();
    stats.moved = converted.len();
    model.children.extend(converted);
    stats
}

fn map_gateway(item: &XmlNode, default_names: &[String], stats: &mut GatewayMvcStats) -> XmlNode {
    let name = text(item, "name");
    let mut node = XmlNode::new("gateway_item");
    node.attributes
        .insert("uuid".to_string(), stable_uuid(&format!("gateway|{name}")));

    let is_default = pf_flag_is_set(item, "defaultgw") || default_names.contains(&name);
    if is_default {
        stats.default_gateways.push(name.clone());
    }

    for flag in FLAGS {
        let set = match *flag {
            "fargw" => pf_flag_is_set(item, "fargw") || pf_flag_is_set(item, "nonlocalgateway"),
            "monitor_noroute" => {
                pf_flag_is_set(item, "monitor_noroute")
                    || pf_flag_is_set(item, "dpinger_dont_add_static_route")
            }
            other => pf_flag_is_set(item, other),
        };
        push(&mut node, flag, bool01(set));
    }
    push(&mut node, "defaultgw", bool01(is_default));
    push(
        &mut node,
        "monitor_killstates",
        bool01(text(item, "gw_down_kill_states") == "down"),
    );

    let ipprotocol = text(item, "ipprotocol");
    push(
        &mut node,
        "ipprotocol",
        if ipprotocol.is_empty() {
            "inet"
        } else {
            &ipprotocol
        },
    );
    // "dynamic" marks a DHCP/PPP gateway; OPNsense stores it as empty.
    push(
        &mut node,
        "gateway",
        &text(item, "gateway").replace("dynamic", ""),
    );
    let weight = text(item, "weight");
    push(
        &mut node,
        "weight",
        if weight.is_empty() { "1" } else { &weight },
    );

    for field in COPIED {
        let mut value = text(item, field);
        if *field == "priority" && value.is_empty() {
            value = "255".to_string();
        }
        if *field == "data_length" && value.is_empty() {
            value = text(item, "data_payload");
        }
        push(&mut node, field, &value);
    }

    if item.get_child("action_disable").is_some() && !pf_flag_is_set(item, "monitor_disable") {
        stats.dropped_fields.push(format!(
            "gateway {name}: 'Disable gateway monitoring action' has no OPNsense equivalent; the gateway can be marked down"
        ));
    }
    for child in &item.children {
        let tag = child.tag.as_str();
        if COPIED.contains(&tag) || FLAGS.contains(&tag) || HANDLED.contains(&tag) {
            continue;
        }
        if !text(item, tag).is_empty() {
            stats
                .dropped_fields
                .push(format!("gateway {name}: field '{tag}' not mapped"));
        }
    }
    node
}

fn text(node: &XmlNode, tag: &str) -> String {
    node.get_text(&[tag])
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

fn bool01(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}

fn push(parent: &mut XmlNode, tag: &str, value: &str) {
    let mut child = XmlNode::new(tag);
    child.text = Some(value.to_string());
    parent.children.push(child);
}

fn ensure_path<'a>(root: &'a mut XmlNode, path: &[&str]) -> &'a mut XmlNode {
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

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::move_legacy_gateways_to_mvc;

    const BASELINE: &[u8] = br#"<opnsense><OPNsense><Gateways version="1.0.0" persisted_at="1"><gateway_item uuid="b"><name>WAN_GW</name><interface>wan</interface><gateway>192.0.2.1</gateway><defaultgw>1</defaultgw></gateway_item></Gateways></OPNsense></opnsense>"#;

    #[test]
    fn moves_pfsense_gateways_into_model() {
        let baseline = parse(BASELINE).expect("parse");
        let mut out = parse(
            br#"<opnsense>
                <gateways>
                  <gateway_item><interface>wan</interface><gateway>203.0.113.30</gateway><name>GW_WAN</name><weight>1</weight><ipprotocol>inet</ipprotocol><interval></interval><descr>Interface wan Gateway</descr></gateway_item>
                  <gateway_item><interface>opt1</interface><gateway>198.51.100.94</gateway><name>WAN2_GW</name><weight></weight><ipprotocol>inet</ipprotocol><descr></descr></gateway_item>
                  <gateway_item><interface>opt2</interface><gateway>192.168.1.254</gateway><name>MGMT_GW</name><weight>1</weight><ipprotocol>inet</ipprotocol><monitor_disable></monitor_disable><action_disable></action_disable><gw_down_kill_states></gw_down_kill_states></gateway_item>
                  <gateway_item><interface>wan</interface><gateway>dynamic</gateway><name>WAN_DHCP6</name><ipprotocol>inet6</ipprotocol><disabled/><gw_down_kill_states>down</gw_down_kill_states></gateway_item>
                  <gateway_group><name>failover</name></gateway_group>
                  <defaultgw4>GW_WAN</defaultgw4>
                </gateways>
                <OPNsense><Gateways version="1.0.0" persisted_at="1"><gateway_item uuid="b"><name>WAN_GW</name></gateway_item></Gateways></OPNsense>
            </opnsense>"#,
        )
        .expect("parse");

        let stats = move_legacy_gateways_to_mvc(&mut out, &baseline);
        assert_eq!(stats.moved, 4);
        assert_eq!(stats.baseline_replaced, 1);
        assert_eq!(stats.default_gateways, vec!["GW_WAN".to_string()]);
        assert!(
            stats.dropped_fields.is_empty(),
            "{:?}",
            stats.dropped_fields
        );

        let legacy = out.get_child("gateways").unwrap();
        assert!(legacy.get_child("gateway_item").is_none());
        assert!(legacy.get_child("defaultgw4").is_none());
        assert!(
            legacy.get_child("gateway_group").is_some(),
            "groups stay legacy"
        );

        let model = out
            .get_child("OPNsense")
            .unwrap()
            .get_child("Gateways")
            .unwrap();
        assert_eq!(
            model.attributes.get("version").map(String::as_str),
            Some("1.0.0")
        );
        let gws = model.get_children("gateway_item");
        let names: Vec<_> = gws.iter().map(|g| g.get_text(&["name"]).unwrap()).collect();
        assert_eq!(names, ["GW_WAN", "WAN2_GW", "MGMT_GW", "WAN_DHCP6"]);
        let field = |i: usize, f: &str| gws[i].get_text(&[f]).unwrap_or("").to_string();
        assert_eq!(field(0, "defaultgw"), "1");
        assert_eq!(field(0, "monitor_disable"), "0");
        assert_eq!(field(0, "priority"), "255");
        assert_eq!(field(1, "defaultgw"), "0");
        assert_eq!(field(1, "weight"), "1");
        // pfSense empty element = set; OPNsense's own migration would lose this.
        assert_eq!(field(2, "monitor_disable"), "1");
        assert_eq!(field(2, "monitor_killstates"), "0");
        assert_eq!(field(3, "gateway"), "");
        assert_eq!(field(3, "disabled"), "1");
        assert_eq!(field(3, "monitor_killstates"), "1");
        assert!(gws.iter().all(|g| g.attributes.contains_key("uuid")));
    }

    #[test]
    fn leaves_config_alone_without_gateways_model_in_baseline() {
        let baseline = parse(br#"<opnsense/>"#).expect("parse");
        let mut out = parse(
            br#"<opnsense><gateways><gateway_item><name>GW_WAN</name></gateway_item></gateways></opnsense>"#,
        )
        .expect("parse");
        let stats = move_legacy_gateways_to_mvc(&mut out, &baseline);
        assert_eq!(stats.moved, 0);
        assert!(out
            .get_child("gateways")
            .unwrap()
            .get_child("gateway_item")
            .is_some());
    }
}
