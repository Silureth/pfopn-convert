//! pfSense remote syslog (`<syslog><remoteserver>`) to OPNsense's Syslog model
//! (`OPNsense/Syslog/destinations/destination`).
//!
//! An empty `program`, `level` or `facility` means "everything" in OPNsense
//! (`syslog-ng-destinations.conf` only adds a filter for non-empty values),
//! which is what pfSense's "Everything" (`logall`) sends.

use xml_diff_core::XmlNode;

use crate::transform::filter_mvc::stable_uuid;
use crate::transform::mvc_util::{bool01, ensure_path, model_mut, push, text};
use crate::transform::rule_flags::pf_flag_is_set;

const MODEL_PATH: &[&str] = &["OPNsense", "Syslog"];
const SERVERS: &[&str] = &["remoteserver", "remoteserver2", "remoteserver3"];
/// pfSense per-category remote log switches (used when `logall` is off).
const CATEGORIES: &[&str] = &[
    "filter",
    "dhcp",
    "auth",
    "portalauth",
    "vpn",
    "dpinger",
    "hostapd",
    "system",
    "resolver",
    "ppp",
    "routing",
    "ntpd",
];

#[derive(Debug, Default)]
pub struct SyslogStats {
    pub destinations: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn from_pfsense(out: &mut XmlNode, source: &XmlNode, baseline: &XmlNode) -> SyslogStats {
    let mut stats = SyslogStats::default();
    let Some(src) = source.get_child("syslog") else {
        return stats;
    };
    let servers: Vec<String> = SERVERS
        .iter()
        .map(|tag| text(src, tag))
        .filter(|s| !s.is_empty())
        .collect();
    // pfSense's <enable> under <syslog> is "Enable Remote Logging".
    if servers.is_empty() || !pf_flag_is_set(src, "enable") {
        return stats;
    }
    let Some(model) = model_mut(out, baseline, MODEL_PATH) else {
        stats.warnings.push(
            "remote syslog: the baseline has no Syslog model; destinations not converted"
                .to_string(),
        );
        return stats;
    };

    let logall = pf_flag_is_set(src, "logall");
    let categories: Vec<&str> = CATEGORIES
        .iter()
        .copied()
        .filter(|c| pf_flag_is_set(src, c))
        .collect();
    let enabled = logall || !categories.is_empty();
    if !logall {
        if categories.is_empty() {
            stats.warnings.push(
                "remote syslog: pfSense sent no log categories; destinations converted disabled"
                    .to_string(),
            );
        } else {
            stats.warnings.push(format!(
                "remote syslog: pfSense sent only {}; the OPNsense destination sends all programs, narrow it under System > Settings > Logging > Remote",
                categories.join(", ")
            ));
        }
    }
    if !text(src, "sourceip").is_empty() {
        stats.warnings.push(
            "remote syslog: source address not converted (OPNsense uses the outgoing interface)"
                .to_string(),
        );
    }
    let ipv6 = text(src, "ipproto") == "ipv6";
    let rfc5424 = text(src, "format") == "rfc5424";

    let destinations = ensure_path(model, &["destinations"]);
    destinations.text = None;
    for server in &servers {
        let (host, port) = split_host_port(server);
        destinations.children.retain(|d| {
            !(d.tag == "destination" && text(d, "hostname") == host && text(d, "port") == port)
        });
        let mut dest = XmlNode::new("destination");
        dest.attributes.insert(
            "uuid".to_string(),
            stable_uuid(&format!("syslog-destination|{host}|{port}")),
        );
        push(&mut dest, "enabled", bool01(enabled));
        let v6 = ipv6 || host.contains(':');
        push(&mut dest, "transport", if v6 { "udp6" } else { "udp4" });
        push(&mut dest, "program", "");
        push(&mut dest, "level", "");
        push(&mut dest, "facility", "");
        push(&mut dest, "hostname", &host);
        push(&mut dest, "certificate", "");
        push(&mut dest, "port", &port);
        push(&mut dest, "rfc5424", bool01(rfc5424));
        push(&mut dest, "description", "Converted from pfSense remote syslog");
        destinations.children.push(dest);
        stats.destinations.push(format!("{host}:{port}"));
    }
    stats
}

/// "host", "host:port", "[v6]:port" or a bare IPv6 address; port defaults to 514.
fn split_host_port(value: &str) -> (String, String) {
    if let Some(rest) = value.strip_prefix('[') {
        if let Some((host, tail)) = rest.split_once(']') {
            let port = tail.strip_prefix(':').filter(|p| !p.is_empty()).unwrap_or("514");
            return (host.to_string(), port.to_string());
        }
    }
    match value.matches(':').count() {
        1 => {
            let (host, port) = value.split_once(':').unwrap();
            let port = if port.is_empty() { "514" } else { port };
            (host.to_string(), port.to_string())
        }
        _ => (value.to_string(), "514".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::{from_pfsense, split_host_port};

    const BASELINE: &[u8] = br#"<opnsense><OPNsense><Syslog version="1.0.2"><general><enabled>1</enabled></general><destinations/></Syslog></OPNsense></opnsense>"#;

    #[test]
    fn converts_remote_servers() {
        let baseline = parse(BASELINE).expect("parse");
        let mut out = baseline.clone();
        let source = parse(
            br#"<pfsense><syslog><remoteserver>10.0.21.205:9001</remoteserver><remoteserver2>logs.example</remoteserver2><remoteserver3></remoteserver3>
                <sourceip></sourceip><ipproto>ipv4</ipproto><enable></enable><logall></logall><format>rfc5424</format></syslog></pfsense>"#,
        )
        .expect("parse");
        let stats = from_pfsense(&mut out, &source, &baseline);
        assert_eq!(stats.destinations, ["10.0.21.205:9001", "logs.example:514"]);
        assert!(stats.warnings.is_empty(), "{:?}", stats.warnings);

        let model = out.get_child("OPNsense").unwrap().get_child("Syslog").unwrap();
        assert_eq!(model.attributes.get("version").map(String::as_str), Some("1.0.2"));
        let dests = model.get_child("destinations").unwrap().get_children("destination");
        assert_eq!(dests.len(), 2);
        assert_eq!(dests[0].get_text(&["hostname"]), Some("10.0.21.205"));
        assert_eq!(dests[0].get_text(&["port"]), Some("9001"));
        assert_eq!(dests[0].get_text(&["transport"]), Some("udp4"));
        assert_eq!(dests[0].get_text(&["rfc5424"]), Some("1"));
        assert_eq!(dests[0].get_text(&["enabled"]), Some("1"));
        assert_eq!(dests[0].get_text(&["program"]).unwrap_or(""), "");
    }

    #[test]
    fn remote_logging_off_converts_nothing() {
        let baseline = parse(BASELINE).expect("parse");
        let mut out = baseline.clone();
        let source = parse(
            br#"<pfsense><syslog><remoteserver>10.0.0.1</remoteserver><logall></logall></syslog></pfsense>"#,
        )
        .expect("parse");
        assert!(from_pfsense(&mut out, &source, &baseline).destinations.is_empty());
    }

    #[test]
    fn category_selection_is_reported() {
        let baseline = parse(BASELINE).expect("parse");
        let mut out = baseline.clone();
        let source = parse(
            br#"<pfsense><syslog><remoteserver>10.0.0.1</remoteserver><enable></enable><filter></filter><system></system></syslog></pfsense>"#,
        )
        .expect("parse");
        let stats = from_pfsense(&mut out, &source, &baseline);
        assert!(stats.warnings.iter().any(|w| w.contains("filter, system")));
    }

    #[test]
    fn splits_host_and_port() {
        assert_eq!(split_host_port("10.0.0.1:9001"), ("10.0.0.1".into(), "9001".into()));
        assert_eq!(split_host_port("10.0.0.1"), ("10.0.0.1".into(), "514".into()));
        assert_eq!(split_host_port("[2001:db8::1]:601"), ("2001:db8::1".into(), "601".into()));
        assert_eq!(split_host_port("2001:db8::1"), ("2001:db8::1".into(), "514".into()));
    }
}
