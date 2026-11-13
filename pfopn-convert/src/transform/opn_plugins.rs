//! pfSense packages to OPNsense plugins.
//!
//! A plugin's settings can only be written when the baseline has the plugin
//! installed: its model (and model version) only exists then. Packages whose
//! plugin is missing from the baseline are reported, so the user can install
//! the plugin, export a new baseline and convert again.
//!
//! The plugins the source needs are also added to `system/firmware/plugins`
//! (OPNsense's list of configured plugins). After a restore, plugins on that
//! list that are not installed show up under System > Firmware > Plugins and
//! can be installed from there. The output's `system` section comes from
//! pfSense, so the baseline's `system/firmware` node is restored first.

use xml_diff_core::XmlNode;

use crate::transform::filter_mvc::stable_uuid;
use crate::transform::mvc_util::{
    bool01, decode_base64, ensure_path, model_mut, node_at, push, set_path, text,
};

const ZABBIX_MODEL: &[&str] = &["OPNsense", "ZabbixAgent"];
const ZABBIX_PROXY_MODEL: &[&str] = &["OPNsense", "zabbixproxy", "general"];
const NODE_EXPORTER_MODEL: &[&str] = &["OPNsense", "NodeExporter"];
const QEMU_MODEL: &[&str] = &["OPNsense", "QemuGuestAgent"];
const NETSNMP_MODEL: &[&str] = &["OPNsense", "netsnmp", "general"];

/// pfSense's bsnmpd modules that Net-SNMP provides an equivalent for
/// (IF-MIB and friends, HOST-RESOURCES-MIB, UCD-SNMP-MIB).
const SNMP_MODULES_COVERED: &[&str] = &["mibii", "hostres", "ucd"];

/// node_exporter collectors the OPNsense plugin can switch on.
const NODE_EXPORTER_COLLECTORS: &[&str] = &[
    "cpu",
    "exec",
    "filesystem",
    "loadavg",
    "meminfo",
    "netdev",
    "time",
    "devstat",
    "interrupts",
    "ntp",
    "zfs",
];

/// Packages handled by other transforms; not reported here.
const HANDLED_ELSEWHERE: &[&str] = &["wireguard", "tailscale", "openvpn-client-export"];

#[derive(Debug, Default)]
pub struct PluginReport {
    /// (OPNsense plugin, pfSense package) whose settings were converted.
    pub converted: Vec<(String, String)>,
    /// (OPNsense plugin, pfSense package) not installed in the baseline.
    pub missing: Vec<(String, String)>,
    /// pfSense packages with no OPNsense plugin, with a hint.
    pub no_equivalent: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn from_pfsense(out: &mut XmlNode, source: &XmlNode, baseline: &XmlNode) -> PluginReport {
    let mut report = PluginReport::default();
    // pfSense's SNMP daemon is a core service, not a package.
    convert_snmp(out, source, baseline, &mut report);
    let Some(packages) = source.get_child("installedpackages") else {
        let wanted: Vec<String> = report
            .converted
            .iter()
            .chain(report.missing.iter())
            .map(|(plugin, _)| plugin.clone())
            .collect();
        restore_firmware(out, baseline, &wanted);
        return report;
    };

    for package in packages.get_children("package") {
        let name = text(package, "name");
        let internal = text(package, "internal_name");
        let key = format!("{} {}", name, internal).to_ascii_lowercase();
        if key.contains("zabbix") && key.contains("proxy") {
            let plugin = zabbix_plugin_name(&name, &internal, "proxy");
            match zabbix_proxy_config(packages) {
                Some(cfg) if node_at(baseline, ZABBIX_PROXY_MODEL).is_some() => {
                    convert_zabbix_proxy(out, baseline, cfg, &mut report.warnings);
                    report.converted.push((plugin, name));
                }
                Some(_) => report.missing.push((plugin, name)),
                None => report.warnings.push(format!(
                    "{name}: package has no settings; nothing to convert"
                )),
            }
        } else if key.contains("zabbix") && key.contains("agent") {
            let plugin = zabbix_plugin_name(&name, &internal, "agent");
            match zabbix_config(packages) {
                Some(cfg) if node_at(baseline, ZABBIX_MODEL).is_some() => {
                    convert_zabbix(out, baseline, cfg, &mut report.warnings);
                    report.converted.push((plugin, name));
                }
                Some(_) => report.missing.push((plugin, name)),
                None => report.warnings.push(format!(
                    "{name}: package has no settings; nothing to convert"
                )),
            }
        } else if key.contains("node_exporter") || key.contains("node-exporter") {
            let plugin = "os-node_exporter".to_string();
            match packages
                .get_child("nodeexporter")
                .and_then(|n| n.get_child("config"))
            {
                Some(cfg) if node_at(baseline, NODE_EXPORTER_MODEL).is_some() => {
                    convert_node_exporter(out, baseline, cfg, &mut report.warnings);
                    report.converted.push((plugin, name));
                }
                Some(_) => report.missing.push((plugin, name)),
                None => report.warnings.push(format!(
                    "{name}: package has no settings; nothing to convert"
                )),
            }
        } else if key.contains("shellcmd") {
            convert_shellcmds(out, baseline, packages, &name, &mut report);
        } else if key.contains("pfblocker") {
            report.no_equivalent.push(format!(
                "{name}: no OPNsense plugin; with --pfblocker-feeds its IP lists, GeoIP lists and DNSBL become URL table aliases, GeoIP aliases and an Unbound DNS blocklist"
            ));
        } else if !HANDLED_ELSEWHERE.iter().any(|h| key.contains(h)) {
            report.no_equivalent.push(format!(
                "{name}: not converted; check System > Firmware > Plugins for an equivalent"
            ));
        }
    }

    let wanted: Vec<String> = report
        .converted
        .iter()
        .chain(report.missing.iter())
        .map(|(plugin, _)| plugin.clone())
        .collect();
    restore_firmware(out, baseline, &wanted);
    report
}

/// OPNsense ships zabbix-agent and zabbix-proxy as variants, e.g.
/// `os-zabbix7-agent`, `os-zabbix74-agent`, `os-zabbix6-proxy`.
fn zabbix_plugin_name(name: &str, internal: &str, kind: &str) -> String {
    let digits: String = internal
        .chars()
        .chain(" ".chars())
        .chain(name.chars())
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    match digits.as_str() {
        "6" | "7" | "74" => format!("os-zabbix{digits}-{kind}"),
        _ => format!("os-zabbix7-{kind}"),
    }
}

fn zabbix_proxy_config(packages: &XmlNode) -> Option<&XmlNode> {
    packages
        .children
        .iter()
        .filter(|c| c.tag.starts_with("zabbixproxy"))
        .find_map(|c| c.get_child("config"))
}

/// pfSense stores PSK textareas base64-encoded; OPNsense wants the hex key.
fn decode_psk(raw: &str) -> String {
    decode_base64(raw)
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty() && k.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or_else(|| raw.to_string())
}

/// Zabbix Proxy package → os-zabbix*-proxy (`OPNsense/zabbixproxy/general`).
fn convert_zabbix_proxy(
    out: &mut XmlNode,
    baseline: &XmlNode,
    cfg: &XmlNode,
    warnings: &mut Vec<String>,
) {
    let Some(model) = model_mut(out, baseline, ZABBIX_PROXY_MODEL) else {
        return;
    };
    let on = |tag: &str| matches!(text(cfg, tag).as_str(), "on" | "yes" | "1");
    set_path(model, &["enabled"], bool01(on("proxyenabled")));
    // Both use ProxyMode semantics: 0 = active, 1 = passive.
    let passive = text(cfg, "proxymode") == "1";
    set_path(model, &["proxymode"], bool01(passive));
    for (pf, opn) in [
        ("server", "server"),
        ("serverport", "serverport"),
        ("hostname", "hostname"),
        ("listenport", "listenport"),
        ("listenip", "listenip"),
        ("sourceip", "sourceip"),
        ("configfrequency", "configfrequency"),
        ("starttrappers", "starttrappers"),
    ] {
        let value = text(cfg, pf);
        if !value.is_empty() {
            set_path(model, &[opn], &value);
        }
    }

    // Active proxies connect to the server (TLSConnect), passive ones accept
    // its connections (TLSAccept); OPNsense picks the directive from the mode.
    let connect = text(cfg, "tlsconnect");
    let accept = text(cfg, "tlsaccept");
    let psk = if passive {
        accept.split(',').any(|a| a.trim() == "psk")
    } else {
        connect == "psk"
    };
    set_path(model, &["encryption"], bool01(psk));
    if psk {
        set_path(model, &["encryptionidentity"], &text(cfg, "tlspskidentity"));
        set_path(
            model,
            &["encryptionpsk"],
            &decode_psk(&text(cfg, "tlspskfile")),
        );
    }
    if connect == "cert" || accept.split(',').any(|a| a.trim() == "cert") {
        warnings.push(
            "Zabbix proxy: certificate-based TLS is not supported by the OPNsense plugin; not converted"
                .to_string(),
        );
    }
    let trapper_timeout = text(cfg, "trappertimeout");
    if !trapper_timeout.is_empty() && trapper_timeout != "300" {
        warnings.push(format!(
            "Zabbix proxy: TrapperTimeout {trapper_timeout} not converted (no OPNsense setting)"
        ));
    }
    if on("startsnmptrapper") {
        warnings.push("Zabbix proxy: SNMP trapper not converted (no OPNsense setting)".to_string());
    }
    if !text(cfg, "advancedparams").is_empty() {
        warnings.push(
            "Zabbix proxy: advanced parameters not converted (no OPNsense setting)".to_string(),
        );
    }
}

fn zabbix_config(packages: &XmlNode) -> Option<&XmlNode> {
    packages
        .children
        .iter()
        .filter(|c| c.tag.starts_with("zabbixagent"))
        .find_map(|c| c.get_child("config"))
}

fn convert_zabbix(
    out: &mut XmlNode,
    baseline: &XmlNode,
    cfg: &XmlNode,
    warnings: &mut Vec<String>,
) {
    let Some(model) = model_mut(out, baseline, ZABBIX_MODEL) else {
        return;
    };
    let on = |tag: &str| matches!(text(cfg, tag).as_str(), "on" | "yes" | "1");
    set_path(
        model,
        &["settings", "main", "enabled"],
        bool01(on("agentenabled")),
    );
    for (pf, path) in [
        ("hostname", &["local", "hostname"][..]),
        ("server", &["settings", "main", "serverList"][..]),
        ("listenport", &["settings", "main", "listenPort"][..]),
        ("listenip", &["settings", "main", "listenIP"][..]),
        ("sourceip", &["settings", "main", "sourceIP"][..]),
        ("startagents", &["settings", "tuning", "startAgents"][..]),
        ("buffersend", &["settings", "tuning", "bufferSend"][..]),
        ("buffersize", &["settings", "tuning", "bufferSize"][..]),
        ("timeout", &["settings", "tuning", "timeout"][..]),
        (
            "refreshactchecks",
            &["settings", "features", "refreshActiveChecks"][..],
        ),
    ] {
        let value = text(cfg, pf);
        if !value.is_empty() {
            set_path(model, path, &value);
        }
    }
    let active = text(cfg, "serveractive");
    set_path(
        model,
        &["settings", "features", "enableActiveChecks"],
        bool01(!active.is_empty()),
    );
    set_path(
        model,
        &["settings", "features", "activeCheckServers"],
        &active,
    );

    let connect = text(cfg, "tlsconnect");
    let accept = text(cfg, "tlsaccept");
    let psk = connect == "psk" || accept.split(',').any(|a| a.trim() == "psk");
    set_path(model, &["settings", "features", "encryption"], bool01(psk));
    if psk {
        set_path(
            model,
            &["settings", "features", "encryptionidentity"],
            &text(cfg, "tlspskidentity"),
        );
        set_path(
            model,
            &["settings", "features", "encryptionpsk"],
            &decode_psk(&text(cfg, "tlspskfile")),
        );
    }
    if connect == "cert" || accept.split(',').any(|a| a.trim() == "cert") {
        warnings.push(
            "Zabbix agent: certificate-based TLS is not supported by the OPNsense plugin; not converted"
                .to_string(),
        );
    }

    let params = decode_base64(&text(cfg, "userparams")).unwrap_or_default();
    let mut items = Vec::new();
    for line in params
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let body = line.strip_prefix("UserParameter=").unwrap_or(line);
        let Some((key, command)) = body.split_once(',') else {
            warnings.push(format!(
                "Zabbix agent: user parameter line not understood: {line}"
            ));
            continue;
        };
        let (key, accept_params) = match key.strip_suffix("[*]") {
            Some(k) => (k, true),
            None => (key, false),
        };
        let mut item = XmlNode::new("userparameter");
        item.attributes.insert(
            "uuid".to_string(),
            stable_uuid(&format!("zabbix-userparameter|{key}")),
        );
        push(&mut item, "id", key);
        push(&mut item, "enabled", "1");
        push(&mut item, "key", key);
        push(&mut item, "command", command.trim());
        push(&mut item, "acceptParams", bool01(accept_params));
        items.push(item);
    }
    if !items.is_empty() {
        let container = ensure_path(model, &["userparameters"]);
        container.text = None;
        container.children.retain(|c| c.tag != "userparameter");
        container.children.extend(items);
    }
}

fn convert_node_exporter(
    out: &mut XmlNode,
    baseline: &XmlNode,
    cfg: &XmlNode,
    warnings: &mut Vec<String>,
) {
    let iface = text(cfg, "listen_iface");
    let listen = if iface.is_empty() || iface == "all" {
        "0.0.0.0".to_string()
    } else {
        let ip = out
            .get_child("interfaces")
            .and_then(|i| i.get_child(&iface))
            .map(|i| text(i, "ipaddr"))
            .unwrap_or_default();
        if ip.parse::<std::net::Ipv4Addr>().is_ok() {
            ip
        } else {
            warnings.push(format!(
                "node_exporter: listen interface '{iface}' has no static IPv4 address; listening on all addresses"
            ));
            "0.0.0.0".to_string()
        }
    };
    let collectors: Vec<String> = text(cfg, "collectors")
        .split(',')
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
        .collect();
    let dropped: Vec<&str> = collectors
        .iter()
        .map(String::as_str)
        .filter(|c| !NODE_EXPORTER_COLLECTORS.contains(c))
        .collect();
    if !dropped.is_empty() {
        warnings.push(format!(
            "node_exporter: collector(s) {} not available in the OPNsense plugin",
            dropped.join(", ")
        ));
    }
    if !text(cfg, "extra_flags").is_empty() {
        warnings.push("node_exporter: extra flags not converted".to_string());
    }
    let Some(model) = model_mut(out, baseline, NODE_EXPORTER_MODEL) else {
        return;
    };
    set_path(
        model,
        &["enabled"],
        bool01(matches!(text(cfg, "enable").as_str(), "on" | "yes" | "1")),
    );
    set_path(model, &["listenaddress"], &listen);
    let port = text(cfg, "listen_port");
    if !port.is_empty() {
        set_path(model, &["listenport"], &port);
    }
    for collector in NODE_EXPORTER_COLLECTORS {
        set_path(
            model,
            &[collector],
            bool01(collectors.iter().any(|c| c == collector)),
        );
    }
}

/// pfSense's SNMP daemon (bsnmpd, `<snmpd>`) -> the `os-net-snmp` plugin.
///
/// Converted: enabled, read-only community, location, contact, and the bind
/// address (an interface becomes its IPv4 address; "all" listens everywhere).
/// The plugin always uses port 161 and has no read-write community and no
/// traps. pfSense's pf, netgraph, bridge and regex MIB modules have no
/// Net-SNMP equivalent: their OIDs (for example the pf state table) stop
/// answering.
fn convert_snmp(
    out: &mut XmlNode,
    source: &XmlNode,
    baseline: &XmlNode,
    report: &mut PluginReport,
) {
    let Some(snmp) = source.get_child("snmpd") else {
        return;
    };
    if snmp.get_child("enable").is_none() {
        return;
    }
    let plugin = "os-net-snmp".to_string();
    let label = "SNMP daemon".to_string();
    if node_at(baseline, NETSNMP_MODEL).is_none() {
        report.missing.push((plugin, label));
        return;
    }

    let community = text(snmp, "rocommunity");
    if community.contains(char::is_whitespace) {
        report.warnings.push(
            "SNMP: the community contains spaces, which the Net-SNMP plugin does not accept; change it in Services > Net-SNMP".to_string(),
        );
    }
    let bind = text(snmp, "bindip");
    let listen = if bind.is_empty() || bind == "all" {
        String::new()
    } else if bind.parse::<std::net::IpAddr>().is_ok() {
        bind.clone()
    } else {
        let ip = out
            .get_child("interfaces")
            .and_then(|i| i.get_child(&bind))
            .map(|i| text(i, "ipaddr"))
            .unwrap_or_default();
        if ip.parse::<std::net::Ipv4Addr>().is_ok() {
            ip
        } else {
            report.warnings.push(format!(
                "SNMP: bind interface '{bind}' has no static IPv4 address; listening on all addresses"
            ));
            String::new()
        }
    };
    let port = text(snmp, "pollport");
    if !port.is_empty() && port != "161" {
        report.warnings.push(format!(
            "SNMP: pfSense polled on port {port}; the Net-SNMP plugin always uses 161"
        ));
    }
    if !text(snmp, "rwcommunity").is_empty() {
        report.warnings.push(
            "SNMP: the read-write community is not converted (the Net-SNMP plugin has none)"
                .to_string(),
        );
    }
    if snmp.get_child("trapenable").is_some() || !text(snmp, "trapserver").is_empty() {
        report.warnings.push(
            "SNMP: traps are not converted (the Net-SNMP plugin does not send them)".to_string(),
        );
    }
    let lost: Vec<&str> = snmp
        .get_child("modules")
        .map(|m| {
            m.children
                .iter()
                .map(|c| c.tag.as_str())
                .filter(|t| !SNMP_MODULES_COVERED.contains(t))
                .collect()
        })
        .unwrap_or_default();
    if !lost.is_empty() {
        report.warnings.push(format!(
            "SNMP: pfSense's bsnmpd module(s) {} have no Net-SNMP equivalent; monitoring items that read them (for example pf states and counters from the pf module) stop working. Interface, host resource and UCD data stay available",
            lost.join(", ")
        ));
    }

    let Some(model) = model_mut(out, baseline, NETSNMP_MODEL) else {
        return;
    };
    set_path(model, &["enabled"], "1");
    set_path(model, &["community"], &community);
    set_path(model, &["syslocation"], &text(snmp, "syslocation"));
    set_path(model, &["syscontact"], &text(snmp, "syscontact"));
    set_path(model, &["listen"], &listen);
    out.children.retain(|c| c.tag != "snmpd");
    report.converted.push((plugin, label));
}

/// Shellcmd: a `qemu-guest-agent` start command becomes the QEMU guest agent
/// plugin; anything else has no OPNsense equivalent.
fn convert_shellcmds(
    out: &mut XmlNode,
    baseline: &XmlNode,
    packages: &XmlNode,
    name: &str,
    report: &mut PluginReport,
) {
    let commands: Vec<&XmlNode> = packages
        .get_child("shellcmdsettings")
        .map(|s| s.get_children("config"))
        .unwrap_or_default();
    for cmd in commands {
        let line = text(cmd, "cmd");
        if line.contains("qemu-guest-agent") {
            let plugin = "os-qemu-guest-agent".to_string();
            if node_at(baseline, QEMU_MODEL).is_some() {
                if let Some(model) = model_mut(out, baseline, QEMU_MODEL) {
                    set_path(model, &["general", "Enabled"], "1");
                }
                report.converted.push((plugin, format!("{name} ({line})")));
            } else {
                report.missing.push((plugin, format!("{name} ({line})")));
            }
        } else if !line.is_empty() {
            report.warnings.push(format!(
                "{name}: '{line}' ({}) not converted; OPNsense has no shellcmd, use a script in /usr/local/etc/rc.syshook.d/",
                text(cmd, "cmdtype")
            ));
        }
    }
}

/// Put the baseline's `system/firmware` back (the merged `system` section is
/// pfSense's) and add `plugins` to its configured-plugin list.
fn restore_firmware(out: &mut XmlNode, baseline: &XmlNode, plugins: &[String]) {
    let Some(base_fw) = node_at(baseline, &["system", "firmware"]) else {
        return;
    };
    let system = ensure_path(out, &["system"]);
    if system.get_child("firmware").is_none() {
        system.children.push(base_fw.clone());
    }
    if plugins.is_empty() {
        return;
    }
    let fw = ensure_path(system, &["firmware"]);
    let current = text(fw, "plugins");
    let mut list: Vec<String> = current
        .split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    for plugin in plugins {
        if !list.contains(plugin) {
            list.push(plugin.clone());
        }
    }
    set_path(fw, &["plugins"], &list.join(","));
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::from_pfsense;

    const SOURCE: &[u8] = br#"<pfsense>
        <interfaces><opt4><ipaddr>10.0.21.254</ipaddr></opt4></interfaces>
        <installedpackages>
          <package><name>pfBlockerNG-devel</name></package>
          <package><name>Shellcmd</name></package>
          <package><name>Zabbix Agent 7</name><internal_name>zabbix-agent7</internal_name></package>
          <package><name>node_exporter</name></package>
          <shellcmdsettings>
            <config><cmd>service qemu-guest-agent start</cmd><cmdtype>earlyshellcmd</cmdtype></config>
            <config><cmd>/root/fix.sh</cmd><cmdtype>shellcmd</cmdtype></config>
          </shellcmdsettings>
          <zabbixagentlts><config><agentenabled>on</agentenabled><server>10.0.21.245</server><serveractive>10.0.21.245</serveractive>
            <hostname>FW-TEST</hostname><listenip>0.0.0.0</listenip><listenport>10050</listenport><refreshactchecks>120</refreshactchecks>
            <timeout>3</timeout><tlsconnect>psk</tlsconnect><tlsaccept>psk</tlsaccept><tlspskidentity>test_psk</tlspskidentity>
            <tlspskfile>MDEyMzQ1Njc4OWFiY2RlZg==</tlspskfile>
            <userparams>VXNlclBhcmFtZXRlcj1jdXN0b20ucGluZ1sqXSxwaW5nIC1jMSAkMQpVc2VyUGFyYW1ldGVyPWN1c3RvbS51cHRpbWUsdXB0aW1l</userparams></config></zabbixagentlts>
          <nodeexporter><config><enable>on</enable><listen_iface>opt4</listen_iface><listen_port>9100</listen_port>
            <collectors>boottime,cpu,exec,filesystem,loadavg,meminfo,netdev,textfile,time</collectors><extra_flags>--log.level=warn</extra_flags></config></nodeexporter>
        </installedpackages></pfsense>"#;

    #[test]
    fn converts_installed_plugins_and_reports_missing() {
        let baseline = parse(
            br#"<opnsense><system><firmware version="1.0.1"><plugins>os-isc-dhcp</plugins></firmware></system>
                <OPNsense><ZabbixAgent version="1.2.4"><local><hostname>Zabbix agent</hostname></local><settings><main><enabled>0</enabled></main></settings></ZabbixAgent>
                <QemuGuestAgent version="1.0.0"><general><Enabled>1</Enabled></general></QemuGuestAgent></OPNsense></opnsense>"#,
        )
        .expect("parse");
        let source = parse(SOURCE).expect("parse");
        // The merged output has pfSense's <system> (no firmware) and interfaces.
        let mut out = parse(
            br#"<opnsense><system><hostname>x</hostname></system><interfaces><opt4><ipaddr>10.0.21.254</ipaddr></opt4></interfaces>
                <OPNsense><ZabbixAgent version="1.2.4"><local><hostname>Zabbix agent</hostname></local><settings><main><enabled>0</enabled></main></settings></ZabbixAgent></OPNsense></opnsense>"#,
        )
        .expect("parse");

        let report = from_pfsense(&mut out, &source, &baseline);
        let converted: Vec<&str> = report.converted.iter().map(|(p, _)| p.as_str()).collect();
        let missing: Vec<&str> = report.missing.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(converted, ["os-qemu-guest-agent", "os-zabbix7-agent"]);
        assert_eq!(missing, ["os-node_exporter"]);
        assert!(report
            .no_equivalent
            .iter()
            .any(|n| n.starts_with("pfBlockerNG-devel")));
        assert!(report.warnings.iter().any(|w| w.contains("/root/fix.sh")));

        let z = out
            .get_child("OPNsense")
            .unwrap()
            .get_child("ZabbixAgent")
            .unwrap();
        let t = |p: &[&str]| z.get_text(p).unwrap_or("").to_string();
        assert_eq!(t(&["settings", "main", "enabled"]), "1");
        assert_eq!(t(&["local", "hostname"]), "FW-TEST");
        assert_eq!(t(&["settings", "main", "serverList"]), "10.0.21.245");
        assert_eq!(t(&["settings", "features", "enableActiveChecks"]), "1");
        assert_eq!(t(&["settings", "features", "encryption"]), "1");
        assert_eq!(
            t(&["settings", "features", "encryptionidentity"]),
            "test_psk"
        );
        assert_eq!(
            t(&["settings", "features", "encryptionpsk"]),
            "0123456789abcdef"
        );
        let params = z
            .get_child("userparameters")
            .unwrap()
            .get_children("userparameter");
        assert_eq!(params[0].get_text(&["key"]), Some("custom.ping"));
        assert_eq!(params[0].get_text(&["acceptParams"]), Some("1"));
        assert_eq!(params[0].get_text(&["command"]), Some("ping -c1 $1"));
        assert_eq!(params[1].get_text(&["key"]), Some("custom.uptime"));

        let q = out
            .get_child("OPNsense")
            .unwrap()
            .get_child("QemuGuestAgent")
            .unwrap();
        assert_eq!(q.get_text(&["general", "Enabled"]), Some("1"));
        assert_eq!(
            q.attributes.get("version").map(String::as_str),
            Some("1.0.0")
        );

        assert_eq!(
            out.get_text(&["system", "firmware", "plugins"]),
            Some("os-isc-dhcp,os-qemu-guest-agent,os-zabbix7-agent,os-node_exporter")
        );
    }

    #[test]
    fn converts_snmp_when_net_snmp_is_installed() {
        let source = parse(
            br#"<pfsense>
              <interfaces><wan><ipaddr>203.0.113.4</ipaddr></wan></interfaces>
              <snmpd><syslocation>Rack 1</syslocation><syscontact></syscontact><rocommunity>s3cret</rocommunity>
                <modules><mibii/><netgraph/><pf/><hostres/><ucd/><regex/></modules>
                <enable/><pollport>161</pollport><trapserver></trapserver><bindip>wan</bindip></snmpd>
            </pfsense>"#,
        )
        .expect("parse");
        let baseline = parse(
            br#"<opnsense><OPNsense><netsnmp><general version="1.0.7"><enabled>0</enabled><community/><listen/></general></netsnmp></OPNsense></opnsense>"#,
        )
        .expect("parse");
        let mut out = parse(
            br#"<opnsense><interfaces><wan><ipaddr>203.0.113.4</ipaddr></wan></interfaces>
              <snmpd><enable/></snmpd>
              <OPNsense><netsnmp><general version="1.0.7"><enabled>0</enabled><community/><listen/></general></netsnmp></OPNsense></opnsense>"#,
        )
        .expect("parse");
        let report = from_pfsense(&mut out, &source, &baseline);
        assert_eq!(
            report.converted,
            vec![("os-net-snmp".to_string(), "SNMP daemon".to_string())]
        );
        let get = |tag: &str| out.get_text(&["OPNsense", "netsnmp", "general", tag]);
        assert_eq!(get("enabled"), Some("1"));
        assert_eq!(get("community"), Some("s3cret"));
        assert_eq!(get("syslocation"), Some("Rack 1"));
        assert_eq!(get("listen"), Some("203.0.113.4"));
        assert!(out.get_child("snmpd").is_none());
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("netgraph, pf, regex")));

        // Without the plugin in the baseline it is reported as missing.
        let bare = parse(b"<opnsense/>").expect("parse");
        let mut out2 = parse(b"<opnsense/>").expect("parse");
        let report2 = from_pfsense(&mut out2, &source, &bare);
        assert_eq!(report2.missing[0].0, "os-net-snmp");
    }

    #[test]
    fn converts_node_exporter_when_installed() {
        let baseline = parse(
            br#"<opnsense><OPNsense><NodeExporter version="0.2.0"><enabled>0</enabled><listenaddress>0.0.0.0</listenaddress><listenport>9100</listenport></NodeExporter></OPNsense></opnsense>"#,
        )
        .expect("parse");
        let source = parse(SOURCE).expect("parse");
        let mut out = parse(
            br#"<opnsense><interfaces><opt4><ipaddr>10.0.21.254</ipaddr></opt4></interfaces></opnsense>"#,
        )
        .expect("parse");
        let report = from_pfsense(&mut out, &source, &baseline);
        assert!(report
            .converted
            .iter()
            .any(|(p, _)| p == "os-node_exporter"));
        let n = out
            .get_child("OPNsense")
            .unwrap()
            .get_child("NodeExporter")
            .unwrap();
        assert_eq!(n.get_text(&["enabled"]), Some("1"));
        assert_eq!(n.get_text(&["listenaddress"]), Some("10.0.21.254"));
        assert_eq!(n.get_text(&["cpu"]), Some("1"));
        assert_eq!(n.get_text(&["zfs"]), Some("0"));
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("boottime, textfile")));
        assert!(report.warnings.iter().any(|w| w.contains("extra flags")));
    }

    #[test]
    fn converts_zabbix_proxy_when_installed() {
        let source = parse(
            br#"<pfsense><installedpackages>
              <package><name>Zabbix Proxy 7</name><internal_name>zabbix-proxy7</internal_name></package>
              <zabbixproxylts><config><proxyenabled>on</proxyenabled><server>zabbix.example.net</server><serverport>10051</serverport>
                <hostname>FW Proxy</hostname><listenip>10.0.21.254</listenip><listenport>10051</listenport><proxymode>0</proxymode>
                <configfrequency>3600</configfrequency><trappertimeout>300</trappertimeout><starttrappers>5</starttrappers>
                <tlsconnect>psk</tlsconnect><tlsaccept>unencrypted</tlsaccept><tlspskidentity>fw_proxy</tlspskidentity>
                <tlspskfile>MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=</tlspskfile>
                <startsnmptrapper>0</startsnmptrapper><advancedparams></advancedparams></config></zabbixproxylts>
            </installedpackages></pfsense>"#,
        )
        .expect("parse");
        let baseline = parse(
            br#"<opnsense><OPNsense><zabbixproxy><general version="2.0.4"><enabled>0</enabled><hostname>Zabbix proxy</hostname></general></zabbixproxy></OPNsense></opnsense>"#,
        )
        .expect("parse");
        let mut out = baseline.clone();
        let report = from_pfsense(&mut out, &source, &baseline);

        assert_eq!(
            report.converted,
            vec![("os-zabbix7-proxy".to_string(), "Zabbix Proxy 7".to_string())]
        );
        let get = |tag: &str| out.get_text(&["OPNsense", "zabbixproxy", "general", tag]);
        assert_eq!(get("enabled"), Some("1"));
        assert_eq!(get("proxymode"), Some("0"));
        assert_eq!(get("server"), Some("zabbix.example.net"));
        assert_eq!(get("hostname"), Some("FW Proxy"));
        assert_eq!(get("listenip"), Some("10.0.21.254"));
        assert_eq!(get("starttrappers"), Some("5"));
        assert_eq!(get("encryption"), Some("1"));
        assert_eq!(get("encryptionidentity"), Some("fw_proxy"));
        assert_eq!(
            get("encryptionpsk"),
            Some("0123456789abcdef0123456789abcdef")
        );
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    }
}
