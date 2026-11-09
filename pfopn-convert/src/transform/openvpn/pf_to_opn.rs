use std::net::IpAddr;

use xml_diff_core::XmlNode;

use super::common::{
    bool_to_01, is_truthy, set_or_insert_text_child, source_assigned_ovpns_units,
    synthetic_uuid_for_id, text_or,
};
use crate::transform::mvc_util::decode_base64;

/// Ciphers OPNsense's Instance model accepts for `data-ciphers` and
/// `data-ciphers-fallback` (OpenVPN/OpenVPN.xml, 26.7).
const DATA_CIPHERS: &[&str] = &[
    "AES-128-GCM",
    "AES-192-GCM",
    "AES-256-GCM",
    "CHACHA20-POLY1305",
    "AES-128-CBC",
    "AES-192-CBC",
    "AES-256-CBC",
    "AES-128-CFB",
    "AES-192-CFB",
    "AES-256-CFB",
    "AES-128-CFB1",
    "AES-192-CFB1",
    "AES-256-CFB1",
    "AES-128-CFB8",
    "AES-192-CFB8",
    "AES-256-CFB8",
    "AES-128-OFB",
    "AES-192-OFB",
    "AES-256-OFB",
];

/// Digests OPNsense's Instance model accepts for `auth`.
const DIGESTS: &[&str] = &[
    "BLAKE2b512",
    "BLAKE2s256",
    "MD4",
    "MD5",
    "MD5-SHA1",
    "RIPEMD160",
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "SHA384",
    "SHA512",
    "SHA512-224",
    "SHA512-256",
    "SHAKE128",
    "SHAKE256",
    "whirlpool",
    "none",
];

const PROTOCOLS: &[&str] = &["udp", "udp4", "udp6", "tcp", "tcp4", "tcp6"];

/// Result of mapping pfSense's legacy OpenVPN config onto OPNsense's model.
#[derive(Debug)]
pub(super) struct PfMapping {
    /// `<Instances>` with one `<Instance>` per converted server.
    pub instances: XmlNode,
    /// `<StaticKey>` entries for the servers' TLS keys.
    pub static_keys: Vec<XmlNode>,
    /// `<Overwrite>` entries converted from `openvpn-csc`.
    pub overwrites: Vec<XmlNode>,
    /// vpnids of the legacy servers that were converted (to drop from `<openvpn>`).
    pub converted_vpnids: Vec<String>,
    /// Whether `openvpn-csc` entries were converted (to drop from `<openvpn>`).
    pub csc_converted: bool,
    pub warnings: Vec<String>,
}

/// Map pfSense OpenVPN servers and client-specific overrides onto OPNsense's
/// OpenVPN model (`OPNsense/OpenVPN`: Instances, StaticKeys, Overwrites).
///
/// OPNsense 26.7 only runs legacy `<openvpn-server>` entries when the
/// `os-openvpn-legacy` plugin is installed (`openvpn_legacy()` checks for its
/// `vpn_openvpn_server.php`), so without this mapping the servers would not
/// start. Field semantics follow how OPNsense's legacy code turned the same
/// settings into an OpenVPN config (`plugins.inc.d/openvpn.inc`):
///
/// - `mode`: `server_user` → `verify_client_cert=none` + `authmode`;
///   `server_tls_user` → client certificate required + `authmode`;
///   `server_tls`/`p2p_tls` → client certificate required. Shared-key modes
///   have no instance equivalent and are left in the legacy format.
/// - `tls` (base64 key) + `tls_type` → a `StaticKey` (`auth`/`crypt`) linked
///   through `tls_key`.
/// - `interface` → `local` (the interface's or VIP's address, as the legacy
///   code bound to it); `any` or a dynamic address → unset (multihome).
/// - `gwredir`/`gwredir6` → `redirect_gateway`; `client2client`,
///   `dynamic_ip`, `duplicate_cn`, `passtos`, `exit_notify` → `various_flags`.
///
/// OpenVPN clients are not converted (warning; they stay in `<openvpn>`).
/// `openvpn-csc` entries are converted like OPNsense's own migration
/// (`OpenVPN/Migrations/M1_0_0.php`), which does not run on an imported
/// config because the baseline's model is already newer.
pub(super) fn map_pfsense_openvpn(source: &XmlNode) -> PfMapping {
    let mut result = PfMapping {
        instances: XmlNode::new("Instances"),
        static_keys: Vec::new(),
        overwrites: Vec::new(),
        converted_vpnids: Vec::new(),
        csc_converted: false,
        warnings: Vec::new(),
    };
    let Some(openvpn) = source.get_child("openvpn") else {
        return result;
    };

    let assigned_units = source_assigned_ovpns_units(source);
    let servers = openvpn.get_children("openvpn-server");
    let server_count = servers.len();
    // vpnid -> instance uuid, for client-specific overrides
    let mut uuid_by_vpnid: Vec<(String, String)> = Vec::new();

    for (idx, server) in servers.into_iter().enumerate() {
        let descr = text_or(server, &["description"], "");
        let label = if descr.is_empty() {
            format!("vpnid {}", text_or(server, &["vpnid"], "?"))
        } else {
            descr.clone()
        };
        let mode = text_or(server, &["mode"], "");
        if matches!(mode.as_str(), "p2p_shared_key" | "shared_key") {
            result.warnings.push(format!(
                "OpenVPN server '{label}': shared-key mode has no OPNsense instance equivalent; left in the legacy format (needs the os-openvpn-legacy plugin, or recreate it with TLS)"
            ));
            continue;
        }

        // Map this server to an interface assignment to keep its device (ovpnsN).
        let mapped_unit = if assigned_units.len() == server_count && idx < assigned_units.len() {
            Some(assigned_units[idx].clone())
        } else if server_count == 1 && assigned_units.len() == 1 {
            Some(assigned_units[0].clone())
        } else {
            None
        };
        let source_vpnid = text_or(server, &["vpnid"], "1");
        let vpnid = mapped_unit.unwrap_or_else(|| source_vpnid.clone());

        let uuid = text_or(server, &["opnsense_instance_uuid"], "");
        let uuid = if uuid.is_empty() {
            synthetic_uuid_for_id(&vpnid, result.instances.children.len())
        } else {
            uuid
        };
        let mut warn = |msg: String| {
            result
                .warnings
                .push(format!("OpenVPN server '{label}': {msg}"))
        };

        let mut inst = XmlNode::new("Instance");
        inst.attributes.insert("uuid".to_string(), uuid.clone());
        let mut set = |tag: &str, value: &str| set_or_insert_text_child(&mut inst, tag, value);

        set("vpnid", &vpnid);
        set(
            "enabled",
            if server.get_child("disable").is_some() {
                "0"
            } else {
                "1"
            },
        );
        set("role", "server");
        set("description", &descr);

        let dev_mode = text_or(server, &["dev_mode"], "tun").to_ascii_lowercase();
        let dco = is_truthy(text_or(server, &["dco"], ""));
        set(
            "dev_type",
            if dco && dev_mode == "tun" {
                "ovpn"
            } else {
                dev_mode.as_str()
            },
        );
        let proto = text_or(server, &["protocol"], "udp").to_ascii_lowercase();
        if PROTOCOLS.contains(&proto.as_str()) {
            set("proto", &proto);
        } else {
            warn(format!(
                "protocol '{proto}' not supported by OPNsense; using udp"
            ));
            set("proto", "udp");
        }
        set("port", &text_or(server, &["local_port"], ""));
        let topology = text_or(server, &["topology"], "subnet");
        set(
            "topology",
            if matches!(topology.as_str(), "net30" | "p2p" | "subnet") {
                topology.as_str()
            } else {
                "subnet"
            },
        );
        let verb = text_or(server, &["verbosity_level"], "");
        if verb.parse::<u8>().is_ok_and(|v| v <= 11) {
            set("verb", &verb);
        }

        // Bind address
        let interface = text_or(server, &["interface"], "any");
        match bind_address(source, server, &interface, &proto) {
            Bind::Address(ip) => set("local", &ip),
            Bind::All => {}
            Bind::Dynamic => warn(format!(
                "bound to '{interface}', which has no static address; OPNsense will listen on all addresses (multihome)"
            )),
        }

        // Tunnel and routes
        set("server", &text_or(server, &["tunnel_network"], ""));
        set("server_ipv6", &text_or(server, &["tunnel_networkv6"], ""));
        set(
            "push_route",
            &join_networks(server, &["local_network", "local_networkv6"]),
        );
        set(
            "route",
            &join_networks(server, &["remote_network", "remote_networkv6"]),
        );
        let maxclients = text_or(server, &["maxclients"], "");
        if maxclients.parse::<u32>().is_ok() {
            set("maxclients", &maxclients);
        }

        // Certificates and client verification
        set("ca", &text_or(server, &["caref"], ""));
        set("cert", &text_or(server, &["certref"], ""));
        set("crl", &text_or(server, &["crlref"], ""));
        set("cert_depth", &text_or(server, &["cert_depth"], ""));
        // isset() in pfSense: an empty element means "on".
        set(
            "remote_cert_tls",
            bool_to_01(server.get_child("remote_cert_tls").is_some()),
        );
        set(
            "verify_client_cert",
            if mode == "server_user" {
                "none"
            } else {
                "require"
            },
        );
        set("use_ocsp", "0");
        if !text_or(server, &["ocspurl"], "").is_empty() {
            warn("OCSP URL not converted (OPNsense uses the CA's OCSP settings; enable 'Use OCSP' by hand if needed)".to_string());
        }

        // User authentication
        let user_mode = mode.contains("user");
        let authmode = text_or(server, &["authmode"], "")
            .split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>()
            .join(",");
        if user_mode {
            if authmode.is_empty() {
                warn("user authentication mode without an authentication server".to_string());
            }
            set("authmode", &authmode);
        }
        // pfSense: server_user needs "enabled"; server_tls_user anything but "disabled".
        let uacn = text_or(server, &["username_as_common_name"], "");
        set(
            "username_as_common_name",
            bool_to_01(
                dev_mode != "tap"
                    && match mode.as_str() {
                        "server_user" => uacn == "enabled",
                        "server_tls_user" => uacn != "disabled",
                        _ => false,
                    },
            ),
        );
        set(
            "strictusercn",
            bool_to_01(is_truthy(text_or(server, &["strictusercn"], ""))),
        );

        // Crypto
        let (ciphers, dropped) = filter_ciphers(&text_or(server, &["data_ciphers"], ""));
        if !dropped.is_empty() {
            warn(format!(
                "data cipher(s) {} not supported by OPNsense; dropped",
                dropped.join(", ")
            ));
        }
        set("data-ciphers", &ciphers.join(","));
        let fallback = text_or(server, &["data_ciphers_fallback"], "");
        if DATA_CIPHERS.contains(&fallback.as_str()) {
            set("data-ciphers-fallback", &fallback);
        } else if !fallback.is_empty() && fallback != "none" {
            warn(format!(
                "fallback cipher '{fallback}' not supported by OPNsense; dropped"
            ));
        }
        let digest = text_or(server, &["digest"], "");
        // pfSense (and OPNsense's legacy code) default to SHA1 when unset.
        let digest = if digest.is_empty() {
            "SHA1".to_string()
        } else {
            digest
        };
        match DIGESTS.iter().find(|d| d.eq_ignore_ascii_case(&digest)) {
            Some(d) => set("auth", d),
            None => warn(format!(
                "digest '{digest}' not supported by OPNsense; OpenVPN's default is used"
            )),
        }

        // TLS key
        let tls = text_or(server, &["tls"], "");
        if !tls.is_empty() {
            match decode_base64(&tls).filter(|k| k.contains("OpenVPN Static key")) {
                Some(key) => {
                    let key_mode = if text_or(server, &["tls_type"], "auth") == "crypt" {
                        "crypt"
                    } else {
                        "auth"
                    };
                    let keydir = text_or(server, &["tlsauth_keydir"], "default");
                    if key_mode == "auth" && !matches!(keydir.as_str(), "" | "default" | "0") {
                        warn(format!(
                            "TLS auth key direction '{keydir}' not converted; OPNsense uses direction 0 on the server (clients need key-direction 1)"
                        ));
                    }
                    let key_uuid = static_key_uuid(&vpnid, result.static_keys.len());
                    let mut sk = XmlNode::new("StaticKey");
                    sk.attributes.insert("uuid".to_string(), key_uuid.clone());
                    set_or_insert_text_child(&mut sk, "mode", key_mode);
                    set_or_insert_text_child(&mut sk, "key", key.trim_end().to_string());
                    set_or_insert_text_child(&mut sk, "description", format!("{label} TLS key"));
                    result.static_keys.push(sk);
                    set("tls_key", &key_uuid);
                }
                None => warn("TLS key could not be decoded; not converted".to_string()),
            }
        }

        // Pushed options
        let mut redirect = Vec::new();
        if is_truthy(text_or(server, &["gwredir"], "")) {
            redirect.push("def1");
        }
        if is_truthy(text_or(server, &["gwredir6"], "")) {
            redirect.push("ipv6");
        }
        set("redirect_gateway", &redirect.join(","));
        set(
            "register_dns",
            bool_to_01(is_truthy(text_or(server, &["push_register_dns"], ""))),
        );
        let mut push_flags = Vec::new();
        if is_truthy(text_or(server, &["push_blockoutsidedns"], "")) {
            push_flags.push("block-outside-dns");
        }
        set("various_push_flags", &push_flags.join(","));
        set("dns_domain", &text_or(server, &["dns_domain"], ""));
        set(
            "dns_domain_search",
            &text_or(server, &["dns_domain_search"], ""),
        );
        set(
            "dns_servers",
            &gather_fields(
                server,
                &["dns_server1", "dns_server2", "dns_server3", "dns_server4"],
            )
            .join(","),
        );
        set(
            "ntp_servers",
            &gather_fields(server, &["ntp_server1", "ntp_server2"]).join(","),
        );
        let inactive = text_or(server, &["inactive_seconds"], "0");
        if inactive.parse::<u32>().is_ok_and(|v| v > 0) {
            set("push_inactive", &inactive);
        }

        // Flags
        let mut flags = Vec::new();
        if is_truthy(text_or(server, &["client2client"], "")) {
            flags.push("client-to-client");
        }
        // pfSense tests this one with isset(): an empty element means "on".
        if server.get_child("duplicate_cn").is_some() {
            flags.push("duplicate-cn");
        }
        if is_truthy(text_or(server, &["dynamic_ip"], "")) {
            flags.push("float");
            flags.push("persist-remote-ip");
        }
        if is_truthy(text_or(server, &["passtos"], "")) {
            flags.push("passtos");
        }
        let exit_notify = text_or(server, &["exit_notify"], "none");
        if !matches!(exit_notify.as_str(), "" | "none") && proto.starts_with("udp") {
            flags.push("explicit-exit-notify");
        }
        set("various_flags", &flags.join(","));

        // Keepalive
        let ping_method = text_or(server, &["ping_method"], "keepalive");
        let (interval, timeout) = if ping_method == "ping" {
            warn("ping/ping-restart settings converted to keepalive".to_string());
            (
                text_or(server, &["ping_seconds"], ""),
                text_or(server, &["ping_action_seconds"], ""),
            )
        } else {
            (
                text_or(server, &["keepalive_interval"], ""),
                text_or(server, &["keepalive_timeout"], ""),
            )
        };
        if interval.parse::<u32>().is_ok() && timeout.parse::<u32>().is_ok() {
            set("keepalive_interval", &interval);
            set("keepalive_timeout", &timeout);
        }

        // Compression: OPNsense instances cannot enable it; "compress migrate"
        // tells clients that still compress to stop.
        let compression = text_or(server, &["compression"], "");
        if !matches!(compression.as_str(), "" | "none" | "no") {
            set("compress_migrate", "1");
            warn(format!(
                "compression '{compression}' is not supported by OPNsense instances; set to 'compress migrate' (remove compression from client configs)"
            ));
        } else if text_or(server, &["allow_compression"], "asym") == "yes" {
            warn("'allow compression' not supported by OPNsense instances; clients that compress will fail".to_string());
        }

        // Settings without an instance equivalent
        let custom = text_or(server, &["custom_options"], "");
        if !custom.is_empty() {
            warn(format!(
                "custom options not converted (OPNsense instances have none): {}",
                custom.replace(['\r', '\n'], " ")
            ));
        }
        if is_truthy(text_or(server, &["netbios_enable"], "")) {
            warn(
                "NetBIOS/WINS options not converted (not supported by OPNsense instances)"
                    .to_string(),
            );
        }
        if dev_mode == "tap" && !text_or(server, &["serverbridge_dhcp"], "").is_empty() {
            warn(
                "bridged (tap) DHCP settings not converted; set Bridge gateway/pool by hand"
                    .to_string(),
            );
        }
        for (field, what) in [
            ("connlimit", "per-client connection limit"),
            ("sndrcvbuf", "send/receive buffer"),
        ] {
            if !text_or(server, &[field], "").is_empty() {
                warn(format!("{what} not converted"));
            }
        }

        set("provision_exclusive", "0");
        result.instances.children.push(inst);
        result.converted_vpnids.push(source_vpnid.clone());
        uuid_by_vpnid.push((source_vpnid, uuid));
    }

    let clients = openvpn.get_children("openvpn-client");
    if !clients.is_empty() {
        result.warnings.push(format!(
            "{} OpenVPN client(s) not converted; they stay in the legacy format (needs the os-openvpn-legacy plugin) or recreate them under VPN > OpenVPN > Instances",
            clients.len()
        ));
    }

    for (idx, csc) in openvpn.get_children("openvpn-csc").into_iter().enumerate() {
        result
            .overwrites
            .push(csc_to_overwrite(csc, idx, &uuid_by_vpnid));
    }
    result.csc_converted = !result.overwrites.is_empty();
    result
}

/// One `openvpn-csc` entry as an OPNsense `Overwrite`, mirroring
/// `OpenVPN/Migrations/M1_0_0.php`. Server references (vpnids) point to the
/// converted instances' UUIDs; unconverted ones keep their vpnid, which
/// OPNsense resolves against legacy servers.
fn csc_to_overwrite(csc: &XmlNode, idx: usize, uuid_by_vpnid: &[(String, String)]) -> XmlNode {
    let mut ow = XmlNode::new("Overwrite");
    ow.attributes.insert(
        "uuid".to_string(),
        format!("00000000-0000-4000-a000-{:012x}", idx + 1),
    );
    let mut set = |tag: &str, value: &str| set_or_insert_text_child(&mut ow, tag, value);
    set(
        "enabled",
        if text_or(csc, &["disable"], "").is_empty() && csc.get_child("disable").is_none() {
            "1"
        } else {
            "0"
        },
    );
    let servers = text_or(csc, &["ovpn_servers"], "")
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|vpnid| {
            uuid_by_vpnid
                .iter()
                .find(|(id, _)| id == vpnid)
                .map(|(_, uuid)| uuid.clone())
                .unwrap_or_else(|| vpnid.to_string())
        })
        .collect::<Vec<_>>()
        .join(",");
    set("servers", &servers);
    set("common_name", &text_or(csc, &["common_name"], ""));
    set("description", &text_or(csc, &["description"], ""));
    for field in ["tunnel_network", "tunnel_networkv6"] {
        let value = text_or(csc, &[field], "");
        if is_network(&value) {
            set(field, &value);
        }
    }
    for kind in ["local", "remote"] {
        let nets = [format!("{kind}_network"), format!("{kind}_networkv6")]
            .iter()
            .flat_map(|f| {
                text_or(csc, &[f.as_str()], "")
                    .split(',')
                    .map(|v| v.trim().to_string())
                    .collect::<Vec<_>>()
            })
            .filter(|v| !v.is_empty() && is_network(v))
            .collect::<Vec<_>>()
            .join(",");
        set(&format!("{kind}_networks"), &nets);
    }
    if !text_or(csc, &["gwredir"], "").is_empty() {
        set("redirect_gateway", "def1");
    }
    set(
        "push_reset",
        bool_to_01(!text_or(csc, &["push_reset"], "").is_empty()),
    );
    set(
        "block",
        bool_to_01(!text_or(csc, &["block"], "").is_empty()),
    );
    set("dns_domain", &text_or(csc, &["dns_domain"], ""));
    set(
        "dns_domain_search",
        &text_or(csc, &["dns_domain_search"], ""),
    );
    for (prefix, target) in [
        ("dns_server", "dns_servers"),
        ("ntp_server", "ntp_servers"),
        ("wins_server", "wins_servers"),
    ] {
        let names: Vec<String> = (1..=4).map(|i| format!("{prefix}{i}")).collect();
        let keys: Vec<&str> = names.iter().map(String::as_str).collect();
        set(target, &gather_fields(csc, &keys).join(","));
    }
    ow
}

enum Bind {
    Address(String),
    All,
    Dynamic,
}

/// The address the legacy code bound a server to: an explicit `ipaddr`, else
/// the selected interface's (or VIP's) address for the protocol's family.
fn bind_address(source: &XmlNode, server: &XmlNode, interface: &str, proto: &str) -> Bind {
    let ipaddr = text_or(server, &["ipaddr"], "");
    if ipaddr.parse::<IpAddr>().is_ok() {
        return Bind::Address(ipaddr);
    }
    if interface.is_empty() || interface == "any" {
        return Bind::All;
    }
    let want_v6 = proto.ends_with('6');
    // pfSense VIP references: "_vip<uniqid>" or "<iface>_vip<vhid>".
    if let Some(pos) = interface.find("_vip") {
        let key = &interface[pos + 4..];
        let vip = source
            .get_child("virtualip")
            .map(|v| v.get_children("vip"))
            .unwrap_or_default()
            .into_iter()
            .find(|v| {
                text_or(v, &["uniqid"], "") == key
                    || (pos > 0
                        && text_or(v, &["interface"], "") == interface[..pos]
                        && text_or(v, &["vhid"], "") == key)
            });
        return match vip.map(|v| text_or(v, &["subnet"], "")) {
            Some(ip) if ip.parse::<IpAddr>().is_ok() => Bind::Address(ip),
            _ => Bind::Dynamic,
        };
    }
    let field = if want_v6 { "ipaddrv6" } else { "ipaddr" };
    let ip = source
        .get_child("interfaces")
        .and_then(|i| i.get_child(interface))
        .map(|i| text_or(i, &[field], ""))
        .unwrap_or_default();
    if ip.parse::<IpAddr>().is_ok() {
        Bind::Address(ip)
    } else {
        Bind::Dynamic
    }
}

fn filter_ciphers(list: &str) -> (Vec<String>, Vec<String>) {
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for cipher in list.split(',').map(str::trim).filter(|c| !c.is_empty()) {
        match DATA_CIPHERS.iter().find(|c| c.eq_ignore_ascii_case(cipher)) {
            Some(c) => kept.push((*c).to_string()),
            None => dropped.push(cipher.to_string()),
        }
    }
    (kept, dropped)
}

/// Comma-separated networks from several fields, trimmed.
fn join_networks(node: &XmlNode, fields: &[&str]) -> String {
    fields
        .iter()
        .flat_map(|f| {
            text_or(node, &[f], "")
                .split(',')
                .map(|v| v.trim().to_string())
                .collect::<Vec<_>>()
        })
        .filter(|v| !v.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}

fn is_network(value: &str) -> bool {
    match value.split_once('/') {
        Some((ip, prefix)) => {
            let Ok(addr) = ip.parse::<IpAddr>() else {
                return false;
            };
            let max = if addr.is_ipv4() { 32 } else { 128 };
            prefix.parse::<u8>().is_ok_and(|p| p <= max)
        }
        None => value.parse::<IpAddr>().is_ok(),
    }
}

fn static_key_uuid(vpnid: &str, index: usize) -> String {
    let digits: String = vpnid.chars().filter(|c| c.is_ascii_digit()).collect();
    let id = digits.parse::<u64>().unwrap_or((index + 1) as u64);
    format!("00000000-0000-4000-9000-{:012x}", id % 0x1_0000_0000_0000)
}

/// Non-empty values of several fields, in order.
fn gather_fields(node: &XmlNode, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .filter_map(|key| {
            node.get_text(&[key])
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
        .collect()
}
