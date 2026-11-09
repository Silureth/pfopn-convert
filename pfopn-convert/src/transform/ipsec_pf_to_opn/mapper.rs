use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use xml_diff_core::XmlNode;

use super::base::{base_opnsense_ipsec, base_swanctl, push_to_ipsec_psk, push_to_swanctl};
use super::proposals::{esp_proposals, ike_proposals};
use super::util::{enabled_from_disabled, push_text_child, stable_uuid, text_or};

/// Result of mapping pfSense's legacy IPsec tunnels onto OPNsense's model.
#[derive(Debug)]
pub struct IpsecMapping {
    /// `OPNsense/IPsec`: the baseline's settings plus the tunnels' pre-shared keys.
    pub ipsec: XmlNode,
    /// `OPNsense/Swanctl`: the baseline's entries plus the converted tunnels.
    pub swanctl: XmlNode,
    /// `<ikeid>` texts of the converted phase1 entries, as written in the
    /// source ("" when missing), to drop them from the legacy `<ipsec>`.
    pub converted_ikeids: Vec<String>,
    /// Whether any converted connection is enabled (OPNsense needs `<ipsec><enable>`).
    pub any_enabled: bool,
    /// pfSense-format `<rule>`s allowing IKE/NAT-T/ESP/AH from each peer; pfSense
    /// adds these automatically, OPNsense only does so for legacy tunnels.
    pub firewall_rules: Vec<XmlNode>,
    pub warnings: Vec<String>,
}

/// Map pfSense phase1/phase2 tunnels onto OPNsense's Swanctl model.
///
/// OPNsense 26.7 only runs legacy `<phase1>` tunnels when the
/// os-strongswan-legacy plugin is installed (`ipsec_legacy()` checks for its
/// `vpn_ipsec_phase1.php`). Field semantics follow pfSense's own swanctl
/// generation (`ipsec_setup_tunnels()`, `ipsec_find_id()`,
/// `ipsec_idinfo_to_cidr()`, `ipsec_get_*_time()` in pfSense 2.7 `ipsec.inc`):
///
/// - proposals are built per encryption item as pfSense does
///   (`<alg><keylen>-<hash>[-prf<prf>]-<dh>`), renamed to OPNsense's
///   spelling (`aes256gcm128` → `aes256gcm16`, `curve25519` → `x25519`) and
///   kept only when OPNsense's proposal list offers them;
/// - IDs: `myaddress` → the interface address, `peeraddress` → the remote
///   gateway, other types with pfSense's `type:` prefixes;
/// - traffic selectors: an interface name (e.g. `lan`) means its subnet;
/// - IKEv2 tunnels without "split connections" become one child holding all
///   phase2 selectors (as pfSense does), IKEv1 tunnels one child per phase2;
/// - rekey/reauth/over time, DPD, start/close/DPD actions as pfSense derives them.
///
/// Mobile (remote access) tunnels and VTI phase2 entries are not converted
/// (warnings); they stay in the legacy section.
pub fn map_pf_ipsec_to_opnsense(
    source: &XmlNode,
    baseline_ipsec: Option<&XmlNode>,
    baseline_swanctl: Option<&XmlNode>,
) -> IpsecMapping {
    let mut ipsec = baseline_ipsec.cloned().unwrap_or_else(base_opnsense_ipsec);
    ipsec.tag = "IPsec".to_string();
    if ipsec.get_child("preSharedKeys").is_none() {
        ipsec.children.push(XmlNode::new("preSharedKeys"));
    }
    let mut swanctl = baseline_swanctl.cloned().unwrap_or_else(base_swanctl);
    swanctl.tag = "Swanctl".to_string();
    for bucket in ["Connections", "locals", "remotes", "children"] {
        if swanctl.get_child(bucket).is_none() {
            swanctl.children.push(XmlNode::new(bucket));
        }
    }

    let mut result = IpsecMapping {
        ipsec,
        swanctl,
        converted_ikeids: Vec::new(),
        any_enabled: false,
        firewall_rules: Vec::new(),
        warnings: Vec::new(),
    };
    let Some(top) = source.get_child("ipsec") else {
        return result;
    };
    let auto_rules = source
        .get_child("system")
        .and_then(|s| s.get_child("disablevpnrules"))
        .is_none();
    let uniqueids = text_or(top, "uniqueids", "");
    let unique = if matches!(uniqueids, "no" | "never" | "keep" | "replace") {
        uniqueids
    } else {
        "replace"
    };
    let phase2s: Vec<&XmlNode> = top.get_children("phase2");

    for (idx, p1) in top.get_children("phase1").into_iter().enumerate() {
        let raw_ikeid = text_or(p1, "ikeid", "").to_string();
        let ikeid = if raw_ikeid.is_empty() {
            (idx + 1).to_string()
        } else {
            raw_ikeid.clone()
        };
        let remote_gw = text_or(p1, "remote-gateway", "").to_string();
        let descr = text_or(p1, "descr", "").to_string();
        let label = if descr.is_empty() {
            format!("ikeid {ikeid}")
        } else {
            descr.clone()
        };
        let mut warn = |msg: String| result.warnings.push(format!("IPsec '{label}': {msg}"));

        if p1.get_child("mobile").is_some() {
            warn("mobile (remote access) tunnel not converted; it stays in the legacy format (needs os-strongswan-legacy) or recreate it under VPN > IPsec > Connections".to_string());
            continue;
        }
        let my_p2s: Vec<&XmlNode> = phase2s
            .iter()
            .copied()
            .filter(|p2| text_or(p2, "ikeid", "") == ikeid)
            .collect();
        if my_p2s.iter().any(|p2| text_or(p2, "mode", "") == "vti") {
            warn("route-based (VTI) phase 2 not converted; it stays in the legacy format (recreate it with VPN > IPsec > Virtual Tunnel Interfaces)".to_string());
            continue;
        }

        let enabled = enabled_from_disabled(p1);
        let version = match text_or(p1, "iketype", "ikev1") {
            "auto" => "0",
            "ikev2" => "2",
            _ => "1",
        };
        let protocol = text_or(p1, "protocol", "inet");
        let interface = text_or(p1, "interface", "wan");
        let local_addr = interface_address(source, interface, protocol == "inet6");
        if local_addr.is_none() {
            warn(format!(
                "interface '{interface}' has no static address; local address left empty (any)"
            ));
        }

        // Proposals
        let (proposals, dropped) = ike_proposals(p1);
        for d in &dropped {
            warn(format!("IKE proposal {d}"));
        }
        let proposals = if proposals.is_empty() {
            warn("no IKE proposal OPNsense supports; using 'default'".to_string());
            "default".to_string()
        } else {
            proposals.join(",")
        };

        // Lifetimes (pfSense ipsec_get_*_time)
        let times = SaTimes::phase1(p1);
        let dpd_delay = text_or(p1, "dpd_delay", "");
        let dpd_maxfail = text_or(p1, "dpd_maxfail", "");
        let dpd = !dpd_delay.is_empty() && !dpd_maxfail.is_empty();

        let conn_uuid = stable_uuid("conn", idx, &ikeid);
        let mut conn = XmlNode::new("Connection");
        conn.attributes
            .insert("uuid".to_string(), conn_uuid.clone());
        push_text_child(&mut conn, "enabled", enabled);
        push_text_child(&mut conn, "proposals", &proposals);
        push_text_child(&mut conn, "unique", unique);
        push_text_child(
            &mut conn,
            "aggressive",
            if version != "2" && text_or(p1, "mode", "main") == "aggressive" {
                "1"
            } else {
                "0"
            },
        );
        push_text_child(&mut conn, "version", version);
        push_text_child(
            &mut conn,
            "mobike",
            if text_or(p1, "mobike", "off") == "on" {
                "1"
            } else {
                "0"
            },
        );
        push_text_child(
            &mut conn,
            "local_addrs",
            local_addr.as_ref().map(|(ip, _)| ip.as_str()).unwrap_or(""),
        );
        push_text_child(&mut conn, "local_port", "");
        push_text_child(&mut conn, "remote_addrs", &remote_gw);
        push_text_child(&mut conn, "remote_port", "");
        push_text_child(
            &mut conn,
            "encap",
            if text_or(p1, "nat_traversal", "on") == "force" {
                "1"
            } else {
                "0"
            },
        );
        push_text_child(&mut conn, "reauth_time", &times.reauth.to_string());
        push_text_child(
            &mut conn,
            "rekey_time",
            &if version == "1" {
                String::new()
            } else {
                times.rekey.to_string()
            },
        );
        push_text_child(&mut conn, "over_time", &times.over.to_string());
        push_text_child(&mut conn, "dpd_delay", if dpd { dpd_delay } else { "" });
        let dpd_timeout = if dpd && version == "1" {
            match (dpd_delay.parse::<u64>(), dpd_maxfail.parse::<u64>()) {
                (Ok(d), Ok(m)) => (d * (m + 1)).to_string(),
                _ => String::new(),
            }
        } else {
            String::new()
        };
        push_text_child(&mut conn, "dpd_timeout", &dpd_timeout);
        push_text_child(&mut conn, "pools", "");
        push_text_child(&mut conn, "send_certreq", "1");
        push_text_child(&mut conn, "send_cert", "");
        push_text_child(&mut conn, "keyingtries", "");
        push_text_child(
            &mut conn,
            "description",
            &if descr.is_empty() {
                format!("IPsec {remote_gw}")
            } else {
                descr.clone()
            },
        );
        push_to_swanctl(&mut result.swanctl, "Connections", conn);

        // Authentication
        let method = text_or(p1, "authentication_method", "pre_shared_key");
        let (local_auth, remote_auth) = match method {
            "pre_shared_key" => ("psk", "psk"),
            "cert" | "rsasig" | "pubkey" => ("pubkey", "pubkey"),
            other => {
                warn(format!(
                    "authentication method '{other}' mapped to certificates (pubkey); check it"
                ));
                ("pubkey", "pubkey")
            }
        };
        let local_id = find_id(p1, "local", local_addr.as_ref().map(|(ip, _)| ip.as_str()));
        let remote_id = find_id(p1, "peer", Some(&remote_gw));

        let mut local = XmlNode::new("local");
        local
            .attributes
            .insert("uuid".to_string(), stable_uuid("local", idx, &ikeid));
        push_text_child(&mut local, "enabled", enabled);
        push_text_child(&mut local, "connection", &conn_uuid);
        push_text_child(&mut local, "round", "0");
        push_text_child(&mut local, "auth", local_auth);
        push_text_child(&mut local, "id", &local_id);
        push_text_child(&mut local, "eap_id", "");
        push_text_child(&mut local, "certs", text_or(p1, "certref", ""));
        push_text_child(&mut local, "pubkeys", "");
        push_text_child(&mut local, "description", &descr);
        push_to_swanctl(&mut result.swanctl, "locals", local);

        let mut remote = XmlNode::new("remote");
        remote
            .attributes
            .insert("uuid".to_string(), stable_uuid("remote", idx, &ikeid));
        push_text_child(&mut remote, "enabled", enabled);
        push_text_child(&mut remote, "connection", &conn_uuid);
        push_text_child(&mut remote, "round", "0");
        push_text_child(&mut remote, "auth", remote_auth);
        push_text_child(&mut remote, "id", &remote_id);
        push_text_child(&mut remote, "eap_id", "");
        push_text_child(&mut remote, "groups", "");
        push_text_child(&mut remote, "certs", "");
        push_text_child(&mut remote, "cacerts", text_or(p1, "caref", ""));
        push_text_child(&mut remote, "pubkeys", "");
        push_text_child(&mut remote, "description", &descr);
        push_to_swanctl(&mut result.swanctl, "remotes", remote);

        // Pre-shared key: OPNsense's legacy code keys site-to-site secrets on
        // the peer's ID only (ipsec_write_secrets()).
        if local_auth == "psk" {
            let key = text_or(p1, "pre-shared-key", "");
            if key.is_empty() {
                warn("pre-shared key is empty".to_string());
            }
            let mut psk = XmlNode::new("preSharedKey");
            psk.attributes
                .insert("uuid".to_string(), stable_uuid("psk", idx, &ikeid));
            push_text_child(
                &mut psk,
                "ident",
                if remote_id.is_empty() {
                    "%any"
                } else {
                    &remote_id
                },
            );
            push_text_child(&mut psk, "remote_ident", "");
            push_text_child(&mut psk, "keyType", "PSK");
            push_text_child(&mut psk, "Key", key);
            push_text_child(&mut psk, "description", &descr);
            push_to_ipsec_psk(&mut result.ipsec, psk);
        }

        // Children
        let start_action = match text_or(p1, "startaction", "") {
            "" => "trap",
            "none" => "none",
            "start" => "start",
            "trap" => "trap",
            other => {
                warn(format!("start action '{other}' not supported; using trap"));
                "trap"
            }
        };
        let close_action = match text_or(p1, "closeaction", "") {
            "start" => "start",
            "trap" => "trap",
            _ => "none",
        };
        // pfSense: trap/clear from the start action, overridden by a close
        // action when one is set ("restart" is OPNsense's "start").
        let dpd_action = if dpd {
            match text_or(p1, "closeaction", "") {
                "" if start_action == "trap" => "trap",
                "" => "clear",
                "trap" => "trap",
                "start" => "start",
                _ => "clear",
            }
        } else {
            "clear"
        };
        let split = version == "1" || p1.get_child("splitconn").is_some();
        let groups: Vec<Vec<&XmlNode>> = if split {
            my_p2s.iter().map(|p2| vec![*p2]).collect()
        } else if my_p2s.is_empty() {
            Vec::new()
        } else {
            vec![my_p2s.clone()]
        };
        if my_p2s.is_empty() {
            warn("no phase 2 entries".to_string());
        }
        for (cidx, group) in groups.into_iter().enumerate() {
            let active: Vec<&XmlNode> = group
                .iter()
                .copied()
                .filter(|p2| enabled_from_disabled(p2) == "1")
                .collect();
            // A merged child is enabled when any of its phase 2 entries is.
            let child_enabled = if active.is_empty() { "0" } else { "1" };
            let members = if active.is_empty() {
                group.clone()
            } else {
                active
            };
            let mut local_ts = Vec::new();
            let mut remote_ts = Vec::new();
            let mut esp = Vec::new();
            let mut reqids = Vec::new();
            let mut mode = "tunnel";
            let mut rekey = 3600u64;
            let mut p2_descr = String::new();
            for p2 in &members {
                let p2_mode = text_or(p2, "mode", "tunnel");
                if p2_mode == "transport" {
                    mode = "transport";
                    if let Some((ip, _)) = &local_addr {
                        push_unique(&mut local_ts, ip.clone());
                    }
                    push_unique(&mut remote_ts, remote_gw.clone());
                } else {
                    match p2
                        .get_child("localid")
                        .map(|id| id_to_cidr(source, id, p2_mode))
                    {
                        Some(Some(ts)) => push_unique(&mut local_ts, ts),
                        _ => warn(format!(
                            "phase 2 local network '{}' could not be resolved",
                            p2.get_text(&["localid", "type"]).unwrap_or("")
                        )),
                    }
                    match p2
                        .get_child("remoteid")
                        .map(|id| id_to_cidr(source, id, p2_mode))
                    {
                        Some(Some(ts)) => push_unique(&mut remote_ts, ts),
                        _ => warn("phase 2 remote network could not be resolved".to_string()),
                    }
                }
                if p2
                    .get_child("natlocalid")
                    .is_some_and(|n| !n.children.is_empty())
                {
                    warn("phase 2 NAT/BINAT translation not converted".to_string());
                }
                let (props, dropped) = esp_proposals(p2);
                for d in dropped {
                    warn(format!("ESP proposal {d}"));
                }
                for p in props {
                    push_unique(&mut esp, p);
                }
                if let Ok(r) = text_or(p2, "reqid", "").parse::<u64>() {
                    reqids.push(r);
                }
                rekey = SaTimes::phase2_rekey(p2);
                if p2_descr.is_empty() {
                    p2_descr = text_or(p2, "descr", "").to_string();
                }
                if !text_or(p2, "pinghost", "").is_empty() {
                    warn(format!(
                        "keep-alive ping host {} not converted (OPNsense connections have none; 'start' actions keep the tunnel up)",
                        text_or(p2, "pinghost", "")
                    ));
                }
            }
            let mut child = XmlNode::new("child");
            child
                .attributes
                .insert("uuid".to_string(), stable_uuid("child", cidx, &ikeid));
            push_text_child(&mut child, "enabled", child_enabled);
            push_text_child(&mut child, "connection", &conn_uuid);
            push_text_child(
                &mut child,
                "reqid",
                &reqids.iter().min().map(u64::to_string).unwrap_or_default(),
            );
            push_text_child(
                &mut child,
                "esp_proposals",
                &if esp.is_empty() {
                    "default".to_string()
                } else {
                    esp.join(",")
                },
            );
            push_text_child(
                &mut child,
                "sha256_96",
                if p1.get_child("sha256_96").is_some() {
                    "1"
                } else {
                    "0"
                },
            );
            push_text_child(&mut child, "start_action", start_action);
            push_text_child(&mut child, "close_action", close_action);
            push_text_child(&mut child, "dpd_action", dpd_action);
            push_text_child(&mut child, "mode", mode);
            push_text_child(&mut child, "policies", "1");
            push_text_child(&mut child, "local_ts", &local_ts.join(","));
            push_text_child(&mut child, "remote_ts", &remote_ts.join(","));
            push_text_child(&mut child, "rekey_time", &rekey.to_string());
            push_text_child(
                &mut child,
                "description",
                &if p2_descr.is_empty() {
                    descr.clone()
                } else {
                    p2_descr
                },
            );
            push_to_swanctl(&mut result.swanctl, "children", child);
        }

        // Firewall rules pfSense would have added automatically.
        if enabled == "1" && auto_rules && !remote_gw.is_empty() {
            let rule_if = rule_interface(source, interface);
            let ipproto = if remote_gw.parse::<Ipv6Addr>().is_ok() {
                "inet6"
            } else {
                "inet"
            };
            if remote_gw.parse::<IpAddr>().is_err() {
                result.warnings.push(format!(
                    "IPsec '{label}': remote gateway '{remote_gw}' is a hostname; allow UDP 500/4500 and ESP from it on {rule_if} by hand"
                ));
            } else {
                let mut protos = vec![("udp", Some("500"), "IKE")];
                if text_or(p1, "nat_traversal", "on") != "off" {
                    protos.push(("udp", Some("4500"), "NAT-T"));
                }
                for p2 in &my_p2s {
                    match text_or(p2, "protocol", "esp") {
                        "ah" if !protos.iter().any(|p| p.0 == "ah") => {
                            protos.push(("ah", None, "AH"))
                        }
                        "esp" if !protos.iter().any(|p| p.0 == "esp") => {
                            protos.push(("esp", None, "ESP"))
                        }
                        _ => {}
                    }
                }
                for (proto, port, what) in protos {
                    result.firewall_rules.push(ipsec_rule(
                        &ikeid, &rule_if, ipproto, proto, port, &remote_gw, &label, what,
                    ));
                }
            }
        }

        if enabled == "1" {
            result.any_enabled = true;
        }
        result.converted_ikeids.push(raw_ikeid);
    }
    result
}

/// SA lifetimes as pfSense derives them (`ipsec_get_rekey_time()` etc.).
struct SaTimes {
    rekey: u64,
    reauth: u64,
    over: u64,
}

impl SaTimes {
    fn phase1(p1: &XmlNode) -> Self {
        let lifetime = num(p1, "lifetime");
        let ikev1 = text_or(p1, "iketype", "ikev1") == "ikev1";
        let rekey = match opt_num(p1, "rekey_time") {
            Some(v) => v,
            None if lifetime > 0 => lifetime * 9 / 10,
            None => 14400,
        };
        let reauth = match opt_num(p1, "reauth_time") {
            Some(v) => v,
            None if lifetime > 0 && ikev1 => lifetime * 9 / 10,
            None => 0,
        };
        let renewmax = rekey.max(reauth);
        let life = if lifetime > 0 {
            lifetime
        } else if renewmax > 0 {
            renewmax * 10 / 9
        } else {
            16000
        };
        let over = if life > 0 && renewmax > 0 {
            life.saturating_sub(renewmax)
        } else {
            life / 10
        };
        SaTimes {
            rekey,
            reauth,
            over,
        }
    }

    fn phase2_rekey(p2: &XmlNode) -> u64 {
        let lifetime = num(p2, "lifetime");
        match opt_num(p2, "rekey_time") {
            Some(v) => v,
            None if lifetime > 0 => lifetime * 9 / 10,
            None => 3600,
        }
    }
}

fn num(node: &XmlNode, tag: &str) -> u64 {
    opt_num(node, tag).unwrap_or(0)
}

fn opt_num(node: &XmlNode, tag: &str) -> Option<u64> {
    text_or(node, tag, "").parse::<u64>().ok()
}

/// pfSense `ipsec_find_id()` + `ipsec_fixup_id()` (without the quoting).
fn find_id(p1: &XmlNode, side: &str, addr: Option<&str>) -> String {
    let (id_type, id_data) = if side == "local" {
        (
            text_or(p1, "myid_type", "myaddress"),
            text_or(p1, "myid_data", ""),
        )
    } else {
        (
            text_or(p1, "peerid_type", "peeraddress"),
            text_or(p1, "peerid_data", ""),
        )
    };
    match id_type {
        "myaddress" | "peeraddress" => addr.unwrap_or("").to_string(),
        "any" => "%any".to_string(),
        "address" | "auto" | "asn1dn" => id_data.to_string(),
        "dyn_dns" => format!("dns:{id_data}"),
        "keyid tag" => format!("keyid:{id_data}"),
        "user_fqdn" => format!("userfqdn:{id_data}"),
        other => format!("{other}:{id_data}"),
    }
}

/// The address pfSense binds a phase1 to: the interface's (or VIP's) static
/// address, with its prefix length.
fn interface_address(source: &XmlNode, interface: &str, v6: bool) -> Option<(String, u8)> {
    if interface.parse::<IpAddr>().is_ok() {
        return Some((interface.to_string(), if v6 { 128 } else { 32 }));
    }
    if let Some(pos) = interface.find("_vip") {
        let key = &interface[pos + 4..];
        let vip = source
            .get_child("virtualip")
            .map(|v| v.get_children("vip"))
            .unwrap_or_default()
            .into_iter()
            .find(|v| {
                text_or(v, "uniqid", "") == key
                    || (pos > 0
                        && text_or(v, "interface", "") == &interface[..pos]
                        && text_or(v, "vhid", "") == key)
            })?;
        let ip = text_or(vip, "subnet", "").to_string();
        let bits = text_or(vip, "subnet_bits", "32").parse().unwrap_or(32);
        return ip.parse::<IpAddr>().is_ok().then_some((ip, bits));
    }
    let iface = source.get_child("interfaces")?.get_child(interface)?;
    let (ip_tag, bits_tag) = if v6 {
        ("ipaddrv6", "subnetv6")
    } else {
        ("ipaddr", "subnet")
    };
    let ip = text_or(iface, ip_tag, "").to_string();
    let bits = text_or(iface, bits_tag, "").parse().ok()?;
    ip.parse::<IpAddr>().is_ok().then_some((ip, bits))
}

/// pfSense `ipsec_idinfo_to_cidr()` for a phase2 local/remote ID.
fn id_to_cidr(source: &XmlNode, id: &XmlNode, mode: &str) -> Option<String> {
    let typ = text_or(id, "type", "");
    match typ {
        "address" => Some(text_or(id, "address", "").to_string()).filter(|a| !a.is_empty()),
        "network" => {
            let addr = text_or(id, "address", "");
            let bits = text_or(id, "netbits", "");
            (!addr.is_empty() && !bits.is_empty()).then(|| format!("{addr}/{bits}"))
        }
        "none" | "mobile" => Some("0.0.0.0/0".to_string()),
        "" => None,
        iface => {
            let (ip, bits) = interface_address(source, iface, mode == "tunnel6")?;
            network_of(&ip, bits)
        }
    }
}

fn network_of(ip: &str, bits: u8) -> Option<String> {
    match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            let bits = bits.min(32);
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(bits))
            };
            Some(format!("{}/{bits}", Ipv4Addr::from(u32::from(v4) & mask)))
        }
        IpAddr::V6(v6) => {
            let bits = bits.min(128);
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(bits))
            };
            Some(format!("{}/{bits}", Ipv6Addr::from(u128::from(v6) & mask)))
        }
    }
}

/// The interface a VIP-bound phase1 belongs to (pfSense `_vip<uniqid>`).
fn rule_interface(source: &XmlNode, interface: &str) -> String {
    if let Some(key) = interface.strip_prefix("_vip") {
        if let Some(vip) = source
            .get_child("virtualip")
            .map(|v| v.get_children("vip"))
            .unwrap_or_default()
            .into_iter()
            .find(|v| text_or(v, "uniqid", "") == key)
        {
            return text_or(vip, "interface", "wan").to_string();
        }
    }
    interface.split("_vip").next().unwrap_or("wan").to_string()
}

#[allow(clippy::too_many_arguments)]
fn ipsec_rule(
    ikeid: &str,
    interface: &str,
    ipproto: &str,
    proto: &str,
    port: Option<&str>,
    remote: &str,
    label: &str,
    what: &str,
) -> XmlNode {
    let mut rule = XmlNode::new("rule");
    rule.attributes.insert(
        "uuid".to_string(),
        stable_uuid(
            "ipsec-rule",
            0,
            &format!("{ikeid}|{proto}|{}", port.unwrap_or("")),
        ),
    );
    push_text_child(&mut rule, "type", "pass");
    push_text_child(&mut rule, "interface", interface);
    push_text_child(&mut rule, "ipprotocol", ipproto);
    push_text_child(&mut rule, "protocol", proto);
    let mut src = XmlNode::new("source");
    push_text_child(&mut src, "address", remote);
    rule.children.push(src);
    let mut dst = XmlNode::new("destination");
    dst.children.push(XmlNode::new("any"));
    if let Some(port) = port {
        push_text_child(&mut dst, "port", port);
    }
    rule.children.push(dst);
    push_text_child(&mut rule, "descr", &format!("IPsec: {label} ({what})"));
    rule
}

fn push_unique(list: &mut Vec<String>, value: String) {
    if !value.is_empty() && !list.contains(&value) {
        list.push(value);
    }
}
