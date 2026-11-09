use xml_diff_core::parse;

use super::{to_opnsense, to_pfsense};

#[test]
fn preserves_additional_openvpn_options() {
    let source = parse(
        br#"<pfsense><openvpn><openvpn-server><vpnid>1</vpnid><mode>server_tls_user</mode><authmode>Local Database</authmode><interface>opt2</interface><protocol>UDP</protocol><dev_mode>tun</dev_mode><local_port>1194</local_port><tunnel_network>10.0.8.0/24</tunnel_network><local_network>10.1.10.0/24</local_network><dns_domain>sheridan.local</dns_domain><dns_server1>10.1.10.1</dns_server1><push_blockoutsidedns>yes</push_blockoutsidedns><push_register_dns>yes</push_register_dns><ntp_server1>10.1.10.1</ntp_server1><netbios_enable>yes</netbios_enable><netbios_ntype>0</netbios_ntype><netbios_scope>scope</netbios_scope><custom_options>push &quot;route 10.1.10.0 255.255.255.0&quot;</custom_options><username>vpnuser</username><username_as_common_name>enabled</username_as_common_name><strictusercn>1</strictusercn></openvpn-server></openvpn></pfsense>"#,
    )
    .expect("source parse");
    let target =
        parse(br#"<opnsense><OPNsense><OpenVPN><Instances/></OpenVPN></OPNsense></opnsense>"#)
            .expect("target parse");
    let mut out = target.clone();

    to_opnsense(&mut out, &source, &target);
    let inst = out
        .get_child("OPNsense")
        .and_then(|o| o.get_child("OpenVPN"))
        .and_then(|o| o.get_child("Instances"))
        .and_then(|i| i.get_child("Instance"))
        .expect("instance");

    // register-dns is pushed through register_dns only (not twice).
    assert_eq!(
        inst.get_text(&["various_push_flags"]),
        Some("block-outside-dns")
    );
    assert_eq!(inst.get_text(&["register_dns"]), Some("1"));
    assert_eq!(inst.get_text(&["dns_servers"]), Some("10.1.10.1"));
    assert_eq!(inst.get_text(&["dns_domain"]), Some("sheridan.local"));
    assert_eq!(inst.get_text(&["ntp_servers"]), Some("10.1.10.1"));
    assert_eq!(inst.get_text(&["authmode"]), Some("Local Database"));
    assert_eq!(inst.get_text(&["verify_client_cert"]), Some("require"));
    assert_eq!(inst.get_text(&["username_as_common_name"]), Some("1"));
    assert_eq!(inst.get_text(&["strictusercn"]), Some("1"));
    // Not part of OPNsense's Instance model: not written (a warning is printed).
    for absent in [
        "custom_options",
        "netbios_enable",
        "netbios_ntype",
        "netbios_scope",
        "username",
    ] {
        assert!(
            inst.get_child(absent).is_none(),
            "{absent} should not be set"
        );
    }
}

#[test]
fn ignores_zero_username() {
    let source = parse(
        br#"<pfsense><openvpn><openvpn-server><vpnid>1</vpnid><username>0</username></openvpn-server></openvpn></pfsense>"#,
    )
    .expect("source parse");
    let target =
        parse(br#"<opnsense><OPNsense><OpenVPN><Instances/></OpenVPN></OPNsense></opnsense>"#)
            .expect("target parse");
    let mut out = target.clone();

    to_opnsense(&mut out, &source, &target);
    let inst = out
        .get_child("OPNsense")
        .and_then(|o| o.get_child("OpenVPN"))
        .and_then(|o| o.get_child("Instances"))
        .and_then(|i| i.get_child("Instance"))
        .expect("instance");

    assert!(inst.get_text(&["username"]).is_none());
}

#[test]
fn maps_opnsense_instance_options_back_to_pfsense() {
    let source = parse(
        br#"<opnsense><OPNsense><OpenVPN><Instances><Instance><vpnid>1</vpnid><enabled>1</enabled><dev_type>tun</dev_type><proto>udp</proto><port>1194</port><server>10.0.8.0/24</server><push_route>10.1.10.0/24</push_route><various_push_flags>block-outside-dns,register-dns,explicit-exit-notify</various_push_flags><register_dns>1</register_dns><dns_servers>10.1.10.1,1.1.1.1</dns_servers><ntp_servers>10.1.10.1</ntp_servers><custom_options>push &quot;route 192.168.20.0 255.255.255.0&quot;</custom_options><username>vpnuser</username><username_as_common_name>1</username_as_common_name><strictusercn>1</strictusercn><netbios_enable>1</netbios_enable><netbios_ntype>0</netbios_ntype><netbios_scope>scope</netbios_scope></Instance></Instances></OpenVPN></OPNsense></opnsense>"#,
    )
    .expect("source parse");
    let target = parse(br#"<pfsense><openvpn/></pfsense>"#).expect("target parse");
    let mut out = target.clone();

    to_pfsense(&mut out, &source, &target);
    let server = out
        .get_child("openvpn")
        .and_then(|o| o.get_child("openvpn-server"))
        .expect("server");

    assert_eq!(server.get_text(&["dns_server1"]), Some("10.1.10.1"));
    assert_eq!(server.get_text(&["dns_server2"]), Some("1.1.1.1"));
    assert_eq!(server.get_text(&["push_blockoutsidedns"]), Some("yes"));
    assert_eq!(server.get_text(&["push_register_dns"]), Some("yes"));
    assert_eq!(server.get_text(&["exit_notify"]), Some("explicit"));
    assert_eq!(
        server.get_text(&["custom_options"]),
        Some(r#"push "route 192.168.20.0 255.255.255.0""#)
    );
    assert_eq!(server.get_text(&["username"]), Some("vpnuser"));
    assert_eq!(
        server.get_text(&["username_as_common_name"]),
        Some("enabled")
    );
    assert_eq!(server.get_text(&["strictusercn"]), Some("1"));
    assert_eq!(server.get_text(&["netbios_enable"]), Some("yes"));
    assert_eq!(server.get_text(&["netbios_ntype"]), Some("0"));
    assert_eq!(server.get_text(&["ntp_server1"]), Some("10.1.10.1"));
}

#[test]
fn maps_pfsense_openvpn_servers_to_opnsense_instances() {
    let source = parse(
        br#"<pfsense><openvpn><openvpn-server><vpnid>1</vpnid><protocol>UDP</protocol><dev_mode>tun</dev_mode><local_port>1194</local_port><tunnel_network>10.8.0.0/24</tunnel_network><local_network>192.168.1.0/24</local_network><certref>cert1</certref><caref>ca1</caref><description>srv</description></openvpn-server></openvpn></pfsense>"#,
    )
    .expect("source parse");
    let target =
        parse(br#"<opnsense><OPNsense><OpenVPN><Instances/></OpenVPN></OPNsense></opnsense>"#)
            .expect("target parse");
    let mut out = target.clone();

    to_opnsense(&mut out, &source, &target);
    assert_eq!(
        out.get_text(&["OPNsense", "OpenVPN", "Instances", "Instance", "server"]),
        Some("10.8.0.0/24")
    );
    assert_eq!(
        out.get_text(&["OPNsense", "OpenVPN", "Instances", "Instance", "proto"]),
        Some("udp")
    );
    let uuid = out
        .get_child("OPNsense")
        .and_then(|o| o.get_child("OpenVPN"))
        .and_then(|o| o.get_child("Instances"))
        .and_then(|i| i.get_child("Instance"))
        .and_then(|i| i.attributes.get("uuid"));
    assert!(uuid.is_some());
    // The converted server is removed from the legacy section.
    assert_eq!(out.get_child("openvpn").map(|n| n.children.len()), Some(0));
}

#[test]
fn uses_source_openvpn_interface_unit_as_vpnid_fallback() {
    let source = parse(
        br#"<pfsense><interfaces><openvpn><if>ovpns2</if></openvpn></interfaces><openvpn><openvpn-server><protocol>UDP</protocol><dev_mode>tun</dev_mode></openvpn-server></openvpn></pfsense>"#,
    )
    .expect("source parse");
    let target = parse(
        br#"<opnsense><OPNsense><OpenVPN><Instances><Instance><vpnid>1</vpnid><enabled>1</enabled><dev_type>tun</dev_type><proto>udp</proto><port/><role>server</role><server/><push_route/><cert/><ca/><cert_depth>1</cert_depth><topology>subnet</topology><description/></Instance></Instances></OpenVPN></OPNsense></opnsense>"#,
    )
    .expect("target parse");
    let mut out = target.clone();

    to_opnsense(&mut out, &source, &target);
    assert_eq!(
        out.get_text(&["OPNsense", "OpenVPN", "Instances", "Instance", "vpnid"]),
        Some("2")
    );
}

#[test]
fn prefers_assigned_ovpns_unit_over_stale_server_vpnid() {
    let source = parse(
        br#"<pfsense><interfaces><opt2><if>ovpns2</if></opt2></interfaces><openvpn><openvpn-server><vpnid>1</vpnid><protocol>UDP</protocol><dev_mode>tun</dev_mode></openvpn-server></openvpn></pfsense>"#,
    )
    .expect("source parse");
    let target = parse(
        br#"<opnsense><OPNsense><OpenVPN><Instances><Instance><vpnid>1</vpnid><enabled>1</enabled><dev_type>tun</dev_type><proto>udp</proto><port/><role>server</role><server/><push_route/><cert/><ca/><cert_depth>1</cert_depth><topology>subnet</topology><description/></Instance></Instances></OpenVPN></OPNsense></opnsense>"#,
    )
    .expect("target parse");
    let mut out = target.clone();

    to_opnsense(&mut out, &source, &target);
    assert_eq!(
        out.get_text(&["OPNsense", "OpenVPN", "Instances", "Instance", "vpnid"]),
        Some("2")
    );
}

#[test]
fn maps_opnsense_instances_to_pfsense_openvpn_servers() {
    let source = parse(
        br#"<opnsense><OPNsense><OpenVPN><Instances><Instance><vpnid>1</vpnid><enabled>1</enabled><proto>udp</proto><dev_type>tun</dev_type><port>1194</port><server>10.0.8.0/24</server><push_route>10.1.10.0/24</push_route><cert>cert1</cert><ca>ca1</ca><description>openvpn server</description></Instance></Instances></OpenVPN></OPNsense></opnsense>"#,
    )
    .expect("source parse");
    let target = parse(br#"<pfsense><openvpn/></pfsense>"#).expect("target parse");
    let mut out = target.clone();

    to_pfsense(&mut out, &source, &target);
    assert_eq!(
        out.get_text(&["openvpn", "openvpn-server", "tunnel_network"]),
        Some("10.0.8.0/24")
    );
    assert_eq!(
        out.get_text(&["openvpn", "openvpn-server", "protocol"]),
        Some("UDP")
    );
}

#[test]
fn to_opnsense_dedupes_top_level_openvpn_entries() {
    let source = parse(
        br#"<pfsense><openvpn><openvpn-server><vpnid>1</vpnid><protocol>UDP</protocol><dev_mode>tun</dev_mode></openvpn-server></openvpn></pfsense>"#,
    )
    .expect("source parse");
    let target = parse(
        br#"<opnsense><openvpn/><openvpn><legacy/></openvpn><OPNsense><OpenVPN><Instances><Instance><vpnid>1</vpnid></Instance></Instances></OpenVPN></OPNsense></opnsense>"#,
    )
    .expect("target parse");
    let mut out = target.clone();

    to_opnsense(&mut out, &source, &target);
    let count = out.children.iter().filter(|c| c.tag == "openvpn").count();
    assert_eq!(count, 1);
}

#[test]
fn to_pfsense_dedupes_top_level_openvpn_entries() {
    let source = parse(
        br#"<opnsense><OPNsense><OpenVPN><Instances><Instance><vpnid>1</vpnid><enabled>1</enabled><proto>udp</proto><dev_type>tun</dev_type><port>1194</port><server>10.0.8.0/24</server></Instance></Instances></OpenVPN></OPNsense></opnsense>"#,
    )
    .expect("source parse");
    let target = parse(br#"<pfsense><openvpn/><openvpn><legacy/></openvpn></pfsense>"#)
        .expect("target parse");
    let mut out = target.clone();

    to_pfsense(&mut out, &source, &target);
    let count = out.children.iter().filter(|c| c.tag == "openvpn").count();
    assert_eq!(count, 1);
}

#[test]
fn preserves_instance_uuid_when_roundtripping_via_pfsense_openvpn() {
    let source = parse(
        br#"<opnsense><OPNsense><OpenVPN><Instances><Instance uuid="inst-uuid-1"><vpnid>1</vpnid><enabled>1</enabled><proto>udp</proto><dev_type>tun</dev_type><port>1194</port><server>10.0.8.0/24</server></Instance></Instances></OpenVPN></OPNsense></opnsense>"#,
    )
    .expect("source parse");
    let pf_target = parse(br#"<pfsense><openvpn/></pfsense>"#).expect("pf target parse");
    let mut pf = pf_target.clone();
    to_pfsense(&mut pf, &source, &pf_target);

    let opn_target =
        parse(br#"<opnsense><OPNsense><OpenVPN><Instances/></OpenVPN></OPNsense></opnsense>"#)
            .expect("opn target parse");
    let mut opn = opn_target.clone();
    to_opnsense(&mut opn, &pf, &opn_target);

    let uuid = opn
        .get_child("OPNsense")
        .and_then(|n| n.get_child("OpenVPN"))
        .and_then(|n| n.get_child("Instances"))
        .and_then(|n| n.get_child("Instance"))
        .and_then(|n| n.attributes.get("uuid"))
        .map(String::as_str);
    assert_eq!(uuid, Some("inst-uuid-1"));
}

#[test]
fn does_not_preserve_top_level_openvpn_servers_for_opnsense_origin() {
    let source = parse(
        br#"<pfsense><openvpn><openvpn-server><opnsense_instance_uuid>inst-uuid-1</opnsense_instance_uuid><vpnid>1</vpnid><protocol>UDP</protocol></openvpn-server></openvpn></pfsense>"#,
    )
    .expect("source parse");
    let target =
        parse(br#"<opnsense><OPNsense><OpenVPN><Instances/></OpenVPN></OPNsense></opnsense>"#)
            .expect("target parse");
    let mut out = target.clone();

    to_opnsense(&mut out, &source, &target);
    assert_eq!(out.get_child("openvpn").map(|n| n.children.len()), Some(0));
}

const TLS_KEY_B64: &str = "IwojIDIwNDggYml0IE9wZW5WUE4gc3RhdGljIGtleQojCi0tLS0tQkVHSU4gT3BlblZQTiBTdGF0aWMga2V5IFYxLS0tLS0KMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYKLS0tLS1FTkQgT3BlblZQTiBTdGF0aWMga2V5IFYxLS0tLS0K";

fn convert(source_xml: &str) -> xml_diff_core::XmlNode {
    let source = parse(source_xml.as_bytes()).expect("source parse");
    let target = parse(br#"<opnsense><OPNsense><OpenVPN version="1.0.1"><Instances/><StaticKeys/><Overwrites/></OpenVPN></OPNsense></opnsense>"#)
        .expect("target parse");
    let mut out = target.clone();
    to_opnsense(&mut out, &source, &target);
    out
}

fn first_instance(out: &xml_diff_core::XmlNode) -> &xml_diff_core::XmlNode {
    out.get_child("OPNsense")
        .and_then(|o| o.get_child("OpenVPN"))
        .and_then(|o| o.get_child("Instances"))
        .and_then(|i| i.get_child("Instance"))
        .expect("instance")
}

#[test]
fn maps_remote_access_server_with_ldap_and_tls_auth_key() {
    let out = convert(&format!(
        r#"<pfsense>
            <interfaces><wan><if>vtnet0</if><ipaddr>203.0.113.10</ipaddr></wan></interfaces>
            <openvpn><openvpn-server>
                <vpnid>1</vpnid><mode>server_user</mode><authmode>DC-1</authmode>
                <protocol>UDP4</protocol><dev_mode>tun</dev_mode><interface>wan</interface><ipaddr></ipaddr>
                <local_port>1194</local_port><description>Remote access</description>
                <tls>{TLS_KEY_B64}</tls><tls_type>auth</tls_type><tlsauth_keydir>default</tlsauth_keydir>
                <caref>ca1</caref><certref>cert1</certref><cert_depth>1</cert_depth>
                <data_ciphers>AES-256-GCM,AES-128-GCM,CHACHA20-POLY1305,AES-128-CBC,BF-CBC</data_ciphers>
                <data_ciphers_fallback>AES-128-CBC</data_ciphers_fallback><digest>SHA256</digest>
                <tunnel_network>10.8.0.0/24</tunnel_network>
                <local_network>10.1.0.0/24, 198.51.100.0/27</local_network>
                <gwredir>yes</gwredir><client2client>yes</client2client><dynamic_ip>yes</dynamic_ip>
                <allow_compression>asym</allow_compression><compression></compression>
                <topology>subnet</topology><dns_domain>example.lan</dns_domain><dns_server1>10.1.0.1</dns_server1>
                <username_as_common_name>enabled</username_as_common_name><exit_notify>none</exit_notify>
                <verbosity_level>1</verbosity_level><ping_method>keepalive</ping_method>
                <keepalive_interval>10</keepalive_interval><keepalive_timeout>60</keepalive_timeout>
                <inactive_seconds>0</inactive_seconds>
            </openvpn-server></openvpn></pfsense>"#
    ));
    let inst = first_instance(&out);
    let get = |tag: &str| inst.get_text(&[tag]);
    assert_eq!(get("role"), Some("server"));
    assert_eq!(get("enabled"), Some("1"));
    assert_eq!(get("proto"), Some("udp4"));
    assert_eq!(get("port"), Some("1194"));
    assert_eq!(get("local"), Some("203.0.113.10"));
    assert_eq!(get("authmode"), Some("DC-1"));
    assert_eq!(get("verify_client_cert"), Some("none"));
    assert_eq!(get("username_as_common_name"), Some("1"));
    assert_eq!(get("ca"), Some("ca1"));
    assert_eq!(get("cert"), Some("cert1"));
    assert_eq!(
        get("data-ciphers"),
        Some("AES-256-GCM,AES-128-GCM,CHACHA20-POLY1305,AES-128-CBC")
    );
    assert_eq!(get("data-ciphers-fallback"), Some("AES-128-CBC"));
    assert_eq!(get("auth"), Some("SHA256"));
    assert_eq!(get("push_route"), Some("10.1.0.0/24,198.51.100.0/27"));
    assert_eq!(get("redirect_gateway"), Some("def1"));
    assert_eq!(
        get("various_flags"),
        Some("client-to-client,float,persist-remote-ip")
    );
    assert_eq!(get("keepalive_interval"), Some("10"));
    assert_eq!(get("keepalive_timeout"), Some("60"));
    assert_eq!(get("verb"), Some("1"));
    assert!(inst.get_child("push_inactive").is_none());
    assert!(inst.get_child("compress_migrate").is_none());

    let key_uuid = get("tls_key").expect("tls_key").to_string();
    let key = out
        .get_child("OPNsense")
        .and_then(|o| o.get_child("OpenVPN"))
        .and_then(|o| o.get_child("StaticKeys"))
        .and_then(|k| k.get_child("StaticKey"))
        .expect("static key");
    assert_eq!(key.attributes.get("uuid"), Some(&key_uuid));
    assert_eq!(key.get_text(&["mode"]), Some("auth"));
    assert!(key
        .get_text(&["key"])
        .unwrap_or("")
        .contains("-----BEGIN OpenVPN Static key V1-----"));

    // Converted: no legacy copy left to run twice.
    assert_eq!(out.get_child("openvpn").map(|n| n.children.len()), Some(0));
}

#[test]
fn maps_tls_crypt_and_isset_flags() {
    let out = convert(&format!(
        r#"<pfsense><openvpn><openvpn-server>
            <vpnid>3</vpnid><mode>server_tls</mode><protocol>TCP</protocol><dev_mode>tun</dev_mode>
            <interface>any</interface><local_port>443</local_port><tunnel_network>10.9.0.0/24</tunnel_network>
            <tls>{TLS_KEY_B64}</tls><tls_type>crypt</tls_type>
            <duplicate_cn></duplicate_cn><remote_cert_tls></remote_cert_tls>
            <compression>adaptive</compression><gwredir></gwredir>
        </openvpn-server></openvpn></pfsense>"#
    ));
    let inst = first_instance(&out);
    assert_eq!(inst.get_text(&["vpnid"]), Some("3"));
    assert_eq!(inst.get_text(&["proto"]), Some("tcp"));
    assert!(inst.get_child("local").is_none() || inst.get_text(&["local"]) == Some(""));
    assert_eq!(inst.get_text(&["verify_client_cert"]), Some("require"));
    assert_eq!(inst.get_text(&["authmode"]), None);
    assert_eq!(inst.get_text(&["username_as_common_name"]), Some("0"));
    // pfSense tests these with isset(): empty elements mean "on".
    assert_eq!(inst.get_text(&["various_flags"]), Some("duplicate-cn"));
    assert_eq!(inst.get_text(&["remote_cert_tls"]), Some("1"));
    assert_eq!(inst.get_text(&["compress_migrate"]), Some("1"));
    assert_eq!(inst.get_text(&["redirect_gateway"]), Some(""));
    // pfSense's default digest
    assert_eq!(inst.get_text(&["auth"]), Some("SHA1"));
    assert_eq!(
        out.get_text(&["OPNsense", "OpenVPN", "StaticKeys", "StaticKey", "mode"]),
        Some("crypt")
    );
}

#[test]
fn keeps_shared_key_servers_and_clients_in_legacy_section() {
    let out = convert(
        r#"<pfsense><openvpn>
            <openvpn-server><vpnid>1</vpnid><mode>p2p_shared_key</mode><protocol>UDP</protocol></openvpn-server>
            <openvpn-server><vpnid>2</vpnid><mode>server_tls</mode><protocol>UDP</protocol><tunnel_network>10.2.0.0/24</tunnel_network></openvpn-server>
            <openvpn-client><vpnid>3</vpnid><mode>p2p_tls</mode><server_addr>198.51.100.1</server_addr></openvpn-client>
        </openvpn></pfsense>"#,
    );
    let instances = out
        .get_child("OPNsense")
        .and_then(|o| o.get_child("OpenVPN"))
        .and_then(|o| o.get_child("Instances"))
        .expect("instances");
    assert_eq!(instances.children.len(), 1);
    assert_eq!(first_instance(&out).get_text(&["vpnid"]), Some("2"));
    let legacy = out.get_child("openvpn").expect("legacy");
    let tags: Vec<(&str, Option<&str>)> = legacy
        .children
        .iter()
        .map(|c| (c.tag.as_str(), c.get_text(&["vpnid"])))
        .collect();
    assert_eq!(
        tags,
        vec![("openvpn-server", Some("1")), ("openvpn-client", Some("3"))]
    );
}

#[test]
fn binds_to_vip_address() {
    let out = convert(
        r#"<pfsense>
            <virtualip><vip><mode>ipalias</mode><interface>wan</interface><uniqid>5f1a2b3c4d5e6</uniqid><subnet>203.0.113.20</subnet></vip></virtualip>
            <openvpn><openvpn-server><vpnid>1</vpnid><mode>server_tls</mode><protocol>UDP4</protocol>
            <interface>_vip5f1a2b3c4d5e6</interface><tunnel_network>10.8.0.0/24</tunnel_network></openvpn-server></openvpn>
        </pfsense>"#,
    );
    assert_eq!(
        first_instance(&out).get_text(&["local"]),
        Some("203.0.113.20")
    );
}

#[test]
fn converts_client_specific_overrides() {
    let out = convert(
        r#"<pfsense><openvpn>
            <openvpn-server><vpnid>1</vpnid><mode>server_tls</mode><protocol>UDP</protocol><tunnel_network>10.8.0.0/24</tunnel_network></openvpn-server>
            <openvpn-csc>
                <common_name>laptop1</common_name><description>Laptop</description><ovpn_servers>1</ovpn_servers>
                <tunnel_network>10.8.0.50/24</tunnel_network><local_network>10.1.0.0/24,bogus</local_network>
                <gwredir>yes</gwredir><block></block><dns_server1>10.1.0.1</dns_server1><dns_server2>10.1.0.2</dns_server2>
            </openvpn-csc>
        </openvpn></pfsense>"#,
    );
    let inst_uuid = first_instance(&out).attributes.get("uuid").cloned();
    let ow = out
        .get_child("OPNsense")
        .and_then(|o| o.get_child("OpenVPN"))
        .and_then(|o| o.get_child("Overwrites"))
        .and_then(|o| o.get_child("Overwrite"))
        .expect("overwrite");
    assert_eq!(ow.get_text(&["common_name"]), Some("laptop1"));
    assert_eq!(ow.get_text(&["servers"]).map(str::to_string), inst_uuid);
    assert_eq!(ow.get_text(&["enabled"]), Some("1"));
    assert_eq!(ow.get_text(&["tunnel_network"]), Some("10.8.0.50/24"));
    assert_eq!(ow.get_text(&["local_networks"]), Some("10.1.0.0/24"));
    assert_eq!(ow.get_text(&["redirect_gateway"]), Some("def1"));
    assert_eq!(ow.get_text(&["dns_servers"]), Some("10.1.0.1,10.1.0.2"));
    assert_eq!(out.get_child("openvpn").map(|n| n.children.len()), Some(0));
}
