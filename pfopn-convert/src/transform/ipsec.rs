use crate::transform::ipsec_pf_to_opn;
use crate::transform::version::inherit_model_attrs;
use xml_diff_core::XmlNode;

/// Transform IPsec configuration for OPNsense output.
///
/// IPsec config lives in up to three places across the two platforms:
/// - `<ipsec>` -- top-level legacy section (both platforms, pfSense-style
///   `<phase1>`/`<phase2>` structure or OPNsense-style `<general>`/`<charon>`).
/// - `<OPNsense><IPsec>` -- nested OPNsense-native settings (pre-shared keys,
///   general tunables, etc.).
/// - `<OPNsense><Swanctl>` -- strongSwan/swanctl connection definitions
///   (OPNsense's modern IPsec backend).
///
/// When a top-level `<ipsec>` exists in the source:
/// - It is copied as-is to the output's top-level `<ipsec>`.
/// - If it contains `<phase1>`/`<phase2>` (pfSense-style), the data is also
///   mapped into OPNsense's `<IPsec>` and `<Swanctl>` structures via
///   `ipsec_pf_to_opn`.
/// - Otherwise (already OPNsense-style), it is placed directly into
///   `<OPNsense><IPsec>`.
///
/// When no top-level `<ipsec>` exists, the nested `<OPNsense><IPsec>` and
/// `<OPNsense><Swanctl>` sections are copied through from the source.
pub fn to_opnsense(out: &mut XmlNode, source: &XmlNode, target: &XmlNode) {
    if let Some(top) = source.get_child("ipsec") {
        // Always preserve the top-level section for round-trip fidelity.
        upsert_top_level_node("ipsec", out, top);
        if looks_like_pfsense_ipsec(top) {
            let target_opn = target.get_child("OPNsense");
            let mut mapping = ipsec_pf_to_opn::map_pf_ipsec_to_opnsense(
                source,
                target_opn.and_then(|o| o.get_child("IPsec")),
                target_opn.and_then(|o| o.get_child("Swanctl")),
            );
            inherit_model_attrs(
                &mut mapping.ipsec,
                target_opn.and_then(|o| o.get_child("IPsec")),
            );
            inherit_model_attrs(
                &mut mapping.swanctl,
                target_opn.and_then(|o| o.get_child("Swanctl")),
            );
            for warning in &mapping.warnings {
                eprintln!("warning: {warning}");
            }
            if !mapping.converted_ikeids.is_empty() {
                eprintln!(
                    "info: converted {} IPsec tunnel(s) to OPNsense connections; added {} firewall rule(s) for IKE/NAT-T/ESP from the peers (pfSense added these automatically)",
                    mapping.converted_ikeids.len(),
                    mapping.firewall_rules.len()
                );
            }
            upsert_nested_opnsense_node("IPsec", out, &mapping.ipsec);
            upsert_nested_opnsense_node("Swanctl", out, &mapping.swanctl);

            // Drop converted tunnels from the legacy section, so nothing runs
            // twice if os-strongswan-legacy is installed later. OPNsense
            // stops strongSwan unless <ipsec><enable> is set.
            let mut legacy = top.clone();
            legacy.children.retain(|c| match c.tag.as_str() {
                "phase1" | "phase2" => {
                    let ikeid = c.get_text(&["ikeid"]).map(str::trim).unwrap_or("");
                    !mapping.converted_ikeids.iter().any(|id| id == ikeid)
                }
                "enable" => false,
                _ => true,
            });
            if mapping.any_enabled || top.get_child("enable").is_some() {
                let mut enable = XmlNode::new("enable");
                enable.text = Some("1".to_string());
                legacy.children.insert(0, enable);
            }
            upsert_top_level_node("ipsec", out, &legacy);
            prepend_filter_rules(out, mapping.firewall_rules);
        } else if looks_like_opnsense_ipsec(top) {
            // Already OPNsense-style (general/charon) -- nest it directly.
            upsert_nested_opnsense_node("IPsec", out, top);
        }
        // A pfSense <ipsec> without phase1/phase2 (e.g. only <vtimaps/> or
        // <client/>) holds no tunnels; keep the baseline's OPNsense IPsec
        // section instead of replacing it with pfSense-only leftovers.
        let _ = target;
        return;
    }

    // No top-level <ipsec> -- pass through nested OPNsense sections as-is.
    if let Some(nested) = source
        .get_child("OPNsense")
        .and_then(|opn| opn.get_child("IPsec"))
    {
        upsert_nested_opnsense_node("IPsec", out, nested);
    }

    if let Some(swanctl) = source
        .get_child("OPNsense")
        .and_then(|opn| opn.get_child("Swanctl"))
    {
        upsert_nested_opnsense_node("Swanctl", out, swanctl);
    }

    let _ = target;
}

/// Transform IPsec configuration for pfSense output.
///
/// pfSense expects a top-level `<ipsec>` section. The source data may come
/// from either location:
/// - A top-level `<ipsec>` (preferred -- used directly and also mirrored
///   into `<OPNsense><IPsec>` for round-trip fidelity).
/// - A nested `<OPNsense><IPsec>` (fallback when no top-level exists --
///   promoted to top-level `<ipsec>` and also kept nested).
///
/// `<OPNsense><Swanctl>` is always carried through so that strongSwan
/// connection data isn't lost if the config is later converted back to
/// OPNsense.
pub fn to_pfsense(out: &mut XmlNode, source: &XmlNode, target: &XmlNode) {
    let mut had_top_level_ipsec = false;
    if let Some(top) = source.get_child("ipsec") {
        // Top-level exists -- use it as the authoritative source.
        had_top_level_ipsec = true;
        upsert_top_level_node("ipsec", out, top);
        upsert_nested_opnsense_node("IPsec", out, top);
    }

    if !had_top_level_ipsec {
        // Fall back to nested OPNsense IPsec and promote it to top-level.
        if let Some(nested) = source
            .get_child("OPNsense")
            .and_then(|opn| opn.get_child("IPsec"))
        {
            upsert_top_level_node("ipsec", out, nested);
            upsert_nested_opnsense_node("IPsec", out, nested);
        }
    }

    // Always carry Swanctl through for lossless round-tripping.
    if let Some(swanctl) = source
        .get_child("OPNsense")
        .and_then(|opn| opn.get_child("Swanctl"))
    {
        upsert_nested_opnsense_node("Swanctl", out, swanctl);
    }

    let _ = target;
}

/// Insert pfSense-format rules ahead of the existing filter rules (pfSense
/// evaluated its automatic IPsec rules before the user's rules).
fn prepend_filter_rules(out: &mut XmlNode, rules: Vec<XmlNode>) {
    if rules.is_empty() {
        return;
    }
    let filter = match out.children.iter().position(|c| c.tag == "filter") {
        Some(idx) => &mut out.children[idx],
        None => {
            out.children.push(XmlNode::new("filter"));
            out.children.last_mut().expect("just pushed")
        }
    };
    let pos = filter
        .children
        .iter()
        .position(|c| c.tag == "rule")
        .unwrap_or(filter.children.len());
    for (offset, rule) in rules.into_iter().enumerate() {
        filter.children.insert(pos + offset, rule);
    }
}

/// Replace or append a top-level child section in the output root.
fn upsert_top_level_node(section: &str, out: &mut XmlNode, node: &XmlNode) {
    if let Some(idx) = out.children.iter().position(|c| c.tag == section) {
        out.children[idx] = clone_with_tag(node, section);
    } else {
        out.children.push(clone_with_tag(node, section));
    }
}

/// Replace or append a section inside the `<OPNsense>` wrapper element.
///
/// If `<OPNsense>` doesn't exist yet, it is created. This ensures nested
/// OPNsense-specific config (IPsec tunables, Swanctl connections) is always
/// stored in the correct location regardless of whether the output tree
/// already had the wrapper.
fn upsert_nested_opnsense_node(section: &str, out: &mut XmlNode, node: &XmlNode) {
    if let Some(opn) = out.children.iter_mut().find(|c| c.tag == "OPNsense") {
        if let Some(idx) = opn.children.iter().position(|c| c.tag == section) {
            opn.children[idx] = clone_with_tag(node, section);
        } else {
            opn.children.push(clone_with_tag(node, section));
        }
        return;
    }

    // No <OPNsense> wrapper yet -- create one.
    let mut opn = XmlNode::new("OPNsense");
    opn.children.push(clone_with_tag(node, section));
    out.children.push(opn);
}

/// Clone a node and override its tag name.
fn clone_with_tag(node: &XmlNode, tag: &str) -> XmlNode {
    let mut out = node.clone();
    out.tag = tag.to_string();
    out
}

/// Detect whether an `<ipsec>` node uses pfSense's phase1/phase2 structure.
///
/// pfSense stores tunnel definitions as `<phase1>` and `<phase2>` children.
/// OPNsense's top-level `<ipsec>` instead contains `<general>` and `<charon>`
/// with the actual tunnels living under `<OPNsense><Swanctl>`. The presence
/// of either phase element is a reliable indicator of pfSense-style config.
fn looks_like_pfsense_ipsec(node: &XmlNode) -> bool {
    node.get_child("phase1").is_some() || node.get_child("phase2").is_some()
}

/// OPNsense-style IPsec settings (`<general>`/`<charon>`), e.g. carried in a
/// pfSense file produced by an earlier OPNsense -> pfSense conversion.
fn looks_like_opnsense_ipsec(node: &XmlNode) -> bool {
    node.get_child("general").is_some() || node.get_child("charon").is_some()
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::{to_opnsense, to_pfsense};

    #[test]
    fn transfers_nested_opnsense_ipsec_when_missing() {
        let source = parse(
            br#"<opnsense><OPNsense><IPsec><general/></IPsec><Swanctl><Connections/></Swanctl></OPNsense></opnsense>"#,
        )
        .expect("source parse");
        let target = parse(br#"<pfsense><system/></pfsense>"#).expect("target parse");
        let mut out = target.clone();

        to_pfsense(&mut out, &source, &target);

        let nested_ipsec = out
            .get_child("OPNsense")
            .and_then(|opn| opn.get_child("IPsec"));
        let nested_swanctl = out
            .get_child("OPNsense")
            .and_then(|opn| opn.get_child("Swanctl"));
        assert!(nested_ipsec.is_some());
        assert!(nested_swanctl.is_some());
    }

    #[test]
    fn replaces_placeholder_top_level_ipsec_with_source() {
        let source =
            parse(br#"<pfsense><ipsec><phase1><descr>src-p1</descr></phase1></ipsec></pfsense>"#)
                .expect("source parse");
        let target =
            parse(br#"<opnsense><ipsec><phase1><descr>dst-p1</descr></phase1></ipsec></opnsense>"#)
                .expect("target parse");
        let mut out = target.clone();

        to_opnsense(&mut out, &source, &target);
        // Converted: no legacy copy left (it would run twice with os-strongswan-legacy).
        assert!(out
            .get_child("ipsec")
            .and_then(|i| i.get_child("phase1"))
            .is_none());
        assert_eq!(
            out.get_text(&[
                "OPNsense",
                "Swanctl",
                "Connections",
                "Connection",
                "description"
            ]),
            Some("src-p1")
        );
    }

    #[test]
    fn replaces_placeholder_nested_opnsense_ipsec_with_source() {
        let source = parse(
            br#"<opnsense><OPNsense><IPsec><phase1><descr>src-ipsec</descr></phase1></IPsec><Swanctl><Connections><c><name>src-conn</name></c></Connections></Swanctl></OPNsense></opnsense>"#,
        )
        .expect("source parse");
        let target = parse(
            br#"<pfsense><OPNsense><IPsec><phase1><descr>dst-ipsec</descr></phase1></IPsec><Swanctl><Connections><c><name>dst-conn</name></c></Connections></Swanctl></OPNsense></pfsense>"#,
        )
        .expect("target parse");
        let mut out = target.clone();

        to_pfsense(&mut out, &source, &target);
        assert_eq!(
            out.get_text(&["OPNsense", "IPsec", "phase1", "descr"]),
            Some("src-ipsec")
        );
        assert_eq!(
            out.get_text(&["OPNsense", "Swanctl", "Connections", "c", "name"]),
            Some("src-conn")
        );
    }

    #[test]
    fn maps_nested_opnsense_ipsec_to_top_level_for_pfsense_output() {
        let source = parse(
            br#"<opnsense><OPNsense><IPsec><phase1><descr>src-nested</descr></phase1></IPsec></OPNsense></opnsense>"#,
        )
        .expect("source parse");
        let target = parse(br#"<pfsense><system/></pfsense>"#).expect("target parse");
        let mut out = target.clone();

        to_pfsense(&mut out, &source, &target);
        assert_eq!(
            out.get_text(&["ipsec", "phase1", "descr"]),
            Some("src-nested")
        );
    }

    #[test]
    fn keepalive_ping_host_starts_the_tunnel_immediately() {
        // pfSense runs ping_hosts.sh when IPsec starts, so tunnels with a ping
        // host come up at once; on-demand (trap) would leave them down.
        let phase2 = |ikeid: &str, net: &str, ping: &str| {
            format!(
                "<phase2><ikeid>{ikeid}</ikeid><mode>tunnel</mode><protocol>esp</protocol>\
                 <localid><type>lan</type></localid>\
                 <remoteid><type>network</type><address>{net}</address><netbits>24</netbits></remoteid>\
                 <encryption-algorithm-option><name>aes256gcm</name><keylen>128</keylen></encryption-algorithm-option>\
                 <pfsgroup>14</pfsgroup><lifetime>3600</lifetime>{ping}</phase2>"
            )
        };
        let phase1 = |ikeid: &str, peer: &str| {
            format!(
                "<phase1><ikeid>{ikeid}</ikeid><iketype>ikev2</iketype><interface>wan</interface>\
                 <remote-gateway>{peer}</remote-gateway><authentication_method>pre_shared_key</authentication_method>\
                 <pre-shared-key>secret</pre-shared-key><myid_type>myaddress</myid_type><peerid_type>peeraddress</peerid_type>\
                 <encryption><item><encryption-algorithm><name>aes</name><keylen>256</keylen></encryption-algorithm>\
                 <hash-algorithm>sha256</hash-algorithm><dhgroup>14</dhgroup></item></encryption>\
                 <lifetime>86400</lifetime><descr>T{ikeid}</descr><startaction></startaction></phase1>"
            )
        };
        let xml = format!(
            "<pfsense><interfaces><wan><if>vtnet0</if><ipaddr>203.0.113.20</ipaddr><subnet>27</subnet></wan>\
             <lan><if>vtnet1</if><ipaddr>10.90.0.254</ipaddr><subnet>24</subnet></lan></interfaces>\
             <ipsec>{}{}{}{}</ipsec></pfsense>",
            phase1("1", "198.51.100.10"),
            phase1("2", "198.51.100.20"),
            phase2("1", "10.10.0.0", "<pinghost>10.10.0.5</pinghost>"),
            phase2("2", "10.20.0.0", ""),
        );
        let source = parse(xml.as_bytes()).expect("source parse");
        let target = parse(b"<opnsense/>").expect("target parse");
        let mut out = target.clone();
        to_opnsense(&mut out, &source, &target);
        let starts: Vec<String> = out
            .get_child("OPNsense")
            .and_then(|o| o.get_child("Swanctl"))
            .and_then(|s| s.get_child("children"))
            .map(|c| {
                c.get_children("child")
                    .iter()
                    .map(|ch| ch.get_text(&["start_action"]).unwrap_or("").to_string())
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(starts, vec!["start", "trap"]);
    }

    #[test]
    fn maps_pfsense_phase1_phase2_into_opnsense_swanctl() {
        let source = parse(
            br#"<pfsense>
              <interfaces>
                <wan><if>vtnet0</if><ipaddr>203.0.113.20</ipaddr><subnet>27</subnet></wan>
                <lan><if>vtnet1</if><ipaddr>10.90.0.254</ipaddr><subnet>24</subnet></lan>
              </interfaces>
              <ipsec>
                <phase1>
                  <ikeid>1</ikeid><iketype>ikev2</iketype><interface>wan</interface><protocol>inet</protocol>
                  <remote-gateway>198.51.100.10</remote-gateway>
                  <authentication_method>pre_shared_key</authentication_method>
                  <pre-shared-key>secret</pre-shared-key>
                  <myid_type>myaddress</myid_type><peerid_type>peeraddress</peerid_type>
                  <encryption>
                    <item><encryption-algorithm><name>aes</name><keylen>256</keylen></encryption-algorithm><hash-algorithm>sha256</hash-algorithm><prf-algorithm>sha1</prf-algorithm><dhgroup>14</dhgroup></item>
                    <item><encryption-algorithm><name>aes256gcm</name><keylen>128</keylen></encryption-algorithm><hash-algorithm>sha256</hash-algorithm><prf-algorithm>sha1</prf-algorithm><dhgroup>14</dhgroup></item>
                  </encryption>
                  <lifetime>86400</lifetime><rekey_time></rekey_time><reauth_time></reauth_time>
                  <descr>Branch</descr>
                  <nat_traversal>on</nat_traversal><mobike>off</mobike>
                  <dpd_delay>10</dpd_delay><dpd_maxfail>5</dpd_maxfail>
                  <startaction></startaction><closeaction>start</closeaction>
                </phase1>
                <phase2>
                  <ikeid>1</ikeid><mode>tunnel</mode><reqid>1</reqid><protocol>esp</protocol>
                  <localid><type>lan</type></localid>
                  <remoteid><type>network</type><address>192.168.10.0</address><netbits>24</netbits></remoteid>
                  <encryption-algorithm-option><name>aes256gcm</name><keylen>auto</keylen></encryption-algorithm-option>
                  <hash-algorithm-option>hmac_sha256</hash-algorithm-option>
                  <pfsgroup>14</pfsgroup><lifetime>3600</lifetime>
                </phase2>
                <phase2>
                  <ikeid>1</ikeid><mode>tunnel</mode><reqid>2</reqid><protocol>esp</protocol>
                  <localid><type>lan</type></localid>
                  <remoteid><type>network</type><address>192.168.11.0</address><netbits>24</netbits></remoteid>
                  <encryption-algorithm-option><name>aes256gcm</name><keylen>auto</keylen></encryption-algorithm-option>
                  <pfsgroup>14</pfsgroup><lifetime>3600</lifetime>
                </phase2>
                <vtimaps/>
              </ipsec>
              <filter><rule><type>pass</type><interface>wan</interface><descr>user rule</descr></rule></filter>
            </pfsense>"#,
        )
        .expect("source parse");
        let target = parse(br#"<opnsense><filter><rule><type>pass</type><interface>wan</interface><descr>user rule</descr></rule></filter></opnsense>"#)
            .expect("target parse");
        let mut out = target.clone();

        to_opnsense(&mut out, &source, &target);
        let conn = |tag: &str| {
            out.get_text(&["OPNsense", "Swanctl", "Connections", "Connection", tag])
                .map(str::to_string)
        };
        assert_eq!(conn("remote_addrs").as_deref(), Some("198.51.100.10"));
        assert_eq!(conn("local_addrs").as_deref(), Some("203.0.113.20"));
        assert_eq!(conn("version").as_deref(), Some("2"));
        assert_eq!(
            conn("proposals").as_deref(),
            Some("aes256-sha256-modp2048,aes256gcm16-sha256-modp2048")
        );
        assert_eq!(conn("pools").as_deref(), Some(""));
        assert_eq!(conn("unique").as_deref(), Some("replace"));
        // pfSense: rekey = 90% of lifetime, no reauth on IKEv2, over = rest
        assert_eq!(conn("rekey_time").as_deref(), Some("77760"));
        assert_eq!(conn("reauth_time").as_deref(), Some("0"));
        assert_eq!(conn("over_time").as_deref(), Some("8640"));
        assert_eq!(conn("dpd_delay").as_deref(), Some("10"));
        assert_eq!(conn("dpd_timeout").as_deref(), Some(""));
        assert_eq!(conn("encap").as_deref(), Some("0"));
        assert_eq!(conn("description").as_deref(), Some("Branch"));

        // IKEv2: both phase 2 entries merged into one child, as pfSense does.
        let children = out
            .get_child("OPNsense")
            .and_then(|o| o.get_child("Swanctl"))
            .and_then(|s| s.get_child("children"))
            .map(|c| c.get_children("child").len());
        assert_eq!(children, Some(1));
        let child = |tag: &str| {
            out.get_text(&["OPNsense", "Swanctl", "children", "child", tag])
                .map(str::to_string)
        };
        assert_eq!(child("local_ts").as_deref(), Some("10.90.0.0/24"));
        assert_eq!(
            child("remote_ts").as_deref(),
            Some("192.168.10.0/24,192.168.11.0/24")
        );
        assert_eq!(
            child("esp_proposals").as_deref(),
            Some("aes256gcm16-modp2048")
        );
        assert_eq!(child("reqid").as_deref(), Some("1"));
        assert_eq!(child("rekey_time").as_deref(), Some("3240"));
        assert_eq!(child("start_action").as_deref(), Some("trap"));
        assert_eq!(child("close_action").as_deref(), Some("start"));
        assert_eq!(child("dpd_action").as_deref(), Some("start"));

        // IDs and the pre-shared key, keyed on the peer like OPNsense's legacy code.
        assert_eq!(
            out.get_text(&["OPNsense", "Swanctl", "locals", "local", "id"]),
            Some("203.0.113.20")
        );
        assert_eq!(
            out.get_text(&["OPNsense", "Swanctl", "remotes", "remote", "id"]),
            Some("198.51.100.10")
        );
        assert_eq!(
            out.get_text(&["OPNsense", "IPsec", "preSharedKeys", "preSharedKey", "Key"]),
            Some("secret")
        );
        assert_eq!(
            out.get_text(&[
                "OPNsense",
                "IPsec",
                "preSharedKeys",
                "preSharedKey",
                "ident"
            ]),
            Some("198.51.100.10")
        );

        // Legacy section: tunnels removed, IPsec enabled, other entries kept.
        let legacy = out.get_child("ipsec").expect("ipsec");
        assert_eq!(legacy.get_text(&["enable"]), Some("1"));
        assert!(legacy.get_child("phase1").is_none());
        assert!(legacy.get_child("phase2").is_none());
        assert!(legacy.get_child("vtimaps").is_some());

        // IKE, NAT-T and ESP from the peer, ahead of the user's rules.
        let descrs: Vec<String> = out
            .get_child("filter")
            .expect("filter")
            .get_children("rule")
            .iter()
            .map(|r| r.get_text(&["descr"]).unwrap_or("").to_string())
            .collect();
        assert_eq!(
            descrs,
            vec![
                "IPsec: Branch (IKE)",
                "IPsec: Branch (NAT-T)",
                "IPsec: Branch (ESP)",
                "user rule"
            ]
        );
        assert_eq!(
            out.get_child("filter").unwrap().get_children("rule")[0]
                .get_text(&["source", "address"]),
            Some("198.51.100.10")
        );
    }

    #[test]
    fn ikev1_gets_one_child_per_phase2_and_no_auto_rules_when_disabled() {
        let source = parse(
            br#"<pfsense>
              <system><disablevpnrules/></system>
              <ipsec>
                <phase1><ikeid>7</ikeid><iketype>ikev1</iketype><remote-gateway>198.51.100.30</remote-gateway>
                  <authentication_method>pre_shared_key</authentication_method><pre-shared-key>k</pre-shared-key>
                  <lifetime>28800</lifetime><dpd_delay>10</dpd_delay><dpd_maxfail>5</dpd_maxfail>
                  <myid_type>fqdn</myid_type><myid_data>fw.example.net</myid_data>
                  <peerid_type>keyid tag</peerid_type><peerid_data>peer1</peerid_data></phase1>
                <phase2><ikeid>7</ikeid><mode>tunnel</mode><reqid>3</reqid><localid><type>network</type><address>10.1.0.0</address><netbits>24</netbits></localid><remoteid><type>network</type><address>10.2.0.0</address><netbits>24</netbits></remoteid></phase2>
                <phase2><ikeid>7</ikeid><mode>tunnel</mode><reqid>4</reqid><localid><type>network</type><address>10.1.0.0</address><netbits>24</netbits></localid><remoteid><type>network</type><address>10.3.0.0</address><netbits>24</netbits></remoteid></phase2>
              </ipsec></pfsense>"#,
        )
        .expect("source parse");
        let target = parse(br#"<opnsense/>"#).expect("target parse");
        let mut out = target.clone();
        to_opnsense(&mut out, &source, &target);

        let swanctl = out
            .get_child("OPNsense")
            .and_then(|o| o.get_child("Swanctl"))
            .expect("swanctl");
        let children = swanctl.get_child("children").unwrap().get_children("child");
        assert_eq!(children.len(), 2);
        assert_eq!(children[1].get_text(&["remote_ts"]), Some("10.3.0.0/24"));
        assert_eq!(children[1].get_text(&["reqid"]), Some("4"));
        let conn = swanctl
            .get_child("Connections")
            .unwrap()
            .get_child("Connection")
            .unwrap();
        assert_eq!(conn.get_text(&["version"]), Some("1"));
        // IKEv1: reauth at 90%, DPD timeout = delay * (maxfail + 1)
        assert_eq!(conn.get_text(&["reauth_time"]), Some("25920"));
        assert_eq!(conn.get_text(&["dpd_timeout"]), Some("60"));
        assert_eq!(
            swanctl.get_text(&["locals", "local", "id"]),
            Some("fqdn:fw.example.net")
        );
        assert_eq!(
            swanctl.get_text(&["remotes", "remote", "id"]),
            Some("keyid:peer1")
        );
        assert!(out.get_child("filter").is_none());
    }

    #[test]
    fn keeps_baseline_ipsec_when_pfsense_has_no_tunnels() {
        let source = parse(br#"<pfsense><ipsec><vtimaps></vtimaps></ipsec></pfsense>"#)
            .expect("source parse");
        let target = parse(
            br#"<opnsense><OPNsense><IPsec version="1.0.6"><general><enabled/></general><charon/><keyPairs/><preSharedKeys/></IPsec></OPNsense></opnsense>"#,
        )
        .expect("target parse");
        let mut out = target.clone();

        to_opnsense(&mut out, &source, &target);
        let ipsec = out
            .get_child("OPNsense")
            .and_then(|o| o.get_child("IPsec"))
            .expect("IPsec");
        assert_eq!(
            ipsec.attributes.get("version").map(String::as_str),
            Some("1.0.6")
        );
        assert!(ipsec.get_child("general").is_some());
        assert!(ipsec.get_child("vtimaps").is_none());
    }

    #[test]
    fn keeps_disabled_state_and_baseline_model_versions() {
        let source = parse(
            br#"<pfsense><ipsec>
                <phase1><ikeid>1</ikeid><remote-gateway>198.51.100.10</remote-gateway><authentication_method>pre_shared_key</authentication_method><pre-shared-key>a</pre-shared-key><disabled></disabled></phase1>
                <phase1><ikeid>2</ikeid><remote-gateway>198.51.100.20</remote-gateway><authentication_method>pre_shared_key</authentication_method><pre-shared-key>b</pre-shared-key></phase1>
                <phase2><ikeid>2</ikeid><mode>tunnel</mode><localid><type>lan</type></localid><remoteid><type>network</type><address>192.168.20.0</address><netbits>24</netbits></remoteid><disabled></disabled></phase2>
                <phase2><ikeid>2</ikeid><mode>tunnel</mode><localid><type>lan</type></localid><remoteid><type>network</type><address>192.168.21.0</address><netbits>24</netbits></remoteid></phase2>
              </ipsec></pfsense>"#,
        )
        .expect("source parse");
        let target = parse(
            br#"<opnsense><OPNsense><IPsec version="1.0.6" persisted_at="1"/><Swanctl version="1.0.0"/></OPNsense></opnsense>"#,
        )
        .expect("target parse");
        let mut out = target.clone();

        to_opnsense(&mut out, &source, &target);
        let opn = out.get_child("OPNsense").expect("OPNsense");
        assert_eq!(
            opn.get_child("IPsec")
                .unwrap()
                .attributes
                .get("version")
                .map(String::as_str),
            Some("1.0.6")
        );
        assert_eq!(
            opn.get_child("Swanctl")
                .unwrap()
                .attributes
                .get("version")
                .map(String::as_str),
            Some("1.0.0")
        );
        let swanctl = opn.get_child("Swanctl").unwrap();
        let conns = swanctl
            .get_child("Connections")
            .unwrap()
            .get_children("Connection");
        assert_eq!(
            conns[0].get_text(&["enabled"]),
            Some("0"),
            "empty <disabled> = disabled"
        );
        assert_eq!(conns[1].get_text(&["enabled"]), Some("1"));
        let children = swanctl.get_child("children").unwrap().get_children("child");
        assert_eq!(children[0].get_text(&["enabled"]), Some("0"));
        assert_eq!(children[1].get_text(&["enabled"]), Some("1"));
    }

    #[test]
    fn to_pfsense_prefers_existing_top_level_ipsec_over_nested_copy() {
        let source = parse(
            br#"<opnsense><ipsec><phase1><descr>top-source</descr></phase1></ipsec><OPNsense><IPsec><phase1><descr>nested-source</descr></phase1></IPsec></OPNsense></opnsense>"#,
        )
        .expect("source parse");
        let target = parse(br#"<pfsense><system/></pfsense>"#).expect("target parse");
        let mut out = target.clone();

        to_pfsense(&mut out, &source, &target);
        assert_eq!(
            out.get_text(&["ipsec", "phase1", "descr"]),
            Some("top-source")
        );
    }

    #[test]
    fn to_opnsense_preserves_opnsense_style_top_level_ipsec() {
        let source = parse(
            br#"<pfsense><ipsec version="1.0.5"><general><enabled>1</enabled></general><charon><threads>8</threads><max_ikev1_exchanges>5</max_ikev1_exchanges></charon></ipsec></pfsense>"#,
        )
        .expect("source parse");
        let target = parse(br#"<opnsense><system/></opnsense>"#).expect("target parse");
        let mut out = target.clone();

        to_opnsense(&mut out, &source, &target);
        assert_eq!(
            out.get_text(&["OPNsense", "IPsec", "charon", "max_ikev1_exchanges"]),
            Some("5")
        );
        let attrs = out
            .get_child("OPNsense")
            .and_then(|opn| opn.get_child("IPsec"))
            .map(|n| &n.attributes);
        assert_eq!(
            attrs.and_then(|a| a.get("version")).map(String::as_str),
            Some("1.0.5")
        );
    }
}
