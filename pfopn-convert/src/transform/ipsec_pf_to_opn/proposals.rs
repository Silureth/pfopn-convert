//! IKE/ESP proposal strings: built the way pfSense builds them, renamed to
//! OPNsense's spelling and checked against the proposals OPNsense's Swanctl
//! model accepts (`IPsec/FieldTypes/IPsecProposalField.php`, 26.7).

use xml_diff_core::XmlNode;

use super::util::text_or;

/// DH groups OPNsense generates proposal combinations for.
const DH_GROUPS: &[&str] = &[
    "modp2048", "modp3072", "modp4096", "modp6144", "modp8192", "ecp224", "ecp256", "ecp384",
    "ecp521", "ecp224bp", "ecp256bp", "ecp384bp", "ecp512bp", "x25519", "x448",
];
const GEN_ENC: &[&str] = &[
    "aes128",
    "aes192",
    "aes256",
    "aes128gcm16",
    "aes192gcm16",
    "aes256gcm16",
];
const GEN_INT: &[&str] = &["sha256", "sha384", "sha512", "aesxcbc"];

const COMMON: &[&str] = &[
    "default",
    "aes256-sha256-modp2048",
    "aes256-sha512-modp2048",
    "aes128-sha256-modp2048",
    "aes128-sha512-modp2048",
    "aes256-sha256-modp4096",
    "aes256-sha512-modp4096",
    "aes256-sha256-ecp521",
    "aes256-sha512-ecp521",
    "aes256-sha1-modp2048",
    "aes192-sha1-modp2048",
    "aes128-sha1-modp2048",
    "aes256-sha1-modp4096",
    "aes256-sha1-ecp521",
    "aes256-sha256-modp1024",
    "aes256-sha512-modp1024",
    "aes256-sha256-modp1536",
    "aes128-sha256-modp1536",
    "aes256gcm16-sha256-modp1536",
    "aes256-sha1",
    "aes256-sha256",
    "null",
];
const AEAD_PHASE1: &[&str] = &[
    "aes256gcm16-sha256-modp2048",
    "aes256gcm16-sha512-modp2048",
    "aes256gcm16-sha256-ecp521",
    "aes256gcm16-sha512-ecp521",
    "aes256gcm16-sha256-x25519",
    "aes256gcm16-sha512-x25519",
    "aes256gcm16-sha256-x448",
    "aes256gcm16-sha512-x448",
    "aes128gcm16-sha256-modp2048",
    "aes128gcm16-sha512-modp2048",
    "aes128gcm16-sha256-ecp521",
    "aes128gcm16-sha512-ecp521",
    "aes128gcm16-sha256-x25519",
    "aes128gcm16-sha512-x25519",
    "aes128gcm16-sha256-x448",
    "aes128gcm16-sha512-x448",
    "chacha20poly1305-sha256-x25519",
    "chacha20poly1305-sha384-x25519",
    "chacha20poly1305-sha512-x25519",
    "chacha20poly1305-sha256-x448",
    "chacha20poly1305-sha384-x448",
    "chacha20poly1305-sha512-x448",
];
const AEAD_PHASE2: &[&str] = &[
    "aes256gcm16-modp2048",
    "aes256gcm16-ecp521",
    "aes256gcm16-x25519",
    "aes256gcm16-x448",
    "aes128gcm16-modp2048",
    "aes128gcm16-ecp521",
    "aes128gcm16-x25519",
    "aes128gcm16-x448",
    "aes256gcm16",
    "chacha20poly1305-x25519",
    "chacha20poly1305-x448",
    "chacha20poly1305",
];

/// Whether OPNsense's proposal list for `phase` (1 = IKE, 2 = ESP) offers `p`.
pub(super) fn is_allowed(p: &str, phase: u8) -> bool {
    if COMMON.contains(&p) {
        return true;
    }
    let aead = if phase == 1 { AEAD_PHASE1 } else { AEAD_PHASE2 };
    if aead.contains(&p) {
        return true;
    }
    let parts: Vec<&str> = p.split('-').collect();
    match parts.as_slice() {
        [enc, int, dh] => GEN_ENC.contains(enc) && GEN_INT.contains(int) && DH_GROUPS.contains(dh),
        // Phase 2 GCM without integrity algorithm: "<gcm>-<dh>".
        [enc, dh] if phase == 2 => {
            enc.contains("gcm16") && GEN_ENC.contains(enc) && DH_GROUPS.contains(dh)
        }
        _ => false,
    }
}

/// pfSense DH group number → strongSwan keyword, in OPNsense's spelling.
fn dh_name(group: &str) -> Option<&'static str> {
    Some(match group.trim() {
        "1" => "modp768",
        "2" => "modp1024",
        "5" => "modp1536",
        "14" => "modp2048",
        "15" => "modp3072",
        "16" => "modp4096",
        "17" => "modp6144",
        "18" => "modp8192",
        "19" => "ecp256",
        "20" => "ecp384",
        "21" => "ecp521",
        "22" => "modp1024s160",
        "23" => "modp2048s224",
        "24" => "modp2048s256",
        "25" => "ecp192",
        "26" => "ecp224",
        "27" => "ecp224bp",
        "28" => "ecp256bp",
        "29" => "ecp384bp",
        "30" => "ecp512bp",
        "31" => "x25519",
        "32" => "x448",
        _ => return None,
    })
}

/// pfSense writes GCM as `<alg>gcm<ICV bits>` (aes256gcm128); OPNsense lists
/// strongSwan's byte form (aes256gcm16).
fn cipher_name(name: &str, keylen: &str) -> String {
    if name.contains("gcm") {
        let icv = match keylen {
            "128" | "" => "16",
            "96" => "12",
            "64" => "8",
            other => other,
        };
        format!("{name}{icv}")
    } else {
        format!("{name}{keylen}")
    }
}

/// IKE proposals of a phase1, in pfSense's order. Returns (kept, dropped notes).
pub(super) fn ike_proposals(p1: &XmlNode) -> (Vec<String>, Vec<String>) {
    let use_prf = text_or(p1, "prfselect_enable", "") == "yes";
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    let items = p1
        .get_child("encryption")
        .map(|e| e.get_children("item"))
        .unwrap_or_default();
    for item in items {
        let name = item
            .get_text(&["encryption-algorithm", "name"])
            .map(str::trim)
            .unwrap_or("");
        let keylen = item
            .get_text(&["encryption-algorithm", "keylen"])
            .map(str::trim)
            .unwrap_or("");
        let hash = text_or(item, "hash-algorithm", "");
        if name.is_empty() || hash.is_empty() {
            continue;
        }
        let dh = text_or(item, "dhgroup", "");
        let dh = match dh_name(dh) {
            Some(d) => format!("-{d}"),
            None if dh.is_empty() => String::new(),
            None => {
                dropped.push(format!("with DH group {dh} not supported; dropped"));
                continue;
            }
        };
        let base = format!("{}-{hash}", cipher_name(name, keylen));
        let prf = text_or(item, "prf-algorithm", "");
        let proposal = format!("{base}{dh}");
        if use_prf && !prf.is_empty() {
            dropped.push(format!(
                "{base}-prf{prf}{dh}: OPNsense has no separate PRF choice; using {proposal}"
            ));
        }
        if is_allowed(&proposal, 1) {
            if !kept.contains(&proposal) {
                kept.push(proposal);
            }
        } else {
            dropped.push(format!("{proposal} not offered by OPNsense; dropped"));
        }
    }
    (kept, dropped)
}

/// ESP proposals of a phase2, in pfSense's order (AEAD first, "auto" key
/// lengths expanded high to low). Returns (kept, dropped notes). Expanded
/// GCM variants with shorter ICVs, which OPNsense does not list, are skipped
/// quietly when the 16-byte one is kept.
pub(super) fn esp_proposals(p2: &XmlNode) -> (Vec<String>, Vec<String>) {
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    if text_or(p2, "protocol", "esp") == "ah" {
        dropped
            .push("AH is not supported by OPNsense connections; using 'default' ESP".to_string());
        return (kept, dropped);
    }
    let dh = text_or(p2, "pfsgroup", "");
    let dh = match dh_name(dh) {
        Some(d) => format!("-{d}"),
        None => String::new(),
    };
    let hashes: Vec<String> = p2
        .get_children("hash-algorithm-option")
        .iter()
        .filter_map(|h| h.text.as_deref().map(str::trim))
        .filter(|h| !h.is_empty())
        .map(|h| h.trim_start_matches("hmac_").to_string())
        .collect();
    let algos = p2.get_children("encryption-algorithm-option");
    let (aead, plain): (Vec<&XmlNode>, Vec<&XmlNode>) = algos
        .into_iter()
        .partition(|a| text_or(a, "name", "").contains("gcm"));
    let ordered = aead.into_iter().rev().chain(plain);
    for alg in ordered {
        let name = text_or(alg, "name", "");
        if name.is_empty() {
            continue;
        }
        let keylen = text_or(alg, "keylen", "");
        let is_aead = name.contains("gcm") || name == "chacha20poly1305";
        let keylens: Vec<(String, bool)> = if keylen == "auto" {
            let expanded: &[&str] = if name == "aes" {
                &["256", "192", "128"]
            } else if name.contains("gcm") {
                &["128", "96", "64"]
            } else {
                &[""]
            };
            expanded.iter().map(|k| ((*k).to_string(), true)).collect()
        } else {
            vec![(keylen.to_string(), false)]
        };
        for (kl, auto) in keylens {
            let cipher = if name == "chacha20poly1305" {
                name.to_string()
            } else {
                cipher_name(name, &kl)
            };
            let candidates: Vec<String> = if !is_aead && !hashes.is_empty() {
                hashes.iter().map(|h| format!("{cipher}-{h}{dh}")).collect()
            } else {
                vec![format!("{cipher}{dh}")]
            };
            for c in candidates {
                if is_allowed(&c, 2) {
                    if !kept.contains(&c) {
                        kept.push(c);
                    }
                } else if !(auto && is_aead) {
                    dropped.push(format!("{c} not offered by OPNsense; dropped"));
                }
            }
        }
    }
    (kept, dropped)
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::{esp_proposals, ike_proposals, is_allowed};

    #[test]
    fn allow_list_matches_opnsense() {
        assert!(is_allowed("aes256-sha256-modp2048", 1));
        assert!(is_allowed("aes256gcm16-sha256-modp2048", 1));
        assert!(is_allowed("aes192-sha384-ecp384", 1));
        assert!(!is_allowed("aes256gcm16-modp2048", 1));
        assert!(is_allowed("aes256gcm16-modp2048", 2));
        assert!(is_allowed("aes192gcm16-x25519", 2));
        assert!(!is_allowed("aes256gcm12-modp2048", 2));
        assert!(!is_allowed("3des-sha1-modp1024", 1));
    }

    #[test]
    fn ike_proposals_follow_pfsense_items() {
        let p1 = parse(
            br#"<phase1><encryption>
                <item><encryption-algorithm><name>aes</name><keylen>256</keylen></encryption-algorithm><hash-algorithm>sha256</hash-algorithm><prf-algorithm>sha1</prf-algorithm><dhgroup>14</dhgroup></item>
                <item><encryption-algorithm><name>aes256gcm</name><keylen>128</keylen></encryption-algorithm><hash-algorithm>sha256</hash-algorithm><dhgroup>14</dhgroup></item>
                <item><encryption-algorithm><name>3des</name></encryption-algorithm><hash-algorithm>sha1</hash-algorithm><dhgroup>2</dhgroup></item>
            </encryption></phase1>"#,
        )
        .expect("parse");
        let (kept, dropped) = ike_proposals(&p1);
        assert_eq!(
            kept,
            vec!["aes256-sha256-modp2048", "aes256gcm16-sha256-modp2048"]
        );
        assert_eq!(dropped.len(), 1);
        assert!(dropped[0].contains("3des-sha1-modp1024"));
    }

    #[test]
    fn esp_proposals_expand_auto_and_put_aead_first() {
        let p2 = parse(
            br#"<phase2><protocol>esp</protocol>
                <encryption-algorithm-option><name>aes</name><keylen>auto</keylen></encryption-algorithm-option>
                <encryption-algorithm-option><name>aes256gcm</name><keylen>auto</keylen></encryption-algorithm-option>
                <hash-algorithm-option>hmac_sha256</hash-algorithm-option>
                <pfsgroup>14</pfsgroup></phase2>"#,
        )
        .expect("parse");
        let (kept, dropped) = esp_proposals(&p2);
        assert_eq!(
            kept,
            vec![
                "aes256gcm16-modp2048",
                "aes256-sha256-modp2048",
                "aes192-sha256-modp2048",
                "aes128-sha256-modp2048"
            ]
        );
        assert!(dropped.is_empty(), "{dropped:?}");
    }
}
