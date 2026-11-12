//! Decode HTML entities in pfSense config values.
//!
//! pfSense writes every config value through `htmlentities()`, and for some
//! fields inside `<![CDATA[...]]>` (`dump_xml_config_sub()`, `xmlparse.inc`);
//! its own parser decodes them again with `html_entity_decode()` (`cData()`).
//! Outside CDATA the XML decoding already undoes it, but inside CDATA nothing
//! does: a bind password "a<b" arrives as "a&lt;b". These fields are decoded
//! once, as pfSense does, before conversion.
//!
//! Descriptions are also HTML-encoded by pfSense's GUI before they are saved,
//! sometimes twice (`kifel&amp;eacute;` for "kifelé", `serp-&gt;z7` for
//! "serp->z7"). OPNsense stores and shows plain UTF-8, so descriptions are
//! decoded until they no longer change.

use xml_diff_core::XmlNode;

/// Elements whose text is a free-form description.
const DESCRIPTION_TAGS: &[&str] = &["descr", "description"];

/// pfSense's `is_cdata_entity()` (RELENG_2_7_2 `xmlparse.inc`): elements whose
/// name starts with one of these are written as CDATA with HTML entities.
const PFSENSE_CDATA_PREFIXES: &[&str] = &[
    "aclname",
    "auth_pass",
    "auth_prompt",
    "auth_user",
    "certca",
    "certname",
    "city",
    "common_name",
    "descr",
    "detail",
    "email",
    "encryption_password",
    "hint",
    "ldap_attr",
    "ldap_authcn",
    "ldap_basedn",
    "ldap_basedomain",
    "ldap_bind",
    "ldapbinddn",
    "ldapbindpass",
    "ldap_extended_query",
    "ldap_filter",
    "ldap_pam_groupdn",
    "ldap_pass",
    "ldap_user",
    "login_banner",
    "organization",
    "password",
    "rangedescr",
    "state",
    "text",
    "username",
    "varusersusername",
    "varuserspassword",
];

/// Decode, once, the HTML entities pfSense put into its CDATA fields (see the
/// module docs). Descriptions are left to `decode_descriptions`. Returns the
/// names of the elements changed (values are never returned: some are
/// passwords).
pub fn decode_pfsense_cdata(root: &mut XmlNode) -> Vec<String> {
    let mut changed = Vec::new();
    decode_cdata_rec(root, &mut changed);
    changed.sort();
    changed.dedup();
    changed
}

fn decode_cdata_rec(node: &mut XmlNode, changed: &mut Vec<String>) {
    let tag = node.tag.as_str();
    if !DESCRIPTION_TAGS.contains(&tag) && PFSENSE_CDATA_PREFIXES.iter().any(|p| tag.starts_with(p))
    {
        if let Some(text) = node.text.as_mut() {
            let decoded = decode_once(text);
            if decoded != *text {
                *text = decoded;
                changed.push(node.tag.clone());
            }
        }
    }
    for child in node.children.iter_mut() {
        decode_cdata_rec(child, changed);
    }
}

/// Decode entities in every description element below `root`. Returns the
/// number of elements changed.
pub fn decode_descriptions(root: &mut XmlNode) -> usize {
    let mut changed = 0;
    if DESCRIPTION_TAGS.contains(&root.tag.as_str()) {
        if let Some(text) = root.text.as_mut() {
            let decoded = decode(text);
            if decoded != *text {
                *text = decoded;
                changed += 1;
            }
        }
    }
    for child in root.children.iter_mut() {
        changed += decode_descriptions(child);
    }
    changed
}

/// Free-text elements checked for characters pfSense lost: descriptions,
/// separator texts and alias entry details. Only these, so secrets
/// (passwords, keys) are never printed.
const FREE_TEXT_TAGS: &[&str] = &["descr", "description", "text", "detail"];

/// Free-text values in which pfSense replaced a character by `?`.
///
/// pfSense stores some accented letters that are not in Latin-1 (for example
/// Hungarian `ő` and `ű`) as a plain `?` in the config, so "Külsők" arrives
/// as "Kuls?k" and the letter cannot be recovered from the backup. A `?`
/// between two letters is reported as `path: text`; URLs are skipped.
pub fn lost_characters(root: &XmlNode) -> Vec<String> {
    let mut found = Vec::new();
    collect_lost(root, &mut Vec::new(), &mut found);
    found
}

fn collect_lost<'a>(node: &'a XmlNode, path: &mut Vec<&'a str>, found: &mut Vec<String>) {
    path.push(node.tag.as_str());
    if FREE_TEXT_TAGS.contains(&node.tag.as_str()) {
        if let Some(text) = node.text.as_deref() {
            let text = decode(text);
            if !text.contains("://") && has_lost_letter(&text) {
                let shown: String = text.chars().take(60).collect();
                found.push(format!("{}: {shown}", path[1..].join("/")));
            }
        }
    }
    for child in &node.children {
        collect_lost(child, path, found);
    }
    path.pop();
}

fn has_lost_letter(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    chars
        .windows(3)
        .any(|w| w[1] == '?' && w[0].is_alphabetic() && w[2].is_alphabetic())
}

/// Decode HTML entities, repeating while the text changes (pfSense
/// sometimes encodes twice). Unknown or malformed entities are left as is.
pub fn decode(input: &str) -> String {
    let mut current = input.to_string();
    for _ in 0..3 {
        let next = decode_once(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn decode_once(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        let decoded = after.find(';').filter(|end| *end <= 10).and_then(|end| {
            let name = &after[..end];
            entity_char(name).map(|c| (c, end))
        });
        match decoded {
            Some((c, end)) => {
                out.push(c);
                rest = &after[end + 1..];
            }
            None => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

fn entity_char(name: &str) -> Option<char> {
    if let Some(num) = name.strip_prefix('#') {
        let code = match num.strip_prefix('x').or_else(|| num.strip_prefix('X')) {
            Some(hex) => u32::from_str_radix(hex, 16).ok()?,
            None => num.parse::<u32>().ok()?,
        };
        return char::from_u32(code);
    }
    if name == "apos" {
        return Some('\'');
    }
    NAMED
        .binary_search_by(|(n, _)| (*n).cmp(name))
        .ok()
        .map(|i| NAMED[i].1)
}

/// HTML 4 named entities (sorted for binary search).
const NAMED: &[(&str, char)] = &[
    ("AElig", '\u{c6}'),
    ("Aacute", '\u{c1}'),
    ("Acirc", '\u{c2}'),
    ("Agrave", '\u{c0}'),
    ("Alpha", '\u{391}'),
    ("Aring", '\u{c5}'),
    ("Atilde", '\u{c3}'),
    ("Auml", '\u{c4}'),
    ("Beta", '\u{392}'),
    ("Ccedil", '\u{c7}'),
    ("Chi", '\u{3a7}'),
    ("Dagger", '\u{2021}'),
    ("Delta", '\u{394}'),
    ("ETH", '\u{d0}'),
    ("Eacute", '\u{c9}'),
    ("Ecirc", '\u{ca}'),
    ("Egrave", '\u{c8}'),
    ("Epsilon", '\u{395}'),
    ("Eta", '\u{397}'),
    ("Euml", '\u{cb}'),
    ("Gamma", '\u{393}'),
    ("Iacute", '\u{cd}'),
    ("Icirc", '\u{ce}'),
    ("Igrave", '\u{cc}'),
    ("Iota", '\u{399}'),
    ("Iuml", '\u{cf}'),
    ("Kappa", '\u{39a}'),
    ("Lambda", '\u{39b}'),
    ("Mu", '\u{39c}'),
    ("Ntilde", '\u{d1}'),
    ("Nu", '\u{39d}'),
    ("OElig", '\u{152}'),
    ("Oacute", '\u{d3}'),
    ("Ocirc", '\u{d4}'),
    ("Ograve", '\u{d2}'),
    ("Omega", '\u{3a9}'),
    ("Omicron", '\u{39f}'),
    ("Oslash", '\u{d8}'),
    ("Otilde", '\u{d5}'),
    ("Ouml", '\u{d6}'),
    ("Phi", '\u{3a6}'),
    ("Pi", '\u{3a0}'),
    ("Prime", '\u{2033}'),
    ("Psi", '\u{3a8}'),
    ("Rho", '\u{3a1}'),
    ("Scaron", '\u{160}'),
    ("Sigma", '\u{3a3}'),
    ("THORN", '\u{de}'),
    ("Tau", '\u{3a4}'),
    ("Theta", '\u{398}'),
    ("Uacute", '\u{da}'),
    ("Ucirc", '\u{db}'),
    ("Ugrave", '\u{d9}'),
    ("Upsilon", '\u{3a5}'),
    ("Uuml", '\u{dc}'),
    ("Xi", '\u{39e}'),
    ("Yacute", '\u{dd}'),
    ("Yuml", '\u{178}'),
    ("Zeta", '\u{396}'),
    ("aacute", '\u{e1}'),
    ("acirc", '\u{e2}'),
    ("acute", '\u{b4}'),
    ("aelig", '\u{e6}'),
    ("agrave", '\u{e0}'),
    ("alefsym", '\u{2135}'),
    ("alpha", '\u{3b1}'),
    ("amp", '\u{26}'),
    ("and", '\u{2227}'),
    ("ang", '\u{2220}'),
    ("aring", '\u{e5}'),
    ("asymp", '\u{2248}'),
    ("atilde", '\u{e3}'),
    ("auml", '\u{e4}'),
    ("bdquo", '\u{201e}'),
    ("beta", '\u{3b2}'),
    ("brvbar", '\u{a6}'),
    ("bull", '\u{2022}'),
    ("cap", '\u{2229}'),
    ("ccedil", '\u{e7}'),
    ("cedil", '\u{b8}'),
    ("cent", '\u{a2}'),
    ("chi", '\u{3c7}'),
    ("circ", '\u{2c6}'),
    ("clubs", '\u{2663}'),
    ("cong", '\u{2245}'),
    ("copy", '\u{a9}'),
    ("crarr", '\u{21b5}'),
    ("cup", '\u{222a}'),
    ("curren", '\u{a4}'),
    ("dArr", '\u{21d3}'),
    ("dagger", '\u{2020}'),
    ("darr", '\u{2193}'),
    ("deg", '\u{b0}'),
    ("delta", '\u{3b4}'),
    ("diams", '\u{2666}'),
    ("divide", '\u{f7}'),
    ("eacute", '\u{e9}'),
    ("ecirc", '\u{ea}'),
    ("egrave", '\u{e8}'),
    ("empty", '\u{2205}'),
    ("emsp", '\u{2003}'),
    ("ensp", '\u{2002}'),
    ("epsilon", '\u{3b5}'),
    ("equiv", '\u{2261}'),
    ("eta", '\u{3b7}'),
    ("eth", '\u{f0}'),
    ("euml", '\u{eb}'),
    ("euro", '\u{20ac}'),
    ("exist", '\u{2203}'),
    ("fnof", '\u{192}'),
    ("forall", '\u{2200}'),
    ("frac12", '\u{bd}'),
    ("frac14", '\u{bc}'),
    ("frac34", '\u{be}'),
    ("frasl", '\u{2044}'),
    ("gamma", '\u{3b3}'),
    ("ge", '\u{2265}'),
    ("gt", '\u{3e}'),
    ("hArr", '\u{21d4}'),
    ("harr", '\u{2194}'),
    ("hearts", '\u{2665}'),
    ("hellip", '\u{2026}'),
    ("iacute", '\u{ed}'),
    ("icirc", '\u{ee}'),
    ("iexcl", '\u{a1}'),
    ("igrave", '\u{ec}'),
    ("image", '\u{2111}'),
    ("infin", '\u{221e}'),
    ("int", '\u{222b}'),
    ("iota", '\u{3b9}'),
    ("iquest", '\u{bf}'),
    ("isin", '\u{2208}'),
    ("iuml", '\u{ef}'),
    ("kappa", '\u{3ba}'),
    ("lArr", '\u{21d0}'),
    ("lambda", '\u{3bb}'),
    ("lang", '\u{2329}'),
    ("laquo", '\u{ab}'),
    ("larr", '\u{2190}'),
    ("lceil", '\u{2308}'),
    ("ldquo", '\u{201c}'),
    ("le", '\u{2264}'),
    ("lfloor", '\u{230a}'),
    ("lowast", '\u{2217}'),
    ("loz", '\u{25ca}'),
    ("lrm", '\u{200e}'),
    ("lsaquo", '\u{2039}'),
    ("lsquo", '\u{2018}'),
    ("lt", '\u{3c}'),
    ("macr", '\u{af}'),
    ("mdash", '\u{2014}'),
    ("micro", '\u{b5}'),
    ("middot", '\u{b7}'),
    ("minus", '\u{2212}'),
    ("mu", '\u{3bc}'),
    ("nabla", '\u{2207}'),
    ("nbsp", '\u{a0}'),
    ("ndash", '\u{2013}'),
    ("ne", '\u{2260}'),
    ("ni", '\u{220b}'),
    ("not", '\u{ac}'),
    ("notin", '\u{2209}'),
    ("nsub", '\u{2284}'),
    ("ntilde", '\u{f1}'),
    ("nu", '\u{3bd}'),
    ("oacute", '\u{f3}'),
    ("ocirc", '\u{f4}'),
    ("oelig", '\u{153}'),
    ("ograve", '\u{f2}'),
    ("oline", '\u{203e}'),
    ("omega", '\u{3c9}'),
    ("omicron", '\u{3bf}'),
    ("oplus", '\u{2295}'),
    ("or", '\u{2228}'),
    ("ordf", '\u{aa}'),
    ("ordm", '\u{ba}'),
    ("oslash", '\u{f8}'),
    ("otilde", '\u{f5}'),
    ("otimes", '\u{2297}'),
    ("ouml", '\u{f6}'),
    ("para", '\u{b6}'),
    ("part", '\u{2202}'),
    ("permil", '\u{2030}'),
    ("perp", '\u{22a5}'),
    ("phi", '\u{3c6}'),
    ("pi", '\u{3c0}'),
    ("piv", '\u{3d6}'),
    ("plusmn", '\u{b1}'),
    ("pound", '\u{a3}'),
    ("prime", '\u{2032}'),
    ("prod", '\u{220f}'),
    ("prop", '\u{221d}'),
    ("psi", '\u{3c8}'),
    ("quot", '\u{22}'),
    ("rArr", '\u{21d2}'),
    ("radic", '\u{221a}'),
    ("rang", '\u{232a}'),
    ("raquo", '\u{bb}'),
    ("rarr", '\u{2192}'),
    ("rceil", '\u{2309}'),
    ("rdquo", '\u{201d}'),
    ("real", '\u{211c}'),
    ("reg", '\u{ae}'),
    ("rfloor", '\u{230b}'),
    ("rho", '\u{3c1}'),
    ("rlm", '\u{200f}'),
    ("rsaquo", '\u{203a}'),
    ("rsquo", '\u{2019}'),
    ("sbquo", '\u{201a}'),
    ("scaron", '\u{161}'),
    ("sdot", '\u{22c5}'),
    ("sect", '\u{a7}'),
    ("shy", '\u{ad}'),
    ("sigma", '\u{3c3}'),
    ("sigmaf", '\u{3c2}'),
    ("sim", '\u{223c}'),
    ("spades", '\u{2660}'),
    ("sub", '\u{2282}'),
    ("sube", '\u{2286}'),
    ("sum", '\u{2211}'),
    ("sup", '\u{2283}'),
    ("sup1", '\u{b9}'),
    ("sup2", '\u{b2}'),
    ("sup3", '\u{b3}'),
    ("supe", '\u{2287}'),
    ("szlig", '\u{df}'),
    ("tau", '\u{3c4}'),
    ("there4", '\u{2234}'),
    ("theta", '\u{3b8}'),
    ("thetasym", '\u{3d1}'),
    ("thinsp", '\u{2009}'),
    ("thorn", '\u{fe}'),
    ("tilde", '\u{2dc}'),
    ("times", '\u{d7}'),
    ("trade", '\u{2122}'),
    ("uArr", '\u{21d1}'),
    ("uacute", '\u{fa}'),
    ("uarr", '\u{2191}'),
    ("ucirc", '\u{fb}'),
    ("ugrave", '\u{f9}'),
    ("uml", '\u{a8}'),
    ("upsih", '\u{3d2}'),
    ("upsilon", '\u{3c5}'),
    ("uuml", '\u{fc}'),
    ("weierp", '\u{2118}'),
    ("xi", '\u{3be}'),
    ("yacute", '\u{fd}'),
    ("yen", '\u{a5}'),
    ("yuml", '\u{ff}'),
    ("zeta", '\u{3b6}'),
    ("zwj", '\u{200d}'),
    ("zwnj", '\u{200c}'),
];

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::{decode, decode_descriptions, decode_pfsense_cdata};

    #[test]
    fn decodes_pfsense_cdata_fields_once() {
        let mut root = parse(
            br#"<pfsense><system><authserver>
              <ldap_bindpw><![CDATA[a&lt;b&amp;amp;c]]></ldap_bindpw>
              <ldap_basedn><![CDATA[DC=x,DC=y]]></ldap_basedn>
              <host>10.0.0.1</host>
            </authserver>
            <user><name>n&amp;lt;</name></user></system></pfsense>"#,
        )
        .expect("parse");
        let changed = decode_pfsense_cdata(&mut root);
        assert_eq!(changed, vec!["ldap_bindpw".to_string()]);
        // Decoded once, as pfSense's html_entity_decode() does: "&amp;amp;"
        // stays "&amp;".
        assert_eq!(
            root.get_text(&["system", "authserver", "ldap_bindpw"]),
            Some("a<b&amp;c")
        );
        // Fields pfSense does not write as CDATA are left alone.
        assert_eq!(root.get_text(&["system", "user", "name"]), Some("n&lt;"));
    }

    #[test]
    fn reports_letters_pfsense_replaced_by_question_marks() {
        let root = xml_diff_core::parse(
            br#"<pfsense>
              <filter>
                <rule><descr>ok?</descr></rule>
                <rule><descr>Kifel&amp;eacute; Kuls?k</descr></rule>
                <separator><lan><sep0><text><![CDATA[Bels?k]]></text></sep0></lan></separator>
              </filter>
              <system><user><password>pa?ss</password></user></system>
              <installedpackages><menu><url>/pkg.php?xml=a.xml</url><descr>see https://x.invalid/a?b=c</descr></menu></installedpackages>
            </pfsense>"#,
        )
        .expect("parse");
        assert_eq!(
            super::lost_characters(&root),
            vec![
                "filter/rule/descr: Kifel\u{e9} Kuls?k".to_string(),
                "filter/separator/lan/sep0/text: Bels?k".to_string(),
            ]
        );
    }

    #[test]
    fn decodes_single_and_double_encoded_entities() {
        assert_eq!(
            decode("zabbix kifel&amp;eacute; saj&amp;aacute;t ip"),
            "zabbix kifel\u{e9} saj\u{e1}t ip"
        );
        assert_eq!(decode("serp-&gt;z7"), "serp->z7");
        assert_eq!(
            decode("&lt;tag&gt; &quot;q&quot; &apos;a&apos; &#39;n&#x41;"),
            "<tag> \"q\" 'a' 'nA"
        );
        assert_eq!(
            decode("R&D & co; &unknown; &amp"),
            "R&D & co; &unknown; &amp"
        );
        assert_eq!(decode("&Ouml;&ouml;&uuml;"), "\u{d6}\u{f6}\u{fc}");
    }

    #[test]
    fn decodes_only_description_elements() {
        let mut root = parse(
            br#"<pfsense><filter><rule><descr>a &amp;gt; b</descr><tag>x&amp;y</tag></rule></filter><aliases><alias><description>&amp;eacute;</description></alias></aliases></pfsense>"#,
        )
        .expect("parse");
        assert_eq!(decode_descriptions(&mut root), 2);
        assert_eq!(root.get_text(&["filter", "rule", "descr"]), Some("a > b"));
        assert_eq!(root.get_text(&["filter", "rule", "tag"]), Some("x&y"));
        assert_eq!(
            root.get_text(&["aliases", "alias", "description"]),
            Some("\u{e9}")
        );
    }
}
