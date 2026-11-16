//! Splits the `convert` and `verify` output into the parts the report
//! screens show: a summary, the warnings, the info lines and verify's issues.

/// One message: an optional topic ("reply-to", "DNSBL Malicious", ...) and
/// the rest of the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub topic: Option<String>,
    pub text: String,
}

#[derive(Debug, Default)]
pub struct ParsedReport {
    pub errors: Vec<Entry>,
    pub warnings: Vec<Entry>,
    pub infos: Vec<Entry>,
    /// `convert_summary` counts, as "349 rules" etc.
    pub converted: Vec<String>,
    /// Lines of the `plugins:` table.
    pub plugins: Vec<String>,
    /// Text after the plugins table (what to do about missing plugins).
    pub plugin_notes: Vec<String>,
    /// verify's "errors=0 warnings=10".
    pub verify_result: Option<(usize, usize)>,
    pub verify_issues: Vec<Entry>,
}

pub fn parse(convert_log: &str, verify_log: &str) -> ParsedReport {
    let mut report = ParsedReport::default();
    let mut in_plugins = false;
    let mut after_plugins = false;

    for line in convert_log.lines() {
        if in_plugins {
            if line.trim().is_empty() {
                if !report.plugins.is_empty() {
                    in_plugins = false;
                    after_plugins = true;
                }
            } else {
                report.plugins.push(line.trim().to_string());
            }
            continue;
        }
        if after_plugins && line.starts_with("  ") {
            report.plugin_notes.push(line.trim().to_string());
            continue;
        }
        if line == "plugins:" {
            in_plugins = true;
        } else if let Some(item) = line.strip_prefix("warning:   ") {
            // A list item under the previous warning.
            match report.warnings.last_mut() {
                Some(last) => last.text.push_str(&format!("\n- {}", item.trim())),
                None => report.warnings.push(entry(item)),
            }
        } else if let Some(rest) = line.strip_prefix("warning: ") {
            report.warnings.push(entry(rest));
        } else if let Some(rest) = line.strip_prefix("info: ") {
            report.infos.push(entry(rest));
        } else if let Some(rest) = line.strip_prefix("Error: ") {
            report.errors.push(entry(rest));
        } else if let Some(rest) = line.strip_prefix("convert_summary ") {
            report.converted = rest
                .split_whitespace()
                .filter_map(|pair| pair.split_once('='))
                .map(|(key, value)| format!("{value} {key}"))
                .collect();
        }
    }

    for line in verify_log.lines() {
        if let Some(rest) = line.strip_prefix("result ") {
            let value = |key: &str| {
                rest.split_whitespace()
                    .find_map(|pair| pair.strip_prefix(key))
                    .and_then(|v| v.parse::<usize>().ok())
            };
            if let (Some(errors), Some(warnings)) = (value("errors="), value("warnings=")) {
                report.verify_result = Some((errors, warnings));
            }
        } else if let Some(rest) = line.strip_prefix("- [error] ") {
            report.verify_issues.push(Entry {
                topic: Some("ERROR".to_string()),
                text: rest.to_string(),
            });
        } else if let Some(rest) = line.strip_prefix("- [warning] ") {
            // Verify's codes (duplicate_firewall_rule) read better as words.
            let mut issue = entry(rest);
            issue.topic = issue.topic.map(|code| code.replace('_', " "));
            report.verify_issues.push(issue);
        } else if let Some(rest) = line.strip_prefix("Error: ") {
            report.errors.push(entry(rest));
        }
    }
    report
}

/// "reply-to: rule 'x' on wan: ..." -> topic "reply-to", text "rule 'x' ...".
/// Only a short first segment without spaces or quotes-heavy content counts as
/// a topic, so ordinary sentences stay whole.
fn entry(line: &str) -> Entry {
    let line = line.trim();
    if let Some((topic, rest)) = line.split_once(": ") {
        let looks_like_topic = topic.len() <= 32
            && !topic.contains('(')
            && !topic.contains('\'')
            && topic.split_whitespace().count() <= 3;
        if looks_like_topic && !rest.is_empty() {
            return Entry {
                topic: Some(topic.to_string()),
                text: rest.to_string(),
            };
        }
    }
    Entry {
        topic: None,
        text: line.to_string(),
    }
}

/// Greedy word wrap to `width` columns; continuation lines get `indent`
/// spaces. Words longer than a line (URLs) get a line of their own.
pub fn wrap(text: &str, width: usize, indent: usize) -> String {
    let mut out = String::new();
    for (n, paragraph) in text.split('\n').enumerate() {
        if n > 0 {
            out.push('\n');
        }
        let mut column = 0;
        for word in paragraph.split_whitespace() {
            let len = word.chars().count();
            if column > 0 && column + 1 + len > width {
                out.push('\n');
                out.push_str(&" ".repeat(indent));
                column = indent;
            } else if column > 0 {
                out.push(' ');
                column += 1;
            }
            out.push_str(word);
            column += len;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONVERT: &str = "\
pfopn-convert 0.5.2
info: decoded HTML entities in 88 pfSense description(s) (e.g. &eacute; -> x)
warning: reply-to: rule 'NAT a' on wan: alias 'zabbix' has entries that cannot be checked
warning: rules kept in the old format:
warning:   rule one
warning:   rule two
info: separators: 32 pfSense separator(s) became rule categories
convert_summary interfaces=7 bridges=0 aliases=53 rules=349 routes=0 vpns=3
warning: node_exporter: extra flags not converted

plugins:
  converted        os-zabbix7-agent       from Zabbix Agent 7
  NOT INSTALLED    os-node_exporter       from node_exporter

  The baseline does not have os-node_exporter, so their settings were not converted.
  To convert them: install them.
";

    const VERIFY: &str = "\
verify platform=opnsense version=24.0 target=opnsense
result errors=0 warnings=2
issues
- [warning] duplicate_firewall_rule: 2 rules on lan match the same traffic: 'A', 'B'
- [error] broken_ref: rule references missing alias x
";

    #[test]
    fn splits_convert_and_verify_output() {
        let report = parse(CONVERT, VERIFY);
        assert_eq!(report.infos.len(), 2);
        assert_eq!(report.infos[1].topic.as_deref(), Some("separators"));
        assert_eq!(report.infos[0].topic, None);
        assert_eq!(report.warnings.len(), 3);
        assert_eq!(report.warnings[0].topic.as_deref(), Some("reply-to"));
        assert_eq!(
            report.warnings[1].text,
            "rules kept in the old format:\n- rule one\n- rule two"
        );
        assert_eq!(report.converted[3], "349 rules");
        assert_eq!(report.plugins.len(), 2);
        assert_eq!(report.plugin_notes.len(), 2);
        assert_eq!(report.verify_result, Some((0, 2)));
        assert_eq!(report.verify_issues.len(), 2);
        assert_eq!(
            report.verify_issues[0].topic.as_deref(),
            Some("duplicate firewall rule")
        );
        assert_eq!(report.verify_issues[1].topic.as_deref(), Some("ERROR"));
    }

    #[test]
    fn convert_errors_are_collected() {
        let report = parse(
            "Error: interface preflight failed: missing target interfaces: opt3\n",
            "",
        );
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.verify_result, None);
    }

    #[test]
    fn wraps_with_hanging_indent() {
        assert_eq!(wrap("aaa bbb ccc ddd", 7, 2), "aaa bbb\n  ccc\n  ddd");
        assert_eq!(wrap("a\n- b c", 3, 2), "a\n- b\n  c");
    }
}
