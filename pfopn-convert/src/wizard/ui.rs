//! The wizard's screens. Each screen runs its own cursive session and returns
//! the user's choice, so OPNsense's own commands can take over the terminal
//! between screens.

use std::path::PathBuf;

use cursive::event::Key;
use cursive::traits::{Nameable, Resizable, Scrollable};
use cursive::view::{Margins, SizeConstraint};
use cursive::views::{
    Checkbox, Dialog, DummyView, EditView, LinearLayout, ListView, ResizedView, SelectView,
    TextView,
};
use cursive::Cursive;

use cursive::theme::{BaseColor, Color, Effect, Style};
use cursive::utils::markup::StyledString;

use super::report::{wrap, Entry, ParsedReport};
use super::{MenuChoice, Options, PluginStatus, RunResult, VERSION};

/// Text width of the report views: fits the 80-column console with the
/// dialog border and the scroll bar.
const TEXT_WIDTH: usize = 70;

/// Run a screen until it stores a result with `done` (or the user presses
/// Esc / Ctrl-C, which gives `None`).
fn run_screen<T: 'static>(build: impl FnOnce(&mut Cursive)) -> Option<T> {
    reset_terminal();
    let mut siv = cursive::default();
    siv.set_window_title(format!("pfopn-convert {VERSION}"));
    // Esc closes a pop-up, or leaves the screen.
    siv.add_global_callback(Key::Esc, |s| {
        if s.screen().len() > 1 {
            s.pop_layer();
        } else {
            s.quit();
        }
    });
    build(&mut siv);
    siv.run();
    siv.take_user_data::<T>()
}

/// Full terminal reset (RIS) before each screen. OPNsense's update and pkg
/// leave attributes and modes behind on the console, and the screen drawn on
/// top of them showed black patches.
fn reset_terminal() {
    use std::io::Write;
    print!("\x1bc\x1b[0m\x1b[2J\x1b[H");
    let _ = std::io::stdout().flush();
}

fn done<T: 'static>(siv: &mut Cursive, value: T) {
    siv.set_user_data(value);
    siv.quit();
}

pub fn main_menu(header: &str, items: Vec<(MenuChoice, String)>) -> MenuChoice {
    let header = header.to_string();
    let chosen = run_screen::<usize>(move |siv| {
        // Leave with "0) Exit", not by accident with Esc.
        siv.clear_global_callbacks(Key::Esc);
        let mut select = SelectView::<usize>::new();
        for (i, (_, label)) in items.iter().enumerate() {
            let number = if i + 1 == items.len() {
                "0".to_string()
            } else {
                (i + 1).to_string()
            };
            select.add_item(format!("{number})  {label}"), i);
        }
        let count = items.len();
        select.set_on_submit(|s, i: &usize| done(s, *i));
        let mut select = cursive::views::OnEventView::new(select);
        for (i, ch) in "1234567".chars().enumerate().take(count - 1) {
            select.set_on_event(ch, move |s| done(s, i));
        }
        select.set_on_event('0', move |s| done(s, count - 1));
        siv.add_layer(
            Dialog::around(
                LinearLayout::vertical()
                    .child(TextView::new(header))
                    .child(DummyView)
                    .child(TextView::new(
                        "pfSense -> OPNsense migration. Work through the entries in order.",
                    ))
                    .child(DummyView)
                    .child(select),
            )
            .title(format!("pfopn-convert {VERSION}"))
            .padding(Margins::lrtb(2, 2, 1, 1)),
        );
    });
    // Keep the mapping by index: MenuChoice is not Clone-able into callbacks.
    let index = chosen.unwrap_or(usize::MAX);
    menu_choice_at(index)
}

fn menu_choice_at(index: usize) -> MenuChoice {
    match index {
        0 => MenuChoice::SystemCheck,
        1 => MenuChoice::Update,
        2 => MenuChoice::Plugins,
        3 => MenuChoice::Options,
        4 => MenuChoice::Convert,
        5 => MenuChoice::Restore,
        _ => MenuChoice::Exit,
    }
}

/// A scrollable text with a Back button.
pub fn show_text(title: &str, text: &str) {
    let title = title.to_string();
    let text = text.to_string();
    run_screen::<()>(move |siv| {
        siv.add_layer(
            Dialog::around(
                TextView::new(text)
                    .scrollable()
                    .scroll_x(true)
                    .resized(SizeConstraint::Free, SizeConstraint::AtMost(40)),
            )
            .title(title)
            .button("Back", |s| done(s, ())),
        );
    });
}

pub fn pick_source(candidates: &[PathBuf]) -> Option<PathBuf> {
    let candidates = candidates.to_vec();
    run_screen::<PathBuf>(move |siv| {
        let mut select = SelectView::<PathBuf>::new();
        for path in candidates {
            select.add_item(path.display().to_string(), path);
        }
        select.set_on_submit(|s, p: &PathBuf| done(s, p.clone()));
        siv.add_layer(
            Dialog::around(select.scrollable())
                .title("Which pfSense config should be converted?")
                .button("Quit", |s| s.quit()),
        );
    })
}

pub fn options(current: &Options) -> Option<Options> {
    let current = current.clone();
    run_screen::<Options>(move |siv| {
        let list = ListView::new()
            .child(
                "pfBlockerNG lists -> URL tables, GeoIP, DNSBL (--pfblocker-feeds)",
                Checkbox::new()
                    .with_checked(current.pfblocker_feeds)
                    .with_name("pfblocker"),
            )
            .child(
                "Keep rules in the old format (--legacy-rules)",
                Checkbox::new()
                    .with_checked(current.legacy_rules)
                    .with_name("legacy"),
            )
            .child(
                "Drop separators instead of categories (--no-separator-categories)",
                Checkbox::new()
                    .with_checked(current.no_separator_categories)
                    .with_name("separators"),
            );
        siv.add_layer(
            Dialog::around(
                LinearLayout::vertical()
                    .child(TextView::new(
                        "The defaults match the tested migrations. See the README for what each does.",
                    ))
                    .child(DummyView)
                    .child(list),
            )
            .title("Conversion options")
            .button("Save", |s| {
                let checked = |s: &mut Cursive, name: &str| {
                    s.call_on_name(name, |c: &mut Checkbox| c.is_checked())
                        .unwrap_or(false)
                };
                let options = Options {
                    pfblocker_feeds: checked(s, "pfblocker"),
                    legacy_rules: checked(s, "legacy"),
                    no_separator_categories: checked(s, "separators"),
                };
                done(s, options);
            })
            .button("Back", |s| s.quit()),
        );
    })
}

/// Returns the plugins chosen for installation.
pub fn plugins(status: &PluginStatus) -> Option<Vec<String>> {
    let mut lines = Vec::new();
    let mut list = ListView::new();
    for row in &status.rows {
        let installed = match row.installed {
            Some(true) => "installed",
            Some(false) => "missing",
            None => "unknown",
        };
        let model = if row.model_present {
            "present"
        } else {
            "absent"
        };
        list.add_child(
            format!(
                "{:<21} pkg: {:<9} settings: {:<7}",
                row.plugin, installed, model
            ),
            Checkbox::new()
                .with_checked(row.installed == Some(false))
                .with_name(format!("plugin:{}", row.plugin)),
        );
        lines.push(row.plugin.clone());
    }
    let mut notes = String::new();
    if status.rows.is_empty() {
        notes.push_str("The pfSense config needs no OPNsense plugins.\n");
    }
    if status
        .rows
        .iter()
        .any(|r| r.installed == Some(true) && !r.model_present)
    {
        notes.push_str(
            "\n\"settings: absent\" on an installed plugin: its settings are not in the config yet,\nso the converter cannot convert them. Open the plugin's page in the GUI once and\nsave it, then check here again.\n",
        );
    }
    if !status.rows.is_empty() {
        notes.push_str("\nNeeded for:\n");
        for row in &status.rows {
            notes.push_str(&format!("  {:<21} {}\n", row.plugin, row.package));
        }
    }
    if !status.no_equivalent.is_empty() {
        notes.push_str("\nNo OPNsense plugin:\n");
        for note in &status.no_equivalent {
            notes.push_str(&format!("  {note}\n"));
        }
    }
    run_screen::<Vec<String>>(move |siv| {
        siv.add_layer(
            Dialog::around(
                LinearLayout::vertical()
                    .child(TextView::new(
                        "Plugins are installed the way System > Firmware > Plugins does it. Selected:",
                    ))
                    .child(DummyView)
                    .child(list)
                    .child(TextView::new(notes))
                    .scrollable(),
            )
            .title("Plugins")
            .button("Install selected", move |s| {
                let selected: Vec<String> = lines
                    .iter()
                    .filter(|plugin| {
                        s.call_on_name(&format!("plugin:{plugin}"), |c: &mut Checkbox| {
                            c.is_checked()
                        })
                        .unwrap_or(false)
                    })
                    .cloned()
                    .collect();
                done(s, selected);
            })
            .button("Back", |s| s.quit()),
        );
    })
}

/// The warning screen before the restore. True when every confirmation was
/// given and "RESTORE" was typed.
pub fn confirm_restore(warning: &str, report: &ParsedReport) -> bool {
    let warning = warning.to_string();
    let mut warnings = report.warnings.clone();
    warnings.extend(report.verify_issues.iter().cloned());
    run_screen::<bool>(move |siv| {
        let checks = ListView::new()
            .child(
                "I have a snapshot or backup of this box to roll back to",
                Checkbox::new().with_name("snapshot"),
            )
            .child(
                "Only an isolated network is connected",
                Checkbox::new().with_name("isolated"),
            )
            .child(
                "Type RESTORE to continue:",
                EditView::new().with_name("word").fixed_width(10),
            );
        siv.add_layer(
            Dialog::around(
                LinearLayout::vertical()
                    .child(ResizedView::with_max_height(
                        24,
                        TextView::new(warning).scrollable(),
                    ))
                    .child(DummyView)
                    .child(checks),
            )
            .title("Before the restore")
            .button("Warnings", move |s| {
                s.add_layer(entries_dialog("Warnings", &warnings));
            })
            .button("Restore", |s| {
                let snapshot = s
                    .call_on_name("snapshot", |c: &mut Checkbox| c.is_checked())
                    .unwrap_or(false);
                let isolated = s
                    .call_on_name("isolated", |c: &mut Checkbox| c.is_checked())
                    .unwrap_or(false);
                let word = s
                    .call_on_name("word", |e: &mut EditView| e.get_content())
                    .map(|c| c.trim().to_string())
                    .unwrap_or_default();
                if snapshot && isolated && word == "RESTORE" {
                    done(s, true);
                } else {
                    s.add_layer(Dialog::info(
                        "Tick both boxes and type RESTORE (capital letters) to continue.",
                    ));
                }
            })
            .button("Back", |s| s.quit()),
        );
    })
    .unwrap_or(false)
}

/// The convert + verify result: a summary, with the messages behind buttons.
pub fn show_report(run: &RunResult, options: &str) {
    let parsed = &run.parsed;
    let mut text = StyledString::new();
    let status = |ok: bool| if ok { "ok" } else { "FAILED" };
    text.append_styled("Convert: ", Effect::Bold);
    text.append_plain(status(run.convert_ok));
    text.append_styled("    Verify: ", Effect::Bold);
    text.append_plain(match parsed.verify_result {
        Some((errors, warnings)) => format!(
            "{} ({errors} error(s), {warnings} warning(s))",
            status(run.verify_ok)
        ),
        None => status(run.verify_ok).to_string(),
    });
    text.append_styled("\nFiles:   ", Effect::Bold);
    text.append_plain(run.dir.display().to_string());
    text.append_styled("\nOptions: ", Effect::Bold);
    text.append_plain(options);

    if !parsed.errors.is_empty() {
        text.append_styled("\n\nERRORS\n", error_style());
        append_entries(&mut text, &parsed.errors);
    }
    if !parsed.converted.is_empty() {
        text.append_styled("\n\nConverted: ", Effect::Bold);
        text.append_plain(wrap(&parsed.converted.join(", "), TEXT_WIDTH - 11, 2));
    }
    if !parsed.plugins.is_empty() {
        text.append_styled("\n\nPlugins\n", Effect::Bold);
        for line in &parsed.plugins {
            text.append_plain(format!("{}\n", plugin_line(line)));
        }
        for line in &parsed.plugin_notes {
            text.append_plain(format!("  {}\n", wrap(line, TEXT_WIDTH - 2, 2)));
        }
    }
    text.append_styled("\n\nMessages: ", Effect::Bold);
    text.append_plain(wrap(
        &format!(
            "{} warning(s), {} info, {} from verify. Read the warnings before the restore: they list what was dropped, changed or must be done by hand.",
            parsed.warnings.len(),
            parsed.infos.len(),
            parsed.verify_issues.len()
        ),
        TEXT_WIDTH - 10,
        0,
    ));

    let warnings = parsed.warnings.clone();
    let infos = parsed.infos.clone();
    let verify = parsed.verify_issues.clone();
    let full = run.report.clone();
    let labels = (
        format!("Warnings ({})", warnings.len()),
        format!("Info ({})", infos.len()),
        format!("Verify ({})", verify.len()),
    );
    run_screen::<()>(move |siv| {
        siv.add_layer(
            Dialog::around(
                TextView::new(text)
                    .scrollable()
                    .resized(SizeConstraint::Free, SizeConstraint::AtMost(40)),
            )
            .title("Convert and verify")
            .button(labels.0, move |s| {
                s.add_layer(entries_dialog("Warnings", &warnings));
            })
            .button(labels.1, move |s| {
                s.add_layer(entries_dialog("Info", &infos));
            })
            .button(labels.2, move |s| {
                s.add_layer(entries_dialog("Verify", &verify));
            })
            .button("Full log", move |s| {
                s.add_layer(
                    Dialog::around(
                        TextView::new(full.clone())
                            .scrollable()
                            .resized(SizeConstraint::Free, SizeConstraint::AtMost(40)),
                    )
                    .title("Full log (report.txt)")
                    .button("Close", |s| {
                        s.pop_layer();
                    }),
                );
            })
            .button("Back", |s| done(s, ())),
        );
    });
}

/// "converted        os-x    from y" as aligned columns, the rest wrapped
/// under the plugin name.
fn plugin_line(line: &str) -> String {
    const STATE: usize = 15;
    let (state, rest) = ["NOT INSTALLED", "no equivalent", "converted"]
        .iter()
        .find_map(|state| line.strip_prefix(state).map(|rest| (*state, rest)))
        .unwrap_or(("", line));
    let rest = wrap(rest, TEXT_WIDTH - 2 - STATE, 0)
        .replace('\n', &format!("\n{}", " ".repeat(2 + STATE)));
    format!("  {state:<STATE$}{rest}")
}

fn error_style() -> Style {
    Style::from(Color::Dark(BaseColor::Red)).combine(Effect::Bold)
}

/// Messages one below the other, a blank line between them, wrapped lines
/// indented, the topic in bold.
fn append_entries(text: &mut StyledString, entries: &[Entry]) {
    for (n, entry) in entries.iter().enumerate() {
        if n > 0 {
            text.append_plain("\n\n");
        }
        match &entry.topic {
            Some(topic) => {
                let full = wrap(&format!("{topic}: {}", entry.text), TEXT_WIDTH, 2);
                let head = format!("{topic}:");
                let style = if topic == "ERROR" {
                    error_style()
                } else {
                    Style::from(Effect::Bold)
                };
                match full.strip_prefix(&head) {
                    Some(rest) => {
                        text.append_styled(head, style);
                        text.append_plain(rest);
                    }
                    None => text.append_plain(full),
                }
            }
            None => text.append_plain(wrap(&entry.text, TEXT_WIDTH, 2)),
        }
    }
}

fn entries_dialog(title: &str, entries: &[Entry]) -> Dialog {
    let mut text = StyledString::new();
    if entries.is_empty() {
        text.append_plain("None.");
    } else {
        append_entries(&mut text, entries);
    }
    Dialog::around(
        TextView::new(text)
            .scrollable()
            .resized(SizeConstraint::Free, SizeConstraint::AtMost(40)),
    )
    .title(format!("{title} ({})", entries.len()))
    .button("Close", |s| {
        s.pop_layer();
    })
}
