//! `pfopn-convert wizard`: a menu-driven migration on the OPNsense box itself.
//!
//! The wizard copies itself and the pfSense config to a work directory, then
//! offers a main menu: system check, OPNsense update, plugins, options,
//! convert + verify, restore. `convert` and `verify` run as child processes of
//! this binary, so their output is exactly what the CLI prints. See
//! `docs/wizard.md`.

mod boxenv;
mod report;
mod ui;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use pfopn_convert::detect::{detect_config, detect_version_info, ConfigFlavor};
use pfopn_convert::transform::opn_plugins;
use xml_diff_core::{parse_file, XmlNode};

use crate::cli::WizardArgs;
use crate::interface_guard::{collect_interfaces, is_virtual_if_name, InterfaceSpec};
use boxenv::{pause, BoxEnv};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn run_wizard(args: WizardArgs) -> Result<()> {
    let work_dir = args.work_dir.clone();
    let exe = std::env::current_exe().context("cannot find the wizard's own binary")?;

    if !args.no_relocate && !same_dir(exe.parent(), &work_dir) {
        return relocate(&args, &exe, &work_dir);
    }

    let env = BoxEnv::new(args.box_root.clone(), args.dry_run);
    let source_path = match &args.source {
        Some(path) => path.clone(),
        None => {
            let candidates = find_pfsense_configs(&work_dir);
            match candidates.len() {
                0 => bail!(
                    "no pfSense config found in {}; copy the pfSense config backup (config-*.xml) there, or name it on the command line",
                    work_dir.display()
                ),
                1 => candidates[0].clone(),
                _ => match ui::pick_source(&candidates) {
                    Some(path) => path,
                    None => return Ok(()),
                },
            }
        }
    };
    let source = parse_file(&source_path)
        .with_context(|| format!("failed to parse {}", source_path.display()))?;
    if detect_config(&source) != ConfigFlavor::PfSense {
        bail!("{} is not a pfSense config", source_path.display());
    }

    let options = Options {
        pfblocker_feeds: has_package(&source, "pfblocker"),
        ..Options::default()
    };
    let mut wizard = Wizard {
        env,
        exe,
        work_dir,
        source_path,
        source,
        options,
        last_run: None,
    };
    wizard.main_loop()
}

/// Copy the binary and the pfSense configs next to it into the work
/// directory, then start the copy, so the medium can be removed.
fn relocate(args: &WizardArgs, exe: &Path, work_dir: &Path) -> Result<()> {
    fs::create_dir_all(work_dir)
        .with_context(|| format!("failed to create {}", work_dir.display()))?;
    let target_exe = work_dir.join("pfopn-convert");
    // Copy then rename: replacing a running binary in place fails ("text file busy").
    let partial = work_dir.join(".pfopn-convert.new");
    fs::copy(exe, &partial)
        .with_context(|| format!("failed to copy the wizard to {}", partial.display()))?;
    fs::rename(&partial, &target_exe)
        .with_context(|| format!("failed to move the wizard to {}", target_exe.display()))?;
    println!("Copied {} to {}", exe.display(), target_exe.display());

    let mut configs = Vec::new();
    if let Some(dir) = exe.parent() {
        configs.extend(find_pfsense_configs(dir));
    }
    let mut source_copy = None;
    if let Some(source) = &args.source {
        if !configs.iter().any(|c| same_file(c, source)) {
            configs.push(source.clone());
        }
    }
    for config in &configs {
        let name = config.file_name().context("config path has no file name")?;
        let target = work_dir.join(name);
        if !same_file(config, &target) {
            fs::copy(config, &target)
                .with_context(|| format!("failed to copy {}", config.display()))?;
            println!("Copied {} to {}", config.display(), target.display());
        }
        if args.source.as_ref().is_some_and(|s| same_file(s, config)) {
            source_copy = Some(target);
        }
    }

    let mut cmd = Command::new(&target_exe);
    cmd.arg("wizard").arg("--work-dir").arg(work_dir);
    cmd.arg("--box-root").arg(&args.box_root);
    if args.dry_run {
        cmd.arg("--dry-run");
    }
    if let Some(source) = source_copy {
        cmd.arg(source);
    }
    println!(
        "Starting {} (the medium can be unmounted now).",
        target_exe.display()
    );
    println!(
        "To start the wizard again later (for example after a reboot):\n  {} wizard",
        target_exe.display()
    );
    exec(cmd)
}

#[cfg(unix)]
fn exec(mut cmd: Command) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let err = cmd.exec();
    Err(err).context("failed to start the copied wizard")
}

#[cfg(not(unix))]
fn exec(mut cmd: Command) -> Result<()> {
    let status = cmd.status().context("failed to start the copied wizard")?;
    std::process::exit(status.code().unwrap_or(1));
}

fn same_dir(dir: Option<&Path>, other: &Path) -> bool {
    match (
        dir.and_then(|d| d.canonicalize().ok()),
        other.canonicalize().ok(),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// `*.xml` files directly in `dir` that are pfSense configs.
fn find_pfsense_configs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| {
            p.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("xml"))
        })
        .filter(|p| {
            parse_file(p)
                .map(|root| detect_config(&root) == ConfigFlavor::PfSense)
                .unwrap_or(false)
        })
        .collect();
    found.sort();
    found
}

fn has_package(source: &XmlNode, needle: &str) -> bool {
    source
        .get_child("installedpackages")
        .map(|p| {
            p.get_children("package").iter().any(|pkg| {
                ["name", "internal_name"].iter().any(|tag| {
                    pkg.get_text(&[tag])
                        .is_some_and(|v| v.to_ascii_lowercase().contains(needle))
                })
            })
        })
        .unwrap_or(false)
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    pub pfblocker_feeds: bool,
    pub legacy_rules: bool,
    pub no_separator_categories: bool,
}

impl Options {
    fn args(&self) -> Vec<&'static str> {
        let mut args = Vec::new();
        if self.pfblocker_feeds {
            args.push("--pfblocker-feeds");
        }
        if self.legacy_rules {
            args.push("--legacy-rules");
        }
        if self.no_separator_categories {
            args.push("--no-separator-categories");
        }
        args
    }

    fn summary(&self) -> String {
        let args = self.args();
        if args.is_empty() {
            "defaults".to_string()
        } else {
            args.join(" ")
        }
    }
}

/// One convert + verify run.
pub struct RunResult {
    pub dir: PathBuf,
    pub baseline: PathBuf,
    pub converted: PathBuf,
    pub convert_ok: bool,
    pub verify_ok: bool,
    /// The full convert + verify output, as in report.txt.
    pub report: String,
    pub parsed: report::ParsedReport,
}

impl RunResult {
    fn ok(&self) -> bool {
        self.convert_ok && self.verify_ok
    }
}

/// Pairing of a source interface with the box's assignment.
pub struct InterfaceRow {
    pub name: String,
    pub descr: String,
    pub address: String,
    /// Device assigned on the box, `None` when missing.
    pub box_device: Option<String>,
    /// Created from the source config (VLAN, OpenVPN, ...); needs no port.
    pub virtual_backed: bool,
}

/// A plugin the source needs.
pub struct PluginRow {
    pub plugin: String,
    pub package: String,
    /// `None` when not running on OPNsense.
    pub installed: Option<bool>,
    /// The plugin's settings model is in the box's config.
    pub model_present: bool,
}

pub struct PluginStatus {
    pub rows: Vec<PluginRow>,
    pub no_equivalent: Vec<String>,
}

pub enum MenuChoice {
    SystemCheck,
    Update,
    Plugins,
    Options,
    Convert,
    Restore,
    Exit,
}

struct Wizard {
    env: BoxEnv,
    exe: PathBuf,
    work_dir: PathBuf,
    source_path: PathBuf,
    source: XmlNode,
    options: Options,
    last_run: Option<RunResult>,
}

impl Wizard {
    fn main_loop(&mut self) -> Result<()> {
        let version = self.env.opnsense_version();
        loop {
            let baseline = parse_file(&self.env.config_path()).ok();
            let interfaces = baseline
                .as_ref()
                .map(|b| interface_rows(&self.source, b))
                .unwrap_or_default();
            let missing_ifs = interfaces
                .iter()
                .filter(|r| r.box_device.is_none() && !r.virtual_backed)
                .count();
            let plugins = baseline.as_ref().map(|b| self.plugin_status(b));

            let header = format!(
                "Box:    {}\nSource: {}",
                version.as_deref().unwrap_or("OPNsense version unknown"),
                file_name(&self.source_path)
            );
            let items = vec![
                (
                    MenuChoice::SystemCheck,
                    format!(
                        "System check            {}",
                        match (&baseline, missing_ifs) {
                            (None, _) =>
                                format!("[cannot read {}]", self.env.config_path().display()),
                            (_, 0) => "[interfaces ok]".to_string(),
                            (_, n) => format!("[{n} interface(s) not assigned]"),
                        }
                    ),
                ),
                (
                    MenuChoice::Update,
                    "Update OPNsense         (console option 12)".to_string(),
                ),
                (
                    MenuChoice::Plugins,
                    format!(
                        "Plugins                 {}",
                        match &plugins {
                            None => "[unknown]".to_string(),
                            Some(p) if p.rows.is_empty() => "[none needed]".to_string(),
                            Some(p) => {
                                let missing = p
                                    .rows
                                    .iter()
                                    .filter(|r| r.installed == Some(false) || !r.model_present)
                                    .count();
                                if missing == 0 {
                                    format!("[{} ok]", p.rows.len())
                                } else {
                                    format!("[{missing} of {} missing]", p.rows.len())
                                }
                            }
                        }
                    ),
                ),
                (
                    MenuChoice::Options,
                    format!("Conversion options      [{}]", self.options.summary()),
                ),
                (
                    MenuChoice::Convert,
                    format!(
                        "Convert and verify      {}",
                        match &self.last_run {
                            None => "[not run]",
                            Some(r) if r.ok() => "[ok]",
                            Some(_) => "[FAILED]",
                        }
                    ),
                ),
                (
                    MenuChoice::Restore,
                    format!(
                        "Restore                 {}",
                        match &self.last_run {
                            Some(r) if r.ok() => "[ready]",
                            _ => "[convert first]",
                        }
                    ),
                ),
                (MenuChoice::Exit, "Exit".to_string()),
            ];

            match ui::main_menu(&header, items) {
                MenuChoice::SystemCheck => {
                    let text =
                        self.system_check_text(baseline.as_ref(), &interfaces, version.as_deref());
                    ui::show_text("System check", &text);
                }
                MenuChoice::Update => {
                    self.env.run_interactive("opnsense-shell", &["firmware"])?;
                    pause("Update finished. Press Enter to return to the menu.");
                }
                MenuChoice::Plugins => match plugins {
                    Some(status) => self.plugins(status)?,
                    None => ui::show_text(
                        "Plugins",
                        &format!("Cannot read {}.", self.env.config_path().display()),
                    ),
                },
                MenuChoice::Options => {
                    if let Some(options) = ui::options(&self.options) {
                        self.options = options;
                    }
                }
                MenuChoice::Convert => {
                    let run = self.convert()?;
                    ui::show_report(&run, &self.options.summary());
                    self.last_run = Some(run);
                }
                MenuChoice::Restore => self.restore()?,
                MenuChoice::Exit => return Ok(()),
            }
        }
    }

    fn plugin_status(&self, baseline: &XmlNode) -> PluginStatus {
        let mut scratch = baseline.clone();
        let report = opn_plugins::from_pfsense(&mut scratch, &self.source, baseline);
        let mut rows: Vec<PluginRow> = report
            .converted
            .iter()
            .map(|(plugin, package)| (plugin, package, true))
            .chain(
                report
                    .missing
                    .iter()
                    .map(|(plugin, package)| (plugin, package, false)),
            )
            .map(|(plugin, package, model_present)| PluginRow {
                plugin: plugin.clone(),
                package: package.clone(),
                installed: self.env.pkg_installed(plugin),
                model_present,
            })
            .collect();
        rows.sort_by(|a, b| a.plugin.cmp(&b.plugin));
        PluginStatus {
            rows,
            no_equivalent: report.no_equivalent,
        }
    }

    fn plugins(&mut self, status: PluginStatus) -> Result<()> {
        let Some(selected) = ui::plugins(&status) else {
            return Ok(());
        };
        if selected.is_empty() {
            return Ok(());
        }
        let mut results = Vec::new();
        for plugin in &selected {
            println!("\n=== Installing {plugin} ===");
            self.env.install_plugin(plugin)?;
            // The install script always exits 0; ask pkg instead.
            let state = match self.env.pkg_installed(plugin) {
                Some(true) => "installed",
                Some(false) => "NOT installed (see the output above)",
                None => "unknown (pkg not available)",
            };
            results.push(format!("  {plugin:<24} {state}"));
        }
        println!("\nResult:\n{}", results.join("\n"));
        pause("Press Enter to return to the menu.");
        Ok(())
    }

    fn system_check_text(
        &self,
        baseline: Option<&XmlNode>,
        interfaces: &[InterfaceRow],
        version: Option<&str>,
    ) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "OPNsense:  {}\n",
            version.unwrap_or("unknown (not running on OPNsense?)")
        ));
        out.push_str(&format!(
            "Internet:  {}\n",
            if self.env.internet_ok() {
                "ok (firmware mirror reachable)"
            } else {
                "NOT reachable - needed for updates and plugins"
            }
        ));
        if baseline.is_none() {
            out.push_str(&format!(
                "Config:    cannot read {}\n",
                self.env.config_path().display()
            ));
        }
        let hostname = [
            self.source.get_text(&["system", "hostname"]).unwrap_or(""),
            self.source.get_text(&["system", "domain"]).unwrap_or(""),
        ]
        .iter()
        .filter(|s| !s.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(".");
        out.push_str(&format!(
            "Source:    {} (pfSense config version {})\n           {}\n",
            hostname,
            detect_version_info(&self.source).value,
            file_name(&self.source_path)
        ));

        out.push_str("\nInterfaces (pfSense -> this box):\n");
        for row in interfaces {
            let target = match (&row.box_device, row.virtual_backed) {
                (Some(dev), _) => dev.clone(),
                (None, true) => "(created by the converter)".to_string(),
                (None, false) => "NOT ASSIGNED".to_string(),
            };
            out.push_str(&format!(
                "  {:<6} {:<16} {:<20} -> {}\n",
                row.name, row.descr, row.address, target
            ));
        }
        let missing: Vec<&str> = interfaces
            .iter()
            .filter(|r| r.box_device.is_none() && !r.virtual_backed)
            .map(|r| r.name.as_str())
            .collect();
        if !missing.is_empty() {
            out.push_str(&format!(
                "\n{} must be assigned before converting: console option 1 (Assign interfaces).\nDisabled pfSense interfaces need a port too.\n",
                missing.join(", ")
            ));
        }
        if let Some(ports) = self.env.network_ports() {
            out.push_str(&format!(
                "\nNetwork ports on this box: {}\n",
                ports.join(" ")
            ));
        }

        let packages = package_names(&self.source);
        if !packages.is_empty() {
            out.push_str(&format!("\npfSense packages: {}\n", packages.join(", ")));
        }
        out
    }

    fn convert(&self) -> Result<RunResult> {
        let dir = self.work_dir.join(timestamp_dir_name(now_unix()));
        fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
        let baseline = dir.join("baseline.xml");
        fs::copy(self.env.config_path(), &baseline)
            .with_context(|| format!("failed to copy {}", self.env.config_path().display()))?;
        let converted = dir.join("converted.xml");

        println!("Converting {} ...", self.source_path.display());
        let mut convert = Command::new(&self.exe);
        convert
            .arg("convert")
            .arg(&self.source_path)
            .args(["--from", "pfsense", "--to", "opnsense", "--target-file"])
            .arg(&baseline)
            .arg("--output")
            .arg(&converted)
            .args(self.options.args());
        let (convert_ok, convert_log) = run_logged(convert, &dir.join("convert.log"))?;

        let (verify_ok, verify_log) = if convert_ok {
            println!("Verifying {} ...", converted.display());
            let mut verify = Command::new(&self.exe);
            verify
                .arg("verify")
                .arg(&converted)
                .args(["--to", "opnsense"]);
            run_logged(verify, &dir.join("verify.log"))?
        } else {
            (false, "not run: convert failed\n".to_string())
        };

        let report = format!(
            "Files: {}\nOptions: {}\n\n=== convert: {} ===\n{}\n=== verify: {} ===\n{}",
            dir.display(),
            self.options.summary(),
            if convert_ok { "ok" } else { "FAILED" },
            convert_log,
            if verify_ok { "ok" } else { "FAILED" },
            verify_log
        );
        fs::write(dir.join("report.txt"), &report)?;
        let parsed = report::parse(&convert_log, &verify_log);
        Ok(RunResult {
            dir,
            baseline,
            converted,
            convert_ok,
            verify_ok,
            report,
            parsed,
        })
    }

    fn restore(&mut self) -> Result<()> {
        let Some(run) = &self.last_run else {
            ui::show_text("Restore", "Run \"Convert and verify\" first.");
            return Ok(());
        };
        if !run.ok() {
            ui::show_text(
                "Restore",
                &format!(
                    "The last conversion failed; fix the problem and convert again.\nReport: {}",
                    run.dir.join("report.txt").display()
                ),
            );
            return Ok(());
        }
        let current = fs::read(self.env.config_path()).ok();
        let at_convert = fs::read(&run.baseline).ok();
        if current.is_none() || current != at_convert {
            ui::show_text(
                "Restore",
                "The box's config changed since the conversion (for example a plugin was installed).\nRun \"Convert and verify\" again, so the restore does not undo that change.",
            );
            return Ok(());
        }
        let converted = parse_file(&run.converted)
            .with_context(|| format!("failed to parse {}", run.converted.display()))?;
        let text = restore_warning(&converted, &run.parsed);
        if !ui::confirm_restore(&text, &run.parsed) {
            return Ok(());
        }

        let backups = self.env.scan_backups();
        if !backups.broken.is_empty() {
            ui::show_text(
                "Restore",
                &format!(
                    "OPNsense's restore stops on these files in {}, because their names have no valid time:\n\n  {}\n\nMove them out of that folder (or delete them), then try again.",
                    self.env.backup_dir().display(),
                    backups.broken.join("\n  ")
                ),
            );
            return Ok(());
        }

        // OPNsense's restore never lists the newest backup (it takes it to be
        // the running config). So the converted config goes in newer than
        // every existing backup, and a copy of the running config on top of
        // it: the converted config is entry 1.
        let converted_time = now_unix().max(backups.newest.map_or(0, |t| t + 1));
        let converted_backup = self.env.add_backup(&run.converted, converted_time)?;
        let running_backup = self
            .env
            .add_backup(&self.env.config_path(), converted_time + 1)?;
        if !self.env.dry_run() {
            println!(
                "The converted config was added to the config backups as {},\nwith a copy of the running config as {} after it.",
                converted_backup.display(),
                running_backup.display()
            );
        }
        println!("\nOPNsense's restore (console option 13) starts now. In its list, pick entry 1:");
        println!(
            "  {}  pfopn-convert: Converted from pfSense by pfo...",
            display_time(converted_time)
        );
        println!("Check the difference ('q' leaves it), answer y to restore and y to reboot.\n");
        if !self.env.dry_run() {
            pause("Press Enter to continue.");
        }
        let finished = self.env.run_interactive("opnsense-shell", &["restore"])?;

        // Still here: the restore ended without a reboot.
        let now_running = fs::read(self.env.config_path()).ok();
        if now_running.is_some() && now_running == fs::read(&run.converted).ok() {
            pause("The converted config is now the running config, without a reboot.\nReboot the box (console option 6) so every service starts with it.\nPress Enter to return to the menu.");
        } else if now_running == at_convert {
            // Nothing restored: take the two backups out again, so a retry
            // does not pile them up.
            self.env.remove_backup(&converted_backup);
            self.env.remove_backup(&running_backup);
            pause(if finished {
                "Nothing was restored. Press Enter to return to the menu."
            } else {
                "OPNsense's restore stopped with an error (see above). Nothing was restored.\nPress Enter to return to the menu."
            });
        } else {
            pause("The box's config changed, but it is not the converted config (another backup restored?).\nPress Enter to return to the menu.");
        }
        Ok(())
    }
}

/// Run a command with stdout and stderr written to one log file (so their
/// order is kept); returns whether it succeeded and the log text.
fn run_logged(mut cmd: Command, log: &Path) -> Result<(bool, String)> {
    let file =
        fs::File::create(log).with_context(|| format!("failed to create {}", log.display()))?;
    let status = cmd
        .stdout(file.try_clone()?)
        .stderr(file)
        .status()
        .context("failed to run the converter")?;
    let text = fs::read_to_string(log).unwrap_or_default();
    Ok((status.success(), text))
}

fn interface_rows(source: &XmlNode, baseline: &XmlNode) -> Vec<InterfaceRow> {
    let target: BTreeMap<String, InterfaceSpec> = collect_interfaces(baseline);
    let mut rows: Vec<InterfaceRow> = collect_interfaces(source)
        .into_values()
        .map(|spec| {
            let address = match (spec.ipaddr.as_deref(), spec.subnet.as_deref()) {
                (Some(ip), Some(net)) if !ip.is_empty() && !net.is_empty() => format!("{ip}/{net}"),
                (Some(ip), _) => ip.to_string(),
                _ => String::new(),
            };
            InterfaceRow {
                box_device: target
                    .get(&spec.name)
                    .map(|t| t.if_name.clone().unwrap_or_default()),
                virtual_backed: spec.if_name.as_deref().is_some_and(is_virtual_if_name),
                descr: spec.descr.clone().unwrap_or_default(),
                address,
                name: spec.name,
            }
        })
        .collect();
    rows.sort_by_key(|r| interface_order(&r.name));
    rows
}

/// wan, lan, opt1, opt2, ..., opt10, then the rest.
fn interface_order(name: &str) -> (u8, u32, String) {
    match name {
        "wan" => (0, 0, String::new()),
        "lan" => (1, 0, String::new()),
        _ => match name.strip_prefix("opt").and_then(|n| n.parse::<u32>().ok()) {
            Some(n) => (2, n, String::new()),
            None => (3, 0, name.to_string()),
        },
    }
}

fn package_names(source: &XmlNode) -> Vec<String> {
    source
        .get_child("installedpackages")
        .map(|p| {
            p.get_children("package")
                .iter()
                .filter_map(|pkg| pkg.get_text(&["name"]).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The text of the warning screen before the restore.
fn restore_warning(converted: &XmlNode, report: &report::ParsedReport) -> String {
    let lan = match (
        converted.get_text(&["interfaces", "lan", "ipaddr"]),
        converted.get_text(&["interfaces", "lan", "subnet"]),
    ) {
        (Some(ip), Some(net)) => format!("{ip}/{net}"),
        (Some(ip), None) => ip.to_string(),
        _ => "(no static LAN address)".to_string(),
    };
    let protocol = converted
        .get_text(&["system", "webgui", "protocol"])
        .filter(|p| !p.is_empty())
        .unwrap_or("https");
    let port = converted
        .get_text(&["system", "webgui", "port"])
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| if protocol == "http" { "80" } else { "443" }.to_string());
    let lan_ip = lan.split('/').next().unwrap_or_default();
    let warnings = report.warnings.len();
    let verify_warnings = report.verify_issues.len();

    format!(
        "NETWORK: the new config carries the pfSense box's IP addresses. Only an \
isolated network may be connected now. Disconnect or move every other port (including \
the internet connection used for updates), or this box takes over live addresses.

ACCESS AFTER THE REBOOT: this box will be at the pfSense LAN address {lan}, web GUI \
{protocol}://{lan_ip}:{port}/, not at its current address. The root password becomes \
the pfSense admin password.

NOT CONVERTED / MANUAL: the conversion has {warnings} warning(s) and verify \
{verify_warnings} (Warnings button). They list what was dropped, kept in the old format \
or must be done by hand.

ONLY TESTABLE AFTER THE CUTOVER: VPN peers, upstream routers, anything outside the \
isolated network. Keep the pfSense box ready to start again, and never run both at once.

ROLLBACK: the config before the restore stays in the backup list (console option 13, \
System > Configuration > History). Take a snapshot or backup of this box now, in \
whatever way suits your setup.
"
    )
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `Mon Nov 16 16:07:50 UTC 2026`-like time as OPNsense's restore list
/// shows it (in UTC; the box's own time zone may differ).
fn display_time(unix: u64) -> String {
    let stamp = timestamp_dir_name(unix);
    format!(
        "{}-{}-{} {}:{}:{} UTC",
        &stamp[0..4],
        &stamp[4..6],
        &stamp[6..8],
        &stamp[9..11],
        &stamp[11..13],
        &stamp[13..15]
    )
}

/// `YYYYMMDD-HHMMSS` (UTC) for a run directory.
fn timestamp_dir_name(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}-{:02}{:02}{:02}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use xml_diff_core::parse;

    #[test]
    fn timestamp_names_are_utc_dates() {
        assert_eq!(timestamp_dir_name(0), "19700101-000000");
        assert_eq!(timestamp_dir_name(1_763_287_000), "20251116-095640");
        assert_eq!(timestamp_dir_name(951_782_400), "20000229-000000");
        assert_eq!(display_time(1_794_845_270), "2026-11-16 16:07:50 UTC");
    }

    #[test]
    fn interface_rows_pair_source_with_box_assignment() {
        let source = parse(
            br#"<pfsense><interfaces>
                <wan><if>igb0</if><descr>WAN</descr><ipaddr>dhcp</ipaddr></wan>
                <lan><if>igb1</if><ipaddr>192.0.2.1</ipaddr><subnet>24</subnet></lan>
                <opt10><if>igb3</if></opt10>
                <opt2><if>igb1.50</if></opt2>
            </interfaces></pfsense>"#,
        )
        .unwrap();
        let baseline = parse(
            br#"<opnsense><interfaces>
                <wan><if>vtnet0</if></wan><lan><if>vtnet1</if></lan>
            </interfaces></opnsense>"#,
        )
        .unwrap();
        let rows = interface_rows(&source, &baseline);
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["wan", "lan", "opt2", "opt10"]);
        assert_eq!(rows[1].box_device.as_deref(), Some("vtnet1"));
        assert_eq!(rows[1].address, "192.0.2.1/24");
        assert!(rows[2].virtual_backed && rows[2].box_device.is_none());
        assert!(!rows[3].virtual_backed && rows[3].box_device.is_none());
    }

    #[test]
    fn restore_warning_shows_new_gui_address() {
        let converted = parse(
            br#"<opnsense><system><webgui><protocol>https</protocol><port>8443</port></webgui></system>
            <interfaces><lan><ipaddr>192.0.2.1</ipaddr><subnet>24</subnet></lan></interfaces></opnsense>"#,
        )
        .unwrap();
        let parsed = report::parse("warning: a\ninfo: b\nwarning: c\n", "");
        let text = restore_warning(&converted, &parsed);
        assert!(text.contains("https://192.0.2.1:8443/"));
        assert!(text.contains("2 warning(s) and verify 0"));
    }

    #[test]
    fn options_map_to_convert_flags() {
        let options = Options {
            pfblocker_feeds: true,
            legacy_rules: false,
            no_separator_categories: true,
        };
        assert_eq!(
            options.args(),
            ["--pfblocker-feeds", "--no-separator-categories"]
        );
        assert_eq!(Options::default().summary(), "defaults");
    }
}
