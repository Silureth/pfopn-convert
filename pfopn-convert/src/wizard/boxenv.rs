//! Everything the wizard does to or reads from the OPNsense box.
//!
//! OPNsense's own commands are used wherever one exists: `opnsense-shell
//! firmware` (console option 12) for updates, the firmware launcher for plugin
//! installs (what System > Firmware > Plugins runs) and `opnsense-shell
//! restore` (console option 13) for the restore. With `dry_run` those commands
//! are printed instead of run, and `root` lets the wizard read a copy of a box's
//! `/conf` on a workstation.

use std::fs;
use std::io::{self, BufRead, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};

/// The firmware launcher OPNsense's GUI and console use for package actions.
pub const FIRMWARE_LAUNCHER: &str = "/usr/local/opnsense/scripts/firmware/launcher.sh";
/// Host used to test internet access (the default firmware mirror).
const MIRROR_HOST: &str = "pkg.opnsense.org:443";

pub struct BoxEnv {
    root: PathBuf,
    dry_run: bool,
}

impl BoxEnv {
    pub fn new(root: PathBuf, dry_run: bool) -> Self {
        Self { root, dry_run }
    }

    pub fn dry_run(&self) -> bool {
        self.dry_run
    }

    /// The running config, used as the conversion baseline.
    pub fn config_path(&self) -> PathBuf {
        self.root.join("conf/config.xml")
    }

    /// OPNsense's config backup directory, which `opnsense-shell restore` lists.
    pub fn backup_dir(&self) -> PathBuf {
        self.root.join("conf/backup")
    }

    /// For example "OPNsense 26.7.8 (amd64)".
    pub fn opnsense_version(&self) -> Option<String> {
        if let Some(out) = command_output("opnsense-version", &[]) {
            return Some(out);
        }
        let core = fs::read_to_string(self.root.join("usr/local/opnsense/version/core")).ok()?;
        let json: serde_json::Value = serde_json::from_str(&core).ok()?;
        let version = json.get("product_version")?.as_str()?;
        Some(format!("OPNsense {version}"))
    }

    /// Whether a package is installed; `None` when `pkg` is not available
    /// (not running on OPNsense).
    pub fn pkg_installed(&self, name: &str) -> Option<bool> {
        let status = Command::new("pkg")
            .args(["info", "-e", name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .ok()?;
        Some(status.success())
    }

    /// Network ports of the box (`ifconfig -l` without pseudo interfaces).
    pub fn network_ports(&self) -> Option<Vec<String>> {
        let list = command_output("ifconfig", &["-l"])?;
        Some(
            list.split_whitespace()
                .filter(|name| !is_pseudo_interface(name))
                .map(str::to_string)
                .collect(),
        )
    }

    /// Whether the firmware mirror can be reached.
    pub fn internet_ok(&self) -> bool {
        let Ok(addrs) = MIRROR_HOST.to_socket_addrs() else {
            return false;
        };
        addrs
            .into_iter()
            .any(|addr| TcpStream::connect_timeout(&addr, Duration::from_secs(5)).is_ok())
    }

    /// Run an OPNsense command in the foreground, with the terminal handed
    /// over to it. Returns whether it exited successfully.
    pub fn run_interactive(&self, program: &str, args: &[&str]) -> Result<bool> {
        let shown = std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        if self.dry_run {
            println!("[dry-run] would run: {shown}");
            return Ok(true);
        }
        println!("==> {shown}");
        let status = Command::new(program)
            .args(args)
            .status()
            .with_context(|| format!("failed to start {program}"))?;
        Ok(status.success())
    }

    /// Install a plugin the way System > Firmware > Plugins does it.
    pub fn install_plugin(&self, plugin: &str) -> Result<bool> {
        self.run_interactive(FIRMWARE_LAUNCHER, &["install", plugin])
    }

    /// Copy a config into the backup directory under the name OPNsense gives
    /// its own backups, so `opnsense-shell restore` lists it. Ownership and
    /// mode are taken from the running config.
    pub fn add_backup(&self, config: &Path, unix_time: u64) -> Result<PathBuf> {
        let target = self.backup_dir().join(format!("config-{unix_time}.xml"));
        if self.dry_run {
            println!(
                "[dry-run] would copy {} to {}",
                config.display(),
                target.display()
            );
            return Ok(target);
        }
        fs::copy(config, &target).with_context(|| {
            format!(
                "failed to copy {} to {}",
                config.display(),
                target.display()
            )
        })?;
        copy_owner_and_mode(&self.config_path(), &target)?;
        Ok(target)
    }

    /// Remove a backup this wizard added (dry run: only say so).
    pub fn remove_backup(&self, backup: &Path) {
        if self.dry_run {
            println!("[dry-run] would remove {}", backup.display());
        } else {
            let _ = fs::remove_file(backup);
        }
    }

    /// The newest backup time, and the `config-*.xml` files whose names
    /// OPNsense's restore cannot read (it stops on them, 26.7.8).
    pub fn scan_backups(&self) -> BackupScan {
        let mut scan = BackupScan::default();
        let Ok(entries) = fs::read_dir(self.backup_dir()) else {
            return scan;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !(name.starts_with("config-") && name.ends_with(".xml")) {
                continue;
            }
            match backup_time(&name) {
                Some(time) => scan.newest = scan.newest.max(Some(time)),
                None => scan.broken.push(name),
            }
        }
        scan.broken.sort();
        scan
    }
}

#[derive(Debug, Default)]
pub struct BackupScan {
    pub newest: Option<u64>,
    pub broken: Vec<String>,
}

/// The time in a backup name as OPNsense writes it (`config-<unix>.xml` or
/// `config-<unix>.<fraction>.xml`); `None` for any other name.
pub fn backup_time(name: &str) -> Option<u64> {
    let middle = name.strip_prefix("config-")?.strip_suffix(".xml")?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let (secs, fraction) = match middle.split_once('.') {
        Some((secs, fraction)) => (secs, Some(fraction)),
        None => (middle, None),
    };
    if !digits(secs) || fraction.is_some_and(|f| !digits(f)) {
        return None;
    }
    secs.parse().ok()
}

#[cfg(unix)]
fn copy_owner_and_mode(from: &Path, to: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = fs::metadata(from).with_context(|| format!("failed to read {}", from.display()))?;
    fs::set_permissions(to, fs::Permissions::from_mode(meta.mode() & 0o777))?;
    // Only root can change the owner; a dry run on a workstation is not root.
    let _ = std::os::unix::fs::chown(to, Some(meta.uid()), Some(meta.gid()));
    Ok(())
}

#[cfg(not(unix))]
fn copy_owner_and_mode(_from: &Path, _to: &Path) -> Result<()> {
    Ok(())
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!text.is_empty()).then_some(text)
}

fn is_pseudo_interface(name: &str) -> bool {
    [
        "lo", "pflog", "pfsync", "enc", "gif", "gre", "tun", "tap", "ovpns", "ovpnc", "wg",
        "bridge", "lagg", "vlan", "ipsec", "carp",
    ]
    .iter()
    .any(|prefix| {
        name.strip_prefix(prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(|c: char| c.is_ascii_digit()))
    }) || name.contains('.')
}

/// Wait for Enter, so the output of a command stays readable before the menu
/// comes back.
pub fn pause(message: &str) {
    print!("\n{message} ");
    let _ = io::stdout().flush();
    let mut line = String::new();
    let _ = io::stdin().lock().read_line(&mut line);
}

#[cfg(test)]
mod tests {
    use super::{backup_time, is_pseudo_interface};

    #[test]
    fn backup_names_as_opnsense_reads_them() {
        assert_eq!(backup_time("config-1794845581.xml"), Some(1_794_845_581));
        assert_eq!(
            backup_time("config-1794845094.3076.xml"),
            Some(1_794_845_094)
        );
        assert_eq!(backup_time("config-.xml"), None);
        assert_eq!(backup_time("config-date +%s.xml"), None);
        assert_eq!(backup_time("config-1794845094..xml"), None);
    }

    #[test]
    fn pseudo_interfaces_are_not_ports() {
        for name in [
            "lo0",
            "pflog0",
            "pfsync0",
            "enc0",
            "vtnet0.50",
            "ovpns1",
            "wg0",
        ] {
            assert!(is_pseudo_interface(name), "{name}");
        }
        for name in ["vtnet0", "igb1", "em0", "ix0", "re0"] {
            assert!(!is_pseudo_interface(name), "{name}");
        }
    }
}
