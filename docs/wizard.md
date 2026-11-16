# On-box migration wizard

Status: `pfopn-convert wizard` since 0.5.4. Tested on an OPNsense 26.7.8 box up to the restore. The user-facing steps are in the [README](../README.md#on-box-wizard), the options in [commands.md](commands.md#wizard).

## Goal

Make a pfSense → OPNsense migration a guided, menu-driven process that runs **on the new OPNsense box**, in the style of the pfSense / bsdinstall text installers. The [README workflow](../README.md#migration-workflow) has 12 manual steps. Most of them exist only because the conversion runs somewhere other than the target box. The wizard does them in order, checks what it can, and stops before anything that cannot be undone.

The CLI (`scan`, `convert`, `verify`) stays the primary interface. The wizard is a front end that runs the same commands, so the tests and the off-box workflow keep working.

Where OPNsense has its own way to do something (firmware update, plugin install, config restore), the wizard runs OPNsense's own command instead of doing it itself.

## What the user does

1. Install OPNsense on the new box, with at least as many network ports as the pfSense box has interfaces, and internet access on one of them.
2. **Assign the interfaces** (console option 1) so every pfSense interface (`wan`, `lan`, `opt1`, …, including disabled ones) has a port, and set IP addresses where needed to reach the box. The wizard checks the assignment but does not change it.
3. Prepare a transfer medium with two files (see [Getting the files onto the box](#getting-the-files-onto-the-box)):
   - the `pfopn-convert` FreeBSD binary,
   - the pfSense config backup (`config-*.xml`).
4. Attach the medium to the box, log in on the console (or over SSH), open the shell (option 8) and start the wizard.
5. Follow the menu. Before the restore, **take a snapshot or backup in whatever way suits the setup** (hypervisor snapshot, ZFS boot environment, config backup). The wizard asks for confirmation that one exists, but does not make it.

## Getting the files onto the box

The wizard needs the converter binary and the old pfSense config on the OPNsense box. OPNsense mounts nothing by itself, and the wizard can't search for a medium it's stored on. So the user starts it **from** the medium, and its first job is to copy itself and the config to the box's disk.

### ISO (virtual machines)

On the workstation, get the FreeBSD binary from the [Releases](https://github.com/Silureth/pfopn-convert/releases) page (`pfopn-convert-freebsd-x86_64.tar.gz`), put it and the config in a folder and build an ISO from it:

```bash
tar -xzf pfopn-convert-freebsd-x86_64.tar.gz
mkdir media
cp pfopn-convert config-pfsense.xml media/
xorriso -as mkisofs -J -R -V PFOPN -o pfopn.iso media/
```

or use the helper, which does the same: `tools/make_media.sh -o pfopn.iso pfopn-convert config-pfsense.xml`.

In Proxmox (or any hypervisor), attach `pfopn.iso` as a CD drive next to the OPNsense installer ISO. On the box:

```sh
mount_cd9660 /dev/cd1 /mnt     # cd0 is usually the installer ISO; ls /dev/cd* to check
/mnt/pfopn-convert wizard
```

### USB stick (physical boxes)

FAT32-formatted stick with the same two files:

```sh
mount_msdosfs /dev/da0s1 /mnt  # ls /dev/da* to check
/mnt/pfopn-convert wizard
```

### Over the network

`scp` both files to `/root/` and run `/root/pfopn-convert wizard`. This works whenever SSH is enabled on the fresh install.

### What the wizard does first

- Copies the binary and every pfSense config next to it to `/root/pfopn-convert/`, then restarts itself from there. The medium can be unmounted and removed, and after a reboot (firmware updates reboot the box) the wizard is started again with `/root/pfopn-convert/pfopn-convert wizard`.
- If there are several pfSense configs, it lets the user pick one.

Every conversion writes its files to `/root/pfopn-convert/<timestamp>/`: the baseline (a copy of the box's `/conf/config.xml` at that time), the converted config and the convert/verify report. They can be copied off the box, for example for a bug report.

## Main menu

The wizard is a main menu, like the OPNsense console menu. The entries are in the order they should be done, and each shows its state. The header shows the wizard's version, the OPNsense version and the selected pfSense config.

### 1. System check

- OPNsense version.
- Internet access (the firmware mirror is reachable).
- Source summary: pfSense version, hostname, interfaces, packages.
- Interfaces: every source interface (logical name, description, IP) next to the port assigned to it on the box. A source interface with no assigned port stops the conversion; the user fixes it in console option 1.

### 2. Update OPNsense

Runs OPNsense's own console update (`opnsense-shell firmware`, the same as console option 12). It can reboot the box; the wizard is started again afterwards. The conversion must run against the version the box will actually run, so this comes before plugins and conversion.

### 3. Plugins

Lists the OPNsense plugins the source needs (Zabbix agent/proxy, node_exporter, net-snmp, qemu-guest-agent, …), with two states each: package installed, and plugin settings present in the box's config (the converter can only convert a plugin's settings when they are). Missing ones are preselected. Selected ones are installed the way the GUI does it (`/usr/local/opnsense/scripts/firmware/launcher.sh install <plugin>`), one after the other, and checked with `pkg info` afterwards (the install script itself always reports success). Packages with no equivalent (for example pfBlockerNG) are listed with what will happen to them.

### 4. Conversion options (advanced)

The defaults match the tested migrations.

- `--pfblocker-feeds` (default on if pfBlockerNG is in the source)
- `--legacy-rules`
- `--no-separator-categories`

### 5. Convert and verify

- The baseline is the box's live `/conf/config.xml` (after the updates, plugins and interface assignment above). No separate baseline export.
- Runs `convert`, then `verify` (without `--strict`: the duplicate-rule warnings every tested box had would block it).
- Shows a summary: convert and verify results with their counts, the files, the options, what was converted and the `plugins:` report. The `warning:` lines, `info:` lines and verify issues are separate lists (buttons), and the full log is one more. A failed `convert` or `verify` (an error, not a warning) blocks the restore, and so does a change to the box's config after the conversion (for example a plugin installed since).

### 6. Restore

A warning screen. It says:

- **Network:** the new config carries the pfSense box's IP addresses. Only an isolated network should be connected now. Every other port should be disconnected or moved, or the box will take over live IPs. The internet connection used for updates should be removed now.
- **Access after the reboot:** the box will be reachable at the source's LAN address and GUI port (shown), not at its current address. The `root` password becomes the pfSense `admin` password.
- **What will not work or must be done by hand:** the warnings from the report.
- **What can only be tested after the cutover:** VPN peers, upstream routers.

The user confirms that a snapshot or backup exists, that only an isolated network is connected, and types `RESTORE`. Then the wizard:

1. checks `/conf/backup/` for `config-*.xml` files whose names have no valid time (for example `config-.xml`). OPNsense's restore stops on them, so the wizard lists them and stops;
2. copies the converted config into `/conf/backup/` as a regular config backup (`config-<unix time>.xml`, newer than every existing one), and a copy of the running config one second after it. OPNsense's restore never lists the newest backup, because it takes that to be the running config, so this puts the converted config at entry 1;
3. starts OPNsense's own restore (`opnsense-shell restore`, the same as console option 13). The user picks entry 1, sees the difference to the current config, confirms, and reboots;
4. if the restore ends without a reboot, says whether the converted config is now running. If nothing was restored, it removes the two backups again, so a retry does not pile them up.

The converted config stays in the backup list, and the config before the restore is in it too, so the restore can be undone the same way (console option 13, or System → Configuration → History).

## Later versions

- **After the restore:** the wizard offers itself again at the first login after the reboot and runs the checks from README steps 7 and 11: `pfctl -nf /tmp/rules.debug`; URL table and GeoIP aliases are not empty (offers to refresh them); DNSBL `dnsbl.size` is not 0; the converted plugins' services are running.
- **After the cutover:** reset the firewall states once (README step 10), re-run the alias/DNSBL checks, checklist of the VPN tunnels and servers from the source with their status.
- **Resume:** a state file so the wizard remembers the choices across reboots.

## Implementation

- A `pfopn-convert wizard` subcommand, built with [`cursive`](https://crates.io/crates/cursive) (crossterm backend, no ncurses dependency). Its default theme looks like the dialog-based installers. One static FreeBSD binary on the medium, no dependencies on the box.
- `convert` and `verify` run as child processes of the same binary, so their output is exactly what the CLI prints.
- OPNsense commands (firmware update, plugin install, restore) run in the foreground with the terminal handed over to them; the menu comes back when they finish.
- `--dry-run` prints the OPNsense commands instead of running them, and `--box-root <dir>` reads `conf/config.xml` from another directory, so the wizard can be tried on a workstation.
- No changes to OPNsense's own console menu (`/usr/local/etc/rc.initial` / `opnsense-shell`): firmware updates overwrite it.

## Decisions

- Interfaces are assigned by the user before the wizard runs (console option 1); the wizard only checks them.
- Snapshots are the user's responsibility; the wizard asks for confirmation that one exists.
- The restore goes through OPNsense's console restore (`opnsense-shell restore`), not a direct copy over `/conf/config.xml`.
- A freshly installed, unconfigured plugin has its settings in `config.xml` right away (checked on a box with os-zabbix7-agent, os-node_exporter and os-qemu-guest-agent), so the conversion can follow the install directly.
- Each build given out for testing gets its own patch version (`0.5.1`, `0.5.2`, …), shown by `--version`, in the wizard's header, at the top of `convert`'s output and in the converted config's revision note.
