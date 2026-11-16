#!/bin/sh
# Build an ISO for the on-box wizard (docs/wizard.md): the FreeBSD
# pfopn-convert binary and one or more pfSense config backups.
#
#   tools/make_media.sh -o pfopn.iso pfopn-convert config-pfsense.xml [more.xml ...]
#
# Attach the ISO to the OPNsense VM as a CD drive, then on the box:
#   mount_cd9660 /dev/cd1 /mnt && /mnt/pfopn-convert wizard
#
# Needs xorriso, genisoimage or mkisofs.

set -eu

usage() {
    echo "usage: $0 -o OUTPUT.iso BINARY CONFIG.xml [CONFIG.xml ...]" >&2
    exit 2
}

output=""
while getopts o: opt; do
    case "$opt" in
    o) output="$OPTARG" ;;
    *) usage ;;
    esac
done
shift $((OPTIND - 1))
[ -n "$output" ] && [ $# -ge 2 ] || usage

binary="$1"
shift
[ -f "$binary" ] || { echo "binary not found: $binary" >&2; exit 1; }
if command -v file >/dev/null 2>&1 && ! file "$binary" | grep -q FreeBSD; then
    echo "warning: $binary does not look like a FreeBSD binary (use the freebsd-x86_64 release)" >&2
fi

staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
cp "$binary" "$staging/pfopn-convert"
chmod 755 "$staging/pfopn-convert"
for config in "$@"; do
    [ -f "$config" ] || { echo "config not found: $config" >&2; exit 1; }
    grep -q "<pfsense>" "$config" || echo "warning: $config does not look like a pfSense config" >&2
    cp "$config" "$staging/"
done

if command -v xorriso >/dev/null 2>&1; then
    xorriso -as mkisofs -quiet -J -R -V PFOPN -o "$output" "$staging"
elif command -v genisoimage >/dev/null 2>&1; then
    genisoimage -quiet -J -R -V PFOPN -o "$output" "$staging"
elif command -v mkisofs >/dev/null 2>&1; then
    mkisofs -quiet -J -R -V PFOPN -o "$output" "$staging"
else
    echo "need xorriso, genisoimage or mkisofs" >&2
    exit 1
fi
echo "wrote $output"
