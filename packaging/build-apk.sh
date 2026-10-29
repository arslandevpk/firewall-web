#!/usr/bin/env sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ] || ! printf '%s\n' "$1" | grep -Eq '^[0-9][A-Za-z0-9.+:~_-]*$'; then
    echo "Usage: $0 VERSION [x86_64|aarch64]" >&2
    exit 2
fi

version=$1
architecture=${2:-$(apk --print-arch)}
case "$architecture" in
    x86_64|aarch64) ;;
    *)
        echo "Unsupported Alpine architecture: $architecture (expected x86_64 or aarch64)." >&2
        exit 1
        ;;
esac
command -v apk >/dev/null 2>&1 || { echo "Run this builder on Alpine Linux with apk-tools installed." >&2; exit 1; }

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
app_dir="$repo_root/firewall-web-standalone"
output_dir="$repo_root/dist"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
root="$work_dir/root"
mkdir -p \
    "$root/usr/lib/firewall-web/fonts/licenses" \
    "$root/usr/bin" \
    "$root/etc/conf.d" \
    "$root/etc/init.d" \
    "$root/usr/share/doc/firewall-web"
install -m 644 "$app_dir/firewall_web.py" "$root/usr/lib/firewall-web/"
install -m 644 "$app_dir"/fonts/*.woff2 "$app_dir"/fonts/*.ttf "$root/usr/lib/firewall-web/fonts/"
install -m 644 "$app_dir"/fonts/licenses/* "$root/usr/lib/firewall-web/fonts/licenses/"
install -m 755 "$script_dir/firewall-web" "$root/usr/bin/firewall-web"
install -m 644 "$app_dir/README.txt" "$root/usr/share/doc/firewall-web/README"
install -m 644 "$repo_root/LICENSE" "$root/usr/share/doc/firewall-web/LICENSE"
install -m 600 "$script_dir/firewall-web.conf" "$root/etc/conf.d/firewall-web"
install -m 755 "$script_dir/firewall-web.openrc" "$root/etc/init.d/firewall-web"
mkdir -p "$output_dir"
apk mkpkg \
    --files "$root" \
    --output "$output_dir/firewall-web_${version}_${architecture}.apk" \
    --info "name:firewall-web" \
    --info "version:${version}-r0" \
    --info "arch:${architecture}" \
    --info "description:Root web console for the Linux firewall" \
    --info "license:MIT AND OFL-1.1 AND Bitstream-Vera" \
    --info "origin:firewall-web" \
    --info "url:https://github.com/arslandevpk/firewall-web" \
    --info "maintainer:Firewall Web contributors" \
    --info "depends:python3" \
    --info "depends:py3-flask" \
    --info "depends:py3-waitress" \
    --info "depends:iptables" \
    --info "depends:nftables" \
    --info "depends:openrc"
printf 'Built %s\n' "$output_dir/firewall-web_${version}_${architecture}.apk"
