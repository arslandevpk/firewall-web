#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || ! "$1" =~ ^[0-9][A-Za-z0-9.+:~_-]*$ ]]; then
  echo "Usage: $0 VERSION [amd64|arm64] (for example: 1.2.3 arm64)" >&2
  exit 2
fi

version=$1
architecture=${2:-$(dpkg --print-architecture)}
case "$architecture" in
  amd64|arm64) ;;
  *)
    echo "Unsupported Debian architecture: $architecture (expected amd64 or arm64)." >&2
    exit 1
    ;;
esac

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
app_dir="$repo_root/firewall-web-standalone"
output_dir="$repo_root/dist"
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT

package_dir="$work_dir/firewall-web"
install -d -m 755 \
  "$package_dir/DEBIAN" \
  "$package_dir/usr/lib/firewall-web" \
  "$package_dir/usr/lib/firewall-web/fonts/licenses" \
  "$package_dir/usr/bin" \
  "$package_dir/usr/lib/systemd/system" \
  "$package_dir/etc/firewall-web" \
  "$package_dir/usr/share/doc/firewall-web"
install -m 644 "$app_dir/firewall_web.py" "$package_dir/usr/lib/firewall-web/"
install -m 644 "$app_dir"/fonts/*.woff2 "$app_dir"/fonts/*.ttf "$package_dir/usr/lib/firewall-web/fonts/"
install -m 644 "$app_dir"/fonts/licenses/* "$package_dir/usr/lib/firewall-web/fonts/licenses/"
install -m 755 "$script_dir/firewall-web" "$package_dir/usr/bin/firewall-web"
install -m 755 "$script_dir/firewall-web-config.py" "$package_dir/usr/lib/firewall-web/firewall-web-config.py"
install -m 755 "$script_dir/debian-postinst" "$package_dir/usr/lib/firewall-web/debian-postinst"
install -m 644 "$script_dir/firewall-web.env.debian" "$package_dir/etc/firewall-web/firewall-web.env"
chmod 600 "$package_dir/etc/firewall-web/firewall-web.env"
install -m 644 "$script_dir/firewall-web.service" "$package_dir/usr/lib/systemd/system/firewall-web.service"
install -m 644 "$app_dir/README.txt" "$package_dir/usr/share/doc/firewall-web/README"
install -m 644 "$app_dir/firewall-web.env.example" "$package_dir/usr/share/doc/firewall-web/firewall-web.env.example"
install -m 644 "$repo_root/LICENSE" "$package_dir/usr/share/doc/firewall-web/LICENSE"
install -m 644 "$repo_root/debian/copyright" "$package_dir/usr/share/doc/firewall-web/copyright"
gzip -n -9 -c "$repo_root/debian/changelog" > "$package_dir/usr/share/doc/firewall-web/changelog.gz"
chmod 644 "$package_dir/usr/share/doc/firewall-web/changelog.gz"

cat > "$package_dir/DEBIAN/control" <<EOF
Package: firewall-web
Version: $version
Section: net
Priority: optional
Architecture: $architecture
Depends: debconf (>= 0.5) | debconf-2.0, python3 (>= 3.10), python3-flask (>= 2.0), python3-waitress (>= 2.0)
Recommends: systemd
Maintainer: arslandevpk <arslandevpk@users.noreply.github.com>
Homepage: https://github.com/arslandevpk/firewall-web
Description: Local web console for the Linux firewall
 Inspect and manage UFW, firewalld, nftables, and IPv4/IPv6 iptables through
 their selected owning manager. Save backups and explicitly configure supported
 boot persistence. Install and run as root to administer this host's firewall.
EOF

cat > "$package_dir/DEBIAN/conffiles" <<'EOF'
/etc/firewall-web/firewall-web.env
EOF
command -v po2debconf >/dev/null 2>&1 || {
  echo "po-debconf is required to build the Debian package." >&2
  exit 1
}
po2debconf "$repo_root/debian/templates" |
  sed -e 's/^description:/Description:/' -e 's/^choices:/Choices:/' -e 's/^default:/Default:/' \
    > "$package_dir/DEBIAN/templates"
chmod 644 "$package_dir/DEBIAN/templates"
install -m 755 "$repo_root/debian/config" "$package_dir/DEBIAN/config"

cat > "$package_dir/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
/usr/lib/firewall-web/debian-postinst "$@"
EOF

cat > "$package_dir/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ] && [ -e /etc/systemd/system/nft-web-restore.service ]; then
    echo "Refusing to remove firewall-web while nft-web-restore.service depends on its code. Migrate or explicitly remove that restore configuration first; firewall rules and saved state were not changed." >&2
    exit 1
fi
if [ "$1" = remove ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet firewall-web.service || systemctl is-enabled --quiet firewall-web.service; then
        systemctl disable --now firewall-web.service
    fi
fi
EOF

cat > "$package_dir/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
. /usr/share/debconf/confmodule
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi
if [ "$1" = purge ]; then
    db_purge
    rm -f /var/lib/firewall-web/initial-pin
    rmdir --ignore-fail-on-non-empty /var/lib/firewall-web 2>/dev/null || true
fi
EOF

chmod 755 "$package_dir/DEBIAN/postinst" "$package_dir/DEBIAN/prerm" "$package_dir/DEBIAN/postrm"
find "$package_dir" -type d -exec chmod 755 {} +
mkdir -p "$output_dir"
dpkg-deb --build --root-owner-group -Zxz "$package_dir" \
  "$output_dir/firewall-web_${version}_${architecture}.deb"
