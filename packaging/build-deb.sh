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
  "$package_dir/usr/lib/systemd/system" \
  "$package_dir/etc/firewall-web" \
  "$package_dir/usr/share/doc/firewall-web"
install -m 644 "$app_dir/firewall_web.py" "$package_dir/usr/lib/firewall-web/"
install -m 644 "$app_dir/firewall-web.env.example" "$package_dir/etc/firewall-web/firewall-web.env"
chmod 600 "$package_dir/etc/firewall-web/firewall-web.env"
install -m 644 "$script_dir/firewall-web.service" "$package_dir/usr/lib/systemd/system/firewall-web.service"
install -m 644 "$app_dir/README.txt" "$package_dir/usr/share/doc/firewall-web/README"

cat > "$package_dir/DEBIAN/control" <<EOF
Package: firewall-web
Version: $version
Section: net
Priority: optional
Architecture: $architecture
Depends: python3 (>= 3.10), python3-flask (>= 3.1), python3-waitress (>= 3), iptables, nftables, systemd
Maintainer: Firewall Web contributors
Homepage: https://github.com/arslandevpk/firewall-web
Description: Local web console for the Linux firewall
 View and manage nftables and IPv4/IPv6 iptables rules, configure masquerading,
 save backups, and explicitly configure boot-time persistence.
EOF

cat > "$package_dir/DEBIAN/conffiles" <<'EOF'
/etc/firewall-web/firewall-web.env
EOF

cat > "$package_dir/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
EOF

cat > "$package_dir/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then
    if systemctl is-active --quiet firewall-web.service || systemctl is-enabled --quiet firewall-web.service; then
        systemctl disable --now firewall-web.service
    fi
fi
EOF

cat > "$package_dir/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
EOF

chmod 755 "$package_dir/DEBIAN/postinst" "$package_dir/DEBIAN/prerm" "$package_dir/DEBIAN/postrm"
find "$package_dir" -type d -exec chmod 755 {} +
mkdir -p "$output_dir"
dpkg-deb --build --root-owner-group "$package_dir" \
  "$output_dir/firewall-web_${version}_${architecture}.deb"
