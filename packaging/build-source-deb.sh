#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
upstream_version=${1:-$(dpkg-parsechangelog -SVersion -l "$repo_root/debian/changelog" | sed 's/-[^-]*$//')}
if [[ $# -gt 1 || ! "$upstream_version" =~ ^[0-9][A-Za-z0-9.+:~_-]*$ ]]; then
  echo "Usage: $0 [UPSTREAM_VERSION]" >&2
  exit 2
fi
version="${upstream_version}-1"
build_root=$(mktemp -d)
trap 'rm -rf -- "$build_root"' EXIT
source_dir="$build_root/firewall-web-$upstream_version"
mkdir -p "$source_dir" "$repo_root/dist/source"

tar -C "$repo_root" \
  --exclude=.git --exclude=dist --exclude=debian --exclude=.venv \
  --exclude=__pycache__ -cf - . | tar -C "$source_dir" -xf -
cp -a "$repo_root/debian" "$source_dir/debian"
sed -i "1s/^firewall-web ([^)]*) /firewall-web (${version}) /" "$source_dir/debian/changelog"
sed -i "s/  -- arslandevpk <arslandevpk@users.noreply.github.com>.*/  -- arslandevpk <arslandevpk@users.noreply.github.com>  $(date -R)/" "$source_dir/debian/changelog"
tar -C "$build_root" \
  --exclude="firewall-web-$upstream_version/debian" \
  -czf "$build_root/firewall-web_${upstream_version}.orig.tar.gz" \
  "firewall-web-$upstream_version"

(cd "$source_dir" && dpkg-buildpackage -us -uc -S)
source_dsc="$build_root/firewall-web_${version}.dsc"
dpkg-source -x "$source_dsc" "$build_root/unpacked"
(cd "$build_root/unpacked" && dpkg-buildpackage -us -uc -b)

cp -a "$build_root"/firewall-web_"$version".* "$repo_root/dist/source/"
cp -a "$build_root/firewall-web_${upstream_version}.orig.tar.gz" "$repo_root/dist/source/"
cp -a "$build_root/firewall-web_${version}_all.deb" "$repo_root/dist/source/"
printf 'Built and verified Debian source package %s in %s\n' "$version" "$repo_root/dist/source"
