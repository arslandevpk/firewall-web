#!/usr/bin/env bash
# Resolve distribution repository prerequisites before APT resolves the local deb.
set -euo pipefail
if [[ $# != 1 || ! -f "$1" ]]; then
  echo "Usage: sudo bash packaging/install-deb.sh /path/to/firewall-web_VERSION_ARCH.deb" >&2
  exit 2
fi
[[ $EUID == 0 ]] || { echo "Run this installer with sudo." >&2; exit 2; }
package=$(realpath -- "$1")
[[ $(dpkg-deb -f "$package" Package) == firewall-web ]] || {
  echo "This is not a firewall-web Debian package." >&2; exit 2;
}
arch=$(dpkg --print-architecture)
[[ $(dpkg-deb -f "$package" Architecture) == "$arch" ]] || {
  echo "Package architecture does not match this system ($arch)." >&2; exit 2;
}
. /etc/os-release
case "$ID" in
  ubuntu) component=universe; official='(archive[.]ubuntu[.]com|[a-zA-Z0-9.-]+[.]archive[.]ubuntu[.]com|security[.]ubuntu[.]com|ports[.]ubuntu[.]com)' ;;
  debian) component=main; official='(deb[.]debian[.]org|security[.]debian[.]org|ftp[.]debian[.]org|[a-zA-Z0-9.-]+[.]debian[.]org)' ;;
  *) echo "Supported distributions: Ubuntu and Debian." >&2; exit 2 ;;
esac
# Edit only existing official binary repositories for this release. Preserve
# their URIs, suites, signatures, architecture filters, and disabled entries.
# add-apt-repository on some Ubuntu versions ignores deb822 source files.
for source in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
  [[ -f "$source" ]] || continue
  temp=$(mktemp)
  if [[ "$source" == *.sources ]]; then
    awk -v component="$component" -v official="$official" -v suite="${VERSION_CODENAME:-}" '
      BEGIN { RS=""; ORS="\n\n" }
      {
        binary=0; trusted=0; current=0; disabled=0; n=split($0, lines, "\n")
        for(i=1;i<=n;i++) {
          if(lines[i] ~ /^Types:.*(^|[[:space:]])deb([[:space:]]|$)/) binary=1
          if(lines[i] ~ "^URIs:.*https?://" official "([/:[:space:]]|$)") trusted=1
          if(suite!="" && lines[i] ~ "^Suites:.*[[:space:]]" suite "(-[a-z]+)?([[:space:]]|$)") current=1
          if(lines[i] ~ /^Enabled:[[:space:]]*no([[:space:]]|$)/) disabled=1
        }
        if(binary && trusted && current && !disabled) {
          for(i=1;i<=n;i++) if(lines[i] ~ /^Components:/ && lines[i] !~ "(^|[[:space:]])" component "([[:space:]]|$)") lines[i]=lines[i] " " component
          for(i=1;i<=n;i++) printf "%s%s",lines[i],(i<n?"\n":"\n\n")
        } else print
      }' "$source" > "$temp"
  else
    awk -v component="$component" -v official="$official" -v suite="${VERSION_CODENAME:-}" '
      /^deb[[:space:]]/ {
        for(i=2;i<NF;i++) if($i ~ "^https?://" official "([/:]|$)" && suite!="" && $(i+1) ~ "^" suite "(-[a-z]+)?$") {
          found=0; for(j=i+2;j<=NF;j++) if($j==component) found=1
          if(!found && $0 !~ /#/) $0=$0 " " component
          break
        }
      }
      {print}' "$source" > "$temp"
  fi
  if ! cmp -s "$source" "$temp"; then
    backup="${source}.fwweb-backup-$(date +%s%N)"
    cp -p -- "$source" "$backup"
    cat "$temp" > "$source"
    echo "Enabled $component in $source (backup: $backup)."
  fi
  rm -f -- "$temp"
done
apt-get -o APT::Update::Error-Mode=any update
# Never bypass dependencies, use pip on system Python, or install another suite.
if ! apt-get --simulate install "$package"; then
  echo "Cannot resolve this package from the configured distribution repositories." >&2
  echo "Check that repositories for this OS release are enabled (Debian: main; Ubuntu: main and universe), that apt-get -o APT::Update::Error-Mode=any update succeeded, and that no package holds/pins conflict." >&2
  echo "Diagnostic: apt-cache policy python3 python3-flask python3-waitress iproute2" >&2
  exit 1
fi
apt-get install -y "$package"
