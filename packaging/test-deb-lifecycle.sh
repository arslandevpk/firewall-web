#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
command -v docker >/dev/null 2>&1 || { echo "Docker is required." >&2; exit 2; }

packaging/build-deb.sh 1.0.2 amd64
packaging/build-deb.sh 1.0.3 amd64

docker run --rm --network bridge \
  -v "$repo_root:/repo:ro" debian:stable-slim sh -ec '
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      python3 python3-flask python3-waitress >/dev/null
    dpkg --install /repo/dist/firewall-web_1.0.2_amd64.deb
    test "$(stat -c %a /etc/firewall-web/firewall-web.env)" = 600
    printf "NFT_SECRET=0123\nNFT_BACKEND=inspection\n" \
      >/etc/firewall-web/firewall-web.env
    chmod 600 /etc/firewall-web/firewall-web.env
    mkdir -p /var/lib/firewall-web
    printf "preserve\n" >/var/lib/firewall-web/unrelated-state

    dpkg --install --force-confold /repo/dist/firewall-web_1.0.3_amd64.deb
    grep -qx "NFT_SECRET=0123" /etc/firewall-web/firewall-web.env
    grep -qx "NFT_BACKEND=inspection" /etc/firewall-web/firewall-web.env
    grep -qx "preserve" /var/lib/firewall-web/unrelated-state

    mkdir -p /etc/systemd/system
    : >/etc/systemd/system/nft-web-restore.service
    if dpkg --remove firewall-web; then
      echo "Package removal did not refuse to orphan the native restore unit." >&2
      exit 1
    else
      status=$?
      test "$status" -ne 0
    fi
    test -e /usr/lib/firewall-web/firewall_web.py
    rm /etc/systemd/system/nft-web-restore.service
    dpkg --remove firewall-web
    test -e /etc/firewall-web/firewall-web.env
    test -e /var/lib/firewall-web/unrelated-state
    test ! -e /usr/lib/firewall-web/firewall_web.py
    echo "Debian package upgrade, configuration/data preservation, and safe removal passed."
  '
