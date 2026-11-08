#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
version=$(dpkg-parsechangelog -l"$root/debian/changelog" -S Version)
arch=$(dpkg --print-architecture)
for image in ubuntu:24.04 ubuntu:26.04 debian:bookworm-slim debian:trixie-slim; do
  docker run --rm --network bridge -e DEBIAN_FRONTEND=noninteractive \
    -e PACKAGE_VERSION="$version" -e PACKAGE_ARCH="$arch" \
    -v "$root:/repo:ro" "$image" bash -ec '
      # Reproduce missing lists, no Python dependencies, and Ubuntu main-only.
      if [[ -f /etc/apt/sources.list.d/ubuntu.sources ]]; then
        sed -i "s/^Components:.*/Components: main/" /etc/apt/sources.list.d/ubuntu.sources
      fi
      if [[ -f /etc/apt/sources.list ]]; then
        sed -i -E "s/ (universe|multiverse|restricted)//g" /etc/apt/sources.list
      fi
      if [[ -f /etc/apt/sources.list.d/debian.sources ]]; then
        sed -i "s/^Components:.*/Components: contrib/" /etc/apt/sources.list.d/debian.sources
      fi
      rm -rf /var/lib/apt/lists/*
      ! dpkg-query -W -f="\${Status}" python3-waitress 2>/dev/null | grep -q "install ok installed"
      bash /repo/packaging/install-deb.sh "/repo/dist/firewall-web_${PACKAGE_VERSION}_${PACKAGE_ARCH}.deb" > /tmp/install.log 2>&1 || { cat /tmp/install.log; exit 1; }
      python3 -c "import flask, waitress"
      dpkg --audit
      apt-get check
      sed -i "s/^NFT_SECRET=.*/NFT_SECRET=1234/;s/^NFT_PORT=.*/NFT_PORT=5505/" /etc/firewall-web/firewall-web.env
      firewall-web >/tmp/app.log 2>&1 &
      server=$!
      trap "kill $server 2>/dev/null || true" EXIT
      python3 /repo/packaging/test-readonly-http.py
      echo "CLEAN INSTALL PASS"
    '
done
