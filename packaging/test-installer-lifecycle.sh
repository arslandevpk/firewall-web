#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
command -v docker >/dev/null 2>&1 || { echo "Docker is required." >&2; exit 2; }

docker run --rm --network bridge \
  -v "$repo_root:/repo:ro" debian:stable-slim sh -ec '
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      python3 python3-flask python3-pip python3-venv python3-waitress >/dev/null
    python3 -m pip download --disable-pip-version-check \
      --dest /tmp/firewall-web-wheels -r /repo/firewall-web-standalone/requirements.txt
    cd /repo/firewall-web-standalone

    test ! -e /etc/firewall-web
    test ! -e /opt/firewall-web
    dpkg-query -W | sort >/tmp/packages.before
    find /etc/systemd/system -maxdepth 2 -type f -print 2>/dev/null | sort >/tmp/units.before || true
    NFT_BACKEND=inspection bash install.sh --dry-run --json >/tmp/dry-run.json
    grep -q "\"selected_backend\": \"inspection\"" /tmp/dry-run.json
    dpkg-query -W | sort >/tmp/packages.after
    find /etc/systemd/system -maxdepth 2 -type f -print 2>/dev/null | sort >/tmp/units.after || true
    cmp /tmp/packages.before /tmp/packages.after
    cmp /tmp/units.before /tmp/units.after
    test ! -e /etc/firewall-web
    test ! -e /opt/firewall-web

    PIP_NO_INDEX=1 PIP_FIND_LINKS=/tmp/firewall-web-wheels \
      NFT_SECRET=0123 bash install.sh --backend inspection --non-interactive
    test "$(stat -c %a /etc/firewall-web/firewall-web.env)" = 600
    grep -qx "NFT_SECRET=0123" /etc/firewall-web/firewall-web.env
    grep -qx "NFT_BACKEND=inspection" /etc/firewall-web/firewall-web.env
    cp /etc/firewall-web/firewall-web.env /tmp/firewall-web.env.before-upgrade

    PIP_NO_INDEX=1 PIP_FIND_LINKS=/tmp/firewall-web-wheels \
      bash install.sh --upgrade
    cmp /tmp/firewall-web.env.before-upgrade /etc/firewall-web/firewall-web.env
    cp /etc/firewall-web/firewall-web.env /tmp/firewall-web.env.before-dry-run
    bash install.sh --dry-run --json >/tmp/dry-run-after-install.json
    cmp /tmp/firewall-web.env.before-dry-run /etc/firewall-web/firewall-web.env

    install -d /etc/systemd/system
    : >/etc/systemd/system/nft-web-restore.service
    if bash install.sh --uninstall; then
      echo "Uninstall did not refuse to orphan the native restore unit." >&2
      exit 1
    else
      status=$?
      test "$status" -eq 4
    fi
    test -e /opt/firewall-web/firewall_web.py
    rm /etc/systemd/system/nft-web-restore.service
    bash install.sh --uninstall
    test ! -e /opt/firewall-web/firewall_web.py
    test -e /etc/firewall-web/firewall-web.env
    test -d /var/lib/firewall-web
    test ! -e /usr/local/bin/firewall-web
    echo "Installer dry-run immutability, noninteractive install, upgrade preservation, and safe uninstall passed."
  '
