#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo "Run: sudo bash install.sh" >&2; exit 1; fi
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ -e /opt/firewall-web/firewall_web.py || -e /etc/firewall-web/firewall-web.env || -e /etc/systemd/system/firewall-web.service || -e /etc/systemd/system/firewall_web.service ]]; then
  echo "Existing installation found. Installer is for first-time installs; nothing changed." >&2; exit 1
fi
read -rsp 'Choose a four-digit PIN: ' pin </dev/tty
printf '\n'
[[ "$pin" =~ ^[0-9]{4}$ ]] || { echo "PIN must be exactly four digits." >&2; exit 1; }
apt-get update
apt-get install -y python3 python3-venv iptables nftables
install -d -m 755 /opt/firewall-web
install -d -m 700 /etc/firewall-web /var/lib/firewall-web
install -m 644 firewall_web.py requirements.txt /opt/firewall-web/
install -m 644 ../LICENSE /opt/firewall-web/LICENSE
install -m 755 firewall-web /usr/local/bin/firewall-web
install -d -m 755 /opt/firewall-web/fonts /opt/firewall-web/fonts/licenses
install -m 644 fonts/*.woff2 fonts/*.ttf /opt/firewall-web/fonts/
install -m 644 fonts/licenses/* /opt/firewall-web/fonts/licenses/
python3 -m venv /opt/firewall-web/venv
/opt/firewall-web/venv/bin/python -m pip install -r /opt/firewall-web/requirements.txt
install -m 600 firewall-web.env.example /etc/firewall-web/firewall-web.env
sed -i "s/^NFT_SECRET=.*/NFT_SECRET=$pin/" /etc/firewall-web/firewall-web.env
unset pin
install -m 644 firewall-web.service /etc/systemd/system/firewall-web.service
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  systemctl daemon-reload
  systemctl enable --now firewall-web.service
  systemctl --no-pager --full status firewall-web.service
else
  printf '\nNo running systemd detected; start the UI in the foreground with: firewall-web\n'
fi
printf '\nOpen http://127.0.0.1:5005 on this server, or use the SSH tunnel in README.txt.\n'
