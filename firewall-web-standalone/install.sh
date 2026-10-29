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
python3 -m venv /opt/firewall-web/venv
/opt/firewall-web/venv/bin/python -m pip install -r /opt/firewall-web/requirements.txt
install -m 600 firewall-web.env.example /etc/firewall-web/firewall-web.env
sed -i "s/^NFT_SECRET=.*/NFT_SECRET=$pin/" /etc/firewall-web/firewall-web.env
unset pin
install -m 644 firewall-web.service /etc/systemd/system/firewall-web.service
systemctl daemon-reload
systemctl enable --now firewall-web.service
systemctl --no-pager --full status firewall-web.service
printf '\nOpen http://127.0.0.1:5005 on this server, or use the SSH tunnel in README.txt.\n'
