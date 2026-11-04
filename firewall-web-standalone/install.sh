#!/usr/bin/env bash
set -euo pipefail
backend=${NFT_BACKEND:-auto}
python_bin=${FIREWALL_WEB_PYTHON:-python3}
non_interactive=false
dry_run=false
json_output=false
while (($#)); do
  case "$1" in
    --help|-h)
      echo "Usage: sudo bash install.sh [--backend auto|ufw|firewalld|nftables|iptables|inspection] [--non-interactive] [--dry-run [--json]]"
      exit 0
      ;;
    --backend)
      (($# >= 2)) || { echo "--backend requires a value." >&2; exit 2; }
      backend=$2
      shift 2
      ;;
    --non-interactive)
      non_interactive=true
      shift
      ;;
    --dry-run)
      dry_run=true
      shift
      ;;
    --json)
      json_output=true
      shift
      ;;
    *)
      echo "Usage: sudo bash install.sh [--backend auto|ufw|firewalld|nftables|iptables|inspection] [--non-interactive] [--dry-run]" >&2
      exit 2
      ;;
  esac
done
[[ "$backend" =~ ^(auto|ufw|firewalld|nftables|iptables|inspection)$ ]] || { echo "Invalid backend: $backend" >&2; exit 2; }
if $json_output && ! $dry_run; then
  echo "--json is only valid with --dry-run." >&2
  exit 2
fi
if [[ $EUID -ne 0 ]]; then echo "Run: sudo bash install.sh" >&2; exit 1; fi
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ -e /opt/firewall-web/firewall_web.py || -e /etc/firewall-web/firewall-web.env || -e /etc/systemd/system/firewall-web.service || -e /etc/systemd/system/firewall_web.service ]]; then
  echo "Existing installation found. Installer is for first-time installs; nothing changed." >&2; exit 1
fi
if $dry_run; then
  if ! "$python_bin" -c 'import flask' >/dev/null 2>&1; then
    echo "Dry run requires Flask to be available to system Python; no changes were made." >&2
    exit 3
  fi
  report=$(NFT_BACKEND="$backend" "$python_bin" firewall_web.py --detect-json)
  if $json_output; then
    printf '%s\n' "$report"
    printf '%s\n' "$report" | "$python_bin" -c 'import json,sys; d=json.load(sys.stdin); sys.exit(4 if d["selected_backend"]=="inspection" and sys.argv[1] not in ("auto","inspection") else 0)' "$backend"
  else
    printf '%s\n' "$report" | "$python_bin" -c 'import json,sys; d=json.load(sys.stdin); print("[firewall-web] Detection: "+d["selected_backend"]+"; "+d["reason"]); sys.exit(4 if d["selected_backend"]=="inspection" and sys.argv[1] not in ("auto","inspection") else 0)' "$backend"
  fi
  exit 0
fi
if $non_interactive; then
  pin=${NFT_SECRET:-}
else
  read -rsp 'Choose a four-digit PIN: ' pin </dev/tty
  printf '\n'
fi
[[ "$pin" =~ ^[0-9]{4}$ ]] || { echo "PIN must be exactly four digits." >&2; exit 1; }
apt-get update
if $non_interactive; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv
else
  apt-get install -y python3 python3-venv
fi
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
report=$(/opt/firewall-web/venv/bin/python /opt/firewall-web/firewall_web.py --backend "$backend" --detect-json)
printf '%s\n' "$report" | /opt/firewall-web/venv/bin/python -c 'import json,sys; d=json.load(sys.stdin); print("[firewall-web] Detection: "+d["selected_backend"]+"; "+d["reason"])'
if [[ "$backend" != auto && "$backend" != inspection ]] && printf '%s\n' "$report" | /opt/firewall-web/venv/bin/python -c 'import json,sys; sys.exit(json.load(sys.stdin)["selected_backend"]=="inspection")'; then
  echo "Requested backend conflicts with current firewall ownership; installation stopped before service setup." >&2
  exit 4
fi
install -m 600 firewall-web.env.example /etc/firewall-web/firewall-web.env
sed -i "s/^NFT_SECRET=.*/NFT_SECRET=$pin/" /etc/firewall-web/firewall-web.env
printf 'NFT_BACKEND=%s\n' "$backend" >> /etc/firewall-web/firewall-web.env
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
