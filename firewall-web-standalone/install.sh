#!/usr/bin/env bash
set -euo pipefail
backend=${NFT_BACKEND:-auto}
backend_ack=${NFT_BACKEND_ACK:-}
python_bin=${FIREWALL_WEB_PYTHON:-python3}
non_interactive=false
dry_run=false
json_output=false
upgrade=false
uninstall=false
backend_specified=false
acknowledgement_specified=false
if [[ -n "$backend_ack" ]]; then acknowledgement_specified=true; fi
while (($#)); do
  case "$1" in
    --help|-h)
      echo "Usage: sudo bash install.sh [--backend auto|ufw|firewalld|nftables|iptables|inspection] [--acknowledge-conflict active-managers:firewalld,ufw] [--non-interactive] [--upgrade | --uninstall | --dry-run [--json]]"
      exit 0
      ;;
    --backend)
      (($# >= 2)) || { echo "--backend requires a value." >&2; exit 2; }
      backend=$2
      backend_specified=true
      shift 2
      ;;
    --acknowledge-conflict)
      (($# >= 2)) || { echo "--acknowledge-conflict requires the exact value from --detect-json." >&2; exit 2; }
      backend_ack=$2
      acknowledgement_specified=true
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
    --upgrade)
      upgrade=true
      shift
      ;;
    --uninstall)
      uninstall=true
      shift
      ;;
    *)
      echo "Usage: sudo bash install.sh [--backend auto|ufw|firewalld|nftables|iptables|inspection] [--acknowledge-conflict active-managers:firewalld,ufw] [--non-interactive] [--upgrade | --uninstall | --dry-run [--json]]" >&2
      exit 2
      ;;
  esac
done
if $upgrade && $uninstall || $dry_run && { $upgrade || $uninstall; } || $uninstall && { $non_interactive || $json_output || $backend_specified || $acknowledgement_specified; }; then
  echo "Choose one operation; --uninstall cannot be combined with install options." >&2
  exit 2
fi
[[ "$backend" =~ ^(auto|ufw|firewalld|nftables|iptables|inspection)$ ]] || { echo "Invalid backend: $backend" >&2; exit 2; }
if $acknowledgement_specified && [[ "$backend" == auto || "$backend" == inspection ]]; then
  echo "A conflict acknowledgement requires an explicit manager backend selection." >&2
  exit 2
fi
if $acknowledgement_specified && [[ "$backend_ack" != active-managers:firewalld,ufw ]]; then
  echo "Unsupported conflict acknowledgement. Use the exact value reported by detection." >&2
  exit 2
fi
if $json_output && ! $dry_run; then
  echo "--json is only valid with --dry-run." >&2
  exit 2
fi
if [[ $EUID -ne 0 ]]; then echo "Run: sudo bash install.sh" >&2; exit 1; fi
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if $dry_run; then
  if ! "$python_bin" -c 'import flask' >/dev/null 2>&1; then
    echo "Dry run requires Flask to be available to system Python; no changes were made." >&2
    exit 3
  fi
  report=$(NFT_BACKEND="$backend" NFT_BACKEND_ACK="$backend_ack" "$python_bin" firewall_web.py --detect-json)
  if $json_output; then
    printf '%s\n' "$report"
    printf '%s\n' "$report" | "$python_bin" -c 'import json,sys; d=json.load(sys.stdin); sys.exit(4 if d["selected_backend"]=="inspection" and sys.argv[1] not in ("auto","inspection") else 0)' "$backend"
  else
    printf '%s\n' "$report" | "$python_bin" -c 'import json,sys; d=json.load(sys.stdin); print("[firewall-web] Detection: "+d["selected_backend"]+"; "+d["reason"]); sys.exit(4 if d["selected_backend"]=="inspection" and sys.argv[1] not in ("auto","inspection") else 0)' "$backend"
  fi
  exit 0
fi

if $uninstall; then
  if [[ ! -e /opt/firewall-web/firewall_web.py && ! -e /etc/systemd/system/firewall-web.service ]]; then
    echo "No standalone installation found."
    exit 0
  fi
  if [[ -e /etc/systemd/system/nft-web-restore.service ]]; then
    echo "Refusing to remove the application while nft-web-restore.service depends on its code. Migrate or explicitly remove that restore configuration first; firewall rules and saved state were not changed." >&2
    exit 4
  fi
  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    if systemctl is-active --quiet firewall-web.service || systemctl is-enabled --quiet firewall-web.service; then
      systemctl disable --now firewall-web.service
    fi
    systemctl daemon-reload
  fi
  rm -f -- /etc/systemd/system/firewall-web.service /etc/systemd/system/firewall_web.service
  rm -f -- /usr/local/bin/firewall-web
  rm -f -- /opt/firewall-web/firewall_web.py /opt/firewall-web/requirements.txt \
    /opt/firewall-web/LICENSE
  rm -rf -- /opt/firewall-web/venv /opt/firewall-web/fonts
  rmdir --ignore-fail-on-non-empty /opt/firewall-web
  echo "Standalone application removed. /etc/firewall-web and /var/lib/firewall-web were preserved; no firewall rules or other services were changed."
  exit 0
fi

existing_install=false
for path in /opt/firewall-web/firewall_web.py /etc/firewall-web/firewall-web.env \
            /etc/systemd/system/firewall-web.service /etc/systemd/system/firewall_web.service; do
  [[ ! -e "$path" ]] || existing_install=true
done
if $upgrade; then
  if ! $existing_install || [[ ! -f /etc/firewall-web/firewall-web.env ]]; then
    echo "--upgrade requires an existing standalone install and its configuration file." >&2
    exit 1
  fi
  if ! $backend_specified; then
    existing_backend=$(awk -F= '/^[[:space:]]*NFT_BACKEND[[:space:]]*=/{value=$2} END {gsub(/[[:space:]"'\'']/, "", value); print value}' /etc/firewall-web/firewall-web.env)
    if [[ -n "$existing_backend" ]]; then
      [[ "$existing_backend" =~ ^(auto|ufw|firewalld|nftables|iptables|inspection)$ ]] || {
        echo "Existing NFT_BACKEND is invalid; correct it or pass --backend explicitly." >&2
        exit 4
      }
      backend=$existing_backend
    fi
  fi
  if ! $acknowledgement_specified && [[ "$backend" =~ ^(ufw|firewalld|nftables|iptables)$ ]]; then
    existing_ack=$(awk -F= '/^[[:space:]]*NFT_BACKEND_ACK[[:space:]]*=/{value=$2} END {gsub(/[[:space:]"'\'']/, "", value); print value}' /etc/firewall-web/firewall-web.env)
    if [[ -n "$existing_ack" ]]; then
      backend_ack=$existing_ack
      acknowledgement_specified=true
    fi
  fi
  if $acknowledgement_specified && [[ "$backend_ack" != active-managers:firewalld,ufw ]]; then
    echo "Existing conflict acknowledgement is invalid; correct it or pass --acknowledge-conflict explicitly." >&2
    exit 4
  fi
elif $existing_install; then
  echo "Existing installation found. Use --upgrade to preserve its configuration, or --uninstall to remove the standalone app." >&2
  exit 1
fi

if ! $upgrade; then
if $non_interactive; then
  pin=${NFT_SECRET:-}
else
  read -rsp 'Choose a four-digit PIN: ' pin </dev/tty
  printf '\n'
fi
[[ "$pin" =~ ^[0-9]{4}$ ]] || { echo "PIN must be exactly four digits." >&2; exit 1; }
fi
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
if [[ ! -x /opt/firewall-web/venv/bin/python ]]; then
  python3 -m venv /opt/firewall-web/venv
fi
/opt/firewall-web/venv/bin/python -m pip install -r /opt/firewall-web/requirements.txt
report=$(NFT_BACKEND_ACK="$backend_ack" /opt/firewall-web/venv/bin/python /opt/firewall-web/firewall_web.py --backend "$backend" --detect-json)
printf '%s\n' "$report" | /opt/firewall-web/venv/bin/python -c 'import json,sys; d=json.load(sys.stdin); print("[firewall-web] Detection: "+d["selected_backend"]+"; "+d["reason"])'
if $acknowledgement_specified && ! printf '%s\n' "$report" | /opt/firewall-web/venv/bin/python -c 'import json,sys; d=json.load(sys.stdin); sys.exit(d.get("conflict_acknowledgement")==sys.argv[1])' "$backend_ack"; then
  echo "Conflict acknowledgement does not match the currently detected active managers." >&2
  exit 4
fi
if [[ "$backend" != auto && "$backend" != inspection ]] && printf '%s\n' "$report" | /opt/firewall-web/venv/bin/python -c 'import json,sys; sys.exit(json.load(sys.stdin)["selected_backend"]=="inspection")'; then
  echo "Requested backend conflicts with current firewall ownership; installation stopped before service setup." >&2
  exit 4
fi
if ! $upgrade; then
  install -m 600 firewall-web.env.example /etc/firewall-web/firewall-web.env
  sed -i "s/^NFT_SECRET=.*/NFT_SECRET=$pin/" /etc/firewall-web/firewall-web.env
  unset pin
  resolved_backend=$backend
  if [[ "$backend" == auto ]] && printf '%s\n' "$report" | /opt/firewall-web/venv/bin/python -c 'import json,sys; sys.exit(json.load(sys.stdin)["selected_backend"]=="inspection")'; then
    resolved_backend=inspection
    echo "[firewall-web] Ambiguous auto-selection; configured inspection-only mode."
  fi
  printf 'NFT_BACKEND=%s\n' "$resolved_backend" >> /etc/firewall-web/firewall-web.env
  if $acknowledgement_specified; then
    printf 'NFT_BACKEND_ACK=%s\n' "$backend_ack" >> /etc/firewall-web/firewall-web.env
  fi
elif $backend_specified; then
  if grep -q '^[[:space:]]*NFT_BACKEND[[:space:]]*=' /etc/firewall-web/firewall-web.env; then
    sed -i "s/^[[:space:]]*NFT_BACKEND[[:space:]]*=.*/NFT_BACKEND=$backend/" /etc/firewall-web/firewall-web.env
  else
    printf 'NFT_BACKEND=%s\n' "$backend" >> /etc/firewall-web/firewall-web.env
  fi
fi
if $upgrade && $acknowledgement_specified; then
  if grep -q '^[[:space:]]*NFT_BACKEND_ACK[[:space:]]*=' /etc/firewall-web/firewall-web.env; then
    sed -i "s/^[[:space:]]*NFT_BACKEND_ACK[[:space:]]*=.*/NFT_BACKEND_ACK=$backend_ack/" /etc/firewall-web/firewall-web.env
  else
    printf 'NFT_BACKEND_ACK=%s\n' "$backend_ack" >> /etc/firewall-web/firewall-web.env
  fi
fi
if ! $upgrade; then
  install -m 644 firewall-web.service /etc/systemd/system/firewall-web.service
fi
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  systemctl daemon-reload
  if $upgrade; then
    if systemctl is-active --quiet firewall-web.service; then
      systemctl restart firewall-web.service
      systemctl --no-pager --full status firewall-web.service
    else
      echo "Upgrade complete; firewall-web.service remains inactive as before."
    fi
  else
    systemctl enable --now firewall-web.service
    systemctl --no-pager --full status firewall-web.service
  fi
else
  printf '\nNo running systemd detected; start/restart the UI in the foreground with: firewall-web\n'
fi
if $upgrade; then
  printf '\nUpgrade complete; existing configuration, PIN, and service enablement were preserved.\n'
else
  printf '\nOpen http://127.0.0.1:5005 on this server, or use the SSH tunnel in README.txt.\n'
fi
