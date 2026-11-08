#!/usr/bin/env bash
set -euo pipefail
backend=${NFT_BACKEND:-auto}
backend_ack=${NFT_BACKEND_ACK:-}
listen_address=${NFT_HOST:-}
listen_port=${NFT_PORT:-}
pin_file=
python_bin=${FIREWALL_WEB_PYTHON:-python3}
non_interactive=false
dry_run=false
json_output=false
upgrade=false
uninstall=false
start_requested=true
start_choice_explicit=false
start_option_seen=false
backend_specified=false
acknowledgement_specified=false
if [[ -n "$backend_ack" ]]; then acknowledgement_specified=true; fi
while (($#)); do
  case "$1" in
    --help|-h)
      echo "Usage: sudo bash install.sh [--backend auto|ufw|firewalld|nftables|iptables|inspection] [--listen-address IP|HOST] [--port PORT] [--pin-file ROOT_ONLY_FILE] [--start-service|--no-start-service] [--acknowledge-conflict VALUE] [--non-interactive] [--upgrade|--uninstall|--dry-run [--json]]"
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
    --listen-address)
      (($# >= 2)) || { echo "--listen-address requires an IP address or hostname." >&2; exit 2; }
      listen_address=$2
      shift 2
      ;;
    --port)
      (($# >= 2)) || { echo "--port requires a TCP port from 1 to 65535." >&2; exit 2; }
      listen_port=$2
      shift 2
      ;;
    --pin-file)
      (($# >= 2)) || { echo "--pin-file requires a root-only file path." >&2; exit 2; }
      pin_file=$2
      shift 2
      ;;
    --start-service)
      $start_option_seen && { echo "Choose only one of --start-service or --no-start-service." >&2; exit 2; }
      start_requested=true
      start_choice_explicit=true
      start_option_seen=true
      shift
      ;;
    --no-start-service)
      $start_option_seen && { echo "Choose only one of --start-service or --no-start-service." >&2; exit 2; }
      start_requested=false
      start_choice_explicit=true
      start_option_seen=true
      shift
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
      echo "Usage: sudo bash install.sh [--backend auto|ufw|firewalld|nftables|iptables|inspection] [--listen-address IP|HOST] [--port PORT] [--pin-file ROOT_ONLY_FILE] [--start-service|--no-start-service] [--acknowledge-conflict VALUE] [--non-interactive] [--upgrade|--uninstall|--dry-run [--json]]" >&2
      exit 2
      ;;
  esac
done
if $upgrade && $uninstall || $dry_run && { $upgrade || $uninstall; } || \
  $uninstall && { $non_interactive || $json_output || $backend_specified || $acknowledgement_specified || \
    [[ -n "$listen_address" || -n "$listen_port" || -n "$pin_file" ]] || $start_choice_explicit; }; then
  echo "Choose one operation; --uninstall cannot be combined with install options." >&2
  exit 2
fi
if $upgrade && $start_choice_explicit; then
  echo "Upgrade preserves the existing service state; do not combine --upgrade with service-start options." >&2
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
  rm -f -- /opt/firewall-web/firewall_web.py /opt/firewall-web/firewall-web-config.py \
    /opt/firewall-web/requirements.txt /opt/firewall-web/LICENSE
  rm -rf -- /opt/firewall-web/venv /opt/firewall-web/fonts
  rmdir --ignore-fail-on-non-empty /opt/firewall-web
  echo "Standalone application removed. /etc/firewall-web and /var/lib/firewall-web were preserved; no firewall rules or other services were changed."
  exit 0
fi

app_installed=false
for path in /opt/firewall-web/firewall_web.py /etc/systemd/system/firewall-web.service \
            /etc/systemd/system/firewall_web.service; do
  [[ ! -e "$path" ]] || app_installed=true
done
if [[ -e /usr/lib/firewall-web/firewall_web.py ]] && ! $app_installed; then
  echo "A system package installation is present; manage it with apt/dpkg instead of the standalone installer." >&2
  exit 1
fi
if $uninstall; then
  if ! $app_installed; then
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
  rm -f -- /opt/firewall-web/firewall_web.py /opt/firewall-web/firewall-web-config.py \
    /opt/firewall-web/requirements.txt /opt/firewall-web/LICENSE
  rm -rf -- /opt/firewall-web/venv /opt/firewall-web/fonts
  rmdir --ignore-fail-on-non-empty /opt/firewall-web
  echo "Standalone application removed. /etc/firewall-web and /var/lib/firewall-web were preserved; no firewall rules or other services were changed."
  exit 0
fi

if $upgrade; then
  if ! $app_installed || [[ ! -f /etc/firewall-web/firewall-web.env ]]; then
    echo "--upgrade requires an existing standalone install and its configuration file." >&2
    exit 1
  fi
elif $app_installed; then
  echo "Existing standalone installation found. Use --upgrade to preserve its configuration, or --uninstall to remove the app." >&2
  exit 1
fi
if $upgrade && [[ -n "$pin_file" ]]; then
  echo "PIN provisioning is only accepted for a first install; upgrades preserve the existing PIN." >&2
  exit 2
fi
if [[ -n "$pin_file" && -n "${NFT_SECRET:-}" ]]; then
  echo "Use either NFT_SECRET or --pin-file, not both." >&2
  exit 2
fi

config=/etc/firewall-web/firewall-web.env
helper_source=../packaging/firewall-web-config.py
config_helper=/opt/firewall-web/firewall-web-config.py
validate_setting() {
  "$python_bin" "$helper_source" validate-value "$1" "$2"
}
current_value() {
  "$python_bin" "$helper_source" read --config "$config" "$1"
}
if [[ -f "$config" ]]; then
  current_host=$(current_value NFT_HOST)
  current_port=$(current_value NFT_PORT)
  current_backend=$(current_value NFT_BACKEND)
  current_ack=$(current_value NFT_BACKEND_ACK)
  current_secret=$(current_value NFT_SECRET)
  validate_setting NFT_SECRET "$current_secret" >/dev/null || current_secret=
else
  current_host=127.0.0.1
  current_port=5005
  current_backend=auto
  current_ack=
  current_secret=
fi
[[ -n "$listen_address" ]] || listen_address=${current_host:-127.0.0.1}
[[ -n "$listen_port" ]] || listen_port=${current_port:-5005}
if ! $backend_specified && [[ -n "$current_backend" ]]; then
  backend=$current_backend
fi
if ! $acknowledgement_specified; then
  backend_ack=$current_ack
fi

prompt_setting() {
  field=$1
  label=$2
  default=$3
  if $non_interactive; then
    answer=$default
  else
    while true; do
      printf '%s [%s]: ' "$label" "$default" >/dev/tty
      IFS= read -r answer </dev/tty || { echo "No interactive terminal; use --non-interactive and explicit options." >&2; exit 2; }
      answer=${answer:-$default}
      if validate_setting "$field" "$answer"; then
        break
      fi
      printf 'Invalid value. Please try again.\n' >/dev/tty
    done
  fi
  if ! validate_setting "$field" "$answer"; then
    echo "Invalid $field value. Correct it or provide a valid option." >&2
    exit 2
  fi
  printf '%s' "$answer"
}

if ! $upgrade; then
  if ! $non_interactive; then
    printf 'Settings are saved in /etc/firewall-web/firewall-web.env; changes later require: systemctl restart firewall-web.service\n' >/dev/tty
  fi
  listen_address=$(prompt_setting NFT_HOST \
    "Console listen address (127.0.0.1 is local-only; wildcard addresses listen on all interfaces)" "$listen_address")
  listen_port=$(prompt_setting NFT_PORT "Console TCP port (1-65535)" "$listen_port")
  backend_default=$backend
  if ! $backend_specified; then
    backend=$(prompt_setting NFT_BACKEND \
      "Firewall manager selection (auto detects existing managers; does not install or activate one)" "$backend")
    [[ "$backend" == "$backend_default" ]] || backend_specified=true
  fi
  if [[ -n "$pin_file" ]]; then
    [[ -f "$pin_file" && ! -L "$pin_file" ]] || { echo "--pin-file must name a regular, non-symlink file." >&2; exit 2; }
    [[ $(stat -c %u "$pin_file") -eq 0 ]] || { echo "--pin-file must be owned by root." >&2; exit 2; }
    pin_mode=$(stat -c %a "$pin_file")
    (( (8#$pin_mode & 077) == 0 )) || { echo "--pin-file must not be accessible to group or other users (chmod 600)." >&2; exit 2; }
    mapfile -t pin_lines < "$pin_file"
    [[ ${#pin_lines[@]} -eq 1 ]] || { echo "--pin-file must contain exactly one four-digit PIN line." >&2; exit 2; }
    pin=${pin_lines[0]}
  elif [[ -n "${NFT_SECRET:-}" ]]; then
    pin=$NFT_SECRET
  elif [[ -n "$current_secret" ]]; then
    pin=
  elif $non_interactive; then
    pin=
  else
    while true; do
      printf 'Web-console authentication PIN (exactly four digits; blank generates a random PIN): ' >/dev/tty
      IFS= read -r -s pin </dev/tty || { echo "No interactive terminal; use --non-interactive or --pin-file." >&2; exit 2; }
      printf '\n' >/dev/tty
      [[ -z "$pin" ]] && break
      if validate_setting NFT_SECRET "$pin"; then break; fi
      printf 'PIN must contain exactly four digits. Try again.\n' >/dev/tty
    done
  fi
  if [[ -n "$pin" ]] && ! validate_setting NFT_SECRET "$pin"; then
    unset pin
    echo "PIN must contain exactly four digits." >&2
    exit 2
  fi
  if ! $non_interactive && ! $start_choice_explicit; then
    printf 'Start and enable only the Firewall Web console now? It will not change firewall rules or open ports. [Y/n] ' >/dev/tty
    IFS= read -r start_answer </dev/tty || { echo "No interactive terminal; select --start-service or --no-start-service." >&2; exit 2; }
    case "$start_answer" in n|N|no|NO) start_requested=false ;; *) start_requested=true ;; esac
  fi
else
  pin=
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
install -m 755 ../packaging/firewall-web-config.py "$config_helper"
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
  resolved_backend=$backend
  if [[ "$backend" == auto ]] && printf '%s\n' "$report" | /opt/firewall-web/venv/bin/python -c 'import json,sys; sys.exit(json.load(sys.stdin)["selected_backend"]=="inspection")'; then
    resolved_backend=inspection
    echo "[firewall-web] Ambiguous auto-selection; configured inspection-only mode."
  fi
  printf '%s\n' "$listen_address" "$listen_port" "$pin" "$resolved_backend" "$backend_ack" |
    /opt/firewall-web/venv/bin/python "$config_helper" apply --config "$config" --mode initial
  if $backend_specified && [[ -f "$config" ]]; then
    printf '%s\n' "" "" "" "$backend" "$backend_ack" |
      /opt/firewall-web/venv/bin/python "$config_helper" apply --config "$config" --mode update
  fi
else
  update_host=
  update_port=
  update_backend=
  update_ack=
  $backend_specified && update_backend=$backend
  $acknowledgement_specified && update_ack=$backend_ack
  [[ -z "${NFT_HOST:-}" ]] || update_host=$NFT_HOST
  [[ -z "${NFT_PORT:-}" ]] || update_port=$NFT_PORT
  if [[ -n "$listen_address" && "$listen_address" != "$current_host" ]]; then update_host=$listen_address; fi
  if [[ -n "$listen_port" && "$listen_port" != "$current_port" ]]; then update_port=$listen_port; fi
  printf '%s\n' "$update_host" "$update_port" "" "$update_backend" "$update_ack" |
    /opt/firewall-web/venv/bin/python "$config_helper" apply --config "$config" --mode update
fi
/opt/firewall-web/venv/bin/python "$config_helper" secure --config "$config"
unset pin

if ! $upgrade; then
  install -m 644 firewall-web.service /etc/systemd/system/firewall-web.service
fi
deferred_reason=
enabled_by_installer=false
policy_denies() {
  action=$1
  [[ -x /usr/sbin/policy-rc.d ]] || return 1
  if /usr/sbin/policy-rc.d firewall-web.service "$action" >/dev/null 2>&1; then
    return 1
  else
    policy_status=$?
  fi
  [[ "$policy_status" -eq 101 ]]
}
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  systemctl daemon-reload
  unit_state=$(systemctl is-enabled firewall-web.service 2>/dev/null || true)
  was_active=false
  systemctl is-active --quiet firewall-web.service && was_active=true
  if [[ "$unit_state" == masked || "$unit_state" == masked-runtime ]]; then
    deferred_reason="the service unit is masked; it was not unmasked or started"
  elif $upgrade; then
    if $was_active; then
      if policy_denies restart; then
        deferred_reason="policy-rc.d denied service restart"
      else
        if ! systemctl restart firewall-web.service; then
          echo "Firewall Web failed to restart. Diagnose with: systemctl status firewall-web.service; journalctl -u firewall-web.service -n 100 --no-pager" >&2
          exit 1
        fi
      fi
    else
      deferred_reason="the service was stopped before the upgrade and remains stopped"
    fi
  elif ! $start_requested; then
    deferred_reason="service startup was disabled by the installation choice"
  elif policy_denies start; then
    deferred_reason="policy-rc.d denied service startup"
  else
    unit_was_enabled=false
    [[ "$unit_state" == enabled ]] && unit_was_enabled=true
    if ! systemctl enable firewall-web.service; then
      echo "Could not enable firewall-web.service; check systemd and unit permissions." >&2
      exit 1
    fi
    [[ "$unit_was_enabled" == true ]] || enabled_by_installer=true
    if ! systemctl start firewall-web.service; then
      [[ "$enabled_by_installer" == true ]] && systemctl disable firewall-web.service || true
      echo "Could not start firewall-web.service. Diagnose with: systemctl status firewall-web.service; journalctl -u firewall-web.service -n 100 --no-pager" >&2
      exit 1
    fi
  fi
  if [[ -z "$deferred_reason" ]]; then
    ready=false
    readiness_deadline=$(($(date +%s) + 600))
    for attempt in $(seq 1 600); do
      (( $(date +%s) < readiness_deadline )) || break
      if systemctl is-active --quiet firewall-web.service &&
        /opt/firewall-web/venv/bin/python "$config_helper" ready --config "$config"; then
        ready=true
        break
      fi
      sleep 1
    done
    if ! $ready; then
      [[ "$enabled_by_installer" == true ]] && systemctl disable firewall-web.service || true
      echo "Firewall Web failed to become active and ready. Diagnose with: systemctl status firewall-web.service; journalctl -u firewall-web.service -n 100 --no-pager" >&2
      exit 1
    fi
  fi
else
  deferred_reason="no running systemd instance is available"
fi

backend_report=$(NFT_BACKEND_ACK="$backend_ack" /usr/local/bin/firewall-web --detect-json)
backend_summary=$(printf '%s\n' "$backend_report" | /opt/firewall-web/venv/bin/python -c '
import json,sys
d=json.load(sys.stdin)
selected=d["selected_backend"]
mode="inspection-only" if selected=="inspection" else "writable" if d["can_write"] or d["manager_can_write"] else "read-only (insufficient host capability)"
print(f"{selected} ({mode})")
')
version=$(sed -n '1s/^firewall-web (\([^)]*\)).*/\1/p' ../debian/changelog | sed 's/-[^-]*$//')
host=$(/opt/firewall-web/venv/bin/python "$config_helper" read --config "$config" NFT_HOST)
port=$(/opt/firewall-web/venv/bin/python "$config_helper" read --config "$config" NFT_PORT)
case "$host" in
  0.0.0.0) access_url="http://127.0.0.1:$port"; access_note="Wildcard listener; use a secured tunnel for remote access. No firewall port was opened." ;;
  ::) access_url="http://[::1]:$port"; access_note="Wildcard listener; use a secured tunnel for remote access. No firewall port was opened." ;;
  ::1) access_url="http://[::1]:$port"; access_note="Localhost-only listener; use an SSH tunnel for remote access." ;;
  127.*|localhost) access_url="http://127.0.0.1:$port"; access_note="Localhost-only listener; use an SSH tunnel for remote access." ;;
  *:*) access_url="http://[$host]:$port"; access_note="No firewall port was opened; remote reachability depends on existing network policy." ;;
  *) access_url="http://$host:$port"; access_note="No firewall port was opened; remote reachability depends on existing network policy." ;;
esac
service_state=not-running
boot_state=unknown
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  service_state=$(systemctl is-active firewall-web.service 2>/dev/null || true)
  [[ -n "$service_state" ]] || service_state=inactive
  boot_state=$(systemctl is-enabled firewall-web.service 2>/dev/null || true)
  [[ -n "$boot_state" ]] || boot_state=unknown
fi
printf '\nFirewall Web %s installed.\n' "${version:-unknown}"
printf 'Selected backend: %s\n' "$backend_summary"
printf 'Service state: %s; boot start: %s\n' "$service_state" "$boot_state"
printf 'Configuration: %s (root-owned, mode 0600)\n' "$config"
printf 'Access URL: %s\n%s\n' "$access_url" "$access_note"
if [[ -f /var/lib/firewall-web/initial-pin ]]; then
  printf 'A generated PIN is stored root-only in /var/lib/firewall-web/initial-pin; retrieve it securely, then remove that file.\n'
fi
if [[ -n "$pin_file" ]]; then
  printf 'Remove the provisioned PIN file securely when it is no longer needed: %s\n' "$pin_file"
fi
printf 'Edit settings: sudoedit %s\n' "$config"
printf 'Restart: sudo systemctl restart firewall-web.service\n'
printf 'Status: sudo systemctl status firewall-web.service\n'
printf 'Recent logs: sudo journalctl -u firewall-web.service -n 100 --no-pager\n'
if [[ -n "$deferred_reason" ]]; then
  printf 'Startup deferred: %s.\n' "$deferred_reason"
  case "$deferred_reason" in
    "no running systemd instance is available")
      printf 'Run in the foreground when appropriate: sudo firewall-web\n' ;;
    "the service was stopped before the upgrade and remains stopped")
      printf 'Start manually when appropriate: sudo systemctl start firewall-web.service\n' ;;
    "the service unit is masked; it was not unmasked or started")
      printf 'After choosing to unmask it: sudo systemctl unmask firewall-web.service && sudo systemctl enable --now firewall-web.service\n' ;;
    "policy-rc.d denied service restart")
      printf 'After the policy permits it: sudo systemctl restart firewall-web.service\n' ;;
    "policy-rc.d denied service startup")
      printf 'After the policy permits it: sudo systemctl enable --now firewall-web.service\n' ;;
    *)
      printf 'After resolving the deferral, start when appropriate: sudo systemctl enable --now firewall-web.service\n' ;;
  esac
fi
if [[ -t 1 && -n "${TERM:-}" && "$TERM" != dumb ]]; then
  printf '\033[1;4mHAPPY FIREWALLING!\033[0m\n'
else
  printf 'HAPPY FIREWALLING!\n'
fi
