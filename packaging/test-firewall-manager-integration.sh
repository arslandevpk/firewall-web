#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
command -v docker >/dev/null 2>&1 || { echo "Docker is required." >&2; exit 2; }
scope=${1:-all}
case "$scope" in
  all|ufw|firewalld|native) ;;
  *) echo "Usage: $0 [all|ufw|firewalld|native]" >&2; exit 2 ;;
esac

if [[ "$scope" == all || "$scope" == ufw ]]; then
docker run --rm --network bridge --cap-add=NET_ADMIN \
  -v "$repo_root:/repo:ro" debian:stable-slim sh -ec '
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      python3 python3-flask python3-waitress curl ufw iptables nftables >/dev/null
    ufw --force reset >/dev/null
    ufw allow 41112/tcp >/dev/null
    ufw --force enable >/dev/null

    start_app() {
      NFT_SECRET=1234 NFT_BACKEND=ufw NFT_BACKUP_DIR=/tmp/fw-backups \
      NFT_ROLLBACK_DIR=/tmp/fw-rollback PYTHONPATH=/repo/firewall-web-standalone \
        python3 -c '"'"'import firewall_web as fw; fw.ROLLBACK_SECONDS=15; from waitress import serve; serve(fw.app, host="127.0.0.1", port=5505, threads=4)'"'"' \
        >/tmp/firewall-web.log 2>&1 &
      app_pid=$!
      for attempt in $(seq 1 30); do
        if curl --fail --silent http://127.0.0.1:5505/ >/dev/null; then return; fi
        sleep 1
      done
      cat /tmp/firewall-web.log
      return 1
    }
    stop_app() {
      if [ -n "${app_pid:-}" ]; then
        kill "$app_pid" 2>/dev/null || true
        wait "$app_pid" 2>/dev/null || true
        app_pid=
      fi
    }
    trap stop_app EXIT
    start_app
    rollback_id=$(python3 /repo/packaging/test-firewall-manager-api.py ufw)
    test "${#rollback_id}" -eq 32
    stop_app
    sleep 17
    status=$(ufw status numbered)
    printf "%s\n" "$status"
    printf "%s\n" "$status" | grep -F "41112/tcp"
    printf "%s\n" "$status" | grep -F "42424/tcp "
    printf "%s\n" "$status" | grep -F "42424/tcp (v6)"
    printf "%s\n" "$status" | grep -F "42426/tcp"
    if printf "%s\n" "$status" | grep -F "42427/tcp"; then exit 1; fi
    if printf "%s\n" "$status" | grep -F "42425"; then exit 1; fi
    ufw reload >/dev/null
    ufw status numbered | grep -F "41112/tcp" >/dev/null
    ufw status numbered | grep -F "42424/tcp (v6)" >/dev/null
    echo "UFW API, route rules, external drift, IPv4/IPv6 pair rollback, unrelated-rule preservation, and reload passed."
  '
fi

if [[ "$scope" == all || "$scope" == firewalld ]]; then
docker run --rm --network bridge --cap-add=NET_ADMIN \
  -v "$repo_root:/repo:ro" debian:stable-slim sh -ec '
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      python3 python3-flask python3-waitress curl firewalld dbus nftables >/dev/null
    mkdir -p /run/dbus
    dbus-daemon --system --fork
    firewalld --nofork --nopid >/tmp/firewalld.log 2>&1 &
    firewalld_pid=$!
    trap "if [ -n \"\${app_pid:-}\" ]; then kill \"\$app_pid\" 2>/dev/null || true; fi; kill \"\$firewalld_pid\" 2>/dev/null || true" EXIT
    for attempt in $(seq 1 30); do
      if firewall-cmd --state >/dev/null 2>&1; then break; fi
      sleep 1
    done
    firewall-cmd --state
    firewall-cmd --permanent --zone=trusted --add-port=41112/tcp >/dev/null
    firewall-cmd --permanent --new-policy=fwtest >/dev/null
    firewall-cmd --permanent --policy=fwtest --add-ingress-zone=HOST >/dev/null
    firewall-cmd --permanent --policy=fwtest --add-egress-zone=ANY >/dev/null
    firewall-cmd --reload >/dev/null

    start_app() {
      NFT_SECRET=1234 NFT_BACKEND=firewalld NFT_BACKUP_DIR=/tmp/fw-backups \
      NFT_ROLLBACK_DIR=/tmp/fw-rollback PYTHONPATH=/repo/firewall-web-standalone \
        python3 -c '"'"'import firewall_web as fw; fw.ROLLBACK_SECONDS=60; from waitress import serve; serve(fw.app, host="127.0.0.1", port=5505, threads=4)'"'"' \
        >/tmp/firewall-web.log 2>&1 &
      app_pid=$!
      for attempt in $(seq 1 30); do
        if curl --fail --silent http://127.0.0.1:5505/ >/dev/null; then return; fi
        sleep 1
      done
      cat /tmp/firewall-web.log
      cat /tmp/firewalld.log
      return 1
    }
    stop_app() {
      if [ -n "${app_pid:-}" ]; then
        kill "$app_pid" 2>/dev/null || true
        wait "$app_pid" 2>/dev/null || true
        app_pid=
      fi
    }
    wait_for_rollback() {
      rollback_id=$1
      expected=$2
      status=
      for attempt in $(seq 1 150); do
        status=$(python3 -c '"'"'import json,sys; print(json.load(open(sys.argv[1]))["status"])'"'"' \
          "/tmp/fw-rollback/$rollback_id.json")
        if [ "$status" != pending ]; then break; fi
        sleep 2
      done
      echo "Rollback $rollback_id status: $status"
      test "$status" = "$expected"
    }
    start_app
    rollback_id=$(python3 /repo/packaging/test-firewall-manager-api.py firewalld)
    test "${#rollback_id}" -eq 32
    stop_app
    wait_for_rollback "$rollback_id" rolled_back
    echo "Checking firewalld permanent rules after rollback..."
    firewall-cmd --permanent --zone=trusted --query-port=42428/tcp
    firewall-cmd --permanent --zone=trusted --query-source=198.51.100.0/24
    firewall-cmd --permanent --zone=trusted --query-interface=lo
    firewall-cmd --permanent --policy=fwtest --query-port=42430/tcp
    echo "Checking firewalld runtime state and unrelated rules..."
    firewall-cmd --policy=fwtest --query-port=42430/tcp
    firewall-cmd --zone=trusted --query-port=42432/tcp >/dev/null && exit 1 || true
    firewall-cmd --zone=trusted --query-port=41112/tcp
    start_app
    conflict_id=$(python3 /repo/packaging/test-firewall-manager-api.py firewalld-after-rollback "$rollback_id")
    test "${#conflict_id}" -eq 32
    stop_app
    sleep 62
    start_app
    python3 /repo/packaging/test-firewall-manager-api.py firewalld-after-external-change "$conflict_id"
    echo "firewalld runtime/permanent zones, bindings, rich rules, policies, reload, durable rollback, conflict preservation, and unrelated-rule retention passed."
  '
fi

if [[ "$scope" == all || "$scope" == native ]]; then
docker run --rm --network bridge --cap-add=NET_ADMIN \
  -v "$repo_root:/repo:ro" debian:stable-slim sh -ec '
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      python3 python3-flask iptables nftables >/dev/null
    NFT_SECRET=1234 NFT_BACKEND=auto NFT_NATIVE_STATE=/tmp/native-rules.json \
    NFT_BACKUP_DIR=/tmp/fw-backups PYTHONPATH=/repo/firewall-web-standalone \
      python3 /repo/packaging/test-native-restore.py
  '
fi
