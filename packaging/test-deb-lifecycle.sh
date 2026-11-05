#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
command -v docker >/dev/null 2>&1 || { echo "Docker is required." >&2; exit 2; }

packaging/build-deb.sh 1.0.3 amd64
packaging/build-deb.sh 1.0.4 amd64

docker run --rm --network bridge \
  -v "$repo_root:/repo:ro" debian:stable-slim sh -ec '
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      python3 python3-flask python3-waitress >/dev/null
    install_log=$(mktemp)
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      /repo/dist/firewall-web_1.0.3_amd64.deb >"$install_log" 2>&1; then
      generated_pin=$(cat /var/lib/firewall-web/initial-pin 2>/dev/null || true)
      if [ -n "$generated_pin" ]; then
        sed "s/$generated_pin/[redacted]/g" "$install_log" >&2
      else
        cat "$install_log" >&2
      fi
      exit 1
    fi
    generated_pin=$(cat /var/lib/firewall-web/initial-pin)
    case "$generated_pin" in
      [0-9][0-9][0-9][0-9]) ;;
      *) echo "First install did not create a four-digit PIN." >&2; exit 1 ;;
    esac
    test "$(stat -c %a /var/lib/firewall-web/initial-pin)" = 600
    if ! tr -d "\r" <"$install_log" | grep -qx "HAPPY FIREWALLING!"; then
      sed "s/$generated_pin/[redacted]/g" "$install_log" >&2
      exit 1
    fi
    if grep -Fq "$generated_pin" "$install_log"; then
      echo "Generated PIN leaked into package output." >&2
      exit 1
    fi
    rm -f "$install_log" /var/lib/firewall-web/initial-pin
    test "$(stat -c %a /etc/firewall-web/firewall-web.env)" = 600
    printf "NFT_SECRET=0123\nNFT_HOST=127.0.0.1\nNFT_PORT=5005\nNFT_BACKEND=inspection\nCUSTOM_SETTING=keep\n" \
      >/etc/firewall-web/firewall-web.env
    chmod 600 /etc/firewall-web/firewall-web.env
    mkdir -p /var/lib/firewall-web
    printf "preserve\n" >/var/lib/firewall-web/unrelated-state

    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      -o Dpkg::Options::=--force-confold /repo/dist/firewall-web_1.0.4_amd64.deb
    grep -qx "NFT_SECRET=0123" /etc/firewall-web/firewall-web.env
    grep -qx "NFT_BACKEND=inspection" /etc/firewall-web/firewall-web.env
    grep -qx "CUSTOM_SETTING=keep" /etc/firewall-web/firewall-web.env
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
    printf "purge-pin\n" >/var/lib/firewall-web/initial-pin
    chmod 600 /var/lib/firewall-web/initial-pin
    dpkg --purge firewall-web
    test ! -e /var/lib/firewall-web/initial-pin
    test ! -e /etc/firewall-web/firewall-web.env
    test -e /var/lib/firewall-web/unrelated-state
    umask 077
    cat >/tmp/firewall-web.preseed <<EOF
firewall-web firewall-web/host string 127.0.0.1
firewall-web firewall-web/port string 5535
firewall-web firewall-web/backend select inspection
firewall-web firewall-web/start-service boolean false
EOF
    debconf-set-selections /tmp/firewall-web.preseed
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      /repo/dist/firewall-web_1.0.4_amd64.deb
    grep -qx "NFT_HOST=127.0.0.1" /etc/firewall-web/firewall-web.env
    grep -qx "NFT_PORT=5535" /etc/firewall-web/firewall-web.env
    grep -qx "NFT_BACKEND=inspection" /etc/firewall-web/firewall-web.env
    test -f /var/lib/firewall-web/initial-pin
    sed -i \
      -e "s/^NFT_HOST=.*/NFT_HOST=192.0.2.10/" \
      -e "s/^NFT_PORT=.*/NFT_PORT=5512/" \
      /etc/firewall-web/firewall-web.env
    printf "CUSTOM_SETTING=admin-edit\n" >>/etc/firewall-web/firewall-web.env
    if ! DEBIAN_FRONTEND=noninteractive dpkg-reconfigure firewall-web >/tmp/reconfigure.log 2>&1; then
      cat /tmp/reconfigure.log >&2
      exit 1
    fi
    if ! grep -qx "NFT_HOST=192.0.2.10" /etc/firewall-web/firewall-web.env ||
      ! grep -qx "NFT_PORT=5512" /etc/firewall-web/firewall-web.env ||
      ! grep -qx "NFT_BACKEND=inspection" /etc/firewall-web/firewall-web.env ||
      ! grep -qx "CUSTOM_SETTING=admin-edit" /etc/firewall-web/firewall-web.env; then
      cat /etc/firewall-web/firewall-web.env >&2
      cat /tmp/reconfigure.log >&2
      exit 1
    fi
    echo "Manual configuration survived dpkg-reconfigure."
    printf "#!/bin/sh\nexit 0\n" >/usr/sbin/policy-rc.d
    chmod 755 /usr/sbin/policy-rc.d
    mkdir -p /run/systemd/system /tmp/mockbin
    cat >/tmp/mockbin/systemctl <<EOF
#!/bin/sh
echo "\$*" >>/tmp/systemctl.calls
case "\$1" in
  daemon-reload) exit 0 ;;
      is-enabled)
    if [ -e /tmp/mock-masked ]; then echo masked; exit 1; fi
    if [ -e /tmp/mock-enabled ]; then echo enabled; exit 0; fi
    echo disabled; exit 1
        ;;
      is-active)
        if [ -e /tmp/mock-active ]; then
          [ "\${2:-}" = --quiet ] || echo active
          exit 0
        fi
        [ "\${2:-}" = --quiet ] || echo inactive
        exit 3
        ;;
      *) exit 99 ;;
    esac
EOF
    chmod 755 /tmp/mockbin/systemctl
    : >/tmp/systemctl.calls
    if ! PATH="/tmp/mockbin:$PATH" DEBIAN_FRONTEND=noninteractive \
      /usr/lib/firewall-web/debian-postinst configure >/tmp/deferred-install.log 2>&1; then
      cat /tmp/deferred-install.log >&2
      exit 1
    fi
    grep -q "Startup deferred: service startup was disabled by the installation choice" /tmp/deferred-install.log
    grep -q "Service state: inactive; boot start: disabled" /tmp/deferred-install.log
    ! grep -Eq "^(enable|start|restart)( |$)" /tmp/systemctl.calls
    printf "firewall-web firewall-web/start-service boolean true\n" >/tmp/start-true.preseed
    debconf-set-selections /tmp/start-true.preseed
    printf "#!/bin/sh\nexit 101\n" >/usr/sbin/policy-rc.d
    if ! PATH="/tmp/mockbin:$PATH" DEBIAN_FRONTEND=noninteractive \
      /usr/lib/firewall-web/debian-postinst configure >/tmp/policy-deferred.log 2>&1; then
      cat /tmp/policy-deferred.log >&2
      exit 1
    fi
    grep -q "Startup deferred: policy-rc.d denied service startup" /tmp/policy-deferred.log
    ! grep -Eq "^(enable|start|restart)( |$)" /tmp/systemctl.calls
    printf "#!/bin/sh\nexit 0\n" >/usr/sbin/policy-rc.d
    : >/tmp/mock-enabled
    : >/tmp/mock-active
    cat >/tmp/mockbin/deb-systemd-invoke <<EOF
#!/bin/sh
echo "\$*" >>/tmp/invoke.calls
exit 1
EOF
    cat >/tmp/mockbin/deb-systemd-helper <<EOF
#!/bin/sh
echo "\$*" >>/tmp/helper.calls
exit 0
EOF
    chmod 755 /tmp/mockbin/deb-systemd-invoke
    chmod 755 /tmp/mockbin/deb-systemd-helper
    : >/tmp/invoke.calls
    : >/tmp/helper.calls
    if PATH="/tmp/mockbin:$PATH" DEBIAN_FRONTEND=noninteractive \
      /usr/lib/firewall-web/debian-postinst configure >/tmp/start-failure.log 2>&1; then
      cat /tmp/start-failure.log >&2
      cat /tmp/invoke.calls >&2
      cat /tmp/helper.calls >&2
      echo "A failed service-start command was reported as successful." >&2
      exit 1
    fi
    if ! grep -q "Failed to start firewall-web.service" /tmp/start-failure.log ||
      grep -qx "HAPPY FIREWALLING!" /tmp/start-failure.log ||
      ! grep -qx "start firewall-web.service" /tmp/invoke.calls; then
      cat /tmp/start-failure.log >&2
      cat /tmp/invoke.calls >&2
      exit 1
    fi

    sed -i -e "s/^NFT_HOST=.*/NFT_HOST=127.0.0.1/" \
      -e "s/^NFT_PORT=.*/NFT_PORT=5507/" /etc/firewall-web/firewall-web.env
    /usr/bin/firewall-web >/tmp/firewall-web-running.log 2>&1 &
    app_pid=$!
    ready=false
    for attempt in $(seq 1 30); do
      if /usr/bin/python3 /usr/lib/firewall-web/firewall-web-config.py ready \
        --config /etc/firewall-web/firewall-web.env; then
        ready=true
        break
      fi
      sleep 1
    done
    if ! $ready; then
      cat /tmp/firewall-web-running.log >&2
      exit 1
    fi
    echo "Authenticated readiness responded from the isolated package instance."
    cat >/tmp/mockbin/deb-systemd-invoke <<EOF
#!/bin/sh
echo "\$*" >>/tmp/invoke.calls
exit 0
EOF
    chmod 755 /tmp/mockbin/deb-systemd-invoke
    if ! PATH="/tmp/mockbin:$PATH" DEBIAN_FRONTEND=noninteractive \
      /usr/lib/firewall-web/debian-postinst configure 1.0.3 >/tmp/upgrade-running.log 2>&1; then
      cat /tmp/upgrade-running.log >&2
      exit 1
    fi
    grep -qx "restart firewall-web.service" /tmp/invoke.calls
    if ! grep -q "Service state: active; boot start: enabled" /tmp/upgrade-running.log; then
      cat /tmp/upgrade-running.log >&2
      exit 1
    fi
    echo "Running-service upgrade restarted and passed readiness."
    kill "$app_pid"
    wait "$app_pid" 2>/dev/null || true
    app_pid=

    rm -f /tmp/mock-active /tmp/mock-enabled
    : >/tmp/invoke.calls
    PATH="/tmp/mockbin:$PATH" DEBIAN_FRONTEND=noninteractive \
      /usr/lib/firewall-web/debian-postinst configure 1.0.3 >/tmp/upgrade-stopped.log 2>&1
    grep -q "Startup deferred: the service was stopped before the upgrade and remains stopped" /tmp/upgrade-stopped.log
    grep -q "Service state: inactive; boot start: disabled" /tmp/upgrade-stopped.log
    test ! -s /tmp/invoke.calls

    : >/tmp/mock-enabled
    PATH="/tmp/mockbin:$PATH" DEBIAN_FRONTEND=noninteractive \
      /usr/lib/firewall-web/debian-postinst configure 1.0.3 >/tmp/upgrade-disabled-active.log 2>&1
    grep -q "Service state: inactive; boot start: enabled" /tmp/upgrade-disabled-active.log
    test ! -s /tmp/invoke.calls

    : >/tmp/mock-masked
    PATH="/tmp/mockbin:$PATH" DEBIAN_FRONTEND=noninteractive \
      /usr/lib/firewall-web/debian-postinst configure 1.0.3 >/tmp/upgrade-masked.log 2>&1
    grep -q "Startup deferred: the service unit is masked" /tmp/upgrade-masked.log
    grep -q "Service state: inactive; boot start: masked" /tmp/upgrade-masked.log
    test ! -s /tmp/invoke.calls
    rm -f /tmp/mock-masked /tmp/mock-enabled
    rm -rf /run/systemd/system /tmp/mock-enabled /tmp/mock-active
    ! grep -q 'firewall-web/secret' /tmp/firewall-web.preseed
    dpkg --purge firewall-web
    rm -f /tmp/firewall-web.preseed
    cat >/tmp/firewall-web.invalid-preseed <<EOF
firewall-web firewall-web/host string 127.0.0.1
firewall-web firewall-web/port string 70000
firewall-web firewall-web/backend select inspection
firewall-web firewall-web/start-service boolean false
EOF
    debconf-set-selections /tmp/firewall-web.invalid-preseed
    if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      /repo/dist/firewall-web_1.0.4_amd64.deb >/tmp/invalid-preseed.log 2>&1; then
      echo "An invalid noninteractive debconf value was accepted." >&2
      exit 1
    fi
    if ! grep -q "Invalid preseeded Firewall Web setting: port" /tmp/invalid-preseed.log ||
      grep -qx "HAPPY FIREWALLING!" /tmp/invalid-preseed.log ||
      ! test -e /etc/firewall-web/firewall-web.env ||
      grep -Eq "^NFT_(HOST|PORT|BACKEND|SECRET)=" /etc/firewall-web/firewall-web.env; then
      cat /tmp/invalid-preseed.log >&2
      dpkg-query -W -f="\${db:Status-Status}\\n" firewall-web >&2 || true
      exit 1
    fi
    printf "firewall-web firewall-web/port string 5525\n" >/tmp/firewall-web.corrected-preseed
    debconf-set-selections /tmp/firewall-web.corrected-preseed
    if ! DEBIAN_FRONTEND=noninteractive dpkg --configure firewall-web >/tmp/corrected-preseed.log 2>&1; then
      cat /tmp/corrected-preseed.log >&2
      exit 1
    fi
    grep -qx "NFT_PORT=5525" /etc/firewall-web/firewall-web.env
    test -f /var/lib/firewall-web/initial-pin
    test_pin=$(python3 -c "import secrets; print(str(secrets.randbelow(10000)).zfill(4))")
    printf "firewall-web firewall-web/secret password %s\n" "$test_pin" \
      >/tmp/firewall-web.pin-preseed
    debconf-set-selections /tmp/firewall-web.pin-preseed
    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure firewall-web >/tmp/pin-reconfigure.log 2>&1
    grep -qx "NFT_SECRET=$test_pin" /etc/firewall-web/firewall-web.env
    test ! -e /var/lib/firewall-web/initial-pin
    ! grep -Fq "$test_pin" /tmp/pin-reconfigure.log
    rm -f /tmp/firewall-web.pin-preseed
    unset test_pin
    dpkg --purge firewall-web >/dev/null
    rm -f /tmp/firewall-web.invalid-preseed
    echo "Debian debconf PIN onboarding, upgrade/config preservation, remove, and purge passed."
  '
