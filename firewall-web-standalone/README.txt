FIREWALL WEB - STANDALONE EDITION

A small web console for the Linux firewall on the machine where it runs.
Detect the active firewall manager and inspect nftables and IPv4/IPv6 iptables
rules. Direct mode can add/delete rules, create chains, set policies, allow
service ports, manage masquerading, export/back up rules, and explicitly save
rules for reboot. Active UFW and firewalld installations are edited through
their own command interfaces.
See the repository's GLOSSARY.md for definitions of UI, firewall, permissions,
networking, and packaging terms.
Includes the responsive browser UI. No agent, hub, connected-server feature,
Cloudflare account, external API, or Tailscale installation is required.
The bundled Hack, JetBrains Mono, Fira Code, Source Code Pro, Cascadia Code,
IBM Plex Mono, and Inconsolata fonts and their licenses are installed alongside
the application; every font choice works offline.

REQUIREMENTS
To change firewall rules, this utility must be installed and run as root with
CAP_NET_ADMIN; it administers the firewall visible to its Linux kernel. PRoot
always starts in read-only mode. Without that capability, other environments
also start in read-only mode. Debian/Ubuntu normally uses systemd; Alpine
normally uses OpenRC. Python 3.10+ is required.
Python dependencies are in requirements.txt.
The installer does not install firewall packages, change firewall policies, or
enable firewall persistence. Review package-manager changes before installing
on an already managed host.

FIRST INSTALL
Unzip the archive and enter its firewall-web-standalone directory, then run:
  sudo bash install.sh
The installer explains and validates the listen address, TCP port, firewall
backend selection, and authentication PIN. The safe listen default is
127.0.0.1:5005. Leave the PIN blank to generate a cryptographically random
four-digit PIN; leading zeroes
are preserved. The PIN is never printed. Retrieve a generated PIN with
`sudo cat /var/lib/firewall-web/initial-pin` and securely remove that root-only
file after recording it. Existing valid configuration and PINs are preserved.
The installer creates a venv, installs application dependencies, runs
read-only manager detection, writes a root-owned mode-0600 configuration file,
and enables/starts the service by default on a running, unmasked systemd host.
It verifies both service activity and authenticated application readiness.
No firewall package is installed or activated, and no firewall rules,
policies, ports, or persistence settings are changed.
Use `--no-start-service` to defer service startup; the installer reports the
actual service and boot-start states and the exact command to start it later.
Configuration changes can be made with `sudoedit
/etc/firewall-web/firewall-web.env`; restart with
`sudo systemctl restart firewall-web.service`.
Use `sudo bash install.sh --upgrade` for an idempotent application upgrade; it
preserves the PIN, backend choice, service enablement, and local configuration.
Use `--backend` to explicitly set the saved backend selection during install.
The installer also accepts `--listen-address IP_OR_HOST`, `--port PORT`,
`--pin-file ROOT_ONLY_FILE`, `--start-service`, and `--no-start-service`.
Noninteractive installation accepts safe defaults and generates a PIN when
`NFT_SECRET` and `--pin-file` are omitted:
  sudo bash install.sh --non-interactive --listen-address 127.0.0.1 --port 5005
For unattended PIN provisioning, use a root-owned mode-0600 file containing
one four-digit PIN and pass its path with `--pin-file`; do not put the PIN in
command arguments or logs. `NFT_SECRET` is also accepted from the process
environment. Remove a provisioning file securely when it is no longer needed.
Use `sudo bash install.sh --uninstall` to remove the standalone app; its
configuration, backups, and firewall rules are preserved. Uninstall refuses
while nft-web-restore.service depends on the application code. Resolve or
migrate that native restore configuration explicitly first. Stop a foreground
process manually before uninstalling from a non-systemd environment.

DEBIAN PACKAGE ARTIFACTS
Run the "Build Debian and Alpine packages" workflow from the GitHub Actions
tab and enter a package version to build amd64 and arm64 .deb artifacts. The
packages require system Python 3.10+, Flask 2.0+, and Waitress 2.0+. iptables
and nftables are optional tools for direct-management mode and are not installed
automatically, so package installation cannot start a second firewall or
persistence service as a side effect.
systemd is recommended for the optional service; it is not required to install
or run the UI. No firewall manager is suggested or installed: Firewall Web
uses the manager already present on the server and never activates firewalld
or another competing manager during installation. CI installs packages in
current Ubuntu and Debian userspaces
with dependencies resolved from their unmodified default APT repositories.
These artifacts are not yet published in the official distro repositories:
`apt install firewall-web` requires Debian/Ubuntu archive acceptance and ongoing
maintenance. A Debian source package is prepared and built by CI; passing those
checks does not imply official archive acceptance or direct APT availability.
Build it locally with `packaging/build-source-deb.sh [VERSION]` after installing
`build-essential` and `debhelper`; outputs go to `dist/source/`.
Install the matching artifact with:
  sudo apt install ./firewall-web_VERSION_ARCH.deb
On a first install, Debian's debconf questions request the listen address, port,
PIN, backend selection, and whether to start the service. Defaults are
localhost-only and port 5005. Leave the PIN blank to generate a random PIN;
the generated credential is kept root-only in
`/var/lib/firewall-web/initial-pin`, not printed in logs. Retrieve it with
`sudo cat /var/lib/firewall-web/initial-pin` and remove that file securely
after recording it. The service runs as root. On a normal running systemd
host, configuration is validated before the package enables/starts the
service, then active state and authenticated HTTP readiness are verified.
The package does not open ports or change firewall settings.

The administrator-owned configuration is
`/etc/firewall-web/firewall-web.env` (root-owned, mode 0600). Edit it with
`sudoedit /etc/firewall-web/firewall-web.env`; apply changes with
`sudo systemctl restart firewall-web.service`. Reconfigure interactively with
`sudo dpkg-reconfigure firewall-web`; it reads current effective host/port/
backend values, never displays the existing PIN, and a blank PIN answer
generates a new one. Upgrades preserve the file, PIN, and deliberately stopped,
disabled, or masked service state.

For unattended installation, first create a root-only debconf preseed file;
put the PIN in that file rather than in command arguments or logs:
  sudo install -m 600 /dev/null /root/firewall-web.preseed
  sudoedit /root/firewall-web.preseed
Use entries such as; omit the password record to generate a PIN:
  firewall-web firewall-web/host string 127.0.0.1
  firewall-web firewall-web/port string 5005
  firewall-web firewall-web/backend select auto
  firewall-web firewall-web/start-service boolean true
For an explicitly provisioned PIN, add a `password` record in this root-only
file. Install with:
  sudo debconf-set-selections /root/firewall-web.preseed
  sudo env DEBIAN_FRONTEND=noninteractive apt-get install ./firewall-web_VERSION_ARCH.deb
Remove the preseed file after installation. To explicitly provision a PIN,
enter its four digits in the `password` preseed record, ensure the file is
root-only, and securely remove it after installation. The debconf password
answer is cleared after the configuration is persisted. On a host without
running systemd, with a masked service, under `policy-rc.d`, or when startup
is declined, installation reports the actual deferred state and next command.
Without systemd, configure the same file and run `sudo firewall-web` in the
foreground.

Useful diagnostics:
  sudo systemctl status firewall-web.service
  sudo journalctl -u firewall-web.service -n 100 --no-pager
  sudo firewall-web --detect
If startup unexpectedly fails, correct the reported configuration problem
before retrying with `sudo dpkg --configure -a`.
Package builds can also be run locally with:
  packaging/build-deb.sh VERSION [amd64|arm64]
Omit the architecture to use the host architecture. The resulting package is
written to the repository's dist/ directory.

ALPINE PACKAGE ARTIFACTS
On Alpine Linux, build a package for the host architecture with:
  packaging/build-apk.sh VERSION [x86_64|aarch64]
The resulting .apk is written to dist/. Install it as root with:
  apk add --allow-untrusted ./firewall-web_VERSION_ARCH.apk
Set your own PIN in /etc/conf.d/firewall-web, then enable and start its OpenRC
service with:
  rc-update add firewall-web default
  rc-service firewall-web start
The package installs the service disabled. In a proot environment without a
running init system, configure the file and run `firewall-web` in the foreground.

USERSPACE, PROOT, AND UML
The UI can run in Debian, Ubuntu, and Alpine userspace environments, including
Termux PRoot. PRoot's simulated root is not kernel root: it cannot add/delete
iptables or nftables rules on Android or the host. PRoot is always read-only;
unprivileged containers without CAP_NET_ADMIN are read-only too. Write controls
are disabled and all write API requests are rejected. A UML
Linux guest can manage its own guest firewall only when its guest kernel grants
CAP_NET_ADMIN; it does not thereby control the physical host firewall. These
restrictions are enforced by PRoot detection and the running kernel capability,
not by a distro label.

DETECTION AND MANAGER SELECTION
Detection runs at application startup and is available as Refresh detection in
the authenticated UI. The read-only CLI report is:
  firewall-web --detect
  firewall-web --detect-json
Select a backend for one CLI invocation with:
  firewall-web --backend auto|ufw|firewalld|nftables|iptables|inspection --detect
Set NFT_BACKEND in the service environment to keep a selection across restarts
and upgrades. auto selects active UFW or firewalld before considering direct
rulesets. Unknown state, competing populated direct backends, and an empty host
default to inspection-only. Two simultaneously active native managers also
default to inspection-only; an administrator may deliberately select one with
the exact acknowledgement returned as `conflict_acknowledgement` by
`firewall-web --detect-json`. For example:
  sudo firewall-web --backend ufw --acknowledge-conflict active-managers:firewalld,ufw --detect
For installation, pass the same value to `install.sh --acknowledge-conflict`.
Set `NFT_BACKEND_ACK` to that exact value in the service environment to persist
the deliberate choice. Acknowledgement only selects one active manager for
manager-owned operations; it never disables, flushes, migrates, or enables
another manager or its persistence. Other incompatible overrides fail closed.
When no firewall is active, choose and configure UFW, firewalld, native
nftables, or iptables yourself using the platform's supported administration
tools, then refresh discovery. Firewall Web never activates filtering or
changes default policies as an installation side effect.

UFW mode supports host and route allow/deny/reject/limit rules, route interface
bindings, source/destination networks and ports, direction, protocol, and
comments where UFW supports them. Route `limit` is unsupported and rejected.
It also supports defaults, stale-checked numbered deletion, and explicit
enable/disable/reload. IPv4/IPv6 behavior and persistence remain UFW-owned.
Deletion and access-risking changes have a 90-second keep-or-auto-rollback
window. The rollback worker can outlive the web process; if manager state
changed concurrently, it skips the inverse and records a conflict rather than
overwriting the new state.

firewalld mode supports services, ports, source/interface zone bindings,
supported policies, and rich rules. Choose an existing zone or policy
explicitly; no zone is assumed. Runtime and permanent changes are separate.
Permanent operations update only the selected object, and an explicit reload
applies saved permanent configuration. Unsupported controls are disabled and
rejected by the API according to detected firewalld capabilities. A reload is
not selectively rolled back because it replaces runtime manager state; review
the effect and retain console access before applying it. Direct nftables/
iptables editors and persistence controls are disabled when UFW or firewalld
owns the selected backend.

Unattended standalone installation uses `--non-interactive` and safe default
host/port values; it generates a PIN if neither `NFT_SECRET` nor a root-only
`--pin-file` is provided. Backend selection can be supplied with `--backend`;
ambiguous unattended auto-selection is saved as inspection-only. Do not pass
PINs in process arguments or CI output. Generated PINs are retrieved from
`/var/lib/firewall-web/initial-pin`.
`--dry-run` prints the read-only discovery report without changing packages,
configuration, services, or firewall state (the selected Python interpreter
must already be able to import Flask). Add `--json` for stable JSON output.
`--upgrade` preserves the existing PIN and backend policy; `--uninstall`
preserves configuration/backups and refuses to orphan an enabled native nft
restore unit.
Example:
  sudo NFT_SECRET=1234 bash install.sh --backend auto --non-interactive
  sudo bash install.sh --dry-run --backend auto --json

Manager ownership and the counter/handle-independent fingerprint are polled
and re-detected before every mutation. Changes from external UFW/firewalld,
nftables/iptables commands, manager restarts, and persistence-service changes
pause writes until the administrator reviews the current state. Rule-specific
tokens reject stale selections. Mutations are serialized within this process;
external CLI writers cannot be locked out, and a residual race exists between
the final revalidation and the manager command.

Access-risking UFW changes and firewalld rule changes use a bounded, durable
90-second keep-or-rollback flow. The rollback only executes its targeted
inverse if the manager still matches the expected post-operation state. If
another change occurs, it records a conflict and leaves the current manager
configuration untouched. Keep console access for all firewall changes.
Ordinary application removal never flushes firewall state or disables another
service. UFW/firewalld rules remain under those managers. Direct nftables
restore service state must be explicitly migrated or removed before uninstall,
so removing the code cannot silently break boot persistence.

PRIVILEGED MANAGER INTEGRATION TESTS
Run `packaging/test-firewall-manager-integration.sh` on a machine with Docker.
It installs UFW and firewalld in separate containers using bridge networking
and `CAP_NET_ADMIN`; it never uses host networking or changes the host firewall.
The test exercises native status, route/binding/rich/policy operations,
runtime/permanent separation, reload, external drift, rule rollback after the
web process exits, rollback conflict preservation, unrelated rules, and a
selective native nft restore that leaves an unrelated table intact.
Docker does not boot a separate systemd VM, so these checks do not prove actual
service enablement or reboot survival. The following manual check must be run
inside a disposable systemd VM with a console and snapshot, never on a
development or production host. Use a separate VM snapshot for UFW and
firewalld, install only the manager being tested, and take a snapshot before
making changes.

For UFW, add an unrelated sentinel before installing Firewall Web:

    sudo ufw allow 42444/tcp comment 'firewall-web-test-sentinel'
    sudo ufw --force enable

For firewalld, add the sentinel permanently:

    sudo firewall-cmd --permanent --zone=public --add-port=42444/tcp
    sudo firewall-cmd --reload

Copy the package for the VM architecture into the VM, install it with
`sudo apt install ./firewall-web_1.0.4_ARCH.deb`, and answer the interactive
setup prompts. With the default settings, verify initial startup and the
unrelated rule:

    sudo systemctl is-enabled firewall-web.service
    sudo systemctl is-active firewall-web.service
    curl --fail http://127.0.0.1:5005/ >/dev/null
    sudo ufw status numbered

For a firewalld VM, use `sudo firewall-cmd --state` and
`sudo firewall-cmd --zone=public --query-port=42444/tcp` instead of the UFW
status command. Use the Firewall Manager UI to make a test change, then run
the manager's supported reload (`sudo ufw reload` or `sudo firewall-cmd
--reload`) and verify both the test change and sentinel. Reboot the VM with
`sudo systemctl reboot`. After it returns, repeat the service-active,
service-enabled, HTTP-readiness, manager-status, and sentinel checks; for
firewalld also verify the permanent sentinel with
`sudo firewall-cmd --permanent --zone=public --query-port=42444/tcp`.
Restore the VM snapshot when finished. Do not treat the Docker integration
suite, a service restart, or a manager reload as evidence of reboot survival.
Run `packaging/test-installer-lifecycle.sh` for an isolated standalone install,
dry-run immutability, upgrade-preservation, and uninstall-guard check. Run
`packaging/test-deb-lifecycle.sh` to verify Debian package upgrades, preserved
configuration/data, and the native-restore uninstall guard. These scripts
require Docker and network access to their package repositories.

ACCESS
For firewall changes, run the utility as root with CAP_NET_ADMIN. The UI can run
read-only without it. Default: http://127.0.0.1:5005 on the host itself.
From your own computer, open an SSH tunnel (replace USER and SERVER):
  ssh -N -L 5005:127.0.0.1:5005 USER@SERVER
Then open http://127.0.0.1:5005 on your computer and enter your PIN.

CONFIGURATION - /etc/firewall-web/firewall-web.env
NFT_SECRET          REQUIRED: your own exactly four-digit PIN; keep it quoted
                    if editing manually. Do not commit the real env file.
NFT_HOST            Default 127.0.0.1. Use your server's LAN IP if LAN access
                    is needed, or 0.0.0.0 to listen on every IPv4 interface.
NFT_PORT            Default 5005. Choose another unused TCP port if necessary.
NFT_BACKEND         auto (default), ufw, firewalld, nftables, iptables, or
                    inspection. Incompatible explicit overrides fail closed.
NFT_ALLOWED_ORIGINS  Empty for direct access. For a reverse proxy set the exact
                    external origin, e.g. https://firewall.example.com (no path).
                    Multiple origins may be comma-separated.
NFT_BACKUP_DIR      Default in example: /var/lib/firewall-web/backups.
NFT_NATIVE_STATE    Default in example: /var/lib/firewall-web/native-rules.json.
The two state paths use /var/lib/nft-web if omitted when running Python directly.
After changing environment values:
  sudo systemctl restart firewall-web.service
The Python file does NOT automatically load .env files; systemd loads the file.

SERVICE COMMANDS
  sudo systemctl status firewall-web.service --no-pager
  sudo journalctl -u firewall-web.service -n 50 --no-pager
  sudo systemctl restart firewall-web.service
  sudo systemctl disable --now firewall-web.service
Stopping the web service does not remove current firewall rules.

BOOT PERSISTENCE (OPTIONAL)
Live edits are not automatically persistent in direct mode. For iptables
persistence install:
  sudo apt-get install iptables-persistent netfilter-persistent
Review installation prompts about saving existing rules, then use the UI's
Persist IPv4 + IPv6 button. It saves system-default backends, not all alternate
legacy/nft variants. Native nft persistence has a separate UI button and creates
nft-web-restore.service; it excludes iptables-owned tables. Keep the application,
venv and saved state at their installed paths for native restoration.
UFW and firewalld use their own persistence; direct persistence controls are
disabled while either manager is active.
Exports and backups alone do not configure automatic restoration at boot.

IMPORTANT
To change firewall rules, run as root with CAP_NET_ADMIN. Rule edits and DROP
policies can cut off SSH/network access. Export a backup and retain console access before edits.
Docker, libvirt and other tools can maintain their own rules. A four-digit PIN
has only 10,000 combinations: use localhost/SSH tunneling, or place the UI behind
HTTPS plus additional access controls. Do not expose it publicly with PIN alone.
Never publish actual environment files, backups, exports, logs, or credentials.
This archive contains examples only, with no personal server addresses or keys.
The application code is MIT-licensed; see the included LICENSE file.
Bundled fonts retain their separate upstream licenses in the installed
font-licenses directory.

TROUBLESHOOTING
401: entered PIN differs from NFT_SECRET in the running service.
503 mentioning PIN: configure exactly four digits and restart the service.
Address in use: change NFT_PORT or stop the other listener.
Missing backend in direct mode: install nftables/iptables explicitly. Writes
need root/CAP_NET_ADMIN. Unknown or conflicting detection remains inspection-only.
Cross-origin error: set NFT_ALLOWED_ORIGINS to the exact external HTTPS origin.
Installer completed but URL inaccessible: default listener is localhost; tunnel
as above rather than opening public ports.
