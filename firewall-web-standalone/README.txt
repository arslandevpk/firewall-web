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
Enter your OWN four-digit PIN. Leading zeros are supported. No PIN is shipped.
The installer refuses to overwrite an existing installation. It creates a venv,
installs application dependencies, runs read-only manager detection, writes a
root-only environment file, and enables the firewall-web.service service, which
runs the utility as root. No firewall rules or policies are changed at startup.

DEBIAN PACKAGE ARTIFACTS
Run the "Build Debian and Alpine packages" workflow from the GitHub Actions
tab and enter a package version to build amd64 and arm64 .deb artifacts. The
packages require system Python 3.10+, Flask 2.0+, and Waitress 2.0+. iptables
and nftables are suggested for direct-management mode and are not installed
automatically, so package installation cannot start a second firewall or
persistence service as a side effect.
systemd is recommended for the optional service; it is not required to install
or run the UI. CI installs each package in current Ubuntu and Debian userspaces
with dependencies resolved from their unmodified default APT repositories.
These artifacts are not yet published in the official distro repositories:
`apt install firewall-web` requires Debian/Ubuntu archive acceptance and ongoing
maintenance. A Debian source package is prepared and built by CI; passing those
checks does not imply official archive acceptance or direct APT availability.
Build it locally with `packaging/build-source-deb.sh [VERSION]` after installing
`build-essential` and `debhelper`; outputs go to `dist/source/`.
Install the matching artifact with:
  sudo apt install ./firewall-web_VERSION_ARCH.deb
The package installs a disabled service and a root-only configuration file with
no PIN configured; its systemd service runs the utility as root. Before starting
the service, set your own four-digit PIN:
  sudoedit /etc/firewall-web/firewall-web.env
  sudo systemctl enable --now firewall-web.service
Without systemd, configure the same file and run `firewall-web` in the
foreground from the package's root shell.
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
rulesets. Conflicting active managers, unknown state, competing populated
direct backends, and an empty host default to inspection-only. An incompatible
override is rejected rather than silently taking over another manager.

UFW mode supports adding allow/deny/reject/limit port rules with optional
source networks and comments, changing default policies, deleting numbered
rules after stale-state revalidation, and explicitly enabling, disabling, or
reloading UFW. IPv4/IPv6 behavior and boot persistence remain UFW-owned.
firewalld mode supports services and ports in an explicitly selected zone, with
runtime and permanent configuration kept separate, plus an explicit reload.
The current UI does not yet expose firewalld source/interface bindings or rich
rules. Direct nftables/iptables editors and direct persistence controls are
disabled whenever UFW or firewalld owns the active firewall.

Unattended standalone installation uses `--non-interactive` and requires
`NFT_SECRET` in the environment. Backend selection can be supplied with
`--backend`; `--dry-run` prints the machine-readable detection report without
changing packages, configuration, services, or firewall state (system Python
must already be able to import Flask). Add `--json` for stable JSON output.
Example:
  sudo NFT_SECRET=1234 bash install.sh --backend auto --non-interactive
  sudo bash install.sh --dry-run --backend auto --json

Manager state is re-detected before each write. UFW numbered deletions and
firewalld manager changes also use configuration tokens that exclude packet
counters and reject stale browser state. The application cannot lock out other
processes from writing concurrently; an external command can still race the
final validation and manager command. Firewall Web does not yet provide a
durable selective rollback for remote-access changes. Keep console access when
changing policies or enabling/disabling a manager. Explicitly app-created
manager or direct rules are left in place when the web application is removed;
uninstallation does not flush rules or disable other persistence services.

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
