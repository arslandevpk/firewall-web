FIREWALL WEB - STANDALONE EDITION

A small web console for the Linux firewall on the machine where it runs.
View nftables and IPv4/IPv6 iptables rules, add/delete rules, create chains,
set policies, allow service ports (including stateless mode), manage
masquerading, export/back up rules, and explicitly save rules for reboot.
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
The installer installs iptables/nftables but does not flush rules or explicitly enable boot restore.
Review package-manager changes when installing on an already managed host.

FIRST INSTALL
Unzip the archive and enter its firewall-web-standalone directory, then run:
  sudo bash install.sh
Enter your OWN four-digit PIN. Leading zeros are supported. No PIN is shipped.
The installer refuses to overwrite an existing installation. It creates a venv,
installs dependencies, writes a root-only environment file, and enables the
firewall-web.service service, which runs the utility as root. No application
firewall changes occur at startup.

DEBIAN PACKAGE ARTIFACTS
Run the "Build Debian and Alpine packages" workflow from the GitHub Actions
tab and enter a package version to build amd64 and arm64 .deb artifacts. The packages require
system Python 3.10+, Flask 2.0+, Waitress 2.0+, iptables, and nftables.
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
Live edits are not automatically persistent. For iptables persistence install:
  sudo apt-get install iptables-persistent netfilter-persistent
Review installation prompts about saving existing rules, then use the UI's
Persist IPv4 + IPv6 button. It saves system-default backends, not all alternate
legacy/nft variants. Native nft persistence has a separate UI button and creates
nft-web-restore.service; it excludes iptables-owned tables. Keep the application,
venv and saved state at their installed paths for native restoration.
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
Missing backend: install nftables/iptables. Writes need root/CAP_NET_ADMIN.
Cross-origin error: set NFT_ALLOWED_ORIGINS to the exact external HTTPS origin.
Installer completed but URL inaccessible: default listener is localhost; tunnel
as above rather than opening public ports.
