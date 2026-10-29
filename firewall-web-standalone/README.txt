FIREWALL WEB - STANDALONE EDITION

A small web console for the Linux firewall on the machine where it runs.
View nftables and IPv4/IPv6 iptables rules, add/delete rules, create chains,
set policies, allow service ports (including stateless mode), manage
masquerading, export/back up rules, and explicitly save rules for reboot.
Includes the responsive browser UI. No agent, hub, connected-server feature,
Cloudflare account, external API, or Tailscale installation is required.

REQUIREMENTS
Debian/Ubuntu with systemd, Python 3.10+, root/sudo, and internet for installing
packages. Python dependencies are in requirements.txt. The installer installs
iptables/nftables but does not flush rules or explicitly enable boot restore.
Review package-manager changes when installing on an already managed host.

FIRST INSTALL
Unzip the archive and enter its firewall-web-standalone directory, then run:
  sudo bash install.sh
Enter your OWN four-digit PIN. Leading zeros are supported. No PIN is shipped.
The installer refuses to overwrite an existing installation. It creates a venv,
installs dependencies, writes a root-only environment file, and enables the
firewall-web.service service. No application firewall changes occur at startup.

ACCESS
Default: http://127.0.0.1:5005 on the host itself.
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
This is a root-level administration tool. Rule edits and DROP policies can cut
off SSH/network access. Export a backup and retain console access before edits.
Docker, libvirt and other tools can maintain their own rules. A four-digit PIN
has only 10,000 combinations: use localhost/SSH tunneling, or place the UI behind
HTTPS plus additional access controls. Do not expose it publicly with PIN alone.
Never publish actual environment files, backups, exports, logs, or credentials.
This archive contains examples only, with no personal server addresses or keys.
If making the repository open source, choose and add your preferred LICENSE.

TROUBLESHOOTING
401: entered PIN differs from NFT_SECRET in the running service.
503 mentioning PIN: configure exactly four digits and restart the service.
Address in use: change NFT_PORT or stop the other listener.
Missing backend: install nftables/iptables. Writes need root/CAP_NET_ADMIN.
Cross-origin error: set NFT_ALLOWED_ORIGINS to the exact external HTTPS origin.
Installer completed but URL inaccessible: default listener is localhost; tunnel
as above rather than opening public ports.
