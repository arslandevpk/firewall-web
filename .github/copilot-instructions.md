# Repository instructions

The application lives in `firewall-web-standalone/`; run the commands below from that directory.

## Build, run, and checks

- There is no application build step or configured test/lint runner. No automated test suite is currently present, so there is no single-test command.
- Install Python dependencies for local development with `python3 -m venv .venv && .venv/bin/python -m pip install -r requirements.txt`.
- Check Python syntax with `python3 -m py_compile firewall_web.py`.
- Run locally with `NFT_SECRET='<four-digit-local-PIN>' NFT_HOST=127.0.0.1 .venv/bin/python firewall_web.py`. The app requires root/CAP_NET_ADMIN to operate on the firewall; use a controlled test host for live operations.
- Production installation is `sudo bash install.sh`. It installs the service and dependencies on Debian/Ubuntu; see `README.txt` for configuration, access, and persistence instructions.
- Build a local Debian package from the repository root with `packaging/build-deb.sh VERSION [amd64|arm64]`; it writes to `dist/` and defaults to the host architecture. `.github/workflows/build-deb.yml` builds both artifacts on demand.

## Architecture

- This is a deliberately single-file Flask application: `firewall_web.py` contains backend command handling, JSON API routes, and the complete HTML/CSS/JavaScript UI. `requirements.txt` lists Flask and Waitress; `install.sh` and `firewall-web.service` install and run it as a systemd service.
- The UI authenticates API requests with the `X-Secret` header and uses the API routes in `firewall_web.py` to view and modify live firewall state. Firewall operations support native nftables and multiple iptables backends; iptables-nft and native nftables can overlap, so the UI reports backend views rather than treating them as separate rule totals.
- Live rule changes are separate from boot persistence. Backups are made before changes; iptables persistence uses netfilter-persistent, while native nft persistence saves only non-iptables-owned tables and installs a separate restore unit.
- Runtime configuration is read from environment variables at process start. The Python process does not load `.env` files; the systemd unit loads `/etc/firewall-web/firewall-web.env`.

## Codebase conventions

- Keep firewall command execution centralized through `run()` and `checked()`: use fixed executable lookup, argument arrays (never a shell), bounded timeouts, and `Problem` errors with appropriate HTTP status codes. API inputs are parsed and validated before use.
- Protect mutating operations with the module-level `LOCK`; take a backup before applying changes. For operations spanning multiple backends, validate all selected changes before the first write and handle rollback failures explicitly.
- Rule deletion uses server-generated tokens to detect stale UI selections. Preserve this stale-state check rather than trusting client-supplied rule text or positions.
- The advanced command route is intentionally powerful but still applies command restrictions; do not bypass its input checks or shell-free execution.
- Keep secrets, actual environment files, firewall exports/backups, and host-specific credentials out of version control. The four-digit PIN is required; there is no shipped default.
- Read `README.txt` before changing installation, network access, or boot-persistence behavior; these can affect a root-managed host's firewall and connectivity.
