# 1.0.5 verification record

This is the current development/artifact candidate, not a published release.

The November 7–8 verification work corrected unsupported-manager ownership,
competing boot restoration, UFW routed-port syntax, confirmation-window timing,
and slow systemd enable/daemon-reload handling. Regression coverage accompanies
these fixes in the source tree.

The original privileged matrix covered nftables, iptables-nft, iptables-legacy,
UFW and firewalld on amd64 and ARM64, with actual reboots. Final affected-code
reruns also passed on separate native amd64 and ARM64 disposable instances:
UFW coexistence with real Docker workloads, a working libvirt guest and a local
Headscale-controlled direct Tailscale tunnel; then native nftables persistence
with a second real reboot. Tests checked effective IPv4/IPv6 traffic, NAT,
unrelated rules, restore-service conflicts, and configuration preservation.
Detailed historical evidence remains in the private verification archive.

Subsequent appearance changes removed arbitrary background/text color pickers,
preserved existing profiles and added Soft Sky, Light Lavender and Pale Rose.
All three were checked on desktop/mobile, including contrast checks.

The read-only Port Checker is first in the menu. Exact numeric port matching,
TCP/UDP status, rule locations, duplicates and listening-process information
are covered by 80 passing regression tests, seven isolated live-kernel scenarios
with IPv4/IPv6 traffic, eight browser navigation checks and actual-API desktop/
mobile checks. Both final Debian architectures were installed on their native
test targets; configuration and stateless firewall rules remained unchanged.
Installed application SHA256:
`964ee9f224c649624f1f2d94b5e12fd7568924eb8869fcf4f1736a630a739055`.

Port Checker live cases include nftables, iptables-nft UFW-shaped chains,
iptables-legacy and firewalld-shaped zone chains. These are additional isolated
kernel checks, not a repeat of the full manager lifecycle/reboot matrix.
Existing firewall-writing Python functions were unchanged by the checker/UI
additions; no additional full reboot matrix is claimed for those additions.

Scope limits: live coexistence was tested with UFW and the local direct tunnel;
other-backend live coexistence, public Tailscale control/WAN/DERP and arbitrary
network configurations are not certified. Port Checker reads this server's
firewall and socket bindings; it cannot certify external cloud/router reachability
and reports uncertainty for unsupported or conditional rule paths.

The Debian review artifact workflow builds both architectures from the exact
commit and includes package checksums and source identity. It creates no GitHub
release or tag. The earlier November 7 delivery deadline was missed.

## Installing the downloaded Debian artifact

Extract the artifact ZIP, then run in that directory:

```sh
sudo bash ./install-deb.sh ./firewall-web_1.0.5_amd64.deb
# On ARM64 use firewall-web_1.0.5_arm64.deb instead.
```

The wrapper refreshes package lists and enables Ubuntu Universe, where the
Python dependencies are supplied. On Debian it enables main in existing official sources if missing. Source files are backed up; repository URLs, suites and signing keys are retained.
APT resolves dependencies before a .deb maintainer script can execute, so the
.deb cannot repair missing repositories itself. Direct apt installation still
works when the required repository components and package lists are present.
The wrapper does not disable dependency checks, modify system Python through
pip, add third-party repositories, or mix distribution releases. Repository
errors and unresolved holds/pins stop installation with a diagnostic.
