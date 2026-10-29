# Firewall Web Glossary

This glossary explains the terms used in Firewall Web's interface, documentation,
and package instructions. Entries are alphabetized and classified by subject.

## A

**Advanced command** — *UI / Firewall operation.* A restricted interface for
running an explicit firewall command. It is powerful and can interrupt network
access; review the command and keep a backup and console access available.

**API** — *Application interface.* The HTTP endpoints used by the browser UI.
Requests are authenticated with the `X-Secret` header. Mutating requests are
rejected unless the process has the required firewall privileges.

## B

**Backend** — *Firewall implementation.* The firewall command or implementation
being viewed or changed, such as native nftables, iptables-nft, or
iptables-legacy. Backend views can overlap; they are not always separate rule
sets.

**Backup** — *Recovery.* A snapshot saved by the application, including an
automatic snapshot before a firewall change. A backup is not automatically
restored at boot.

**Boot persistence** — *Startup / Recovery.* The separate configuration that
restores selected firewall rules after the machine starts. Live edits and
backups do not enable boot persistence by themselves.

## C

**CAP_NET_ADMIN** — *Linux privilege.* A Linux capability that permits
network-administration operations, including changing firewall rules. Running
as root alone does not guarantee this capability is available.

**Chain** — *Firewall structure.* An ordered list of rules. In nftables a chain
may be attached to a network hook or may be a regular chain; iptables also uses
chains to organize rules and policies.

**Connection tracking** — *Firewall / Networking.* Kernel tracking of network
flows and their state, used by common rules that allow established or related
traffic.

## D

**Default backend** — *Firewall implementation.* The backend selected by the
system's default `iptables` command. It may alias an explicit backend such as
iptables-nft.

**DROP policy** — *Firewall action.* A chain policy that discards packets that
reach the end of the chain without matching an earlier rule. It can disconnect
remote access.

## E

**Export** — *Recovery.* A downloaded snapshot of firewall views for the user's
records. An export is not a boot-restore configuration.

## F

**Family** — *nftables.* The address or packet family for an nftables table,
such as `ip`, `ip6`, or `inet`.

**Filter table** — *Firewall structure.* A table commonly used for packet
filtering. Table names and available types depend on the firewall backend.

## G

**Gateway** — *Networking.* A device or host that forwards traffic between
networks. Firewall Web's masquerade controls can support source NAT on a host
acting as a gateway, but do not enable forwarding on their own.

## H

**Hook** — *nftables.* A point in packet processing, such as `input`,
`forward`, or `postrouting`, where a base chain can be attached.

## I

**Interface** — *Networking.* A network device, such as `eth0`, on which a
firewall or masquerade rule can match or send traffic.

**iptables** — *Firewall backend.* The command-line firewall interface used to
view and manage IPv4 rules; `ip6tables` is its IPv6 counterpart. The commands
may select different implementations on different systems.

**iptables-legacy** — *Firewall backend.* The traditional xtables
implementation. Its rules can be separate from native nftables rules.

**iptables-nft** — *Firewall backend.* The iptables-compatible interface that
stores rules in the kernel's nftables subsystem. Its rules can appear in both
iptables-nft and native nftables views.

**IPv4 / IPv6** — *Networking.* The two Internet Protocol address families.
Firewall Web can show and manage rules for both, where the system has the
corresponding tools installed.

## J

**Jump / target** — *Firewall rule.* An action or destination chain a rule
selects when its match conditions are met, for example accepting, dropping, or
jumping to another chain.

## K

**Kernel** — *Linux system.* The operating-system core that owns the active
firewall rules and enforces capabilities such as `CAP_NET_ADMIN`.

## L

**Live rules** — *Firewall state.* Rules currently loaded in the running
kernel. They are distinct from files or settings that restore rules after boot.

## M

**Masquerade** — *NAT / Networking.* A form of source network address
translation that uses the outgoing interface's address. It does not by itself
enable packet forwarding or permit forwarded traffic.

## N

**Native nftables** — *Firewall backend.* Rules managed directly with nftables,
rather than through the iptables compatibility commands.

**nftables** — *Firewall backend.* Linux's modern packet-filtering framework,
with tables, chains, rules, sets, and expressions.

**NAT (Network Address Translation)** — *Networking.* Rewriting packet
addresses or ports as traffic passes through a system. Masquerading is one
kind of source NAT.

## O

**OpenRC** — *Service manager.* The init and service-management system commonly
used by Alpine Linux. The Alpine package provides an OpenRC service.

## P

**PIN** — *Access control.* The four-digit secret required to authenticate to
the UI. Set your own value; no default PIN is provided.

**Policy** — *Firewall action.* The default action for packets that reach the
end of a built-in chain without matching a rule, usually `ACCEPT` or `DROP`.

**PRoot** — *Userspace environment.* A user-space tool that can simulate root
inside some environments, including Termux. It does not grant kernel
`CAP_NET_ADMIN`; Firewall Web therefore remains read-only in PRoot.

**Priority** — *nftables.* The ordering value used by a base chain at a hook to
determine when it runs relative to other chains.

## Q

**Quick looks** — *UI / Appearance.* Preset color palettes in Display and Feel.
They change the browser's appearance preferences, not firewall configuration.

## R

**Read-only mode** — *Permissions.* The UI state used when firewall mutation is
not permitted. Viewing remains available, while write controls are disabled
and mutation requests are rejected.

**Rule** — *Firewall structure.* A condition and action evaluated for matching
packets. Rules are ordered within a chain.

## S

**Service port** — *UI / Firewall operation.* A helper for allowing an incoming
TCP or UDP port, with options for IP family, interface, and connection
tracking.

**Stateless (NOTRACK)** — *Firewall operation.* A mode that bypasses connection
tracking for matching traffic. It is not compatible with NAT or masquerading
for that traffic.

**systemd** — *Service manager.* The service manager commonly used by Debian
and Ubuntu. Firewall Web's Debian package includes a systemd service.

## T

**Table** — *Firewall structure.* A named container for firewall chains and
related objects. Tables are grouped by family in nftables.

**Termux** — *Android terminal environment.* Termux can run a Linux userspace
such as PRoot, but that does not let the userspace change the Android host's
firewall.

## U

**UML (User-Mode Linux)** — *Virtualization.* A Linux kernel running as a
userspace process. It can manage its own guest firewall only if its guest
kernel provides `CAP_NET_ADMIN`; it does not thereby manage the physical
host's firewall.

## V

**Virtual environment (venv)** — *Python / Installation.* An isolated Python
environment used by the standalone installer to keep the application's
Python dependencies separate from system Python packages.

## W

**Waitress** — *Web server.* The production WSGI server used to serve the
Flask application.

## X

**xtables** — *Firewall implementation.* The family of Linux firewall tools
behind traditional iptables. The iptables-nft compatibility backend uses
nftables, while iptables-legacy uses a separate legacy ruleset.

## Z

**Zone** — *Firewall concept; not a Firewall Web object.* Some firewall
managers group interfaces and rules into named zones. This application manages
the underlying nftables and iptables rules directly and does not create or
manage firewalld zones.

## Classifications

- **Firewall structure / backend / operation** — How rules, chains, tables,
  actions, and implementations work.
- **Networking / NAT** — Addresses, interfaces, forwarding, and translation.
- **Permissions / access control** — Authentication and kernel privileges.
- **Recovery / startup / service manager** — Backups, boot persistence, and
  service startup.
- **UI / Appearance / Installation** — Browser controls and software runtime
  terms.
