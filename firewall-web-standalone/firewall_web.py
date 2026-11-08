#!/usr/bin/env python3
"""firewall_web - single-file mini firewall UI for Linux.

Install in a virtual environment: pip install flask waitress
Install and run as root with CAP_NET_ADMIN to change firewall rules. Without
that kernel capability, the authenticated interface runs in read-only mode.
Set NFT_SECRET to an access key of exactly four digits:
    sudo env NFT_SECRET='YOUR_FOUR_DIGIT_PIN' python3 firewall_web.py
Open http://127.0.0.1:5005 or http://<machine-LAN-IP>:5005 and enter that key.

NFT_HOST defaults to 127.0.0.1 (localhost only);
NFT_PORT defaults to 5005. Set NFT_HOST to a specific LAN/Tailscale address to
restrict the listener, or 127.0.0.1 for localhost-only access through an SSH tunnel.
Use HTTPS on an authenticated reverse proxy if exposing it beyond localhost.
For TLS termination at a reverse proxy, set NFT_ALLOWED_ORIGINS to its exact
public origin, e.g. https://firewall.example.com (comma-separated if needed).
NFT_BACKUP_DIR defaults to /var/lib/nft-web/backups.

Changes affect the LIVE firewall. Click Persist IPv4 + IPv6 to run
netfilter-persistent save, verify both saved files, and enable its boot service.
This needs Debian/Ubuntu packages iptables-persistent and netfilter-persistent
and uses the system-default iptables/ip6tables backends, not every alternative.
Click Persist native nft for other nftables tables; this creates/enables a
separate boot restore unit and excludes tables owned by iptables-nft. Keep this
script and its Python environment at their installed paths for that unit.
Backups/exports alone do not enable boot-time restoration.
Docker, Podman, Tailscale, libvirt and other firewall managers may
maintain their own rules. iptables-nft and nftables share the same kernel rules;
iptables-legacy uses a separate ruleset. Edit iptables-owned rules via iptables.
No firewall command is run merely by importing this module.
"""

import base64
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException


app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 128 * 1024
SECRET = os.environ.get('NFT_SECRET', '')
PORT = int(os.environ.get('NFT_PORT', '5005'))
HOST = os.environ.get('NFT_HOST', '127.0.0.1')
ALLOWED_ORIGINS = {v.strip().rstrip('/') for v in os.environ.get('NFT_ALLOWED_ORIGINS', '').split(',') if v.strip()}
BACKUP_DIR = Path(os.environ.get('NFT_BACKUP_DIR', '/var/lib/nft-web/backups'))
IPT_FILES = (Path('/etc/iptables/rules.v4'), Path('/etc/iptables/rules.v6'))
IPT_PLUGINS = (Path('/usr/share/netfilter-persistent/plugins.d/15-ip4tables'),
               Path('/usr/share/netfilter-persistent/plugins.d/25-ip6tables'))
NATIVE_STATE = Path(os.environ.get('NFT_NATIVE_STATE', '/var/lib/nft-web/native-rules.json'))
NATIVE_UNIT = Path('/etc/systemd/system/nft-web-restore.service')
FONT_DIR = Path(__file__).with_name('fonts')
FONT_ASSETS = {
    'Hack-Regular.ttf': 'font/ttf',
    'JetBrainsMono.woff2': 'font/woff2',
    'FiraCode.woff2': 'font/woff2',
    'SourceCodePro.woff2': 'font/woff2',
    'CascadiaCode.woff2': 'font/woff2',
    'IBMPlexMono.woff2': 'font/woff2',
    'Inconsolata.woff2': 'font/woff2',
}
PATH = '/usr/sbin:/sbin:/usr/bin:/bin'
LOCK = threading.RLock()
DETECTION_LOCK = threading.Lock()
SELECTED_BACKEND_AT_START = None
SELECTED_FINGERPRINT_AT_START = None
SELECTION_REVIEW_REQUIRED = False
FINGERPRINT_REVIEW_REQUIRED = False
ROLLBACK_SECONDS = 90
ROLLBACK_DIR = Path(os.environ.get('NFT_ROLLBACK_DIR', '/var/lib/firewall-web/rollback'))
TABLES = ('filter', 'nat', 'mangle', 'raw', 'security')
BACKENDS = {
    'iptables': 'iptables-save', 'ip6tables': 'ip6tables-save',
    'iptables-nft': 'iptables-nft-save', 'ip6tables-nft': 'ip6tables-nft-save',
    'iptables-legacy': 'iptables-legacy-save',
    'ip6tables-legacy': 'ip6tables-legacy-save',
}
BACKEND_CHOICES = ('auto', 'ufw', 'firewalld', 'nftables', 'iptables', 'inspection')


def has_net_admin():
    try:
        for line in Path('/proc/self/status').read_text().splitlines():
            if line.startswith('CapEff:'):
                return bool(int(line.split()[1], 16) & (1 << 12))
    except (OSError, ValueError, IndexError):
        pass
    return False


def is_proot():
    return any(os.environ.get(name) for name in ('PROOT_TMP_DIR', 'PROOT_LOADER', 'PROOT_BARRIER'))


def can_manage_firewall():
    return os.geteuid() == 0 and has_net_admin() and not is_proot()


def read_only_reason():
    if is_proot():
        return ('PRoot does not grant kernel firewall access. This interface is read-only '
                'and cannot change the Android or host firewall.')
    if os.geteuid() != 0:
        return 'Run as root with CAP_NET_ADMIN to change firewall rules.'
    if has_net_admin():
        return ''
    return ('Kernel CAP_NET_ADMIN is unavailable. Firewall changes are disabled. '
            'Termux PRoot, unprivileged containers, and some userspace guests cannot '
            'manage the host firewall.')


def _probe(name, args=()):
    if not executable(name):
        return {'installed': False, 'available': False}
    try:
        out, error, rc = run(name, args)
    except Problem as exc:
        return {'installed': True, 'available': False, 'error': exc.message}
    result = {'installed': True, 'available': rc == 0, 'returncode': rc}
    if rc == 0:
        result['output'] = out.strip()
    else:
        message = (error or out).strip()
        result['error'] = message or f'{name} exited with status {rc}'
        if 'permission denied' in message.lower() or 'operation not permitted' in message.lower():
            result['available'] = False
            result['permission_denied'] = True
    return result


def _systemd_service(name):
    if not executable('systemctl'):
        return {'available': False}
    active = _probe('systemctl', ['is-active', '--quiet', name])
    enabled = _probe('systemctl', ['is-enabled', '--quiet', name])
    unavailable = any(marker in (active.get('error', '') + enabled.get('error', '')).lower()
                      for marker in ('not been booted with systemd', 'failed to connect to bus',
                                     'system has not been booted'))
    if unavailable:
        return {'available': False, 'active': None, 'enabled': None}
    return {
        'available': True,
        'active': active.get('returncode') == 0 if active.get('available') or active.get('returncode') is not None else None,
        'enabled': enabled.get('returncode') == 0 if enabled.get('available') or enabled.get('returncode') is not None else None,
    }


def _save_rules(name):
    probe = _probe(name, ['-c'])
    if not probe.get('available'):
        return probe
    parsed = parse_save(probe['output'], name.removesuffix('-save'))
    probe['rule_count'] = len(parsed['rules'])
    probe['tables'] = parsed['tables']
    probe['chains'] = parsed['chains']
    probe['canonical'] = canonical_save(probe['output'])
    probe['populated'] = bool(parsed['rules']) or any(
        chain['policy'] not in ('ACCEPT', '-') for chain in parsed['chains'])
    return probe


def _ufw_ipv6_setting():
    try:
        for line in Path('/etc/default/ufw').read_text().splitlines():
            if line.strip().startswith('IPV6='):
                return line.split('=', 1)[1].strip()
    except OSError:
        pass
    return None


OTHER_FIREWALL_SERVICES = {
    'ferm.service': 'ferm',
    'shorewall.service': 'shorewall',
    'shorewall6.service': 'shorewall6',
    'firehol.service': 'firehol',
    'arno-iptables-firewall.service': 'arno-iptables-firewall',
    'csf.service': 'csf',
    'apf.service': 'apf',
}


def other_firewall_managers():
    # One read-only systemd query also discovers oneshot managers such as ferm.
    result = _probe('systemctl', [
        'list-units', '--type=service', '--state=active,activating,reloading',
        '--no-legend', '--plain', '--no-pager', *OTHER_FIREWALL_SERVICES,
    ])
    if result.get('available'):
        active = sorted({line.split()[0] for line in result.get('output', '').splitlines()
                         if line.split() and line.split()[0] in OTHER_FIREWALL_SERVICES})
        return {'active': active, 'unknown': []}
    return {'active': [], 'unknown': sorted(
        unit for unit, binary in OTHER_FIREWALL_SERVICES.items() if executable(binary))}


def detect_firewall():
    """Read-only inventory and conservative selection of the controlling manager."""
    ufw = _probe('ufw', ['status', 'verbose'])
    ufw_rules = _probe('ufw', ['status', 'numbered'])
    ufw_text = ufw.get('output', '')
    ufw_active = (re.search(r'(?im)^Status:\s*active\s*$', ufw_text) is not None
                  if ufw.get('available') else None)
    ufw_info = {
        'installed': ufw.get('installed', False),
        'status': 'not installed' if not ufw.get('installed') else
                  'active' if ufw_active is True else 'inactive' if ufw_active is False else 'unknown',
        'version': _probe('ufw', ['--version']).get('output'),
        'default_policies': next((line.split(':', 1)[1].strip()
                                  for line in ufw_text.splitlines()
                                  if line.lower().startswith('default:')), None),
        'ipv6': _ufw_ipv6_setting(),
        'rule_count': sum(bool(re.match(r'^\s*\[\s*\d+\]', line))
                          for line in ufw_rules.get('output', '').splitlines())
                      if ufw_rules.get('available') else None,
        'permission_denied': ufw.get('permission_denied', False),
    }

    firewalld = _probe('firewall-cmd', ['--state'])
    firewalld_state = (firewalld.get('output') or firewalld.get('error', '')).strip()
    firewalld_service = _systemd_service('firewalld.service')
    if re.search(r'\bnot running\b', firewalld_state, re.IGNORECASE):
        firewalld_active = False
    elif firewalld_state.lower() == 'running' and firewalld.get('available'):
        firewalld_active = True
    else:
        firewalld_active = firewalld_service.get('active')
    zones = _probe('firewall-cmd', ['--get-active-zones']) if firewalld_active else {'available': False}
    zone_details = {}
    if zones.get('available'):
        current_zone = None
        for line in zones['output'].splitlines():
            if line and not line[:1].isspace():
                current_zone = line.strip()
                zone_details[current_zone] = {'interfaces': [], 'sources': []}
            elif current_zone and line.strip():
                kind, _, value = line.strip().partition(':')
                if kind in ('interfaces', 'sources') and value.strip():
                    zone_details[current_zone][kind] = value.split()
    firewalld_inventory = {'zones': {}, 'policies': {}, 'default_zone': None,
                           'capabilities': {}}
    inventory_errors = []
    if firewalld_active:
        help_result = _probe('firewall-cmd', ['--help'])
        help_text = help_result.get('output', '')
        for capability, option in (
                ('zone_bindings', '--add-interface'),
                ('source_bindings', '--add-source'),
                ('rich_rules', '--add-rich-rule'),
                ('policies', '--get-policies')):
            firewalld_inventory['capabilities'][capability] = option in help_text
        zones_result = _probe('firewall-cmd', ['--get-zones'])
        permanent_zones_result = _probe('firewall-cmd', ['--permanent', '--get-zones'])
        if not zones_result.get('available') or not permanent_zones_result.get('available'):
            inventory_errors.append('firewalld zones could not be enumerated')
        zone_names = sorted(set(zones_result.get('output', '').split()) |
                            set(permanent_zones_result.get('output', '').split()))
        zone_blocks = {}
        for scope, args in (('runtime', ['--list-all-zones']),
                            ('permanent', ['--permanent', '--list-all-zones'])):
            result = _probe('firewall-cmd', args)
            try:
                zone_blocks[scope] = (_split_firewalld_zones(result['output'])
                                      if result.get('available') else {})
            except Problem:
                zone_blocks[scope] = {}
            if not result.get('available'):
                inventory_errors.append(f'firewalld {scope} zones could not be read')
        for zone_name in zone_names:
            runtime = zone_blocks['runtime'].get(zone_name)
            permanent = zone_blocks['permanent'].get(zone_name)
            if runtime is None or permanent is None:
                inventory_errors.append(f'firewalld zone {zone_name} could not be read')
            firewalld_inventory['zones'][zone_name] = {
                'runtime': runtime, 'permanent': permanent,
            }
        runtime_policies = _probe('firewall-cmd', ['--get-policies'])
        permanent_policies = _probe('firewall-cmd', ['--permanent', '--get-policies'])
        if runtime_policies.get('available') and permanent_policies.get('available'):
            policy_names = sorted(set(runtime_policies.get('output', '').split()) |
                                  set(permanent_policies.get('output', '').split()))
            for policy_name in policy_names:
                runtime = _probe('firewall-cmd', [f'--policy={policy_name}', '--list-all'])
                permanent = _probe('firewall-cmd', ['--permanent', f'--policy={policy_name}', '--list-all'])
                if not runtime.get('available') or not permanent.get('available'):
                    inventory_errors.append(f'firewalld policy {policy_name} could not be read')
                firewalld_inventory['policies'][policy_name] = {
                    'runtime': runtime.get('output') if runtime.get('available') else None,
                    'permanent': permanent.get('output') if permanent.get('available') else None,
                }
        elif firewalld_inventory['capabilities'].get('policies'):
            inventory_errors.append('firewalld policies could not be enumerated')
        default_zone = _probe('firewall-cmd', ['--get-default-zone'])
        if not default_zone.get('available'):
            inventory_errors.append('firewalld default zone could not be read')
        firewalld_inventory['default_zone'] = default_zone.get('output')
        firewalld_inventory['active_zones'] = zones.get('output') if zones.get('available') else None
        firewalld_inventory['errors'] = inventory_errors
    firewalld_info = {
        'installed': firewalld.get('installed', False),
        'status': 'not installed' if not firewalld.get('installed') else
                  'active' if firewalld_active is True else 'inactive' if firewalld_active is False else 'unknown',
        'version': _probe('firewall-cmd', ['--version']).get('output'),
        'active_zones': zone_details if zones.get('available') else None,
        'inventory': firewalld_inventory if firewalld_active else None,
        'capabilities': firewalld_inventory['capabilities'] if firewalld_active else {},
        'inventory_errors': inventory_errors,
        'permission_denied': firewalld.get('permission_denied', False),
    }

    saves = {}
    for name in ('iptables-save', 'ip6tables-save', 'iptables-nft-save', 'ip6tables-nft-save',
                 'iptables-legacy-save', 'ip6tables-legacy-save'):
        if executable(name):
            saves[name] = _save_rules(name)
    nft = _probe('nft', ['-j', '-a', '-n', 'list', 'ruleset'])
    nft_tables = []
    payload = {}
    if nft.get('available'):
        try:
            payload = json.loads(nft['output'])
            nft_tables = [entry['table'] for entry in payload.get('nftables', []) if 'table' in entry]
        except (ValueError, TypeError, KeyError):
            nft['available'] = False
            nft['error'] = 'nft returned an invalid JSON ruleset'
    compat = set()
    for name in ('iptables-nft-save', 'ip6tables-nft-save'):
        if saves.get(name, {}).get('available'):
            family = 'ip6' if name.startswith('ip6') else 'ip'
            compat.update((family, table) for table in saves[name].get('tables', []))
    firewalld_tables = [table for table in nft_tables if table.get('name') == 'firewalld']
    native_tables = [table for table in nft_tables
                     if (table.get('family'), table.get('name')) not in compat
                     and table.get('name') != 'firewalld']
    native_keys = {(table.get('family'), table.get('name')) for table in native_tables}
    native_rules = [entry['rule'] for entry in payload.get('nftables', [])
                    if nft.get('available') and isinstance(entry, dict) and 'rule' in entry
                    and (entry['rule'].get('family'), entry['rule'].get('table')) in native_keys]
    native_chains = [entry['chain'] for entry in payload.get('nftables', [])
                     if nft.get('available') and isinstance(entry, dict) and 'chain' in entry
                     and (entry['chain'].get('family'), entry['chain'].get('table')) in native_keys]
    native_enforcing_chains = [chain for chain in native_chains
                               if chain.get('hook') and chain.get('policy') not in (None, 'accept')]
    native_populated = bool(native_rules or native_enforcing_chains)

    legacy_populated = any(saves.get(name, {}).get('populated', False) for name in
                           ('iptables-legacy-save', 'ip6tables-legacy-save'))
    default_populated = any(saves.get(name, {}).get('populated', False) for name in
                            ('iptables-save', 'ip6tables-save'))
    nft_compat_populated = any(saves.get(name, {}).get('populated', False) for name in
                               ('iptables-nft-save', 'ip6tables-nft-save'))
    default_versions, default_modes = {}, {}
    alternative_conflict = False
    write_backends = []
    for family, command in (('ip', 'iptables'), ('ip6', 'ip6tables')):
        version = _probe(command, ['--version']).get('output')
        mode = ('nf_tables' if version and 'nf_tables' in version
                else 'legacy' if version else 'unknown')
        default_versions[family] = version
        default_modes[family] = mode
        default_name = command + '-save'
        nft_name, legacy_name = command + '-nft-save', command + '-legacy-save'
        default_rules = saves.get(default_name, {}).get('populated', False)
        nft_rules = saves.get(nft_name, {}).get('populated', False)
        legacy_rules = saves.get(legacy_name, {}).get('populated', False)
        if nft_rules and legacy_rules:
            alternative_conflict = True
        if default_rules and ((mode == 'nf_tables' and legacy_rules)
                              or (mode == 'legacy' and nft_rules)
                              or (mode == 'unknown' and (nft_rules or legacy_rules))):
            alternative_conflict = True
        if (default_rules and mode == 'nf_tables' and nft_rules
                and saves[default_name].get('canonical') != saves[nft_name].get('canonical')):
            alternative_conflict = True
        if (default_rules and mode == 'legacy' and legacy_rules
                and saves[default_name].get('canonical') != saves[legacy_name].get('canonical')):
            alternative_conflict = True
        if default_rules:
            write_backends.append(command)
            alias = nft_name if mode == 'nf_tables' else legacy_name if mode == 'legacy' else None
            if (alias and saves.get(alias, {}).get('available')
                    and saves[default_name].get('canonical') == saves[alias].get('canonical')):
                write_backends.append(command + ('-nft' if mode == 'nf_tables' else '-legacy'))
        elif nft_rules and not legacy_rules:
            write_backends.append(command + '-nft')
        elif legacy_rules and not nft_rules:
            write_backends.append(command + '-legacy')
    modes = set(default_modes.values()) - {'unknown'}
    default_implementation = (next(iter(modes)) if len(modes) == 1
                              else 'mixed' if len(modes) > 1 else 'unknown')
    default_iptables_version = default_versions['ip']
    ufw_owned_chains = sorted({chain['name'] for save in saves.values()
                               for chain in save.get('chains', [])
                               if re.match(r'(?i)^ufw[-_]', chain['name'])})
    possible_manager_ownership = bool(ufw_owned_chains and ufw_active is not True)
    possible_manager_ownership = possible_manager_ownership or bool(
        firewalld_tables and firewalld_active is not True)
    netfilter_service = _systemd_service('netfilter-persistent.service')
    netfilter_service['installed'] = bool(executable('netfilter-persistent')
                                          or any(path.exists() for path in IPT_PLUGINS))
    persistence = {
        'netfilter_persistent': netfilter_service,
        'iptables_persistent': {
            'installed': any(Path(path).exists() for path in ('/etc/iptables/rules.v4', '/etc/iptables/rules.v6'))
                          or any(path.exists() for path in IPT_PLUGINS),
            'files': [path for path in ('/etc/iptables/rules.v4', '/etc/iptables/rules.v6') if Path(path).exists()],
        },
        'nftables': _systemd_service('nftables.service'),
        'native_restore': _systemd_service('nft-web-restore.service'),
    }
    listeners = _probe('ss', ['-lnt'])
    forwarded = {}
    for family, path in (('ipv4', '/proc/sys/net/ipv4/ip_forward'),
                         ('ipv6', '/proc/sys/net/ipv6/conf/all/forwarding')):
        try:
            forwarded[family] = Path(path).read_text().strip() == '1'
        except OSError:
            forwarded[family] = None

    other_managers = other_firewall_managers()
    other_ownership = other_managers['active'] or other_managers['unknown']
    active_managers = [name for name, active in (('ufw', ufw_active), ('firewalld', firewalld_active)) if active]
    persistence_conflicts = [
        service for key, service in (
            ('nftables', 'nftables.service'),
            ('netfilter_persistent', 'netfilter-persistent.service'),
            ('native_restore', 'nft-web-restore.service'))
        if active_managers and (persistence[key].get('enabled') or persistence[key].get('active'))
    ]
    required_conflict_ack = (
        'active-managers:' + ','.join(sorted(active_managers))
        if len(active_managers) > 1 else None)
    uncertain = ufw_active is None and ufw_info['installed']
    uncertain = uncertain or (ufw_active is True and not ufw_rules.get('available'))
    uncertain = uncertain or (firewalld_active is None and firewalld_info['installed'])
    uncertain = uncertain or (firewalld_active is True and bool(inventory_errors))
    uncertain = uncertain or (bool(executable('nft')) and not nft.get('available'))
    uncertain = uncertain or any(info.get('installed') and not info.get('available')
                                 for info in saves.values())
    uncertain = uncertain or possible_manager_ownership
    direct = []
    if native_populated:
        direct.append('nftables')
    if default_populated or legacy_populated or nft_compat_populated:
        direct.append('iptables')
    if other_ownership:
        selected = 'inspection'
        reason = ('Unsupported firewall manager ownership is active or cannot be established: '
                  + ', '.join(other_ownership) + '; writes are disabled. Use the owning manager.')
    elif persistence_conflicts:
        selected = 'inspection'
        reason = ('An active firewall manager conflicts with direct boot restore services: '
                  + ', '.join(persistence_conflicts) + '; writes are disabled until ownership is resolved.')
    elif len(active_managers) > 1:
        reason = 'Multiple firewall managers report active; writes are disabled until an administrator resolves ownership.'
        selected = 'inspection'
    elif uncertain:
        reason = ('Manager-owned rules were found but the owning manager is inactive or unknown; writes are disabled.'
                  if possible_manager_ownership else
                  'Firewall state is unknown because a required inspection command failed or permission was denied; writes are disabled.')
        selected = 'inspection'
    elif active_managers:
        selected = active_managers[0]
        reason = f'{selected} is active; direct ruleset editors must not bypass it.'
    elif alternative_conflict:
        reason = 'Both iptables-nft and iptables-legacy contain rules; their ownership is ambiguous.'
        selected = 'inspection'
    elif len(direct) > 1:
        reason = 'Independently populated direct firewall backends were detected; ownership is ambiguous.'
        selected = 'inspection'
    elif direct:
        selected = direct[0]
        reason = f'Direct {selected} rules were detected; only this selected backend is eligible for writes.'
    else:
        selected = 'inspection'
        reason = 'No active firewall manager or populated direct ruleset was detected; no firewall will be enabled automatically.'

    requested = os.environ.get('NFT_BACKEND', 'auto').strip().lower()
    if requested not in BACKEND_CHOICES:
        reason = f'Invalid NFT_BACKEND={requested!r}; inspection-only mode is active.'
        selected = 'inspection'
    elif requested != 'auto':
        if (other_ownership or persistence_conflicts) and requested != 'inspection':
            pass  # Explicit backend selection cannot bypass another firewall manager.
        elif requested == selected:
            pass
        elif requested == 'inspection':
            selected = 'inspection'
            reason = 'Inspection-only mode was explicitly selected.'
        elif (len(active_managers) > 1 and not uncertain and requested in active_managers
              and os.environ.get('NFT_BACKEND_ACK', '') == required_conflict_ack):
            selected = requested
            reason = (f'{requested} was explicitly selected after acknowledging the active-manager conflict '
                      f'({required_conflict_ack}). Only {requested}-owned operations are enabled.')
        elif (requested in ('nftables', 'iptables') and requested in direct
              and not active_managers and not uncertain and not alternative_conflict):
            selected = requested
            reason = f'{requested} was explicitly selected; other populated backends remain separately scoped and are not changed by this selection.'
        else:
            reason = f'NFT_BACKEND={requested} conflicts with detected ownership ({selected}); inspection-only mode is active.'
            selected = 'inspection'
    report = {
        'managers': {'ufw': ufw_info, 'firewalld': firewalld_info},
        'direct': {
            'nftables': {'installed': bool(executable('nft')), 'tables': native_tables,
                         'underlying_packet_filter': 'nf_tables' if nft_tables else 'unknown',
                         'version': _probe('nft', ['--version']).get('output'),
                         'status': 'populated' if native_populated else 'empty' if nft.get('available') else 'unknown'},
            'iptables': {'installed': bool(saves), 'alternatives': {
                             name: {key: value for key, value in info.items()
                                    if key not in ('output', 'canonical')}
                             for name, info in saves.items()},
                         'default_implementation': default_implementation,
                         'default_version': default_iptables_version,
                         'default_versions': default_versions,
                         'status': 'populated' if default_populated or legacy_populated or nft_compat_populated else 'empty' if saves else 'unknown'},
        },
        'persistence': persistence,
        'interfaces': [name for _, name in socket.if_nameindex()],
        'listeners': listeners.get('output') if listeners.get('available') else listeners.get('error'),
        'forwarding': forwarded,
        'service_owners': [
            {'service': label, 'chains': sorted({chain['name'] for save in saves.values()
                                                 for chain in save.get('chains', [])
                                                 if re.search(pattern, chain['name'])} |
                                                {chain['name'] for chain in native_chains
                                                 if re.search(pattern, chain.get('name', ''))})}
            for label, pattern in (('UFW', r'(?i)^ufw[-_]'), ('Docker', r'(?i)DOCKER'), ('Podman', r'(?i)CNI|NETAVARK'),
                                   ('libvirt', r'(?i)LIBVIRT'), ('Tailscale', r'(?i)TS-'))
            if any(re.search(pattern, chain['name'])
                   for save in saves.values() for chain in save.get('chains', []))
            or any(re.search(pattern, chain.get('name', '')) for chain in native_chains)
        ] + ([{'service': 'firewalld', 'chains': []}] if firewalld_tables else []),
        'ownership_concerns': {'ufw_chains': ufw_owned_chains,
                               'firewalld_tables': firewalld_tables if firewalld_active is not True else []},
        'active_managers': active_managers,
        'other_firewall_managers': other_managers,
        'persistence_conflicts': persistence_conflicts,
        'conflict_acknowledgement': required_conflict_ack,
        'selected_backend': selected,
        'write_backends': write_backends if selected == 'iptables' else [],
        'reason': reason,
        'can_write': can_manage_firewall() and selected in ('nftables', 'iptables'),
        'manager_can_write': can_manage_firewall() and selected in ('ufw', 'firewalld'),
    }
    nft_configuration = {
        'tables': [configuration_only(table) for table in native_tables],
        'chains': [configuration_only(chain) for chain in native_chains],
        'rules': [configuration_only(rule) for rule in native_rules],
    }
    iptables_configuration = {
        name: info.get('canonical') for name, info in sorted(saves.items())
        if info.get('available') and info.get('canonical')
    }
    if selected == 'ufw':
        selected_configuration = {
            'verbose': ufw_text,
            'numbered': ufw_rules.get('output') if ufw_rules.get('available') else None,
            'ipv6': ufw_info['ipv6'],
            'persistence': persistence,
        }
    elif selected == 'firewalld':
        selected_configuration = {'firewalld': firewalld_inventory,
                                  'persistence': persistence}
    elif selected == 'nftables':
        selected_configuration = {'nftables': nft_configuration,
                                  'persistence': persistence}
    elif selected == 'iptables':
        selected_configuration = {
            'backends': {name: iptables_configuration.get(name)
                         for name in sorted(set(write_backends))},
            'default_modes': default_modes,
            'persistence': persistence,
        }
    else:
        selected_configuration = {
            'selection': selected,
            'managers': {
                'ufw': ufw_info['status'], 'firewalld': firewalld_info['status'],
            },
            'nftables': nft.get('error') or nft_configuration,
            'iptables': iptables_configuration,
            'persistence': persistence,
        }
    selected_configuration['other_firewall_managers'] = other_managers
    selected_configuration['observed_ownership'] = {
        'ufw': {
            'status': ufw_info['status'],
            'version': ufw_info['version'],
            'verbose': ufw_text if ufw.get('available') else ufw.get('error'),
            'numbered': ufw_rules.get('output') if ufw_rules.get('available') else ufw_rules.get('error'),
            'ipv6': ufw_info['ipv6'],
        },
        'firewalld': {
            'status': firewalld_info['status'],
            'version': firewalld_info['version'],
            'inventory': firewalld_inventory if firewalld_active else None,
        },
        'nftables': nft.get('error') or nft_configuration,
        'iptables': iptables_configuration,
        'default_modes': default_modes,
        'persistence': persistence,
    }
    report['selected_fingerprint'] = signature(configuration_only(selected_configuration))
    return report


def current_detection():
    global SELECTED_BACKEND_AT_START, SELECTED_FINGERPRINT_AT_START
    global SELECTION_REVIEW_REQUIRED, FINGERPRINT_REVIEW_REQUIRED
    report = detect_firewall()
    with DETECTION_LOCK:
        selected = report['selected_backend']
        if SELECTED_BACKEND_AT_START is None:
            SELECTED_BACKEND_AT_START = selected
            SELECTED_FINGERPRINT_AT_START = report['selected_fingerprint']
        elif selected != SELECTED_BACKEND_AT_START:
            SELECTION_REVIEW_REQUIRED = True
        elif report['selected_fingerprint'] != SELECTED_FINGERPRINT_AT_START:
            FINGERPRINT_REVIEW_REQUIRED = True
        report['previous_backend'] = SELECTED_BACKEND_AT_START if SELECTION_REVIEW_REQUIRED else None
        report['previous_fingerprint'] = (
            SELECTED_FINGERPRINT_AT_START if FINGERPRINT_REVIEW_REQUIRED else None)
        report['selection_review_required'] = (
            SELECTION_REVIEW_REQUIRED or FINGERPRINT_REVIEW_REQUIRED)
        report['fingerprint_review_required'] = FINGERPRINT_REVIEW_REQUIRED
        if FINGERPRINT_REVIEW_REQUIRED and not SELECTION_REVIEW_REQUIRED:
            report['reason'] = ('Firewall configuration changed outside this application; '
                                'review the current rules before writing.')
    return report


def accept_current_detection():
    global SELECTED_BACKEND_AT_START, SELECTED_FINGERPRINT_AT_START
    global SELECTION_REVIEW_REQUIRED, FINGERPRINT_REVIEW_REQUIRED
    report = detect_firewall()
    if report['selected_backend'] == 'inspection':
        raise Problem(report['reason'], 409)
    with DETECTION_LOCK:
        SELECTED_BACKEND_AT_START = report['selected_backend']
        SELECTED_FINGERPRINT_AT_START = report['selected_fingerprint']
        SELECTION_REVIEW_REQUIRED = False
        FINGERPRINT_REVIEW_REQUIRED = False
    if report['selected_backend'] == 'ufw':
        _, _, report['manager_state_token'] = _ufw_state()
    elif report['selected_backend'] == 'firewalld':
        report['manager_state_token'] = signature(_firewalld_state())
    report['previous_backend'] = None
    report['selection_review_required'] = False
    return report


class Problem(Exception):
    def __init__(self, message, status=400):
        self.message, self.status = message, status


def executable(name):
    return shutil.which(name, path=PATH)


def run(name, args=(), stdin=None):
    """Fixed executable lookup, argv only, bounded runtime, no shell."""
    binary = executable(name)
    if not binary:
        raise Problem(f'{name} is not installed.', 503)
    try:
        p = subprocess.run(
            [binary, *args], input=stdin, capture_output=True, text=True,
            timeout=(180 if name == 'systemctl' and args and args[0] in ('enable', 'daemon-reload') else 12),
            env={'PATH': PATH, 'LC_ALL': 'C'}, check=False,
        )
    except subprocess.TimeoutExpired:
        raise Problem(f'{name} timed out. Refresh before retrying: a change may have completed.', 504)
    except OSError as exc:
        raise Problem(f'Could not execute {name}: {exc}', 503)
    return p.stdout, p.stderr, p.returncode


def checked(name, args=(), stdin=None):
    out, error, rc = run(name, args, stdin)
    if rc:
        raise Problem(error.strip() or out.strip() or f'{name} exited with status {rc}', 422)
    return out


def data():
    d = request.get_json(silent=True)
    if not isinstance(d, dict):
        raise Problem('A JSON object is required.')
    return d


def text(d, key, default='', maximum=8192):
    value = d.get(key, default)
    if not isinstance(value, str) or len(value) > maximum or '\x00' in value:
        raise Problem(f'Invalid {key}.')
    return value.strip()


def identifier(value):
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}', value):
        raise Problem('Use a table/chain name beginning with a letter or underscore, followed by letters, digits, _, . or -.')
    return value


def integer(value, minimum=1, maximum=2**63-1):
    if isinstance(value, bool) or not re.fullmatch(r'-?\d+', str(value)):
        raise Problem('Invalid integer.')
    value = int(value)
    if not minimum <= value <= maximum:
        raise Problem(f'Integer must be between {minimum} and {maximum}.')
    return value


def family(d):
    f = text(d, 'family', 'inet')
    if f not in ('ip', 'ip6', 'inet', 'arp', 'bridge', 'netdev'):
        raise Problem('Invalid nftables family.')
    return f


def backend(d):
    b = text(d, 'backend', 'iptables')
    if b not in BACKENDS:
        raise Problem('Invalid iptables backend.')
    if not executable(b):
        raise Problem(f'{b} is not installed.', 503)
    detection = current_detection()
    if (detection['selection_review_required'] or detection['selected_backend'] != 'iptables'
            or b not in detection['write_backends']):
        raise Problem(f'{b} is not part of the selected writable iptables backend. Refresh detection.', 409)
    return b


def stable(value):
    """Exclude mutable nft counter values from rule identity."""
    if isinstance(value, list):
        return [stable(v) for v in value]
    if isinstance(value, dict):
        return {k: ({} if k == 'counter' else stable(v)) for k, v in value.items()}
    return value


def signature(value):
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    return hmac.new(SECRET.encode(), encoded, hashlib.sha256).hexdigest()


def configuration_only(value):
    """Keep rule configuration while excluding counters and volatile handles."""
    if isinstance(value, list):
        return [configuration_only(item) for item in value]
    if isinstance(value, dict):
        ignored = {'counter', 'handle', 'packets', 'bytes'}
        return {key: configuration_only(item) for key, item in value.items()
                if key not in ignored}
    return value


def nft_state():
    raw = checked('nft', ['-a', '-n', 'list', 'ruleset'])
    payload = json.loads(checked('nft', ['-j', '-a', '-n', 'list', 'ruleset']))
    tables, chains, rules = [], [], []
    for item in payload.get('nftables', []):
        if 'table' in item:
            tables.append(item['table'])
        if 'chain' in item:
            chains.append(item['chain'])
        if 'rule' in item:
            r = dict(item['rule'])
            r['token'] = signature(stable(r))
            r['masquerade'] = any('masquerade' in x for x in r.get('expr', []) if isinstance(x, dict))
            rules.append(r)
    return {'backend': 'nft', 'raw': raw, 'tables': tables, 'chains': chains, 'rules': rules}


def parse_save(raw, b):
    tables, chains, rules, current = [], [], [], None
    counts = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('*'):
            current = line[1:]
            tables.append(current)
        elif line.startswith(':') and current:
            c, policy, *rest = line[1:].split()
            chains.append({'table': current, 'name': c, 'policy': policy,
                           'counters': ' '.join(rest)})
        elif current and (line.startswith('-A ') or line.startswith('[')):
            packets, size = 0, 0
            match = re.match(r'^\[(\d+):(\d+)\]\s+(.*)$', line)
            if match:
                packets, size, line = int(match[1]), int(match[2]), match[3]
            parts = shlex.split(line)
            if len(parts) < 3 or parts[0] != '-A':
                continue
            c, spec = parts[1], parts[2:]
            key = (current, c)
            counts[key] = counts.get(key, 0) + 1
            identity = [b, current, c, spec]
            rules.append({'table': current, 'chain': c, 'number': counts[key],
                          'spec': spec, 'expression': shlex.join(spec),
                          'packets': packets, 'bytes': size, 'token': signature(identity),
                          'masquerade': any(spec[i] in ('-j', '--jump') and spec[i+1] == 'MASQUERADE'
                                            for i in range(len(spec)-1))})
    return {'backend': b, 'raw': raw, 'tables': tables, 'chains': chains, 'rules': rules}


def ipt_state(b):
    save = BACKENDS[b]
    if not executable(save):
        raise Problem(f'{save} is needed to list all tables and counters.', 503)
    result = parse_save(checked(save, ['-c']), b)
    result['version'] = checked(b, ['--version']).strip()
    return result


def capture():
    """Include nft and every installed iptables variant; don't merge aliases."""
    names = [n for n in ('nft', *BACKENDS) if executable(n)]
    def one(n):
        try:
            return n, nft_state() if n == 'nft' else ipt_state(n)
        except (Problem, ValueError) as exc:
            return n, {'error': str(exc.message if isinstance(exc, Problem) else exc)}
    with ThreadPoolExecutor(max_workers=4) as pool:
        states = dict(pool.map(one, names))
    return {'created_utc': datetime.now(timezone.utc).isoformat(), 'states': states,
            'note': 'iptables-nft and nftables overlap; default commands may alias explicit backends. Snapshot only; configure boot restoration in Persistence.'}


# Read-only, exact-port inspection. A verdict describes NEW incoming traffic at
# the local firewall, not an Internet reachability test or a firewall change.
def _pc_port_contains(value, port):
    if isinstance(value, bool):
        return None
    if isinstance(value, int) or isinstance(value, str) and value.isascii() and value.isdigit():
        return int(value) == port
    if isinstance(value, dict):
        if 'elem' in value and isinstance(value['elem'],dict):
            return _pc_port_contains(value['elem'].get('val'),port)
        if 'range' in value:
            try:
                return int(value['range'][0]) <= port <= int(value['range'][1])
            except (ValueError, TypeError, IndexError):
                return None
        if 'set' in value:
            return _pc_port_contains(value['set'], port)
        return None
    if isinstance(value, list):
        matches = [_pc_port_contains(v, port) for v in value]
        return True if True in matches else None if None in matches else False
    if isinstance(value, str) and re.fullmatch(r'[0-9,:-]+', value):
        members = []
        for part in value.split(','):
            limits = re.split('[:-]', part)
            members.append({'range': limits} if len(limits) == 2 else part)
        return _pc_port_contains(members, port)
    return None


def _pc_ipt_condition(rule, protocol, family, port):
    spec = rule['spec']; conditions = []; explicit = False; target = 'next'; jump = None
    i = 0; negate = False
    while i < len(spec):
        arg = spec[i]; i += 1
        if arg == '!':
            negate = True; continue
        if arg in ('-j', '--jump', '-g', '--goto'):
            if i == len(spec): return None, False, 'unknown', None
            target = spec[i]; i += 1
            if arg in ('-g', '--goto'):
                jump = target; target = 'goto'
            continue
        if arg in ('--comment', '--log-prefix', '--log-level', '--reject-with'):
            i += 1; continue
        value = None
        if arg in ('-p', '--protocol', '--dport', '--destination-port', '--dports',
                   '--destination-ports', '--sport', '--source-port', '--sports',
                   '-s', '--source', '-d', '--destination', '-i', '--in-interface',
                   '-o', '--out-interface', '--ctstate', '--state', '--dst-type', '--src-type', '--rt-type', '-m', '--match'):
            if i == len(spec): return None, False, 'unknown', None
            value = spec[i]; i += 1
        if value == '!' and i < len(spec):
            negate = True; value = spec[i]; i += 1
        condition = True
        if arg in ('-p', '--protocol'):
            condition = value in ('all', '0', protocol, '6' if protocol == 'tcp' else '17')
        elif arg in ('--dport', '--destination-port', '--dports', '--destination-ports'):
            condition = _pc_port_contains(value, port)
            if condition is True and not negate: explicit = True
        elif arg in ('--ctstate', '--state'):
            condition = 'NEW' in value.upper().split(',')
        elif arg in ('-s', '--source', '-d', '--destination'):
            condition = True if value in ('0.0.0.0/0', '::/0', 'anywhere') else None
        elif arg in ('-i', '--in-interface'):
            condition = False if value == 'lo' else None
        elif arg in ('-o', '--out-interface'):
            condition = None
        elif arg in ('--sport', '--source-port', '--sports'):
            condition = None
        elif arg == '--dst-type':
            condition = True if value == 'LOCAL' else False if value in ('MULTICAST','BROADCAST') else None
        elif arg == '--src-type':
            condition = False if value == 'LOCAL' else None
        elif arg == '--rt-type':
            condition = False if value == '0' else None
        elif arg in ('-m', '--match'):
            condition = True if value in ('tcp', 'udp', 'multiport', 'conntrack', 'state', 'comment','addrtype') else None
        elif arg == '--syn':
            condition = protocol == 'tcp'
        elif arg == '--tcp-flags':
            # Only the common NEW TCP SYN test is unambiguous here.
            pair = spec[i:i+2]; i += 2
            condition = True if protocol == 'tcp' and pair == ['FIN,SYN,RST,ACK', 'SYN'] else None
        elif value is None:
            condition = None
        if negate:
            condition = None if condition is None else not condition
            negate = False
        conditions.append(condition)
    if target in ('ACCEPT',): action = 'allow'
    elif target in ('DROP', 'REJECT'): action = 'block'
    elif target == 'RETURN': action = 'return'
    elif target in ('LOG', 'NFLOG', 'MARK', 'CONNMARK', 'CT', 'NOTRACK', 'next'): action = 'next'
    elif target in ('DNAT', 'REDIRECT'): action = 'forward'
    elif target == 'goto': action = 'goto'
    elif target == 'unknown': action = 'unknown'
    else: action, jump = 'jump', target
    condition = False if False in conditions else None if None in conditions else True
    return condition, explicit, action, jump


def _pc_protocol_contains(value, protocol):
    if isinstance(value,dict) and 'set' in value: value=value['set']
    if isinstance(value,list):
        results=[_pc_protocol_contains(v,protocol) for v in value]
        return True if True in results else None if None in results else False
    if value in (protocol,6 if protocol=='tcp' else 17):return True
    if isinstance(value,int):return False
    if value in ('tcp','udp','icmp','icmpv6','ipv6-icmp','igmp','sctp','dccp','udplite','esp','ah','gre'):return False
    return None


def _pc_nft_condition(rule, protocol, family, port, sets):
    conditions = []; explicit = False; action = 'next'; jump = None
    for expr in rule.get('expr', []):
        if not isinstance(expr, dict):
            conditions.append(None); continue
        if any(k in expr for k in ('counter', 'log', 'comment')): continue
        if 'accept' in expr: action = 'allow'; continue
        if 'drop' in expr or 'reject' in expr: action = 'block'; continue
        if 'return' in expr: action = 'return'; continue
        if 'jump' in expr:
            action, jump = 'jump', expr['jump'].get('target'); continue
        if 'goto' in expr:
            action, jump = 'goto', expr['goto'].get('target'); continue
        if 'vmap' in expr:
            vmap = expr['vmap']; key = vmap.get('key', {})
            entries = vmap.get('data', {}).get('set') if isinstance(vmap.get('data'),dict) else None
            if isinstance(key,dict) and key.get('ct',{}).get('key')=='state' and isinstance(entries,list):
                valid=True; selected=None
                for entry in entries:
                    if isinstance(entry,list) and len(entry)==2: value, verdict=entry
                    elif isinstance(entry,dict) and isinstance(entry.get('elem'),dict): value, verdict=entry['elem'].get('val'),entry['elem'].get('data')
                    else: valid=False;break
                    if value=='new':selected=verdict
                if valid and selected is None:continue
                if valid and isinstance(selected,dict):
                    if 'accept' in selected:action='allow';continue
                    if 'drop' in selected or 'reject' in selected:action='block';continue
            action='unknown';continue
        if 'dnat' in expr or 'redirect' in expr: action = 'forward'; continue
        m = expr.get('match')
        if not isinstance(m, dict):
            conditions.append(None); continue
        left, right, op = m.get('left'), m.get('right'), m.get('op', '==')
        condition = None
        if isinstance(left, dict) and 'payload' in left:
            payload = left['payload']; field = payload.get('field'); transport = payload.get('protocol')
            if transport in ('ip','ip6') and transport != family:
                condition = False
            elif transport in ('icmp','icmpv6','icmpx'):
                condition = False
            elif field in ('dport', 'sport'):
                if transport in ('tcp', 'udp') and transport != protocol:
                    condition = False
                elif field == 'dport':
                    if isinstance(right, str) and right.startswith('@'):
                        right = sets.get((rule.get('family'), rule.get('table'), right[1:]))
                    condition = _pc_port_contains(right, port)
                    if condition is True and op in ('==', 'in'): explicit = True
            elif field in ('saddr', 'daddr'):
                if isinstance(right, dict) and right.get('prefix', {}).get('len') == 0: condition = True
            elif field in ('protocol', 'nexthdr'):
                condition = _pc_protocol_contains(right,protocol)
        elif isinstance(left, dict) and 'meta' in left:
            key = left['meta'].get('key')
            if key == 'l4proto':
                if isinstance(right,str) and right.startswith('@'):right=sets.get((rule.get('family'),rule.get('table'),right[1:]))
                condition = _pc_protocol_contains(right,protocol)
            elif key == 'nfproto':
                condition = right in (family,'ipv4' if family=='ip' else 'ipv6',2 if family=='ip' else 10) if right in ('ip','ip6','ipv4','ipv6',2,10) else None
            elif key in ('iifname', 'iif') and right in ('lo', 1): condition = False
        elif isinstance(left, dict) and 'ct' in left and left['ct'].get('key') == 'state':
            values = right.get('set', []) if isinstance(right, dict) else [right]
            condition = 'new' in values
        if op in ('!=', 'not in'): condition = None if condition is None else not condition
        elif op not in ('==', 'in'): condition = None
        conditions.append(condition)
    return (False if False in conditions else None if None in conditions else True), explicit, action, jump


def _pc_layer_verdict(layer, protocol, family, port):
    """Conservative symbolic walk: unknown address/interface matches branch.

    Rule order, jumps/returns, default policies and multiple base chains matter.
    Never turn a partially understood path into an unconditional 'allowed'.
    """
    rules = layer['rules']; chains = layer['chains']; sets = layer.get('sets', {})
    memo = {}; budget = [10000]
    def walk(chain, trail=()):
        if chain in memo: return memo[chain]
        if chain in trail or len(trail) > 24 or chain not in chains: return {'unknown'}
        pending = True; results = set()
        for rule in rules.get(chain, []):
            budget[0] -= 1
            if budget[0] < 0: return {'unknown'}
            if layer['kind'] == 'iptables': cond, _, action, target = _pc_ipt_condition(rule, protocol, family, port)
            else: cond, _, action, target = _pc_nft_condition(rule, protocol, family, port, sets)
            if cond is False: continue
            if action == 'next': continue
            if action == 'return':
                results.add('return')
                if cond is True: pending = False; break
                continue
            outcomes = walk(target, trail+(chain,)) if action in ('jump','goto') else {action}
            if action == 'goto':
                results.update(outcomes)
                if cond is True: pending = False; break
                continue
            results.update(outcomes - {'return'})
            if cond is True and 'return' not in outcomes:
                pending = False; break
        if pending:
            policy = chains[chain].get('policy', 'return').lower()
            results.add({'accept':'allow', 'drop':'block'}.get(policy, 'return'))
        memo[chain] = results
        return results
    verdicts = []
    for root in layer['roots']:
        outcomes = walk(root)
        if 'return' in outcomes:
            outcomes = (outcomes-{'return'}) | {{'accept':'allow','drop':'block'}.get(chains[root].get('policy','accept').lower(),'unknown')}
        if outcomes == {'block'}: verdicts.append('blocked')
        elif outcomes == {'allow'} or outcomes == {'return'}: verdicts.append('allowed')
        elif 'unknown' in outcomes or 'forward' in outcomes: verdicts.append('unknown')
        else: verdicts.append('restricted')
    return 'blocked' if 'blocked' in verdicts else 'unknown' if 'unknown' in verdicts else 'restricted' if 'restricted' in verdicts else 'allowed'


def _pc_layers(nft_payload, saves):
    layers = []; skipped = set()
    for backend, state in saves.items():
        family = 'ip6' if backend.startswith('ip6') else 'ip'
        if backend.endswith('-nft'): skipped.update((family,table) for table in state['tables'])
        for table in state['tables']:
            chains = {c['name']:c for c in state['chains'] if c['table'] == table}
            rules = {name:[r for r in state['rules'] if r['table'] == table and r['chain'] == name] for name in chains}
            roots = [name for name in ('PREROUTING', 'INPUT') if name in chains and chains[name]['policy'] != '-']
            if table == 'nat': roots = []  # Translation is shown separately, not called an input allow.
            layers.append({'kind':'iptables','backend':backend,'family':family,'table':table,'chains':chains,'rules':rules,'roots':roots})
    sets = {}
    for item in nft_payload.get('nftables', []):
        value = item.get('set') or item.get('element')
        if isinstance(value, dict):
            key = (value.get('family'), value.get('table'), value.get('name'))
            sets.setdefault(key, []).extend(value.get('elem', []))
    tables = {}
    for item in nft_payload.get('nftables', []):
        for kind in ('chain', 'rule'):
            r = item.get(kind)
            if not isinstance(r, dict): continue
            family, table = r.get('family'), r.get('table')
            if (family,table) in skipped: continue
            if family not in ('ip', 'ip6', 'inet', 'bridge', 'netdev'): continue
            key = (family, table)
            layer = tables.setdefault(key, {'kind':'nftables','backend':'nftables','family':family,'table':table,'chains':{},'rules':{},'roots':[],'sets':sets})
            if kind == 'chain':
                layer['chains'][r['name']] = r
                if r.get('hook') in ('input', 'prerouting', 'ingress'): layer['roots'].append(r['name'])
            else: layer['rules'].setdefault(r['chain'], []).append(r)
    layers.extend(tables.values())
    return layers


def _pc_advanced_effect(layer, protocol, family, port):
    # A translation, NOTRACK or userspace verdict can change the tuple/state
    # before later rules. Do not evaluate those later rules against old values.
    roots=[n for n,c in layer['chains'].items() if
           (layer['kind']=='iptables' and n in ('PREROUTING','INPUT') and c.get('policy')!='-')
           or (layer['kind']=='nftables' and c.get('hook') in ('prerouting','input','ingress'))]
    pending=list(roots);seen=set()
    while pending:
        chain=pending.pop()
        if chain in seen:continue
        seen.add(chain)
        if len(seen)>10000:return True
        for rule in layer['rules'].get(chain,[]):
            cond,_,action,target=(_pc_ipt_condition(rule,protocol,family,port) if layer['kind']=='iptables' else _pc_nft_condition(rule,protocol,family,port,layer.get('sets',{})))
            if cond is False:continue
            if action in ('jump','goto'):
                if target not in layer['chains']:return True
                pending.append(target)
            if action in ('unknown','forward'):return True
            if layer['kind']=='iptables':
                if 'NOTRACK' in rule['spec'] or '--notrack' in rule['spec']:return True
            else:
                understood={'match','counter','log','comment','accept','drop','reject','return','jump','goto','limit','quota','vmap'}
                if any(not isinstance(expr,dict) or set(expr)-understood for expr in rule.get('expr',[])):return True
    return False


def _pc_rule_rows(layers, port):
    rows = []
    for layer in layers:
        parents = {}
        for chain, rules in layer['rules'].items():
            for r in rules:
                if layer['kind'] == 'iptables': target = _pc_ipt_condition(r, 'tcp', layer['family'], port)[3]
                else: target = next((x[k].get('target') for x in r.get('expr', []) if isinstance(x,dict) for k in ('jump','goto') if k in x), None)
                if target: parents.setdefault(target, set()).add(chain)
        scope_cache={}
        def scope(name, trail=()):
            if name in scope_cache: return scope_cache[name]
            if name in trail or len(trail)>24: return 'Other rule'
            c = layer['chains'].get(name, {}); hook = c.get('hook')
            if name == 'INPUT' and layer['kind'] == 'iptables' or hook == 'input': return 'Incoming'
            if name == 'FORWARD' or hook == 'forward': return 'Forwarded'
            if name == 'OUTPUT' or hook == 'output': return 'Outgoing'
            if name == 'PREROUTING' or hook in ('prerouting', 'ingress'): return 'Before incoming traffic'
            scopes = {scope(p, trail+(name,)) for p in parents.get(name, [])}
            result='Incoming' if 'Incoming' in scopes else next(iter(sorted(scopes)), 'Unused chain')
            scope_cache[name]=result
            return result
        for chain, rules in layer['rules'].items():
            for index, rule in enumerate(rules, 1):
                for protocol in ('tcp', 'udp'):
                    families = ['ip','ip6'] if layer['family'] in ('inet','bridge','netdev') else [layer['family']]
                    applicable = []
                    for family in families:
                        cond, explicit, action, _ = (_pc_ipt_condition(rule, protocol, family, port) if layer['kind']=='iptables' else _pc_nft_condition(rule, protocol, family, port, layer.get('sets', {})))
                        if cond is not False and (explicit or action in ('allow','block','forward')): applicable.append((family, cond, action, explicit))
                    if not applicable: continue
                    action = applicable[0][2]
                    location = ('Rule #'+str(rule['number'])) if layer['kind']=='iptables' else ('Handle #'+str(rule['handle']) if 'handle' in rule else 'Rule '+str(index)+' (display order)')
                    expression = rule.get('expression') if layer['kind']=='iptables' else json.dumps(rule.get('expr', []), sort_keys=True)
                    rows.append({'protocol':protocol,'family':'IPv4 + IPv6' if len(applicable)==2 else 'IPv6' if applicable[0][0]=='ip6' else 'IPv4',
                                 'action':{'allow':'Allow','block':'Block','forward':'Forward','jump':'Continue checking'}.get(action,'Check needed'),
                                 'scope':scope(chain),'location':location,'backend':layer['backend'],'table':layer['table'],'chain':chain,
                                 'port_specific':any(e for _,_,_,e in applicable),'restricted':any(c is None for _,c,_,_ in applicable),'rule':expression,
                                 'identity':json.dumps([layer['backend'],layer['family'],layer['table'],chain,protocol,rule.get('spec',stable(rule.get('expr',[])))],sort_keys=True)})
    counts = {}
    for row in rows: counts[row['identity']] = counts.get(row['identity'],0)+1
    for row in rows: row['copies'] = counts[row.pop('identity')]
    return rows


def _pc_listener_rows(tcp, udp, port):
    rows = []
    for raw in (tcp, udp):
        for line in raw.splitlines():
            parts = line.split(None, 6)
            if len(parts) < 6: continue
            protocol = 'tcp' if parts[0].startswith('tcp') else 'udp' if parts[0].startswith('udp') else None
            if not protocol or protocol == 'tcp' and parts[1] != 'LISTEN': continue
            address, sep, number = parts[4].rpartition(':')
            if not sep or not number.isdigit() or int(number) != port: continue
            processes = re.findall(r'\("([^"\n]+)",pid=([0-9]+)', parts[6] if len(parts)>6 else '')
            services = []
            for name, pid in processes:
                unit = None
                try:
                    groups = Path('/proc')/pid/'cgroup'
                    units=[v for v in groups.read_text(errors='replace').replace('\n','/').split('/') if v.endswith('.service')]
                    unit=units[-1] if units else None
                except (OSError, StopIteration): pass
                services.append({'name':name,'pid':int(pid),'unit':unit})
            row = {'protocol':protocol,'address':address.strip('[]'),'services':services,
                   'local_only':address.strip('[]') in ('127.0.0.1','::1')}
            if row not in rows: rows.append(row)
    return rows


def inspect_port(port):
    notes = []; saves = {}; probes = {}
    names = [n for n in ('nft','iptables-nft-save','ip6tables-nft-save','iptables-legacy-save','ip6tables-legacy-save','iptables-save','ip6tables-save') if executable(n)]
    def read(name):
        return name, _probe(name, ['-j','-a','-n','list','ruleset'] if name=='nft' else ['-c'])
    with ThreadPoolExecutor(max_workers=4) as pool: probes = dict(pool.map(read,names))
    nft_payload = {}; readable = False
    if probes.get('nft',{}).get('available'):
        try:
            nft_payload=json.loads(probes['nft']['output'])
            if not isinstance(nft_payload,dict) or not isinstance(nft_payload.get('nftables'),list): raise ValueError('Incomplete rules')
            readable=True
        except (ValueError, KeyError): notes.append('Some firewall rules could not be read.')
    elif 'nft' in probes: notes.append('Native firewall rules could not be read.')
    for family in ('iptables','ip6tables'):
        explicit = [n for n in (family+'-nft-save',family+'-legacy-save') if n in probes]
        for name in explicit or [family+'-save']:
            result=probes.get(name,{})
            if result.get('available'):
                try:
                    saves[name.removesuffix('-save')]=parse_save(result['output'],name.removesuffix('-save'));readable=True
                except (ValueError,KeyError): notes.append('Some firewall rules could not be parsed.')
            elif name in probes: notes.append('Some '+('IPv6' if family.startswith('ip6') else 'IPv4')+' firewall rules could not be read.')
    layers=_pc_layers(nft_payload,saves);rows=_pc_rule_rows(layers,port)
    results={}
    for protocol in ('tcp','udp'):
        families={}
        for family in ('ip','ip6'):
            applicable=[l for l in layers if l['roots'] and l['family'] in (family,'inet','bridge','netdev')]
            verdicts=[_pc_layer_verdict(l,protocol,family,port) for l in applicable]
            verdicts=['unknown' if l['family'] in ('bridge','netdev') and v!='allowed' else v for l,v in zip(applicable,verdicts)]
            advanced=any(_pc_advanced_effect(l,protocol,family,port) for l in layers if l['family'] in (family,'inet','bridge','netdev'))
            forwarded=any(r['protocol']==protocol and r['action']=='Forward' and r['scope']=='Before incoming traffic' and r['family'] in (('IPv4','IPv4 + IPv6') if family=='ip' else ('IPv6','IPv4 + IPv6')) for r in rows)
            value='unknown' if forwarded or advanced else 'blocked' if 'blocked' in verdicts else 'unknown' if 'unknown' in verdicts or notes or not readable else 'restricted' if 'restricted' in verdicts else 'allowed'
            families['IPv6' if family=='ip6' else 'IPv4']=value
        values=set(families.values())
        value=next(iter(values)) if len(values)==1 else 'restricted'
        results[protocol]={'state':value,'families':families,'label':{'allowed':'Allowed','blocked':'Not opened','restricted':'Restricted / mixed rules','unknown':'Could not fully check'}[value]}
    if not notes and any('unknown' in v['families'].values() for v in results.values()):
        notes.append('An advanced or forwarding rule needs a closer check; no open/closed guess was made.')
    tcp=_probe('ss',['-H','-antup'])
    listeners=_pc_listener_rows(tcp.get('output',''),'',port)
    usage_known=tcp.get('available')
    if not usage_known:notes.append('Listening services could not be fully checked. Root access and ss are needed.')
    managers=[]
    ufw=_probe('ufw',['status']);firewalld=_probe('firewall-cmd',['--state'])
    if re.search(r'(?im)^Status:\s*active\s*$',ufw.get('output','')):managers.append('UFW')
    if firewalld.get('output','').strip()=='running':managers.append('firewalld')
    if len(managers)>1: notes.append('More than one firewall manager is active; review the matching rules.')
    allowed=[p.upper() for p,v in results.items() if v['state']=='allowed']
    if len(allowed)==2:summary='TCP and UDP allowed'
    elif all(v['state']=='blocked' for v in results.values()):summary='Not opened'
    elif allowed: summary=allowed[0]+' allowed; '+('UDP' if allowed[0]=='TCP' else 'TCP')+' '+results['udp' if allowed[0]=='TCP' else 'tcp']['label'].lower()
    else:summary='Restricted or mixed access' if any(v['state']=='restricted' for v in results.values()) else 'Could not fully check'
    return {'port':port,'summary':summary,'protocols':results,'rules':rows,'listeners':listeners,'usage_known':bool(usage_known),
            'firewall':', '.join(managers) or 'Live kernel firewall','notes':list(dict.fromkeys(notes)),
            'scope':'New incoming traffic at this server. Local firewall rules only; cloud/router rules and external reachability are not tested.',
            'checked_utc':datetime.now(timezone.utc).isoformat()}


@app.get('/api/port-check')
def port_check():
    value=request.args.get('port','').strip()
    if not re.fullmatch(r'[0-9]{1,5}',value) or not 1<=int(value)<=65535:
        raise Problem('Enter one port number from 1 to 65535.')
    return jsonify(inspect_port(int(value)))


def backup(required=None):
    snapshot = capture()
    if required and ('error' in snapshot['states'].get(required, {'error': 'unavailable'})):
        raise Problem('Cannot back up the selected backend; change cancelled.', 503)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    # mkstemp is exclusive and creates files with mode 0600.
    fd, filename = tempfile.mkstemp(prefix=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S-'),
                                    suffix='.json', dir=BACKUP_DIR)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(snapshot, stream, indent=2)
            stream.write('\n')
    except Exception:
        Path(filename).unlink(missing_ok=True)
        raise
    return Path(filename).name


def private_write(path, content):
    """Atomic config replacement; a failed write preserves the old file."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix='.nft-web-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def config_backup(paths):
    """Preserve pre-existing persistence files as well as live-rule backups."""
    saved = {'created_utc': datetime.now(timezone.utc).isoformat(), 'files': {}}
    for path in paths:
        saved['files'][str(path)] = base64.b64encode(path.read_bytes()).decode() if path.exists() else None
    BACKUP_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix='persistence-before-', suffix='.json', dir=BACKUP_DIR)
    with os.fdopen(fd, 'w') as stream:
        json.dump(saved, stream, indent=2)
    return Path(name).name


def canonical_save(raw):
    lines = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        line = re.sub(r'^\[\d+:\d+\]\s+', '', line)
        if line.startswith(':'):
            line = re.sub(r'\s+\[\d+:\d+\]$', '', line)
        lines.append(line)
    return lines


def enable_boot_service(name):
    checked('systemctl', ['enable', name])
    state = checked('systemctl', ['is-enabled', name]).strip()
    if state != 'enabled':
        raise Problem(f'Rules saved, but {name} is not persistently enabled ({state}).', 500)


def compatibility_tables():
    """Find nftables tables owned by IPv4/IPv6 xtables compatibility tools."""
    owned = set()
    for f, explicit, default in (('ip', 'iptables-nft-save', 'iptables'),
                                 ('ip6', 'ip6tables-nft-save', 'ip6tables')):
        if executable(explicit):
            raw = checked(explicit)
        elif executable(default) and 'nf_tables' in checked(default, ['--version']):
            raw = checked(BACKENDS[default])
        else:
            continue
        owned.update((f, t) for t in parse_save(raw, default)['tables'])
    return owned


def native_restore_script(saved, present):
    if saved.get('version') != 1 or not isinstance(saved.get('tables'), list):
        raise Problem('Invalid native persistence file.', 500)
    commands, seen = [], set()
    for entry in saved['tables']:
        f, name = entry['family'], identifier(entry['name'])
        if f not in ('ip', 'ip6', 'inet', 'arp', 'bridge', 'netdev') or (f, name) in seen:
            raise Problem('Invalid or duplicate native table.', 500)
        seen.add((f, name))
        if (f, name) in present:
            commands.append(f'delete table {f} {name}')
        commands.append(entry['rules'])
    return '\n'.join(commands) + '\n'


def restore_native():
    def require_restore_ownership():
        detection = detect_firewall()
        empty_host = (detection['selected_backend'] == 'inspection'
                      and detection['reason'].startswith(
                          'No active firewall manager or populated direct ruleset'))
        if (not can_manage_firewall()
                or detection['active_managers']
                or detection['selected_backend'] != 'nftables' and not empty_host):
            raise Problem('Native nftables restore cancelled because current firewall ownership is not safely direct.', 409)

    require_restore_ownership()
    saved = json.loads(NATIVE_STATE.read_text())
    current = json.loads(checked('nft', ['-j', 'list', 'tables']))
    present = {(x['table']['family'], x['table']['name']) for x in current.get('nftables', []) if 'table' in x}
    owned = compatibility_tables()
    if any((x['family'], x['name']) in owned for x in saved.get('tables', [])):
        raise Problem('A saved native table is now owned by iptables-nft; restore cancelled to preserve it.', 500)
    # One atomic transaction. Replace only saved native tables; no global flush.
    require_restore_ownership()
    nft_script(native_restore_script(saved, present))


def unit_quote(value):
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%').replace('\n', '\\n') + '"'


def nft_script(script):
    return checked('nft', ['-f', '-'], stdin=script + '\n')


def one_expression(value):
    if not value or any(c in value for c in ('\n', '\r', ';')):
        raise Problem('Enter one rule expression, without command separators.')
    # Braces are allowed for nft sets. Kernel nft grammar validates the expression.
    return value


IPT_FORBIDDEN = {'-A', '-I', '-D', '-R', '-F', '-X', '-N', '-P', '-E', '-Z',
                 '--append', '--insert', '--delete', '--replace', '--flush',
                 '--delete-chain', '--new-chain', '--policy', '--rename-chain',
                 '--zero', '-t', '--table', '-w', '--wait', '-M', '--modprobe',
                 '--help', '-h', '--version', '-V', '--set-counters', '-c'}


def ipt_expression(value):
    try:
        args = shlex.split(value)
    except ValueError as exc:
        raise Problem(str(exc))
    if not args or any(a.split('=', 1)[0] in IPT_FORBIDDEN or a.startswith('-M') for a in args):
        raise Problem('Enter match/target options only; choose operation and table using the form.')
    return args


def checkbox(d, key, default=False):
    value = d.get(key, default)
    if not isinstance(value, bool):
        raise Problem(f'{key} must be true or false.')
    return value


def service_port(value):
    match = re.fullmatch(r'(\d{1,5})(?:[:-](\d{1,5}))?', value)
    if not match:
        raise Problem('Enter one port (1-65535) or a range such as 8000:8010.')
    first = integer(match[1], maximum=65535)
    last = integer(match[2] or match[1], minimum=first, maximum=65535)
    return str(first) if first == last else f'{first}:{last}'


def port_comment(spec):
    try:
        return spec[spec.index('--comment') + 1]
    except (ValueError, IndexError):
        return ''


def port_rules(protocol, port, iface, stateless):
    marker = 'nft-web:port:' + hashlib.sha256(json.dumps([protocol, port, iface]).encode()).hexdigest()[:16] + ':'
    incoming = (['-i', iface] if iface else []) + ['-p', protocol, '--dport', port]
    outgoing = (['-o', iface] if iface else []) + ['-p', protocol, '--sport', port]
    def rule(table, chain, match, role, target):
        return {'table': table, 'chain': chain,
                'spec': [*match, '-m', 'comment', '--comment', marker + role, *target]}
    # Allow replies explicitly, including with a restrictive OUTPUT policy.
    desired = [rule('filter', 'INPUT', incoming, 'in', ['-j', 'ACCEPT']),
               rule('filter', 'OUTPUT', outgoing, 'out', ['-j', 'ACCEPT'])]
    if stateless:
        # NOTRACK must happen before conntrack, in raw. Apply permits first.
        desired += [rule('raw', 'PREROUTING', [*incoming, '-m', 'addrtype', '--dst-type', 'LOCAL'], 'notrack-in', ['-j', 'CT', '--notrack']),
                    rule('raw', 'OUTPUT', outgoing, 'notrack-out', ['-j', 'CT', '--notrack'])]
    return marker, desired


def port_plan(state, marker, desired):
    """Diff only this tool's matching service-port rules; leave other rules alone."""
    remaining, remove = list(desired), []
    for r in state['rules']:
        if not port_comment(r['spec']).startswith(marker):
            continue
        equal = next((i for i, x in enumerate(remaining) if
                      (x['table'], x['chain'], x['spec']) == (r['table'], r['chain'], r['spec'])), None)
        if equal is None:
            remove.append(r)
        else:
            remaining.pop(equal)
    return remove, remaining


def port_test_rules(state, remove, add):
    """Construct the final affected tables for restore --test, never apply them."""
    touched = sorted({r['table'] for r in [*remove, *add]})
    current = list(state['rules'])
    for r in remove:
        current.remove(r)
    # Actual additions are inserted first; reflect that order in the syntax test.
    for r in add:
        current.insert(0, r)
    lines = []
    for table in touched:
        lines.append('*' + table)
        chains = [c for c in state['chains'] if c['table'] == table]
        if not chains:
            names = ('INPUT', 'FORWARD', 'OUTPUT') if table == 'filter' else ('PREROUTING', 'OUTPUT')
            chains = [{'name': n, 'policy': 'ACCEPT'} for n in names]
        for c in chains:
            lines.append(f':{c["name"]} {c["policy"]} [0:0]')
        for r in current:
            if r['table'] != table:
                continue
            # iptables-restore uses double-quoted/escaped arguments.
            args = ['-A', r['chain'], *r['spec']]
            lines.append(' '.join('"' + a.replace('\\', '\\\\').replace('"', '\\"') + '"'
                                  if any(x.isspace() or x in '\\"' for x in a) else a for a in args))
        lines.append('COMMIT')
    return '\n'.join(lines) + '\n'


@app.before_request
def authenticate():
    if request.method == 'GET' and (request.path == '/' or request.path.startswith('/fonts/')):
        return None
    if not re.fullmatch(r'[0-9]{4}', SECRET):
        raise Problem('Server requires NFT_SECRET with exactly four digits.', 503)
    supplied = request.headers.get('X-Secret', '')
    if not hmac.compare_digest(supplied.encode(), SECRET.encode()):
        raise Problem('Unauthorized: enter the configured access key.', 401)
    origin = request.headers.get('Origin')
    if origin and origin not in {request.host_url.rstrip('/'), *ALLOWED_ORIGINS}:
        raise Problem('Cross-origin requests are not allowed.', 403)
    if request.method not in ('GET', 'HEAD', 'OPTIONS') and not can_manage_firewall():
        raise Problem(read_only_reason(), 403)
    if request.method not in ('GET', 'HEAD', 'OPTIONS'):
        if request.path == '/api/backup' or request.path.endswith('/confirm') and request.path.startswith('/api/rollback/'):
            return None
        detection = current_detection()
        if detection['selection_review_required'] and request.path != '/api/detection/review':
            raise Problem('The selected firewall backend changed while the application was running. Refresh and explicitly review the new selection before writing.', 409)
        if request.path == '/api/detection/review':
            return None
        manager = ('ufw' if request.path.startswith('/api/ufw/')
                   else 'firewalld' if request.path.startswith('/api/firewalld/') else None)
        if manager:
            if detection['selected_backend'] != manager or not detection['manager_can_write']:
                raise Problem(detection['reason'], 409 if detection['selected_backend'] != manager else 403)
        elif detection['selected_backend'] not in ('nftables', 'iptables'):
            raise Problem(detection['reason'], 409)
        path_backend = None
        if request.path.startswith('/api/nft/') or request.path == '/api/persist/nft':
            path_backend = 'nftables'
        elif request.path.startswith('/api/iptables/') or request.path == '/api/persist/iptables':
            path_backend = 'iptables'
        elif request.path == '/api/masquerade':
            engine = (request.get_json(silent=True) or {}).get('engine', 'nft')
            path_backend = 'nftables' if engine == 'nft' else 'iptables'
        elif request.path == '/api/exec':
            engine = (request.get_json(silent=True) or {}).get('engine', 'nft')
            path_backend = 'nftables' if engine == 'nft' else 'iptables'
        if path_backend and detection['selected_backend'] != path_backend:
            raise Problem(f'{detection["selected_backend"]} is selected; this operation targets {path_backend}.', 409)
        if (request.path == '/api/persist/iptables'
                and not {'iptables', 'ip6tables'}.issubset(detection['write_backends'])):
            raise Problem('The system-default iptables backends are not the selected writable alternatives.', 409)


@app.after_request
def headers(response):
    global SELECTED_FINGERPRINT_AT_START, SELECTION_REVIEW_REQUIRED
    global FINGERPRINT_REVIEW_REQUIRED
    if (response.status_code < 300 and request.method in ('POST', 'DELETE')
            and request.path not in ('/api/backup', '/api/detection/review')
            and not request.path.startswith('/api/rollback/')):
        try:
            report = detect_firewall()
        except Problem as exc:
            app.logger.warning('Firewall write completed but post-change detection failed: %s', exc.message)
            response.headers['X-Firewall-Review-Required'] = 'true'
        else:
            with DETECTION_LOCK:
                if SELECTED_BACKEND_AT_START is not None:
                    if report['selected_backend'] == SELECTED_BACKEND_AT_START:
                        SELECTED_FINGERPRINT_AT_START = report['selected_fingerprint']
                        FINGERPRINT_REVIEW_REQUIRED = False
                    else:
                        SELECTION_REVIEW_REQUIRED = True
                        response.headers['X-Firewall-Review-Required'] = 'true'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    if response.status_code < 300 and request.method in ('POST', 'DELETE'):
        payload = response.get_json(silent=True)
        if isinstance(payload, dict) and payload.get('pending_rollback_id'):
            # Inventory verification may be slow; the browser gets the full window.
            arm_rollback_confirmation(payload['pending_rollback_id'])
    return response


@app.errorhandler(Problem)
def problem(exc):
    return jsonify(error=exc.message), exc.status


@app.errorhandler(HTTPException)
def http_error(exc):
    return jsonify(error=exc.description), exc.code


@app.errorhandler(Exception)
def unexpected(exc):
    app.logger.exception('Request failed')
    return jsonify(error='Internal error. Check the service log; refresh before retrying.'), 500


@app.get('/')
def index():
    # No secret substitution, no Jinja evaluation of firewall output.
    return Response(HTML, mimetype='text/html')


@app.get('/fonts/<path:filename>')
def font_asset(filename):
    mimetype = FONT_ASSETS.get(filename)
    if not mimetype:
        raise Problem('Font not found.', 404)
    return send_from_directory(FONT_DIR, filename, mimetype=mimetype, max_age=31536000)


@app.get('/api/health')
def health():
    # Readiness must not launch a full firewall inventory on every retry.
    return jsonify(ok=True)


@app.get('/api/status')
def status():
    installed = [n for n in BACKENDS if executable(n)]
    def flag(path):
        try:
            return Path(path).read_text().strip() == '1'
        except OSError:
            return None
    detection = current_detection()
    detection['report_version'] = 1
    return jsonify(nft=bool(executable('nft')), backends=installed, detection=detection,
                   root=os.geteuid() == 0, interfaces=[n for _, n in socket.if_nameindex()],
                   can_manage_firewall=can_manage_firewall(),
                   read_only_reason=read_only_reason() or ('' if detection['can_write'] or detection['manager_can_write'] else detection['reason']),
                   forwarding={'ip': flag('/proc/sys/net/ipv4/ip_forward'),
                               'ip6': flag('/proc/sys/net/ipv6/conf/all/forwarding')})


@app.get('/api/detection')
def detection_report():
    report = current_detection()
    report['report_version'] = 1
    return jsonify(report)


@app.post('/api/detection/review')
def review_detection():
    if text(data(), 'confirm') != 'REVIEW':
        raise Problem('Type REVIEW to acknowledge the detected backend and manager state.')
    report = accept_current_detection()
    return jsonify(ok=True, detection=report,
                   message='Current firewall backend selection reviewed. No firewall rules were changed.')


def _ufw_rules():
    raw = checked('ufw', ['status', 'numbered'])
    rules = []
    for line in raw.splitlines():
        match = re.match(r'^\s*\[\s*(\d+)\]\s+(.+?)\s*$', line)
        if match:
            text_value = match[2]
            rules.append({'number': int(match[1]), 'text': text_value,
                          'token': signature([int(match[1]), text_value])})
    return raw, rules


def _ufw_state():
    verbose = checked('ufw', ['status', 'verbose'])
    numbered, rules = _ufw_rules()
    payload = {'verbose': verbose, 'numbered': numbered, 'ipv6': _ufw_ipv6_setting()}
    return payload, rules, signature(payload)


def _require_state_token(d, current):
    supplied = text(d, 'state_token')
    if not hmac.compare_digest(supplied, current):
        raise Problem('Firewall manager configuration changed. Refresh detection and review the current rules before retrying.', 409)


def _require_selected_write_backend(backend):
    detection = current_detection()
    if detection['selection_review_required']:
        raise Problem('Firewall configuration changed. Review the current detection before writing.', 409)
    if detection['selected_backend'] != backend or not detection['can_write']:
        raise Problem(f'{backend} is not the selected writable backend.', 409)
    return detection


def _ufw_policy(payload, direction):
    line = next((line for line in payload.get('verbose', '').splitlines()
                 if line.lower().startswith('default:')), '')
    match = re.search(r'([A-Za-z]+)\s+\(' + re.escape(direction) + r'\)', line, re.I)
    return match.group(1).lower() if match else None


def _ufw_rule_insert_args(number, rule_text, has_ipv4_ipv6_pair=False):
    line, marker, comment = rule_text.partition('#')
    match = re.search(r'\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)\s+', line, re.I)
    if not match:
        raise Problem('This UFW rule cannot be reconstructed safely for timed rollback; deletion was cancelled.', 409)
    target, source = line[:match.start()].strip(), line[match.end():].strip()
    action, direction = match.group(1).lower(), match.group(2).upper()

    def endpoint(value):
        interface = ''
        interface_match = re.search(r'\s+on\s+([A-Za-z0-9_.:-]{1,64})$', value)
        if interface_match:
            interface = interface_match.group(1)
            value = value[:interface_match.start()].strip()
        family_hint = 'ip6' if '(v6)' in value else 'ip'
        value = value.replace('(v6)', '').strip()
        if value.lower() in ('anywhere', 'any'):
            return 'any', '', '', interface, family_hint
        parts = value.split()
        port, protocol, address = '', '', value
        if parts and re.fullmatch(r'\d{1,5}(?:[:-]\d{1,5})?(?:/(?:tcp|udp))?', parts[-1], re.I):
            candidate = parts.pop()
            if '/' in candidate:
                port, protocol = candidate.rsplit('/', 1)
            else:
                port = candidate
            address = ' '.join(parts).strip() or 'any'
        try:
            if address != 'any':
                address = str(ipaddress.ip_network(address, strict=False))
                family_hint = 'ip6' if ipaddress.ip_network(address).version == 6 else 'ip'
        except ValueError:
            raise Problem('This UFW rule has a format the timed rollback cannot safely reconstruct; deletion was cancelled.', 409)
        return address, port, protocol.lower(), interface, family_hint

    destination, destination_port, destination_protocol, out_iface, destination_family = endpoint(target)
    source_address, source_port, source_protocol, in_iface, source_family = endpoint(source)
    protocol = destination_protocol or source_protocol
    if source_protocol and destination_protocol and source_protocol != destination_protocol:
        raise Problem('This UFW rule has conflicting protocols; deletion was cancelled because safe rollback cannot be guaranteed.', 409)
    family_hint = 'ip6' if 'ip6' in (source_family, destination_family) else 'ip'
    args = ['route', 'insert', str(number), action] if direction == 'FWD' else ['insert', str(number), action]
    if direction in ('IN', 'OUT'):
        args.append(direction.lower())
    if in_iface:
        args += ['in', 'on', in_iface]
    if out_iface:
        args += ['out', 'on', out_iface]
    if source_address != 'any' or source_port:
        args += ['from', source_address]
    elif destination == 'any' and not has_ipv4_ipv6_pair:
        args += ['from', '::/0' if family_hint == 'ip6' else '0.0.0.0/0']
    if source_port:
        args += ['port', source_port]
    if destination != 'any' or destination_port:
        args += ['to', destination]
    if destination_port:
        args += ['port', destination_port]
    if protocol:
        args += ['proto', protocol]
    if marker and comment.strip():
        args += ['comment', comment.strip()]
    return args


@app.get('/api/ufw')
def ufw_status():
    detection = current_detection()
    if detection['selected_backend'] != 'ufw':
        raise Problem('UFW is not the selected active manager.', 409)
    payload, rules, token = _ufw_state()
    return jsonify(status=payload['verbose'], rules=rules, state_token=token,
                   defaults=next((line.split(':', 1)[1].strip()
                                  for line in payload['verbose'].splitlines()
                                  if line.lower().startswith('default:')), None),
                   ipv6=payload['ipv6'], numbered=payload['numbered'])


@app.post('/api/ufw/rule')
def ufw_add_rule():
    d = data()
    action = text(d, 'action')
    kind = text(d, 'kind', 'port')
    if kind not in ('port', 'route') or action not in ('allow', 'deny', 'reject', 'limit'):
        raise Problem('Choose a supported UFW rule type and allow, deny, reject, or limit action.')
    if kind == 'route' and action == 'limit':
        raise Problem('UFW does not support limit route rules.')
    protocol = text(d, 'protocol', 'tcp')
    if protocol not in ('tcp', 'udp'):
        raise Problem('Protocol must be tcp or udp.')

    def network(key):
        value = text(d, key, 'any', 128)
        if value in ('any', 'anywhere'):
            return 'any'
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            raise Problem(f'{key.replace("_", " ").title()} must be a valid IPv4 or IPv6 address or network.')

    source, destination = network('source'), network('destination')
    source_port = service_port(text(d, 'source_port')) if text(d, 'source_port') else ''
    port_value = text(d, 'port')
    port = service_port(port_value) if port_value else ''
    if kind == 'port' and not port:
        raise Problem('A destination port or port range is required for a port rule.')
    if kind == 'route' and source == 'any' and destination == 'any' and not port:
        raise Problem('A route rule must identify a source, destination, or destination port.')
    interface_in, interface_out = text(d, 'interface_in'), text(d, 'interface_out')
    interfaces = {name for _, name in socket.if_nameindex()}
    for interface in (interface_in, interface_out):
        if interface and (interface not in interfaces
                          or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', interface)):
            raise Problem('Choose an existing network interface.')
    direction = text(d, 'direction')
    if direction not in ('', 'in', 'out'):
        raise Problem('Direction must be in or out.')
    if kind == 'route' and direction:
        raise Problem('Route rules use explicit incoming and outgoing interfaces, not a single direction.')
    if direction and (interface_in or interface_out):
        raise Problem('Choose a direction or an explicit interface binding, not both.')
    comment = text(d, 'comment', '', 120)
    if comment and not re.fullmatch(r'[A-Za-z0-9 .:_-]+', comment):
        raise Problem('Comment may contain letters, numbers, spaces, and . : _ - only.')

    args = (['route'] if kind == 'route' else []) + [action]
    if direction:
        args.append(direction)
    if interface_in:
        args += ['in', 'on', interface_in]
    if interface_out:
        args += ['out', 'on', interface_out]
    if source != 'any':
        args += ['from', source]
        if source_port:
            args += ['port', source_port]
    elif source_port:
        args += ['from', 'any', 'port', source_port]
    if destination != 'any' or port:
        args += ['to', destination]
    if port:
        args += ['port', port]
    if port or source_port:
        args += ['proto', protocol]
    if comment:
        args += ['comment', comment]
    if (kind == 'port' and source == 'any' and destination == 'any'
            and not source_port and not direction and not interface_in and not interface_out
            and port and not comment):
        args = [action, f'{port}/{protocol}']

    with LOCK:
        before, _, token = _ufw_state()
        _require_state_token(d, token)
        saved = backup()
        before, _, token = _ufw_state()
        _require_state_token(d, token)
        rollback_id = None
        if action in ('deny', 'reject', 'limit'):
            inverse = (['route', 'delete', action, *args[2:]]
                       if kind == 'route' else ['--force', 'delete', *args])
            rollback_id = prepare_rollback('ufw', inverse, before)
        try:
            checked('ufw', args)
            after, _, state_token = _ufw_state()
            if rollback_id:
                if after == before:
                    cancel_rollback(rollback_id)
                    rollback_id = None
                else:
                    commit_rollback(rollback_id, after)
        except Problem:
            if rollback_id:
                cancel_rollback(rollback_id)
            raise
    return jsonify(ok=True, backup=saved, state_token=state_token,
                   pending_rollback_id=rollback_id,
                   message='Rule added through UFW; IPv4/IPv6 handling and persistence remain managed by UFW.')


@app.delete('/api/ufw/rule')
def ufw_delete_rule():
    d = data()
    number, token = integer(d.get('number'), maximum=1000000), text(d, 'token')
    with LOCK:
        before, rules, state_token = _ufw_state()
        _require_state_token(d, state_token)
        found = [rule for rule in rules if rule['number'] == number]
        if len(found) != 1 or not hmac.compare_digest(found[0]['token'], token):
            raise Problem('UFW rule changed or was renumbered. Refresh and select it again.', 409)
        paired = any(
            rule['number'] != number
            and re.sub(r'\s*\(v6\)', '', rule['text']).strip()
            == re.sub(r'\s*\(v6\)', '', found[0]['text']).strip()
            for rule in rules
        )
        inverse = _ufw_rule_insert_args(number, found[0]['text'], paired)
        saved = backup()
        before, rules, state_token = _ufw_state()
        _require_state_token(d, state_token)
        found = [rule for rule in rules if rule['number'] == number]
        if len(found) != 1 or not hmac.compare_digest(found[0]['token'], token):
            raise Problem('UFW rule changed or was renumbered during deletion. Refresh and select it again.', 409)
        rollback_id = prepare_rollback('ufw', inverse, before)
        try:
            checked('ufw', ['--force', 'delete', str(number)])
            after, _, state_token = _ufw_state()
            if after == before:
                cancel_rollback(rollback_id)
                rollback_id = None
            else:
                commit_rollback(rollback_id, after)
        except Problem:
            cancel_rollback(rollback_id)
            raise
    return jsonify(ok=True, backup=saved, state_token=state_token,
                   pending_rollback_id=rollback_id,
                   message='Selected numbered UFW rule deleted after revalidation.')


@app.post('/api/ufw/default')
def ufw_default():
    d = data()
    direction, policy = text(d, 'direction'), text(d, 'policy')
    if direction not in ('incoming', 'outgoing', 'routed') or policy not in ('allow', 'deny', 'reject'):
        raise Problem('Choose incoming, outgoing, or routed and allow, deny, or reject.')
    if text(d, 'confirm') != 'APPLY':
        raise Problem('Default policy changes require typing APPLY.')
    with LOCK:
        before, _, token = _ufw_state()
        _require_state_token(d, token)
        saved = backup()
        before, _, token = _ufw_state()
        _require_state_token(d, token)
        previous = _ufw_policy(before, direction)
        rollback_id = None
        if previous != policy:
            if previous not in ('allow', 'deny', 'reject'):
                raise Problem('The current default policy cannot be safely restored by the timed rollback; no change was made.', 409)
            rollback_id = prepare_rollback('ufw', ['default', previous, direction], before)
        try:
            checked('ufw', ['default', policy, direction])
            after, _, state_token = _ufw_state()
            if rollback_id:
                if after == before:
                    cancel_rollback(rollback_id)
                    rollback_id = None
                else:
                    commit_rollback(rollback_id, after)
        except Problem:
            if rollback_id:
                cancel_rollback(rollback_id)
            raise
    return jsonify(ok=True, backup=saved, state_token=state_token,
                   pending_rollback_id=rollback_id,
                   message=f'UFW default {direction} policy set to {policy}.')


@app.post('/api/ufw/action')
def ufw_action():
    d = data()
    action = text(d, 'action')
    confirmations = {'enable': 'ENABLE', 'disable': 'DISABLE', 'reload': 'RELOAD'}
    if action not in confirmations or text(d, 'confirm') != confirmations[action]:
        raise Problem('Enable, disable, and reload require the corresponding explicit confirmation.')
    with LOCK:
        before, _, token = _ufw_state()
        _require_state_token(d, token)
        saved = backup()
        before, _, token = _ufw_state()
        _require_state_token(d, token)
        args = ['--force', action] if action in ('enable', 'disable') else [action]
        was_active = re.search(r'(?im)^Status:\s*active\s*$', before.get('verbose', '')) is not None
        rollback_id = None
        if action in ('enable', 'disable') and was_active != (action == 'enable'):
            inverse = ['--force', 'disable' if action == 'enable' else 'enable']
            rollback_id = prepare_rollback('ufw', inverse, before)
        try:
            checked('ufw', args)
            after, _, state_token = _ufw_state()
            if rollback_id:
                if after == before:
                    cancel_rollback(rollback_id)
                    rollback_id = None
                else:
                    commit_rollback(rollback_id, after)
        except Problem:
            if rollback_id:
                cancel_rollback(rollback_id)
            raise
    return jsonify(ok=True, backup=saved, state_token=state_token,
                   pending_rollback_id=rollback_id,
                   message=f'UFW {action} completed through the UFW command interface.')


def _firewalld_zones(permanent=False):
    args = ['--get-zones']
    if permanent:
        args.insert(0, '--permanent')
    return checked('firewall-cmd', args).split()


def _firewalld_policies(permanent=False):
    args = ['--get-policies']
    if permanent:
        args.insert(0, '--permanent')
    out, error, rc = run('firewall-cmd', args)
    if rc and ('INVALID_OPTION' in error or 'INVALID_OPTION' in out):
        return []
    if rc:
        raise Problem(error.strip() or out.strip() or 'Could not list firewalld policies.', 503)
    return out.split()


def _split_firewalld_zones(output):
    zones, current = {}, None
    for line in output.splitlines():
        if line and not line[:1].isspace():
            match = re.fullmatch(r'([A-Za-z0-9_.-]+)(?:\s+\([^\r\n]*\))?\s*', line)
            if not match or match.group(1) in zones:
                raise Problem('Could not parse firewalld zone inventory safely.', 503)
            current = match.group(1)
            zones[current] = [line]
        elif current is not None:
            zones[current].append(line)
        elif line.strip():
            raise Problem('Could not parse firewalld zone inventory safely.', 503)
    return {name: '\n'.join(lines).rstrip() for name, lines in zones.items()}


def _parse_firewalld_list_all(output):
    values = {}
    for line in output.splitlines():
        entry = line.strip()
        if entry.startswith('rule '):
            values['rich rules'] = '\n'.join(filter(
                None, (values.get('rich rules', ''), entry)))
            continue
        key, separator, value = entry.partition(':')
        if separator:
            values[key] = value.strip()
    return values


def _firewalld_zone(zone, permanent=False):
    args = [f'--zone={zone}', '--list-all']
    if permanent:
        args.insert(0, '--permanent')
    return _parse_firewalld_list_all(checked('firewall-cmd', args))


def _firewalld_policy(policy, permanent=False):
    args = [f'--policy={policy}', '--list-all']
    if permanent:
        args.insert(0, '--permanent')
    return _parse_firewalld_list_all(checked('firewall-cmd', args))


def _firewalld_zone(zone, permanent=False):
    args = [f'--zone={zone}', '--list-all']
    if permanent:
        args.insert(0, '--permanent')
    return _parse_firewalld_list_all(checked('firewall-cmd', args))


def _firewalld_state():
    runtime_zones, permanent_zones = _firewalld_zones(), _firewalld_zones(True)
    runtime = _split_firewalld_zones(checked('firewall-cmd', ['--list-all-zones']))
    permanent = _split_firewalld_zones(checked('firewall-cmd', ['--permanent', '--list-all-zones']))
    if (set(runtime) != set(runtime_zones) or set(permanent) != set(permanent_zones)
            or set(runtime) != set(permanent)):
        raise Problem('Firewalld zone inventory changed or was incomplete; refresh before writing.', 409)
    zones = {
        zone: {'runtime': _parse_firewalld_list_all(runtime[zone]),
               'permanent': _parse_firewalld_list_all(permanent[zone])}
        for zone in sorted(set(runtime_zones) | set(permanent_zones))
    }
    runtime_policies, permanent_policies = _firewalld_policies(), _firewalld_policies(True)
    policies = {
        policy: {'runtime': _firewalld_policy(policy),
                 'permanent': _firewalld_policy(policy, True)}
        for policy in sorted(set(runtime_policies) | set(permanent_policies))
    }
    active = checked('firewall-cmd', ['--get-active-zones'])
    default_zone = checked('firewall-cmd', ['--get-default-zone']).strip()
    # firewalld exposes one default-zone setting; --permanent is invalid here.
    return {'zones': zones, 'policies': policies, 'active_zones': active,
            'default_zone': default_zone, 'permanent_default_zone': default_zone}


def manager_state(manager):
    if manager == 'ufw':
        return _ufw_state()[0]
    if manager == 'firewalld':
        return _firewalld_state()
    raise Problem('Rollback is supported only for native manager operations.', 400)


def _rollback_path(rollback_id):
    if not re.fullmatch(r'[0-9a-f]{32}', rollback_id):
        raise Problem('Invalid rollback identifier.')
    return ROLLBACK_DIR / f'{rollback_id}.json'


def _write_rollback(record):
    private_write(_rollback_path(record['id']), json.dumps(record, sort_keys=True) + '\n')


def prepare_rollback(manager, inverse_args, before):
    if manager not in ('ufw', 'firewalld') or not isinstance(inverse_args, list) or not inverse_args:
        raise Problem('Invalid rollback plan.', 500)
    if not all(isinstance(arg, str) and '\x00' not in arg for arg in inverse_args):
        raise Problem('Invalid rollback arguments.', 500)
    ROLLBACK_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(ROLLBACK_DIR, 0o700)
    rollback_id = uuid.uuid4().hex
    record = {
        'version': 1, 'id': rollback_id,
        'manager': manager,
        'inverse_args': inverse_args,
        'before': before, 'expected_after': None,
        'created_at': time.time(), 'deadline': time.time() + max(600, ROLLBACK_SECONDS),
        'status': 'pending', 'message': 'Waiting for administrator confirmation.',
    }
    _write_rollback(record)
    try:
        if Path('/run/systemd/system').is_dir() and executable('systemd-run'):
            env_args = ['--setenv=NFT_ROLLBACK_DIR=' + str(ROLLBACK_DIR)]
            backend_setting = os.environ.get('NFT_BACKEND')
            if backend_setting:
                env_args.append('--setenv=NFT_BACKEND=' + backend_setting)
            checked('systemd-run', [
                '--quiet', '--collect', '--unit=firewall-web-rollback-' + rollback_id,
                '--on-active=1s', *env_args, '--',
                sys.executable, str(Path(__file__).resolve()), '--rollback', rollback_id,
            ])
        else:
            # A detached worker survives a dropped browser connection or web-process exit.
            worker_env = {'PATH': PATH, 'NFT_ROLLBACK_DIR': str(ROLLBACK_DIR),
                          'NFT_BACKEND': os.environ.get('NFT_BACKEND', 'auto')}
            subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), '--rollback', rollback_id],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                close_fds=True, start_new_session=True, env=worker_env,
            )
    except (Problem, OSError) as exc:
        _rollback_path(rollback_id).unlink(missing_ok=True)
        if isinstance(exc, Problem):
            raise
        raise Problem(f'Could not start the rollback worker: {exc}', 503)
    return rollback_id


@contextmanager
def rollback_lock(rollback_id):
    lock_path = _rollback_path(rollback_id).with_suffix('.lock')
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def commit_rollback(rollback_id, expected_after):
    with rollback_lock(rollback_id):
        path = _rollback_path(rollback_id)
        record = json.loads(path.read_text())
        if record.get('status') != 'pending':
            raise Problem('Rollback timer is no longer pending.', 409)
        record['expected_after'] = expected_after
        record['message'] = 'Confirm this change before the rollback deadline.'
        _write_rollback(record)


def arm_rollback_confirmation(rollback_id):
    with rollback_lock(rollback_id):
        path = _rollback_path(rollback_id)
        record = json.loads(path.read_text())
        if record.get('status') != 'pending' or record.get('expected_after') is None:
            raise Problem('The change could not be armed for confirmation; refresh the firewall state.', 409)
        record['ready_at'] = time.time()
        record['deadline'] = record['ready_at'] + ROLLBACK_SECONDS
        record['message'] = 'Confirm this change before the rollback deadline.'
        _write_rollback(record)


def cancel_rollback(rollback_id):
    with rollback_lock(rollback_id):
        path = _rollback_path(rollback_id)
        if not path.exists():
            return
        record = json.loads(path.read_text())
        record['status'] = 'cancelled'
        record['message'] = 'Operation did not complete; rollback cancelled.'
        _write_rollback(record)


def confirm_rollback(rollback_id):
    with rollback_lock(rollback_id):
        path = _rollback_path(rollback_id)
        try:
            record = json.loads(path.read_text())
        except OSError:
            raise Problem('Rollback request was not found or has expired.', 404)
        if record.get('status') != 'pending':
            raise Problem(f'Rollback is {record.get("status", "unavailable")}; refresh the firewall state.', 409)
        record['status'] = 'confirmed'
        record['message'] = 'Administrator confirmed the change; the timed rollback will not run.'
        _write_rollback(record)
        return record


def run_rollback(rollback_id):
    path = _rollback_path(rollback_id)
    while path.exists():
        with rollback_lock(rollback_id):
            try:
                record = json.loads(path.read_text())
            except OSError:
                return
            if record.get('status') != 'pending':
                return
            remaining = record.get('deadline', 0) - time.time()
            if remaining <= 0:
                try:
                    if record.get('expected_after') is None:
                        record['status'] = 'conflict'
                        record['message'] = 'The operation did not record its resulting state; no rollback was attempted.'
                    else:
                        current = manager_state(record['manager'])
                        detection = detect_firewall()
                        if (not can_manage_firewall() or detection['selected_backend'] != record['manager']
                                or current != record['expected_after']):
                            record['status'] = 'conflict'
                            record['message'] = ('Firewall manager state changed after the operation; rollback was skipped '
                                                 'to preserve concurrent changes. Review the current rules manually.')
                        else:
                            command = 'ufw' if record['manager'] == 'ufw' else 'firewall-cmd'
                            checked(command, record['inverse_args'])
                            record['status'] = 'rolled_back'
                            record['message'] = 'The unconfirmed change was selectively rolled back.'
                except (Problem, OSError, ValueError, KeyError) as exc:
                    record['status'] = 'conflict'
                    record['message'] = 'Rollback failed safely: ' + (
                        exc.message if isinstance(exc, Problem) else str(exc))
                _write_rollback(record)
                return
        # Re-read deadlines and confirmations; never sleep while holding the record lock.
        time.sleep(min(remaining, 1.0))


@app.get('/api/rollback/<rollback_id>')
def rollback_status(rollback_id):
    try:
        record = json.loads(_rollback_path(rollback_id).read_text())
    except OSError:
        raise Problem('Rollback request was not found or has expired.', 404)
    return jsonify(id=rollback_id, status=record.get('status'),
                   deadline=record.get('deadline'), message=record.get('message'))


@app.post('/api/rollback/<rollback_id>/confirm')
def rollback_confirm(rollback_id):
    if text(data(), 'confirm') != 'KEEP':
        raise Problem('Type KEEP to cancel the scheduled rollback.')
    record = confirm_rollback(rollback_id)
    return jsonify(ok=True, status=record['status'], message=record['message'])


@app.get('/api/firewalld')
def firewalld_status():
    detection = current_detection()
    if detection['selected_backend'] != 'firewalld':
        raise Problem('firewalld is not the selected active manager.', 409)
    state = _firewalld_state()
    state_token = signature(configuration_only(state))
    return jsonify(version=_probe('firewall-cmd', ['--version']).get('output'),
                   active_zones=detection['managers']['firewalld']['active_zones'],
                   default_zone=state['default_zone'],
                   permanent_default_zone=state['permanent_default_zone'],
                   zones=state['zones'], policies=state['policies'],
                   capabilities=detection['managers']['firewalld'].get('capabilities', {}),
                   state_token=state_token)


@app.post('/api/firewalld/rule')
def firewalld_rule():
    d = data()
    scope, action = text(d, 'scope', 'zone'), text(d, 'action')
    rule_type, value = text(d, 'type'), text(d, 'value')
    state = text(d, 'state')
    if scope not in ('zone', 'policy') or action not in ('add', 'remove') or state not in ('runtime', 'permanent'):
        raise Problem('Choose add/remove and runtime/permanent.')
    inventory = _firewalld_state()
    state_token = signature(configuration_only(inventory))
    _require_state_token(d, state_token)
    capabilities = current_detection()['managers']['firewalld'].get('capabilities', {})
    if scope == 'zone':
        zone = text(d, 'zone')
        if zone not in inventory['zones']:
            raise Problem('Select an installed firewalld zone.')
        target = [f'--zone={zone}']
    else:
        policy = text(d, 'policy')
        if not current_detection()['managers']['firewalld'].get('capabilities', {}).get('policies'):
            raise Problem('This firewalld version does not support policies; that control is unavailable.', 409)
        if policy not in inventory['policies']:
            raise Problem('Select an installed firewalld policy.')
        target = [f'--policy={policy}']
    if scope == 'policy' and rule_type in ('source', 'interface'):
        raise Problem('Source and interface bindings belong to zones, not firewalld policies.')
    if rule_type == 'port':
        port = service_port(value).replace(':', '-')
        protocol = text(d, 'protocol', 'tcp')
        if protocol not in ('tcp', 'udp'):
            raise Problem('Protocol must be tcp or udp.')
        value = f'{port}/{protocol}'
        option = 'port'
    elif rule_type == 'service':
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', value):
            raise Problem('Invalid firewalld service name.')
        if value not in checked('firewall-cmd', ['--get-services']).split():
            raise Problem('Service is not available in firewalld.')
        option = 'service'
    elif rule_type == 'source':
        if not capabilities.get('source_bindings'):
            raise Problem('This firewalld version does not support source bindings; that control is unavailable.', 409)
        if value.startswith('ipset:'):
            value = 'ipset:' + identifier(value[6:])
        else:
            try:
                value = str(ipaddress.ip_network(value, strict=False))
            except ValueError:
                if not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', value):
                    raise Problem('Source binding must be an IPv4/IPv6 network, MAC address, or ipset name.')
                value = value.lower()
        option = 'source'
    elif rule_type == 'interface':
        if not capabilities.get('zone_bindings'):
            raise Problem('This firewalld version does not support interface bindings; that control is unavailable.', 409)
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', value):
            raise Problem('Invalid firewalld interface name.')
        option = 'interface'
    elif rule_type == 'rich-rule':
        if (len(value) > 2048 or any(ord(char) < 32 or ord(char) == 127 for char in value)
                or not value.startswith('rule ')):
            raise Problem('Enter one firewalld rich rule beginning with "rule " and no control characters.')
        if not current_detection()['managers']['firewalld'].get('capabilities', {}).get('rich_rules'):
            raise Problem('This firewalld version does not support rich rules; that control is unavailable.', 409)
        option = 'rich-rule'
    else:
        raise Problem('Unsupported firewalld rule type.')
    command = [*target, f'--{action}-{option}={value}']
    if state == 'permanent':
        command.insert(0, '--permanent')
    with LOCK:
        current = _firewalld_state()
        _require_state_token(d, signature(configuration_only(current)))
        selected = zone if scope == 'zone' else policy
        if selected not in current['zones' if scope == 'zone' else 'policies']:
            raise Problem(f'Selected firewalld {scope} is no longer available.', 409)
        saved = backup()
        current = _firewalld_state()
        _require_state_token(d, signature(configuration_only(current)))
        before = current
        rollback_id = prepare_rollback(
            'firewalld',
            [*target, f'--{("remove" if action == "add" else "add")}-{option}={value}',
             *( ['--permanent'] if state == 'permanent' else [])],
            before,
        )
        try:
            checked('firewall-cmd', command)
            after = _firewalld_state()
            state_token = signature(configuration_only(after))
            if configuration_only(after) == configuration_only(before):
                cancel_rollback(rollback_id)
                rollback_id = None
            else:
                commit_rollback(rollback_id, after)
        except Problem:
            cancel_rollback(rollback_id)
            raise
    return jsonify(ok=True, backup=saved,
                   state_token=state_token,
                   pending_rollback_id=rollback_id,
                   message=f'{rule_type.title()} {value} {action}ed in {selected} {scope} {state} configuration. Runtime and permanent state were not conflated.')


@app.post('/api/firewalld/reload')
def firewalld_reload():
    d = data()
    if text(d, 'confirm') != 'RELOAD':
        raise Problem('Reloading firewalld requires typing RELOAD.')
    with LOCK:
        current = _firewalld_state()
        _require_state_token(d, signature(current))
        saved = backup()
        _require_state_token(d, signature(_firewalld_state()))
        checked('firewall-cmd', ['--reload'])
        state_token = signature(_firewalld_state())
    return jsonify(ok=True, backup=saved, state_token=state_token,
                   message='firewalld reloaded its permanent configuration.')


@app.get('/api/rules')
def rules():
    b = request.args.get('backend', 'nft')
    if b != 'nft' and b not in BACKENDS:
        raise Problem('Invalid backend.')
    return jsonify(nft_state() if b == 'nft' else ipt_state(b))


@app.get('/api/overview')
def overview():
    return jsonify(capture())


@app.get('/api/export')
def export():
    return Response(json.dumps(capture(), indent=2), mimetype='application/json',
                    headers={'Content-Disposition': 'attachment; filename=firewall-backup.json'})


@app.post('/api/backup')
def save_backup():
    with LOCK:
        return jsonify(ok=True, backup=backup())


@app.post('/api/persist/iptables')
def persist_iptables():
    if text(data(), 'confirm') != 'SAVE':
        raise Problem('Persistence requires confirmation.')
    required = ('netfilter-persistent', 'systemctl', 'iptables-save', 'ip6tables-save',
                'iptables-restore', 'ip6tables-restore')
    if any(not executable(n) for n in required) or any(not os.access(p, os.X_OK) for p in IPT_PLUGINS):
        raise Problem('Install iptables-persistent and netfilter-persistent with both IPv4/IPv6 plugins first. systemd and both save/restore commands are required.', 503)
    with LOCK:
        detection = _require_selected_write_backend('iptables')
        if not {'iptables', 'ip6tables'}.issubset(detection['write_backends']):
            raise Problem('Both system-default IP families must be selected writable backends.', 409)
        # Fail before writing if either IP family cannot be read.
        checked('iptables-save')
        checked('ip6tables-save')
        saved = backup('iptables')
        config_saved = config_backup(IPT_FILES)
        _require_selected_write_backend('iptables')
        checked('netfilter-persistent', ['save'])
        for path, saver, restorer in zip(IPT_FILES, ('iptables-save', 'ip6tables-save'),
                                        ('iptables-restore', 'ip6tables-restore')):
            if not path.is_file():
                raise Problem(f'Save did not produce {path}. Some persistence files may have changed; boot persistence is not confirmed.', 500)
            content = path.read_text()
            if canonical_save(content) != canonical_save(checked(saver)):
                raise Problem(f'{path} does not match current rules. Check plugin skip-save settings or concurrent changes, then retry. Some files may have been updated.', 409)
            checked(restorer, ['--test'], stdin=content)
        _require_selected_write_backend('iptables')
        enable_boot_service('netfilter-persistent.service')
    return jsonify(ok=True, backup=saved, configuration_backup=config_saved,
                   files=[str(p) for p in IPT_FILES],
                   message='IPv4 and IPv6 rules saved and validated. netfilter-persistent is enabled to restore them at boot. Uses system-default iptables/ip6tables backends.')


@app.post('/api/persist/nft')
def persist_nft():
    if text(data(), 'confirm') != 'SAVE':
        raise Problem('Persistence requires confirmation.')
    if not executable('nft') or not executable('systemctl'):
        raise Problem('nftables and systemd are required for native persistence.', 503)
    with LOCK:
        _require_selected_write_backend('nftables')
        saved = backup('nft')
        state, owned = nft_state(), compatibility_tables()
        tables = []
        for table in state['tables']:
            f, name = table['family'], identifier(table['name'])
            if (f, name) in owned:
                continue
            raw = checked('nft', ['-n', 'list', 'table', f, name])
            tables.append({'family': f, 'name': name, 'rules': raw})
        payload = {'version': 1, 'tables': tables, 'created_utc': datetime.now(timezone.utc).isoformat()}
        present = {(x['family'], x['name']) for x in state['tables']}
        if tables:
            # Validate the replacement transaction without applying it.
            checked('nft', ['-c', '-f', '-'], stdin=native_restore_script(payload, present))
        config_saved = config_backup((NATIVE_STATE, NATIVE_UNIT))
        _require_selected_write_backend('nftables')
        private_write(NATIVE_STATE, json.dumps(payload, indent=2) + '\n')
        command = ' '.join((unit_quote(sys.executable), unit_quote(Path(__file__).resolve()), '--restore-native'))
        unit = (
            '[Unit]\nDescription=firewall_web native firewall restore\nDefaultDependencies=no\n'
            'After=local-fs.target systemd-modules-load.service nftables.service netfilter-persistent.service\n'
            'Before=network-pre.target shutdown.target\nWants=network-pre.target\nConflicts=shutdown.target\n\n'
            '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
            'Environment=' + unit_quote('NFT_NATIVE_STATE=' + str(NATIVE_STATE.resolve())) + '\n'
            'ExecStart=' + command + '\n\n[Install]\nWantedBy=multi-user.target\n'
        )
        private_write(NATIVE_UNIT, unit)
        NATIVE_UNIT.chmod(0o644)
        _require_selected_write_backend('nftables')
        checked('systemctl', ['daemon-reload'])
        _require_selected_write_backend('nftables')
        enable_boot_service('nft-web-restore.service')
    return jsonify(ok=True, backup=saved, configuration_backup=config_saved,
                   native_tables=len(tables), excluded_iptables_tables=len(owned),
                   message=f'{len(tables)} native nftables tables saved; boot restore enabled. iptables-nft tables are excluded: use Persist IPv4 + IPv6 for those. Keep this script and its Python environment at their installed paths.')


@app.post('/api/nft/rule')
def nft_add_rule():
    d = data()
    f, t, c = family(d), identifier(text(d, 'table')), identifier(text(d, 'chain'))
    expression = one_expression(text(d, 'rule'))
    operation = text(d, 'operation', 'add')
    if operation not in ('add', 'insert'):
        raise Problem('Operation must be add or insert.')
    with LOCK:
        saved = backup('nft')
        nft_script(f'{operation} rule {f} {t} {c} {expression}')
    return jsonify(ok=True, backup=saved)


@app.delete('/api/nft/rule')
def nft_delete_rule():
    d = data()
    f, t, c = family(d), identifier(text(d, 'table')), identifier(text(d, 'chain'))
    handle, token = integer(d.get('handle')), text(d, 'token')
    with LOCK:
        candidates = [r for r in nft_state()['rules'] if
                      (r['family'], r['table'], r['chain'], r['handle']) == (f, t, c, handle)]
        if not candidates or not hmac.compare_digest(candidates[0]['token'], token):
            raise Problem('Rule changed or disappeared. Refresh and select it again.', 409)
        saved = backup('nft')
        nft_script(f'delete rule {f} {t} {c} handle {handle}')
    return jsonify(ok=True, backup=saved)


@app.post('/api/nft/chain')
def nft_create_chain():
    d = data()
    f, t, c = family(d), identifier(text(d, 'table')), identifier(text(d, 'chain'))
    hook = text(d, 'hook')
    if f not in ('ip', 'ip6', 'inet'):
        raise Problem('This chain builder supports ip, ip6 and inet. Use Advanced for other families.')
    clause = ''
    if hook:
        kind, policy = text(d, 'type', 'filter'), text(d, 'policy', 'accept')
        if hook not in ('input', 'output', 'forward', 'prerouting', 'postrouting') or kind not in ('filter', 'nat', 'route') or policy not in ('accept', 'drop'):
            raise Problem('Invalid chain settings.')
        priority = integer(d.get('priority', 0), -30000, 30000)
        clause = f' {{ type {kind} hook {hook} priority {priority}; policy {policy}; }}'
    with LOCK:
        saved = backup('nft')
        # A transaction: do not partially create a table if chain creation fails.
        nft_script(f'add table {f} {t}\ncreate chain {f} {t} {c}{clause}')
    return jsonify(ok=True, backup=saved)


@app.post('/api/iptables/rule')
def ipt_add_rule():
    d = data()
    b, t, c = backend(d), identifier(text(d, 'table', 'filter')), identifier(text(d, 'chain', 'INPUT'))
    if t not in TABLES:
        raise Problem('Invalid iptables table.')
    operation = text(d, 'operation', 'append')
    if operation not in ('append', 'insert'):
        raise Problem('Operation must be append or insert.')
    args = ['-w', '5', '-t', t, '-A' if operation == 'append' else '-I', c]
    if operation == 'insert':
        args.append(str(integer(d.get('position', 1), maximum=1000000)))
    args += ipt_expression(text(d, 'rule'))
    with LOCK:
        saved = backup(b)
        checked(b, args)
    return jsonify(ok=True, backup=saved)


@app.post('/api/iptables/port')
def ipt_service_port():
    d = data()
    ipv4, ipv6, stateless = checkbox(d, 'ipv4', True), checkbox(d, 'ipv6', True), checkbox(d, 'stateless')
    if not (ipv4 or ipv6):
        raise Problem('Select IPv4, IPv6, or both.')
    mode, protocol = text(d, 'mode', 'default'), text(d, 'protocol', 'tcp')
    if mode not in ('default', 'nft', 'legacy') or protocol not in ('tcp', 'udp'):
        raise Problem('Invalid backend mode or protocol.')
    port, iface = service_port(text(d, 'port')), text(d, 'iface')
    if iface and iface not in {n for _, n in socket.if_nameindex()}:
        raise Problem('Choose an existing interface.')
    suffix = '' if mode == 'default' else '-' + mode
    backends = ([backend({'backend': 'iptables' + suffix})] if ipv4 else [])
    backends += ([backend({'backend': 'ip6tables' + suffix})] if ipv6 else [])
    marker, desired = port_rules(protocol, port, iface, stateless)
    with LOCK:
        plans = []
        # Read and validate every selected family before changing either one.
        for b in backends:
            state = ipt_state(b)
            remove, add = port_plan(state, marker, desired)
            if remove or add:
                checked(b + '-restore', ['--test'], stdin=port_test_rules(state, remove, add))
            plans.append((b, remove, add))
        saved = backup(backends[0])
        undo, changed = [], 0
        try:
            for b, remove, add in plans:
                for r in remove:
                    prefix = ['-w', '5', '-t', r['table']]
                    checked(b, [*prefix, '-D', r['chain'], *r['spec']])
                    undo.append((b, [*prefix, '-I', r['chain'], str(r['number']), *r['spec']]))
                    changed += 1
                for r in add:
                    prefix = ['-w', '5', '-t', r['table']]
                    checked(b, [*prefix, '-I', r['chain'], '1', *r['spec']])
                    undo.append((b, [*prefix, '-D', r['chain'], *r['spec']]))
                    changed += 1
        except Problem as exc:
            failures = []
            for b, args in reversed(undo):
                try:
                    checked(b, args)
                except Problem as rollback_error:
                    failures.append(rollback_error.message)
            note = ('Rollback errors: ' + '; '.join(failures)) if failures else 'Confirmed changes from this request were rolled back.'
            raise Problem(f'Port update failed: {exc.message} {note} Refresh to verify; a timed-out operation may have completed. Backup: {saved}', 500)
    families = 'IPv4 + IPv6' if ipv4 and ipv6 else 'IPv4' if ipv4 else 'IPv6'
    tracking = 'stateless (NOTRACK)' if stateless else 'normal connection tracking'
    return jsonify(ok=True, backup=saved, backends=backends, changed=changed,
                   message=f'{protocol.upper()} service port {port}: {families}, {tracking}. {changed} rule changes. Save in Persistence for boot restoration.')


@app.delete('/api/iptables/rule')
def ipt_delete_rule():
    d = data()
    b, t, c, token = backend(d), identifier(text(d, 'table')), identifier(text(d, 'chain')), text(d, 'token')
    with LOCK:
        found = [r for r in ipt_state(b)['rules'] if r['table'] == t and r['chain'] == c and hmac.compare_digest(r['token'], token)]
        if not found:
            raise Problem('Rule changed or disappeared. Refresh and select it again.', 409)
        saved = backup(b)
        # Exact saved specification, not a stale line number or client-supplied argv.
        checked(b, ['-w', '5', '-t', t, '-D', c, *found[0]['spec']])
    return jsonify(ok=True, backup=saved)


@app.post('/api/iptables/chain')
def ipt_chain():
    d = data()
    b, t, c = backend(d), identifier(text(d, 'table', 'filter')), identifier(text(d, 'chain'))
    if t not in TABLES:
        raise Problem('Invalid iptables table.')
    action = text(d, 'action', 'create')
    if action == 'create':
        args = ['-N', c]
    elif action == 'policy':
        policy = text(d, 'policy', 'ACCEPT')
        if policy not in ('ACCEPT', 'DROP'):
            raise Problem('Policy must be ACCEPT or DROP.')
        args = ['-P', c, policy]
    else:
        raise Problem('Invalid chain action.')
    with LOCK:
        saved = backup(b)
        checked(b, ['-w', '5', '-t', t, *args])
    return jsonify(ok=True, backup=saved)


@app.post('/api/masquerade')
def masquerade():
    d = data()
    engine, action = text(d, 'engine', 'nft'), text(d, 'action', 'enable')
    if action not in ('enable', 'disable'):
        raise Problem('Invalid masquerade action.')
    iface, source = text(d, 'iface'), text(d, 'source')
    if iface and iface not in {n for _, n in socket.if_nameindex()}:
        raise Problem('Choose an existing outgoing interface.')
    f = text(d, 'family', 'ip')
    if engine != 'nft':
        b = backend({'backend': engine})
        f = 'ip6' if b.startswith('ip6tables') else 'ip'
    elif f not in ('ip', 'ip6'):
        raise Problem('Choose ip or ip6 for masquerading.')
    if source:
        try:
            network = ipaddress.ip_network(source, strict=False)
        except ValueError:
            raise Problem('Invalid source subnet.')
        if network.version != (6 if f == 'ip6' else 4):
            raise Problem('Source subnet does not match the IP family.')
        source = str(network)
    marker = 'nft-web:masq:' + hashlib.sha256(json.dumps([iface, source]).encode()).hexdigest()[:16]
    with LOCK:
        saved = backup(engine)
        if engine == 'nft':
            t, c = identifier(text(d, 'table', 'nft_web_nat')), 'postrouting'
            state = nft_state()
            found = [r for r in state['rules'] if r['family'] == f and r['table'] == t and r['chain'] == c and r.get('comment') == marker]
            if action == 'disable':
                for r in found:
                    nft_script(f'delete rule {f} {t} {c} handle {r["handle"]}')
            elif not found:
                commands = []
                if not any(x['family'] == f and x['name'] == t for x in state['tables']):
                    commands.append(f'add table {f} {t}')
                chain = next((x for x in state['chains'] if x['family'] == f and x['table'] == t and x['name'] == c), None)
                if chain and (chain.get('type') != 'nat' or chain.get('hook') != 'postrouting'):
                    raise Problem('Existing postrouting chain is not a NAT/postrouting base chain.')
                if not chain:
                    commands.append(f'add chain {f} {t} {c} {{ type nat hook postrouting priority 100; policy accept; }}')
                expr = (f'{f} saddr {source} ' if source else '')
                expr += (f'oifname {json.dumps(iface)} ' if iface else '')
                commands.append(f'add rule {f} {t} {c} {expr}counter masquerade comment "{marker}"')
                nft_script('\n'.join(commands))
        else:
            args = (['-s', source] if source else []) + (['-o', iface] if iface else [])
            args += ['-m', 'comment', '--comment', marker, '-j', 'MASQUERADE']
            _, error, rc = run(b, ['-w', '5', '-t', 'nat', '-C', 'POSTROUTING', *args])
            if rc not in (0, 1):
                raise Problem(error.strip() or 'Cannot check NAT rule.', 422)
            if action == 'enable' and rc == 1:
                checked(b, ['-w', '5', '-t', 'nat', '-A', 'POSTROUTING', *args])
            elif action == 'disable' and rc == 0:
                checked(b, ['-w', '5', '-t', 'nat', '-D', 'POSTROUTING', *args])
    return jsonify(ok=True, backup=saved, message='Matching managed masquerade rule ' + ('enabled.' if action == 'enable' else 'disabled.'))


@app.post('/api/exec')
def advanced():
    d = data()
    if text(d, 'confirm') != 'RUN':
        raise Problem('Type RUN to execute an advanced command.')
    engine, command = text(d, 'engine', 'nft'), text(d, 'cmd', maximum=32768)
    if not command:
        raise Problem('Command is required.')
    with LOCK:
        if engine == 'nft':
            if command.startswith('nft '):
                command = command[4:]
            # This is an intentionally powerful authenticated admin console.
            # No CLI options, includes, file reads, monitor jobs or shell execution.
            if not re.match(r'^(list|get|add|create|insert|replace|delete|flush|reset|destroy)\s', command):
                raise Problem('Use an nft command beginning with list/get/add/create/insert/replace/delete/flush/reset/destroy.')
            if re.search(r'(^|[;\n])\s*(include|import|export|monitor)\b', command):
                raise Problem('File directives and monitoring are not supported.')
            saved = backup('nft')
            out = nft_script(command)
        else:
            b = backend({'backend': engine})
            try:
                args = shlex.split(command)
            except ValueError as exc:
                raise Problem(str(exc))
            if args and args[0] == b:
                args.pop(0)
            if not args or any(a in ('|', '&&', '||', ';', '>','<') or a.startswith('-M') or a.split('=', 1)[0] in ('--modprobe', '--help', '-h') for a in args):
                raise Problem('Use one iptables argument list. Shell operators and helper-program options are disabled.')
            saved = backup(b)
            out = checked(b, ['-w', '5', *args])
    return jsonify(ok=True, output=out or '(no output)', backup=saved)


HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>firewall_web | Mini firewall</title><style>
:root{color-scheme:dark;--bg:#0d1117;--panel:#161b22;--line:#30363d;--muted:#919baa;--blue:#58a6ff;--green:#3fb950;--red:#ff7b72}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:#d7dfe8;font:14px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace}
main{max-width:1480px;margin:auto;padding:24px}h1{margin:0;color:var(--blue);font-size:25px}h2{font-size:16px;margin:0 0 14px}h3{font-size:14px;margin:0}p{margin:8px 0}.muted{color:var(--muted);font-size:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:20px;margin:16px 0}.row{display:flex;align-items:end;flex-wrap:wrap;gap:10px}.between{justify-content:space-between;align-items:center}
button,input,select,textarea{font:inherit;border:1px solid var(--line);border-radius:5px;padding:8px 10px;background:#0d1117;color:inherit}button{cursor:pointer;background:#21262d}button:hover{border-color:var(--blue)}button:disabled{opacity:.5;cursor:wait}button.primary{color:var(--blue);border-color:var(--blue)}button.danger{color:var(--red)}button.good{color:var(--green)}button:focus-visible,input:focus,textarea:focus,select:focus{outline:2px solid var(--blue);outline-offset:2px}
label{display:flex;flex-direction:column;gap:5px;color:var(--muted);font-size:12px}input,select{min-width:100px;max-width:100%}textarea{width:100%;min-height:90px;resize:vertical}.wide{flex:1;min-width:240px}.small{width:110px}.hidden{display:none!important}
pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:650px;overflow:auto;font-size:12px;padding:12px;background:#0d1117;border-radius:5px}summary{cursor:pointer;color:var(--blue);padding:10px 0}.rules{width:100%;border-collapse:collapse;font-size:12px}.rules th,.rules td{text-align:left;border-bottom:1px solid var(--line);padding:10px 8px;vertical-align:top}.rules td.expr{overflow-wrap:anywhere;white-space:pre-wrap;min-width:180px}.scroll{overflow-x:auto;max-width:100%}
.badge{display:inline-block;border:1px solid var(--line);border-radius:12px;padding:2px 9px;margin:4px;font-size:12px}.notice{border-left:3px solid var(--blue);padding-left:12px}.warning{border-left-color:#d29922}#toast{position:fixed;right:20px;bottom:20px;max-width:min(650px,90vw);white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid var(--green);background:#10251b;padding:14px;border-radius:7px;z-index:60}#toast.error{border-color:var(--red);background:#351c1c}#connection{font-size:12px;color:var(--muted)}.count{color:var(--green)}#app[aria-busy=true]{opacity:.8}
.app-shell{display:grid;grid-template-columns:220px minmax(0,1fr);gap:26px;align-items:start;margin-top:22px}.sidebar{position:sticky;top:20px;background:#111720;border:1px solid var(--line);border-radius:10px;max-height:calc(100dvh - 40px);overflow:auto;padding:18px 10px}.sidebar-heading{padding:0 12px 16px;color:#d7dfe8;font-weight:600;letter-spacing:1px;font-size:12px}.nav-group{margin:16px 12px 6px;text-transform:uppercase;font-size:10px;letter-spacing:1.5px;color:var(--muted)}.tabs{display:flex;flex-direction:column;gap:5px}.tab{display:flex;align-items:center;gap:12px;min-height:44px;text-align:left;width:100%;padding:10px 12px;border:1px solid transparent;border-left:3px solid transparent;border-radius:5px;background:transparent;color:#a6b1c0}.tab .nav-index{font-size:10px;color:#66778d;min-width:16px}.tab:hover{background:#192331;border-color:transparent}.tab.active{color:#b8dcff;background:#152a40;border-color:#244565;border-left-color:var(--blue)}.tab.active .nav-index{color:var(--blue)}.sidebar-footer{margin:24px 12px 0;padding-top:16px;border-top:1px solid var(--line);font-size:11px;color:var(--muted)}.sidebar-footer strong{display:block;font-size:11px;color:var(--green);margin-bottom:6px}
.workspace{min-width:0}.page-heading{display:flex;align-items:center;gap:12px;padding:4px 0 14px;border-bottom:1px solid var(--line)}#page-title{font-size:22px;color:#edf3fb;margin:0}#page-description{max-width:740px;margin:5px 0 0}.toolbar{margin:16px 0;align-items:center}.toolbar-actions{align-items:center}.toolbar-actions label{flex-direction:row;align-items:center}.toolbar-actions select{min-width:100px}.panel>.card:first-child,.panel>form.card:first-child{margin-top:0}.panel{min-width:0}.action-card p{max-width:850px}.action-card button{margin-top:12px}.menu-toggle,.sidebar-close,.nav-backdrop{display:none}
.checks{display:flex;gap:12px 24px;flex-wrap:wrap;padding:14px 0}.checks label{display:flex;flex-direction:row;align-items:center;gap:8px;font-size:13px;color:#d7dfe8}.checks input[type=checkbox]{appearance:auto;min-width:0;width:18px;height:18px;margin:0;accent-color:var(--blue);flex:none}.checks fieldset{border:0;margin:0;padding:0;display:flex;gap:18px;flex-wrap:wrap}.checks legend{font-size:11px;color:var(--muted);margin-bottom:8px}
@media(max-width:820px){main{padding:16px}.app-shell{grid-template-columns:minmax(0,1fr);gap:0;margin-top:18px}.sidebar{display:none;position:fixed;left:0;top:0;bottom:0;z-index:51;width:250px;max-width:85vw;max-height:none;border-radius:0;border-top:0;border-bottom:0;border-left:0;padding:24px 12px}.sidebar-open .sidebar{display:block}.nav-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:50}.sidebar-open .nav-backdrop{display:block}.menu-toggle{display:inline-flex;align-items:center;gap:8px;min-height:40px}.sidebar-close{display:block;width:100%;margin:20px 0 0;min-height:42px}.drawer-open{overflow:hidden}#page-title{font-size:20px}.toolbar{gap:12px}.toolbar-actions{width:100%;justify-content:space-between}.page-heading{align-items:flex-start}.menu-toggle{flex-shrink:0}}
@media(max-width:600px){main{padding:12px}.card{padding:14px}input,select{width:100%}.row label{flex:1 1 130px;min-width:0}.row .wide{flex-basis:100%;min-width:0}h1{font-size:21px}.toolbar-actions label{flex:0 1 auto}.toolbar-actions select{width:auto}.toolbar-actions{gap:8px}.badge{font-size:11px;margin:2px}.page-heading{flex-wrap:wrap}.page-heading>div{flex:1;min-width:170px}}
</style><style>
:root{--text:#d7dfe8;--control-bg:#0d1117;--button-bg:#21262d;--sidebar-bg:#111720;--sidebar-text:#a6b1c0;--heading-text:#edf3fb;--nav-active-bg:#152a40;--nav-active-text:#b8dcff}
:root[data-theme=light]{color-scheme:light;--bg:#f4f6f8;--panel:#fff;--line:#cbd2d9;--muted:#586575;--blue:#0969da;--green:#1a7f37;--red:#cf222e;--text:#1f2328;--control-bg:#fff;--button-bg:#f3f4f6;--sidebar-bg:#e9edf2;--sidebar-text:#3e4c5c;--heading-text:#1f2328;--nav-active-bg:#dbeafe;--nav-active-text:#084298}
body{color:var(--text);font-size:var(--ui-font-size,14px)}
pre{background:var(--control-bg);color:var(--text)}
.tab .nav-index{color:var(--muted)}
:root[data-theme=light] .tab.active .nav-index{color:var(--nav-active-text)}
:root[data-theme=light] .sidebar-footer strong{color:#166534}
:root[data-theme=light] #toast{background:#e8f5ec}
:root[data-theme=light] #toast.error{background:#fff0ee}
button,input,select,textarea{background:var(--control-bg);color:var(--text)}
button{background:var(--button-bg)}
.sidebar{background:var(--sidebar-bg)}
.sidebar-heading,.checks label{color:var(--text)}
.tab{color:var(--sidebar-text)}
.tab:hover{background:color-mix(in srgb,var(--blue) 10%,var(--sidebar-bg))}
.tab.active{color:var(--nav-active-text);background:var(--nav-active-bg);border-color:color-mix(in srgb,var(--blue) 45%,var(--line))}
#page-title{color:var(--heading-text)}
body,button,input,select,textarea{font-family:var(--ui-font-family,ui-monospace,SFMono-Regular,Consolas,monospace)}
.animation-setting{display:flex;flex-direction:row;align-items:center;gap:8px}
.animation-setting input{min-width:0;width:16px;height:16px;accent-color:var(--blue)}
.brand-cursor{animation:cursor-blink .8s steps(2,start) infinite}
@keyframes cursor-blink{to{visibility:hidden}}
@font-face{font-family:Hack;src:url('/fonts/Hack-Regular.ttf') format('truetype');font-style:normal;font-weight:400;font-display:swap}
@font-face{font-family:'JetBrains Mono';src:url('/fonts/JetBrainsMono.woff2') format('woff2');font-style:normal;font-weight:400;font-display:swap}
@font-face{font-family:'Fira Code';src:url('/fonts/FiraCode.woff2') format('woff2');font-style:normal;font-weight:400;font-display:swap}
@font-face{font-family:'Source Code Pro';src:url('/fonts/SourceCodePro.woff2') format('woff2');font-style:normal;font-weight:400;font-display:swap}
@font-face{font-family:'Cascadia Code';src:url('/fonts/CascadiaCode.woff2') format('woff2');font-style:normal;font-weight:400;font-display:swap}
@font-face{font-family:'IBM Plex Mono';src:url('/fonts/IBMPlexMono.woff2') format('woff2');font-style:normal;font-weight:400;font-display:swap}
@font-face{font-family:Inconsolata;src:url('/fonts/Inconsolata.woff2') format('woff2');font-style:normal;font-weight:400;font-display:swap}
.setting-control{margin:10px 0 20px}
.panel#display .setting-control>label,.panel#display .setting-control>h3{font-size:14px;font-weight:400}
.site-credit{text-align:center;margin:48px 0 2px;padding:10px;font-size:9px;color:var(--muted)}
.site-credit a{color:inherit;text-decoration:underline;text-underline-offset:2px}
.setting-control input[type=range]{width:min(420px,100%);accent-color:var(--blue)}
#app[data-active-tab=ports] .toolbar :is(#badges,#manager-summary,#refresh,label),#app[data-active-tab=ports] #access-warning{display:none}
#app[data-active-tab=ports] .toolbar{justify-content:flex-end}
.port-check-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,260px),1fr));gap:16px}
.port-check-grid .card{margin:0}#port-check-results{overflow-wrap:anywhere}.port-check-verdict{font-size:20px;font-weight:700;margin:8px 0}
.port-check-rule{padding:12px 0;border-bottom:1px solid var(--line)}.port-check-rule:last-child{border:0}
.port-check-rule summary{padding:4px 0}.port-check-rule p{overflow-wrap:anywhere}.port-check-rule .badge{margin-left:0}
.presets{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-top:12px}
.preset{padding:10px;background:var(--control-bg);color:var(--text);border:1px solid var(--line);border-radius:8px;text-align:left}
.preset-swatch{display:grid;place-items:center;height:62px;margin-bottom:8px;border:1px solid color-mix(in srgb,var(--text) 20%,transparent);border-radius:5px;font-size:30px;font-weight:700}
.preset[aria-pressed=true]{outline:2px solid var(--blue);outline-offset:2px}
</style></head><body><main>
<div class="row between"><div><h1 id="brand-title"><span id="brand-text">firewall_web</span><span class="brand-cursor" aria-hidden="true">_</span></h1><p class="muted"><strong>A mini firewall console | nftables / iptables / masquerade</strong></p></div><span id="connection">Locked</span></div>
<p class="muted notice warning">To change firewall rules, this utility must be installed and run as root with CAP_NET_ADMIN. Termux PRoot and unprivileged userspace environments provide read-only UI only; PRoot cannot change the Android host firewall.</p>
<form class="card row" id="login"><label class="wide">4-digit PIN<input id="key" type="password" autocomplete="current-password" placeholder="Enter PIN" inputmode="numeric" pattern="[0-9]{4}" minlength="4" maxlength="4" required></label><button class="primary">Unlock</button><span class="muted">The key stays in this page's memory. The utility must run as root to administer the firewall.</span></form>
<section id="app" class="hidden">
<div class="app-shell">
<aside id="sidebar" class="sidebar" aria-label="Firewall sections">
<div class="sidebar-heading">FIREWALL CONSOLE</div>
<nav class="tabs" role="tablist" aria-label="Firewall sections" aria-orientation="vertical">
<p class="nav-group" role="presentation">Rules &amp; networking</p>
<button id="tab-ports" role="tab" aria-selected="false" aria-controls="ports" tabindex="-1" class="tab" data-tab="ports"><span class="nav-index" aria-hidden="true">01</span>Port Checker</button>
<button id="tab-overview" role="tab" aria-selected="true" aria-controls="overview" tabindex="0" class="tab active" data-tab="overview"><span class="nav-index" aria-hidden="true">02</span>All Rules</button>
<button id="tab-manager" role="tab" aria-selected="false" aria-controls="manager" tabindex="-1" class="tab" data-tab="manager"><span class="nav-index" aria-hidden="true">03</span>Firewall Manager</button>
<button id="tab-nft" role="tab" aria-selected="false" aria-controls="nft" tabindex="-1" class="tab" data-tab="nft"><span class="nav-index" aria-hidden="true">04</span>nftables</button>
<button id="tab-ipt" role="tab" aria-selected="false" aria-controls="ipt" tabindex="-1" class="tab" data-tab="ipt"><span class="nav-index" aria-hidden="true">05</span>iptables</button>
<button id="tab-masq" role="tab" aria-selected="false" aria-controls="masq" tabindex="-1" class="tab" data-tab="masq"><span class="nav-index" aria-hidden="true">06</span>Masquerade</button>
<p class="nav-group" role="presentation">Administration</p>
<button id="tab-persistence" role="tab" aria-selected="false" aria-controls="persistence" tabindex="-1" class="tab" data-tab="persistence"><span class="nav-index" aria-hidden="true">07</span>Persistence</button>
<button id="tab-backups" role="tab" aria-selected="false" aria-controls="backups" tabindex="-1" class="tab" data-tab="backups"><span class="nav-index" aria-hidden="true">08</span>Backups</button>
<button id="tab-advanced" role="tab" aria-selected="false" aria-controls="advanced" tabindex="-1" class="tab" data-tab="advanced"><span class="nav-index" aria-hidden="true">09</span>Advanced</button>
<p class="nav-group" role="presentation">Personalization</p>
<button id="tab-display" role="tab" aria-selected="false" aria-controls="display" tabindex="-1" class="tab" data-tab="display"><span class="nav-index" aria-hidden="true">10</span>Display and Feel</button>
</nav>
<div class="sidebar-footer"><strong>Live firewall</strong>Save edits in Persistence to restore them after boot.</div>
<button id="sidebar-close" class="sidebar-close">Close menu</button>
</aside>
<div id="nav-backdrop" class="nav-backdrop" aria-hidden="true"></div>
<div id="workspace" class="workspace">
<header class="page-heading"><button id="menu-toggle" class="menu-toggle" aria-controls="sidebar" aria-expanded="false" aria-label="Open sections">Sections</button><div><h2 id="page-title">All Rules</h2><p id="page-description" class="muted">A complete view of the firewall backends installed on this machine.</p></div></header>
<div class="row between toolbar"><div id="badges"></div><div class="row toolbar-actions"><span id="manager-summary" class="badge" role="status" aria-live="polite">Firewall manager: checking</span><button id="refresh" class="primary">Refresh</button><label>Auto-refresh<select id="auto"><option value="0">Off</option><option value="15">15 seconds</option><option value="30">30 seconds</option></select></label><button id="logout">Lock</button></div></div><p id="access-warning" class="muted notice warning hidden" role="status"></p>
<section id="ports" class="panel hidden" role="tabpanel" aria-labelledby="tab-ports" tabindex="0">
<div class="card"><h2>Check a port</h2><p class="muted">See what the firewall allows and which service is using the port. Nothing is changed.</p>
<form id="port-check-form" class="row"><label>Port number<input id="port-check-number" name="port" type="number" min="1" max="65535" step="1" inputmode="numeric" placeholder="80" required></label><button id="port-check-submit" class="primary">Check port</button></form></div>
<div id="port-check-results" role="status" aria-live="polite"><p class="muted">Enter a port number above, for example 80.</p></div>
</section>
<section id="manager" class="panel hidden" role="tabpanel" aria-labelledby="tab-manager" tabindex="0"><section class="card" aria-labelledby="detection-heading"><div class="row between"><div><h2 id="detection-heading">Firewall manager detection</h2><p id="detection-summary" class="muted" role="status" aria-live="polite">Detection has not run yet.</p></div><div class="row"><button id="refresh-detection" type="button">Refresh detection</button><button id="review-detection" type="button" class="hidden">Review detected changes</button></div></div><pre id="detection-details"></pre>
<div id="ufw-controls" class="hidden"><h3>UFW-managed rules</h3><p class="muted">Changes use UFW and are persisted by UFW. IPv4/IPv6 behavior follows UFW configuration. Risky rule changes start a 90-second rollback unless you confirm keeping them.</p>
<form id="ufw-add" class="manager-write-form"><div class="row"><label>Rule kind<select name="kind"><option value="port">Host rule</option><option value="route">Forwarded route</option></select></label><label>Action<select name="action"><option>allow</option><option>deny</option><option>reject</option><option>limit</option></select></label><label>Direction<select name="direction"><option value="">Any</option><option>in</option><option>out</option></select></label><label>Source network<input name="source" value="any" placeholder="any or 192.0.2.0/24"></label><label>Source port/range<input name="source_port" placeholder="optional"></label><label>Destination network<input name="destination" value="any" placeholder="any or 198.51.100.0/24"></label><label>Destination port/range<input name="port" placeholder="22 or 8000:8010"></label><label>Protocol<select name="protocol"><option>tcp</option><option>udp</option></select></label><label>Incoming interface<input name="interface_in" placeholder="optional interface"></label><label>Outgoing interface<input name="interface_out" placeholder="optional interface"></label><label>Comment<input name="comment" maxlength="120"></label><button class="good">Add UFW rule</button></div></form>
<p class="muted notice warning">Changing defaults, deny/reject rules, or enabling/disabling UFW can disconnect SSH or the web UI. Risky changes roll back after 90 seconds unless confirmed. Rollback is skipped if the manager configuration changed concurrently.</p><form id="ufw-default" class="manager-write-form"><div class="row"><label>Direction<select name="direction"><option>incoming</option><option>outgoing</option><option>routed</option></select></label><label>Policy<select name="policy"><option>allow</option><option>deny</option><option>reject</option></select></label><label>Type APPLY to confirm<input name="confirm" required></label><button class="danger">Set default policy</button></div></form>
<div class="row"><button id="ufw-enable" type="button">Enable UFW</button><button id="ufw-disable" type="button" class="danger">Disable UFW</button><button id="ufw-reload" type="button">Reload UFW</button></div><pre id="ufw-status"></pre><div id="ufw-rules"></div></div>
<div id="firewalld-controls" class="hidden"><h3>firewalld-managed rules</h3><p class="muted">Select a zone or supported policy explicitly. Runtime and permanent changes stay separate; permanent changes require an explicit reload to take effect. Risky changes roll back after 90 seconds unless confirmed.</p>
<form id="firewalld-add" class="manager-write-form"><div class="row"><label>Scope<select id="firewalld-scope" name="scope"><option value="zone">Zone</option><option value="policy">Policy</option></select></label><label>Zone<select id="firewalld-zone" name="zone" required></select></label><label>Policy<select id="firewalld-policy" name="policy" disabled></select></label><label>Rule type<select name="type"><option value="port">Port</option><option value="service">Service</option><option value="source">Source binding</option><option value="interface">Interface binding</option><option value="rich-rule">Rich rule</option></select></label><label>Value<input name="value" placeholder="ssh, 8443, 192.0.2.0/24 or rule ..." required></label><label>Protocol<select name="protocol"><option>tcp</option><option>udp</option></select></label><label>Configuration<select name="state"><option value="runtime">Runtime</option><option value="permanent">Permanent</option></select></label><label>Action<select name="action"><option value="add">Add</option><option value="remove">Remove</option></select></label><button class="good">Apply firewalld change</button></div></form>
<div class="row"><button id="firewalld-reload" type="button" class="danger">Reload from permanent configuration</button></div><pre id="firewalld-status"></pre></div></section></section>
<section id="overview" class="panel" role="tabpanel" aria-labelledby="tab-overview" tabindex="0"><div class="card"><h2>All installed firewall views</h2><p class="muted">Full listings include all tables. iptables-nft overlaps with nftables; default and explicit backend commands may show the same rules. These are views, not independent rule totals.</p><div id="all-views"></div></div></section>
<section id="nft" class="panel hidden" role="tabpanel" aria-labelledby="tab-nft" tabindex="0">
<div class="card"><h2>nftables rules</h2><div class="row"><label class="wide">Search<input id="n-search" placeholder="Family, table, chain, expression or comment"></label><label>Filter<select id="n-filter"><option value="all">All rules</option><option value="masq">Masquerade only</option></select></label></div><div id="n-rules"></div><details><summary>Complete native ruleset | handles included</summary><pre id="n-raw"></pre></details></div>
<form class="card firewall-write-form nft-write-form" id="n-add"><h2>Add nftables rule</h2><div class="row"><label>Family<select name="family"><option>inet</option><option>ip</option><option>ip6</option><option>bridge</option><option>arp</option><option>netdev</option></select></label><label>Table<input name="table" value="filter" required></label><label>Chain<input name="chain" value="input" required></label><label>Position<select name="operation"><option value="add">Append</option><option value="insert">Insert first</option></select></label></div><label>Rule expression<textarea name="rule" placeholder="ct state established,related counter accept" required></textarea></label><p class="muted">Use existing tables/chains, or create one below. Names are case-sensitive.</p><button class="good">Add rule</button></form>
<form class="card firewall-write-form" id="n-chain"><h2>Create nftables table / chain</h2><div class="row"><label>Family<select name="family"><option>inet</option><option>ip</option><option>ip6</option></select></label><label>Table<input name="table" value="mini_firewall" required></label><label>Chain<input name="chain" value="input" required></label><label>Hook<select name="hook"><option value="">Regular chain (no hook)</option><option>input</option><option>output</option><option>forward</option><option>prerouting</option><option>postrouting</option></select></label><label>Type<select name="type"><option>filter</option><option>nat</option><option>route</option></select></label><label>Priority<input name="priority" type="number" value="0" class="small"></label><label>Policy<select name="policy"><option>accept</option><option>drop</option></select></label><button class="good">Create</button></div></form>
</section>
<section id="ipt" class="panel hidden" role="tabpanel" aria-labelledby="tab-ipt" tabindex="0">
<form class="card firewall-write-form" id="i-port"><h2>Add a service port</h2><p class="muted">Allow an incoming TCP or UDP service and its replies. Select one IP family or both in a single submission.</p><div class="row"><label>Protocol<select name="protocol"><option value="tcp">TCP</option><option value="udp">UDP</option></select></label><label>Port or range<input name="port" placeholder="e.g. 41641 or 8000:8010" required inputmode="text"></label><label>Backend mode<select name="mode"><option value="default">System default</option><option value="nft">iptables-nft</option><option value="legacy">iptables-legacy</option></select></label><label>Interface<select name="iface" id="p-iface"><option value="">Any interface</option></select></label></div><div class="checks"><fieldset><legend>IP families</legend><label><input id="p-ipv4" name="ipv4" type="checkbox" checked>IPv4</label><label><input id="p-ipv6" name="ipv6" type="checkbox" checked>IPv6</label></fieldset><fieldset><legend>Connection tracking</legend><label><input id="p-stateless" name="stateless" type="checkbox">Stateless (NOTRACK)</label></fieldset></div><p class="muted notice">Stateless is off by default: normal system connection tracking is used, as in a usual Debian setup. When enabled, raw-table NOTRACK rules bypass tracking for incoming traffic and replies. This is incompatible with NAT/masquerading for that traffic.</p><p class="muted">Rules are inserted first so earlier terminal filter rules do not hide this permit. Re-submitting the same port updates rules created by this form. Save in Persistence afterward to survive boot.</p><button class="good">Add / update port</button></form>
<div class="card"><h2>iptables rules</h2><div class="row"><label>Executable / backend<select id="i-backend"></select></label><label class="wide">Search<input id="i-search" placeholder="Table, chain, target or expression"></label><label>Filter<select id="i-filter"><option value="all">All rules</option><option value="masq">Masquerade only</option></select></label></div><p id="i-version" class="muted"></p><div id="i-rules"></div><details><summary>Complete save-format listing | all tables and counters</summary><pre id="i-raw"></pre></details></div>
<form class="card firewall-write-form" id="i-add"><h2>Add iptables rule | selected backend above</h2><div class="row"><label>Table<select name="table"><option>filter</option><option>nat</option><option>mangle</option><option>raw</option><option>security</option></select></label><label>Chain<input name="chain" value="INPUT" required></label><label>Position<select name="operation"><option value="append">Append</option><option value="insert">Insert</option></select></label><label>Insert at #<input name="position" type="number" min="1" value="1" class="small"></label></div><label>Match / target options<textarea name="rule" placeholder="-p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT" required></textarea></label><p class="muted">Do not include the executable, -A/-I, table or chain here.</p><button class="good">Add rule</button></form>
<form class="card firewall-write-form" id="i-chain"><h2>iptables chain / policy</h2><div class="row"><label>Table<select name="table"><option>filter</option><option>nat</option><option>mangle</option><option>raw</option><option>security</option></select></label><label>Chain<input name="chain" value="INPUT" required></label><label>Action<select name="action"><option value="create">Create user chain</option><option value="policy">Set built-in policy</option></select></label><label>Policy<select name="policy"><option>ACCEPT</option><option>DROP</option></select></label><button class="primary">Apply</button></div></form>
</section>
<section id="masq" class="panel hidden" role="tabpanel" aria-labelledby="tab-masq" tabindex="0"><div class="card"><h2>Masquerade / source NAT</h2><p class="muted notice warning">NAT alone does not enable forwarding or allow forwarded traffic. Check forwarding status above. This control never flushes existing NAT rules.</p><form id="m-form" class="firewall-write-form"><div class="row"><label>Engine<select name="engine" id="m-engine"></select></label><label>nft family<select name="family"><option>ip</option><option>ip6</option></select></label><label>nft table<input name="table" value="nft_web_nat"></label><label>Outgoing interface<select name="iface" id="m-iface"></select></label><label class="wide">Source subnet (optional)<input name="source" placeholder="e.g. 192.168.200.0/24"></label></div><p class="muted">Blank interface/subnet means any. nftables uses a dedicated postrouting NAT chain. Enable is idempotent. Disable removes only nft-web-tagged rules matching these settings. Delete other existing masquerade rules from the rules lists.</p><div class="row"><button class="good" name="action" value="enable">Enable matching rule</button><button class="danger" name="action" value="disable">Disable matching rule</button></div></form></div></section>
<section id="persistence" class="panel hidden" role="tabpanel" aria-labelledby="tab-persistence" tabindex="0">
<div class="card action-card"><h2>IPv4 + IPv6 boot persistence</h2><p>Save the current system-default iptables and ip6tables rules, including masquerading, and enable restoration after boot.</p><p class="muted">Uses netfilter-persistent and its IPv4/IPv6 plugins. Both saved files are validated. This saves the default backends, not all legacy/nft alternatives at once.</p><button id="persist-ipt" class="good">Persist IPv4 + IPv6</button></div>
<div class="card action-card"><h2>Native nftables boot persistence</h2><p>Save native nftables tables and enable their dedicated boot restore service.</p><p class="muted">iptables-nft tables are excluded and use the IPv4 + IPv6 button above. Keep this script and its Python environment at their installed paths.</p><button id="persist-nft" class="good">Persist native nft</button></div>
<p class="muted notice">Use these controls after making rule changes. Saving a backup alone does not enable boot restoration. Rules maintained by other services may change independently.</p>
</section>
<section id="backups" class="panel hidden" role="tabpanel" aria-labelledby="tab-backups" tabindex="0">
<div class="card action-card"><h2>Save a backup on this machine</h2><p>Capture every installed firewall view, including rule counters, into a protected server-side JSON file.</p><p class="muted">A backup is also made automatically before firewall changes.</p><button id="backup" class="primary">Save backup</button></div>
<div class="card action-card"><h2>Download a backup</h2><p>Export the current firewall views as a JSON file for your own records.</p><p class="muted">Exports are snapshots, not automatically restored boot configurations.</p><button id="export" class="primary">Download backup</button></div>
</section>
<section id="advanced" class="panel hidden" role="tabpanel" aria-labelledby="tab-advanced" tabindex="0"><form class="card firewall-write-form" id="raw-form"><h2>Advanced command</h2><p class="muted notice warning">This has full firewall access. Flushing rules or setting a DROP policy can disconnect SSH, containers or this UI. Export a backup first. No shell commands or file directives.</p><label>Executable<select id="raw-engine" name="engine"></select></label><label>Command<textarea name="cmd" placeholder="nft: list ruleset&#10;iptables: -t filter -S" required></textarea></label><div class="row"><label>Type RUN to execute<input name="confirm" placeholder="RUN" required autocomplete="off"></label><button class="danger">Run</button></div><pre id="raw-out">Output appears here.</pre></form></section>
<section id="display" class="panel hidden" role="tabpanel" aria-labelledby="tab-display" tabindex="0">
<div class="card"><h2>Display and Feel</h2><p class="muted">Personal appearance settings are saved in this browser.</p>
<div class="setting-control"><label for="theme-select">Color theme</label><select id="theme-select"><option value="system">System default</option><option value="dark">Dark</option><option value="light">Light</option></select></div>
<div class="setting-control"><label class="animation-setting"><input id="header-animation" type="checkbox" checked>Animate header</label></div>
<div class="setting-control"><label for="font-size">Font size: <output id="font-size-value">14px</output></label><input id="font-size" type="range" min="12" max="20" step="1" value="14"></div>
<div class="setting-control"><label for="font-family">Bundled font family</label><select id="font-family"><option value="JetBrains Mono,ui-monospace,monospace">JetBrains Mono</option><option value="Hack,ui-monospace,monospace">Hack</option><option value="Fira Code,ui-monospace,monospace">Fira Code</option><option value="Source Code Pro,ui-monospace,monospace">Source Code Pro</option><option value="Cascadia Code,ui-monospace,monospace">Cascadia Code</option><option value="IBM Plex Mono,ui-monospace,monospace">IBM Plex Mono</option><option value="Inconsolata,ui-monospace,monospace">Inconsolata</option></select></div>
<div class="setting-control"><h3>Quick looks</h3><p class="muted">Choose from nine curated palettes, six light and three dark.</p><div id="appearance-presets" class="presets"></div></div>
</div></section>
<p id="updated" class="muted"></p></div></div></section><div id="toast" class="hidden" role="status"></div>
<footer class="site-credit"><em>Created &amp; Conceptualized by <a href="https://github.com/arslandevpk/firewall-web" target="_blank" rel="noopener noreferrer">arslandevpk</a></em></footer>
</main><script>
'use strict';
const $=id=>document.getElementById(id);let key='',status={},snapshot=null,nft=null,ipt=null,busy=false,refreshing=false,timer=null,detectionTimer=null,firewallWritable=false;
function el(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e}
const appearanceKey='firewall-web-appearance';
const fontFamilies=['JetBrains Mono,ui-monospace,monospace','Hack,ui-monospace,monospace','Fira Code,ui-monospace,monospace','Source Code Pro,ui-monospace,monospace','Cascadia Code,ui-monospace,monospace','IBM Plex Mono,ui-monospace,monospace','Inconsolata,ui-monospace,monospace'];
const colorPresets=[
{name:'Paper',theme:'light',bg:'#f4f6f8',text:'#1f2328'},
{name:'Warm Sand',theme:'light',bg:'#f5efe6',text:'#332719'},
{name:'Soft Mint',theme:'light',bg:'#eaf4ef',text:'#18352a'},
{name:'Soft Sky',theme:'light',bg:'#edf5ff',text:'#20334d'},
{name:'Light Lavender',theme:'light',bg:'#f3effb',text:'#352b49'},
{name:'Pale Rose',theme:'light',bg:'#fff1f3',text:'#482b35'},
{name:'Midnight',theme:'dark',bg:'#0d1117',text:'#d7dfe8'},
{name:'Deep Ocean',theme:'dark',bg:'#0a1929',text:'#d5e8ff'},
{name:'Forest',theme:'dark',bg:'#102019',text:'#d7eee0'}];
let appearance={theme:'system',font:fontFamilies[0],size:14,preset:'',animate:!matchMedia('(prefers-reduced-motion: reduce)').matches};
try{
 const saved=JSON.parse(localStorage.getItem(appearanceKey)||'{}');
 if(['system','light','dark'].includes(saved.theme))appearance.theme=saved.theme;
 if(fontFamilies.includes(saved.font))appearance.font=saved.font;
 if(Number.isInteger(saved.size)&&saved.size>=12&&saved.size<=20)appearance.size=saved.size;
 // Preserve curated legacy selections, but discard arbitrary custom colors.
 const preset=colorPresets.find(p=>p.theme===appearance.theme&&(p.name===saved.preset||(!saved.preset&&p.bg===saved.bg&&p.text===saved.text)));
 if(preset)appearance.preset=preset.name;
 if(typeof saved.animate==='boolean')appearance.animate=saved.animate;
}catch(error){console.warn('Could not load saved appearance settings:',error)}
function applyAppearance(save=true){
 const root=document.documentElement;
 const effective=appearance.theme==='system'?(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'):appearance.theme;
 const preset=colorPresets.find(p=>p.name===appearance.preset&&p.theme===effective);
 root.dataset.theme=effective;
 root.style.setProperty('--ui-font-family',appearance.font);root.style.setProperty('--ui-font-size',appearance.size+'px');
 for(const [variable,value] of [['--bg',preset?.bg],['--text',preset?.text]]){
  if(value)root.style.setProperty(variable,value);else root.style.removeProperty(variable);
 }
 $('theme-select').value=appearance.theme;$('font-family').value=appearance.font;$('font-size').value=appearance.size;$('font-size-value').textContent=appearance.size+'px';$('header-animation').checked=appearance.animate;
 for(const button of document.querySelectorAll('.preset'))button.setAttribute('aria-pressed',String(button.dataset.preset===preset?.name));
 if(save){try{localStorage.setItem(appearanceKey,JSON.stringify(appearance))}catch(error){notice('Appearance updated but could not be saved in this browser: '+error.message,true)}}
}
function initAppearance(){
 const holder=$('appearance-presets');
 for(const preset of colorPresets){
  const button=el('button',undefined,'preset');button.type='button';button.dataset.preset=preset.name;button.setAttribute('aria-pressed','false');
  const swatch=el('span','A','preset-swatch');swatch.style.background=preset.bg;swatch.style.color=preset.text;
  button.append(swatch,el('span',preset.name+' · '+preset.theme));
  button.onclick=()=>{appearance.theme=preset.theme;appearance.preset=preset.name;applyAppearance()};holder.append(button);
 }
 $('theme-select').onchange=()=>{appearance.theme=$('theme-select').value;appearance.preset='';applyAppearance()};
 $('font-family').onchange=()=>{appearance.font=$('font-family').value;applyAppearance()};
 $('font-size').oninput=()=>{appearance.size=Number($('font-size').value);applyAppearance()};
 $('header-animation').onchange=()=>{appearance.animate=$('header-animation').checked;applyAppearance();setHeaderAnimation(appearance.animate)};
 matchMedia('(prefers-color-scheme: dark)').addEventListener('change',()=>{if(appearance.theme==='system')applyAppearance(false)});
 applyAppearance(false);setHeaderAnimation(appearance.animate);
}
let headerTimer=null;
function setHeaderAnimation(enabled){clearTimeout(headerTimer);const text=$('brand-text'),full='firewall_web';let index=enabled?0:full.length,deleting=false;text.textContent=full.slice(0,index);if(!enabled)return;function type(){index++;text.textContent=full.slice(0,index);if(index===full.length){deleting=true;headerTimer=setTimeout(erase,1000)}else headerTimer=setTimeout(type,130)}function erase(){index--;text.textContent=full.slice(0,index);if(index===0){deleting=false;headerTimer=setTimeout(type,350)}else headerTimer=setTimeout(erase,95)}headerTimer=setTimeout(type,350)}
function notice(message,error=false){const t=$('toast');t.textContent=message;t.className=error?'error':'';clearTimeout(t._timer);t._timer=setTimeout(()=>t.classList.add('hidden'),error?12000:5005)}
async function api(path,method='GET',body=null){const r=await fetch(path,{method,headers:{'Content-Type':'application/json','X-Secret':key},body:body===null?null:JSON.stringify(body),cache:'no-store'});let d;try{d=await r.json()}catch{throw Error('Server returned an invalid response ('+r.status+').')}if(!r.ok||d.error)throw Error(d.error||'HTTP '+r.status);if(r.headers.get('X-Firewall-Review-Required')==='true')d.review_required=true;return d}
function values(form){return Object.fromEntries(new FormData(form).entries())}
function options(node,items){const old=node.value;node.replaceChildren();for(const [value,label] of items){const o=el('option',label);o.value=value;node.append(o)}if(items.some(x=>x[0]===old))node.value=old}
function setFirewallWritable(allowed,reason=''){const selected=status.detection?.selected_backend,review=status.detection?.selection_review_required||status.managerDrift;firewallWritable=allowed&&!review;const manager=firewallWritable&&['ufw','firewalld'].includes(selected);for(const form of document.querySelectorAll('.firewall-write-form')){let enabled=firewallWritable&&['nftables','iptables'].includes(selected);if(form.id.startsWith('n-'))enabled=firewallWritable&&selected==='nftables';if(form.id.startsWith('i-'))enabled=firewallWritable&&selected==='iptables'&&status.detection.write_backends.length>0;for(const control of form.elements)control.disabled=!enabled}for(const form of document.querySelectorAll('.manager-write-form'))for(const control of form.elements)control.disabled=!manager;for(const id of ['persist-ipt','persist-nft'])$(id).disabled=!(firewallWritable&&(id==='persist-ipt'?selected==='iptables'&&status.detection.write_backends.includes('iptables')&&status.detection.write_backends.includes('ip6tables'):selected==='nftables'));for(const id of ['ufw-enable','ufw-disable','ufw-reload','firewalld-reload'])if($(id))$(id).disabled=!manager;$('backup').disabled=!allowed;$('review-detection').disabled=!allowed;$('review-detection').classList.toggle('hidden',!review);if(status.detection)$('detection-details').textContent=$('detection-details').textContent.split('\nManagement listeners:')[0]+'\nManagement listeners: '+(status.detection.listeners||'unknown');$('access-warning').textContent=reason;$('access-warning').classList.toggle('hidden',!reason)}
async function change(path,method,body){if(!firewallWritable){notice(status.read_only_reason||'Firewall changes are disabled until the detected manager state is reviewed.',true);return}if(busy)return;busy=true;$('app').setAttribute('aria-busy','true');try{const r=await api(path,method,body);if(r.state_token){status.managerStateToken=r.state_token;status.managerDrift=false}if(r.pending_rollback_id){const keep=confirm((r.message||'Risky firewall change applied.')+'\\n\\nClick OK to keep this change. Cancel to leave the 90-second automatic rollback armed.');if(keep){const confirmed=await api('/api/rollback/'+r.pending_rollback_id+'/confirm','POST',{confirm:'KEEP'});notice(confirmed.message)}else notice('Rollback remains armed for 90 seconds. It will be skipped if firewall configuration changes concurrently.',true)}else notice((r.message||'Change applied.')+(r.backup?' Backup: '+r.backup:''));if(r.review_required)status.read_only_reason='Post-change firewall detection was incomplete; review detection before writing.';await refresh(true);return r}catch(e){notice(e.message,true)}finally{busy=false;$('app').setAttribute('aria-busy','false')}}
function display(expr){if(expr===null)return '';if(typeof expr!=='object')return String(expr);if(Array.isArray(expr))return expr.map(display).join(', ');if(expr.payload)return expr.payload.protocol+' '+expr.payload.field;if(expr.meta)return 'meta '+expr.meta.key;if(expr.ct)return 'ct '+expr.ct.key;if(expr.prefix)return expr.prefix.addr+'/'+expr.prefix.len;if(expr.set)return '{ '+display(expr.set)+' }';if(expr.range)return expr.range.map(display).join('-');if(expr.match){const m=expr.match;return display(m.left)+' '+(m.op==='=='?'':m.op+' ')+display(m.right)}if(expr.counter)return 'counter packets '+(expr.counter.packets||0)+' bytes '+(expr.counter.bytes||0);for(const k of ['accept','drop','return','continue','masquerade'])if(k in expr)return k+(expr[k]?' '+JSON.stringify(expr[k]):'');for(const k of ['jump','goto'])if(expr[k])return k+' '+expr[k].target;return JSON.stringify(expr)}
function ruleTable(rules,isNft){const table=el('table',undefined,'rules');const head=el('tr');for(const h of isNft?['Handle','Expression / comment','Action']:['#','Packets / bytes','Rule options','Action'])head.append(el('th',h));table.append(head);for(const r of rules){const row=el('tr');row.append(el('td',String(isNft?r.handle:r.number)));if(!isNft)row.append(el('td',r.packets+' / '+r.bytes));row.append(el('td',isNft?r.expr.map(display).join(' ')+(r.comment?' | comment '+r.comment:''):r.expression,'expr'));const cell=el('td'),button=el('button','Delete','danger');button.disabled=!firewallWritable;button.onclick=()=>{if(!firewallWritable)return;if(!confirm('Delete this exact rule?\n'+(isNft?r.expr.map(display).join(' '):r.expression)))return;change(isNft?'/api/nft/rule':'/api/iptables/rule','DELETE',isNft?{family:r.family,table:r.table,chain:r.chain,handle:r.handle,token:r.token}:{backend:ipt.backend,table:r.table,chain:r.chain,token:r.token})};cell.append(button);row.append(cell)}return table}
function renderRules(state,isNft){const prefix=isNft?'n':'i',holder=$(prefix+'-rules');holder.replaceChildren();if(!state||state.error){holder.append(el('p',state?.error||'Backend unavailable.','muted'));$(prefix+'-raw').textContent=state?.error||'';return}const query=$(prefix+'-search').value.toLowerCase(),onlyMasq=$(prefix+'-filter').value==='masq';$(prefix+'-raw').textContent=state.raw||'(empty ruleset)';if(!isNft)$('i-version').textContent=state.version+' | IPv'+(state.backend.startsWith('ip6')?'6':'4');for(const c of state.chains){const f=isNft?c.family+' ':'';let rows=state.rules.filter(r=>r.table===c.table&&r.chain===c.name&&(!isNft||r.family===c.family));rows=rows.filter(r=>(!onlyMasq||r.masquerade)&&JSON.stringify(r).toLowerCase().includes(query));if((query||onlyMasq)&&!rows.length)continue;const details=el('details');details.open=true;const info=f+c.table+' / '+c.name+' | '+rows.length+' rules'+(c.policy?' | policy '+c.policy:'')+(c.hook?' | '+c.type+' / '+c.hook+' / priority '+c.prio:'');details.append(el('summary',info));const scroll=el('div',undefined,'scroll');scroll.append(rows.length?ruleTable(rows,isNft):el('p','No rules in this chain.','muted'));details.append(scroll);holder.append(details)}if(!state.chains.length)holder.append(el('p','No tables/chains in this view.','muted'))}
function overviewView(){const host=$('all-views');host.replaceChildren();for(const [name,state]of Object.entries(snapshot.states)){const d=el('details');d.append(el('summary',name+' | '+(state.error?'unavailable':state.rules.length+' rules / '+state.chains.length+' chains')+(state.version?' | '+state.version:'')));d.append(el('pre',state.error||state.raw||'(empty ruleset)'));host.append(d)}if(!host.children.length)host.append(el('p','No firewall executables found. Install nftables and/or iptables on the target host.','muted'))}
function renderDetection(d){const previous=status.detection?.selected_backend;if(previous&&previous!==d.selected_backend){status.managerStateToken=null;status.pendingManagerStateToken=null;status.managerDrift=false} $('detection-summary').textContent=d.selection_review_required?(d.fingerprint_review_required?'Firewall configuration changed externally. Review the current rules before writing.':'Detected backend changed from '+d.previous_backend+' to '+d.selected_backend+'. Explicit review is required before writes.'):d.reason;$('manager-summary').textContent='Firewall manager: '+d.selected_backend+(d.selection_review_required?' · review required':'');const lines=['Selected backend: '+d.selected_backend,'UFW: '+d.managers.ufw.status+(d.managers.ufw.version?' ('+d.managers.ufw.version+')':''),'firewalld: '+d.managers.firewalld.status+(d.managers.firewalld.version?' ('+d.managers.firewalld.version+')':''),'Native nftables: '+d.direct.nftables.status+'; kernel backend: '+d.direct.nftables.underlying_packet_filter,'Direct iptables: '+d.direct.iptables.status+'; default implementation: '+d.direct.iptables.default_implementation,'Persistence: netfilter-persistent '+(d.persistence.netfilter_persistent.active===null?'unknown':d.persistence.netfilter_persistent.active?'active':'inactive')+'; native nft restore '+(d.persistence.native_restore.active===null?'unknown':d.persistence.native_restore.active?'active':'inactive'),'Other detected rule owners: '+(d.service_owners.length?d.service_owners.map(x=>x.service+(x.chains.length?': '+x.chains.join(', '):'')).join('; '):'none identified'),'Forwarding: IPv4 '+(d.forwarding.ipv4===null?'unknown':d.forwarding.ipv4?'on':'off')+', IPv6 '+(d.forwarding.ipv6===null?'unknown':d.forwarding.ipv6?'on':'off')];if(d.conflict_acknowledgement)lines.push('To deliberately select one active manager, set NFT_BACKEND_ACK='+d.conflict_acknowledgement);$('detection-details').textContent=lines.join('\n');status.detection=d;status.can_manage_firewall=d.can_write||d.manager_can_write;status.read_only_reason=d.selection_review_required?(d.fingerprint_review_required?'Firewall configuration changed externally; explicitly review the current state before writing.':'The detected manager changed during this session; explicitly review the new selection before writing.'):status.can_manage_firewall?'':(status.read_only_reason||d.reason);configureBackends();setFirewallWritable(status.can_manage_firewall,status.read_only_reason);$('ufw-controls').classList.toggle('hidden',d.selected_backend!=='ufw');$('firewalld-controls').classList.toggle('hidden',d.selected_backend!=='firewalld');$('connection').textContent='Unlocked | '+(status.can_manage_firewall?'selected manager: '+d.selected_backend:'read-only | '+d.selected_backend)}
function configureBackends(){if(!status.detection)return;const d=status.detection,choices=d.selected_backend==='iptables'&&d.write_backends.length?d.write_backends:status.backends;options($('i-backend'),choices.map(n=>[n,n]));if(d.selected_backend==='iptables'){const modes=[];if(d.write_backends.includes('iptables'))modes.push(['default','System default']);if(d.write_backends.includes('iptables-nft'))modes.push(['nft','iptables-nft']);if(d.write_backends.includes('iptables-legacy'))modes.push(['legacy','iptables-legacy']);options($('i-port').elements.namedItem('mode'),modes)}}
async function refresh(force=false){if(refreshing||(busy&&!force)||!key)return;refreshing=true;try{const previous=status.detection?.selected_backend,detection=await api('/api/detection');renderDetection(detection);if(previous&&previous!==detection.selected_backend)notice('Firewall manager changed from '+previous+' to '+detection.selected_backend+'. Writes were re-evaluated; review detection before continuing.',true);await refreshManager();configureBackends();snapshot=await api('/api/overview');nft=snapshot.states.nft;ipt=snapshot.states[$('i-backend').value];overviewView();renderRules(nft,true);renderRules(ipt,false);$('updated').textContent='Last refreshed '+new Date().toLocaleString()+' | Rule counters are snapshots.'}finally{refreshing=false}}
function updateManagerToken(token){if(status.managerStateToken&&status.managerStateToken!==token){status.pendingManagerStateToken=token;status.managerDrift=true;status.read_only_reason='Manager configuration changed externally. Review the current rules before enabling controls.'}else if(!status.managerDrift)status.managerStateToken=token;setFirewallWritable(status.can_manage_firewall,status.read_only_reason)}
async function refreshManager(){if(!key)return;const selected=status.detection?.selected_backend;if(selected==='ufw'){const d=await api('/api/ufw');updateManagerToken(d.state_token);$('ufw-status').textContent=d.status+'\nIPv6: '+(d.ipv6||'unknown');const host=$('ufw-rules');host.replaceChildren();for(const rule of d.rules){const row=el('div',`[${rule.number}] ${rule.text}`,'row between');const button=el('button','Delete','danger');button.disabled=!status.can_manage_firewall||status.managerDrift||status.detection.selection_review_required;button.onclick=()=>{if(confirm('Delete this UFW rule after revalidating its displayed number and text? This action may affect IPv4/IPv6 rules separately. Keep console access.\\n'+rule.text))change('/api/ufw/rule','DELETE',{number:rule.number,token:rule.token,state_token:status.managerStateToken})};row.append(button);host.append(row)}}else if(selected==='firewalld'){const d=await api('/api/firewalld');updateManagerToken(d.state_token);options($('firewalld-zone'),Object.keys(d.zones).map(zone=>[zone,zone]));options($('firewalld-policy'),Object.keys(d.policies).map(policy=>[policy,policy]));const caps=d.capabilities||{};for(const [value,cap] of [['source','source_bindings'],['interface','zone_bindings'],['rich-rule','rich_rules']])$('firewalld-add').elements.namedItem('type').querySelector('option[value="'+value+'"]').disabled=!caps[cap];$('firewalld-scope').querySelector('option[value="policy"]').disabled=!caps.policies;$('firewalld-policy').disabled=!caps.policies||$('firewalld-scope').value!=='policy';$('firewalld-zone').disabled=$('firewalld-scope').value==='policy';$('firewalld-status').textContent='Version: '+(d.version||'unknown')+'\\nDefault zone: '+(d.default_zone||'unknown')+'\\nPermanent default zone: '+(d.permanent_default_zone||'unknown')+'\\nActive zone bindings: '+JSON.stringify(d.active_zones)+'\\nRuntime/permanent zones, bindings, rich rules, and policies:\\n'+JSON.stringify({zones:d.zones,policies:d.policies},null,2)}}

let portCheckGeneration=0;
function renderPortCheck(d){
 const host=$('port-check-results');host.replaceChildren();
 host.append(el('h2','Port '+d.port));const grid=el('div',undefined,'port-check-grid');
 const firewall=el('div',undefined,'card');firewall.append(el('h3','Firewall'),el('p',d.summary,'port-check-verdict'));
 for(const protocol of ['tcp','udp']){
  const value=d.protocols[protocol];const row=el('p');row.append(el('strong',protocol.toUpperCase()+': '),el('span',value.label));firewall.append(row);
  if(new Set(Object.values(value.families)).size>1)firewall.append(el('p',Object.entries(value.families).map(([f,v])=>f+': '+({allowed:'allowed',blocked:'not opened',restricted:'restricted',unknown:'needs checking'}[v])).join(' · '),'muted'));
 }
 firewall.append(el('p','Checked: '+d.firewall,'muted'));grid.append(firewall);
 const usage=el('div',undefined,'card');usage.append(el('h3','Service using this port'));
 if(d.listeners.length){
  const protocols=[...new Set(d.listeners.map(s=>s.protocol.toUpperCase()))];usage.append(el('p','In use · '+protocols.join(' + '),'port-check-verdict'));
  for(const socket of d.listeners){
   const names=socket.services.length?[...new Set(socket.services.map(s=>s.unit||s.name))].join(', '):'Service name unavailable';
   usage.append(el('p',socket.protocol.toUpperCase()+' · '+names));
   usage.append(el('p',socket.local_only?'Local connections only ('+socket.address+')':'Listening/bound on '+({'0.0.0.0':'all IPv4 addresses','::':'all IPv6 addresses','*':'all network addresses'}[socket.address]||socket.address),'muted'));
  }
 }else if(!d.usage_known){usage.append(el('p','Could not check','port-check-verdict'),el('p','The service list could not be read.','muted'));}
 else if(d.rules.some(r=>r.action==='Forward')){usage.append(el('p','Forwarding rule found','port-check-verdict'),el('p','No host listener found. The service may be in a container or on another machine.','muted'));}
 else{usage.append(el('p','Not in use','port-check-verdict'),el('p','No local TCP listener or UDP binding was found.','muted'));}
 grid.append(usage);host.append(grid);
 const specific=d.rules.filter(r=>r.port_specific),general=d.rules.filter(r=>!r.port_specific);
 const rules=el('div',undefined,'card');rules.append(el('h3','Matching port rules'+(specific.length?' · '+specific.length:'')));
 if(!specific.length)rules.append(el('p','No rule names this port specifically. General rules and defaults can still allow or block it.','muted'));
 function addRule(parent,r){
  const row=el('div',undefined,'port-check-rule');const heading=el('p');heading.append(el('strong',r.protocol.toUpperCase()+' · '+r.action),el('span',r.family,'badge'));row.append(heading);
  row.append(el('p',r.location+' · '+r.scope));
  if(r.restricted)row.append(el('p','Access depends on an address, network or another condition.','muted'));
  if(r.copies>1)row.append(el('p',r.copies+' matching copies in this chain. Check for duplicates.','notice warning'));
  const more=el('details');more.append(el('summary','Rule details'),el('p',r.backend+' · '+r.table+' / '+r.chain,'muted'),el('pre',r.rule));row.append(more);parent.append(row);
 }
 for(const r of specific)addRule(rules,r);host.append(rules);
 if(general.length){const more=el('details',undefined,'card');more.append(el('summary','General rule details (may not be reached)'));for(const r of general)addRule(more,r);host.append(more);}
 for(const note of d.notes)host.append(el('p',note,'notice warning'));
 host.append(el('p','Incoming access at this server only. A router or cloud firewall may still block it. Rules with restrictions may depend on your source address or network.','muted'));
 host.append(el('p','Checked '+new Date(d.checked_utc).toLocaleString()+' · Check again after changing rules or services.','muted'));
}
$('port-check-form').onsubmit=async e=>{
 e.preventDefault();const form=e.currentTarget;if(!form.reportValidity())return;
 const port=$('port-check-number').value;if(!/^[0-9]{1,5}$/.test(port)||Number(port)<1||Number(port)>65535){notice('Enter one port number from 1 to 65535.',true);return;}
 const generation=++portCheckGeneration;const button=$('port-check-submit');button.disabled=true;button.textContent='Checking…';$('port-check-results').replaceChildren(el('p','Checking port '+Number(port)+'…','muted'));
 try{const result=await api('/api/port-check?port='+encodeURIComponent(port));if(generation===portCheckGeneration&&key)renderPortCheck(result);}
 catch(error){if(generation===portCheckGeneration)$('port-check-results').replaceChildren(el('p','Could not check this port: '+error.message,'notice warning'));}
 finally{if(generation===portCheckGeneration){button.disabled=false;button.textContent='Check port';}}
};

$('login').onsubmit=async e=>{e.preventDefault();key=$('key').value;try{status=await api('/api/status');$('key').value='';$('app').classList.remove('hidden');$('login').classList.add('hidden');renderDetection(status.detection);options($('i-backend'),status.backends.map(n=>[n,n]));const engines=[...(status.nft?[['nft','nftables']]:[]),...status.backends.map(n=>[n,n])];options($('m-engine'),engines);options($('raw-engine'),engines);options($('m-iface'),[['','Any interface'],...status.interfaces.filter(n=>n!=='lo').map(n=>[n,n])]);options($('p-iface'),[['','Any interface'],...status.interfaces.map(n=>[n,n])]);$('badges').replaceChildren();for(const [label,value]of [['IPv4 forwarding',status.forwarding.ip],['IPv6 forwarding',status.forwarding.ip6]])$('badges').append(el('span',label+': '+(value===null?'unknown':value?'on':'off'),'badge'));await refresh();try{await refreshManager()}catch(error){notice('Firewall manager status could not be refreshed: '+error.message,true)}}catch(err){key='';notice(err.message,true)}};
 detectionTimer=setInterval(async()=>{if(!key||document.hidden||busy)return;try{const previously=status.detection?.selection_review_required,detection=await api('/api/detection');renderDetection(detection);if(detection.selection_review_required&&!previously)notice(detection.fingerprint_review_required?'Firewall configuration changed outside this application; writes paused until review.':'Firewall manager changed; writes paused until review.',true)}catch(error){notice('Firewall detection poll failed: '+error.message,true)}},15000);
$('logout').onclick=()=>{portCheckGeneration++;$('port-check-results').replaceChildren(el('p','Enter a port number above, for example 80.','muted'));$('port-check-number').value='';$('port-check-submit').disabled=false;$('port-check-submit').textContent='Check port';setSidebar(false,false);key='';snapshot=nft=ipt=null;$('app').classList.add('hidden');$('login').classList.remove('hidden');$('connection').textContent='Locked';clearInterval(timer);$('auto').value='0';$('all-views').replaceChildren();$('n-rules').replaceChildren();$('i-rules').replaceChildren();$('n-raw').textContent='';$('i-raw').textContent='';$('raw-out').textContent='Output appears here.';$('key').focus()};
const sectionInfo={overview:['All Rules','A complete view of the firewall backends installed on this machine.'],manager:['Firewall Manager','Review ownership and manage UFW or firewalld through its native controls.'],nft:['nftables','Inspect native tables and chains, then add or remove individual rules.'],ipt:['iptables','Manage IPv4 and IPv6 rules using the backend you select.'],masq:['Masquerade','Configure source NAT for an outgoing interface and subnet.'],persistence:['Persistence','Save firewall changes and enable their restoration after boot.'],backups:['Backups','Keep a protected snapshot on the server or download your own copy.'],advanced:['Advanced','Run an explicit firewall command when you need more control.']};
sectionInfo.ports=['Port Checker','One port. Firewall rules and listening services, in plain language.'];
sectionInfo.display=['Display and Feel','Choose a color profile, font, text size, and animation in this browser.'];
const mobileNav=window.matchMedia('(max-width:820px)');
function setSidebar(open,restoreFocus=true){open=Boolean(open&&mobileNav.matches);const wasOpen=$('app').classList.contains('sidebar-open');$('app').classList.toggle('sidebar-open',open);document.body.classList.toggle('drawer-open',open);$('workspace').inert=open;$('menu-toggle').setAttribute('aria-expanded',String(open));$('menu-toggle').setAttribute('aria-label',open?'Close sections':'Open sections');if(open)document.querySelector('.tab.active').focus();else if(wasOpen&&restoreFocus)$('menu-toggle').focus()}
function activateTab(id,closeMenu=true){if(!Object.hasOwn(sectionInfo,id))id='overview';$('app').dataset.activeTab=id;for(const b of document.querySelectorAll('.tab')){const selected=b.dataset.tab===id;b.classList.toggle('active',selected);b.setAttribute('aria-selected',String(selected));b.tabIndex=selected?0:-1}for(const p of document.querySelectorAll('.panel'))p.classList.toggle('hidden',p.id!==id);$('page-title').textContent=sectionInfo[id][0];$('page-description').textContent=sectionInfo[id][1];history.replaceState(null,'','#'+id);const wasOpen=$('app').classList.contains('sidebar-open');if(closeMenu){setSidebar(false,false);if(wasOpen)$(id).focus({preventScroll:true})}}
const navigationTabs=Array.from(document.querySelectorAll('.tab'));
for(const [i,b]of navigationTabs.entries()){b.onclick=()=>activateTab(b.dataset.tab);b.onkeydown=e=>{let next=null;if(e.key==='ArrowDown')next=(i+1)%navigationTabs.length;if(e.key==='ArrowUp')next=(i+navigationTabs.length-1)%navigationTabs.length;if(e.key==='Home')next=0;if(e.key==='End')next=navigationTabs.length-1;if(next!==null){e.preventDefault();activateTab(navigationTabs[next].dataset.tab,false);navigationTabs[next].focus()}}}
$('menu-toggle').onclick=()=>setSidebar(!$('app').classList.contains('sidebar-open'));$('sidebar-close').onclick=()=>setSidebar(false);$('nav-backdrop').onclick=()=>setSidebar(false);mobileNav.addEventListener('change',()=>setSidebar(false,false));
document.addEventListener('keydown',e=>{if(!$('app').classList.contains('sidebar-open'))return;if(e.key==='Escape'){e.preventDefault();setSidebar(false)}else if(e.key==='Tab'){const first=document.querySelector('.tab.active'),last=$('sidebar-close');if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus()}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus()}}});
window.addEventListener('hashchange',()=>activateTab(location.hash.slice(1),false));activateTab(location.hash.slice(1),false);initAppearance();
$('refresh').onclick=()=>refresh().catch(e=>notice(e.message,true));$('auto').onchange=()=>{clearInterval(timer);if(+$('auto').value)timer=setInterval(()=>{if(!document.hidden&&!busy)refresh().catch(e=>notice(e.message,true))},+$('auto').value*1000)};
$('refresh-detection').onclick=async()=>{try{await refresh();notice('Firewall detection and rules refreshed.')}catch(e){notice(e.message,true)}};
$('review-detection').onclick=async()=>{if(!confirm('Review the currently detected manager and rules, then allow future operations against this selection? No firewall settings will be changed.'))return;try{const r=await api('/api/detection/review','POST',{confirm:'REVIEW'});status.managerDrift=false;status.managerStateToken=null;renderDetection(r.detection);status.managerStateToken=r.detection.manager_state_token||null;status.read_only_reason='';await refreshManager();notice(r.message)}catch(e){notice(e.message,true)}};
for(const [id,path]of [['ufw-add','/api/ufw/rule'],['ufw-default','/api/ufw/default'],['firewalld-add','/api/firewalld/rule']])$(id).onsubmit=e=>{e.preventDefault();const d=values(e.currentTarget);d.state_token=status.managerStateToken;if(id==='firewalld-add'){d.zone=$('firewalld-zone').value;d.policy=$('firewalld-policy').value;if(d.scope==='policy'&&!status.detection.managers.firewalld.capabilities.policies){notice('firewalld policies are unsupported by this version.',true);return}}if(id==='ufw-add'&&!confirm('Apply this rule through UFW? Risky denies will have a 90-second automatic rollback.'))return;change(path,'POST',d)};
$('firewalld-scope').onchange=()=>{$('firewalld-zone').disabled=$('firewalld-scope').value==='policy';$('firewalld-policy').disabled=$('firewalld-scope').value!=='policy'||!status.detection?.managers.firewalld.capabilities.policies};
for(const [id,action,confirmText]of [['ufw-enable','enable','ENABLE'],['ufw-disable','disable','DISABLE'],['ufw-reload','reload','RELOAD']])$(id).onclick=()=>{const typed=prompt('Type '+confirmText+' to confirm the UFW '+action+' action.');if(typed===confirmText)change('/api/ufw/action','POST',{action,confirm:typed,state_token:status.managerStateToken})};
$('firewalld-reload').onclick=()=>{if(prompt('Type RELOAD to apply permanent firewalld configuration.')==='RELOAD')change('/api/firewalld/reload','POST',{confirm:'RELOAD',state_token:status.managerStateToken})};
for(const id of ['n-search','n-filter'])$(id).addEventListener('input',()=>renderRules(nft,true));for(const id of ['i-search','i-filter'])$(id).addEventListener('input',()=>renderRules(ipt,false));$('i-backend').onchange=()=>{ipt=snapshot?.states[$('i-backend').value];renderRules(ipt,false)};
for(const [id,path]of [['n-add','/api/nft/rule'],['n-chain','/api/nft/chain'],['i-add','/api/iptables/rule'],['i-chain','/api/iptables/chain']])$(id).onsubmit=e=>{e.preventDefault();const d=values(e.currentTarget);if(id.startsWith('i-'))d.backend=$('i-backend').value;if((d.policy==='DROP'||d.policy==='drop')&&!confirm('A DROP policy can disconnect remote access. Continue?'))return;change(path,'POST',d)};
$('i-port').onsubmit=e=>{e.preventDefault();const d=values(e.currentTarget);d.ipv4=$('p-ipv4').checked;d.ipv6=$('p-ipv6').checked;d.stateless=$('p-stateless').checked;if(!d.ipv4&&!d.ipv6){notice('Select IPv4, IPv6, or both.',true);return}const families=d.ipv4&&d.ipv6?'IPv4 + IPv6':d.ipv4?'IPv4':'IPv6';if(!confirm('Allow '+d.protocol.toUpperCase()+' service port '+d.port+' for '+families+' on '+(d.iface||'any interface')+'?\n'+(d.stateless?'Stateless: bypass connection tracking in both directions. NAT will not work for this traffic.':'Normal connection tracking (default).')))return;change('/api/iptables/port','POST',d)};
$('m-form').onsubmit=e=>{e.preventDefault();const d=values(e.currentTarget);d.action=e.submitter?.value||'enable';if(d.action==='enable'&&!confirm('Enable masquerading using these settings?\n'+(d.source||'Any source')+' -> '+(d.iface||'Any outgoing interface')))return;change('/api/masquerade','POST',d)};
$('raw-form').onsubmit=async e=>{e.preventDefault();const r=await change('/api/exec','POST',values(e.currentTarget));if(r)$('raw-out').textContent=r.output};$('backup').onclick=()=>change('/api/backup','POST',{});$('export').onclick=async()=>{try{const r=await fetch('/api/export',{headers:{'X-Secret':key},cache:'no-store'});if(!r.ok){const d=await r.json();throw Error(d.error||'Export failed')}const url=URL.createObjectURL(await r.blob()),a=el('a');a.href=url;a.download='firewall-backup.json';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000)}catch(e){notice(e.message,true)}};
$('persist-ipt').onclick=()=>{if(confirm('Save the current system-default IPv4 AND IPv6 iptables rules (including NAT) and enable netfilter-persistent boot restoration?\n\nThis overwrites rules.v4 and rules.v6 after backing them up. Explicit alternate legacy/nft backends are not all saved together.'))change('/api/persist/iptables','POST',{confirm:'SAVE'})};
$('persist-nft').onclick=()=>{if(confirm('Save current native nftables tables and enable their separate boot restore service?\n\niptables-nft tables are excluded; persist those with the IPv4 + IPv6 button. Keep this script and its Python environment at their installed paths.'))change('/api/persist/nft','POST',{confirm:'SAVE'})};
</script></body></html>'''


if __name__ == '__main__':
    if sys.argv[1:] == ['--restore-native']:
        if not can_manage_firewall():
            raise SystemExit('Native firewall restore requires root with CAP_NET_ADMIN.')
        if os.environ.get('NFT_BACKEND', 'auto').strip().lower() not in ('auto', 'nftables'):
            raise SystemExit('Native firewall restore cancelled by NFT_BACKEND selection.')
        current = detect_firewall()
        if current['active_managers'] or any(
                manager['status'] == 'unknown' for manager in current['managers'].values()):
            raise SystemExit('Native firewall restore cancelled: a manager is active or its state is unknown.')
        try:
            restore_native()
        except Exception as exc:
            raise SystemExit(f'Native firewall restore failed: {exc.message if isinstance(exc, Problem) else exc}')
        raise SystemExit(0)
    args = sys.argv[1:]
    if args in (['--help'], ['-h']):
        print('Usage: firewall-web [--backend auto|ufw|firewalld|nftables|iptables|inspection] [--acknowledge-conflict active-managers:firewalld,ufw] [--detect|--detect-json]')
        print('Set NFT_BACKEND in the service environment to persist backend selection.')
        print('A conflict acknowledgement only selects one of multiple active native managers; it never disables or migrates another manager.')
        raise SystemExit(0)
    while args and args[0] in ('--backend', '--acknowledge-conflict'):
        option = args[0]
        if len(args) < 2:
            raise SystemExit('Missing value for ' + option)
        if option == '--backend':
            if args[1] not in BACKEND_CHOICES:
                raise SystemExit('Invalid backend. Choose auto, ufw, firewalld, nftables, iptables, or inspection.')
            os.environ['NFT_BACKEND'] = args[1]
        else:
            os.environ['NFT_BACKEND_ACK'] = args[1]
        args = args[2:]
    if args and args[0] == '--rollback':
        if len(args) != 2:
            raise SystemExit('Usage: firewall-web --rollback ROLLBACK_ID')
        try:
            run_rollback(args[1])
        except Problem as exc:
            raise SystemExit(f'Firewall rollback failed: {exc.message}')
        raise SystemExit(0)
    report = current_detection()
    if args in (['--detect'], ['--detect-json']):
        if args == ['--detect-json']:
            report['report_version'] = 1
            print(json.dumps(report, sort_keys=True))
        else:
            print(f"Selected backend: {report['selected_backend']}\n{report['reason']}")
        raise SystemExit(0)
    if args:
        raise SystemExit('Usage: firewall-web [--backend auto|ufw|firewalld|nftables|iptables|inspection] [--acknowledge-conflict active-managers:firewalld,ufw] [--detect|--detect-json]')
    if not re.fullmatch(r'[0-9]{4}', SECRET):
        raise SystemExit('Set NFT_SECRET to an access key of exactly four digits. No default key is accepted.')
    try:
        from waitress import serve
    except ImportError:
        raise SystemExit('Install dependencies first: pip install flask waitress')
    mode = 'writable: ' + report['selected_backend'] if report['can_write'] else 'read-only: ' + report['reason']
    print(f'[firewall_web] Detection: {mode}', flush=True)
    print(f'[firewall_web] Listening on {HOST}:{PORT}; {mode}.')
    serve(app, host=HOST, port=PORT, threads=4)
