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
TABLES = ('filter', 'nat', 'mangle', 'raw', 'security')
BACKENDS = {
    'iptables': 'iptables-save', 'ip6tables': 'ip6tables-save',
    'iptables-nft': 'iptables-nft-save', 'ip6tables-nft': 'ip6tables-nft-save',
    'iptables-legacy': 'iptables-legacy-save',
    'ip6tables-legacy': 'ip6tables-legacy-save',
}


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
            timeout=12, env={'PATH': PATH, 'LC_ALL': 'C'}, check=False,
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
    saved = json.loads(NATIVE_STATE.read_text())
    current = json.loads(checked('nft', ['-j', 'list', 'tables']))
    present = {(x['table']['family'], x['table']['name']) for x in current.get('nftables', []) if 'table' in x}
    owned = compatibility_tables()
    if any((x['family'], x['name']) in owned for x in saved.get('tables', [])):
        raise Problem('A saved native table is now owned by iptables-nft; restore cancelled to preserve it.', 500)
    # One atomic transaction. Replace only saved native tables; no global flush.
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


@app.after_request
def headers(response):
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
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


@app.get('/api/status')
def status():
    installed = [n for n in BACKENDS if executable(n)]
    def flag(path):
        try:
            return Path(path).read_text().strip() == '1'
        except OSError:
            return None
    return jsonify(nft=bool(executable('nft')), backends=installed,
                   root=os.geteuid() == 0, interfaces=[n for _, n in socket.if_nameindex()],
                   can_manage_firewall=can_manage_firewall(), read_only_reason=read_only_reason(),
                   forwarding={'ip': flag('/proc/sys/net/ipv4/ip_forward'),
                               'ip6': flag('/proc/sys/net/ipv6/conf/all/forwarding')})


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
        # Fail before writing if either IP family cannot be read.
        checked('iptables-save')
        checked('ip6tables-save')
        saved = backup('iptables')
        config_saved = config_backup(IPT_FILES)
        checked('netfilter-persistent', ['save'])
        for path, saver, restorer in zip(IPT_FILES, ('iptables-save', 'ip6tables-save'),
                                        ('iptables-restore', 'ip6tables-restore')):
            if not path.is_file():
                raise Problem(f'Save did not produce {path}. Some persistence files may have changed; boot persistence is not confirmed.', 500)
            content = path.read_text()
            if canonical_save(content) != canonical_save(checked(saver)):
                raise Problem(f'{path} does not match current rules. Check plugin skip-save settings or concurrent changes, then retry. Some files may have been updated.', 409)
            checked(restorer, ['--test'], stdin=content)
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
        checked('systemctl', ['daemon-reload'])
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
.color-control{display:flex;align-items:center;gap:12px}
.color-control input[type=color]{width:56px;min-width:56px;max-width:56px;height:42px;padding:3px;cursor:pointer}
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
<button id="tab-overview" role="tab" aria-selected="true" aria-controls="overview" class="tab active" data-tab="overview"><span class="nav-index" aria-hidden="true">01</span>All Rules</button>
<button id="tab-nft" role="tab" aria-selected="false" aria-controls="nft" tabindex="-1" class="tab" data-tab="nft"><span class="nav-index" aria-hidden="true">02</span>nftables</button>
<button id="tab-ipt" role="tab" aria-selected="false" aria-controls="ipt" tabindex="-1" class="tab" data-tab="ipt"><span class="nav-index" aria-hidden="true">03</span>iptables</button>
<button id="tab-masq" role="tab" aria-selected="false" aria-controls="masq" tabindex="-1" class="tab" data-tab="masq"><span class="nav-index" aria-hidden="true">04</span>Masquerade</button>
<p class="nav-group" role="presentation">Administration</p>
<button id="tab-persistence" role="tab" aria-selected="false" aria-controls="persistence" tabindex="-1" class="tab" data-tab="persistence"><span class="nav-index" aria-hidden="true">05</span>Persistence</button>
<button id="tab-backups" role="tab" aria-selected="false" aria-controls="backups" tabindex="-1" class="tab" data-tab="backups"><span class="nav-index" aria-hidden="true">06</span>Backups</button>
<button id="tab-advanced" role="tab" aria-selected="false" aria-controls="advanced" tabindex="-1" class="tab" data-tab="advanced"><span class="nav-index" aria-hidden="true">07</span>Advanced</button>
<p class="nav-group" role="presentation">Personalization</p>
<button id="tab-display" role="tab" aria-selected="false" aria-controls="display" tabindex="-1" class="tab" data-tab="display"><span class="nav-index" aria-hidden="true">08</span>Display and Feel</button>
</nav>
<div class="sidebar-footer"><strong>Live firewall</strong>Save edits in Persistence to restore them after boot.</div>
<button id="sidebar-close" class="sidebar-close">Close menu</button>
</aside>
<div id="nav-backdrop" class="nav-backdrop" aria-hidden="true"></div>
<div id="workspace" class="workspace">
<header class="page-heading"><button id="menu-toggle" class="menu-toggle" aria-controls="sidebar" aria-expanded="false" aria-label="Open sections">Sections</button><div><h2 id="page-title">All Rules</h2><p id="page-description" class="muted">A complete view of the firewall backends installed on this machine.</p></div></header>
<div class="row between toolbar"><div id="badges"></div><div class="row toolbar-actions"><button id="refresh" class="primary">Refresh</button><label>Auto-refresh<select id="auto"><option value="0">Off</option><option value="15">15 seconds</option><option value="30">30 seconds</option></select></label><button id="logout">Lock</button></div></div><p id="access-warning" class="muted notice warning hidden" role="status"></p>
<section id="overview" class="panel" role="tabpanel" aria-labelledby="tab-overview" tabindex="0"><div class="card"><h2>All installed firewall views</h2><p class="muted">Full listings include all tables. iptables-nft overlaps with nftables; default and explicit backend commands may show the same rules. These are views, not independent rule totals.</p><div id="all-views"></div></div></section>
<section id="nft" class="panel hidden" role="tabpanel" aria-labelledby="tab-nft" tabindex="0">
<div class="card"><h2>nftables rules</h2><div class="row"><label class="wide">Search<input id="n-search" placeholder="Family, table, chain, expression or comment"></label><label>Filter<select id="n-filter"><option value="all">All rules</option><option value="masq">Masquerade only</option></select></label></div><div id="n-rules"></div><details><summary>Complete native ruleset | handles included</summary><pre id="n-raw"></pre></details></div>
<form class="card firewall-write-form" id="n-add"><h2>Add nftables rule</h2><div class="row"><label>Family<select name="family"><option>inet</option><option>ip</option><option>ip6</option><option>bridge</option><option>arp</option><option>netdev</option></select></label><label>Table<input name="table" value="filter" required></label><label>Chain<input name="chain" value="input" required></label><label>Position<select name="operation"><option value="add">Append</option><option value="insert">Insert first</option></select></label></div><label>Rule expression<textarea name="rule" placeholder="ct state established,related counter accept" required></textarea></label><p class="muted">Use existing tables/chains, or create one below. Names are case-sensitive.</p><button class="good">Add rule</button></form>
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
<div class="setting-control"><label for="background-color">Background color</label><div class="color-control"><input id="background-color" type="color" value="#0d1117"><span class="muted">Choose a custom page background.</span></div></div>
<div class="setting-control"><label for="font-color">Font color</label><div class="color-control"><input id="font-color" type="color" value="#d7dfe8"><span class="muted">Choose the primary text color.</span></div></div>
<div class="setting-control"><h3>Quick looks</h3><p class="muted">Choose from six curated palettes, three light and three dark.</p><div id="appearance-presets" class="presets"></div></div>
</div></section>
<p id="updated" class="muted"></p></div></div></section><div id="toast" class="hidden" role="status"></div>
<footer class="site-credit"><em>Created &amp; Conceptualized by <a href="https://github.com/arslandevpk/firewall-web" target="_blank" rel="noopener noreferrer">arslandevpk</a></em></footer>
</main><script>
'use strict';
const $=id=>document.getElementById(id);let key='',status={},snapshot=null,nft=null,ipt=null,busy=false,refreshing=false,timer=null,firewallWritable=false;
function el(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e}
const appearanceKey='firewall-web-appearance';
const fontFamilies=['JetBrains Mono,ui-monospace,monospace','Hack,ui-monospace,monospace','Fira Code,ui-monospace,monospace','Source Code Pro,ui-monospace,monospace','Cascadia Code,ui-monospace,monospace','IBM Plex Mono,ui-monospace,monospace','Inconsolata,ui-monospace,monospace'];
const colorPresets=[
{name:'Paper',theme:'light',bg:'#f4f6f8',text:'#1f2328'},
{name:'Warm Sand',theme:'light',bg:'#f5efe6',text:'#332719'},
{name:'Soft Mint',theme:'light',bg:'#eaf4ef',text:'#18352a'},
{name:'Midnight',theme:'dark',bg:'#0d1117',text:'#d7dfe8'},
{name:'Deep Ocean',theme:'dark',bg:'#0a1929',text:'#d5e8ff'},
{name:'Forest',theme:'dark',bg:'#102019',text:'#d7eee0'}];
let appearance={theme:'system',font:fontFamilies[0],size:14,bg:'',text:'',animate:!matchMedia('(prefers-reduced-motion: reduce)').matches};
try{const saved=JSON.parse(localStorage.getItem(appearanceKey)||'{}');if(['system','light','dark'].includes(saved.theme))appearance.theme=saved.theme;if(fontFamilies.includes(saved.font))appearance.font=saved.font;if(Number.isInteger(saved.size)&&saved.size>=12&&saved.size<=20)appearance.size=saved.size;if(typeof saved.bg==='string'&&/^#[0-9a-f]{6}$/i.test(saved.bg))appearance.bg=saved.bg;if(typeof saved.text==='string'&&/^#[0-9a-f]{6}$/i.test(saved.text))appearance.text=saved.text;if(typeof saved.animate==='boolean')appearance.animate=saved.animate}catch(error){console.warn('Could not load saved appearance settings:',error)}
function applyAppearance(save=true){const root=document.documentElement;const effective=appearance.theme==='system'?(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'):appearance.theme;root.dataset.theme=effective;root.style.setProperty('--ui-font-family',appearance.font);root.style.setProperty('--ui-font-size',appearance.size+'px');if(appearance.bg)root.style.setProperty('--bg',appearance.bg);else root.style.removeProperty('--bg');if(appearance.text)root.style.setProperty('--text',appearance.text);else root.style.removeProperty('--text');$('theme-select').value=appearance.theme;$('font-family').value=appearance.font;$('font-size').value=appearance.size;$('font-size-value').textContent=appearance.size+'px';$('background-color').value=appearance.bg|| (effective==='dark'?'#0d1117':'#f4f6f8');$('font-color').value=appearance.text|| (effective==='dark'?'#d7dfe8':'#1f2328');$('header-animation').checked=appearance.animate;for(const button of document.querySelectorAll('.preset'))button.setAttribute('aria-pressed',String(colorPresets.some(p=>p.name===button.dataset.preset&&p.theme===appearance.theme&&p.bg===appearance.bg&&p.text===appearance.text)));if(save){try{localStorage.setItem(appearanceKey,JSON.stringify(appearance))}catch(error){notice('Appearance updated but could not be saved in this browser: '+error.message,true)}}}
function initAppearance(){const holder=$('appearance-presets');for(const preset of colorPresets){const button=el('button',undefined,'preset');button.type='button';button.dataset.preset=preset.name;button.setAttribute('aria-pressed','false');const swatch=el('span','A','preset-swatch');swatch.style.background=preset.bg;swatch.style.color=preset.text;button.append(swatch,el('span',preset.name+' · '+preset.theme));button.onclick=()=>{appearance.theme=preset.theme;appearance.bg=preset.bg;appearance.text=preset.text;applyAppearance()};holder.append(button)}$('theme-select').onchange=()=>{appearance.theme=$('theme-select').value;applyAppearance()};$('font-family').onchange=()=>{appearance.font=$('font-family').value;applyAppearance()};$('font-size').oninput=()=>{appearance.size=Number($('font-size').value);applyAppearance()};$('background-color').oninput=()=>{appearance.bg=$('background-color').value;applyAppearance()};$('font-color').oninput=()=>{appearance.text=$('font-color').value;applyAppearance()};$('header-animation').onchange=()=>{appearance.animate=$('header-animation').checked;applyAppearance();setHeaderAnimation(appearance.animate)};matchMedia('(prefers-color-scheme: dark)').addEventListener('change',()=>{if(appearance.theme==='system')applyAppearance(false)});applyAppearance(false);setHeaderAnimation(appearance.animate)}
let headerTimer=null;
function setHeaderAnimation(enabled){clearTimeout(headerTimer);const text=$('brand-text'),full='firewall_web';let index=enabled?0:full.length,deleting=false;text.textContent=full.slice(0,index);if(!enabled)return;function type(){index++;text.textContent=full.slice(0,index);if(index===full.length){deleting=true;headerTimer=setTimeout(erase,1000)}else headerTimer=setTimeout(type,130)}function erase(){index--;text.textContent=full.slice(0,index);if(index===0){deleting=false;headerTimer=setTimeout(type,350)}else headerTimer=setTimeout(erase,95)}headerTimer=setTimeout(type,350)}
function notice(message,error=false){const t=$('toast');t.textContent=message;t.className=error?'error':'';clearTimeout(t._timer);t._timer=setTimeout(()=>t.classList.add('hidden'),error?12000:5005)}
async function api(path,method='GET',body=null){const r=await fetch(path,{method,headers:{'Content-Type':'application/json','X-Secret':key},body:body===null?null:JSON.stringify(body),cache:'no-store'});let d;try{d=await r.json()}catch{throw Error('Server returned an invalid response ('+r.status+').')}if(!r.ok||d.error)throw Error(d.error||'HTTP '+r.status);return d}
function values(form){return Object.fromEntries(new FormData(form).entries())}
function options(node,items){const old=node.value;node.replaceChildren();for(const [value,label] of items){const o=el('option',label);o.value=value;node.append(o)}if(items.some(x=>x[0]===old))node.value=old}
function setFirewallWritable(allowed,reason=''){firewallWritable=allowed;for(const form of document.querySelectorAll('.firewall-write-form'))for(const control of form.elements)control.disabled=!allowed;for(const id of ['persist-ipt','persist-nft','backup'])$(id).disabled=!allowed;$('access-warning').textContent=reason;$('access-warning').classList.toggle('hidden',allowed)}
async function change(path,method,body){if(!firewallWritable){notice(status.read_only_reason||'Firewall changes are disabled without CAP_NET_ADMIN.',true);return}if(busy)return;busy=true;$('app').setAttribute('aria-busy','true');try{const r=await api(path,method,body);notice((r.message||'Change applied.')+(r.backup?' Backup: '+r.backup:''));await refresh(true);return r}catch(e){notice(e.message,true)}finally{busy=false;$('app').setAttribute('aria-busy','false')}}
function display(expr){if(expr===null)return '';if(typeof expr!=='object')return String(expr);if(Array.isArray(expr))return expr.map(display).join(', ');if(expr.payload)return expr.payload.protocol+' '+expr.payload.field;if(expr.meta)return 'meta '+expr.meta.key;if(expr.ct)return 'ct '+expr.ct.key;if(expr.prefix)return expr.prefix.addr+'/'+expr.prefix.len;if(expr.set)return '{ '+display(expr.set)+' }';if(expr.range)return expr.range.map(display).join('-');if(expr.match){const m=expr.match;return display(m.left)+' '+(m.op==='=='?'':m.op+' ')+display(m.right)}if(expr.counter)return 'counter packets '+(expr.counter.packets||0)+' bytes '+(expr.counter.bytes||0);for(const k of ['accept','drop','return','continue','masquerade'])if(k in expr)return k+(expr[k]?' '+JSON.stringify(expr[k]):'');for(const k of ['jump','goto'])if(expr[k])return k+' '+expr[k].target;return JSON.stringify(expr)}
function ruleTable(rules,isNft){const table=el('table',undefined,'rules');const head=el('tr');for(const h of isNft?['Handle','Expression / comment','Action']:['#','Packets / bytes','Rule options','Action'])head.append(el('th',h));table.append(head);for(const r of rules){const row=el('tr');row.append(el('td',String(isNft?r.handle:r.number)));if(!isNft)row.append(el('td',r.packets+' / '+r.bytes));row.append(el('td',isNft?r.expr.map(display).join(' ')+(r.comment?' | comment '+r.comment:''):r.expression,'expr'));const cell=el('td'),button=el('button','Delete','danger');button.disabled=!firewallWritable;button.onclick=()=>{if(!firewallWritable)return;if(!confirm('Delete this exact rule?\n'+(isNft?r.expr.map(display).join(' '):r.expression)))return;change(isNft?'/api/nft/rule':'/api/iptables/rule','DELETE',isNft?{family:r.family,table:r.table,chain:r.chain,handle:r.handle,token:r.token}:{backend:ipt.backend,table:r.table,chain:r.chain,token:r.token})};cell.append(button);row.append(cell)}return table}
function renderRules(state,isNft){const prefix=isNft?'n':'i',holder=$(prefix+'-rules');holder.replaceChildren();if(!state||state.error){holder.append(el('p',state?.error||'Backend unavailable.','muted'));$(prefix+'-raw').textContent=state?.error||'';return}const query=$(prefix+'-search').value.toLowerCase(),onlyMasq=$(prefix+'-filter').value==='masq';$(prefix+'-raw').textContent=state.raw||'(empty ruleset)';if(!isNft)$('i-version').textContent=state.version+' | IPv'+(state.backend.startsWith('ip6')?'6':'4');for(const c of state.chains){const f=isNft?c.family+' ':'';let rows=state.rules.filter(r=>r.table===c.table&&r.chain===c.name&&(!isNft||r.family===c.family));rows=rows.filter(r=>(!onlyMasq||r.masquerade)&&JSON.stringify(r).toLowerCase().includes(query));if((query||onlyMasq)&&!rows.length)continue;const details=el('details');details.open=true;const info=f+c.table+' / '+c.name+' | '+rows.length+' rules'+(c.policy?' | policy '+c.policy:'')+(c.hook?' | '+c.type+' / '+c.hook+' / priority '+c.prio:'');details.append(el('summary',info));const scroll=el('div',undefined,'scroll');scroll.append(rows.length?ruleTable(rows,isNft):el('p','No rules in this chain.','muted'));details.append(scroll);holder.append(details)}if(!state.chains.length)holder.append(el('p','No tables/chains in this view.','muted'))}
function overviewView(){const host=$('all-views');host.replaceChildren();for(const [name,state]of Object.entries(snapshot.states)){const d=el('details');d.append(el('summary',name+' | '+(state.error?'unavailable':state.rules.length+' rules / '+state.chains.length+' chains')+(state.version?' | '+state.version:'')));d.append(el('pre',state.error||state.raw||'(empty ruleset)'));host.append(d)}if(!host.children.length)host.append(el('p','No firewall executables found. Install nftables and/or iptables on the target host.','muted'))}
async function refresh(force=false){if(refreshing||(busy&&!force)||!key)return;refreshing=true;try{snapshot=await api('/api/overview');nft=snapshot.states.nft;ipt=snapshot.states[$('i-backend').value];overviewView();renderRules(nft,true);renderRules(ipt,false);$('updated').textContent='Last refreshed '+new Date().toLocaleString()+' | Rule counters are snapshots.'}finally{refreshing=false}}
$('login').onsubmit=async e=>{e.preventDefault();key=$('key').value;try{status=await api('/api/status');$('key').value='';$('app').classList.remove('hidden');$('login').classList.add('hidden');setFirewallWritable(status.can_manage_firewall===true,status.read_only_reason||'');$('connection').textContent='Unlocked | '+(status.can_manage_firewall?'firewall access':'read-only');options($('i-backend'),status.backends.map(n=>[n,n]));const engines=[...(status.nft?[['nft','nftables']]:[]),...status.backends.map(n=>[n,n])];options($('m-engine'),engines);options($('raw-engine'),engines);options($('m-iface'),[['','Any interface'],...status.interfaces.filter(n=>n!=='lo').map(n=>[n,n])]);options($('p-iface'),[['','Any interface'],...status.interfaces.map(n=>[n,n])]);$('badges').replaceChildren();for(const [label,value]of [['IPv4 forwarding',status.forwarding.ip],['IPv6 forwarding',status.forwarding.ip6]])$('badges').append(el('span',label+': '+(value===null?'unknown':value?'on':'off'),'badge'));await refresh()}catch(err){key='';notice(err.message,true)}};
$('logout').onclick=()=>{setSidebar(false,false);key='';snapshot=nft=ipt=null;$('app').classList.add('hidden');$('login').classList.remove('hidden');$('connection').textContent='Locked';clearInterval(timer);$('auto').value='0';$('all-views').replaceChildren();$('n-rules').replaceChildren();$('i-rules').replaceChildren();$('n-raw').textContent='';$('i-raw').textContent='';$('raw-out').textContent='Output appears here.';$('key').focus()};
const sectionInfo={overview:['All Rules','A complete view of the firewall backends installed on this machine.'],nft:['nftables','Inspect native tables and chains, then add or remove individual rules.'],ipt:['iptables','Manage IPv4 and IPv6 rules using the backend you select.'],masq:['Masquerade','Configure source NAT for an outgoing interface and subnet.'],persistence:['Persistence','Save firewall changes and enable their restoration after boot.'],backups:['Backups','Keep a protected snapshot on the server or download your own copy.'],advanced:['Advanced','Run an explicit firewall command when you need more control.']};
sectionInfo.display=['Display and Feel','Personalize theme, font, text size, and colors in this browser.'];
const mobileNav=window.matchMedia('(max-width:820px)');
function setSidebar(open,restoreFocus=true){open=Boolean(open&&mobileNav.matches);const wasOpen=$('app').classList.contains('sidebar-open');$('app').classList.toggle('sidebar-open',open);document.body.classList.toggle('drawer-open',open);$('workspace').inert=open;$('menu-toggle').setAttribute('aria-expanded',String(open));$('menu-toggle').setAttribute('aria-label',open?'Close sections':'Open sections');if(open)document.querySelector('.tab.active').focus();else if(wasOpen&&restoreFocus)$('menu-toggle').focus()}
function activateTab(id,closeMenu=true){if(!Object.hasOwn(sectionInfo,id))id='overview';for(const b of document.querySelectorAll('.tab')){const selected=b.dataset.tab===id;b.classList.toggle('active',selected);b.setAttribute('aria-selected',String(selected));b.tabIndex=selected?0:-1}for(const p of document.querySelectorAll('.panel'))p.classList.toggle('hidden',p.id!==id);$('page-title').textContent=sectionInfo[id][0];$('page-description').textContent=sectionInfo[id][1];history.replaceState(null,'','#'+id);const wasOpen=$('app').classList.contains('sidebar-open');if(closeMenu){setSidebar(false,false);if(wasOpen)$(id).focus({preventScroll:true})}}
const navigationTabs=Array.from(document.querySelectorAll('.tab'));
for(const [i,b]of navigationTabs.entries()){b.onclick=()=>activateTab(b.dataset.tab);b.onkeydown=e=>{let next=null;if(e.key==='ArrowDown')next=(i+1)%navigationTabs.length;if(e.key==='ArrowUp')next=(i+navigationTabs.length-1)%navigationTabs.length;if(e.key==='Home')next=0;if(e.key==='End')next=navigationTabs.length-1;if(next!==null){e.preventDefault();activateTab(navigationTabs[next].dataset.tab,false);navigationTabs[next].focus()}}}
$('menu-toggle').onclick=()=>setSidebar(!$('app').classList.contains('sidebar-open'));$('sidebar-close').onclick=()=>setSidebar(false);$('nav-backdrop').onclick=()=>setSidebar(false);mobileNav.addEventListener('change',()=>setSidebar(false,false));
document.addEventListener('keydown',e=>{if(!$('app').classList.contains('sidebar-open'))return;if(e.key==='Escape'){e.preventDefault();setSidebar(false)}else if(e.key==='Tab'){const first=document.querySelector('.tab.active'),last=$('sidebar-close');if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus()}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus()}}});
window.addEventListener('hashchange',()=>activateTab(location.hash.slice(1),false));activateTab(location.hash.slice(1),false);initAppearance();
$('refresh').onclick=()=>refresh().catch(e=>notice(e.message,true));$('auto').onchange=()=>{clearInterval(timer);if(+$('auto').value)timer=setInterval(()=>{if(!document.hidden&&!busy)refresh().catch(e=>notice(e.message,true))},+$('auto').value*1000)};
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
        try:
            restore_native()
        except Exception as exc:
            raise SystemExit(f'Native firewall restore failed: {exc.message if isinstance(exc, Problem) else exc}')
        raise SystemExit(0)
    if not re.fullmatch(r'[0-9]{4}', SECRET):
        raise SystemExit('Set NFT_SECRET to an access key of exactly four digits. No default key is accepted.')
    try:
        from waitress import serve
    except ImportError:
        raise SystemExit('Install dependencies first: pip install flask waitress')
    mode = 'firewall access' if can_manage_firewall() else 'read-only (' + read_only_reason() + ')'
    print(f'[firewall_web] Listening on {HOST}:{PORT}; {mode}.')
    serve(app, host=HOST, port=PORT, threads=4)
