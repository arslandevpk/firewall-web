#!/usr/bin/env python3
import json
import os
import sys
import time
from unittest import mock
import urllib.error
import urllib.request


sys.path.insert(0, '/repo/firewall-web-standalone')
import firewall_web

base = 'http://127.0.0.1:5505'
secret = '1234'

if os.geteuid() == 0:
    with mock.patch.dict(os.environ, {'PROOT_TMP_DIR': '/tmp/proot'}):
        with mock.patch.object(firewall_web, 'has_net_admin', return_value=True):
            assert firewall_web.can_manage_firewall() is False
            assert 'PRoot' in firewall_web.read_only_reason()


def request(path, method='GET'):
    req = urllib.request.Request(
        base + path,
        data=b'{}' if method == 'POST' else None,
        headers={'X-Secret': secret, 'Content-Type': 'application/json'},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


for attempt in range(30):
    try:
        page = urllib.request.urlopen(base, timeout=2).read()
        break
    except OSError:
        if attempt == 29:
            raise
        time.sleep(1)

font = urllib.request.urlopen(base + '/fonts/JetBrainsMono.woff2', timeout=5).read()
status_code, status_body = request('/api/status')
status = json.loads(status_body)
assert status_code == 200 and status['root'] is True
assert status['can_manage_firewall'] is False
assert 'CAP_NET_ADMIN' in status['read_only_reason']
assert b'Termux PRoot' in page and font
write_code, write_body = request('/api/backup', 'POST')
assert write_code == 403 and b'CAP_NET_ADMIN' in write_body
write_code, write_body = request('/api/iptables/port', 'POST')
assert write_code == 403 and b'CAP_NET_ADMIN' in write_body
print('Userspace UI, bundled font, and enforced read-only mode passed')
