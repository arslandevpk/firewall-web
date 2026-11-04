#!/usr/bin/env python3
"""Privileged manager API integration checks; run only inside the isolated Docker testbed."""

import json
import subprocess
import sys
import urllib.error
import urllib.request


BASE = 'http://127.0.0.1:5505'
HEADERS = {'Content-Type': 'application/json', 'X-Secret': '1234'}


def api(path, method='GET', payload=None, expected=200):
    request = urllib.request.Request(
        BASE + path,
        data=None if payload is None else json.dumps(payload).encode(),
        headers=HEADERS,
        method=method,
    )
    try:
        response = urllib.request.urlopen(request, timeout=90)
        status, content = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, content = error.code, error.read()
    result = json.loads(content)
    if status != expected:
        raise AssertionError(f'{method} {path}: expected HTTP {expected}, got {status}: {result}')
    return result


def command(*args, expected=0):
    result = subprocess.run(args, text=True, capture_output=True, check=False)
    if result.returncode != expected:
        raise AssertionError(
            f'{args!r}: expected exit {expected}, got {result.returncode}: '
            f'{result.stderr.strip()} {result.stdout.strip()}')
    return result.stdout.strip()


def require_selected(manager):
    detection = api('/api/detection')
    if detection['selected_backend'] != manager:
        raise AssertionError(f'expected {manager}, got {detection["selected_backend"]}: {detection["reason"]}')
    return detection


def ufw_stage():
    require_selected('ufw')
    api('/api/persist/iptables', 'POST', {'confirm': 'SAVE'}, expected=409)
    api('/api/persist/nft', 'POST', {'confirm': 'SAVE'}, expected=409)
    state = api('/api/ufw')
    api('/api/ufw/rule', 'POST', {
        'kind': 'port', 'action': 'allow', 'port': '42424', 'protocol': 'tcp',
        'source': 'any', 'state_token': state['state_token'],
    })
    state = api('/api/ufw')
    route = api('/api/ufw/rule', 'POST', {
        'kind': 'route', 'action': 'allow', 'port': '42425', 'protocol': 'tcp',
        'source': '192.0.2.0/24', 'destination': '198.51.100.0/24',
        'interface_in': 'eth0', 'interface_out': 'eth0',
        'state_token': state['state_token'],
    })
    state = api('/api/ufw')
    route_rule = next(rule for rule in state['rules'] if '42425' in rule['text'])
    deleted_route = api('/api/ufw/rule', 'DELETE', {
        'number': route_rule['number'], 'token': route_rule['token'],
        'state_token': state['state_token'],
    })
    api('/api/rollback/' + deleted_route['pending_rollback_id'] + '/confirm',
        'POST', {'confirm': 'KEEP'})

    stale_state = api('/api/ufw')
    command('ufw', 'allow', '42426/tcp')
    rejected = api('/api/ufw/rule', 'POST', {
        'kind': 'port', 'action': 'allow', 'port': '42427', 'protocol': 'tcp',
        'source': 'any', 'state_token': stale_state['state_token'],
    }, expected=409)
    if 'review' not in rejected['error'].lower() and 'changed' not in rejected['error'].lower():
        raise AssertionError('external UFW update was not explained')
    api('/api/detection/review', 'POST', {'confirm': 'REVIEW'})

    state = api('/api/ufw')
    paired_rule = next(rule for rule in state['rules']
                       if '42424/tcp' in rule['text'] and '(v6)' not in rule['text'])
    deleted = api('/api/ufw/rule', 'DELETE', {
        'number': paired_rule['number'], 'token': paired_rule['token'],
        'state_token': state['state_token'],
    })
    return deleted['pending_rollback_id']


def firewalld_rule(state, *, scope='zone', zone='trusted', policy='fwtest',
                   rule_type='port', value='42428', action='add',
                   configuration='permanent', protocol='tcp', keep=True):
    result = api('/api/firewalld/rule', 'POST', {
        'scope': scope, 'zone': zone, 'policy': policy,
        'type': rule_type, 'value': value, 'action': action,
        'state': configuration, 'protocol': protocol,
        'state_token': state['state_token'],
    })
    if keep and result.get('pending_rollback_id'):
        api('/api/rollback/' + result['pending_rollback_id'] + '/confirm',
            'POST', {'confirm': 'KEEP'})
    state['state_token'] = result['state_token']
    if not keep:
        state['pending_rollback_id'] = result.get('pending_rollback_id')
    return state


def firewalld_stage():
    detection = require_selected('firewalld')
    api('/api/persist/iptables', 'POST', {'confirm': 'SAVE'}, expected=409)
    api('/api/persist/nft', 'POST', {'confirm': 'SAVE'}, expected=409)
    state = api('/api/firewalld')
    if not detection['managers']['firewalld']['capabilities'].get('source_bindings'):
        raise AssertionError('test firewalld does not expose source bindings')
    if not detection['managers']['firewalld']['capabilities'].get('zone_bindings'):
        raise AssertionError('test firewalld does not expose interface bindings')
    if not detection['managers']['firewalld']['capabilities'].get('rich_rules'):
        raise AssertionError('test firewalld does not expose rich rules')
    state = firewalld_rule(state, value='42428', rule_type='port')
    state = firewalld_rule(state, value='198.51.100.0/24', rule_type='source')
    state = firewalld_rule(state, value='lo', rule_type='interface')
    state = firewalld_rule(
        state, value='rule family="ipv4" source address="192.0.2.0/24" '
        'port port="42429" protocol="tcp" accept', rule_type='rich-rule')
    state = firewalld_rule(
        state, scope='policy', value='42430', rule_type='port')
    command('firewall-cmd', '--check-config')
    api('/api/firewalld/reload', 'POST', {
        'confirm': 'RELOAD', 'state_token': state['state_token'],
    })
    state = api('/api/firewalld')
    for args in (
            ('--permanent', '--zone=trusted', '--query-port=42428/tcp'),
            ('--permanent', '--zone=trusted', '--query-source=198.51.100.0/24'),
            ('--permanent', '--zone=trusted', '--query-interface=lo'),
            ('--permanent', '--zone=trusted', '--query-rich-rule=rule family="ipv4" source address="192.0.2.0/24" port port="42429" protocol="tcp" accept'),
            ('--permanent', '--policy=fwtest', '--query-port=42430/tcp'),
            ('--zone=trusted', '--query-port=42428/tcp'),
            ('--policy=fwtest', '--query-port=42430/tcp')):
        command('firewall-cmd', *args)

    state = firewalld_rule(state, value='42431', configuration='runtime')
    command('firewall-cmd', '--zone=trusted', '--query-port=42431/tcp')
    command('firewall-cmd', '--permanent', '--zone=trusted', '--query-port=42431/tcp', expected=1)
    api('/api/firewalld/reload', 'POST', {
        'confirm': 'RELOAD', 'state_token': state['state_token'],
    })
    state = api('/api/firewalld')
    command('firewall-cmd', '--zone=trusted', '--query-port=42431/tcp', expected=1)

    state = firewalld_rule(state, value='42432', configuration='runtime', keep=False)
    return state['state_token'], state.get('pending_rollback_id')


def firewalld_after_rollback(rollback_id):
    record = api('/api/rollback/' + rollback_id)
    if record['status'] != 'rolled_back':
        raise AssertionError(f'worker did not roll back after web process exit: {record}')
    command('firewall-cmd', '--zone=trusted', '--query-port=42432/tcp', expected=1)
    state = api('/api/firewalld')
    pending = firewalld_rule(state, value='42433', configuration='runtime', keep=False)
    command('firewall-cmd', '--zone=trusted', '--add-port=42434/tcp')
    return pending['state_token'], pending.get('pending_rollback_id')


def firewalld_after_external_change(rollback_id):
    record = api('/api/rollback/' + rollback_id)
    if record['status'] != 'conflict':
        raise AssertionError(f'rollback overwrote or missed external change: {record}')
    command('firewall-cmd', '--zone=trusted', '--query-port=42433/tcp')
    command('firewall-cmd', '--zone=trusted', '--query-port=42434/tcp')
    command('firewall-cmd', '--permanent', '--zone=trusted', '--add-port=41112/tcp')
    command('firewall-cmd', '--reload')
    command('firewall-cmd', '--zone=trusted', '--query-port=41112/tcp')
    return True


if __name__ == '__main__':
    mode = sys.argv[1]
    if mode == 'ufw':
        print(ufw_stage())
    elif mode == 'firewalld':
        _, rollback_id = firewalld_stage()
        print(rollback_id)
    elif mode == 'firewalld-after-rollback':
        _, rollback_id = firewalld_after_rollback(sys.argv[2])
        print(rollback_id)
    elif mode == 'firewalld-after-external-change':
        firewalld_after_external_change(sys.argv[2])
    else:
        raise SystemExit('Unknown integration-test mode.')
