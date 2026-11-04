import json
import unittest
from unittest import mock

import firewall_web as fw


NFT_EMPTY = json.dumps({'nftables': []})
NFT_FIREWALLD = json.dumps({'nftables': [
    {'table': {'family': 'inet', 'name': 'firewalld'}},
    {'chain': {'family': 'inet', 'table': 'firewalld', 'name': 'filter_INPUT'}},
    {'rule': {'family': 'inet', 'table': 'firewalld', 'chain': 'filter_INPUT',
              'expr': [{'accept': None}]}},
]})
SAVE_EMPTY = '*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n'
SAVE_POPULATED = ('*filter\n:INPUT ACCEPT [0:0]\n'
                  '-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n')


class FirewallDetectionTests(unittest.TestCase):
    def setUp(self):
        fw.SELECTED_BACKEND_AT_START = None
        fw.SELECTION_REVIEW_REQUIRED = False

    def run_detection(self, *, ufw='missing', firewalld='missing',
                      nft=NFT_EMPTY, saves=None, nft_permission=False):
        saves = saves or {}

        def probe(name, args=()):
            if name == 'ufw':
                if ufw == 'missing':
                    return {'installed': False, 'available': False}
                if args == ['status', 'verbose']:
                    output = 'Status: active\n' if ufw == 'active' else 'Status: inactive\n'
                    return {'installed': True, 'available': True, 'output': output}
                if args == ['status', 'numbered']:
                    return {'installed': True, 'available': True, 'output': 'Status: active\n'}
                if args == ['--version']:
                    return {'installed': True, 'available': True, 'output': 'ufw 0.36.2'}
            if name == 'firewall-cmd':
                if firewalld == 'missing':
                    return {'installed': False, 'available': False}
                if args == ['--state']:
                    if firewalld == 'inactive-error':
                        return {'installed': True, 'available': False,
                                'returncode': 252, 'error': 'FirewallD is not running'}
                    return {'installed': True, 'available': True,
                            'output': 'running' if firewalld == 'active' else 'not running'}
                if args == ['--get-active-zones']:
                    return {'installed': True, 'available': True,
                            'output': 'public\n  interfaces: eth0' if firewalld == 'active' else ''}
                if args == ['--version']:
                    return {'installed': True, 'available': True, 'output': '2.1.0'}
            if name.endswith('-save'):
                content = saves.get(name, SAVE_EMPTY)
                return {'installed': True, 'available': True, 'output': content}
            if name == 'nft':
                if args == ['-j', '-a', '-n', 'list', 'ruleset']:
                    if nft_permission:
                        return {'installed': True, 'available': False, 'permission_denied': True,
                                'error': 'Permission denied'}
                    return {'installed': True, 'available': True, 'output': nft}
                if args == ['--version']:
                    return {'installed': True, 'available': True, 'output': 'nftables v1.0.9'}
            if name == 'iptables' and args == ['--version']:
                return {'installed': True, 'available': True, 'output': 'iptables v1.8.10 (nf_tables)'}
            if name == 'ss':
                return {'installed': True, 'available': True, 'output': ''}
            return {'installed': False, 'available': False}

        installed = {'nft', 'ss', 'iptables', 'ufw', 'firewall-cmd',
                     'iptables-save', 'ip6tables-save', 'iptables-nft-save',
                     'ip6tables-nft-save', 'iptables-legacy-save',
                     'ip6tables-legacy-save'}
        with (mock.patch.object(fw, '_probe', side_effect=probe),
              mock.patch.object(fw, 'executable',
                                side_effect=lambda name: '/usr/sbin/' + name if name in installed else None),
              mock.patch.object(fw, '_systemd_service',
                                return_value={'available': True, 'active': False, 'enabled': False}),
              mock.patch.object(fw, 'can_manage_firewall', return_value=True)):
            return fw.detect_firewall()

    def test_active_ufw_owns_iptables_nft_and_legacy_rules(self):
        result = self.run_detection(
            ufw='active',
            saves={'iptables-save': SAVE_POPULATED,
                   'iptables-nft-save': SAVE_POPULATED,
                   'iptables-legacy-save': SAVE_POPULATED})
        self.assertEqual(result['selected_backend'], 'ufw')
        self.assertTrue(result['manager_can_write'])
        self.assertFalse(result['can_write'])

    def test_active_firewalld_is_not_counted_as_direct_nft(self):
        result = self.run_detection(firewalld='active', nft=NFT_FIREWALLD)
        self.assertEqual(result['selected_backend'], 'firewalld')
        self.assertEqual(result['direct']['nftables']['status'], 'empty')

    def test_competing_active_managers_require_inspection(self):
        result = self.run_detection(ufw='active', firewalld='active')
        self.assertEqual(result['selected_backend'], 'inspection')
        self.assertEqual(set(result['active_managers']), {'ufw', 'firewalld'})

    def test_inactive_manager_and_empty_ruleset_remain_inspection_only(self):
        result = self.run_detection(ufw='inactive', firewalld='inactive')
        self.assertEqual(result['selected_backend'], 'inspection')
        self.assertEqual(result['managers']['ufw']['status'], 'inactive')
        self.assertEqual(result['managers']['firewalld']['status'], 'inactive')
        self.assertIn('no firewall will be enabled', result['reason'])

    def test_firewalld_explicit_not_running_error_is_known_inactive(self):
        result = self.run_detection(firewalld='inactive-error')
        self.assertEqual(result['managers']['firewalld']['status'], 'inactive')
        self.assertNotIn('firewalld', result['active_managers'])

    def test_permission_denied_detection_is_unknown_not_empty(self):
        result = self.run_detection(nft_permission=True)
        self.assertEqual(result['selected_backend'], 'inspection')
        self.assertEqual(result['direct']['nftables']['status'], 'unknown')
        self.assertIn('permission was denied', result['reason'])

    def test_native_nft_rules_select_direct_nftables(self):
        payload = {'nftables': [
            {'table': {'family': 'inet', 'name': 'filter'}},
            {'chain': {'family': 'inet', 'table': 'filter', 'name': 'input'}},
            {'rule': {'family': 'inet', 'table': 'filter', 'chain': 'input',
                      'expr': [{'accept': None}]}},
        ]}
        result = self.run_detection(nft=json.dumps(payload))
        self.assertEqual(result['selected_backend'], 'nftables')
        self.assertTrue(result['can_write'])

    def test_native_nft_drop_policy_selects_direct_nftables(self):
        payload = {'nftables': [
            {'table': {'family': 'inet', 'name': 'filter'}},
            {'chain': {'family': 'inet', 'table': 'filter', 'name': 'input',
                       'type': 'filter', 'hook': 'input', 'policy': 'drop'}},
        ]}
        result = self.run_detection(nft=json.dumps(payload))
        self.assertEqual(result['selected_backend'], 'nftables')
        self.assertEqual(result['direct']['nftables']['status'], 'populated')

    def test_backend_change_during_process_requires_explicit_review(self):
        with mock.patch.object(fw, 'detect_firewall',
                               side_effect=[{'selected_backend': 'nftables'},
                                            {'selected_backend': 'ufw'}]):
            first = fw.current_detection()
            second = fw.current_detection()
        self.assertFalse(first['selection_review_required'])
        self.assertTrue(second['selection_review_required'])
        self.assertEqual(second['previous_backend'], 'nftables')

    def test_direct_editor_is_rejected_when_ufw_is_selected(self):
        detection = {'selected_backend': 'ufw', 'manager_can_write': True,
                     'can_write': False, 'reason': 'UFW is the active manager.',
                     'selection_review_required': False}
        client = fw.app.test_client()
        with (mock.patch.object(fw, 'SECRET', '1234'),
              mock.patch.object(fw, 'can_manage_firewall', return_value=True),
              mock.patch.object(fw, 'current_detection', return_value=detection),
              mock.patch.object(fw, 'run', side_effect=AssertionError('firewall command must not run'))):
            response = client.post('/api/iptables/rule', json={},
                                   headers={'X-Secret': '1234'})
        self.assertEqual(response.status_code, 409)

    def test_old_page_cannot_write_after_backend_selection_changes(self):
        detection = {'selected_backend': 'ufw', 'manager_can_write': True,
                     'can_write': False, 'reason': 'UFW is the active manager.',
                     'selection_review_required': True, 'previous_backend': 'nftables'}
        client = fw.app.test_client()
        with (mock.patch.object(fw, 'SECRET', '1234'),
              mock.patch.object(fw, 'can_manage_firewall', return_value=True),
              mock.patch.object(fw, 'current_detection', return_value=detection),
              mock.patch.object(fw, 'run', side_effect=AssertionError('firewall command must not run'))):
            response = client.post('/api/iptables/rule', json={},
                                   headers={'X-Secret': '1234'})
        self.assertEqual(response.status_code, 409)

    def test_stale_ufw_state_token_prevents_delete(self):
        detection = {'selected_backend': 'ufw', 'manager_can_write': True,
                     'can_write': False, 'reason': 'UFW is the active manager.',
                     'selection_review_required': False}
        client = fw.app.test_client()
        with (mock.patch.object(fw, 'SECRET', '1234'),
              mock.patch.object(fw, 'can_manage_firewall', return_value=True),
              mock.patch.object(fw, 'current_detection', return_value=detection),
              mock.patch.object(fw, '_ufw_state',
                                return_value=({}, [{'number': 1, 'token': 'rule'}], 'current')),
              mock.patch.object(fw, 'backup') as backup,
              mock.patch.object(fw, 'checked') as checked):
            response = client.delete('/api/ufw/rule',
                                     json={'number': 1, 'token': 'rule', 'state_token': 'stale'},
                                     headers={'X-Secret': '1234'})
        self.assertEqual(response.status_code, 409)
        backup.assert_not_called()
        checked.assert_not_called()

    def test_ufw_rule_is_dispatched_through_ufw(self):
        detection = {'selected_backend': 'ufw', 'manager_can_write': True,
                     'can_write': False, 'reason': 'UFW is the active manager.',
                     'selection_review_required': False}
        client = fw.app.test_client()
        with (mock.patch.object(fw, 'SECRET', '1234'),
              mock.patch.object(fw, 'can_manage_firewall', return_value=True),
              mock.patch.object(fw, 'current_detection', return_value=detection),
              mock.patch.object(fw, '_ufw_state', return_value=({}, [], 'current')),
              mock.patch.object(fw, 'backup', return_value='backup.json'),
              mock.patch.object(fw, 'checked', return_value='') as checked):
            response = client.post('/api/ufw/rule',
                                   json={'action': 'allow', 'port': '22', 'protocol': 'tcp',
                                         'source': 'any', 'state_token': 'current'},
                                   headers={'X-Secret': '1234'})
        self.assertEqual(response.status_code, 200)
        checked.assert_called_once_with('ufw', ['allow', '22/tcp'])

    def test_stale_firewalld_token_prevents_rule_change(self):
        detection = {'selected_backend': 'firewalld', 'manager_can_write': True,
                     'can_write': False, 'reason': 'firewalld is the active manager.',
                     'selection_review_required': False}
        client = fw.app.test_client()
        with (mock.patch.object(fw, 'SECRET', '1234'),
              mock.patch.object(fw, 'can_manage_firewall', return_value=True),
              mock.patch.object(fw, 'current_detection', return_value=detection),
              mock.patch.object(fw, '_firewalld_state', return_value={'zones': {'public': {}}}),
              mock.patch.object(fw, 'backup') as backup,
              mock.patch.object(fw, 'checked') as checked):
            response = client.post('/api/firewalld/rule',
                                   json={'zone': 'public', 'action': 'add', 'type': 'port',
                                         'value': '443', 'protocol': 'tcp', 'state': 'runtime',
                                         'state_token': 'stale'},
                                   headers={'X-Secret': '1234'})
        self.assertEqual(response.status_code, 409)
        backup.assert_not_called()
        checked.assert_not_called()


if __name__ == '__main__':
    unittest.main()
