import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
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
        fw.SELECTED_FINGERPRINT_AT_START = None
        fw.SELECTION_REVIEW_REQUIRED = False
        fw.FINGERPRINT_REVIEW_REQUIRED = False

    def run_detection(self, *, ufw='missing', firewalld='missing',
                      nft=NFT_EMPTY, saves=None, nft_permission=False, other_active=(), services=None):
        saves = saves or {}

        def probe(name, args=()):
            if name == 'systemctl' and args and args[0] == 'list-units':
                return {'installed': True, 'available': True, 'output': '\n'.join(
                    unit + ' loaded active exited test firewall' for unit in other_active)}
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
                if args == ['--help']:
                    return {'installed': True, 'available': True,
                            'output': '--add-interface --add-source --add-rich-rule --get-policies'}
                if args in (['--get-zones'], ['--permanent', '--get-zones']):
                    return {'installed': True, 'available': True, 'output': 'public trusted'}
                if args in (['--get-policies'], ['--permanent', '--get-policies']):
                    return {'installed': True, 'available': True, 'output': ''}
                if args == ['--get-default-zone']:
                    return {'installed': True, 'available': True, 'output': 'public'}
                if args == ['--permanent', '--get-default-zone']:
                    return {'installed': True, 'available': True, 'output': 'public'}
                if args in (['--list-all-zones'], ['--permanent', '--list-all-zones']):
                    return {'installed': True, 'available': True,
                            'output': 'public\n  interfaces: eth0\n  sources:\n  services: ssh\ntrusted\n  interfaces:\n  sources:\n  services:'}
                if (args and args[-1] == '--list-all'
                        and any(arg.startswith('--zone=') for arg in args)):
                    return {'installed': True, 'available': True,
                            'output': 'interfaces: eth0\nsources:\nservices: ssh'}
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
                                side_effect=lambda name: (services or {}).get(name,
                                    {'available': True, 'active': False, 'enabled': False})),
              mock.patch.object(fw, 'can_manage_firewall', return_value=True)):
            return fw.detect_firewall()

    def test_inactive_other_manager_does_not_block_direct_rules(self):
        result = self.run_detection(other_active=(),
            saves={'iptables-save': SAVE_POPULATED,
                   'iptables-nft-save': SAVE_POPULATED})
        self.assertEqual(result['selected_backend'], 'iptables')

    def test_other_manager_unknown_when_systemd_inspection_fails(self):
        with (mock.patch.object(fw, '_probe', return_value={
                'installed': True, 'available': False, 'error': 'Failed to connect to bus'}),
              mock.patch.object(fw, 'executable', side_effect=lambda name:
                                '/usr/sbin/ferm' if name == 'ferm' else None)):
            result = fw.other_firewall_managers()
        self.assertEqual(result, {'active': [], 'unknown': ['ferm.service']})

    def test_service_rule_owners_are_not_treated_as_full_firewall_managers(self):
        with mock.patch.object(fw, '_probe', return_value={
                'available': True, 'output': 'docker.service loaded active running Docker\n'
                                            'tailscaled.service loaded active running Tailscale'}):
            self.assertEqual(fw.other_firewall_managers(), {'active': [], 'unknown': []})

    def test_boot_service_enable_has_bounded_slow_host_budget(self):
        with (mock.patch.object(fw, 'executable', return_value='/usr/bin/systemctl'),
              mock.patch.object(fw.subprocess, 'run', return_value=mock.Mock(
                  stdout='', stderr='', returncode=0)) as run):
            fw.run('systemctl', ['enable', 'netfilter-persistent.service'])
            self.assertEqual(run.call_args.kwargs['timeout'], 180)
            fw.run('systemctl', ['is-active', '--quiet', 'ufw'])
            self.assertEqual(run.call_args.kwargs['timeout'], 12)

    def test_daemon_reload_tolerates_slow_systemd_without_relaxing_probes(self):
        def slow_systemd(argv, **kwargs):
            if kwargs['timeout'] < 15:
                raise fw.subprocess.TimeoutExpired(argv, kwargs['timeout'])
            return mock.Mock(stdout='', stderr='', returncode=0)
        with (mock.patch.object(fw, 'executable', return_value='/usr/bin/systemctl'),
              mock.patch.object(fw.subprocess, 'run', side_effect=slow_systemd) as run):
            self.assertEqual(fw.checked('systemctl', ['daemon-reload']), '')
            self.assertEqual(run.call_args.kwargs['timeout'], 180)
            with self.assertRaises(fw.Problem) as caught:
                fw.run('systemctl', ['is-active', '--quiet', 'ufw'])
            self.assertEqual(caught.exception.status, 504)
            self.assertEqual(run.call_args.kwargs['timeout'], 12)

    def test_confirmation_window_starts_after_response_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            rid = 'b' * 32
            path = Path(directory) / (rid + '.json')
            path.write_text(json.dumps({'id': rid, 'status': 'pending',
                'expected_after': {}, 'created_at': 100, 'deadline': 190}))
            with (mock.patch.object(fw, 'ROLLBACK_DIR', Path(directory)),
                  mock.patch.object(fw.time, 'time', return_value=1000),
                  mock.patch.object(fw, 'detect_firewall', return_value={
                      'selected_backend': 'ufw', 'selected_fingerprint': 'after'}),
                  fw.app.test_request_context('/api/firewalld/rule', method='POST')):
                response = fw.jsonify(ok=True, pending_rollback_id=rid)
                fw.headers(response)
            record = json.loads(path.read_text())
            self.assertEqual(record['deadline'], 1000 + fw.ROLLBACK_SECONDS)

    def test_rollback_worker_observes_confirmation_without_stale_long_sleep(self):
        with tempfile.TemporaryDirectory() as directory:
            rid = 'c' * 32
            path = Path(directory) / (rid + '.json')
            record = {'id': rid, 'status': 'pending', 'deadline': 100,
                      'expected_after': {}}
            path.write_text(json.dumps(record))
            def confirmed(_):
                record['status'] = 'confirmed'
                path.write_text(json.dumps(record))
            with (mock.patch.object(fw, 'ROLLBACK_DIR', Path(directory)),
                  mock.patch.object(fw.time, 'time', return_value=0),
                  mock.patch.object(fw.time, 'sleep', side_effect=confirmed) as sleep):
                fw.run_rollback(rid)
            self.assertLessEqual(sleep.call_args.args[0], 1)

    def test_active_manager_and_direct_boot_restore_conflict_blocks_override(self):
        for manager in ('ufw', 'firewalld'):
            for service in ('nftables.service', 'netfilter-persistent.service',
                            'nft-web-restore.service'):
                with self.subTest(manager=manager, service=service), mock.patch.dict(
                        fw.os.environ, {'NFT_BACKEND': manager}):
                    options = {manager: 'active'}
                    if manager == 'firewalld':
                        options['nft'] = NFT_FIREWALLD
                    result = self.run_detection(**options, services={
                        service: {'available': True, 'active': False, 'enabled': True}})
                    self.assertEqual(result['selected_backend'], 'inspection')
                    self.assertFalse(result['manager_can_write'])
                    self.assertIn(service, result['reason'])

    def test_ufw_route_port_with_any_destination_uses_explicit_to(self):
        payload = dict(kind='route', action='allow', port='43986', protocol='tcp',
                       source='any', destination='any', interface_in='lo',
                       interface_out='lo', state_token='fresh')
        expected = ['route', 'allow', 'in', 'on', 'lo', 'out', 'on', 'lo',
                    'to', 'any', 'port', '43986', 'proto', 'tcp']
        with (fw.app.test_request_context('/api/ufw/rule', method='POST', json=payload),
              mock.patch.object(fw, '_ufw_state', return_value=({}, [], 'fresh')),
              mock.patch.object(fw, 'backup', return_value='test-backup'),
              mock.patch.object(fw, 'checked', return_value='Rule added') as checked):
            fw.ufw_add_rule()
        self.assertEqual(checked.call_args.args, ('ufw', expected))

    def test_unsupported_active_firewall_manager_blocks_direct_override(self):
        for unit in ('ferm.service', 'shorewall.service', 'firehol.service'):
            with self.subTest(unit=unit), mock.patch.dict(fw.os.environ, {'NFT_BACKEND': 'iptables'}):
                result = self.run_detection(other_active=(unit,),
                    saves={'iptables-save': SAVE_POPULATED,
                           'iptables-nft-save': SAVE_POPULATED})
                self.assertEqual(result['selected_backend'], 'inspection')
                self.assertFalse(result['can_write'])
                self.assertIn(unit, result['reason'])

    def test_unsupported_manager_blocks_supported_manager_override(self):
        with mock.patch.dict(fw.os.environ, {'NFT_BACKEND': 'ufw',
                'NFT_BACKEND_ACK': 'active-managers:firewalld,ufw'}):
            result = self.run_detection(ufw='active', firewalld='active',
                                       nft=NFT_FIREWALLD, other_active=('ferm.service',))
        self.assertEqual(result['selected_backend'], 'inspection')
        self.assertFalse(result['manager_can_write'])

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

    def test_exact_conflict_acknowledgement_selects_one_active_manager(self):
        with mock.patch.dict(fw.os.environ, {
                'NFT_BACKEND': 'ufw',
                'NFT_BACKEND_ACK': 'active-managers:firewalld,ufw'}):
            result = self.run_detection(ufw='active', firewalld='active')
        self.assertEqual(result['selected_backend'], 'ufw')
        self.assertTrue(result['manager_can_write'])
        self.assertEqual(result['conflict_acknowledgement'],
                         'active-managers:firewalld,ufw')
        self.assertIn('Only ufw-owned operations', result['reason'])

    def test_stale_conflict_acknowledgement_does_not_resolve_conflict(self):
        with mock.patch.dict(fw.os.environ, {
                'NFT_BACKEND': 'ufw',
                'NFT_BACKEND_ACK': 'active-managers:firewalld'}):
            result = self.run_detection(ufw='active', firewalld='active')
        self.assertEqual(result['selected_backend'], 'inspection')

    def test_inactive_manager_and_empty_ruleset_remain_inspection_only(self):
        result = self.run_detection(ufw='inactive', firewalld='inactive')
        self.assertEqual(result['selected_backend'], 'inspection')
        self.assertEqual(result['managers']['ufw']['status'], 'inactive')
        self.assertEqual(result['managers']['firewalld']['status'], 'inactive')
        self.assertIn('no firewall will be enabled', result['reason'])

    def test_populated_iptables_nft_and_legacy_alternatives_are_ambiguous(self):
        result = self.run_detection(saves={
            'iptables-nft-save': SAVE_POPULATED,
            'iptables-legacy-save': SAVE_POPULATED,
        })
        self.assertEqual(result['selected_backend'], 'inspection')
        self.assertIn('ownership is ambiguous', result['reason'])

    def test_firewalld_explicit_not_running_error_is_known_inactive(self):
        result = self.run_detection(firewalld='inactive-error')
        self.assertEqual(result['managers']['firewalld']['status'], 'inactive')
        self.assertNotIn('firewalld', result['active_managers'])

    def test_firewalld_state_uses_supported_default_zone_query(self):
        with (mock.patch.object(fw, '_firewalld_zones', side_effect=[['trusted'], ['trusted']]),
              mock.patch.object(fw, '_firewalld_zone', side_effect=[{}, {}]),
              mock.patch.object(fw, '_firewalld_policies', side_effect=[[], []]),
              mock.patch.object(fw, 'checked', side_effect=lambda _, args: {
                  '--list-all-zones': 'trusted\n  target: default',
                  '--get-active-zones': 'trusted',
                  '--get-default-zone': 'trusted',
              }[args[-1]])):
            state = fw._firewalld_state()
        self.assertEqual(state['permanent_default_zone'], 'trusted')

    def test_zone_inventory_preserves_separate_rules_and_rejects_duplicates(self):
        output = ('public (active)\n  interfaces: eth0\n  rich rules:\n'
                  '    rule family="ipv6" source address="2001:db8::/32" accept\n'
                  'trusted\n  interfaces: eth1\n  ports: 42424/tcp\n')
        zones = fw._split_firewalld_zones(output)
        public = fw._parse_firewalld_list_all(zones['public'])
        trusted = fw._parse_firewalld_list_all(zones['trusted'])
        self.assertIn('2001:db8::/32', public['rich rules'])
        self.assertEqual(public['interfaces'], 'eth0')
        self.assertEqual(trusted['interfaces'], 'eth1')
        self.assertEqual(trusted['ports'], '42424/tcp')
        with self.assertRaises(fw.Problem):
            fw._split_firewalld_zones(output + 'public\n  target: DROP\n')

    def test_inventory_query_count_does_not_grow_with_zone_count(self):
        names = [f'zone{i}' for i in range(20)]
        text = '\n'.join(name + '\n  target: default' for name in names)
        with (mock.patch.object(fw, '_firewalld_zones', return_value=names),
              mock.patch.object(fw, '_firewalld_policies', return_value=[]),
              mock.patch.object(fw, 'checked', side_effect=lambda _, args:
                                text if args[-1] == '--list-all-zones' else 'zone0') as calls):
            state = fw._firewalld_state()
        self.assertEqual(len(state['zones']), 20)
        self.assertLessEqual(calls.call_count, 4)
        self.assertFalse(any('--list-all' in call.args[1] for call in calls.call_args_list))

    def test_malformed_zone_inventory_disables_writes(self):
        with mock.patch.object(fw, '_split_firewalld_zones',
                               side_effect=fw.Problem('Incomplete inventory', 503)):
            result = self.run_detection(firewalld='active', nft=NFT_FIREWALLD)
        self.assertEqual(result['selected_backend'], 'inspection')
        self.assertFalse(result['manager_can_write'])

    def test_firewalld_state_preserves_multiline_ipv6_rich_rules(self):
        rich_rule = ('rule family="ipv6" source address="2001:db8::/32" '
                     'service name="ssh" accept')
        output = 'target: default\nrich rules:\n  ' + rich_rule + '\n'
        with mock.patch.object(fw, 'checked', return_value=output):
            zone = fw._firewalld_zone('trusted')
            policy = fw._firewalld_policy('fwtest')
        self.assertEqual(zone['rich rules'], rich_rule)
        self.assertEqual(policy['rich rules'], rich_rule)

    def test_rollback_cli_dispatches_worker_without_starting_server(self):
        rollback_id = 'a' * 32
        with tempfile.TemporaryDirectory() as directory:
            env = os.environ.copy()
            env.update({'NFT_ROLLBACK_DIR': directory, 'NFT_SECRET': '1234'})
            result = subprocess.run(
                [sys.executable, str(Path(fw.__file__)), '--rollback', rollback_id],
                env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

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

    def test_service_owned_chains_are_reported_without_reclassifying_them(self):
        save = ('*filter\n:INPUT ACCEPT [0:0]\n:DOCKER - [0:0]\n'
                ':CNI-FORWARD - [0:0]\n:LIBVIRT_INP - [0:0]\n:ts-input - [0:0]\n'
                '-A DOCKER -j ACCEPT\nCOMMIT\n')
        result = self.run_detection(saves={'iptables-save': save})
        owners = {item['service']: item['chains'] for item in result['service_owners']}
        self.assertEqual(result['selected_backend'], 'iptables')
        self.assertEqual(owners['Docker'], ['DOCKER'])
        self.assertEqual(owners['Podman'], ['CNI-FORWARD'])
        self.assertEqual(owners['libvirt'], ['LIBVIRT_INP'])
        self.assertEqual(owners['Tailscale'], ['ts-input'])

    def test_persistence_requires_fresh_selected_backend(self):
        detection = {'selection_review_required': False,
                     'selected_backend': 'ufw', 'can_write': False}
        with mock.patch.object(fw, 'current_detection', return_value=detection):
            with self.assertRaisesRegex(fw.Problem, 'not the selected writable backend'):
                fw._require_selected_write_backend('iptables')

    def test_native_restore_refuses_when_a_manager_owns_the_firewall(self):
        detection = {'selected_backend': 'ufw', 'active_managers': ['ufw'],
                     'reason': 'ufw is active'}
        with (mock.patch.object(fw, 'detect_firewall', return_value=detection),
              mock.patch.object(fw, 'can_manage_firewall', return_value=True),
              mock.patch.object(fw, 'nft_script') as write):
            with self.assertRaisesRegex(fw.Problem, 'ownership is not safely direct'):
                fw.restore_native()
        write.assert_not_called()

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
                               side_effect=[{'selected_backend': 'nftables',
                                             'selected_fingerprint': 'one'},
                                            {'selected_backend': 'ufw',
                                             'selected_fingerprint': 'two'}]):
            first = fw.current_detection()
            second = fw.current_detection()
        self.assertFalse(first['selection_review_required'])
        self.assertTrue(second['selection_review_required'])
        self.assertEqual(second['previous_backend'], 'nftables')

    def test_external_configuration_change_requires_review(self):
        reports = [
            {'selected_backend': 'nftables', 'selected_fingerprint': 'initial'},
            {'selected_backend': 'nftables', 'selected_fingerprint': 'external'},
        ]
        with mock.patch.object(fw, 'detect_firewall', side_effect=reports):
            first = fw.current_detection()
            second = fw.current_detection()
        self.assertFalse(first['selection_review_required'])
        self.assertTrue(second['selection_review_required'])
        self.assertTrue(second['fingerprint_review_required'])

    def test_configuration_fingerprint_ignores_counters_and_handles(self):
        before = {'rule': {'handle': 3, 'counter': {'packets': 4, 'bytes': 90},
                           'expr': [{'accept': None}]}}
        after = {'rule': {'handle': 9, 'counter': {'packets': 20, 'bytes': 900},
                          'expr': [{'accept': None}]}}
        self.assertEqual(fw.configuration_only(before), fw.configuration_only(after))

    def test_selected_manager_fingerprint_includes_external_direct_rule_changes(self):
        baseline = self.run_detection(ufw='active')
        changed = self.run_detection(
            ufw='active',
            saves={'iptables-save': SAVE_POPULATED})
        self.assertEqual(baseline['selected_backend'], 'ufw')
        self.assertEqual(changed['selected_backend'], 'ufw')
        self.assertNotEqual(baseline['selected_fingerprint'], changed['selected_fingerprint'])

    def test_ufw_dual_stack_pair_rollback_uses_family_neutral_rule(self):
        paired = fw._ufw_rule_insert_args(1, '22/tcp ALLOW IN Anywhere', True)
        single = fw._ufw_rule_insert_args(1, '22/tcp ALLOW IN Anywhere', False)
        ipv6 = fw._ufw_rule_insert_args(1, '22/tcp (v6) ALLOW IN Anywhere (v6)', False)
        self.assertEqual(paired, ['insert', '1', 'allow', 'in', 'to', 'any', 'port', '22', 'proto', 'tcp'])
        self.assertEqual(single, ['insert', '1', 'allow', 'in', 'from', '0.0.0.0/0', 'to', 'any', 'port', '22', 'proto', 'tcp'])
        self.assertIn('::/0', ipv6)

    def test_ufw_route_deletion_rollback_reconstructs_both_interfaces(self):
        args = fw._ufw_rule_insert_args(
            2, '198.51.100.0/24 443/tcp on eth1 ALLOW FWD 192.0.2.0/24 on eth0')
        self.assertEqual(args, [
            'route', 'insert', '2', 'allow', 'in', 'on', 'eth0',
            'out', 'on', 'eth1', 'from', '192.0.2.0/24',
            'to', '198.51.100.0/24', 'port', '443', 'proto', 'tcp'])

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

    def test_ufw_route_rule_is_dispatched_with_native_ufw_syntax(self):
        detection = {'selected_backend': 'ufw', 'manager_can_write': True,
                     'can_write': False, 'reason': 'UFW is the active manager.',
                     'selection_review_required': False}
        client = fw.app.test_client()
        with (mock.patch.object(fw, 'SECRET', '1234'),
              mock.patch.object(fw, 'can_manage_firewall', return_value=True),
              mock.patch.object(fw, 'current_detection', return_value=detection),
              mock.patch.object(fw.socket, 'if_nameindex', return_value=[(1, 'eth0'), (2, 'eth1')]),
              mock.patch.object(fw, '_ufw_state', return_value=({}, [], 'current')),
              mock.patch.object(fw, 'backup', return_value='backup.json'),
              mock.patch.object(fw, 'checked', return_value='') as checked):
            response = client.post('/api/ufw/rule',
                                   json={'kind': 'route', 'action': 'allow', 'source': '192.0.2.0/24',
                                         'destination': '198.51.100.0/24', 'port': '443',
                                         'protocol': 'tcp', 'interface_in': 'eth0',
                                         'interface_out': 'eth1', 'state_token': 'current'},
                                   headers={'X-Secret': '1234'})
        self.assertEqual(response.status_code, 200)
        checked.assert_called_once_with(
            'ufw', ['route', 'allow', 'in', 'on', 'eth0', 'out', 'on', 'eth1',
                    'from', '192.0.2.0/24', 'to', '198.51.100.0/24',
                    'port', '443', 'proto', 'tcp'])

    def test_ufw_route_limit_is_rejected(self):
        detection = {'selected_backend': 'ufw', 'manager_can_write': True,
                     'selection_review_required': False}
        client = fw.app.test_client()
        with (mock.patch.object(fw, 'SECRET', '1234'),
              mock.patch.object(fw, 'can_manage_firewall', return_value=True),
              mock.patch.object(fw, 'current_detection', return_value=detection),
              mock.patch.object(fw, 'checked') as checked):
            response = client.post('/api/ufw/rule',
                                   json={'kind': 'route', 'action': 'limit', 'port': '22',
                                         'state_token': 'current'},
                                   headers={'X-Secret': '1234'})
        self.assertEqual(response.status_code, 400)
        checked.assert_not_called()

    def test_unscoped_ufw_route_is_rejected(self):
        detection = {'selected_backend': 'ufw', 'manager_can_write': True,
                     'selection_review_required': False}
        client = fw.app.test_client()
        with (mock.patch.object(fw, 'SECRET', '1234'),
              mock.patch.object(fw, 'can_manage_firewall', return_value=True),
              mock.patch.object(fw, 'current_detection', return_value=detection),
              mock.patch.object(fw, 'backup') as backup,
              mock.patch.object(fw, 'checked') as checked):
            response = client.post('/api/ufw/rule',
                                   json={'kind': 'route', 'action': 'allow',
                                         'state_token': 'current'},
                                   headers={'X-Secret': '1234'})
        self.assertEqual(response.status_code, 400)
        backup.assert_not_called()
        checked.assert_not_called()

    def test_firewalld_source_binding_uses_native_runtime_command(self):
        detection = {'selected_backend': 'firewalld', 'manager_can_write': True,
                     'selection_review_required': False,
                     'managers': {'firewalld': {'capabilities': {'source_bindings': True}}}}
        current = {'zones': {'trusted': {'runtime': {}, 'permanent': {}}},
                   'policies': {}, 'active_zones': '', 'default_zone': 'public',
                   'permanent_default_zone': 'public'}
        after = json.loads(json.dumps(current))
        after['zones']['trusted']['runtime']['sources'] = '192.0.2.0/24'
        client = fw.app.test_client()
        with (mock.patch.object(fw, 'SECRET', '1234'),
              mock.patch.object(fw, 'can_manage_firewall', return_value=True),
              mock.patch.object(fw, 'current_detection', return_value=detection),
              mock.patch.object(fw, '_firewalld_state',
                                side_effect=[current, current, current, after]),
              mock.patch.object(fw, 'backup', return_value='backup.json'),
              mock.patch.object(fw, 'prepare_rollback', return_value='rollback-id') as prepare,
              mock.patch.object(fw, 'commit_rollback') as commit,
              mock.patch.object(fw, 'arm_rollback_confirmation') as arm,
              mock.patch.object(fw, 'checked', return_value='') as checked):
            token = fw.signature(fw.configuration_only(current))
            response = client.post('/api/firewalld/rule',
                                   json={'scope': 'zone', 'zone': 'trusted', 'type': 'source',
                                         'value': '192.0.2.0/24', 'action': 'add',
                                         'state': 'runtime', 'state_token': token},
                                   headers={'X-Secret': '1234'})
        self.assertEqual(response.status_code, 200)
        checked.assert_called_once_with('firewall-cmd',
                                       ['--zone=trusted', '--add-source=192.0.2.0/24'])
        prepare.assert_called_once()
        commit.assert_called_once()
        arm.assert_called_once_with('rollback-id')

    def test_unsupported_firewalld_rich_rule_is_rejected(self):
        detection = {'selected_backend': 'firewalld', 'manager_can_write': True,
                     'selection_review_required': False,
                     'managers': {'firewalld': {'capabilities': {'rich_rules': False}}}}
        current = {'zones': {'public': {'runtime': {}, 'permanent': {}}},
                   'policies': {}, 'active_zones': '', 'default_zone': 'public',
                   'permanent_default_zone': 'public'}
        client = fw.app.test_client()
        with (mock.patch.object(fw, 'SECRET', '1234'),
              mock.patch.object(fw, 'can_manage_firewall', return_value=True),
              mock.patch.object(fw, 'current_detection', return_value=detection),
              mock.patch.object(fw, '_firewalld_state', return_value=current),
              mock.patch.object(fw, 'checked') as checked):
            token = fw.signature(fw.configuration_only(current))
            response = client.post('/api/firewalld/rule',
                                   json={'scope': 'zone', 'zone': 'public', 'type': 'rich-rule',
                                         'value': 'rule family="ipv4" service name="ssh" accept',
                                         'action': 'add', 'state': 'permanent',
                                         'state_token': token},
                                   headers={'X-Secret': '1234'})
        self.assertEqual(response.status_code, 409)
        checked.assert_not_called()

    def test_unsupported_firewalld_source_binding_is_rejected(self):
        detection = {'selected_backend': 'firewalld', 'manager_can_write': True,
                     'selection_review_required': False,
                     'managers': {'firewalld': {'capabilities': {'source_bindings': False}}}}
        current = {'zones': {'public': {'runtime': {}, 'permanent': {}}},
                   'policies': {}, 'active_zones': '', 'default_zone': 'public',
                   'permanent_default_zone': 'public'}
        client = fw.app.test_client()
        with (mock.patch.object(fw, 'SECRET', '1234'),
              mock.patch.object(fw, 'can_manage_firewall', return_value=True),
              mock.patch.object(fw, 'current_detection', return_value=detection),
              mock.patch.object(fw, '_firewalld_state', return_value=current),
              mock.patch.object(fw, 'checked') as checked):
            token = fw.signature(fw.configuration_only(current))
            response = client.post('/api/firewalld/rule',
                                   json={'scope': 'zone', 'zone': 'public', 'type': 'source',
                                         'value': '192.0.2.0/24', 'action': 'add',
                                         'state': 'runtime', 'state_token': token},
                                   headers={'X-Secret': '1234'})
        self.assertEqual(response.status_code, 409)
        checked.assert_not_called()

    def test_scheduled_rollback_skips_external_manager_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ('a' * 32 + '.json')
            record = {'version': 1, 'id': 'a' * 32, 'manager': 'ufw',
                      'inverse_args': ['default', 'allow', 'incoming'],
                      'expected_after': {'verbose': 'our expected state'},
                      'deadline': time.time() - 1, 'status': 'pending',
                      'message': ''}
            path.write_text(json.dumps(record))
            with (mock.patch.object(fw, 'ROLLBACK_DIR', Path(directory)),
                  mock.patch.object(fw, 'manager_state', return_value={'verbose': 'external change'}),
                  mock.patch.object(fw, 'detect_firewall',
                                    return_value={'selected_backend': 'ufw'}),
                  mock.patch.object(fw, 'can_manage_firewall', return_value=True),
                  mock.patch.object(fw, 'checked') as checked):
                fw.run_rollback('a' * 32)
            checked.assert_not_called()
            result = json.loads(path.read_text())
            self.assertEqual(result['status'], 'conflict')
            self.assertIn('preserve concurrent changes', result['message'])

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
