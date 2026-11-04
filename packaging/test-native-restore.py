#!/usr/bin/env python3
"""Verify selective native nftables restore in an isolated NET_ADMIN container."""

import json
import subprocess

import firewall_web as fw


def command(*args, stdin=None):
    return subprocess.run(args, input=stdin, check=True, text=True,
                          capture_output=True).stdout


command('nft', '-f', '-', stdin=(
    'add table inet fwweb_test\n'
    'add chain inet fwweb_test input { type filter hook input priority 0; policy accept; }\n'
    'add rule inet fwweb_test input tcp dport 43210 counter accept\n'
    'add table inet unrelated_test\n'
    'add chain inet unrelated_test input { type filter hook input priority 0; policy accept; }\n'
    'add rule inet unrelated_test input udp dport 43211 counter accept\n'
))

saved_table = command('nft', '-n', 'list', 'table', 'inet', 'fwweb_test')
fw.NATIVE_STATE.write_text(json.dumps({
    'version': 1,
    'tables': [{'family': 'inet', 'name': 'fwweb_test', 'rules': saved_table}],
}))
command('nft', 'flush', 'chain', 'inet', 'fwweb_test', 'input')
command('nft', 'add', 'rule', 'inet', 'fwweb_test', 'input',
        'tcp', 'dport', '43212', 'counter', 'drop')

fw.restore_native()
restored = command('nft', '-n', 'list', 'table', 'inet', 'fwweb_test')
unrelated = command('nft', '-n', 'list', 'table', 'inet', 'unrelated_test')
assert '43210' in restored and '43212' not in restored, restored
assert '43211' in unrelated, unrelated
print('Native nft restore replaced only the saved table and preserved the unrelated table.')
