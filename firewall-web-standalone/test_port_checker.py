import json
import unittest
from unittest.mock import patch
import firewall_web as fw


def ipt(lines, policy='DROP', extra=''):
    return fw.parse_save('*filter\n:INPUT '+policy+' [0:0]\n'+extra+'\n'+lines+'\nCOMMIT\n','iptables-nft')


def nft(rules, policy='drop', chains=None, extra=None):
    items=[{'chain':{'family':'inet','table':'test','name':'input','hook':'input','type':'filter','policy':policy}}]
    items += [{'chain':c} for c in chains or []]
    for i,r in enumerate(rules,1):
        items.append({'rule':dict(family='inet',table='test',chain='input',handle=i,**r)})
    return {'nftables':items+(extra or [])}


def match(port,proto='tcp'):
    return {'match':{'op':'==','left':{'payload':{'protocol':proto,'field':'dport'}},'right':port}}


class PortCheckerTests(unittest.TestCase):
    def test_exact_membership_ranges_and_sets_not_substring(self):
        for v,expected in [(80,True),(8080,False),(9080,False),('80',True),('8080',False),('80,443',True),('70:90',True),({'set':[8080,80]},True),({'range':[81,90]},False),('@missing',None)]:
            self.assertIs(fw._pc_port_contains(v,80),expected)

    def test_iptables_duplicates_and_exact_rule_numbers(self):
        state=ipt('-A INPUT -p tcp --dport 80 -j ACCEPT\n-A INPUT -p udp --dport 8080 -j ACCEPT\n-A INPUT -p tcp --dport 80 -j ACCEPT')
        layers=fw._pc_layers({}, {'iptables-nft':state})
        rows=[r for r in fw._pc_rule_rows(layers,80) if r['port_specific']]
        self.assertEqual([r['location'] for r in rows],['Rule #1','Rule #3'])
        self.assertTrue(all(r['protocol']=='tcp' and r['copies']==2 for r in rows))
        self.assertEqual(fw._pc_layer_verdict(layers[0],'tcp','ip',80),'allowed')
        self.assertEqual(fw._pc_layer_verdict(layers[0],'udp','ip',80),'blocked')

    def test_earlier_deny_wins_over_later_allow(self):
        layer=fw._pc_layers({}, {'iptables-nft':ipt('-A INPUT -p tcp --dport 80 -j REJECT\n-A INPUT -p tcp --dport 80 -j ACCEPT')})[0]
        self.assertEqual(fw._pc_layer_verdict(layer,'tcp','ip',80),'blocked')

    def test_jump_return_does_not_execute_rules_after_return(self):
        layer=fw._pc_layers({}, {'iptables-nft':ipt('-A INPUT -j helper\n-A INPUT -p tcp --dport 80 -j ACCEPT\n-A helper -j RETURN\n-A helper -j DROP',extra=':helper - [0:0]')})[0]
        self.assertEqual(fw._pc_layer_verdict(layer,'tcp','ip',80),'allowed')

    def test_return_from_drop_base_chain_uses_policy(self):
        layer=fw._pc_layers({}, {'iptables-nft':ipt('-A INPUT -j RETURN')})[0]
        self.assertEqual(fw._pc_layer_verdict(layer,'tcp','ip',80),'blocked')

    def test_existing_connections_do_not_open_new_port(self):
        layer=fw._pc_layers({}, {'iptables-nft':ipt('-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT')})[0]
        self.assertEqual(fw._pc_layer_verdict(layer,'tcp','ip',80),'blocked')

    def test_source_restriction_is_not_unconditional_allow(self):
        layer=fw._pc_layers({}, {'iptables-nft':ipt('-A INPUT -s 10.0.0.0/8 -p tcp --dport 80 -j ACCEPT')})[0]
        self.assertEqual(fw._pc_layer_verdict(layer,'tcp','ip',80),'restricted')

    def test_default_accept_and_generic_drop_are_both_understood(self):
        for lines,expected in [('', 'allowed'),('-A INPUT -j DROP','blocked')]:
            layer=fw._pc_layers({}, {'iptables-nft':ipt(lines,policy='ACCEPT')})[0]
            self.assertEqual(fw._pc_layer_verdict(layer,'tcp','ip',80),expected)

    def test_nft_exact_set_lookup_and_handles(self):
        payload=nft([{'expr':[match('@web'),{'accept':None}]},{'expr':[match(8080,'udp'),{'accept':None}]}],extra=[{'set':{'family':'inet','table':'test','name':'web','elem':[80,443]}}])
        layer=fw._pc_layers(payload,{})[0]
        self.assertEqual(fw._pc_layer_verdict(layer,'tcp','ip',80),'allowed')
        self.assertEqual(fw._pc_layer_verdict(layer,'udp','ip6',80),'blocked')
        rows=[r for r in fw._pc_rule_rows([layer],80) if r['port_specific']]
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['location'],'Handle #1')

    def test_multiple_nft_base_chains_drop_overrides_accept(self):
        payload=nft([{'expr':[match(80),{'accept':None}]}])
        payload['nftables'] += [{'chain':{'family':'inet','table':'test','name':'later','hook':'input','policy':'drop'}}]
        layer=fw._pc_layers(payload,{})[0]
        self.assertEqual(fw._pc_layer_verdict(layer,'tcp','ip',80),'blocked')

    def test_empty_xtables_does_not_hide_native_filter_table(self):
        payload=nft([{'expr':[match(80),{'accept':None}]}]);payload['nftables'][0]['chain']['table']='filter';payload['nftables'][1]['rule']['table']='filter'
        layers=fw._pc_layers(payload,{'iptables-nft':fw.parse_save('', 'iptables-nft')})
        self.assertTrue(any(l['kind']=='nftables' and l['table']=='filter' for l in layers))

    def test_unreadable_set_is_not_reported_as_an_open_rule(self):
        layer=fw._pc_layers(nft([{'expr':[match('@missing'),{'accept':None}]}]),{})[0]
        self.assertNotEqual(fw._pc_layer_verdict(layer,'tcp','ip',80),'allowed')
        self.assertEqual([r for r in fw._pc_rule_rows([layer],80) if r['port_specific']],[])

    def test_ufw_not_local_guard_does_not_obscure_local_service_allow(self):
        state=ipt('-A INPUT -j ufw-before-input\n-A ufw-before-input -j ufw-not-local\n-A ufw-before-input -p tcp --dport 80 -j ACCEPT\n-A ufw-not-local -m addrtype --dst-type LOCAL -j RETURN\n-A ufw-not-local -j DROP',extra=':ufw-before-input - [0:0]\n:ufw-not-local - [0:0]')
        layer=fw._pc_layers({}, {'iptables-nft':state})[0]
        self.assertEqual(fw._pc_layer_verdict(layer,'tcp','ip',80),'allowed')

    def test_nft_goto_zone_handles_have_incoming_location(self):
        payload=nft([{'expr':[{'goto':{'target':'public'}}]}],chains=[{'family':'inet','table':'test','name':'public'}])
        payload['nftables'].append({'rule':{'family':'inet','table':'test','chain':'public','handle':50,'expr':[match(80),{'accept':None}]}})
        layer=fw._pc_layers(payload,{})[0]
        self.assertEqual(fw._pc_layer_verdict(layer,'tcp','ip',80),'allowed')
        self.assertEqual(fw._pc_layer_verdict(layer,'udp','ip',80),'blocked')
        self.assertEqual(next(r for r in fw._pc_rule_rows([layer],80) if r['port_specific'])['scope'],'Incoming')

    def test_state_verdict_map_does_not_accept_new_connections_as_established(self):
        state={'vmap':{'key':{'ct':{'key':'state'}},'data':{'set':[['established',{'accept':None}],['related',{'accept':None}],['invalid',{'drop':None}]]}}}
        layer=fw._pc_layers(nft([{'expr':[state]},{'expr':[match(80),{'accept':None}]}]),{})[0]
        self.assertEqual(fw._pc_layer_verdict(layer,'tcp','ip',80),'allowed')
        self.assertEqual(fw._pc_layer_verdict(layer,'udp','ip',80),'blocked')

    def test_ipv4_payload_does_not_become_ipv6_allow(self):
        rule={'family':'inet','table':'test','expr':[{'match':{'op':'==','left':{'payload':{'protocol':'ip','field':'daddr'}},'right':{'prefix':{'addr':'0.0.0.0','len':0}}}},match(80),{'accept':None}]}
        self.assertIs(fw._pc_nft_condition(rule,'tcp','ip6',80,{})[0],False)

    def test_listener_ports_are_exact_including_ipv6_and_udp(self):
        rows=fw._pc_listener_rows('tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("decoy",pid=12,fd=3))\ntcp LISTEN 0 128 [::]:80 [::]:* users:(("nginx",pid=13,fd=3))\nudp UNCONN 0 0 127.0.0.1:80 0.0.0.0:* users:(("dns",pid=14,fd=3))','',80)
        self.assertEqual([r['protocol'] for r in rows],['tcp','udp'])
        self.assertEqual(rows[0]['services'][0]['name'],'nginx');self.assertTrue(rows[1]['local_only'])

    def test_api_requires_auth_and_validates_single_port_before_reading(self):
        with patch.object(fw,'SECRET','1234'),patch.object(fw,'inspect_port',return_value={'port':80}) as inspect:
            client=fw.app.test_client();self.assertEqual(client.get('/api/port-check?port=80').status_code,401)
            for value in ['0','65536','80,443','80:90','80;id','-1','a','']:
                self.assertEqual(client.get('/api/port-check?port='+value,headers={'X-Secret':'1234'}).status_code,400)
            inspect.assert_not_called()
            self.assertEqual(client.get('/api/port-check?port=80',headers={'X-Secret':'1234'}).status_code,200)
            inspect.assert_called_once_with(80)

    def test_unknown_protocol_group_never_means_a_known_closed_port(self):
        rule={'family':'inet','table':'test','expr':[{'match':{'left':{'meta':{'key':'l4proto'}},'op':'==','right':'@unknown'}},match(80,'th'),{'accept':None}]}
        self.assertIsNone(fw._pc_nft_condition(rule,'tcp','ip',80,{})[0])
        self.assertIs(fw._pc_protocol_contains({'set':['tcp','udp']},'tcp'),True)
        self.assertIsNone(fw._pc_protocol_contains('@unknown','udp'))

    def test_notrack_requires_state_review_instead_of_a_false_open(self):
        state=fw.parse_save('*raw\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -p tcp --dport 80 -j CT --notrack\nCOMMIT\n*filter\n:INPUT DROP [0:0]\n-A INPUT -m conntrack --ctstate NEW -p tcp --dport 80 -j ACCEPT\nCOMMIT\n','iptables-nft')
        layers=fw._pc_layers({}, {'iptables-nft':state})
        self.assertTrue(any(fw._pc_advanced_effect(l,'tcp','ip',80) for l in layers))
        self.assertFalse(any(fw._pc_advanced_effect(l,'udp','ip',80) for l in layers))

    def test_nft_tuple_rewrite_is_not_silently_ignored(self):
        payload=nft([{'expr':[match(80),{'mangle':{'key':{'payload':{'protocol':'tcp','field':'dport'}},'value':8080}}]}])
        self.assertTrue(fw._pc_advanced_effect(fw._pc_layers(payload,{})[0],'tcp','ip',80))

    def test_generic_forwarding_rule_is_visible_even_without_a_port_selector(self):
        payload=nft([])
        payload['nftables'] += [{'chain':{'family':'ip','table':'nat','name':'pre','hook':'prerouting','policy':'accept'}},{'rule':{'family':'ip','table':'nat','chain':'pre','handle':5,'expr':[{'dnat':{'addr':'10.0.0.2'}}]}}]
        layers=fw._pc_layers(payload,{})
        self.assertTrue(any(r['action']=='Forward' for r in fw._pc_rule_rows(layers,80)))

    def test_unreadable_firewall_is_unknown_not_closed(self):
        with patch.object(fw,'executable',return_value=True),patch.object(fw,'_probe',return_value={'available':False,'permission_denied':True}):
            result=fw.inspect_port(80)
        self.assertEqual(result['summary'],'Could not fully check')
        self.assertFalse(result['usage_known'])

    def test_forwarding_is_not_mislabelled_as_closed_local_port(self):
        payload=nft([])
        payload['nftables'] += [{'chain':{'family':'ip','table':'natcase','name':'prerouting','hook':'prerouting','policy':'accept'}},{'rule':{'family':'ip','table':'natcase','chain':'prerouting','handle':11,'expr':[match(80),{'dnat':{'addr':'10.0.0.2','port':8080}}]}}]
        def probe(name,args):
            if name=='nft':return {'available':True,'output':json.dumps(payload)}
            if name=='ss':return {'available':True,'output':''}
            return {'available':False}
        with patch.object(fw,'executable',side_effect=lambda n:n=='nft'),patch.object(fw,'_probe',side_effect=probe):
            result=fw.inspect_port(80)
        self.assertEqual(result['protocols']['tcp']['families']['IPv4'],'unknown')
        self.assertTrue(any(r['action']=='Forward' for r in result['rules']))

    def test_query_only_uses_read_commands_and_never_write_detection(self):
        data=ipt('-A INPUT -p tcp --dport 80 -j ACCEPT')
        raw=data['raw']
        def probe(name,args):
            if name.endswith('-save'):self.assertEqual(args,['-c']);return {'available':True,'output':raw}
            if name=='ss':self.assertEqual(args,['-H','-antup']);return {'available':True,'output':''}
            if name=='ufw':self.assertEqual(args,['status']);return {'available':True,'output':'Status: active'}
            if name=='firewall-cmd':self.assertEqual(args,['--state']);return {'available':False}
            self.fail((name,args))
        with patch.object(fw,'executable',side_effect=lambda n:n in ('iptables-nft-save','ip6tables-nft-save')),patch.object(fw,'_probe',side_effect=probe),patch.object(fw,'current_detection',side_effect=AssertionError('write-selection state must not change')):
            result=fw.inspect_port(80)
        self.assertEqual(result['summary'],'TCP allowed; UDP not opened');self.assertFalse(result['listeners'])


if __name__=='__main__':unittest.main()
