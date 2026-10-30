"""Synthetic compiler-shape regressions, not captured production rulesets."""
import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'lib'))
import pve_compiled as compiled
import proxmox_host as host

ADMINS = ['8.8.8.8/32', '2606:4700:4700::1111/128']


def fixture():
    expected = compiled.expected_rules(host.firewall_content(ADMINS))
    snapshot = {'schema_version': 1, 'ipsets': {}}
    for family in (4, 6):
        snapshot['ipv'+str(family)] = {
            'PVEFW-INPUT': ['-A PVEFW-INPUT -j PVEFW-HOST-IN', '-A PVEFW-INPUT -j DROP'],
            'PVEFW-HOST-IN': [f'-A PVEFW-HOST-IN -s {source} -p tcp --dport {port} -j RETURN'
                              for f, source, _, port in expected if f == family]}
        name = f'PVEFW-0-management-v{family}'
        snapshot['ipsets'][name] = [f'create {name} hash:net family '+('inet' if family == 4 else 'inet6')+' hashsize 64']
    return snapshot


class CompiledTests(unittest.TestCase):
    def setUp(self):
        self.expected = compiled.expected_rules(host.firewall_content(ADMINS))
        self.snapshot = fixture()

    def test_expected_dual_stack_rules_verified_without_access_claim(self):
        result = compiled.analyze(self.snapshot, self.expected)
        self.assertTrue(result['semantic_rules_verified'])
        self.assertFalse(result['activation_allowed'])
        self.assertFalse(result['management_access_verified'])

    def test_silent_omission_and_changed_fields_rejected(self):
        for family in ('ipv4', 'ipv6'):
            for replacement in (None, '-p udp', '--dport 23', '-j DROP', '-s 1.1.1.1/32'):
                snapshot = copy.deepcopy(self.snapshot)
                rows = snapshot[family]['PVEFW-HOST-IN']
                if replacement is None:
                    rows.pop(0)
                else:
                    old = rows[0]
                    if replacement.startswith('-p '): rows[0] = old.replace('-p tcp', replacement)
                    elif replacement.startswith('--dport'): rows[0] = old.replace('--dport 22', replacement)
                    elif replacement.startswith('-j'): rows[0] = old.replace('-j RETURN', replacement)
                    else: rows[0] = old.replace(old.split(' -s ')[1].split(' -p ')[0], '1.1.1.1/32')
                with self.assertRaisesRegex(ValueError, 'omitted or changed'):
                    host.validate_compiled(snapshot, self.expected)

    def test_invalid_candidate_ip_and_protocol_do_not_reach_compiler(self):
        text = host.firewall_content(ADMINS)
        for invalid in (text.replace('8.8.8.8/32', 'NOT_AN_IP'), text.replace('-p tcp', '-p not_a_protocol')):
            with self.assertRaises(ValueError): compiled.expected_rules(invalid)

    def test_rule_in_wrong_chain_or_family_is_not_evidence(self):
        removed = self.snapshot['ipv4']['PVEFW-HOST-IN'].pop(0)
        self.snapshot['ipv4']['UNREACHABLE'] = [removed.replace('PVEFW-HOST-IN', 'UNREACHABLE')]
        self.snapshot['ipv6']['PVEFW-HOST-IN'].append(removed)
        with self.assertRaises(ValueError): host.validate_compiled(self.snapshot, self.expected)

    def test_management_set_broader_than_admins_and_unrequested_ports(self):
        for family in (4, 6):
            name = f'PVEFW-0-management-v{family}'
            self.snapshot['ipsets'][name].append(f'add {name} '+('8.8.0.0/16' if family == 4 else '2606:4700::/32'))
            for port in ('22', '8006', '3128', '5900:5999', '60000:60050'):
                self.snapshot['ipv'+str(family)]['PVEFW-HOST-IN'].append(
                    f'-A PVEFW-HOST-IN -m set --match-set {name} src -p tcp --dport {port} -j RETURN')
        result = compiled.analyze(self.snapshot, self.expected)
        risks = result['potential_openings']
        self.assertTrue(any(5900 in risk.get('ports', []) for risk in risks))
        self.assertTrue(any(60000 in risk.get('ports', []) for risk in risks))
        self.assertTrue(any(3128 in risk.get('ports', []) for risk in risks))
        self.assertTrue(all(risk['return_requires_caller_continuation'] for risk in risks))
        self.assertTrue(all(not risk['terminal_accept_in_this_chain'] for risk in risks))

    def test_return_continuations_are_recorded_not_assumed_accept(self):
        result = compiled.analyze(self.snapshot, self.expected)
        edge = result['input_graphs']['4']['ordered_calls'][0]
        self.assertEqual(edge['continuation_index'], 1)
        self.assertEqual(self.snapshot['ipv4']['PVEFW-INPUT'][1], '-A PVEFW-INPUT -j DROP')
        self.assertFalse(result['management_access_verified'])

    def test_unknown_set_match_target_or_cycle_never_authorize(self):
        for rule in ('-m set --match-set UNKNOWN src -p tcp --dport 22 -j RETURN',
                     '-p tcp --dport 8006 -j MYSTERY', '-j PVEFW-INPUT'):
            snapshot = copy.deepcopy(self.snapshot)
            snapshot['ipv4']['PVEFW-HOST-IN'].append('-A PVEFW-HOST-IN '+rule)
            result = compiled.analyze(snapshot, self.expected)
            self.assertTrue(result['potential_openings'])
            self.assertFalse(result['activation_allowed'])

    def test_negations_are_not_treated_as_safe_positive_exemptions(self):
        for match in ('! -i lo', '! -p udp', '-m conntrack ! --ctstate ESTABLISHED,RELATED',
                      '-p tcp ! --dport 22', '! -s 8.8.8.8/32'):
            snapshot = copy.deepcopy(self.snapshot)
            snapshot['ipv4']['PVEFW-HOST-IN'].append('-A PVEFW-HOST-IN '+match+' -j RETURN')
            result = compiled.analyze(snapshot, self.expected)
            self.assertTrue(result['potential_openings'], match)
            self.assertFalse(result['activation_allowed'])

    def test_unsupported_snapshot_fails_closed(self):
        for snapshot in ({}, {'schema_version': 1, 'ipsets': {}}, dict(self.snapshot, ipv4=[])):
            with self.assertRaises(ValueError): compiled.analyze(snapshot, self.expected)
