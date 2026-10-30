import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('spamhaus_udp',ROOT/'modules/xtls-spamhaus-udp.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class SpamhausUDPTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.rules=[{'handle':1,'comment':'xtls-sh-out-v4','expr':[{'counter':{'packets':42}}]},
                    {'handle':2,'comment':'xtls-sh-diag-v4'},
                    {'handle':3,'comment':'foreign-xtls-sh-udp-drop-v4'}]
        self.initial=copy.deepcopy(self.rules)
        self.batches=[];self.fail_check=False;self.fail_apply=False;self.empty=False
        self.guard=module.Guard(self.root,self.root/'lock',self.runner)
        (self.root/'exemptions.txt').write_text('192.0.2.10\n2001:db8::1\n')

    def runner(self,argv,batch=None):
        if 'set' in argv:
            version=int(argv[-1][-1])
            return json.dumps({'nftables':[{'set':{'type':'ipv4_addr' if version==4 else 'ipv6_addr',
                                                  'elem':[] if self.empty else ['test']}}]})
        if 'chain' in argv:
            return json.dumps({'nftables':[{'rule':r} for r in self.rules]})
        if '-c' in argv:
            if self.fail_check: raise RuntimeError('nft check failed')
            return ''
        if self.fail_apply: raise RuntimeError('nft apply failed')
        self.batches.append(batch)
        for line in batch.splitlines():
            if line.startswith('delete rule'):
                handle=int(line.split()[-1]);self.rules=[r for r in self.rules if r['handle']!=handle]
            elif line.startswith('add rule'):
                marker=re.search(r'comment "([^"]+)"',line).group(1)
                self.rules.append({'handle':max(r['handle'] for r in self.rules)+1,'comment':marker})
        return ''

    def quiet(self,action):
        with contextlib.redirect_stdout(io.StringIO()): action()

    def test_enable_repeat_disable_preserve_other_rules(self):
        self.quiet(self.guard.enable);self.quiet(self.guard.enable)
        self.assertEqual(self.guard.mode(),'block')
        self.assertEqual(len(self.rules),5)
        self.assertEqual(self.rules[:3],self.initial)
        self.quiet(self.guard.disable);self.quiet(self.guard.disable)
        self.assertEqual(self.guard.mode(),'observe')
        self.assertEqual(self.rules,self.initial)

    def test_rules_only_original_udp_and_exemptions(self):
        self.quiet(self.guard.enable)
        batch=self.batches[-1]
        drops=[line for line in batch.splitlines() if line.startswith('add rule')]
        self.assertEqual(len(drops),2)
        for line in drops:
            self.assertIn('ct direction original meta l4proto udp',line)
            self.assertIn('daddr != @xtls_sh_udp_allow',line)
            self.assertNotIn('tcp',line)
        self.assertIn('192.0.2.10/32',batch)
        self.assertIn('2001:db8::1/128',batch)
        self.assertNotIn('flush set inet xtls_spamhaus_out v4',batch)

    def test_missing_or_invalid_exemptions_refuse_without_changes(self):
        for content in ('bad address','0.0.0.0/0','::/0'):
            (self.root/'exemptions.txt').write_text(content)
            with self.assertRaises(ValueError): self.guard.enable()
            self.assertEqual(self.rules,self.initial)
        (self.root/'exemptions.txt').unlink()
        with self.assertRaises(FileNotFoundError): self.guard.enable()
        self.assertEqual(self.guard.mode(),'observe')

    def test_empty_source_and_nft_errors_preserve_observe(self):
        self.empty=True
        with self.assertRaises(ValueError): self.guard.enable()
        self.empty=False
        for flag in ('fail_check','fail_apply'):
            setattr(self,flag,True)
            with self.assertRaises(RuntimeError): self.guard.enable()
            setattr(self,flag,False)
            self.assertEqual(self.rules,self.initial)
            self.assertEqual(self.guard.mode(),'observe')

    def test_restore_saved_block_and_heal_observe(self):
        self.quiet(self.guard.enable)
        self.rules=copy.deepcopy(self.initial)
        self.quiet(self.guard.restore)
        self.assertEqual(len(self.rules),5)
        self.guard.save_mode('observe')
        self.quiet(self.guard.restore)
        self.assertEqual(self.rules,self.initial)

    def test_disable_failure_saves_safe_boot_intent(self):
        self.quiet(self.guard.enable)
        self.fail_apply=True
        with self.assertRaises(RuntimeError): self.guard.disable()
        self.assertEqual(self.guard.mode(),'observe')
        self.fail_apply=False;self.quiet(self.guard.restore)
        self.assertEqual(self.rules,self.initial)

    def test_unknown_mode_refuses_restore(self):
        (self.root/'mode').write_text('unknown')
        with self.assertRaises(ValueError): self.guard.restore()
        self.assertEqual(self.rules,self.initial)

    def test_failed_mode_save_removes_new_drop(self):
        with patch.object(self.guard,'save_mode',side_effect=OSError('disk full')):
            with self.assertRaises(OSError): self.guard.enable()
        self.assertEqual(self.rules,self.initial)
        self.assertEqual(self.guard.mode(),'observe')


if __name__=='__main__': unittest.main()
