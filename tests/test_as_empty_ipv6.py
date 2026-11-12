"""Exercise the installer and generated timer with upstream's empty IPv6 format."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / 'vps-setup.sh').read_text()
HELPER = SOURCE[SOURCE.index('asb_extract_feed() {'):SOURCE.index('# Managed AS/Threat IPSet persistence:')]
INSTALL = SOURCE[SOURCE.index('asb_install_iptables() {'):SOURCE.index('asb_create_update_script_iptables() {')]
UPDATER = SOURCE.split("cat <<'MANAGED_UPDATER'\n", 1)[1].split('\nMANAGED_UPDATER', 1)[0]


def feed(v, count):
    family = 'inet' if v == 4 else 'inet6'
    header = f'create blacklist-v{v} hash:net family {family} hashsize 1024 maxelem {count*2}\n'
    return header + ''.join(f'add blacklist-v{v} '+(f'8.0.{i}.0/24' if v == 4 else f'2001:4860:{i:x}::/48')+'\n' for i in range(count))


class ASFeedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root/'bin').mkdir(); (self.root/'as').mkdir()
        for v, n in ((4,100),(6,0)):
            (self.root/f'feed{v}').write_text(feed(v,n))
        self.state = self.root/'state'
        self.state.write_text('{}')
        self.env = dict(os.environ, FIXTURE=str(self.root), PATH=str(self.root/'bin')+':'+os.environ['PATH'])
        script = '''import json,os,sys
from pathlib import Path
p=Path(os.environ['FIXTURE']); a=sys.argv[1:]; tool=Path(sys.argv[0]).name
state=json.loads((p/'state').read_text()); rules=state.setdefault('rules',[])
with (p/'calls').open('a') as f: f.write(tool+' '+' '.join(a)+'\\n')
rc=0
if tool=='ipset':
    op,name=a[:2]
    if op=='list':
        if name not in state: rc=1
        else: print('Number of entries:',len(state[name]))
    elif op=='create':
        if name in state: rc=1
        else: state[name]=[]
    elif op=='add': state[name].append(a[2])
    elif op=='swap': state[name],state[a[2]]=state[a[2]],state[name]
    elif op=='destroy': state.pop(name,None)
    elif op=='save':
        print('create',name,'hash:net')
        for net in state[name]: print('add',name,net)
elif tool in ('iptables','ip6tables'):
    name=a[a.index('--match-set')+1]; key=tool+':'+name
    if a[0]=='-C': rc=0 if key in rules else 1
    elif os.environ.get('FAIL_RULE')==tool: rc=1
    elif name not in state: rc=1
    elif key not in rules: rules.append(key)
elif tool=='curl':
    version=6 if any('blacklist-v6' in x for x in a) else 4
    Path(a[a.index('-o')+1]).write_text((p/f'feed{version}').read_text())
(p/'state').write_text(json.dumps(state))
sys.exit(rc)
'''
        for name in ('ipset','iptables','ip6tables','curl'):
            p = self.root/'bin'/name; p.write_text('#!'+sys.executable+'\n'+script); p.chmod(0o755)

    def run_install(self, **env):
        prelude = '''
log_section() { :; }; log() { :; }; rn_warn() { echo "$*"; }; rn_error() { echo "$*"; }
asb_detect_crowdsec() { :; }; asb_print_env() { :; }; asb_detect_trafficguard() { return 1; }
ensure_loopback_accept() { :; }; persist_ipsets() { :; }; managed_remove_legacy_cron() { :; }
enable_managed_blocklist_timer() { :; }
vps_fetch_github() { local v=4; [[ "$4" != *v6* ]] || v=6; cp "$FIXTURE/feed$v" "$5"; }
ASB_DIR="$FIXTURE/as"; ASB_CRON_SCRIPT="$FIXTURE/cron"
'''
        return subprocess.run(['bash','-c',HELPER+prelude+INSTALL+'\nrc=0; asb_install_iptables || rc=$?; exit "$rc"'],
                              env=self.env|env,text=True,capture_output=True,timeout=30)

    def data(self): return json.loads(self.state.read_text())

    def run_update(self):
        body = HELPER+UPDATER
        # Redirect every persistent path; real flock and temporary work are safe.
        body=body.replace('/run/firewall-blocklist-update.lock',str(self.root/'lock'))
        body=body.replace('/etc/ipset.conf',str(self.root/'ipset.conf'))
        body=body.replace('/etc/.ipset.conf.',str(self.root/'.ipset.conf.'))
        body=body.replace('/var/log/as-blacklist-update.log',str(self.root/'update.log'))
        body=body.replace('/usr/local/sbin/firewall-blocklist-rules.sh',str(self.root/'rules.sh'))
        rules = SOURCE.split("<<'SAFE_RULES'\n",1)[1].split('\nSAFE_RULES',1)[0]
        (self.root/'rules.sh').write_text(rules); (self.root/'rules.sh').chmod(0o755)
        (self.root/'ipset.conf').write_text('previous persisted state\n')
        return subprocess.run(['bash','-c',body,'test-updater','as'],env=self.env,text=True,capture_output=True,timeout=30)

    def test_fresh_install_empty_ipv6_skips_missing_set_and_rule(self):
        r=self.run_install(); self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertEqual(len(self.data()['asn-blacklist-v4']),100)
        self.assertNotIn('asn-blacklist-v6',self.data())
        self.assertNotIn('ip6tables:asn-blacklist-v6',self.data()['rules'])
        self.assertIn('IPv6 AS-фид явно пуст',r.stdout)
        self.assertNotIn('ip6tables ',(self.root/'calls').read_text())

    def test_empty_feed_preserves_previous_ipv6_set(self):
        self.state.write_text(json.dumps({'asn-blacklist-v6':['2001:4860::/32']}))
        r=self.run_install(); self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertEqual(self.data()['asn-blacklist-v6'],['2001:4860::/32'])
        self.assertIn('ip6tables:asn-blacklist-v6',self.data()['rules'])

    def test_malformed_or_suspicious_ipv6_is_partial_failure_not_ok(self):
        for text in ('<html>oops</html>',feed(6,1),feed(6,0).replace('inet6','inet'),feed(6,0)+'flush blacklist-v6\n'):
            (self.root/'feed6').write_text(text)
            r=self.run_install(); self.assertNotEqual(r.returncode,0,r.stdout+r.stderr)
            self.assertIn('AS установлен частично',r.stdout)
            self.assertNotIn('asn-blacklist-v6',self.data())

    def test_ipv6_rule_insertion_failure_is_not_success(self):
        (self.root/'feed6').write_text(feed(6,5))
        r=self.run_install(FAIL_RULE='ip6tables'); self.assertNotEqual(r.returncode,0)
        self.assertNotIn('ip6tables: AS DROP проверен',r.stdout)

    def test_timer_empty_ipv6_updates_ipv4_and_preserves_previous_ipv6(self):
        for previous in (False,True):
            initial={'asn-blacklist-v4':['9.9.9.0/24']}
            if previous: initial['asn-blacklist-v6']=['2001:4860::/32']
            self.state.write_text(json.dumps(initial))
            r=self.run_update(); self.assertEqual(r.returncode,0,r.stdout+r.stderr)
            self.assertEqual(len(self.data()['asn-blacklist-v4']),100)
            self.assertEqual(self.data().get('asn-blacklist-v6'),initial.get('asn-blacklist-v6'))

    def test_timer_nonempty_ipv6_after_initial_empty_adds_set_and_rule(self):
        self.state.write_text(json.dumps({'asn-blacklist-v4':['9.9.9.0/24']}))
        (self.root/'feed6').write_text(feed(6,5))
        r=self.run_update(); self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertEqual(len(self.data()['asn-blacklist-v6']),5)
        self.assertIn('ip6tables:asn-blacklist-v6',self.data()['rules'])

    def test_timer_invalid_ipv6_preserves_both_sets_and_persistence(self):
        initial={'asn-blacklist-v4':['9.9.9.0/24'],'asn-blacklist-v6':['2001:4860::/32']}
        self.state.write_text(json.dumps(initial)); (self.root/'feed6').write_text('')
        r=self.run_update(); self.assertNotEqual(r.returncode,0)
        for key in initial: self.assertEqual(self.data()[key],initial[key])
        self.assertEqual((self.root/'ipset.conf').read_text(),'previous persisted state\n')
