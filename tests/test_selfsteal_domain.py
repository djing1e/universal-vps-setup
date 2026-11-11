"""Transactional domain change and rollback never recreate the node."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('domain_tool',ROOT/'modules/xtls-selfsteal-domain.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
NGINX='''http {
    server { listen 80; server_name old.example.com; }
    server { listen 80 default_server; server_name _; }
    server {
        listen unix:/dev/shm/nginx.sock ssl proxy_protocol;
        server_name old.example.com;
        ssl_certificate /etc/letsencrypt/live/old.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/old.example.com/privkey.pem;
    }
}
'''

class Backend:
    def __init__(self,kind): self.kind=kind; self.calls=[]; self.fail=None; self.interrupt=False
    def __call__(self,args,cwd=None,timeout=60):
        self.calls.append(args)
        if self.fail and self.fail in args:
            if self.interrupt:raise KeyboardInterrupt()
            raise RuntimeError('injected')
        if 'ps' in args and '-q' in args:return 'node\n'
        if args[:2]==['docker','inspect']:return json.dumps([{'Id':'node','State':{'Running':True,'StartedAt':'original'}}])
        return ''

class Prepared(m.Manager):
    def inspect(self):
        self.kind=self.run.kind;self.old='old.example.com'
        self.compose_cmd=['docker','compose'];self.compose_path=self.base/'docker-compose.yml'
        self.compose_original=self.compose_path.read_text();self.compose_mode=0o600
        self.conf_path=self.base/('nginx.conf' if self.kind=='nginx' else 'Caddyfile')
        self.conf_original=self.conf_path.read_text()
        self.proxy={'Id':'proxy','Name':'/proxy'}
        self.node={'Id':'node','State':{'Running':True,'StartedAt':'original'}}
        self.config={'services':{'caddy':{'environment':{'SELF_STEAL_DOMAIN':self.old,'TOKEN':'secret$$value'}},'remnanode':{'image':'node','environment':{'SECRET_KEY':'untouched$$value'}}}}
        return dict(status='noop' if self.new==self.old else 'ready',web_server=self.kind,old_domain=self.old,new_domain=self.new)
    def wait_tls(self,name,timeout=90):
        self.run.calls.append(['TLS',name])
        if getattr(self,'bad_tls',False) and name==self.new:raise RuntimeError('new TLS failed')
    def http_probe(self):self.run.calls.append(['HTTP_PROBE',self.new])
    def hook_path(self):return self.base/'hooks/new-domain.sh'

class DomainTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name)
        (self.base/'docker-compose.yml').write_text('original compose\n')
        (self.base/'nginx.conf').write_text(NGINX)
        (self.base/'Caddyfile').write_text('original Caddyfile\n')
        self.addCleanup(patch.stopall)
        patch.object(m,'secure',side_effect=lambda p,directory=False:Path(p)).start()
    def manager(self,kind='nginx'):
        self.backend=Backend(kind)
        return Prepared(self.base,'new.example.com',self.backend,self.base/'backups')
    def test_domain_validation(self):
        for x in ('Example.COM.','a'*63+'.example.com'):self.assertTrue(m.domain(x))
        for x in ('localhost','a..com','https://a.com','a.com:443','*.a.com','a'*64+'.com','a;echo.com','a/b.com','a.com\nfoo'):
            with self.assertRaises(ValueError):m.domain(x)
    def test_nginx_success_preserves_inode_node_compose_and_old_certificates(self):
        obj=self.manager();inode=obj.base.joinpath('nginx.conf').stat().st_ino
        result=obj.apply();self.assertEqual(result['status'],'changed')
        self.assertEqual((self.base/'nginx.conf').stat().st_ino,inode)
        self.assertIn('/live/new.example.com/',(self.base/'nginx.conf').read_text())
        self.assertIn('server_names_hash_bucket_size 512;',(self.base/'nginx.conf').read_text())
        self.assertEqual((self.base/'docker-compose.yml').read_text(),'original compose\n')
        self.assertIn(' new.example.com ',(self.base/'hooks/new-domain.sh').read_text())
        self.assertFalse(any('up' in c or 'restart' in c or 'delete' in c for c in self.backend.calls))
        self.assertEqual(json.loads((obj.backup/'state.json').read_text())['state'],'complete')
    def test_caddy_recreates_only_caddy_and_preserves_other_service(self):
        obj=self.manager('caddy');obj.apply()
        updated=json.loads((self.base/'docker-compose.yml').read_text())
        self.assertEqual(updated['services']['caddy']['environment']['SELF_STEAL_DOMAIN'],'new.example.com')
        self.assertEqual(updated['services']['remnanode'],obj.config['services']['remnanode'])
        self.assertEqual(updated['services']['caddy']['environment']['TOKEN'],'secret$$value')
        ups=[c for c in self.backend.calls if 'up' in c]
        self.assertEqual(len(ups),1);self.assertEqual(ups[0][-1],'caddy');self.assertIn('--no-deps',ups[0])
    def test_nginx_certificate_and_renewal_failures_restore_old_config(self):
        for stage in ('certonly','renew'):
            with self.subTest(stage=stage):
                obj=self.manager();self.backend.fail=stage
                with self.assertRaises(RuntimeError):obj.apply()
                self.assertEqual((self.base/'nginx.conf').read_text(),NGINX)
                self.assertEqual(json.loads((obj.backup/'state.json').read_text())['state'],'rolled_back')
    def test_interrupt_also_rolls_back(self):
        obj=self.manager();self.backend.fail='certonly';self.backend.interrupt=True
        with self.assertRaises(KeyboardInterrupt):obj.apply()
        self.assertEqual((self.base/'nginx.conf').read_text(),NGINX)
    def test_caddy_new_tls_failure_restores_compose_and_recreates_only_proxy(self):
        obj=self.manager('caddy');obj.bad_tls=True
        with self.assertRaises(RuntimeError):obj.apply()
        self.assertEqual((self.base/'docker-compose.yml').read_text(),'original compose\n')
        self.assertEqual([c[-1] for c in self.backend.calls if 'up' in c],['caddy','caddy'])
    def test_pending_prevents_apply_before_mutation(self):
        obj=self.manager();pending=self.base/'backups/previous';pending.mkdir(parents=True)
        (pending/'state.json').write_text('{"state":"pending"}')
        with self.assertRaises(ValueError):obj.apply()
        self.assertEqual((self.base/'nginx.conf').read_text(),NGINX)
        self.assertFalse(any(c[0]=='certbot' for c in self.backend.calls))
    def test_same_domain_is_noop(self):
        obj=self.manager();obj.new='old.example.com'
        self.assertEqual(obj.apply()['status'],'noop');self.assertEqual(self.backend.calls,[])
    def test_unknown_hook_rolls_back_without_overwriting_it(self):
        obj=self.manager();obj.hook_path().parent.mkdir();obj.hook_path().write_text('foreign hook')
        with self.assertRaises(ValueError):obj.apply()
        self.assertEqual(obj.hook_path().read_text(),'foreign hook')
        self.assertEqual((self.base/'nginx.conf').read_text(),NGINX)
    def test_runner_redacts_failure_output_and_arguments(self):
        with self.assertRaises(RuntimeError) as ctx:
            m.Runner()(['bash','-c','echo SECRET_TOKEN >&2; exit 7'])
        self.assertNotIn('SECRET_TOKEN',str(ctx.exception))
    def test_backup_is_private(self):
        obj=self.manager();obj.apply()
        self.assertEqual(obj.backup.stat().st_mode&0o777,0o700)
    def test_fresh_install_refuses_existing_files_and_containers(self):
        import subprocess
        source=(ROOT/'vps-setup.sh').read_text()
        body=source.split('rn_fresh_install_preflight() {',1)[1].split('\n}\n',1)[0]
        function='rn_fresh_install_preflight() {'+body+'\n}\n'
        env=dict(os.environ,RN_INSTALL_DIR=str(self.base))
        result=subprocess.run(['bash','-c','rn_error() { :; }; '+function+'rn_fresh_install_preflight'],env=env,capture_output=True)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual((self.base/'docker-compose.yml').read_text(),'original compose\n')
        empty=self.base/'empty';empty.mkdir()
        env['RN_INSTALL_DIR']=str(empty)
        result=subprocess.run(['bash','-c','rn_error() { :; }; docker() { return 0; }; '+function+'rn_fresh_install_preflight'],env=env,capture_output=True)
        self.assertNotEqual(result.returncode,0)
    def test_domain_action_is_available_without_installation(self):
        source=(ROOT/'vps-setup.sh').read_text()
        self.assertIn('6) rn_change_selfsteal_domain ;;',source)
        self.assertIn('3) rn_change_selfsteal_domain ;;',source)
        self.assertIn('[[ "$RN_METHOD" =~ ^[1236]$ ]]',source)
    def test_embedded_module_matches_tested_source(self):
        source=(ROOT/'vps-setup.sh').read_text()
        embedded=source.split("<<'PY_SELFSTEAL_DOMAIN'\n",1)[1].split('\nPY_SELFSTEAL_DOMAIN',1)[0]
        self.assertEqual(embedded,(ROOT/'modules/xtls-selfsteal-domain.py').read_text().rstrip())

if __name__=='__main__':unittest.main()
