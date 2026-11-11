"""Real Compose proxy changes; local test CA, no public ACME account needed."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('domain_change',ROOT/'modules/xtls-selfsteal-domain.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def cmd(*args):return subprocess.run(args,check=True,text=True,capture_output=True).stdout.strip()

def compose(base,*args):return cmd('docker','compose','--project-directory',str(base),'-f',str(base/'docker-compose.yml'),*args)

with tempfile.TemporaryDirectory() as temp:
    root=Path(temp);base=root/'node';base.mkdir()
    name='domain-ci-'+str(os.getpid())
    shared=Path('/dev/shm/nginx.sock')
    if shared.exists():raise RuntimeError('CI socket already occupied')
    caddyfile=ROOT/'vps-setup.sh'
    source=caddyfile.read_text();function=source[source.index('rn_create_caddyfile() {'):source.index('\nrn_create_compose() {')]
    subprocess.run(['bash','-c','rn_info() { :; }; rn_success() { :; };\n'+function+'\nrn_create_caddyfile'],
                   env=dict(os.environ,RN_INSTALL_DIR=str(base),RN_CF_MODE='false'),check=True)
    p=base/'Caddyfile';p.write_text(p.read_text().replace('    bind unix/{$CADDY_SOCKET_PATH}', '    bind unix/{$CADDY_SOCKET_PATH}\n    tls internal'))
    p.chmod(0o600)
    www=root/'html';www.mkdir();(www/'index.html').write_text('SelfSteal CI')
    config={'name':name,'services':{
        'caddy':{'image':'caddy:2.11.2','container_name':name+'-caddy','network_mode':'host',
                 'environment':{'SELF_STEAL_DOMAIN':'old.example.com','CADDY_SOCKET_PATH':'/dev/shm/nginx.sock','TEST_TOKEN':'test$$value'},
                 'volumes':[str(p)+':/etc/caddy/Caddyfile:ro',str(www)+':/var/www/html:ro','/dev/shm:/dev/shm',name+'-data:/data']},
        'remnanode':{'image':'busybox:1.37','command':['sleep','3600'],'environment':{'SECRET_KEY':'untouched$$value'}}},
        'volumes':{name+'-data':{}}}
    (base/'docker-compose.yml').write_text(json.dumps(config));(base/'docker-compose.yml').chmod(0o600)
    try:
        compose(base,'up','-d')
        proxy=compose(base,'ps','-q','caddy')
        ca=root/'ca.crt'
        for attempt in range(30):
            r=subprocess.run(['docker','cp',proxy+':/data/caddy/pki/authorities/local/root.crt',str(ca)],capture_output=True)
            if not r.returncode:break
            time.sleep(1)
        os.environ['SSL_CERT_FILE']=str(ca)
        obj=m.Manager(base,'new.example.com',backup_root=root/'backups')
        result=obj.apply();assert result['status']=='changed'
        env=cmd('docker','exec',compose(base,'ps','-q','caddy'),'env').splitlines()
        assert 'SELF_STEAL_DOMAIN=new.example.com' in env
        assert 'TEST_TOKEN=test$value' in env
        assert 'SECRET_KEY=untouched$value' in cmd('docker','exec',compose(base,'ps','-q','remnanode'),'env').splitlines()
        # A failed new TLS check must restore only the proxy and the original domain.
        obj2=m.Manager(base,'failed.example.com',backup_root=root/'backups')
        original_wait=obj2.wait_tls
        def failed_new_tls(domain,timeout=90):
            if domain=='failed.example.com':raise RuntimeError('injected TLS failure')
            original_wait(domain,timeout)
        obj2.wait_tls=failed_new_tls
        try:obj2.apply()
        except RuntimeError:pass
        else:raise AssertionError('expected rollback')
        assert 'SELF_STEAL_DOMAIN=new.example.com' in cmd('docker','exec',compose(base,'ps','-q','caddy'),'env').splitlines()
        print('PASS real Caddy domain change, Compose secret preservation, node ID/start unchanged and automatic rollback')
    finally:
        compose(base,'down','-v')
        shared.unlink(missing_ok=True)

    # Fresh Nginx fixture uses the known v5 configuration and isolated cert names.
    old='old-domain-ci.example.com';new='new-domain-ci.example.com'
    certroot=Path('/etc/letsencrypt/live');oldline=certroot/old;newline=certroot/new
    if oldline.exists() or newline.exists():raise RuntimeError('CI certificate fixture collision')
    oldline.mkdir(parents=True)
    cmd('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=SelfSteal CI',
        '-addext','subjectAltName=DNS:'+old+',DNS:'+new,
        '-keyout',str(oldline/'privkey.pem'),'-out',str(oldline/'fullchain.pem'))
    os.environ['SSL_CERT_FILE']=str(oldline/'fullchain.pem')
    source=(ROOT/'vps-setup.sh').read_text()
    func=source[source.index('rn_create_nginx_config() {'):source.index('\nrn_nginx_create_hook() {')]
    subprocess.run(['bash','-c',func+'\nrn_create_nginx_config'],env=dict(os.environ,RN_INSTALL_DIR=str(base),RN_DOMAIN=old),check=True)
    nginx=base/'nginx-selfsteal/nginx.conf'
    config['services'].pop('caddy')
    config['services']['nginx']={'image':'nginx:stable-alpine','container_name':name+'-nginx','network_mode':'host','volumes':[
        str(nginx)+':/etc/nginx/nginx.conf:ro',str(www)+':/var/www/html:ro','/dev/shm:/dev/shm',
        '/etc/letsencrypt:/etc/letsencrypt:ro','/var/www/letsencrypt:/var/www/letsencrypt:ro']}
    (base/'docker-compose.yml').write_text(json.dumps(config));nginx.chmod(0o600)
    class TestACME(m.Runner):
        def __call__(self,args,cwd=None,timeout=60):
            if args[0]=='systemctl':return 'enabled\n' if 'is-enabled' in args else 'active\n'
            if args[0]=='certbot':
                if args[1]=='certonly':
                    token=Path('/var/www/letsencrypt/.well-known/acme-challenge/domain-ci-token')
                    token.write_text('challenge');token.chmod(0o644)
                    try:
                        req=urllib.request.Request('http://127.0.0.1/.well-known/acme-challenge/domain-ci-token',headers={'Host':new})
                        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=10) as response:
                            assert response.read()==b'challenge'
                        shutil.copytree(oldline,newline)
                    finally:token.unlink(missing_ok=True)
                return ''
            return super().__call__(args,cwd,timeout)
    hook=None
    try:
        compose(base,'up','-d')
        for attempt in range(30):
            if shared.is_socket():break
            time.sleep(1)
        obj=m.Manager(base,new,run=TestACME(),backup_root=root/'backups')
        result=obj.apply();hook=obj.hook_path();assert result['status']=='changed'
        effective=cmd('docker','exec',compose(base,'ps','-q','nginx'),'cat','/etc/nginx/nginx.conf')
        assert '/live/'+new+'/' in effective
        assert old not in effective
        print('PASS real Nginx reload, unchanged bind-mount inode, dual-domain HTTP-01, new TLS and node ID/start unchanged')
    finally:
        compose(base,'down','-v');shared.unlink(missing_ok=True)
        if hook:hook.unlink(missing_ok=True)
        shutil.rmtree(oldline);shutil.rmtree(newline,ignore_errors=True)
