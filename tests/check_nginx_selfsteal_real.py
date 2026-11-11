"""CI: run the generated Nginx config with real TLS, PROXY protocol and HTTP-01."""
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
from test_nginx_selfsteal_install import NginxInstallTests

def run(*args, **kwargs):
    return subprocess.run(args,check=True,text=True,capture_output=True,**kwargs).stdout.strip()

fixture=NginxInstallTests();fixture.setUp()
name='selfsteal-ci-'+str(os.getpid())
try:
    r=fixture.run_shell('umask 077; mkdir -p "$RN_INSTALL_DIR"; rn_create_nginx_config && rn_create_nginx_compose')
    if r.returncode:raise RuntimeError(r.stderr)
    conf=fixture.install/'nginx-selfsteal/nginx.conf'
    conf.write_text(conf.read_text().replace(str(fixture.root/'www'),'/var/www').replace(str(fixture.root/'certs'),'/etc/letsencrypt').replace(str(fixture.root/'nginx.sock'),'/dev/shm/nginx.sock'))
    certs=fixture.root/'certs';lineage=certs/'live/test.example.com';lineage.mkdir(parents=True)
    run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
        '-subj','/CN=test.example.com','-addext','subjectAltName=DNS:test.example.com',
        '-keyout',str(lineage/'privkey.pem'),'-out',str(lineage/'fullchain.pem'))
    www=fixture.root/'www';(www/'html').mkdir();(www/'html/index.html').write_text('SelfSteal CI')
    challenge=www/'letsencrypt/.well-known/acme-challenge/probe';challenge.write_text('acme-token');challenge.chmod(0o644)
    shared=fixture.root/'shm';shared.mkdir()
    compose=json.loads(run('docker','compose','-f',str(fixture.install/'docker-compose.yml'),'config','--format','json'))
    assert compose['services']['remnanode']['environment']['SECRET_KEY']==fixture.env['RN_SECRET_KEY']
    volumes=[]
    for src,dst in [(conf,'/etc/nginx/nginx.conf'),(certs,'/etc/letsencrypt'),(www/'html','/var/www/html'),(www/'letsencrypt','/var/www/letsencrypt'),(shared,'/dev/shm')]:
        volumes+=['-v',str(src)+':'+dst+('' if dst=='/dev/shm' else ':ro')]
    run('docker','run','--rm',*volumes,'nginx:stable-alpine','nginx','-t')
    run('docker','run','-d','--name',name,'-p','127.0.0.1::80',*volumes,'nginx:stable-alpine')
    address=run('docker','port',name,'80/tcp')
    context=ssl.create_default_context(cafile=str(lineage/'fullchain.pem'))
    for attempt in range(30):
        try:
            sock=socket.socket(socket.AF_UNIX);sock.settimeout(3);sock.connect(str(shared/'nginx.sock'))
            sock.sendall(b'PROXY TCP4 127.0.0.2 127.0.0.1 12345 443\r\n')
            with context.wrap_socket(sock,server_hostname='test.example.com') as tls:
                tls.sendall(b'GET / HTTP/1.1\r\nHost: test.example.com\r\nConnection: close\r\n\r\n')
                assert tls.recv(4096).startswith(b'HTTP/1.1 200')
            break
        except (OSError,AssertionError):
            if attempt==29:raise
            time.sleep(1)
    assert run('curl','--noproxy','*','-fsS','-H','Host: test.example.com','http://'+address+'/.well-known/acme-challenge/probe')=='acme-token'
    assert run('curl','--noproxy','*','-sS','-o','/dev/null','-w','%{http_code}','-H','Host: unknown.example','http://'+address+'/')=='204'
    run('docker','exec',name,'nginx','-s','reload')
    print('PASS real Nginx config, Compose secret, Unix PROXY/TLS/HTTP 200, HTTP-01 webroot, default 204 and reload')
finally:
    subprocess.run(['docker','rm','-f',name],capture_output=True)
    fixture.tmp.cleanup()
