"""Fresh SelfSteal installation: inert services, real generated config/files."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE=(Path(__file__).resolve().parents[1]/'vps-setup.sh').read_text()
HELPERS=SOURCE[SOURCE.index('rn_create_nginx_config() {'):SOURCE.index('\nsetup_remnanode_builtin() {')]
BUILTIN=SOURCE[SOURCE.index('setup_remnanode_builtin() {'):SOURCE.index('\nsetup_remnanode_egames() {')]

class NginxInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.install=self.root/'node'
        self.env=dict(os.environ, RN_INSTALL_DIR=str(self.install),RN_DOMAIN='test.example.com',
                      RN_NODE_VERSION='3.4.4',RN_NODE_PORT='2222',RN_SECRET_KEY='a$secret:"key',
                      RN_XHTTP_MODE='true',RN_MEM_LIMIT='1500m',CALLS=str(self.root/'calls'))
        self.helpers=HELPERS.replace('/var/www',str(self.root/'www')).replace('/etc/letsencrypt',str(self.root/'certs')).replace('/dev/shm/nginx.sock',str(self.root/'nginx.sock'))
        self.base='''
rn_info() { :; }; rn_success() { :; }; rn_warn() { :; }
rn_error() { echo "$*" >&2; return 1; }
docker() { case "$1" in info) return 0;; inspect) return 1;; *) echo "docker $*" >> "$CALLS";; esac; }
ss() { :; }
'''
    def run_shell(self, tail, extra=''):
        return subprocess.run(['bash','-c',self.base+self.helpers+'\n'+extra+'\n'+tail],env=self.env,text=True,capture_output=True,timeout=10)
    def test_templates_permissions_and_secret_escaping(self):
        r=self.run_shell('umask 077; mkdir -p "$RN_INSTALL_DIR"; rn_create_nginx_config && rn_create_nginx_compose && rn_nginx_create_hook')
        self.assertEqual(r.returncode,0,r.stderr)
        conf=(self.install/'nginx-selfsteal/nginx.conf').read_text()
        self.assertIn('ssl proxy_protocol;',conf)
        self.assertNotIn('listen 443',conf)
        self.assertIn('http2 on;',conf)
        self.assertIn('location ^~ /.well-known/acme-challenge/',conf)
        compose=(self.install/'docker-compose.yml').read_text()
        self.assertIn('SECRET_KEY: "a$$secret:\\"key"',compose)
        self.assertIn('mem_limit: "1500m"',compose)
        self.assertIn('nginx:stable-alpine',compose)
        self.assertNotIn('caddy:',compose)
        self.assertEqual((self.install/'docker-compose.yml').stat().st_mode&0o777,0o600)
        self.assertEqual((self.root/'www/letsencrypt/.well-known/acme-challenge').stat().st_mode&0o777,0o755)
        hook=(self.root/'certs/renewal-hooks/deploy/reload-nginx-selfsteal.sh').read_text()
        self.assertIn(' test.example.com ',hook)
        self.assertNotIn('fr.xtls.win',hook)
    def test_preflight_preserves_existing_deployment(self):
        self.install.mkdir(); marker=self.install/'docker-compose.yml';marker.write_text('old')
        r=self.run_shell('rn_nginx_preflight')
        self.assertNotEqual(r.returncode,0)
        self.assertEqual(marker.read_text(),'old')
        self.assertFalse((self.root/'calls').exists())
    def test_preflight_refuses_containers_ports_socket_and_renewal(self):
        for stub in ('docker() { return 0; }', 'ss() { echo LISTEN; }',
                     'touch "'+str(self.root/'nginx.sock')+'"',
                     'mkdir -p "'+str(self.root/'certs/renewal')+'"; touch "'+str(self.root/'certs/renewal/test.example.com.conf')+'"'):
            r=self.run_shell('rn_nginx_preflight',stub)
            self.assertNotEqual(r.returncode,0,stub)
            (self.root/'nginx.sock').unlink(missing_ok=True)
    def test_install_orders_certificate_and_renewal_before_node(self):
        stubs='''
rn_install_deps() { echo deps >> "$CALLS"; }
apt-get() { echo apt >> "$CALLS"; }
rn_prepare_dirs() { mkdir -p "$RN_INSTALL_DIR"; }
rn_create_stub() { mkdir -p "'''+str(self.root/'www/html')+'''"; }
rn_compose() { echo "compose $*" >> "$CALLS"; [[ "$*" != 'ps -q remnanode' ]] || echo node-id; }
certbot() { echo "certbot $*" >> "$CALLS"; if [[ "${FAIL_CERT:-}" == 1 ]]; then return 1; fi; }
systemctl() { echo "systemctl $*" >> "$CALLS"; }
rn_nginx_tls_test() { echo tls >> "$CALLS"; }
rn_setup_oom_watcher() { echo oom >> "$CALLS"; }
rn_setup_logrotate() { echo rotate >> "$CALLS"; }
rn_open_panel_port() { echo panel >> "$CALLS"; }
rn_print_summary() { echo summary >> "$CALLS"; }
ufw() { :; }
'''
        r=self.run_shell('rn_install_nginx_selfsteal',stubs)
        self.assertEqual(r.returncode,0,r.stderr)
        calls=(self.root/'calls').read_text()
        self.assertLess(calls.index('certbot certonly'),calls.index('compose up -d --no-deps nginx'))
        self.assertLess(calls.index('--dry-run'),calls.index('compose up -d --no-deps remnanode'))
        self.assertIn('oom',calls);self.assertIn('rotate',calls)
        self.assertNotIn('stop',calls);self.assertNotIn('down',calls)
    def test_certificate_failure_does_not_start_containers(self):
        r=self.run_shell('rn_install_nginx_selfsteal','''
rn_install_deps() { :; }; apt-get() { :; }
rn_prepare_dirs() { mkdir -p "$RN_INSTALL_DIR"; }
rn_create_stub() { mkdir -p "'''+str(self.root/'www/html')+'''"; }
rn_compose() { echo "compose $*" >> "$CALLS"; }
certbot() { return 1; }; ufw() { :; }
''')
        self.assertNotEqual(r.returncode,0)
        self.assertNotIn('up -d',(self.root/'calls').read_text())
    def test_menu_keeps_caddy_default_and_adds_nginx_choice(self):
        caddy=['rn_choose_install_dir','rn_ask_params','rn_ask_cloudflare','rn_install_deps','rn_prepare_dirs','rn_create_stub','rn_create_dockerfile','rn_create_caddyfile','rn_create_compose','rn_setup_oom_watcher','rn_setup_logrotate','rn_open_panel_port','rn_start_services','rn_print_summary']
        stubs='\n'.join(n+'() { echo '+n+'; }' for n in caddy+['rn_install_nginx_selfsteal'])+'\nprint_header() { :; }\n'
        for answer,expected,absent in [('\n','rn_create_caddyfile','rn_install_nginx_selfsteal'),('2\n','rn_install_nginx_selfsteal','rn_ask_cloudflare'),('0\n',None,'rn_choose_install_dir')]:
            r=subprocess.run(['bash','-c',self.base+stubs+BUILTIN+'\nsetup_remnanode_builtin'],input=answer,text=True,capture_output=True)
            self.assertEqual(r.returncode,0,r.stderr)
            if expected:self.assertIn(expected,r.stdout)
            self.assertNotIn(absent,r.stdout)

if __name__=='__main__':unittest.main()
