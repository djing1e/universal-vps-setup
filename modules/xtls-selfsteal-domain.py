#!/usr/bin/env python3
"""Change a known Compose SelfSteal deployment without recreating Remnanode."""
import argparse
import fcntl
import hashlib
import http.client
import secrets
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time

MARKER = '# Managed by vps-setup selfsteal-domain'


def domain(value):
    value = value.strip().lower().rstrip('.')
    labels = value.split('.')
    if len(value) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in labels
    ):
        raise ValueError('Нужен DNS-домен без схемы, порта, пути и wildcard')
    return value


def secure(path, directory=False):
    path = Path(path)
    if path.resolve() != path.absolute():
        raise ValueError('Symlink/неоднозначный путь: ' + str(path))
    info = path.lstat()
    good = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not good or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Требуется обычный root-owned ресурс без записи для других: ' + str(path))
    return path


def write_mounted(path, content):
    # Replacing the inode would leave a file bind mount pointing at stale content.
    secure(path)
    with open(path, 'r+', encoding='utf-8') as stream:
        stream.seek(0)
        stream.write(content)
        stream.truncate()
        stream.flush()
        os.fsync(stream.fileno())


def replace_file(path, content, mode=0o600):
    path = Path(path)
    if path.exists() or path.is_symlink():
        secure(path)
    fd, name = tempfile.mkstemp(prefix='.selfsteal-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


class Runner:
    def __call__(self, args, cwd=None, timeout=60):
        try:
            result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise RuntimeError('Истекло время операции: ' + args[0]) from None
        if result.returncode:
            # Compose output and process arguments can contain API tokens or keys.
            raise RuntimeError('Операция завершилась ошибкой: ' + args[0] + ' (код ' + str(result.returncode) + ')')
        return result.stdout


class Manager:
    def __init__(self, base, new, run=None, backup_root='/var/backups/vps-selfsteal-domain'):
        self.base = Path(base).absolute()
        self.new = domain(new)
        self.run = run or Runner()
        self.backup_root = Path(backup_root)
        self.backup = None
        self.changed = False
        self.compose_changed = False
        self.hook_changed = False

    def compose(self, *args, file=None):
        cmd = self.compose_cmd + ['--project-directory', str(self.base), '-f', str(file or self.compose_path)]
        return self.run(cmd + list(args), cwd=self.base, timeout=120)

    def inspect(self):
        secure(self.base, True)
        self.compose_path = secure(self.base / 'docker-compose.yml')
        self.compose_original = self.compose_path.read_text()
        self.compose_mode = self.compose_path.stat().st_mode & 0o777
        try:
            self.run(['docker', 'compose', 'version'])
            self.compose_cmd = ['docker', 'compose']
        except RuntimeError:
            self.run(['docker-compose', 'version'])
            self.compose_cmd = ['docker-compose']
        self.config = json.loads(self.compose('config', '--format', 'json'))
        services = self.config.get('services', {})
        proxies = [x for x in ('nginx', 'caddy') if x in services]
        if len(proxies) != 1 or 'remnanode' not in services:
            raise ValueError('Нужен Compose с одной SelfSteal-службой nginx/caddy и remnanode')
        self.kind = proxies[0]
        proxy_ids = self.compose('ps', '-q', self.kind).split()
        node_ids = self.compose('ps', '-q', 'remnanode').split()
        if len(proxy_ids) != 1 or len(node_ids) != 1:
            raise ValueError('Ожидалась одна работающая SelfSteal-служба и одна Remnanode')
        self.proxy = json.loads(self.run(['docker', 'inspect', proxy_ids[0]]))[0]
        self.node = json.loads(self.run(['docker', 'inspect', node_ids[0]]))[0]
        if not self.proxy['State']['Running'] or not self.node['State']['Running']:
            raise ValueError('Сначала восстановите работающие контейнеры')
        labels = self.proxy['Config'].get('Labels', {})
        if (labels.get('com.docker.compose.service') != self.kind or
            Path(labels.get('com.docker.compose.project.working_dir', '/')) != self.base or
            self.proxy['HostConfig']['NetworkMode'] != 'host'):
            raise ValueError('Неизвестный владелец/топология SelfSteal')
        # A stopped orphan can be configured to restart at the next Docker boot.
        project = labels.get('com.docker.compose.project')
        all_ids = self.run(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project]).split()
        if all_ids:
            for obj in json.loads(self.run(['docker', 'inspect', *all_ids])):
                svc = obj['Config'].get('Labels', {}).get('com.docker.compose.service')
                if svc in ('nginx', 'caddy') and svc != self.kind:
                    policy = obj['HostConfig'].get('RestartPolicy', {}).get('Name', '')
                    if obj['State']['Running'] or policy not in ('', 'no'):
                        raise ValueError('Обнаружен конфликтующий proxy-контейнер; требуется ручная проверка')
        mounts = {x['Destination']: x for x in self.proxy['Mounts']}
        self.socket = Path('/dev/shm/nginx.sock')
        if '/dev/shm' not in mounts or mounts['/dev/shm']['Source'] != '/dev/shm' or not self.socket.is_socket():
            raise ValueError('SelfSteal-сокет не готов или /dev/shm не разделяется с хостом')
        if self.kind == 'nginx':
            m = mounts.get('/etc/nginx/nginx.conf', {})
            self.conf_path = secure(self.base / 'nginx-selfsteal/nginx.conf')
            if m.get('Source') != str(self.conf_path):
                raise ValueError('Неизвестный mount конфига Nginx')
            self.conf_original = self.conf_path.read_text()
            certs = re.findall(r'^\s*ssl_certificate\s+/etc/letsencrypt/live/([^/;]+)/fullchain.pem;', self.conf_original, re.M)
            if len(certs) != 1:
                raise ValueError('Не удалось однозначно определить сертификат Nginx')
            self.old = domain(certs[0])
            names = re.findall(r'^\s*server_name\s+([^;]+);', self.conf_original, re.M)
            if names != [self.old, '_', self.old] or not re.search(
                r'listen\s+unix:/dev/shm/nginx\.sock\s+ssl\s+proxy_protocol;', self.conf_original
            ) or ('/live/' + self.old + '/privkey.pem') not in self.conf_original:
                raise ValueError('Нестандартный конфиг Nginx; автоматическая смена отменена')
            for target in ('/etc/letsencrypt', '/var/www/letsencrypt'):
                if mounts.get(target, {}).get('Source') != target:
                    raise ValueError('Нестандартный Certbot mount: ' + target)
            self.run(['systemctl', 'is-enabled', 'certbot.timer'])
            self.run(['systemctl', 'is-active', 'certbot.timer'])
            self.run(['docker', 'exec', self.proxy['Id'], 'nginx', '-t'])
        else:
            self.conf_path = secure(self.base / 'Caddyfile')
            if mounts.get('/etc/caddy/Caddyfile', {}).get('Source') != str(self.conf_path):
                raise ValueError('Неизвестный mount Caddyfile')
            self.conf_original = self.conf_path.read_text()
            env = services['caddy'].get('environment', {})
            if not isinstance(env, dict):
                raise ValueError('Нестандартное окружение Caddy')
            self.old = domain(env.get('SELF_STEAL_DOMAIN', ''))
            actual_env = dict(x.split('=', 1) for x in self.proxy['Config'].get('Env', []) if '=' in x)
            if actual_env.get('SELF_STEAL_DOMAIN') != self.old:
                raise ValueError('Домен Compose не совпадает с работающим Caddy')
            if (env.get('CADDY_SOCKET_PATH') != str(self.socket) or
                'unix/{$CADDY_SOCKET_PATH}' not in self.conf_original or
                '{$SELF_STEAL_DOMAIN}' not in self.conf_original or
                'proxy_protocol' not in self.conf_original or 'admin off' not in self.conf_original):
                raise ValueError('Нестандартный Caddyfile; автоматическая смена отменена')
            self.run(['docker', 'exec', '-e', 'SELF_STEAL_DOMAIN=' + self.new, self.proxy['Id'],
                      'caddy', 'validate', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'])
        return {'web_server': self.kind, 'old_domain': self.old, 'new_domain': self.new,
                'status': 'noop' if self.old == self.new else 'ready',
                'remnanode_restart': False,
                'proxy_action': 'reload' if self.kind == 'nginx' else 'recreate_caddy_only'}

    def node_unchanged(self):
        ids = self.compose('ps', '-q', 'remnanode').split()
        if ids != [self.node['Id']]:
            raise RuntimeError('Контейнер Remnanode изменился во время операции')
        obj = json.loads(self.run(['docker', 'inspect', ids[0]]))[0]
        if not obj['State']['Running'] or obj['State']['StartedAt'] != self.node['State']['StartedAt']:
            raise RuntimeError('Состояние Remnanode изменилось во время операции')

    def wait_tls(self, name, timeout=90):
        deadline = time.monotonic() + timeout
        while True:
            try:
                ctx = ssl.create_default_context()
                with socket.socket(socket.AF_UNIX) as raw:
                    raw.settimeout(4)
                    raw.connect(str(self.socket))
                    raw.sendall(b'PROXY TCP4 127.0.0.2 127.0.0.1 12345 443\r\n')
                    with ctx.wrap_socket(raw, server_hostname=name) as tls:
                        tls.sendall(('GET / HTTP/1.1\r\nHost: ' + name + '\r\nConnection: close\r\n\r\n').encode())
                        if not re.match(rb'HTTP/1\.[01] [234]\d\d\b', tls.recv(4096)):
                            raise RuntimeError('SelfSteal HTTP не готов')
                return
            except (OSError, RuntimeError):
                if time.monotonic() >= deadline:
                    raise RuntimeError('Не пройдена проверка Unix PROXY/TLS/HTTP для ' + name) from None
                time.sleep(1)

    def nginx_reload(self):
        self.run(['docker', 'exec', self.proxy['Id'], 'nginx', '-t'])
        self.run(['docker', 'exec', self.proxy['Id'], 'nginx', '-s', 'reload'])

    def hook_path(self):
        digest = hashlib.sha256((self.proxy['Name'] + self.new).encode()).hexdigest()[:16]
        return Path('/etc/letsencrypt/renewal-hooks/deploy') / ('vps-selfsteal-' + digest + '.sh')

    def apply(self):
        plan = self.inspect()
        if plan['status'] == 'noop':
            return plan
        self.wait_tls(self.old)
        self.backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        secure(self.backup_root, True)
        for p in self.backup_root.glob('*/state.json'):
            if json.loads(p.read_text()).get('state') == 'pending':
                raise ValueError('Найдена незавершённая операция: ' + str(p.parent))
        self.backup = Path(tempfile.mkdtemp(prefix=time.strftime('%Y%m%dT%H%M%S-'), dir=self.backup_root))
        os.chmod(self.backup, 0o700)
        shutil.copy2(self.compose_path, self.backup / 'docker-compose.yml')
        shutil.copy2(self.conf_path, self.backup / self.conf_path.name)
        print('Резервная копия: ' + str(self.backup), flush=True)
        self.state('pending')
        try:
            self.changed = True
            if self.kind == 'nginx':
                self.nginx_apply()
            else:
                self.config['services']['caddy']['environment']['SELF_STEAL_DOMAIN'] = self.new
                candidate = self.backup / 'candidate.json'
                candidate.write_text(json.dumps(self.config, indent=2))
                self.compose('config', '-q', file=candidate)
                self.compose_changed = True
                replace_file(self.compose_path, candidate.read_text(), self.compose_mode)
                print('Пересоздаю только Caddy; Remnanode продолжает работать', flush=True)
                self.compose('up', '-d', '--no-deps', '--pull', 'never', '--no-build', 'caddy')
            self.wait_tls(self.new)
            self.node_unchanged()
            self.state('complete')
            return dict(plan, status='changed', backup=str(self.backup))
        except BaseException:
            print('Ошибка: восстанавливаю прежний домен', flush=True)
            try:
                self.rollback()
                self.state('rolled_back')
                print('Откат проверен; прежний домен восстановлен', flush=True)
            except BaseException:
                print('Откат не подтверждён. Ручная проверка: ' + str(self.backup), file=sys.stderr, flush=True)
            raise

    def state(self, value):
        replace_file(self.backup / 'state.json', json.dumps(dict(
            state=value, old_domain=self.old, new_domain=self.new, web_server=self.kind)))

    def http_probe(self):
        parent = secure('/var/www/letsencrypt/.well-known/acme-challenge', True)
        token = 'vps-domain-' + secrets.token_hex(16)
        path = parent / token
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, 'w') as stream:
            stream.write(token)
        path.chmod(0o644)
        try:
            for attempt in range(20):
                connection = http.client.HTTPConnection('127.0.0.1', 80, timeout=3)
                try:
                    connection.request('GET', '/.well-known/acme-challenge/' + token, headers={'Host': self.new})
                    response = connection.getresponse()
                    if response.status == 200 and response.read(4096).decode() == token:
                        return
                except (OSError, http.client.HTTPException):
                    pass
                finally:
                    connection.close()
                time.sleep(1)
            raise RuntimeError('Новый HTTP-01 host не готов; выпуск сертификата отменён')
        finally:
            path.unlink(missing_ok=True)

    def nginx_apply(self):
        print('Подготавливаю HTTP-01; действующий TLS остаётся на прежнем домене', flush=True)
        stage = self.conf_original.replace('server_name ' + self.old + ';',
                                          'server_name ' + self.old + ' ' + self.new + ';', 1)
        if not re.search(r'^\s*server_names_hash_bucket_size\s', stage, re.M):
            if stage.count('http {') != 1:
                raise ValueError('Блок http неоднозначен')
            stage = stage.replace('http {', 'http {\n    server_names_hash_bucket_size 512;', 1)
        else:
            stage = re.sub(r'(?m)^\s*server_names_hash_bucket_size\s+\d+;',
                           '    server_names_hash_bucket_size 512;', stage)
        write_mounted(self.conf_path, stage)
        self.nginx_reload()
        self.http_probe()
        print('Выпускаю сертификат: ' + self.new, flush=True)
        self.run(['certbot', 'certonly', '--webroot', '-w', '/var/www/letsencrypt',
                  '--cert-name', self.new, '-d', self.new, '--non-interactive', '--agree-tos',
                  '--register-unsafely-without-email'], timeout=240)
        final = stage.replace('server_name ' + self.old + ' ' + self.new + ';',
                              'server_name ' + self.old + ';').replace(self.old, self.new)
        write_mounted(self.conf_path, final)
        self.nginx_reload()
        self.wait_tls(self.new)
        self.run(['certbot', 'renew', '--cert-name', self.new, '--dry-run', '--non-interactive'], timeout=240)
        self.hook = self.hook_path()
        self.hook.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        secure(self.hook.parent, True)
        self.hook_original = None
        if self.hook.exists() or self.hook.is_symlink():
            secure(self.hook)
            self.hook_original = self.hook.read_text()
            if MARKER not in self.hook_original:
                raise ValueError('Неизвестный Certbot hook; замена отменена')
            shutil.copy2(self.hook, self.backup / 'renewal-hook.sh')
        self.hook_changed = True
        name = self.proxy['Name'].lstrip('/')
        if not re.fullmatch(r'[a-zA-Z0-9_.-]+', name):
            raise ValueError('Некорректное имя контейнера')
        hook = '#!/bin/sh\n' + MARKER + '\nset -eu\ncase " ${RENEWED_DOMAINS:-} " in\n'
        hook += '  *" ' + self.new + ' "*) ;;\n  *) exit 0 ;;\nesac\n'
        hook += 'docker exec ' + name + ' nginx -t\ndocker exec ' + name + ' nginx -s reload\n'
        replace_file(self.hook, hook, 0o755)

    def rollback(self):
        if self.kind == 'nginx':
            write_mounted(self.conf_path, self.conf_original)
            self.nginx_reload()
            if self.hook_changed:
                if self.hook_original is None:
                    self.hook.unlink(missing_ok=True)
                else:
                    replace_file(self.hook, self.hook_original, 0o755)
        elif self.compose_changed:
            replace_file(self.compose_path, self.compose_original, self.compose_mode)
            self.compose('up', '-d', '--no-deps', '--pull', 'never', '--no-build', 'caddy')
        self.wait_tls(self.old)
        self.node_unchanged()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'apply'))
    parser.add_argument('--dir', default='/opt/remnanode')
    parser.add_argument('--new-domain', required=True)
    parser.add_argument('--confirm')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('Запускайте от root')
    if args.action == 'apply' and args.confirm != 'CHANGE-SELFSTEAL-DOMAIN':
        raise ValueError('Не подтверждена смена домена')
    os.umask(0o077)
    lock = Path('/run/lock/vps-selfsteal-domain.lock')
    if lock.exists() or lock.is_symlink():
        secure(lock)
    with lock.open('a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        def interrupted(signum, frame):
            raise RuntimeError('Операция прервана сигналом ' + str(signum))
        signal.signal(signal.SIGTERM, interrupted)
        obj = Manager(args.dir, args.new_domain)
        print(json.dumps(obj.inspect() if args.action == 'check' else obj.apply(), ensure_ascii=False, indent=2))
        if args.action == 'apply':
            print('Обновите домен Reality/SNI и клиентского хоста в панели. Старые сертификаты сохранены.')


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print('Ошибка: ' + str(error), file=sys.stderr)
        sys.exit(1)
