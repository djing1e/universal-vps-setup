#!/usr/bin/env python3
"""Proxmox Host: bounded Audit, deterministic Plan, guarded transactional Apply.

Never imports or calls the VPS provisioning functions. No network requests.
"""
import argparse
import ast
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import time

try:
    from .vps_inventory import probe
except ImportError:
    from vps_inventory import probe

MAX_FILE = 65536
CONFIRM = 'APPLY PROXMOX HOST'


def read_file(path):
    try:
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            raise ValueError('not a regular file: '+str(path))
        with path.open('rb') as stream:
            data = stream.read(MAX_FILE + 1)
        if len(data) > MAX_FILE:
            raise ValueError('oversized file: '+str(path))
        return data
    except FileNotFoundError:
        return None


def fingerprint(data):
    return hashlib.sha256(data).hexdigest() if data is not None else None


def detect(root=Path('/'), runner=probe):
    package = runner(['dpkg-query', '-W', '-f=${Status}', 'pve-manager'])
    version = runner(['pveversion'])
    installed = package.get('status') == 'ok' and package.get('output', '').strip() == 'install ok installed'
    valid_version = version.get('status') == 'ok' and version.get('output', '').startswith('pve-manager/')
    markers = (root/'etc/pve').exists() or (root/'usr/bin/pveversion').exists()
    if installed and valid_version:
        state = 'proxmox'
    elif installed or valid_version or markers or os.uname().release.endswith('-pve'):
        state = 'proxmox_uncertain'
    elif (package.get('status') == 'ok' or (package.get('status') == 'error' and package.get('returncode') == 1)) and version.get('status') == 'unavailable':
        state = 'vps'
    else:
        state = 'unknown'
    return {'profile': state, 'package': package, 'version': version,
            'default': 'audit', 'changes_applied': False}


def node_name():
    node = socket.gethostname().split('.')[0]
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9-]{0,62}', node):
        raise ValueError('invalid local node name')
    return node


def paths(node):
    return {'firewall': f'/etc/pve/nodes/{node}/host.fw',
            'ssh': '/etc/ssh/sshd_config.d/00-proxmox-host.conf',
            'fail2ban': '/etc/fail2ban/jail.d/proxmox-host.local'}


def audit(root=Path('/'), runner=probe, node=None):
    node = node or node_name()
    report = detect(root, runner)
    report.update(mode='audit', node=node, probes={}, files={})
    commands = {
        'guests': ['qm', 'list'],
        'containers': ['pct', 'list'],
        'firewall': ['pve-firewall', 'status'],
        'ssh_effective': ['sshd', '-T'],
        'ports': ['ss', '-H', '-lnt'],
        'bridges': ['ip', '-j', '-d', 'link', 'show', 'type', 'bridge'],
        'addresses': ['ip', '-j', 'address', 'show'],
        'ipv4_routes': ['ip', '-j', '-4', 'route', 'show'],
        'ipv6_routes': ['ip', '-j', '-6', 'route', 'show'],
        'cluster': ['pvecm', 'status'],
        'alternative_firewall': ['systemctl', 'is-active', 'proxmox-firewall.service'],
    }
    for name, argv in commands.items():
        result = runner(argv)
        # Never publish authentication-related SSH fields or unrelated settings.
        if name == 'ssh_effective':
            result = dict(result, output='\n'.join(line for line in result.get('output', '').splitlines()
                          if line.split(' ', 1)[0] in {
                              'port', 'listenaddress', 'permitrootlogin', 'passwordauthentication',
                              'kbdinteractiveauthentication', 'pubkeyauthentication'}))
        report['probes'][name] = result
    files = ['/etc/pve/firewall/cluster.fw', *paths(node).values()]
    for name in files:
        try:
            data = read_file(root/name.lstrip('/'))
            item = {'sha256': fingerprint(data), 'status': 'absent' if data is None else 'observed'}
            # Firewall files contain rules only; SSH/fail2ban contents are not disclosed.
            if name.endswith('.fw'):
                item['content'] = (data or b'').decode('utf-8')
            report['files'][name] = item
        except (OSError, ValueError, UnicodeError):
            report['files'][name] = {'status': 'unknown'}
    # Ping only, never guest-exec or read VM configuration (which can include secrets).
    guests = report['probes']['guests']
    report['guest_agent'] = {}
    if guests.get('status') == 'ok':
        for line in guests.get('output', '').splitlines()[:129]:
            columns = line.split()
            if len(columns) > 2 and columns[0].isdigit() and columns[2] == 'running':
                report['guest_agent'][columns[0]] = runner(['qm', 'agent', columns[0], 'ping'])
    report['limitations'] = ['Read-only snapshot; failures mean unknown, not absent.',
                            'Review private IP topology before sharing. No guest configuration is read.']
    return report


def admin_networks(values):
    if not values:
        raise ValueError('explicit admin IPv4 AND IPv6 allowlists required; never infer server/client IP')
    networks = []
    for value in values:
        net = ipaddress.ip_network(value, strict=True)
        if net.prefixlen == 0 or not net.is_global or net.is_multicast:
            raise ValueError('admin network must be a global unicast range narrower than /0')
        networks.append(net)
    if {n.version for n in networks} != {4, 6}:
        raise ValueError('explicit IPv4 and IPv6 admin networks required')
    return sorted({str(n) for n in networks})


def firewall_content(admins, spice=False):
    lines = ['# Managed by universal-vps-setup Proxmox Host', '[OPTIONS]',
             'enable: 1', 'policy_in: DROP', 'policy_out: ACCEPT', '', '[RULES]']
    for network in admin_networks(admins):
        for port in [22, 8006] + ([3128] if spice else []):
            lines.append(f'IN ACCEPT -source {network} -p tcp -dport {port}')
    # PVE's standard rules retain established connections and necessary ICMP/NDP.
    # No FORWARD, VM, NIC, bridge, route, or cluster-wide writes.
    return '\n'.join(lines) + '\n'


def make_plan(report, operation, admins=(), spice=False, dynamic_admin=False):
    if report.get('profile') != 'proxmox':
        raise ValueError('confirmed Proxmox detection required')
    node = report['node']
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9-]{0,62}', node):
        raise ValueError('invalid node')
    if operation not in ('firewall', 'ssh', 'fail2ban', 'crowdsec-observe', 'sysctl-advice'):
        raise ValueError('operation is not allowlisted')
    blockers = []
    content = None
    destination = paths(node).get(operation)
    if operation == 'firewall':
        content = firewall_content(admins, spice)
        cluster = report['files'].get('/etc/pve/firewall/cluster.fw', {})
        if cluster.get('status') != 'observed' or not re.search(
                r'(?m)^enable:\s*1[ \t]*$', cluster.get('content', '').split('[OPTIONS]', 1)[-1].split('[', 1)[0]):
            blockers.append('Datacenter firewall must already be enabled and reviewed manually; this tool never changes cluster policy')
        current = report['files'].get(destination, {})
        if current.get('status') not in ('observed', 'absent'):
            blockers.append('host firewall file state unknown')
        if current.get('status') == 'observed' and not current.get('content', '').startswith(
                '# Managed by universal-vps-setup Proxmox Host\n'):
            blockers.append('existing foreign host rules require manual migration; never overwrite')
        status = report['probes']['firewall']
        if status.get('status') != 'ok' or 'enabled/running' not in status.get('output', ''):
            blockers.append('pve-firewall must already be enabled/running')
        alternative = report['probes']['alternative_firewall']
        if alternative.get('status') not in ('ok', 'error') or alternative.get('output', '').strip() not in ('inactive', 'unknown'):
            blockers.append('alternative proxmox-firewall backend active or unknown')
        if re.search(r'(?m)^nftables:\s*1', cluster.get('content', '')):
            blockers.append('nftables backend not supported; do not replace it')
        ssh = report['probes']['ssh_effective']
        ports = [line for line in ssh.get('output', '').splitlines() if line.startswith('port ')]
        if ssh.get('status') != 'ok' or ports != ['port 22']:
            blockers.append('effective SSH port must be exactly 22')
        if dynamic_admin:
            blockers.append('dynamic admin IP: establish a stable trusted egress/CIDR before activation')
    elif operation == 'ssh':
        content = ('# Managed by universal-vps-setup Proxmox Host\n'
                   'PermitRootLogin prohibit-password\nPasswordAuthentication no\n'
                   'KbdInteractiveAuthentication no\nPubkeyAuthentication yes\n')
    elif operation == 'fail2ban':
        content = ('# Managed by universal-vps-setup Proxmox Host\n'
                   '[sshd]\nenabled = true\nbackend = systemd\nport = 22\n'
                   'banaction = dummy\n')
    plan = {'schema_version': 1, 'profile': 'proxmox', 'mode': 'plan', 'node': node,
            'operation': operation, 'admin_networks': list(admins), 'spice': bool(spice),
            'dynamic_admin': bool(dynamic_admin), 'blockers': blockers,
            'destination': destination, 'content': content,
            'before_sha256': report['files'].get(destination, {}).get('sha256'),
            'cluster_sha256': report['files'].get('/etc/pve/firewall/cluster.fw', {}).get('sha256'),
            'changes_applied': False,
            'invariants': {key: fingerprint(json.dumps(report['probes'][key], sort_keys=True).encode())
                           for key in ('guests', 'containers', 'bridges', 'addresses', 'ipv4_routes', 'ipv6_routes', 'ssh_effective')},
            'protected': ['VM/CT configuration', 'bridges', 'routes', 'DNS', 'kernel',
                          'cluster firewall', 'FORWARD policy', 'guest NIC firewall flags'],
            'notes': ['No package installation. fail2ban uses dummy action (no firewall bans).',
                      'CrowdSec requires an existing installation with no bouncers.',
                      'sysctl is advisory only: retain PVE defaults; no writes.',
                      'Apply requires console/rescue, rollback and key-login confirmations.']}
    plan['id'] = fingerprint(json.dumps(plan, sort_keys=True).encode())
    return plan


def run(argv):
    result = probe(argv, timeout=30)
    if result['status'] != 'ok':
        raise RuntimeError('command failed: '+ ' '.join(argv)+': '+result.get('output', '')[:1000])
    return result.get('output', '')


def validate_ssh_effective(effective):
    for line in ('passwordauthentication no', 'kbdinteractiveauthentication no',
                 'pubkeyauthentication yes', 'permitrootlogin prohibit-password'):
        if line not in effective.splitlines() and not (line.endswith('prohibit-password') and
                                                       'permitrootlogin without-password' in effective.splitlines()):
            raise ValueError('SSH Include/Match precedence requires manual review: '+line)


def check_fail2ban_dump():
    """Only the dummy SSH jail may be loaded/reloaded by this profile."""
    dump = run(['fail2ban-client', '-d'])
    parsed = False
    for line in dump.splitlines():
        if not line.startswith('['):
            continue
        command = ast.literal_eval(line)
        parsed = True
        if not isinstance(command, list) or not command:
            raise ValueError('unrecognized fail2ban dry-run output')
        if command[0] == 'add' and command[1] != 'sshd':
            raise ValueError('other enabled fail2ban jails require manual review')
        if len(command) > 3 and command[0] == 'set' and command[2] == 'addaction' and command[3] != 'dummy':
            raise ValueError('fail2ban actions other than dummy are prohibited')

    if not parsed:
        raise ValueError('fail2ban dry-run state unknown')


def atomic_write(path, content):
    # Parent directory must exist; never follow a destination symlink.
    if path.is_symlink():
        raise ValueError('refusing symlink: '+str(path))
    tmp = path.with_name(path.name + '.proxmox-host-tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def rollback(transaction):
    """Used by both the independent systemd timer and immediate failure path."""
    with (transaction/'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if (transaction/'committed').exists() or (transaction/'rolled-back').exists():
            return
        state = json.loads((transaction/'state.json').read_text())
        path = Path(state['destination']) if state['destination'] else None
        if path:
            if state['existed']:
                atomic_write(path, (transaction/'before').read_bytes())
                if not str(path).startswith('/etc/pve/'):
                    os.chmod(path, state['mode'])
            else:
                path.unlink(missing_ok=True)
        if state['operation'] == 'firewall':
            run(['pve-firewall', 'compile'])
            run(['systemctl', 'restart', 'pve-firewall.service'])
        elif state['operation'] == 'ssh':
            run(['sshd', '-t'])
            run(['systemctl', 'reload', 'ssh.service'])
        elif state['operation'] == 'fail2ban':
            run(['systemctl', 'restart' if state['was_active'] else 'stop', 'fail2ban.service'])
        elif state['operation'] == 'crowdsec-observe' and not state['was_active']:
            run(['systemctl', 'stop', 'crowdsec.service'])
        (transaction/'rolled-back').touch()


def apply(plan, args, root=Path('/'), runner=probe):
    # Root/runner arguments exist for fixture integration tests, not CLI overrides.
    if args.confirm != CONFIRM or not all((args.console_confirmed, args.rollback_confirmed,
                                          args.key_login_confirmed)):
        raise ValueError('explicit plan, console/rescue, rollback and working key login confirmations required')
    if not 60 <= args.rollback_seconds <= 600:
        raise ValueError('rollback timeout must be 60..600 seconds')
    if os.geteuid() != 0:
        raise ValueError('root required')
    identity = detect(root, runner)
    if identity['profile'] != 'proxmox' or not re.match(r'pve-manager/9\.2[./-]', identity['version'].get('output', '')):
        raise ValueError('Apply is restricted to confirmed Proxmox VE 9.2')
    os_release = read_file(root/'etc/os-release') or b''
    if not re.search(rb'(?m)^ID=[\"\']?debian[\"\']?$', os_release) or not re.search(rb'(?m)^VERSION_ID=[\"\']?13[\"\']?$', os_release):
        raise ValueError('Apply is restricted to Debian 13')
    current = audit(root, runner, plan.get('node'))
    if plan.get('node') != node_name() and root == Path('/'):
        raise ValueError('plan belongs to another node')
    fresh = make_plan(current, plan['operation'], plan['admin_networks'], plan['spice'], plan['dynamic_admin'])
    if fresh != plan or plan['blockers']:
        raise ValueError('plan stale, modified or blocked; run Audit and Plan again')
    op = plan['operation']
    if op == 'sysctl-advice':
        return {'status': 'advisory_only', 'changes_applied': False}
    if op == 'crowdsec-observe':
        packages = runner(['dpkg-query', '-W', '-f=${binary:Package}\n'])
        bouncers = runner(['cscli', 'bouncers', 'list', '-o', 'json'])
        if packages.get('status') != 'ok' or 'crowdsec' not in packages.get('output', '').splitlines():
            raise ValueError('CrowdSec must already be installed')
        if any('bouncer' in line for line in packages.get('output', '').splitlines()) or (
                bouncers.get('status') != 'ok' or json.loads(bouncers.get('output', 'null')) != []):
            raise ValueError('CrowdSec bouncers present or unknown; observe-only cannot be guaranteed')
    if op == 'fail2ban':
        run(['fail2ban-client', '-t'])
        check_fail2ban_dump()
    if op == 'ssh':
        run(['sshd', '-t'])
        effective = run(['sshd', '-T'])
        if 'pubkeyauthentication yes' not in effective:
            raise ValueError('working public-key authentication required')
    destination = root/plan['destination'].lstrip('/') if plan['destination'] else None
    previous = read_file(destination) if destination else None
    if destination and previous == plan['content'].encode():
        if op == 'ssh':
            validate_ssh_effective(run(['sshd', '-T']))
        return {'status': 'unchanged', 'changes_applied': False}
    if op in ('ssh', 'fail2ban') and previous and not previous.startswith(
            b'# Managed by universal-vps-setup Proxmox Host\n'):
        raise ValueError('foreign configuration requires manual review')
    transaction = root/'var/lib/proxmox-host'/str(time.time_ns())
    transaction.mkdir(parents=True, mode=0o700)
    os.chmod(transaction.parent, 0o700)
    state = {'operation': op, 'destination': str(destination) if destination else None,
             'existed': previous is not None,
             'mode': stat.S_IMODE(destination.stat().st_mode) if previous is not None else 0o600,
             'was_active': runner(['systemctl', 'is-active', 'fail2ban.service' if op == 'fail2ban' else 'crowdsec.service']).get('status') == 'ok',
             'deadline': time.time() + args.rollback_seconds}
    if previous is not None:
        (transaction/'before').write_bytes(previous)
    (transaction/'state.json').write_text(json.dumps(state))
    # Snapshot self and dependency so edits/deletions of the checkout cannot break rollback.
    for name in ('proxmox_host.py', 'vps_inventory.py'):
        shutil.copyfile(Path(__file__).with_name(name), transaction/name)
    try:
        if op == 'firewall':
            candidate = transaction/'candidate.fw'
            candidate.write_text(plan['content'])
            run(['perl', '-e',
                 'use PVE::Cluster; use PVE::Firewall; PVE::Cluster::cfs_update(); '
                 '$SIG{__WARN__}=sub { die @_ }; '
                 'my $c=PVE::Firewall::load_clusterfw_conf(); '
                 'my $h=PVE::Firewall::load_hostfw_conf($c,$ARGV[0]); '
                 'PVE::Firewall::compile($c,$h);', str(candidate)])
        watchdog = 'proxmox-host-' + transaction.name
        run(['systemd-run', '--unit='+watchdog, '--on-active='+str(args.rollback_seconds)+'s',
             '--timer-property=AccuracySec=1s', sys.executable, str(transaction/'proxmox_host.py'),
             '_rollback', str(transaction)])
    except BaseException:
        (transaction/'rolled-back').touch()
        raise
    try:
        with (transaction/'lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if time.time() >= state['deadline'] or (transaction/'rolled-back').exists():
                raise ValueError('rollback deadline elapsed')
            if destination:
                if fingerprint(read_file(destination)) != plan['before_sha256']:
                    raise ValueError('destination changed since plan')
                if op == 'firewall' and fingerprint(read_file(root/'etc/pve/firewall/cluster.fw')) != plan['cluster_sha256']:
                    raise ValueError('cluster configuration changed since plan')
                atomic_write(destination, plan['content'].encode())
        if op == 'firewall':
            run(['pve-firewall', 'compile'])
            run(['systemctl', 'restart', 'pve-firewall.service'])
            run(['pve-firewall', 'status'])
        elif op == 'ssh':
            run(['sshd', '-t'])
            effective = run(['sshd', '-T'])
            validate_ssh_effective(effective)
            run(['systemctl', 'reload', 'ssh.service'])
        elif op == 'fail2ban':
            run(['fail2ban-client', '-t'])
            check_fail2ban_dump()
            run(['systemctl', 'restart', 'fail2ban.service'])
        elif op == 'crowdsec-observe':
            run(['systemctl', 'start', 'crowdsec.service'])
        # Never hold the transaction lock while waiting for systemd/sshd/PVE.
        # The independent watchdog must be able to restore files during a hang.
        with (transaction/'lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if time.time() >= state['deadline'] or (transaction/'rolled-back').exists():
                raise ValueError('Apply expired or rolled back during service verification')
            (transaction/'applied').touch()
    except BaseException:
        rollback(transaction)
        raise
    return {'status': 'pending_verification', 'transaction': str(transaction),
            'changes_applied': True, 'rollback_seconds': args.rollback_seconds,
            'verification': 'manual_attestation_required_not_automatic_access_check',
            'next': 'Verify NEW SSH key login and IPv4/IPv6 UI access from allowed sources, '
                    'and guest connectivity from another session, then commit before timeout.'}


def commit(transaction, verified):
    if verified != 'VERIFIED SSH UI IPV4 IPV6 AND GUESTS':
        raise ValueError('independent access and guest verification required')
    with (transaction/'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = json.loads((transaction/'state.json').read_text())
        if not (transaction/'applied').exists():
            raise ValueError('Apply has not completed; manual attestation cannot commit it')
        if (transaction/'rolled-back').exists() or time.time() >= state['deadline']:
            raise ValueError('transaction expired; audit again')
        (transaction/'committed').touch()


def transaction_path(value):
    path = Path(value)
    if path.parent != Path('/var/lib/proxmox-host') or not path.name.isdigit() or path.is_symlink():
        raise ValueError('invalid transaction path')
    info = path.stat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('transaction must be root-owned mode 0700')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('audit')
    plan = sub.add_parser('plan')
    plan.add_argument('operation', choices=['firewall', 'ssh', 'fail2ban', 'crowdsec-observe', 'sysctl-advice'])
    plan.add_argument('--admin', action='append', default=[])
    plan.add_argument('--spice', action='store_true')
    plan.add_argument('--dynamic-admin', action='store_true')
    ap = sub.add_parser('apply')
    ap.add_argument('plan', type=Path)
    ap.add_argument('--confirm', required=True)
    for flag in ('console-confirmed', 'rollback-confirmed', 'key-login-confirmed'):
        ap.add_argument('--'+flag, action='store_true')
    ap.add_argument('--rollback-seconds', type=int, default=180)
    for name in ('commit', '_rollback'):
        command = sub.add_parser(name)
        command.add_argument('transaction')
        if name == 'commit':
            command.add_argument('--verified', required=True)
    args = parser.parse_args()
    try:
        if args.action == 'audit':
            output = audit()
        elif args.action == 'plan':
            output = make_plan(audit(), args.operation, args.admin, args.spice, args.dynamic_admin)
        elif args.action == 'apply':
            if os.geteuid() != 0:
                raise ValueError('root required')
            with open('/run/proxmox-host.lock', 'a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                # A pending transaction cannot be superseded before verification/rollback.
                for directory in Path('/var/lib/proxmox-host').glob('[0-9]*'):
                    if not (directory/'committed').exists() and not (directory/'rolled-back').exists():
                        raise ValueError('pending transaction: verify or roll back first')
                output = apply(json.loads(read_file(args.plan)), args)
        else:
            if os.geteuid() != 0:
                raise ValueError('root required')
            transaction = transaction_path(args.transaction)
            if args.action == 'commit':
                commit(transaction, args.verified)
            else:
                rollback(transaction)
            output = {'status': args.action}
        print(json.dumps(output, indent=2, ensure_ascii=False))
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        parser.exit(1, str(error)+'\n')


if __name__ == '__main__':
    main()
