#!/usr/bin/env python3
"""Read-only VPS inventory. No install/update actions, network requests or telemetry."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import time

SCHEMA_VERSION = 1
MAX_OUTPUT = 32768
UNITS = (
    'ssh.service', 'docker.service', 'containerd.service',
    'caddy.service', 'nginx.service', 'haproxy.service',
    'postgresql.service', 'redis-server.service', 'crowdsec.service',
    'crowdsec-firewall-bouncer.service', 'fail2ban.service', 'ufw.service',
    'systemd-resolved.service', 'nextdns-doh.service', 'netbird.service',
    'vpsguard-firewall.service', 'as-blacklist-update.timer',
    'threat-blacklist-update.timer', 'xtls-c2-feed-restore.service',
    'xtls-c2-feed-update.timer', 'xtls-udp-abuse-restore.service',
    'xtls-spamhaus-output-restore.service', 'xtls-spamhaus-output-update.timer',
    'xtls-auto-abuse-guard.service', 'xtls-auto-abuse-guard.timer',
    'xtls-spamhaus-udp-restore.service', 'xtls-smtp25-guard-restore.service',
    'xtls-portscan-observe-restore.service',
)
SAVED_MODES = {
    '/etc/xtls-c2-feed/mode': ('observe', 'block'),
    '/etc/xtls-spamhaus-udp/mode': ('observe', 'block'),
    '/etc/xtls-spamhaus-output/diagnostics-mode': ('enabled', 'disabled'),
    '/etc/xtls-smtp25-guard/mode': ('observe', 'block', 'disabled'),
    '/etc/xtls-portscan-observe/enabled': ('enabled', 'disabled'),
}
PROBES = {
    'pve_package': ['dpkg-query', '-W', '-f=${Status}', 'pve-manager'],
    'pve_version': ['pveversion'],
    'containers': ['docker', '--host', 'unix:///var/run/docker.sock', 'ps', '-a', '--format',
                   '{"id":{{json .ID}},"name":{{json .Names}},"image":{{json .Image}},"state":{{json .State}}}'],
    'nft_tables': ['nft', 'list', 'tables'],
    'ipset_names': ['ipset', 'list', '-name'],
    'ufw': ['ufw', 'status'],
    'dns': ['resolvectl', 'dns'],
    'dns_domains': ['resolvectl', 'domain'],
    'ipv4_routes': ['ip', '-j', '-4', 'route', 'show'],
    'ipv6_routes': ['ip', '-j', '-6', 'route', 'show'],
    'links': ['ip', '-j', 'link', 'show'],
    'network_tuning': ['sysctl', 'net.core.default_qdisc',
                       'net.ipv4.tcp_congestion_control', 'net.netfilter.nf_conntrack_max'],
    'docker_version': ['docker', '--version'],
}


def probe(argv, timeout=5, limit=MAX_OUTPUT):
    """Fixed argv only; cap bytes during reading and terminate hung command groups."""
    started = time.monotonic()
    try:
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, start_new_session=True,
                                 env=dict(os.environ, LC_ALL='C', SYSTEMD_PAGER='cat'))
    except FileNotFoundError:
        return {'status': 'unavailable'}
    except OSError:
        return {'status': 'error', 'detail': 'cannot start probe'}
    output = bytearray()
    status = None
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        try:
            while selector.get_map():
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    status = 'timeout'
                    break
                for key, _ in selector.select(min(remaining, .2)):
                    chunk = os.read(key.fileobj.fileno(), min(4096, limit + 1 - len(output)))
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(chunk)
                        if len(output) > limit:
                            status = 'limited'
                            break
                if status:
                    break
            if not status:
                try:
                    child.wait(timeout=max(.01, timeout-(time.monotonic()-started)))
                except subprocess.TimeoutExpired:
                    status = 'timeout'
        finally:
            if status:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            child.wait()
            child.stdout.close()
    return {'status': status or ('ok' if child.returncode == 0 else 'error'),
            'returncode': child.returncode,
            'output': bytes(output[:limit]).decode('utf-8', 'replace')}


def unit_state(name, runner=probe):
    result = runner(['systemctl', 'show', '--no-pager', name,
                     '--property=LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths'])
    if result['status'] != 'ok':
        return {'status': 'unknown', 'probe': result}
    fields = dict(line.split('=', 1) for line in result.get('output', '').splitlines() if '=' in line)
    if fields.get('LoadState') == 'not-found':
        return {'status': 'absent', 'properties': fields}
    if fields.get('LoadState') != 'loaded':
        return {'status': 'unknown', 'properties': fields}
    if not all(fields.get(key) for key in ('ActiveState', 'SubState')):
        return {'status': 'unknown', 'properties': fields}
    return {'status': 'observed', 'properties': fields}


def file_fingerprint(path, expected, max_bytes=2*1024*1024):
    """Content equality is not proof of ownership or permission to update."""
    try:
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            return {'status': 'unknown', 'reason': 'symlink_requires_review'}
        if not stat.S_ISREG(mode):
            return {'status': 'unknown', 'reason': 'not_a_regular_file'}
        with path.open('rb') as stream:
            raw = stream.read(max_bytes + 1)
    except FileNotFoundError:
        return {'status': 'absent'}
    except OSError:
        return {'status': 'unknown', 'reason': 'unreadable'}
    if len(raw) > max_bytes:
        return {'status': 'unknown', 'reason': 'file_too_large'}
    digest = hashlib.sha256(raw).hexdigest()
    return {'status': 'known_content' if digest in expected else 'custom_or_unknown',
            'sha256': digest, 'ownership': 'not_established'}


def saved_mode(path, allowed):
    """Read persisted intent only; never execute a module or infer live filtering."""
    try:
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            return {'status': 'unknown', 'reason': 'not_a_regular_file'}
        with path.open('rb') as stream:
            raw = stream.read(257)
    except FileNotFoundError:
        return {'status': 'absent'}
    except OSError:
        return {'status': 'unknown', 'reason': 'unreadable'}
    if len(raw) > 256:
        return {'status': 'unknown', 'reason': 'file_too_large'}
    value = raw.decode('ascii', 'replace').strip()
    if value not in allowed:
        return {'status': 'unknown', 'reason': 'unrecognized_mode'}
    return {'status': 'observed', 'value': value, 'scope': 'saved_only'}


def os_identity(root):
    fields = {}
    try:
        with (root/'etc/os-release').open() as stream:
            raw = stream.read(16384)
        for line in raw.splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                if key in ('ID', 'VERSION_ID', 'VERSION_CODENAME'):
                    fields[key] = value.strip('"\'')
    except OSError:
        pass
    return {'status': 'observed' if fields else 'unknown', 'properties': fields}


def registration_observation(root):
    try:
        from module_registry import inspect
        return {'auto-abuse-guard': inspect(root)}
    except (ImportError,OSError,ValueError,TypeError,KeyError):
        return {'auto-abuse-guard': {'status':'unknown','reason':'registry_catalog_unavailable',
                                   'changes_applied':False,'automatic_update':False}}


def collect(root=Path('/'), runner=probe, manifest=None):
    if manifest is None:
        manifest = json.loads(Path(__file__).with_name('inventory_manifest.json').read_text())
    files = {item['path']: file_fingerprint(root/item['path'].lstrip('/'), item['sha256'])
             for item in manifest['files']}
    # Do not turn a failed/permission-denied probe into an absent component.
    units = {name: unit_state(name, runner) for name in UNITS}
    observations = {}
    for name, argv in PROBES.items():
        docker = units['docker.service']
        if name == 'containers' and (docker['status'] != 'observed' or
                                     docker.get('properties', {}).get('ActiveState') != 'active'):
            observations[name] = {'status': 'unknown', 'detail': 'Docker not confirmed active; daemon query skipped'}
        else:
            observations[name] = runner(argv)
    pve_markers = (root/'etc/pve').exists() or (root/'usr/bin/pveversion').exists()
    package = observations['pve_package']
    version = observations['pve_version']
    installed = package.get('status') == 'ok' and package.get('output', '').strip() == 'install ok installed'
    version_ok = version.get('status') == 'ok' and version.get('output', '').startswith('pve-manager/')
    profile = 'proxmox' if installed and version_ok else ('proxmox_uncertain' if installed or version_ok or pve_markers or os.uname().release.endswith('-pve') else 'vps')
    if profile == 'vps' and (package.get('status') not in ('ok', 'error') or (package.get('status') == 'error' and package.get('returncode') != 1)):
        profile = 'unknown'
    pve = None
    if profile != 'vps':
        try:
            from .proxmox_host import audit
        except ImportError:
            from proxmox_host import audit
        pve = audit(root, runner)
    return {
        'host_profile': profile, 'proxmox': pve,
        'schema_version': SCHEMA_VERSION,
        'mode': 'audit', 'changes_applied': False,
        'os': os_identity(root), 'kernel': os.uname().release,
        'modules': files, 'services': units, 'probes': observations,
        'component_registry': registration_observation(root),
        'saved_modes': {path: saved_mode(root/path.lstrip('/'), allowed)
                        for path, allowed in SAVED_MODES.items()},
        'update_gate': 'manual_review_required',
        'limitations': [
            'No automatic update or ownership inference; known hashes only identify content.',
            'Probe errors, missing tools and output limits leave state unknown.',
            'No compose files, container environments, access logs or credentials are read.',
            'Snapshot is not atomic; no health or rollback guarantee is implied.',
            'Saved modes describe intent only, not live firewall enforcement.',
            'Network probe output may contain private topology; review before sharing.',
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['audit'])
    parser.parse_args()
    print(json.dumps(collect(), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
