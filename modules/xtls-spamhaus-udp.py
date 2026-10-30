#!/usr/bin/env python3
"""Opt-in UDP DROP using existing Spamhaus OUTPUT CIDR sets. No TCP rules."""
import argparse
import contextlib
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tempfile

TABLE = 'xtls_spamhaus_out'
MARKERS = {f'xtls-sh-udp-drop-v{v}' for v in (4, 6)}


def _require_vps_host():
    import os as _os
    import subprocess as _subprocess
    from pathlib import Path as _Path
    _pve = _Path('/etc/pve').exists() or _Path('/usr/bin/pveversion').exists() or _os.uname().release.endswith('-pve')
    try:
        _pkg = _subprocess.run(['dpkg-query', '-W', '-f=${Status}', 'pve-manager'],
                               capture_output=True, timeout=3, text=True)
        _pve = _pve or (_pkg.returncode == 0 and _pkg.stdout == 'install ok installed')
    except (OSError, _subprocess.TimeoutExpired):
        raise SystemExit('Host detection unavailable; refusing node module')
    if _pve:
        raise SystemExit('BLOCKED: node module is not allowed on Proxmox Host')


def command(argv, batch=None):
    return subprocess.check_output(argv, input=batch, text=True, timeout=20)


class Guard:
    def __init__(self, root=Path('/etc/xtls-spamhaus-udp'),
                 lock=Path('/run/xtls-spamhaus-udp.lock'), runner=command):
        self.root, self.lockfile, self.run = root, lock, runner

    @contextlib.contextmanager
    def locked(self):
        _require_vps_host()
        with self.lockfile.open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def mode(self):
        try:
            value = (self.root/'mode').read_text().strip()
        except FileNotFoundError:
            return 'observe'
        if value not in ('observe', 'block'):
            raise ValueError('unknown saved UDP mode; manual review required')
        return value

    def save_mode(self, mode):
        _require_vps_host()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix='.mode-', dir=self.root)
        try:
            with os.fdopen(fd, 'w') as stream:
                stream.write(mode+'\n')
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.root/'mode')
        finally:
            Path(name).unlink(missing_ok=True)

    def snapshot(self):
        obj = json.loads(self.run(['nft','-j','-a','list','chain','inet',TABLE,'output']))
        return [item['rule'] for item in obj['nftables'] if 'rule' in item]

    def exemptions(self):
        path = self.root/'exemptions.txt'
        if path.is_symlink():
            raise ValueError('exemptions symlink requires manual review')
        # Explicit file required even when the operator chooses no exemptions.
        with path.open() as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError('exemption file too large')
        nets = {4: set(), 6: set()}
        for line in raw.splitlines():
            value = line.split('#',1)[0].strip()
            if not value:
                continue
            net = ipaddress.ip_network(value, strict=False)
            if net.prefixlen == 0:
                raise ValueError('default-route exemption is not allowed')
            nets[net.version].add(str(net))
        return nets

    def check_source_sets(self):
        for version in (4,6):
            obj = json.loads(self.run(['nft','-j','list','set','inet',TABLE,f'v{version}']))
            sets = [item['set'] for item in obj['nftables'] if 'set' in item]
            expected = 'ipv4_addr' if version == 4 else 'ipv6_addr'
            if len(sets) != 1 or sets[0].get('type') != expected or not sets[0].get('elem'):
                raise ValueError(f'Spamhaus IPv{version} set absent, empty or wrong type')

    def apply(self, enabled):
        _require_vps_host()
        nets = self.exemptions() if enabled else None
        if enabled:
            self.check_source_sets()
        rules = self.snapshot()
        lines = []
        for rule in rules:
            if rule.get('comment') in MARKERS:
                handle = rule.get('handle')
                if type(handle) is not int or handle < 0:
                    raise ValueError('cannot identify owned UDP rule')
                lines.append(f'delete rule inet {TABLE} output handle {handle}')
        if enabled:
            for version, family, kind in [(4,'ip','ipv4_addr'),(6,'ip6','ipv6_addr')]:
                name = f'xtls_sh_udp_allow{version}'
                # add set is idempotent for an existing set; all changes are atomic.
                lines += [f'add set inet {TABLE} {name} {{ type {kind}; flags interval; auto-merge; }}',
                          f'flush set inet {TABLE} {name}']
                if nets[version]:
                    lines.append(f'add element inet {TABLE} {name} {{ '+', '.join(sorted(nets[version]))+' }')
                lines.append(f'add rule inet {TABLE} output ct direction original meta l4proto udp '
                             f'{family} daddr @v{version} {family} daddr != @{name} '
                             f'counter drop comment "xtls-sh-udp-drop-v{version}"')
        if lines:
            batch = '\n'.join(lines)+'\n'
            self.run(['nft','-c','-f','-'], batch)
            self.run(['nft','-f','-'], batch)
        remaining = [rule for rule in self.snapshot() if rule.get('comment') in MARKERS]
        if len(remaining) != (2 if enabled else 0) or (enabled and {r['comment'] for r in remaining} != MARKERS):
            raise RuntimeError('UDP rule verification failed')

    def enable(self):
        with self.locked():
            # Rollback mode write failure to observation; never claim persisted block.
            self.apply(True)
            try:
                self.save_mode('block')
            except OSError:
                self.apply(False)
                raise
        print('Spamhaus UDP DROP enabled and persisted; original direction only')

    def disable(self):
        with self.locked():
            # Safe intent first, so boot restore can heal failed removal.
            self.save_mode('observe')
            self.apply(False)
        print('Spamhaus UDP DROP disabled and persisted')

    def restore(self):
        with self.locked():
            mode = self.mode()
            self.apply(mode == 'block')
        print('Spamhaus UDP mode restored:', mode)

    def status(self):
        with self.locked():
            saved = self.mode()
            rules = [r for r in self.snapshot() if r.get('comment') in MARKERS]
        print('Saved UDP mode:', saved)
        print('Live owned UDP DROP rules:', len(rules))
        for rule in rules:
            counters = [e['counter'] for e in rule.get('expr',[]) if 'counter' in e]
            print(rule['comment'], json.dumps(counters))


def main():
    _require_vps_host()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['enable-block','disable-block','restore','status'])
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, 'root required\n')
    guard = Guard()
    action = {'enable-block':guard.enable,'disable-block':guard.disable,
              'restore':guard.restore,'status':guard.status}[args.action]
    try:
        action()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        parser.exit(1, 'ERROR: '+str(exc)+'\n')


if __name__ == '__main__':
    _require_vps_host()

    main()
