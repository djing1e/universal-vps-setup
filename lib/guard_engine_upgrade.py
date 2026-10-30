#!/usr/bin/env python3
"""Narrow, opt-in engine-only update of the known Auto Abuse Guard observer."""
import argparse
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import uuid

from vps_inventory import probe, os_identity
from module_registry import Registration

POLICY = Path(__file__).with_name('guard_engine_policy.json')
ENGINE = '/usr/local/sbin/xtls-auto-abuse-guard'
SERVICE = 'xtls-auto-abuse-guard.service'
TIMER = 'xtls-auto-abuse-guard.timer'
CONFIRM = 'UPDATE-GUARD-ENGINE'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_regular(path, limit=2*1024*1024):
    # Refuse links in every path component, including alternate parent layouts.
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise ValueError('symlink requires manual review: '+str(ancestor))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('regular file with one hard link required: '+str(path))
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('root-owned, non-writable by group/others file required: '+str(path))
        raw = stream.read(limit+1)
    if len(raw) > limit:
        raise ValueError('file exceeds limit: '+str(path))
    return raw, info


def atomic_write(path, raw, mode):
    fd, tmp = tempfile.mkstemp(prefix='.'+path.name+'-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchown(stream.fileno(), 0, 0)
            os.fchmod(stream.fileno(), mode)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(tmp).unlink(missing_ok=True)


class Upgrade:
    def __init__(self, policy, root=Path('/'), runner=probe, registration=None):
        self.policy, self.root, self.runner = policy, root, runner
        self.registration = registration if registration is not None else Registration(root)
        self.engine = root/ENGINE.lstrip('/')
        self.backups = root/'var/lib/xtls-safe-upgrade'
        self.lock = root/'run/xtls-auto-abuse-guard-install.lock'

    def command(self, *args):
        result = self.runner(['systemctl', *args], timeout=40)
        if result['status'] != 'ok':
            raise RuntimeError('systemctl '+args[0]+' failed ('+result['status']+')')
        return result.get('output', '')

    def state(self, name):
        output = self.command('show', '--no-pager', name,
                              '--property=LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths,NeedDaemonReload')
        values = dict(line.split('=',1) for line in output.splitlines() if '=' in line)
        expected = '/etc/systemd/system/'+name
        if (values.get('LoadState') != 'loaded' or values.get('FragmentPath') != expected or
                values.get('DropInPaths') != '' or values.get('NeedDaemonReload') != 'no' or
                not values.get('SubState')):
            raise ValueError('unknown effective unit: '+name)
        allowed = ('active','inactive') if name == TIMER else ('active','inactive','activating')
        if values.get('ActiveState') not in allowed:
            raise ValueError('unhealthy/unknown unit state: '+name)
        if name == TIMER and values.get('UnitFileState') not in ('enabled','disabled'):
            raise ValueError('unknown timer enablement')
        return values

    def check(self, candidate):
        identity = os_identity(self.root)
        props = identity.get('properties', {})
        if (props.get('ID'), props.get('VERSION_ID')) not in (('debian','13'),('ubuntu','24.04')):
            raise ValueError('unsupported or unknown OS')
        raw, _ = read_regular(candidate)
        if digest(raw) != self.policy['target_sha256']:
            raise ValueError('candidate fingerprint does not match pinned release')
        compile(raw, str(candidate), 'exec')
        current, info = read_regular(self.engine)
        current_hash = digest(current)
        if current_hash not in self.policy['accepted_current_sha256']:
            raise ValueError('unknown installed engine; update refused')
        if stat.S_IMODE(info.st_mode) != 0o755 or info.st_gid != 0:
            raise ValueError('unexpected installed executable permissions')
        unit_bytes = {}
        for name, expected in self.policy['units'].items():
            path = self.root/'etc/systemd/system'/name
            data, _ = read_regular(path)
            if digest(data) != expected:
                raise ValueError('custom/unknown unit file: '+name)
            unit_bytes[name] = data
        if self.registration.release['resources'][ENGINE]['sha256']!=self.policy['target_sha256']:
            raise ValueError('registry target and update policy disagree')
        receipt = self.registration.snapshot()
        states = {name:self.state(name) for name in (SERVICE,TIMER)}
        return {'component':'auto-abuse-guard', 'changes_applied':False,
                'status':'noop' if current_hash == self.policy['target_sha256'] else 'ready_for_explicit_apply',
                'current_sha256':current_hash, 'target_sha256':self.policy['target_sha256'],
                'target_revision':self.policy['target_revision'],
                'registry_state':'registered_matches' if receipt is not None else 'unregistered',
                'timer_active':states[TIMER]['ActiveState']=='active',
                'timer_enabled':states[TIMER]['UnitFileState'],
                'verification':'service_scan' if states[TIMER]['ActiveState']=='active' else 'static_only'}, raw, current, unit_bytes

    def verify_scan(self):
        # A failed candidate can exhaust systemd's start budget. Clear only this
        # observer's failure/start-limit before testing either engine.
        reset = self.runner(['systemctl','reset-failed',SERVICE], timeout=40)
        if reset['status'] != 'ok':
            # systemd may garbage-collect an inactive unit with no active timer.
            # An unloaded unit has no start-rate state to clear. Accept only this
            # exact diagnostic and revalidate the known inactive unit before start.
            unloaded = (reset['status']=='error' and
                        f'Unit {SERVICE} not loaded.' in reset.get('output',''))
            if not unloaded:
                raise RuntimeError('systemctl reset-failed failed ('+reset['status']+')')
            if self.state(SERVICE)['ActiveState'] != 'inactive':
                raise RuntimeError('reset-failed fallback requires known inactive unit')
        self.command('start', SERVICE)
        result = self.command('show','--no-pager',SERVICE,'--property=Result,ExecMainStatus')
        values = dict(line.split('=',1) for line in result.splitlines() if '=' in line)
        if values.get('Result') != 'success' or values.get('ExecMainStatus') != '0':
            raise RuntimeError('observer scan failed')

    def verify_timer(self, report):
        state = self.state(TIMER)
        if (state['ActiveState'] != ('active' if report['timer_active'] else 'inactive') or
                state['UnitFileState'] != report['timer_enabled']):
            raise RuntimeError('timer state was not preserved')

    @contextlib.contextmanager
    def locked(self):
        fd = os.open(self.lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        with os.fdopen(fd, 'a') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
                raise ValueError('unsafe installer lock')
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield

    def unresolved(self):
        if self.backups.is_symlink():
            raise ValueError('backup directory symlink requires review')
        if not self.backups.exists():
            return
        info = self.backups.stat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('unsafe backup directory ownership/permissions')
        # An interrupted transaction must be examined, never silently overwritten.
        for directory in self.backups.iterdir():
            record = directory/'transaction.json'
            if not record.is_file() or directory.is_symlink() or record.is_symlink():
                raise ValueError('unrecognized backup entry requires manual review')
            value = json.loads(read_regular(record, 16384)[0])
            if not isinstance(value, dict) or value.get('status') not in ('committed','rolled_back'):
                raise ValueError('unfinished transaction requires manual recovery: '+str(directory))

    def apply(self, candidate):
        if os.geteuid() != 0:
            raise ValueError('root required')
        with self.locked():
            self.unresolved()
            report, raw, old, units = self.check(candidate)
            old_receipt = self.registration.snapshot()
            if report['status'] == 'noop':
                return report
            # Back up before stopping anything. Never overwrite unit files or history.
            if self.backups.is_symlink():
                raise ValueError('backup directory symlink requires review')
            self.backups.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory = self.backups/(datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex)
            directory.mkdir(mode=0o700)
            atomic_write(directory/'engine', old, 0o700)
            if old_receipt is not None: atomic_write(directory/'registry-before.json', old_receipt, 0o600)
            for name,data in units.items():
                atomic_write(directory/name, data, 0o600)
            record = dict(report, status='pending', registry_before_present=old_receipt is not None)
            def save(status):
                record['status'] = status
                atomic_write(directory/'transaction.json', json.dumps(record,indent=2).encode()+b'\n', 0o600)
            save('pending')
            replaced = False
            new_receipt = None
            try:
                self.command('stop', TIMER)
                self.command('stop', SERVICE)
                # Fresh ownership/state/content check after quiescing only the observer.
                fresh, _, current, _ = self.check(candidate)
                if current != old or fresh['timer_enabled'] != report['timer_enabled']:
                    raise ValueError('state changed during preparation; update refused')
                replaced = True
                atomic_write(self.engine, raw, 0o755)
                if report['timer_active']:
                    self.verify_scan()
                if read_regular(self.engine)[0] != raw:
                    raise RuntimeError('post-update fingerprint verification failed')
                if report['timer_active']:
                    self.command('start', TIMER)
                self.verify_timer(report)
                new_receipt = self.registration.prepare('managed_update')
                self.registration.replace(old_receipt,new_receipt)
                if self.registration.snapshot()!=new_receipt: raise RuntimeError('registry verification failed')
                save('committed')
                return dict(report, status='updated', changes_applied=True, backup=str(directory))
            except Exception as failure:
                try:
                    # A timed-out systemctl client does not imply its unit has stopped.
                    self.command('stop', TIMER)
                    self.command('stop', SERVICE)
                    if replaced:
                        live = read_regular(self.engine)[0]
                        if live == raw:
                            atomic_write(self.engine, old, 0o755)
                        elif live != old:
                            raise ValueError('engine changed externally; refusing blind rollback')
                    if read_regular(self.engine)[0] != old:
                        raise RuntimeError('old engine not restored')
                    self.registration.restore(old_receipt,new_receipt)
                    if report['timer_active']:
                        if replaced:
                            self.verify_scan()
                        self.command('start', TIMER)
                    self.verify_timer(report)
                    save('rolled_back')
                except Exception as recovery:
                    save('recovery_required')
                    raise RuntimeError('automatic rollback incomplete; backup: '+str(directory)+'; '+str(recovery)) from failure
                raise RuntimeError('update failed; old engine and timer restored; backup: '+str(directory)+'; '+str(failure)) from failure


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['check','apply'])
    parser.add_argument('--candidate', required=True, type=Path)
    parser.add_argument('--confirm')
    args = parser.parse_args()
    try:
        policy = json.loads(POLICY.read_text())
        updater = Upgrade(policy)
        if args.action == 'apply':
            if args.confirm != CONFIRM:
                raise ValueError('explicit --confirm '+CONFIRM+' required')
            result = updater.apply(args.candidate)
        else:
            result = updater.check(args.candidate)[0]
        print(json.dumps(result,ensure_ascii=False,indent=2))
    except (OSError, ValueError, RuntimeError, SyntaxError) as exc:
        parser.exit(1,'Upgrade refused: '+str(exc)+'\n')


if __name__ == '__main__':
    main()
