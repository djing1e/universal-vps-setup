#!/usr/bin/env python3
"""Destructive Guard-only integration fixture: explicit disposable VM, real systemd."""
import argparse
import copy
import fcntl
import json
import os
from pathlib import Path
import socket
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'lib'))
import guard_engine_upgrade as upgrade

PHRASE = 'TEST-VM-GUARD-UPGRADE'


def require_test_host(hostname, confirmation):
    if hostname != 'vm1-xtlspro' or confirmation != PHRASE:
        raise ValueError('only explicitly confirmed disposable vm1-xtlspro is allowed')
    if os.geteuid() != 0:
        raise ValueError('root required')
    if Path('/proc/1/comm').read_text().strip() != 'systemd':
        raise ValueError('real systemd must be PID 1')


def fixture_policy(policy, old, target):
    # In-memory test policy only. The production policy file is never changed.
    value = copy.deepcopy(policy)
    value['target_sha256'] = upgrade.digest(target)
    value['accepted_current_sha256'] = [upgrade.digest(old), upgrade.digest(target)]
    return value


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(confirmation):
    require_test_host(socket.gethostname(), confirmation)
    policy = json.loads(upgrade.POLICY.read_text())
    guard = upgrade.Upgrade(policy)
    baseline, original, _, units = guard.check(guard.engine)
    require(baseline['status']=='noop', 'install current release before running fixture')
    require(baseline['timer_active'] and baseline['timer_enabled']=='enabled',
            'fixture requires initially enabled/active Guard timer')
    for name in ('docker.service','remnanode.service'):
        result = upgrade.probe(['systemctl','show','--no-pager',name,'--property=ActiveState'])
        require(result['status']=='ok' and 'ActiveState=active' not in result.get('output',''),
                'active or unknown application service: '+name)
    require(not Path('/opt/remnanode').exists() and not Path('/var/log/remnanode/access.log').exists(),
            'Remnanode paths found: refuse disposable-VM fixture')
    lockfd = os.open('/run/xtls-guard-systemd-test.lock', os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW, 0o600)
    with os.fdopen(lockfd,'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        directory = Path(tempfile.mkdtemp(prefix='xtls-guard-systemd-test.', dir='/root'))
        print('TEST_ARTIFACTS='+str(directory), flush=True)
        upgrade.atomic_write(directory/'original-engine', original, 0o700)
        upgrade.atomic_write(directory/'original-state.json', json.dumps(baseline,indent=2).encode()+b'\n',0o600)
        for name, raw in units.items():
            upgrade.atomic_write(directory/name, raw, 0o600)
        # Comments force a different hash while retaining the exact observer code.
        old = original+b'\n# Disposable VM fixture: previous engine\n'
        good = original+b'\n# Disposable VM fixture: next engine\n'
        bad = b'#!/usr/bin/env python3\nraise SystemExit(73)\n'
        known = {upgrade.digest(raw) for raw in (original,old,good,bad)}
        candidate = directory/'candidate.py'
        guard.backups = directory/'transactions'
        results = []

        def stage_old():
            with guard.locked():
                guard.command('stop',upgrade.TIMER)
                guard.command('stop',upgrade.SERVICE)
                live = upgrade.read_regular(guard.engine)[0]
                require(upgrade.digest(live) in known, 'external engine change; refusing fixture replacement')
                upgrade.atomic_write(guard.engine,old,0o755)
                guard.verify_scan()

        def set_candidate(raw):
            upgrade.atomic_write(candidate,raw,0o600)
            guard.policy = fixture_policy(policy,old,raw)

        try:
            # 1: real replacement, both ExecStarts and active timer restored.
            stage_old()
            guard.command('start',upgrade.TIMER)
            set_candidate(good)
            result = guard.apply(candidate)
            require(result['status']=='updated', 'successful replacement did not update')
            require(guard.engine.read_bytes()==good, 'candidate bytes differ')
            record = json.loads((Path(result['backup'])/'transaction.json').read_text())
            require(record['status']=='committed', 'transaction not committed')
            results.append('PASS successful update + real systemd scans + active timer')
            print(results[-1],flush=True)

            # 2: syntactically valid, pinned test candidate fails under systemd.
            stage_old()
            guard.command('start',upgrade.TIMER)
            set_candidate(bad)
            try:
                guard.apply(candidate)
                raise RuntimeError('bad candidate unexpectedly succeeded')
            except RuntimeError as error:
                require('old engine and timer restored' in str(error), str(error))
            require(guard.engine.read_bytes()==old,'rollback did not restore old engine')
            guard.verify_timer({'timer_active':True,'timer_enabled':'enabled'})
            require(any(json.loads(p.read_text()).get('status')=='rolled_back'
                        for p in guard.backups.glob('*/transaction.json')), 'rollback record missing')
            results.append('PASS intentional exit 73 + automatic rollback + old scan + active timer')
            print(results[-1],flush=True)

            # 3: preserve actual disabled/inactive state; no enable/start by apply.
            stage_old()
            guard.command('disable',upgrade.TIMER)
            set_candidate(good)
            result = guard.apply(candidate)
            require(result['status']=='updated' and result['verification']=='static_only',
                    'disabled timer update did not use static verification')
            guard.verify_timer({'timer_active':False,'timer_enabled':'disabled'})
            results.append('PASS disabled/inactive timer preserved')
            print(results[-1],flush=True)

            # 4: a child exits immediately after the real timer stop. Its pending
            # record/lock release persist; a subsequent real apply must refuse.
            stage_old()
            guard.command('enable',upgrade.TIMER)
            guard.command('start',upgrade.TIMER)
            set_candidate(good)
            pid = os.fork()
            if pid == 0:
                real_runner = guard.runner
                def interrupted_runner(argv, **kwargs):
                    result = real_runner(argv, **kwargs)
                    if argv==['systemctl','stop',upgrade.TIMER] and result['status']=='ok':
                        os._exit(91)
                    return result
                guard.runner = interrupted_runner
                try:
                    guard.apply(candidate)
                except Exception as error:
                    os.write(2,('child error: '+str(error)+'\n').encode())
                os._exit(92)
            _, status = os.waitpid(pid,0)
            require(os.waitstatus_to_exitcode(status)==91,'interruption checkpoint not reached')
            before = guard.engine.read_bytes()
            try:
                guard.apply(candidate)
                raise RuntimeError('pending transaction was accepted')
            except ValueError as error:
                require('unfinished transaction' in str(error),str(error))
            require(guard.engine.read_bytes()==before,'blocked apply changed engine')
            pending = [p.parent for p in guard.backups.glob('*/transaction.json')
                       if json.loads(p.read_text()).get('status')=='pending']
            require(len(pending)==1,'expected one interrupted transaction')
            # Archive the interrupted record separately; do not forge a commit.
            pending[0].rename(directory/'interrupted-transaction')
            results.append('PASS real child interruption + pending blocks next apply')
            print(results[-1],flush=True)
        finally:
            guard.command('stop',upgrade.TIMER)
            guard.command('stop',upgrade.SERVICE)
            live = upgrade.read_regular(guard.engine)[0]
            require(upgrade.digest(live) in known,
                    'RESTORE REFUSED: external engine change; inspect '+str(directory))
            upgrade.atomic_write(guard.engine,original,0o755)
            for name, raw in units.items():
                require(upgrade.read_regular(Path('/etc/systemd/system')/name)[0]==raw,
                        'unit changed externally: '+name)
            guard.policy = policy
            guard.verify_scan()
            guard.command('enable',upgrade.TIMER)
            guard.command('start',upgrade.TIMER)
            guard.verify_timer(baseline)
            require(guard.engine.read_bytes()==original,'final engine restore failed')
            print('RESTORE PASS: original release + unchanged units + enabled/active timer',flush=True)
        (directory/'results.json').write_text(json.dumps(results,indent=2)+'\n')
        return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--confirm',required=True)
    args = parser.parse_args()
    try:
        run(args.confirm)
    except (OSError,ValueError,RuntimeError) as error:
        parser.exit(1,'TEST FAILED: '+str(error)+'\n')


if __name__=='__main__':
    main()
