"""Run only inside a disposable network namespace (CI, as root)."""
import json
from pathlib import Path
import socket
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def nft(*args):
    return subprocess.check_output(['nft', *args], text=True)


with tempfile.TemporaryDirectory() as directory:
    d = Path(directory)
    script = d/'observer.sh'
    source = (ROOT/'modules/xtls-spamhaus-output.sh').read_text()
    source = source.replace('ROOT=/etc/xtls-spamhaus-output', 'ROOT='+str(d/'state'))
    source = source.replace('LOCK=/run/xtls-spamhaus-output.lock', 'LOCK='+str(d/'lock'))
    script.write_text(source)
    def enable():
        subprocess.run(['bash', str(script), 'diagnostics-enable'], check=True)
    enable()
    original_counters = {
        item['rule']['comment']: item['rule']
        for item in json.loads(nft('-j', '-a', 'list', 'chain', 'inet', 'xtls_spamhaus_out', 'output'))['nftables']
        if item.get('rule', {}).get('comment') in ('xtls-sh-out-v4', 'xtls-sh-out-v6')
    }
    # Simulate duplicate observation counters as well as legacy diagnostics.
    for version,family in [(4,'ip'),(6,'ip6')]:
        nft('add','rule','inet','xtls_spamhaus_out','output',family,'daddr',f'@v{version}',
            'counter','comment',f'"xtls-sh-out-v{version}"')
        nft('add','rule','inet','xtls_spamhaus_out','output',family,'daddr',f'@v{version}',
            'log','prefix',f'"XTLS-SH{version} "','comment',f'"xtls-sh-diag-v{version}"')
    enable()
    enable()
    rules=nft('-a','list','chain','inet','xtls_spamhaus_out','output')
    for version in (4,6):
        own=[line for line in rules.splitlines() if f'comment "xtls-sh-diag-v{version}"' in line]
        assert len(own)==1 and 'ct direction original' in own[0], rules
    counter_rows = [item['rule'] for item in json.loads(nft('-j', '-a', 'list', 'chain', 'inet', 'xtls_spamhaus_out', 'output'))['nftables']
                    if item.get('rule', {}).get('comment') in original_counters]
    assert len(counter_rows) == 2, counter_rows
    assert all(row == original_counters[row['comment']] for row in counter_rows), counter_rows
    assert ' drop' not in rules
    for version,family,address,af in [(4,'ip','127.0.0.1',socket.AF_INET),
                                      (6,'ip6','::1',socket.AF_INET6)]:
        nft('add','element','inet','xtls_spamhaus_out',f'v{version}',f'{{ {address} }}')
        for direction in ('original','reply'):
            nft('add','rule','inet','xtls_spamhaus_out','output','ct','direction',direction,
                family,'daddr',f'@v{version}','counter','comment',f'"test-{direction}-v{version}"')
        with socket.socket(af) as server:
            server.settimeout(3)
            server.bind((address,0))
            server.listen()
            with socket.socket(af) as client:
                client.settimeout(3)
                client.connect(server.getsockname())
                connection,_=server.accept()
                with connection:
                    connection.settimeout(3)
                    client.sendall(b'hello')
                    assert connection.recv(5)==b'hello'
                    connection.sendall(b'reply')
                    assert client.recv(5)==b'reply'
        obj=json.loads(nft('-j','list','chain','inet','xtls_spamhaus_out','output'))
        counts={}
        for item in obj['nftables']:
            rule=item.get('rule',{})
            for expression in rule.get('expr',[]):
                if 'counter' in expression:
                    counts[rule.get('comment')]=expression['counter']['packets']
        original=counts[f'test-original-v{version}'];reply=counts[f'test-reply-v{version}']
        assert original>0 and reply>0, counts
        assert counts[f'xtls-sh-out-v{version}']==original+reply, counts
        print(f'IPv{version}: original={original}, reply={reply}; counters include both, diagnostics original only')
    print('Real nft migration, repeat enable, IPv4/IPv6 conntrack direction: OK')
    # Exercise both modules in the same namespace, not just independent runs.
    from test_c2_feed import C2Tests
    observer_before = nft('-s', 'list', 'table', 'inet', 'xtls_spamhaus_out')
    fixture = C2Tests()
    fixture.setUp()
    try:
        (fixture.bin/'nft').unlink()
        (fixture.bin/'nft').symlink_to(shutil.which('nft'))
        fixture.run_cli('install')
        fixture.run_cli('enable-block', answer='ENABLE-C2-BLOCK\n')
        fixture.run_cli('update')
        fixture.run_cli('disable-block')
        fixture.run_cli('restore')
        assert observer_before == nft('-s', 'list', 'table', 'inet', 'xtls_spamhaus_out')
        c2_before = nft('-s', 'list', 'table', 'ip', 'xtls_c2_feed')
        enable()
        assert c2_before == nft('-s', 'list', 'table', 'ip', 'xtls_c2_feed')
        assert 'xtls-c2-block' not in nft('list','chain','ip','xtls_c2_feed','output')
        print('Cross-module coexistence: C2 transitions preserve observer; diagnostics preserve C2')
    finally:
        fixture.doCleanups()
