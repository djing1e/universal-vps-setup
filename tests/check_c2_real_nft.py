"""Run only via `unshare --net`; never change the caller's firewall."""
import os
import shutil
import subprocess

from test_c2_feed import C2Tests


def main():
    nft = shutil.which('nft')
    if not nft:
        raise SystemExit('nft is required')
    parent_ns = os.readlink('/proc/self/ns/net')
    # Namespace creation failure stops the test before any nft command runs.
    subprocess.run(['unshare', '--net', 'python3', __file__, parent_ns], check=True)


def check(parent_ns):
    assert os.readlink('/proc/self/ns/net') != parent_ns, 'network isolation required'
    nft = shutil.which('nft')
    fixture = C2Tests()
    fixture.setUp()
    try:
        (fixture.bin / 'nft').unlink()
        (fixture.bin / 'nft').symlink_to(nft)

        def command(*args):
            return subprocess.check_output([nft, *args], text=True)

        def rules():
            return command('-a', 'list', 'chain', 'ip', 'xtls_c2_feed', 'output')

        fixture.run_cli('install')
        assert 'xtls-c2-block' not in rules()
        fixture.run_cli('enable-block', answer='ENABLE-C2-BLOCK\n')
        fixture.run_cli('enable-block', answer='ENABLE-C2-BLOCK\n')
        assert rules().count('comment "xtls-c2-block"') == 1
        fixture.run_cli('update')
        assert rules().count('comment "xtls-c2-block"') == 1
        command('add rule ip xtls_c2_feed output counter comment "unrelated"')
        command('add rule ip xtls_c2_feed output ip daddr . tcp dport @c2_pairs counter drop comment "xtls-c2-block"')
        before = command('list', 'set', 'ip', 'xtls_c2_feed', 'c2_pairs')
        fixture.run_cli('disable-block')
        fixture.run_cli('disable-block')
        assert 'xtls-c2-block' not in rules()
        assert 'comment "unrelated"' in rules()
        assert before == command('list', 'set', 'ip', 'xtls_c2_feed', 'c2_pairs')
        # Heal the originally reported mismatch through both service entrypoints.
        for action in ['update', 'restore']:
            command('add rule ip xtls_c2_feed output ip daddr . tcp dport @c2_pairs counter drop comment "xtls-c2-block"')
            fixture.run_cli(action)
            assert 'xtls-c2-block' not in rules()
        # nft state disappears on boot; persisted mode/cache must reconstruct it.
        installed = fixture.root / 'usr/local/sbin/xtls-c2-feed'
        for mode in ['observe', 'block', 'observe']:
            if mode == 'block':
                fixture.run_cli('enable-block', answer='ENABLE-C2-BLOCK\n')
            else:
                fixture.run_cli('disable-block')
            command('delete', 'table', 'ip', 'xtls_c2_feed')
            fixture.run_cli('restore', script=installed)
            assert ('xtls-c2-block' in rules()) == (mode == 'block')
            assert (fixture.cache / 'mode').read_text().strip() == mode
        print('Real nft namespace checks passed')
    finally:
        fixture.doCleanups()


if __name__ == '__main__':
    import sys
    if len(sys.argv) == 1:
        main()
    elif len(sys.argv) == 2:
        check(sys.argv[1])
    else:
        raise SystemExit('Unexpected arguments')
