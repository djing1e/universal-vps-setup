"""Run in a disposable netns; use loopback fixtures, never a public destination."""
import contextlib
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('udp_real',ROOT/'modules/xtls-spamhaus-udp.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


def nft(*args):
    return subprocess.check_output(['nft',*args],text=True)


def packets():
    obj=json.loads(nft('-j','list','chain','inet','xtls_spamhaus_out','output'))
    return {r['comment']:sum(e['counter']['packets'] for e in r.get('expr',[]) if 'counter' in e)
            for entry in obj['nftables'] if (r:=entry.get('rule',{})).get('comment')}


nft('add','table','inet','xtls_spamhaus_out')
for v,kind,address in [(4,'ipv4_addr','127.0.0.1'),(6,'ipv6_addr','::1')]:
    nft(f'add set inet xtls_spamhaus_out v{v} {{ type {kind}; flags interval; elements = {{ {address} }}; }}')
nft('add chain inet xtls_spamhaus_out output { type filter hook output priority -18; policy accept; }')
nft('add rule inet xtls_spamhaus_out output counter comment "preserve-counter"')
with tempfile.TemporaryDirectory() as directory:
    root=Path(directory)
    (root/'exemptions.txt').write_text('# explicitly reviewed empty fixture\n')
    guard=module.Guard(root,root/'lock')
    with contextlib.ExitStack() as stack:
        pairs=[]
        for af,address in [(socket.AF_INET,'127.0.0.1'),(socket.AF_INET6,'::1')]:
            server=stack.enter_context(socket.socket(af,socket.SOCK_DGRAM))
            client=stack.enter_context(socket.socket(af,socket.SOCK_DGRAM))
            server.settimeout(.3);client.settimeout(.3)
            server.bind((address,0));client.connect(server.getsockname())
            client.send(b'initial');data,peer=server.recvfrom(64)
            assert data==b'initial'
            server.sendto(b'initial-reply',peer);assert client.recv(64)==b'initial-reply'
            pairs.append((af,address,server,client,peer))
        guard.enable();guard.enable()
        for af,address,server,client,peer in pairs:
            version=4 if af==socket.AF_INET else 6
            previous=packets()[f'xtls-sh-udp-drop-v{version}']
            try:
                client.send(b'must-drop')
            except PermissionError:
                # Linux may report a local OUTPUT DROP directly as EPERM.
                # Still require receiver timeout AND the DROP counter increase.
                pass
            try:
                server.recvfrom(64)
                raise AssertionError('original UDP was not dropped')
            except socket.timeout:
                pass
            assert packets()[f'xtls-sh-udp-drop-v{version}']>previous
            server.sendto(b'reply-must-pass',peer)
            assert client.recv(64)==b'reply-must-pass'
            with socket.socket(af) as listener,socket.socket(af) as tcp:
                listener.settimeout(1);tcp.settimeout(1)
                listener.bind((address,0));listener.listen()
                tcp.connect(listener.getsockname())
                connection,_=listener.accept();connection.close()
        # Explicit exemptions permit original UDP even though DROP sets match it.
        (root/'exemptions.txt').write_text('127.0.0.1\n::1\n')
        guard.restore()
        for _,_,server,client,_ in pairs:
            client.send(b'exempt');assert server.recvfrom(64)[0]==b'exempt'
        (root/'exemptions.txt').write_text('# no exemptions\n')
        guard.disable();guard.restore()
        for _,_,server,client,_ in pairs:
            client.send(b'observe');assert server.recvfrom(64)[0]==b'observe'
        guard.enable()
        # Counter rules and source sets survive the block/observe transitions.
        assert packets()['preserve-counter']>0
        assert len([k for k in packets() if k.startswith('xtls-sh-udp-drop')])==2
        nft('flush set inet xtls_spamhaus_out v4')
        try:
            guard.enable()
            raise AssertionError('empty source set accepted')
        except ValueError:
            pass
        assert guard.mode()=='block'
        guard.disable()
        print('Real UDP DROP IPv4/IPv6, reply/TCP pass, exemptions, restore and safe disable: OK')
