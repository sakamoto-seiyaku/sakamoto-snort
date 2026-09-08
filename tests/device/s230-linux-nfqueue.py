#!/usr/bin/env python3
"""Real Linux Product acceptance; invoke inside a disposable user/net namespace."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--artifact', type=Path, required=True)
parser.add_argument('--vppctl', type=Path, required=True)
parser.add_argument('--policy-client', type=Path, default=ROOT/'build-output/s230-policy')
args = parser.parse_args()
args.output = args.output.resolve()
args.artifact = args.artifact.resolve()
args.output.mkdir(parents=True, exist_ok=False)
env = dict(os.environ, LD_LIBRARY_PATH=str(args.artifact/'lib'))

def command(*argv, check=True):
    p = subprocess.run(list(map(str, argv)), env=env, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
    if check and p.returncode:
        raise RuntimeError(p.stdout)
    return p.stdout

def save(path, text):
    path.write_text(text)
    return text

def rows(text, prefix):
    return [dict(x.split('=', 1) for x in line.split()[1:] if '=' in x)
            for line in text.splitlines() if line.startswith(prefix)]

def queue_bind(queue):
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12) as s:
        s.bind((0, 0)); s.settimeout(2)
        payload = struct.pack('!BBH', 0, 0, queue)
        payload += struct.pack('HH', 8, 1) + struct.pack('!BBH', 1, 0, 2)
        s.send(struct.pack('IHHII', 16+len(payload), 0x302, 5, 1, 0)+payload)
        reply = s.recv(4096)
        assert struct.unpack_from('H', reply, 4)[0] == 2
        return struct.unpack_from('i', reply, 16)[0]

result = dict(status='HOLD', started_ns=time.time_ns(), cases=[], generations=[])
save(args.output/'kernel.txt', command('uname', '-a')+command('id')+
     'netns='+os.readlink('/proc/self/ns/net')+'\n')
assert os.getuid() == 0
uid_map = Path('/proc/self/uid_map').read_text().split()
assert len(uid_map) == 3 and uid_map[0] == '0' and uid_map[1] != '0' and uid_map[2] == '1', 'run in a rootless user/network namespace'
save(args.output/'uid-map.txt', ' '.join(uid_map)+'\n')
assert 'product.host.evidence=OFF' in (args.artifact/'product-vpp-artifact.properties').read_text()
result['artifact_manifest_sha256'] = hashlib.sha256((args.artifact/'product-vpp-artifact.properties').read_bytes()).hexdigest()
command('ip', 'link', 'set', 'lo', 'up')
for i in range(1, 9):
    command('ip', '-6', 'addr', 'add', f'fd20:6230::{i}/128', 'dev', 'lo', 'nodad')

try:
    for family in (4, 6):
        for protocol in (17, 6):
            coverage = set()
            for attempt in range(32):
                index = len(result['generations'])
                generation = 23010+index
                run = args.output/f'g{index}'
                run.mkdir()
                runtime = ROOT/f'build-output/product-vpp-runtime-s230-{args.output.name}-{index}'
                host = f'127.0.0.{attempt//4+1}' if family == 4 else f'fd20:6230::{attempt//4+1}'
                port = 30000+attempt%4
                launch = dict(env, PRODUCT_ARTIFACT_DIR=str(args.artifact),
                    PRODUCT_RUNTIME_DIR=str(runtime), PRODUCT_GENERATION=str(generation),
                    PRODUCT_WORKER_COUNT='2', SAKAMOTO_RUNTIME_PROFILE='root',
                    SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0', SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4')
                log = (run/'vpp.log').open('w')
                process = subprocess.Popen(['bash', str(ROOT/'tools/product/run-host-vpp.sh')],
                                           env=launch, stdout=log, stderr=subprocess.STDOUT)
                def cli(label, *commands):
                    return save(run/(label+'.txt'), ''.join(command(args.vppctl, '-s', runtime/'cli.sock', c) for c in commands))
                def drain(label):
                    for _ in range(100):
                        text = cli(label, 'show product completion')
                        status = rows(text, 'completion.status ')[0]
                        if all(status[k] == '0' for k in ('pending', 'frames', 'buffers', 'obligations')):
                            return
                        time.sleep(.02)
                    raise RuntimeError('drain timeout '+text)
                hooks = False
                server = None
                try:
                    for _ in range(100):
                        if (runtime/'cli.sock').exists(): break
                        if process.poll() is not None: raise RuntimeError((run/'vpp.log').read_text())
                        time.sleep(.05)
                    for _ in range(100):
                        initial = cli('initial', 'show product root lanes', 'show threads')
                        lanes = rows(initial, 'root.lane ')
                        if len(lanes) == 4 and all(x['ready'] == '1' for x in lanes): break
                        time.sleep(.02)
                    assert len(lanes) == 4 and all(x['ready'] == '1' for x in lanes)
                    busy = {q: queue_bind(q) for q in range(176, 180)}
                    assert all(v in (-1, -16) for v in busy.values()), busy
                    save(run/'queues-busy.json', json.dumps(busy))
                    save(run/'fds-before.txt', '\n'.join(f'{p.name} {os.readlink(p)}' for p in Path(f'/proc/{process.pid}/fd').iterdir()))
                    hooks = True
                    for tool, span in (('iptables', '176:177'), ('ip6tables', '178:179')):
                        for hook in ('INPUT', 'OUTPUT'):
                            for proto in ('udp', 'tcp'):
                                extra = ['-m', 'owner', '--uid-owner', '0'] if hook == 'OUTPUT' else []
                                command(tool, '-t', 'mangle', '-A', hook, '-p', proto, *extra,
                                        '-j', 'NFQUEUE', '--queue-balance', span)
                    save(run/'hooks.txt', command('iptables-save', '-t', 'mangle')+command('ip6tables-save', '-t', 'mangle'))
                    af = socket.AF_INET if family == 4 else socket.AF_INET6
                    kind = socket.SOCK_DGRAM if protocol == 17 else socket.SOCK_STREAM
                    server = socket.socket(af, kind)
                    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    server.bind((host, 40606)); server.settimeout(.3)
                    if protocol == 6: server.listen(1)
                    for blocked in (True, False):
                        revision = 1 if blocked else 2
                        save(run/f'policy-{revision}.txt', command(args.policy_client, runtime/'api.sock',
                             generation, run/'policy', revision, int(blocked)))
                        nonce = f's230-{generation}-{revision}-{time.time_ns()}'
                        observed = []
                        def endpoint():
                            try:
                                if protocol == 17:
                                    data, peer = server.recvfrom(4096)
                                    observed.append(data.decode()); server.sendto(data, peer)
                                else:
                                    conn, _ = server.accept()
                                    with conn:
                                        conn.settimeout(2)
                                        data = conn.recv(4096)
                                        observed.append(data.decode()); conn.sendall(data)
                            except TimeoutError:
                                pass
                        thread = threading.Thread(target=endpoint)
                        thread.start()
                        delivered = False
                        with socket.socket(af, kind) as client:
                            client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                            client.settimeout(.2 if blocked else 2)
                            client.bind(('127.0.0.1' if family == 4 else '::1', port))
                            try:
                                if protocol == 17: client.sendto(nonce.encode(), (host, 40606))
                                else: client.connect((host, 40606)); client.sendall(nonce.encode())
                                delivered = client.recv(4096) == nonce.encode()
                            except TimeoutError:
                                pass
                        thread.join(3)
                        assert not thread.is_alive()
                        assert delivered == (not blocked), (nonce, delivered)
                        assert observed == ([] if blocked else [nonce]), (nonce, observed)
                        time.sleep(.05); drain(f'drain-{revision}')
                        facts = rows((run/'vpp.log').read_text(), 's216 ')
                        selected = [d for d in facts if d.get('stage') == 'admit' and
                                    d['src_port'] == str(port) and d['dst_port'] == '40606' and d['direction'] == '3']
                        assert selected
                        lane, owner = int(selected[-1]['origin_lane']), int(selected[-1]['owner'])
                        coverage.add((lane, owner))
                        case = dict(generation=generation, family=family, protocol=protocol, blocked=blocked,
                                    lane=lane, owner=owner, nonce=nonce, delivered=delivered, endpoint=observed,
                                    host=host, source_port=port)
                        result['cases'].append(case)
                        save(run/f'case-{revision}.json', json.dumps(case, indent=2))
                    server.close(); server = None
                    drain('settled')
                    cli('runtime', 'show product root lanes', 'show product completion', 'show product primary',
                        'show runtime', 'show threads', 'show node product-packet-policy',
                        'show node product-packet-origin-completion', 'show node product-packet-owner-guard')
                finally:
                    try:
                        if server is not None: server.close()
                        if hooks:
                            for tool in ('iptables', 'ip6tables'): command(tool, '-t', 'mangle', '-F')
                        if process.poll() is None and (runtime/'cli.sock').exists():
                            drain('stop-drain')
                            cli('close', *[f'product root lane close {i}' for i in range(4)])
                            cli('closed', 'show product root lanes', 'show product completion')
                            free = {q: queue_bind(q) for q in range(176, 180)}
                            save(run/'queues-free.json', json.dumps(free))
                            assert all(v == 0 for v in free.values()), free
                            save(run/'fds-closed.txt', '\n'.join(f'{p.name} {os.readlink(p)}' for p in Path(f'/proc/{process.pid}/fd').iterdir()))
                    finally:
                        if process.poll() is None:
                            process.terminate()
                            try: process.wait(timeout=10)
                            except subprocess.TimeoutExpired:
                                process.kill(); process.wait(timeout=5)
                        log.close()
                    assert not Path(f'/proc/{process.pid}').exists()
                    save(run/'stop.json', json.dumps(dict(pid=process.pid, process_absent=True)))
                    save(run/'hooks-after.txt', command('iptables-save', '-t', 'mangle')+command('ip6tables-save', '-t', 'mangle'))
                result['generations'].append(generation)
                print(f'{generation} family={family} protocol={protocol} coverage={sorted(coverage)}', flush=True)
                target = {(lane, owner) for lane in ((0, 1) if family == 4 else (2, 3)) for owner in (0, 1)}
                if coverage == target: break
            assert coverage == target, (family, protocol, coverage)
    result['status'] = 'RAW_COMPLETE'
finally:
    result['completed_ns'] = time.time_ns()
    save(args.output/'result.json', json.dumps(result, indent=2)+'\n')
