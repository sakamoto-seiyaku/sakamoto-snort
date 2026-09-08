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
    command('ip', '-6', 'addr', 'add', f'fd20:6208::{i}/128', 'dev', 'lo', 'nodad')


try:
    for family in (4,6):
        for protocol,mode in ((17,'normal'),(6,'normal'),(6,'midstream')):
            coverage=set()
            for attempt in range(32):
                index=len(result['generations']);generation=20810+index
                run=args.output/f'g{index}';run.mkdir()
                runtime=ROOT/f'build-output/product-vpp-runtime-s208-{args.output.name}-{index}'
                host=f'127.0.0.{attempt//4+1}' if family==4 else f'fd20:6208::{attempt//4+1}'
                port=32000+attempt%4
                launch=dict(env,PRODUCT_ARTIFACT_DIR=str(args.artifact),PRODUCT_RUNTIME_DIR=str(runtime),
                    PRODUCT_GENERATION=str(generation),PRODUCT_WORKER_COUNT='2',SAKAMOTO_RUNTIME_PROFILE='root',
                    SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0',SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4')
                log=(run/'vpp.log').open('w')
                process=subprocess.Popen(['bash',str(ROOT/'tools/product/run-host-vpp.sh')],env=launch,stdout=log,stderr=subprocess.STDOUT)
                def cli(label,*commands):
                    return save(run/(label+'.txt'),''.join(command(args.vppctl,'-s',runtime/'cli.sock',c) for c in commands))
                def drain(label):
                    for _ in range(150):
                        d=rows(cli(label,'show product completion'),'completion.status ')[0]
                        if all(d[k]=='0' for k in ('pending','frames','buffers','obligations')):return
                        time.sleep(.02)
                    raise RuntimeError('drain timeout '+str(d))
                def policy(revision,blocked):
                    save(run/f'policy-{revision}.txt',command(args.policy_client,runtime/'api.sock',generation,run/'policy',revision,int(blocked)))
                hooks=False;client=None;server=None;connection=[];received=[];stop_server=threading.Event();accepted=threading.Event();thread=None
                try:
                    for _ in range(100):
                        if (runtime/'cli.sock').exists():break
                        if process.poll() is not None:raise RuntimeError((run/'vpp.log').read_text())
                        time.sleep(.05)
                    for _ in range(100):
                        lanes=rows(cli('initial','show product root lanes','show threads'),'root.lane ')
                        if len(lanes)==4 and all(d['ready']=='1' for d in lanes):break
                        time.sleep(.02)
                    assert len(lanes)==4 and all(d['ready']=='1' for d in lanes)
                    save(run/'queues-busy.json',json.dumps({q:queue_bind(q) for q in range(176,180)}))
                    af=socket.AF_INET if family==4 else socket.AF_INET6;kind=socket.SOCK_DGRAM if protocol==17 else socket.SOCK_STREAM
                    server=socket.socket(af,kind);server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);server.bind((host,40608));server.settimeout(.1)
                    if protocol==6:server.listen(2)
                    def echo():
                        conn=None
                        try:
                            while not stop_server.is_set():
                                try:
                                    if protocol==17:
                                        data,peer=server.recvfrom(4096);received.append(data.hex());server.sendto(data,peer)
                                    else:
                                        if conn is None:
                                            conn,_=server.accept();conn.settimeout(.1);connection.append(conn);accepted.set()
                                        data=conn.recv(4096)
                                        if not data:break
                                        received.append(data.hex());conn.sendall(data)
                                except TimeoutError:continue
                        finally:
                            if conn is not None:conn.close()
                    thread=threading.Thread(target=echo);thread.start()
                    def socket_client():
                        c=socket.socket(af,kind);c.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);c.settimeout(2)
                        c.bind(('127.0.0.1' if family==4 else '::1',port));c.connect((host,40608));return c
                    if mode=='midstream':
                        client=socket_client();assert accepted.wait(2);time.sleep(.05)
                        save(run/'before-hooks.txt',command('iptables-save','-t','mangle')+command('ip6tables-save','-t','mangle'))
                    hooks=True
                    for tool,span in (('iptables','176:177'),('ip6tables','178:179')):
                        for hook in ('INPUT','OUTPUT'):
                            for proto in ('tcp','udp'):
                                extra=['-m','owner','--uid-owner','0'] if hook=='OUTPUT' else []
                                command(tool,'-t','mangle','-A',hook,'-p',proto,*extra,'-j','NFQUEUE','--queue-balance',span)
                    save(run/'hooks.txt',command('iptables-save','-t','mangle')+command('ip6tables-save','-t','mangle'))
                    case=dict(generation=generation,family=family,protocol=protocol,mode=mode,host=host,source_port=port,nonces=[])
                    if mode=='normal':
                        policy(1,True)
                        with socket.socket(af,kind) as blocked:
                            blocked.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);blocked.settimeout(.2)
                            blocked.bind(('127.0.0.1' if family==4 else '::1',port))
                            nonce=f's208-{generation}-drop-{time.time_ns()}'
                            try:
                                if protocol==17:blocked.sendto(nonce.encode(),(host,40608))
                                else:blocked.connect((host,40608));blocked.sendall(nonce.encode())
                                blocked.recv(4096);raise RuntimeError('early DROP delivered')
                            except TimeoutError:pass
                        drain('drop-drain')
                        pools=rows(cli('drop-flows','show product flows'),'flow.pool ')
                        assert all(d['entries']=='0' and d['allocations']=='0' for d in pools),pools
                        assert not received
                        case['drop_nonce']=nonce
                    policy(2,False)
                    if client is None:client=socket_client()
                    if protocol==6:assert accepted.wait(2)
                    for revision in (2,3):
                        if revision==3:policy(3,False)
                        nonce=f's208-{generation}-r{revision}-{time.time_ns()}';case['nonces'].append(nonce)
                        if mode=='midstream' and revision==2:
                            connection[0].sendall(nonce.encode())
                        else:client.sendall(nonce.encode())
                        value=b''
                        while len(value)<len(nonce):value+=client.recv(4096)
                        assert value==nonce.encode(),(nonce,value)
                        drain(f'r{revision}-drain')
                        cli(f'r{revision}-flows','show product flows','show product primary','show product completion')
                    client.close();client=None;time.sleep(.1);drain('after-client-close')
                    stop_server.set();thread.join(2);assert not thread.is_alive();server.close();server=None
                    trace=(run/'vpp.log').read_text();facts=rows(trace,'s216 ')
                    first=next(d for d in facts if d.get('stage')=='admit' and d['source']=='NFQ_CAPTURED' and int(d['protocol'])==protocol and (int(d['src_port'])==port or int(d['dst_port'])==port))
                    case['lane']=int(first['origin_lane']);case['owner']=int(first['owner']);coverage.add((case['lane'],case['owner']))
                    save(run/'endpoint.json',json.dumps(received))
                    save(run/'case.json',json.dumps(case,indent=2));result['cases'].append(case)
                    cli('runtime','show product root lanes','show product completion','show product primary','show product flows','show runtime','show threads','show node product-packet-policy','show node product-packet-origin-completion','show node product-packet-owner-guard')
                finally:
                    try:
                        if client is not None:client.close()
                        stop_server.set()
                        if thread is not None:thread.join(2)
                        if server is not None:server.close()
                        if hooks:
                            for tool in ('iptables','ip6tables'):command(tool,'-t','mangle','-F')
                        if process.poll() is None and (runtime/'cli.sock').exists():
                            drain('stop-drain')
                            save(run/'fds-before.txt','\n'.join(f'{p.name} {os.readlink(p)}' for p in Path(f'/proc/{process.pid}/fd').iterdir()))
                            closed=cli('close','product root stop');assert 'root.stop=ok' in closed,closed
                            cli('closed','show product root lanes','show product completion','show product primary','show product flows')
                            free={q:queue_bind(q) for q in range(176,180)};save(run/'queues-free.json',json.dumps(free));assert all(v==0 for v in free.values())
                            save(run/'fds-closed.txt','\n'.join(f'{p.name} {os.readlink(p)}' for p in Path(f'/proc/{process.pid}/fd').iterdir()))
                    finally:
                        if process.poll() is None:
                            process.terminate()
                            try:process.wait(timeout=10)
                            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                        log.close()
                    assert not Path(f'/proc/{process.pid}').exists()
                    save(run/'stop.json',json.dumps(dict(pid=process.pid,process_absent=True)))
                    save(run/'hooks-after.txt',command('iptables-save','-t','mangle')+command('ip6tables-save','-t','mangle'))
                result['generations'].append(generation)
                print(generation,family,protocol,mode,sorted(coverage),flush=True)
                target={(lane,owner) for lane in ((0,1) if family==4 else (2,3)) for owner in (0,1)}
                if coverage==target:break
            assert coverage==target,(family,protocol,mode,coverage)
    result['status']='RAW_COMPLETE'
finally:
    result['completed_ns']=time.time_ns();save(args.output/'result.json',json.dumps(result,indent=2)+'\n')
