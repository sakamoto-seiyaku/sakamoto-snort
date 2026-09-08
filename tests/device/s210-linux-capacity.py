#!/usr/bin/env python3
"""S210 real Linux capacity acceptance; invoke inside a disposable user/net namespace."""
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
import importlib.util

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

class ControlClient:
 def __init__(self,path):
  self.socket=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.socket.settimeout(5);self.socket.connect(str(path))
 def call(self,command_text,marker):
  self.socket.sendall((command_text+'\n').encode());response=b''
  while True:
   chunk=self.socket.recv(65536)
   if not chunk:raise RuntimeError('control EOF '+repr(response))
   response+=chunk;text=response.decode(errors='replace').replace('\r','')
   start=text.find(marker)
   if start>=0 and '\n' in text[start:]:return text
   if 'rejected' in text or 'unknown input' in text:raise RuntimeError(text)
 def close(self):
  try:self.socket.sendall(b'quit\n')
  except OSError:pass
  self.socket.close()


result = dict(status='HOLD', started_ns=time.time_ns(), cases=[])
save(args.output/'kernel.txt', command('uname', '-a') + command('id') +
     'netns=' + os.readlink('/proc/self/ns/net') + '\n')
uid_map = Path('/proc/self/uid_map').read_text().split()
assert os.getuid() == 0 and uid_map[:1] == ['0'] and uid_map[1] != '0' and uid_map[2] == '1'
save(args.output/'uid-map.txt', ' '.join(uid_map)+'\n')
assert 'product.host.evidence=OFF' in (args.artifact/'product-vpp-artifact.properties').read_text()
result['artifact_manifest_sha256'] = hashlib.sha256((args.artifact/'product-vpp-artifact.properties').read_bytes()).hexdigest()
command('ip', 'link', 'set', 'lo', 'up')
for i in range(1, 9):
    command('ip', '-6', 'addr', 'add', f'fd20:6210::{i}/128', 'dev', 'lo', 'nodad')

try:
 for family in (4, 6):
  for owner in (0, 1):
   index = len(result['cases'])
   generation = 21010 + index
   run = args.output/f'g{index}'
   run.mkdir()
   runtime = ROOT/f'build-output/product-vpp-runtime-s210-{args.output.name}-{index}'
   af = socket.AF_INET if family == 4 else socket.AF_INET6
   local = '127.0.0.1' if family == 4 else '::1'
   hosts = [f'127.0.0.{i}' if family == 4 else f'fd20:6210::{i}' for i in range(1, 9)]
   launch = dict(env, PRODUCT_ARTIFACT_DIR=str(args.artifact), PRODUCT_RUNTIME_DIR=str(runtime),
                 PRODUCT_GENERATION=str(generation), PRODUCT_WORKER_COUNT='2',
                 SAKAMOTO_RUNTIME_PROFILE='root', SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0',
                 SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4')
   log = (run/'vpp.log').open('w')
   process = subprocess.Popen(['bash', str(ROOT/'tools/product/run-host-vpp.sh')],
                              env=launch, stdout=log, stderr=subprocess.STDOUT)
   servers, threads, clients, endpoint = [], [], [], []
   done = threading.Event()
   control = None
   case = dict(generation=generation, family=family, protocol=17, owner=owner,
               uid=0, sent=[], received=[], phases={}, warm=[])

   def cli(label, *commands):
       return save(run/(label+'.txt'), ''.join(command(args.vppctl, '-s', runtime/'cli.sock', c) for c in commands))

   def drain(label):
       for _ in range(200):
           status = rows(cli(label, 'show product completion'), 'completion.status ')[0]
           if all(status[k] == '0' for k in ('pending', 'frames', 'buffers', 'obligations')):
               return
           time.sleep(.02)
       raise RuntimeError('drain timeout '+str(status))

   def configure(label, credits=32, primary=64, completion=128):
       drain(label+'-drain')
       text = cli(label, f'product capacity credits {credits} primary-slots {primary} completion-slots {completion}')
       assert 'capacity.configured' in text, text

   def send(client, phase, count=1):
       names = [f's210-{generation}-{phase}-{i}' for i in range(count)]
       for name in names:
           client.send((name+'\n').encode())
       case['sent'].extend(names)
       case['phases'].setdefault(phase, []).extend(names)
       return names

   def collect(client, expected, timeout=8):
       deadline = time.monotonic()+timeout
       found = []
       while len(found) < len(expected) and time.monotonic() < deadline:
           client.settimeout(max(.01, deadline-time.monotonic()))
           data = client.recv(4096).decode().strip()
           found.append(data)
       case['received'].extend(found)
       assert sorted(found) == sorted(expected), (found, expected)

   def echo(server):
       while not done.is_set():
           try:
               data, peer = server.recvfrom(4096)
               endpoint.append(data.decode().strip())
               server.sendto(data, peer)
           except TimeoutError:
               pass

   try:
       for _ in range(200):
           if (runtime/'cli.sock').exists(): break
           if process.poll() is not None: raise RuntimeError((run/'vpp.log').read_text())
           time.sleep(.03)
       lanes = rows(cli('initial', 'show product root lanes', 'show product primary', 'show threads'), 'root.lane ')
       assert len(lanes) == 4 and all(d['ready'] == '1' for d in lanes)
       save(run/'queues-busy.json', json.dumps({q: queue_bind(q) for q in range(176, 180)}))
       assert 'packet.trace_limit=4096' in cli('trace-limit', 'product packet-trace limit 4096')
       control = ControlClient(runtime/'cli.sock')
       save(run/'allow.txt', control.call('product policy publish 1 101 0 10000', 'policy.publish=ok'))
       for target in hosts:
           server = socket.socket(af, socket.SOCK_DGRAM)
           server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
           server.bind((target, 40610)); server.settimeout(.1)
           servers.append(server)
           thread = threading.Thread(target=echo, args=(server,)); threads.append(thread); thread.start()
       tool, span = ('iptables', '176:177') if family == 4 else ('ip6tables', '178:179')
       command(tool, '-t', 'mangle', '-A', 'OUTPUT', '-p', 'udp', '--dport', '40610',
               '-m', 'owner', '--uid-owner', '0', '-j', 'NFQUEUE', '--queue-balance', span)
       save(run/'hooks.txt', command('iptables-save', '-t', 'mangle')+command('ip6tables-save', '-t', 'mangle'))
       selected = None
       for attempt in range(64):
           c = socket.socket(af, socket.SOCK_DGRAM)
           c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
           c.bind((local, 0)); c.connect((hosts[attempt % len(hosts)], 40610)); clients.append(c)
           nonce = send(c, f'warm-{attempt}')
           collect(c, nonce)
           fact = [d for d in rows((run/'vpp.log').read_text(), 's216 ')
                   if d.get('stage') == 'admit' and nonce[0].encode().hex() in d.get('raw', '')][0]
           case['warm'].append(dict(nonce=nonce[0], port=c.getsockname()[1], host=hosts[attempt % len(hosts)],
                                    owner=int(fact['owner']), origin=int(fact['worker'])))
           if int(fact['owner']) == owner and int(fact['worker']) != owner:
               selected = c
               case['selected'] = case['warm'][-1]
               break
       assert selected is not None, 'no actual remote flow found'

       configure('credit', credits=0)
       collect(selected, send(selected, 'credit', 8))
       configure('credit-off')
       collect(selected, send(selected, 'credit-recovery', 8))

       configure('enqueue', primary=2)
       save(run/'hold.txt', control.call(f'product policy hold-next {owner} 500000', 'policy.hold=armed'))
       held = send(selected, 'held')
       deadline = time.monotonic()+4
       while 's209 event=hold_begin' not in (run/'vpp.log').read_text():
           assert time.monotonic() < deadline, 'held packet not observed'
           time.sleep(.001)
       burst = send(selected, 'enqueue', 48)
       collect(selected, held+burst)
       configure('enqueue-off')
       collect(selected, send(selected, 'enqueue-recovery', 8))

       configure('completion', completion=2)
       save(run/'drop.txt', command(args.policy_client, runtime/'api.sock', generation, run/'policy', 2, 1))
       # Actual native FQ pressure. Every already-decided DROP must survive it.
       for attempt in range(4):
           send(selected, f'drop-{attempt}', 32)
           drain(f'drop-{attempt}-drain')
           if 's210 event=completion_deferred' in (run/'vpp.log').read_text(): break
       assert 's210 event=completion_deferred' in (run/'vpp.log').read_text(), 'return pressure not exercised'
       # Pre-policy credit bypasses may legitimately echo during this phase.
       selected.settimeout(.1)
       while True:
           try: case['received'].append(selected.recv(4096).decode().strip())
           except TimeoutError: break
       configure('completion-off')
       save(run/'allow-again.txt', control.call('product policy publish 3 303 0 30000', 'policy.publish=ok'))
       collect(selected, send(selected, 'completion-recovery', 8))
       command(tool, '-t', 'mangle', '-F')
       drain('final-drain')
       cli('runtime', 'show product root lanes', 'show product completion', 'show product primary',
           'show product flows', 'show runtime', 'show threads', 'show node product-packet-policy',
           'show node product-packet-origin-completion', 'show node product-packet-owner-guard')
       save(run/'endpoint.json', json.dumps(endpoint))
       save(run/'case.json', json.dumps(case, indent=2))
       result['cases'].append(case)
   finally:
       for tool in ('iptables', 'ip6tables'): command(tool, '-t', 'mangle', '-F')
       for c in clients: c.close()
       done.set()
       for t in threads: t.join(2)
       for server in servers: server.close()
       if control is not None: control.close()
       try:
           if process.poll() is None and (runtime/'cli.sock').exists():
               drain('stop-drain')
               save(run/'fds-before.txt', '\n'.join(f'{p.name} {os.readlink(p)}' for p in Path(f'/proc/{process.pid}/fd').iterdir()))
               assert 'root.stop=ok' in cli('close', 'product root stop')
               cli('closed', 'show product root lanes', 'show product completion', 'show product primary', 'show product flows')
               free = {q: queue_bind(q) for q in range(176, 180)}
               save(run/'queues-free.json', json.dumps(free)); assert all(v == 0 for v in free.values())
               save(run/'fds-closed.txt', '\n'.join(f'{p.name} {os.readlink(p)}' for p in Path(f'/proc/{process.pid}/fd').iterdir()))
       finally:
           if process.poll() is None:
               process.terminate()
               try: process.wait(timeout=10)
               except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
           log.close()
       save(run/'stop.json', json.dumps(dict(pid=process.pid, process_absent=not Path(f'/proc/{process.pid}').exists())))
       save(run/'hooks-after.txt', command('iptables-save', '-t', 'mangle')+command('ip6tables-save', '-t', 'mangle'))
   print('completed', generation, family, owner, flush=True)
 result['status'] = 'RAW_COMPLETE'
except Exception as error:
 result['error'] = repr(error)
 raise
finally:
 result['completed_ns'] = time.time_ns()
 save(args.output/'result.json', json.dumps(result, indent=2)+'\n')
