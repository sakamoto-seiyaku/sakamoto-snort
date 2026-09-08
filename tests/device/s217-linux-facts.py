#!/usr/bin/env python3
"""S217 real netlink attribute normalization; invoke inside a disposable user/net namespace."""
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
parser.add_argument('--control-dir', type=Path)
args = parser.parse_args()
args.output = args.output.resolve()
args.artifact = args.artifact.resolve()
args.output.mkdir(parents=True, exist_ok=False)
env = dict(os.environ, LD_LIBRARY_PATH=str(args.artifact/'lib')+':'+str(args.control_dir.resolve() if args.control_dir else ROOT/'build-output/s217-facts/linux-build-d/control'))

def command(*argv, check=True):
    if argv[0] in ('iptables','ip6tables'):
        argv = (argv[0], '-w', '5', *argv[1:])
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

plan_spec=importlib.util.spec_from_file_location('plan',ROOT/'tests/device/s217-facts-plan.py')
plan=importlib.util.module_from_spec(plan_spec);plan_spec.loader.exec_module(plan)
NET=ROOT/'build-output/s231-fragments/linux-net';ECHO=ROOT/'build-output/s231-fragments/linux-echo'
runtime=ROOT/('build-output/product-vpp-runtime-s217-'+args.output.name)
generation=21710
launch=dict(env,PRODUCT_ARTIFACT_DIR=str(args.artifact),PRODUCT_RUNTIME_DIR=str(runtime),
 PRODUCT_GENERATION=str(generation),PRODUCT_WORKER_COUNT='2',SAKAMOTO_RUNTIME_PROFILE='root',
 SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0',SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4')
result=dict(status='HOLD',started_ns=time.time_ns(),generation=generation,cases=[],platform='linux',helper_sha256={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (NET,ECHO,args.policy_client)})
assert os.getuid()==0 and Path('/proc/self/uid_map').read_text().split()[1]!='0'
save(args.output/'kernel.txt',command('uname','-a')+command('id'))
command('ip','link','set','lo','up')
log=(args.output/'vpp.log').open('w');process=subprocess.Popen(['bash',str(ROOT/'tools/product/run-host-vpp.sh')],env=launch,stdout=log,stderr=subprocess.STDOUT)
elog=(args.output/'endpoint.log').open('w');echo=subprocess.Popen([str(ECHO),'40631','127.0.0.1','::1'],stdout=elog,stderr=subprocess.STDOUT)
def cli(label,*commands):return save(args.output/(label+'.txt'),''.join(command(args.vppctl,'-s',runtime/'cli.sock',c) for c in commands))
def drain(label):
 deadline=time.monotonic()+10
 while time.monotonic()<deadline:
  text=cli(label,'show product completion');d=rows(text,'completion.status ')[0]
  if all(d[k]=='0' for k in ('pending','frames','buffers','obligations')):return
  time.sleep(.03)
 raise RuntimeError('completion debt '+str(d))
def clear():
 for tool in ('iptables','ip6tables'):command(tool,'-t','mangle','-F')
revision=21700
def probe(family,hook,c,protocol=17):
 global revision
 label=f'{family}-{hook}-{c["name"]}-{protocol}';revision+=1
 cli(label+'-fault','product root facts-fault '+str(c['fault']))
 response=command(args.policy_client,runtime/'api.sock',generation,args.output/'policy',revision,c['mode'],c['uid'],1)
 save(args.output/(label+'-policy.txt'),response);assert 'policy rc=0' in response
 nonce='s217-'+label+'-'+str(time.time_ns())
 argv=[NET,'probe',0,family,protocol,'127.0.0.1' if family==4 else '::1',40631,nonce]
 if c['blocked']:argv.append('drop')
 response=save(args.output/(label+'-probe.txt'),command(*argv))
 assert ('probe.blocked' if c['blocked'] else 'probe uid=') in response
 drain(label+'-drain')
 result['cases'].append(dict(c,family=family,hook=hook,protocol=protocol,label=label,nonce=nonce,revision=revision))
try:
 for _ in range(200):
  if (runtime/'cli.sock').exists():break
  if process.poll() is not None:raise RuntimeError((args.output/'vpp.log').read_text())
  time.sleep(.03)
 cli('initial','product packet-trace limit 4096','show product root lanes')
 for family in (4,6):
  for hook in ('OUTPUT','INPUT'):
   clear();tool='iptables' if family==4 else 'ip6tables';span='176:177' if family==4 else '178:179'
   for protocol in ('udp','tcp'):
    command(tool,'-t','mangle','-A',hook,'-o' if hook=='OUTPUT' else '-i','lo','-p',protocol,
      '--dport' if hook=='OUTPUT' else '--sport','40631','-j','NFQUEUE','--queue-balance',span)
   save(args.output/f'{family}-{hook}-hooks.txt',command('iptables-save','-t','mangle')+command('ip6tables-save','-t','mangle'))
   baseline=dict(name='baseline',fault=0,mode=0,uid=0,blocked=False)
   probe(family,hook,baseline)
   facts=rows((args.output/'vpp.log').read_text(),'s217 event=nfq_facts ')
   facts=[f for f in facts if f['raw_hook']==('3' if hook=='OUTPUT' else '1')];assert facts
   observed=facts[-1];uid=int(observed['raw_uid']) if observed['raw_uid_present']=='1' else 0
   for case in plan.cases(uid,observed['raw_uid_present']=='1',int(observed['normalized_ifindex'])):probe(family,hook,case)
   probe(family,hook,baseline,6)
 clear();drain('final-drain');cli('runtime','show product root lanes','show product completion','show product primary','show product flows','show product reassembly')
 assert 'root.stop=ok' in cli('close','product root stop')
 cli('closed','show product root lanes','show product completion')
 free={q:queue_bind(q) for q in range(176,180)};save(args.output/'queues-free.json',json.dumps(free));assert all(v==0 for v in free.values())
 result['status']='RAW_COMPLETE'
finally:
 clear();echo.terminate();echo.wait(timeout=5);elog.close()
 if process.poll() is None:process.terminate();process.wait(timeout=10)
 log.close();result['process_absent']=not Path(f'/proc/{process.pid}').exists()
 result['completed_ns']=time.time_ns();save(args.output/'result.json',json.dumps(result,indent=2)+'\n')
