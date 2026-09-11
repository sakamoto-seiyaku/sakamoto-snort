#!/usr/bin/env python3
"""S229 native errors and real retained enqueue rejection on Linux."""
import argparse,hashlib,importlib.util,json,os,socket,struct,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--artifact',type=Path,required=True);p.add_argument('--vppctl',type=Path,required=True);p.add_argument('--policy-client',type=Path,required=True);p.add_argument('--suite',choices=['basic','geometry','ingress-handoff','sendout-handoff','policy-return'],required=True);p.add_argument('--control-dir',type=Path,required=True);args=p.parse_args()
args.output=args.output.resolve();args.output.mkdir(parents=True,exist_ok=False);args.artifact=args.artifact.resolve()
env=dict(os.environ,LD_LIBRARY_PATH=str(args.control_dir.resolve())+':'+str(args.artifact/'lib'))
def save(path,text):path.write_text(text);return text
def command(*argv,check=True):
 result=subprocess.run(list(map(str,argv)),env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=20)
 if check and result.returncode:raise RuntimeError(result.stdout)
 return result.stdout
def rows(text,prefix):return [dict(x.split('=',1) for x in line.split()[1:] if '=' in x) for line in text.splitlines() if line.startswith(prefix)]
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


spec=importlib.util.spec_from_file_location('scenarios',ROOT/'tests/device/s229-reassembly-scenarios.py');scenarios=importlib.util.module_from_spec(spec);spec.loader.exec_module(scenarios)
generation=22910;runtime=ROOT/('build-output/product-vpp-runtime-s229-'+args.output.name)
launch=dict(env,PRODUCT_ARTIFACT_DIR=str(args.artifact),PRODUCT_RUNTIME_DIR=str(runtime),PRODUCT_GENERATION=str(generation),PRODUCT_WORKER_COUNT='2',SAKAMOTO_RUNTIME_PROFILE='root',SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0',SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4')
result=dict(status='HOLD',started_ns=time.time_ns(),generation=generation,platform='linux',source='GRAPH_INJECTED',suite=args.suite,policy_helper_sha256=hashlib.sha256(args.policy_client.read_bytes()).hexdigest())
assert os.getuid()==0 and Path('/proc/self/uid_map').read_text().split()[1]!='0'
save(args.output/'kernel.txt',command('uname','-a')+command('id')+'netns='+os.readlink('/proc/self/ns/net')+'\n')
command('ip','link','set','lo','up');log=(args.output/'vpp.log').open('w');process=subprocess.Popen(['bash',str(ROOT/'tools/product/run-host-vpp.sh')],env=launch,stdout=log,stderr=subprocess.STDOUT);control=None;revision=22900

def cli(label,*commands):return save(args.output/(label+'.txt'),''.join(command(args.vppctl,'-s',runtime/'cli.sock',c) for c in commands))
try:
 for _ in range(200):
  if (runtime/'cli.sock').exists():break
  if process.poll() is not None:raise RuntimeError((args.output/'vpp.log').read_text())
  time.sleep(.03)
 cli('initial-native','product packet-trace limit 4096','trace add product-packet-admit 64','show product root lanes','show product reassembly','show product primary')
 busy={q:queue_bind(q) for q in range(176,180)};save(args.output/'queues-busy.json',json.dumps(busy));assert all(v!=0 for v in busy.values())
 control=ControlClient(runtime/'cli.sock')
 def policy(blocked):
  global revision
  revision+=1;response=command(args.policy_client,runtime/'api.sock',generation,args.output/'policy',revision,int(blocked),22900,1)
  save(args.output/f'policy-{revision}.txt',response);assert 'policy rc=0' in response
 def await_hold(token,event='hold_begin'):
  deadline=time.monotonic()+2
  while time.monotonic()<deadline:
   trace=(args.output/'vpp.log').read_text()
   if any(f'event={event} ' in line and f'token={token} ' in line for line in trace.splitlines()):
    if event=='hold_begin':assert f's209 event=hold_end token={token} ' not in trace,'hold ended before pressure could be sent'
    return
   time.sleep(.005)
  raise RuntimeError('worker did not enter diagnostic hold')
 runner=scenarios.Scenarios(control.call,lambda n,t:save(args.output/n,t),policy,await_hold);result['cases']=runner.cases;result['holds']=runner.holds
 if args.suite=='basic':runner.basic()
 elif args.suite=='geometry':runner.geometry()
 else:runner.pressure(args.suite)
 control.close();control=None
 cli('runtime','show product reassembly','show product completion','show product primary','show product root lanes','show runtime','show threads','show trace')
 cli('native-stop-final','product root stop');cli('after-stop','show product reassembly','show product completion','show product root lanes')
 result['status']='RAW_COMPLETE'
except Exception as error:result['error']=repr(error);raise
finally:
 if control:control.close()
 if process.poll() is None:
  process.terminate()
  try:process.wait(timeout=8)
  except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5);result['forced_kill']=True
 log.close();result['process_absent']=process.poll() is not None
 free={q:queue_bind(q) for q in range(176,180)};save(args.output/'queues-free.json',json.dumps(free))
 result['completed_ns']=time.time_ns();save(args.output/'result.json',json.dumps(result,indent=2)+'\n')
