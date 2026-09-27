#!/usr/bin/env python3
"""R2 real SMTP, FTP control/data and FTPS under unified Product rules."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import select
import subprocess
import time
from helpers.t25_observation_client import ObservationClient

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--artifact', type=Path, required=True)
parser.add_argument('--stage', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--build', type=Path, required=True)
parser.add_argument('--fixtures',type=Path,required=True)
parser.add_argument('--observation',action='store_true')


args = parser.parse_args()

artifact, stage, output = (p.resolve() for p in (args.artifact, args.stage, args.output))
output.mkdir(parents=True, exist_ok=False)
assert os.getuid() == 0
uid_map = Path('/proc/self/uid_map').read_text().split()
assert int(uid_map[2]) > 12002, 'two real mapped UIDs required'
env = dict(os.environ, LD_LIBRARY_PATH=str(artifact/'lib'))
vppctl = stage/'source/build-root/install-vpp-native/vpp/bin/vppctl'
runtime_tag = hashlib.sha256(str(output).encode()).hexdigest()[:12]
runtime = ROOT/('build-output/product-vpp-runtime-'+runtime_tag)
generation = 28401
config_dir = output/'configuration'
result = dict(status='HOLD', generation=generation, profile='root', source='NFQ_CAPTURED',
              cases=[], observation=args.observation, started_ns=time.time_ns(), artifact=str(artifact),
              manifest_sha256=hashlib.sha256((artifact/'product-vpp-artifact.properties').read_bytes()).hexdigest())
build_path=args.build.resolve()
build=json.loads(build_path.read_text())
assert Path(build['artifact']) == artifact
for name, expected in build['artifact_hashes'].items():
    assert hashlib.sha256((artifact/name).read_bytes()).hexdigest()==expected,name
result.update(build=str(build_path),build_sha256=hashlib.sha256(build_path.read_bytes()).hexdigest(),
              source_sha256=build['source_sha256'],runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              policy_uids=[12001])
(output/'runner.py').write_bytes(Path(__file__).read_bytes())
if args.observation:
    helper=ROOT/'tests/device/helpers/t25_observation_client.py'
    (output/'observation-helper.py').write_bytes(helper.read_bytes())
    result['observation_helper_sha256']=hashlib.sha256(helper.read_bytes()).hexdigest()

def command(*argv, check=True):
    p = subprocess.run(list(map(str, argv)), env=env, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=30)
    if check and p.returncode: raise RuntimeError(p.stdout)
    return p.stdout

def save(name, text):
    (output/name).write_text(text)
    return text

def props(text):
    return dict(line.split('=', 1) for line in text.splitlines() if '=' in line)

def cli(name, *commands):
    return save(name+'.txt', ''.join(command(vppctl, '-s', runtime/'cli.sock', c) for c in commands))

def api(name, operation, *values):
    text = save(name+'.txt', command(artifact/'bin/sakamoto-product-core-host', operation,
                                   runtime/'api.sock', generation, *values, check=False))
    return props(text)

def drain(name):
    deadline = time.monotonic()+10
    while time.monotonic() < deadline:
        text = cli(name, 'show product completion')
        row = next(line for line in text.splitlines() if line.startswith('completion.status '))
        values = dict(item.split('=',1) for item in row.split()[1:] if '=' in item)
        if all(values[key] == '0' for key in ('pending','frames','buffers','obligations')): return
        time.sleep(.02)
    raise RuntimeError('completion drain timeout')

save('environment.txt', command('uname','-a')+command('id')+'uid_map='+' '.join(uid_map)
     +'\nnetns='+os.readlink('/proc/self/ns/net')+'\n')
command('ip','link','set','lo','up')
launch = dict(env, PRODUCT_ARTIFACT_DIR=str(artifact), PRODUCT_RUNTIME_DIR=str(runtime),
              PRODUCT_RULE_CONFIG_DIR=str(config_dir), PRODUCT_GENERATION=str(generation),
              PRODUCT_WORKER_COUNT='2', SAKAMOTO_RUNTIME_PROFILE='root',
              SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0', SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4',
              SAKAMOTO_LINUX_NETWORK_SOURCE='external')

peer_source=ROOT/'tests/device/helpers/r2_mail_peer.py'
save('socket-peer.py',peer_source.read_text())
result['peer_sha256']=hashlib.sha256(peer_source.read_bytes()).hexdigest()
endpoint_log=(output/'endpoint.jsonl').open('w')
endpoint=subprocess.Popen(['python3','-u',str(peer_source),'server','--host','127.0.0.2','--directory',str(args.fixtures.resolve())],
    env=env,user=12001,group=12001,extra_groups=[],stdout=endpoint_log,stderr=subprocess.STDOUT)
deadline=time.monotonic()+5
while '"kind": "ready"' not in (output/'endpoint.jsonl').read_text():
    assert endpoint.poll() is None
    assert time.monotonic()<deadline
    time.sleep(.02)
hooks = [['iptables','-t','mangle','-A','OUTPUT','-p','tcp','-m','owner','--uid-owner','12001',
          flag,str(port),'-j','NFQUEUE','--queue-num','176']
         for port in (2525,2121,40612,990,40613,20) for flag in ['--sport','--dport']]
clients=[]
process = None; log = None; hooked = []; observer = None
def start(label):
    global process, log, runtime, generation, observer
    generation = 28401 if label == "first" else 25602
    runtime = ROOT/("build-output/product-vpp-runtime-"+runtime_tag+"-"+label)
    launch.update(PRODUCT_RUNTIME_DIR=str(runtime), PRODUCT_GENERATION=str(generation))
    log = (output/(label+'-vpp.log')).open('w')
    process = subprocess.Popen(['bash', str(ROOT/'tools/product/run-host-vpp.sh')], env=launch,
                               stdout=log, stderr=subprocess.STDOUT)
    deadline = time.monotonic()+20
    while not (runtime/'api.sock').exists():
        assert process.poll() is None, (output/(label+'-vpp.log')).read_text()
        assert time.monotonic() < deadline
        time.sleep(.05)
    while True:
        status = api(label+'-initial', 'rule-query')
        if status.get('query.adapter_available') == 'true': break
        assert time.monotonic() < deadline, status
        time.sleep(.05)
    save(label+'-process.txt', 'pid='+str(process.pid)+'\nexe='+os.readlink(f'/proc/{process.pid}/exe')
         +'\ncmd='+Path(f'/proc/{process.pid}/cmdline').read_bytes().replace(b'\0',b' ').decode())
    cli(label+'-startup', 'product packet-trace limit 4096', 'show product root lanes', 'show threads')
    if args.observation:
        observer=ObservationClient(artifact/'bin/sakamoto-product-core-host',runtime,generation,
            output/'observation/overall.json',output,env)
        observer.query('baseline')
    for hook in hooks: command(*hook); hooked.append(hook)
    return status

def stop(label):
    global process, log, observer
    for hook in hooked:
        removal=hook.copy(); removal[3]='-D'; command(*removal)
    hooked.clear()
    if observer is not None:observer.close();observer=None
    if process is not None:
        if process.poll() is None and (runtime/'cli.sock').exists():
            drain(label+'-drain'); assert 'root.stop=ok' in cli(label+'-stop','product root stop')
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
        assert not Path(f'/proc/{process.pid}').exists()
        save(label+'-stopped.txt', f'pid={process.pid}\nexit_code={process.returncode}\nabsent=True\n')
        log.close(); process = None

def submit(label, prior, lines):
    request=output/(label+'-request.txt');request.write_text('\n'.join(lines)+'\n')
    status=api(label+'-apply','rule-replace-all',prior['config.saved_revision'],request)
    (output/(label+'-source.conf')).write_bytes((config_dir/'rules.conf').read_bytes())
    return status

def configure(label, prior, protocol, target, mode=1):
    expression='0f'+target.to_bytes(4,'little').hex()
    versions=[prior.get(f'config.rule.{i}.version','0') for i in range(3)]
    lines=[f'0 {versions[0]} 4294967295 4294967295 4294967295 10 0 {protocol} 0 2 * * 0 65535 0 65535 {expression}',
           f'0 {versions[1]} 4294967295 4294967295 4294967295 20 0 {protocol} 0 2 * * 0 65535 0 65535 {expression}03',
           f'0 {versions[2]} 12001 4294967295 4294967295 100 0 {protocol} 0 1 * * 0 65535 0 65535',
           'group 10','edge 10 1 0','group 20','edge 20 1 1',
           f'bind 1 12001 2 10 {mode}','bind 2 12001 2 20 1']
    status=submit(label,prior,lines)
    assert status['config.result']=='0' and status['config.saved_revision']==status['config.active_revision'],status
    result.setdefault('configurations',[]).append(dict(label=label,revision=int(status['config.active_revision']),
        source=label+'-source.conf',query=label+'-apply.txt',expression=expression,mode=mode,protocol=protocol,target=target))
    return status

class Client:
    def __init__(self,label,application,port):
        self.label,self.protocol,self.port=label,"tcp",port
        self.application=application
        self.nonce='R2-'+label+'-'+str(time.time_ns())
        self.process=subprocess.Popen(['python3','-u',str(peer_source),'client','--host','127.0.0.2',
            '--application',application,'--source',str(port),'--nonce',self.nonce],
            env=env,user=12001,group=12001,extra_groups=[],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,text=True,bufsize=1)
        self.events=[];clients.append(self)
        assert self.read()['kind']=='connected'
    def read(self):
        assert select.select([self.process.stdout],[],[],20)[0], 'client response deadline'
        line=self.process.stdout.readline();assert line,line
        value=json.loads(line);self.events.append(value)
        save(self.label+'-client.json',json.dumps(self.events,indent=2))
        return value
    def execute(self,operation,wanted):
        self.process.stdin.write(json.dumps(dict(op=operation,timeout=1 if wanted=='timeout' else 10))+'\n')
        self.process.stdin.flush();answer=self.read()
        if answer['kind']=='tls_ready':answer=self.read()
        assert answer['kind']==wanted,answer
        return answer
    def capture(self,label,status,phase):
        time.sleep(.1);drain(label+'-drain')
        api(label+'-query','rule-query');cli(label+'-flow','show product flows')
        if args.observation:observer.query(label)
        result['cases'].append(dict(label=label,client=self.label,protocol=self.protocol,port=self.port,nonce=self.nonce,
            phase=phase,application=self.application,revision=int(status['config.active_revision']),query=label+'-query.txt',flow=label+'-flow.txt',
            generation=generation,observation=(label+'-observation.json' if args.observation else None)))
    def close(self):
        if self.process.poll() is None:
            self.execute('close','closed');self.process.wait(timeout=5)
        assert self.process.returncode==0

try:
    result['fixtures_sha256']=hashlib.sha256((args.fixtures/'fixtures.json').read_bytes()).hexdigest()
    save('fixtures.json',(args.fixtures/'fixtures.json').read_text())
    status=start('first')
    for application,port,target in [('smtp',45100,1007),('ftp',45101,1008),
                                     ('explicit',45102,1010),('implicit',45103,1010),('data',45104,1009)]:
        status=configure(application+'-observe',status,6,target)
        client=Client(application,application,port)
        client.execute('first','first_ready');client.capture(application+'-first',status,'first')
        client.execute('added','added_ready');client.capture(application+'-added',status,'added')
        status=configure(application+'-enforce',status,6,target,0)
        client.execute('send','timeout');client.capture(application+'-blocked',status,'blocked')
        status=configure(application+'-recover',status,6,target,1)
        client.execute('recv','received')
        client.execute('repeat','received');client.capture(application+'-budget',status,'budget')
        client.close()
    cache=cli('final-counters','show product flows','show product completion')
    if args.observation:observer.query('final')
    result['status']='RAW_COMPLETE'
except Exception as error:
    result['error']=repr(error);raise
finally:
    for client in clients:
        if client.process.poll() is None:
            client.process.terminate();client.process.wait(timeout=3)
    stop('final')
    endpoint.terminate();endpoint.wait(timeout=3);endpoint_log.close()
    save('hooks-after.txt',command('iptables-save','-t','mangle'))
    result['process_absent']=process is None
    result['completed_ns']=time.time_ns();save('result.json',json.dumps(result,indent=2)+'\n')
print('R2 Linux mail/file protocol facts and rules collected')
