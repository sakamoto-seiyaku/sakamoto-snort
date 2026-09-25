#!/usr/bin/env python3
"""T08 real NFQUEUE TCP/UDP: live CT, direction, Rank and snapshot replacement."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import select
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--artifact', type=Path, required=True)
parser.add_argument('--stage', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--build', type=Path, required=True)
parser.add_argument('--rule-session',type=Path,required=True)

args = parser.parse_args()
artifact, stage, output = (p.resolve() for p in (args.artifact, args.stage, args.output))
output.mkdir(parents=True, exist_ok=False)
assert os.getuid() == 0
uid_map = Path('/proc/self/uid_map').read_text().split()
assert int(uid_map[2]) > 12002, 'two real mapped UIDs required'
env = dict(os.environ, LD_LIBRARY_PATH=str(artifact/'lib'))
vppctl = stage/'source/build-root/install-vpp-native/vpp/bin/vppctl'
# Keep every VPP Unix socket below sockaddr_un.sun_path, including stats.sock.
runtime_tag = hashlib.sha256(str(output).encode()).hexdigest()[:12]
runtime = ROOT/('build-output/product-vpp-runtime-'+runtime_tag)
generation = 25901
config_dir = output/'configuration'
result = dict(status='HOLD', generation=generation, profile='root', source='NFQ_CAPTURED',
              cases=[], started_ns=time.time_ns(), artifact=str(artifact),
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

peer_source=ROOT/'tests/device/helpers/t07_socket_peer.py'
save('socket-peer.py',peer_source.read_text())
result['peer_sha256']=hashlib.sha256(peer_source.read_bytes()).hexdigest()
endpoint_log=(output/'endpoint.jsonl').open('w')
endpoint=subprocess.Popen(['python3','-u',str(peer_source),'server','--host','127.0.0.2','--port','40610'],
    user=12001,group=12001,extra_groups=[],stdout=endpoint_log,stderr=subprocess.STDOUT)
deadline=time.monotonic()+5
while '"kind": "ready"' not in (output/'endpoint.jsonl').read_text():
    assert endpoint.poll() is None
    assert time.monotonic()<deadline
    time.sleep(.02)
hooks = [['iptables','-t','mangle','-A','OUTPUT','-p',protocol,'-m','owner','--uid-owner','12001',
          flag,'40610','-j','NFQUEUE','--queue-num','176']
         for protocol in ['tcp','udp'] for flag in ['--sport','--dport']]
clients=[]
rule_session=None
process = None; log = None; hooked = []
def start(label):
    global process, log, runtime, generation
    generation = 25901 if label == "first" else 25602
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
    for hook in hooks: command(*hook); hooked.append(hook)
    return status

def stop(label):
    global process, log
    for hook in hooked:
        removal=hook.copy(); removal[3]='-D'; command(*removal)
    hooked.clear()
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

import sys
sys.path.insert(0,str(ROOT/'tests/device/helpers'))
from t08_rules import request as rule_request
rule_helper=ROOT/'tests/device/helpers/t08_rules.py'
save('rule-request-helper.py',rule_helper.read_text())
result['rule_helper_sha256']=hashlib.sha256(rule_helper.read_bytes()).hexdigest()

def configure(label, prior, protocol, scenario, mode=0):
    status=submit(label,prior,rule_request(prior,12001,protocol,scenario,mode))
    assert status['config.result']=='0' and status['config.saved_revision']==status['config.active_revision'],status
    result.setdefault('configurations',[]).append(dict(label=label,revision=int(status['config.active_revision']),
        source=label+'-source.conf',query=label+'-apply.txt',scenario=scenario,mode=mode,protocol=protocol))
    cli(label+'-index', 'show product policy-index', 'show runtime', 'show memory')
    return status

class Client:
    def __init__(self,label,protocol,port):
        self.label,self.protocol,self.port=label,protocol,port
        self.process=subprocess.Popen(['python3','-u',str(peer_source),'client','--host','127.0.0.2',
            '--port','40610','--protocol',protocol,'--source-port',str(port)],
            user=12001,group=12001,extra_groups=[],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,text=True,bufsize=1)
        self.events=[];clients.append(self)
        assert self.read()['kind']=='connected'
    def read(self):
        assert select.select([self.process.stdout],[],[],12)[0], 'client response deadline'
        line=self.process.stdout.readline();assert line,line
        value=json.loads(line);self.events.append(value)
        save(self.label+'-client.json',json.dumps(self.events,indent=2))
        return value
    def begin(self,request):
        self.process.stdin.write(json.dumps(request)+'\n');self.process.stdin.flush()
    def exchange(self,label,status,delivered=True,nonce=None,receive_only=False):
        nonce=nonce or f't08-{label}-{time.time_ns()}'
        before=api(label+'-before','rule-query')
        self.begin(dict(op='recv' if receive_only else 'send',data='' if receive_only else nonce,
                        length=len(nonce),timeout=10 if receive_only else .8))
        if not receive_only:assert self.read()['kind']=='sent'
        answer=self.read();assert (answer['kind']=='received' and bytes.fromhex(answer['data']).decode()==nonce)==delivered,answer
        time.sleep(.1);drain(label+'-drain')
        queried=api(label+'-query','rule-query');cli(label+'-flow','show product flows', 'show product policy-index', 'show runtime')
        result['cases'].append(dict(label=label,client=self.label,protocol=self.protocol,port=self.port,nonce=nonce,
            delivered=delivered,receive_only=receive_only,revision=int(status['config.active_revision']),
            before=label+'-before.txt',query=label+'-query.txt',response=answer))
        return nonce
    def close(self):
        if self.process.poll() is None:
            self.begin(dict(op='close'));self.process.wait(timeout=5)
        assert self.process.returncode==0

try:
    status=start('first')
    for protocol,number,baseport in [('tcp',6,43100),('udp',17,43200)]:
        for index,scenario in enumerate(['chain','early-drop']):
            label=protocol+'-'+scenario
            status=configure(label+'-observe',status,number,scenario,1)
            client=Client(label,protocol,baseport+index)
            client.exchange(label+'-initial',status)
            status=configure(label+'-enforce',status,number,scenario,0)
            nonce=client.exchange(label+'-blocked',status,False)
            assert int(api(label+'-drop-check','rule-query')['query.actual_drops'])>0
            status=configure(label+'-recover',status,number,scenario,1)
            client.exchange(label+'-recovered',status,nonce=nonce if protocol=='tcp' else None,receive_only=protocol=='tcp')
            client.close()
        status=configure(protocol+'-static-first',status,number,'static-first')
        client=Client(protocol+'-static-first',protocol,baseport+2)
        client.exchange(protocol+'-static-wins',status);client.close()
    # A held old reader must use its complete old post-flow view after a new
    # configuration becomes active. The next packet must use the new view.
    status=configure('race-observe',status,17,'early-drop',1)
    client=Client('race','udp',43300);client.exchange('race-initial',status)
    status=configure('race-old-enforce',status,17,'early-drop',0)
    rule_session=subprocess.Popen([str(args.rule_session.resolve()),str(runtime/'api.sock'),str(generation)],
        env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
    assert rule_session.stdout.readline().strip()=='ready'
    helper_source=ROOT/'tests/device/helpers/t08_rule_session.c'
    save('rule-session.c',helper_source.read_text())
    result['rule_session']=dict(path=str(args.rule_session.resolve()),sha256=hashlib.sha256(args.rule_session.read_bytes()).hexdigest(),
        source_sha256=hashlib.sha256(helper_source.read_bytes()).hexdigest())
    trace=(output/'first-vpp.log').read_text()
    packets=[dict(w.split('=',1) for w in line.split()[1:] if '=' in w)
             for line in trace.splitlines() if line.startswith('s216 stage=admit ')]
    packet=next(p for p in reversed(packets) if bytes.fromhex(p['raw'])[20:22]==struct.pack('!H',43300))
    cli('race-hold','product policy hold-next '+packet['owner']+' 500000')
    old_offset=len((output/'first-vpp.log').read_text())
    nonce='t08-race-held-'+str(time.time_ns())
    client.begin(dict(op='send',data=nonce,timeout=1.2));assert client.read()['kind']=='sent'
    deadline=time.monotonic()+2
    while 's209 event=hold_begin' not in (output/'first-vpp.log').read_text()[old_offset:]:
        assert time.monotonic()<deadline
        time.sleep(.005)
    old_revision=int(status['config.active_revision'])
    publication_started=time.monotonic_ns()
    rule_session.stdin.write(str(old_revision)+' 1\n');rule_session.stdin.flush()
    answer=json.loads(rule_session.stdout.readline())
    publication_completed=time.monotonic_ns()
    save('race-session-publication.json',json.dumps(dict(started_ns=publication_started,completed_ns=publication_completed,**answer)))
    assert answer['rc']==answer['result']==0 and answer['saved_revision']==answer['active_revision']==old_revision+1
    # This readback intentionally happens only after publication; client creation
    # may wait for a worker barrier and must not be part of the race trigger.
    response=client.read();assert response['kind']=='timeout',response
    status=api('race-new-observe-apply','rule-query')
    cli('race-new-observe-index', 'show product policy-index', 'show runtime', 'show memory')
    (output/'race-new-observe-source.conf').write_bytes((config_dir/'rules.conf').read_bytes())
    result['configurations'].append(dict(label='race-new-observe',revision=int(status['config.active_revision']),
        source='race-new-observe-source.conf',query='race-new-observe-apply.txt',scenario='early-drop',mode=1,protocol=17))
    answer=response
    result['race']=dict(nonce=nonce,old_revision=old_revision,new_revision=int(status['config.active_revision']),
                        response=answer,port=43300)
    client.exchange('race-new-packet',status);client.close()
    cli('final-flow','show product flows', 'show product policy-index', 'show runtime');api('final-query','rule-query')
    stop('first');result['status']='RAW_COMPLETE';result['process_absent']=True
finally:
    for client in clients:
        if client.process.poll() is None:
            client.process.terminate();client.process.wait(timeout=3)
    if rule_session:
        rule_session.stdin.close();rule_session.wait(timeout=3)
    stop('cleanup')
    endpoint.terminate();endpoint.wait(timeout=3);endpoint_log.close()
    save('hooks-after.txt',command('iptables-save','-t','mangle'))
    result['completed_ns']=time.time_ns();save('result.json',json.dumps(result,indent=2)+'\n')
print('T08 Linux CT/state/direction/Rank/observe/live update and held snapshot collected')
