#!/usr/bin/env python3
"""T14 bounded TCP reconstruction through Product NFQUEUE and actual kernel endpoints."""
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
parser.add_argument('--fixtures',type=Path,required=True)
parser.add_argument('--helper',type=Path,required=True)


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
generation = 26501
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

peer_source=ROOT/'tests/device/helpers/t14_tcp_peer.py'
save('socket-peer.py',peer_source.read_text())
result['peer_sha256']=hashlib.sha256(peer_source.read_bytes()).hexdigest()
fixtures=json.loads(args.fixtures.read_text())
endpoint=None;endpoint_log=None
def start_endpoint():
    global endpoint,endpoint_log
    endpoint_log=(output/'endpoint.jsonl').open('w')
    endpoint=subprocess.Popen(['python3','-u',str(peer_source),'server','--host','127.0.0.2','--directory',str(args.fixtures.resolve().parent)],
        env=env,user=12001,group=12001,extra_groups=[],stdout=endpoint_log,stderr=subprocess.STDOUT)
    deadline=time.monotonic()+5
    while '"kind": "ready"' not in (output/'endpoint.jsonl').read_text():
        assert endpoint.poll() is None
        assert time.monotonic()<deadline
        time.sleep(.02)
hooks = [['iptables','-t','mangle','-A','OUTPUT','-p',protocol,'-m','owner','--uid-owner','12001',
          flag,str(port),'-j','NFQUEUE','--queue-num','176']
         for protocol,port in [('tcp',40640),('tcp',40641)] for flag in ['--sport','--dport']]
clients=[]
process = None; log = None; hooked = []
def start(label):
    global process, log, runtime, generation
    generation = 26501 if label == "first" else 25602
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
    errors=[]
    for hook in hooked:
        removal=hook.copy();removal[3]='-D'
        try:command(*removal)
        except Exception as error:errors.append(repr(error))
    hooked.clear()
    if process is not None:
        try:
            if process.poll() is None and (runtime/'cli.sock').exists():
                drain(label+'-drain')
                assert 'root.stop=ok' in cli(label+'-stop','product root stop')
        except Exception as error:errors.append(repr(error))
        finally:
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
            assert not Path(f'/proc/{process.pid}').exists()
            save(label+'-stopped.txt',f'pid={process.pid}\nexit_code={process.returncode}\nabsent=True\n')
            if log is not None:log.close()
            process=None
    if errors:raise RuntimeError('runtime cleanup: '+repr(errors))

def submit(label, prior, lines):
    request=output/(label+'-request.txt');request.write_text('\n'.join(lines)+'\n')
    status=api(label+'-apply','rule-replace-all',prior['config.saved_revision'],request)
    (output/(label+'-source.conf')).write_bytes((config_dir/'rules.conf').read_bytes())
    return status

def configure(label, prior, protocol, expected_protocol_id, mode=1):
    expression='1001'
    versions=[prior.get(f'config.rule.{i}.version','0') for i in range(3)]
    lines=[f'0 {versions[0]} 4294967295 4294967295 4294967295 10 0 {protocol} 0 2 * * 0 65535 0 65535 {expression}',
           f'0 {versions[1]} 4294967295 4294967295 4294967295 20 0 {protocol} 0 2 * * 0 65535 0 65535 {expression}03',
           f'0 {versions[2]} 12001 4294967295 4294967295 100 0 {protocol} 0 1 * * 0 65535 0 65535',
           'group 10','edge 10 1 0','group 20','edge 20 1 1',
           f'bind 1 12001 2 10 {mode}',f'bind 2 12001 2 20 {mode}']
    status=submit(label,prior,lines)
    assert status['config.result']=='0' and status['config.saved_revision']==status['config.active_revision'],status
    result.setdefault('configurations',[]).append(dict(label=label,revision=int(status['config.active_revision']),
        source=label+'-source.conf',query=label+'-apply.txt',expression=expression,mode=mode,protocol=protocol,target=expected_protocol_id))
    return status


helper=args.helper.resolve()
result['helper_sha256']=hashlib.sha256(helper.read_bytes()).hexdigest()
result['helper_source_sha256']=hashlib.sha256((ROOT/'tests/device/helpers/t14-tcp-wire.c').read_bytes()).hexdigest()
(output/'wire-helper').write_bytes(helper.read_bytes())
save('wire-helper.c',(ROOT/'tests/device/helpers/t14-tcp-wire.c').read_text())
raw_hooks=[]
def capture(label,port,status,phase,mode,expected):
    drain(label+'-drain');api(label+'-query','rule-query')
    text=cli(label+'-flow','show product flows')
    rows=[dict(item.split('=',1) for item in line.split()[1:] if '=' in item)
          for line in text.splitlines() if line.startswith('flow.entry ')]
    row=next(r for r in rows if str(port) in (r['port_a'],r['port_b']))
    identity=[row['worker'],row['slot'],row['incarnation']]
    facts=api(label+'-sni','sni-query',*identity)
    assert facts.get('sni.code')=='0',facts
    assert facts['sni.result']==str(expected),facts
    stale=api(label+'-stale','sni-query',identity[0],identity[1],int(identity[2])+100000)
    assert stale.get('sni.code')!='0'
    result['cases'].append(dict(label=label,client=mode,profile='root',protocol='tcp',port=port,
        phase=phase,mode=mode,revision=int(status['config.active_revision']),query=label+'-query.txt',
        flow=label+'-flow.txt',sni=label+'-sni.txt',identity=identity,generation=generation))
    return facts

class RawClient:
    def __init__(self,mode,port,fixture):
        self.mode,self.port=mode,port
        self.gate=output/('gate-'+mode);self.gate.mkdir(mode=0o777);self.gate.chmod(0o777)
        self.base=self.gate/'probe'
        hook=['iptables','-t','raw','-I','OUTPUT','-p','tcp','--sport',str(port),'--dport','40641',
              '--tcp-flags','RST','RST','-j','DROP']
        command(*hook);raw_hooks.append(hook)
        self.log=(output/(mode+'-client.jsonl')).open('w')
        self.process=subprocess.Popen([str(helper),'12001','127.0.0.2',str(port),mode,
            str(args.fixtures.resolve().parent/(fixture+'.bin')),str(self.base)],env=env,stdout=self.log,stderr=subprocess.STDOUT)
        clients.append(self)
        result.setdefault('sessions',[]).append(dict(label=mode,mode=mode,port=port,fixture=fixture,
            generation=generation,profile='root',started_ns=time.time_ns()))
    def phase(self,name):
        deadline=time.monotonic()+15
        while not Path(str(self.base)+'.'+name).exists():
            assert self.process.poll() is None,(output/(self.mode+'-client.jsonl')).read_text()
            assert time.monotonic()<deadline,name
            time.sleep(.02)
    def release(self,name):Path(str(self.base)+'.release-'+name).touch()
    def close(self):
        self.release('complete');self.process.wait(timeout=5);self.log.close()
        assert self.process.returncode==0

try:
    start_endpoint()
    result['fixtures_sha256']=hashlib.sha256(args.fixtures.read_bytes()).hexdigest()
    save('fixtures.json',args.fixtures.read_text())
    status=start('first');status=configure('observe',status,6,1003)
    for index,(mode,fixture,expected) in enumerate((('reorder','named',1),('bytes','maximum',2),
        ('sparse','named',0),('span','named',0),('packets','named',0))):
        client=RawClient(mode,46520+index,fixture);client.phase('prefix_ready')
        capture(mode+'-prefix',client.port,status,'prefix',mode,0)
        client.release('prefix_ready');client.phase('complete')
        capture(mode+'-complete',client.port,status,'complete',mode,expected)
        client.close()
    cli('final-counters','show product flows','show product completion')
    result['status']='RAW_COMPLETE'
except Exception as error:
    result['error']=repr(error);raise
finally:
    cleanup_errors=[]
    for client in clients:
        try:
            if client.process.poll() is None:client.process.terminate();client.process.wait(timeout=3)
            client.log.close()
        except Exception as error:cleanup_errors.append(repr(error))
    for hook in raw_hooks:
        removal=hook.copy();removal[3]='-D'
        try:command(*removal)
        except Exception as error:cleanup_errors.append(repr(error))
    try:stop('final')
    except Exception as error:cleanup_errors.append(repr(error))
    if endpoint is not None:endpoint.terminate();endpoint.wait(timeout=3)
    if endpoint_log is not None:endpoint_log.close()
    save('hooks-after.txt',command('iptables-save','-t','mangle')+command('iptables-save','-t','raw'))
    result['process_absent']=(process is None and (endpoint is None or endpoint.poll() is not None)
                              and all(client.process.poll() is not None for client in clients))
    if cleanup_errors:result['cleanup_error']=cleanup_errors
    result['completed_ns']=time.time_ns();save('result.json',json.dumps(result,indent=2)+'\n')
    if cleanup_errors:raise RuntimeError('cleanup: '+repr(cleanup_errors))
print('T14 Linux TCP reordered/duplicate/bounded inputs and endpoint receipts collected')
