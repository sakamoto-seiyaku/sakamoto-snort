#!/usr/bin/env python3
"""T01: real Product API -> saved source -> NFQUEUE UDP outcome, isolated netns."""
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
parser.add_argument('--artifact', type=Path, required=True)
parser.add_argument('--stage', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--build', type=Path, required=True)
args = parser.parse_args()
artifact, stage, output = (p.resolve() for p in (args.artifact, args.stage, args.output))
output.mkdir(parents=True, exist_ok=False)
assert os.getuid() == 0
uid_map = Path('/proc/self/uid_map').read_text().split()
assert len(uid_map) == 3 and uid_map[0] == '0' and uid_map[1] != '0' and uid_map[2] == '1'
env = dict(os.environ, LD_LIBRARY_PATH=str(artifact/'lib'))
vppctl = stage/'source/build-root/install-vpp-native/vpp/bin/vppctl'
runtime = ROOT/('build-output/product-vpp-runtime-t02-'+output.name)
generation = 25301
config_dir = output/'configuration'
result = dict(status='HOLD', generation=generation, profile='root', source='NFQ_CAPTURED',
              cases=[], endpoint=[], started_ns=time.time_ns(), artifact=str(artifact),
              manifest_sha256=hashlib.sha256((artifact/'product-vpp-artifact.properties').read_bytes()).hexdigest())
build_path=args.build.resolve()
build=json.loads(build_path.read_text())
assert Path(build['artifact']) == artifact
for name, expected in build['artifact_hashes'].items():
    assert hashlib.sha256((artifact/name).read_bytes()).hexdigest()==expected,name
result.update(build=str(build_path),build_sha256=hashlib.sha256(build_path.read_bytes()).hexdigest(),
              source_sha256=build['source_sha256'],runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              policy_uid=int(uid_map[1]))
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
              SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0', SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4')

servers = []
done = threading.Event()
threads = []
for family, address in [(socket.AF_INET, '127.0.0.2'), (socket.AF_INET6, '::1')]:
    server = socket.socket(family, socket.SOCK_DGRAM)
    server.bind((address, 40608)); server.settimeout(.1); servers.append(server)
    def endpoint(server=server):
        while not done.is_set():
            try: data, peer = server.recvfrom(2048)
            except socket.timeout: continue
            result['endpoint'].append(data.decode()); server.sendto(data, peer)
    thread = threading.Thread(target=endpoint); thread.start(); threads.append(thread)
hooks = [[tool, '-t', 'mangle', '-A', 'OUTPUT', '-p', 'udp', '--sport', '32000', '--dport', '40608',
          '-j', 'NFQUEUE', '--queue-num', '176'] for tool in ['iptables', 'ip6tables']]
process = None; log = None; hooked = []
def start(label):
    global process, log, runtime, generation
    generation = 25301 if label == "first" else 25302
    runtime = ROOT/("build-output/product-vpp-runtime-t02-"+output.name+"-"+label)
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

def submit(label, prior, action, excess=False):
    lines=[]
    for i,(source,destination) in enumerate([('127.0.0.0/8','127.0.0.0/8'),('::1/128','::1/128')]):
        base=prior.get(f'config.rule.{i}.version','0')
        lines.append(f'0 {base} {uid_map[1]} 4294967295 4294967295 0 {i} 17 3 {action} {source} {destination} 31999 32001 40600 40610')
    if excess:
        for i in range(127): lines.append(f'0 0 {20000+i} 4294967295 4294967295 0 0 6 0 2 0.0.0.0/0 0.0.0.0/0 0 65535 0 65535')
    request=output/(label+'-request.txt');request.write_text('\n'.join(lines)+'\n')
    status=api(label+'-apply','rule-replace-all',prior['config.saved_revision'],request)
    source=config_dir/'rules.conf'
    if source.exists(): (output/(label+'-source.conf')).write_bytes(source.read_bytes())
    return status

def probes(label, status, active_versions, active_revision, delivered, lifetime):
    for i,(family,source,destination) in enumerate([(socket.AF_INET,'127.0.0.1','127.0.0.2'),(socket.AF_INET6,'::1','::1')]):
        nonce=f't02-{label}-v{4 if i==0 else 6}-{time.time_ns()}'
        with socket.socket(family,socket.SOCK_DGRAM) as probe:
            probe.bind((source,32000));probe.settimeout(.5);probe.sendto(nonce.encode(),(destination,40608))
            try: received=probe.recv(2048).decode()
            except socket.timeout: received=None
        assert (received==nonce)==delivered
        drain(label+f'-v{i}-drain')
        queried=api(label+f'-v{i}-query','rule-query')
        assert queried['config.saved_revision']==status['config.saved_revision']
        assert int(queried['query.winner_version'])==active_versions[i],queried
        assert int(queried['query.winner_revision'])==active_revision,queried
        assert int(queried['query.winner_action'])==(1 if delivered else 2),queried
        assert (nonce in result['endpoint'])==delivered
        result['cases'].append(dict(phase=label,family=4 if i==0 else 6,nonce=nonce,delivered=delivered,
            rule_version=active_versions[i],revision=active_revision,saved_revision=int(status['config.saved_revision']),
            query=label+f'-v{i}-query.txt',lifetime=lifetime,generation=generation))

try:
    status=start('first'); assert status['config.saved_revision']==status['config.active_revision']=='1'
    for label,action in [('allow',1),('drop',2)]:
        status=submit(label,status,action); assert status['config.result']=='0',status
        active=[int(status[f'config.rule.{i}.version']) for i in range(2)]
        revision=int(status['config.active_revision']);probes(label,status,active,revision,action==1,'first')
    original=(config_dir/'rules.conf').read_bytes(); moved=output/'configuration-unavailable'
    config_dir.rename(moved)
    try: failed=submit('save-failure',status,1)
    finally: moved.rename(config_dir)
    assert failed['config.result']==failed['config.save_error']=='3',failed
    assert failed['config.saved_revision']==status['config.saved_revision']
    assert (config_dir/'rules.conf').read_bytes()==original
    (output/'save-failure-source.conf').write_bytes(original)
    probes('save-failure',failed,active,revision,False,'first')
    failed=submit('compile-failure',status,1,excess=True)
    assert failed['config.result']==failed['config.compile_error']=='5' and failed['config.count']=='129',failed
    assert failed['config.active_revision']==status['config.active_revision']
    assert int(failed['config.saved_revision'])==int(status['config.saved_revision'])+1
    probes('compile-failure',failed,active,revision,False,'first')
    status=submit('recover',failed,1);assert status['config.result']=='0',status
    active=[int(status[f'config.rule.{i}.version']) for i in range(2)]
    revision=int(status['config.active_revision']);probes('recover',status,active,revision,True,'first')
    saved=(config_dir/'rules.conf').read_bytes();stop('first')
    assert (config_dir/'rules.conf').read_bytes()==saved
    status=start('restart');assert int(status['config.saved_revision'])==int(status['config.active_revision'])==revision
    assert [int(status[f'config.rule.{i}.version']) for i in range(2)]==active
    probes('restart',status,active,revision,True,'restart');stop('restart')
    result['status']='RAW_COMPLETE';result['process_absent']=True
finally:
    stop('cleanup');done.set()
    for thread in threads:thread.join(2)
    for server in servers:server.close()
    save('hooks-after.txt',command('iptables-save','-t','mangle')+command('ip6tables-save','-t','mangle'))
    save('endpoint.json',json.dumps(result['endpoint']))
    result['completed_ns']=time.time_ns();save('result.json',json.dumps(result,indent=2)+'\n')
print('T02 Linux complete source/failures/dual-stack/restart collected')
