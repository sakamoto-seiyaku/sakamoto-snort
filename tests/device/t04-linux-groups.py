#!/usr/bin/env python3
"""T04 real NFQUEUE traffic: shared groups, two actual Linux UIDs and modes."""
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
assert int(uid_map[2]) > 12002, 'two real mapped UIDs required'
env = dict(os.environ, LD_LIBRARY_PATH=str(artifact/'lib'))
vppctl = stage/'source/build-root/install-vpp-native/vpp/bin/vppctl'
runtime = ROOT/('build-output/product-vpp-runtime-t04-'+output.name)
generation = 25501
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
              policy_uids=[12001,12002])
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
hooks = [[tool, '-t', 'mangle', '-A', 'OUTPUT', '-p', 'udp', '--sport', '32000:32001', '--dport', '40608',
          '-j', 'NFQUEUE', '--queue-num', '176'] for tool in ['iptables', 'ip6tables']]
process = None; log = None; hooked = []
def start(label):
    global process, log, runtime, generation
    generation = 25501 if label == "first" else 25502
    runtime = ROOT/("build-output/product-vpp-runtime-t04-"+output.name+"-"+label)
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

versions=[(30<<16)|1,(20<<16)|1,(10<<16)|1,(5<<16)|1]
def source_lines(promote=False, reverse=False, conflict=False):
    lines=[]
    for i in range(4):
        version=versions[i];base=0
        priority,order,action=[(20,0,2),(10,9,2),(10,1,1),(10,1,2)][i]
        if promote and i==2: base=version;version=0;priority=0
        lines.append(f'{version} {base} 4294967295 4294967295 4294967295 {priority} {order} 17 3 {action} 127.0.0.0/8 127.0.0.0/8 32000 32001 40608 40608')
    edges=['group 10','group 20','edge 20 2 10',*[f'edge 10 1 {i}' for i in range(4)],'edge 20 1 3']
    bindings=['bind 1 12001 2 20 0','bind 2 12002 2 20 1','bind 3 12001 1 3 '+str(int(conflict)),'bind 4 12002 1 3 1']
    return lines+(list(reversed(edges)) if reverse else edges)+(list(reversed(bindings)) if reverse else bindings)

def probes(label,status,lifetime,winner=3):
    for app_uid,mode in [(12001,0),(12002,1)]:
        name=label+'-uid'+str(app_uid)
        before=api(name+'-before','rule-query')
        nonce=f't04-{name}-{time.time_ns()}'
        code="""import socket,sys,os,json
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',int(sys.argv[1])));s.settimeout(.6)
s.sendto(sys.argv[2].encode(),('127.0.0.2',40608))
try: received=s.recv(2048).decode()
except socket.timeout: received=None
print(json.dumps(dict(uid=os.getuid(),nonce=sys.argv[2],received=received)))
"""
        sent=subprocess.run(['python3','-c',code,str(32000+mode),nonce],user=app_uid,group=app_uid,extra_groups=[],env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=True)
        save(name+'-probe.json',sent.stdout);probe=json.loads(sent.stdout)
        declared=1 if winner==2 else 2;delivered=mode==1 or declared==1
        assert (probe['received']==nonce)==delivered,probe
        drain(name+'-drain')
        queried=api(name+'-query','rule-query')
        assert int(queried['query.winner_version'])==int(status[f'config.rule.{winner}.version']),queried
        assert queried['query.winner_action']==str(declared),queried
        assert int(queried['query.logical_hits'])==int(before['query.logical_hits'])+1,queried
        assert int(queried['query.actual_drops'])==int(before['query.actual_drops'])+int(not delivered),queried
        assert (nonce in result['endpoint'])==delivered
        result['cases'].append(dict(phase=label,uid=app_uid,mode=mode,family=4,nonce=nonce,delivered=delivered,
            declared_action=declared,rule_version=int(status[f'config.rule.{winner}.version']),revision=int(status['config.active_revision']),
            query=name+'-query.txt',before=name+'-before.txt',probe=name+'-probe.json',lifetime=lifetime,generation=generation))

try:
    status=start('first')
    status=submit('mixed',status,source_lines());assert status['config.result']=='0',status
    assert status['config.count']=='4' and status['config.active_count']=='8'
    probes('mixed',status,'first')
    status=submit('reordered',status,source_lines(reverse=True));assert status['config.result']=='0',status
    probes('reordered',status,'first')
    failed=submit('conflict',status,source_lines(conflict=True))
    assert failed['config.result']=='13' and failed['config.saved_revision']==status['config.saved_revision'],failed
    assert (output/'conflict-source.conf').read_bytes()==(output/'reordered-source.conf').read_bytes()
    probes('conflict-retained',status,'first')
    stop('first')
    status=start('restart');probes('restart',status,'restart')
    status=submit('promoted',status,source_lines(promote=True));assert status['config.result']=='0',status
    probes('promoted',status,'restart',winner=2)
    stop('restart');result['status']='RAW_COMPLETE';result['process_absent']=True
finally:
    stop('cleanup');done.set()
    for thread in threads:thread.join(2)
    for server in servers:server.close()
    save('hooks-after.txt',command('iptables-save','-t','mangle')+command('ip6tables-save','-t','mangle'))
    save('endpoint.json',json.dumps(result['endpoint']))
    result['completed_ns']=time.time_ns();save('result.json',json.dumps(result,indent=2)+'\n')
print('T04 Linux groups/two UIDs/modes/precedence/restart collected')
