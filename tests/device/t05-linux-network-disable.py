#!/usr/bin/env python3
"""T05 real NFQUEUE traffic: ordinary network disabling and shared observe groups."""
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
runtime = ROOT/('build-output/product-vpp-runtime-t05-'+output.name)
generation = 25601
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
              SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0', SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4',
              SAKAMOTO_LINUX_NETWORK_SOURCE='external')

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
    generation = 25601 if label == "first" else 25602
    runtime = ROOT/("build-output/product-vpp-runtime-t05-"+output.name+"-"+label)
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
def source_lines():
    lines=[]
    for i in range(4):
        priority,order,action=[(20,0,2),(10,9,2),(10,1,1),(10,1,2)][i]
        lines.append(f'{versions[i]} 0 4294967295 4294967295 4294967295 {priority} {order} 17 3 {action} 127.0.0.0/8 127.0.0.0/8 32000 32001 40608 40608')
    return lines+['group 10','group 20','edge 20 2 10',*[f'edge 10 1 {i}' for i in range(4)],
                  'edge 20 1 3','bind 1 12001 2 20 1','bind 2 12002 2 20 1',
                  'bind 3 12001 1 3 1','bind 4 12002 1 3 1']

network_revision=0
network_context=1
helper=output/'network-publish'
helper_source=ROOT/'tests/device/helpers/s235-policy.c'
command('cc','-Wall','-Wextra','-Werror','-I',ROOT/'src/product/include',helper_source,
        '-L',build_path.parent/'control','-lsakamoto_product_core',
        '-Wl,-rpath,'+str(build_path.parent/'control'),'-Wl,-rpath-link,'+str(artifact/'lib'),
        '-o',helper)
result['network_helper']=dict(source_sha256=hashlib.sha256(helper_source.read_bytes()).hexdigest(),
                              binary_sha256=hashlib.sha256(helper.read_bytes()).hexdigest())
(output/'network-helper.c').write_bytes(helper_source.read_bytes())
def network(label,context):
    global network_revision,network_context
    network_revision+=1;network_context=context
    save(label+'-network.txt',command(helper,runtime/'api.sock',generation,output,
             network_revision,4,12001,context,1))

def toggle(label,prior,blocked):
    request=output/(label+'-request.txt')
    request.write_text('0 0 12001 1 1 0 0 0 3 '+str(2 if blocked else 1)+' * * 0 65535 0 65535\n')
    status=api(label+'-apply','rule-network-disable',prior['config.saved_revision'],request)
    assert status['config.result']=='0',status
    (output/(label+'-source.conf')).write_bytes((config_dir/'rules.conf').read_bytes())
    return status

def probes(label,status,lifetime,disabled=False,observe_switch=False):
    for app_uid in [12001,12002]:
        winner=4 if observe_switch or (disabled and app_uid==12001 and network_context==1) else 3
        mode=0 if winner==4 and not observe_switch else 1
        name=label+'-uid'+str(app_uid)
        before=api(name+'-before','rule-query')
        nonce=f't05-{name}-{time.time_ns()}'
        code="""import socket,sys,os,json
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',int(sys.argv[1])));s.settimeout(.6)
s.sendto(sys.argv[2].encode(),('127.0.0.2',40608))
try: received=s.recv(2048).decode()
except socket.timeout: received=None
print(json.dumps(dict(uid=os.getuid(),nonce=sys.argv[2],received=received)))
"""
        sent=subprocess.run(['python3','-c',code,str(32000+(app_uid==12002)),nonce],user=app_uid,group=app_uid,extra_groups=[],env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=True)
        save(name+'-probe.json',sent.stdout);probe=json.loads(sent.stdout)
        declared=2;delivered=mode==1
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
            query=name+'-query.txt',before=name+'-before.txt',probe=name+'-probe.json',lifetime=lifetime,generation=generation,network_context=network_context,
            source_file=label+'-source.conf'))

try:
    status=start('first');network('wifi',1)
    status=submit('shared',status,source_lines());assert status['config.result']=='0',status
    assert status['config.count']=='4' and status['config.active_count']=='8'
    probes('shared',status,'first')
    status=toggle('disabled',status,True)
    assert status['config.count']=='5' and status['config.active_count']=='9'
    probes('disabled',status,'first',disabled=True)
    network('mobile',2)
    (output/'outside-source.conf').write_bytes((config_dir/'rules.conf').read_bytes())
    probes('outside',status,'first',disabled=True)
    network('wifi-again',1)
    status=toggle('enabled',status,False)
    assert status['config.count']=='4' and status['config.active_count']=='8'
    probes('enabled',status,'first')
    status=toggle('disabled-again',status,True)
    # Full source API can make this same ordinary rule reusable and observed.
    switch_version=status['config.rule.4.version']
    lines=source_lines()
    rule=f'0 {switch_version} 4294967295 1 1 0 0 0 3 2 * * 0 65535 0 65535'
    lines.insert(4,rule);lines.append('edge 10 1 4')
    status=submit('observe-switch',status,lines);assert status['config.result']=='0',status
    assert status['config.count']=='5' and status['config.active_count']=='10'
    assert int(status['config.rule.4.version'])==int(switch_version)+1
    probes('observe-switch',status,'first',observe_switch=True)
    stop('first')
    status=start('restart');network('restart-wifi',1)
    (output/'restart-source.conf').write_bytes((config_dir/'rules.conf').read_bytes())
    probes('restart',status,'restart',observe_switch=True)
    stop('restart');result['status']='RAW_COMPLETE';result['process_absent']=True

finally:
    stop('cleanup');done.set()
    for thread in threads:thread.join(2)
    for server in servers:server.close()
    save('hooks-after.txt',command('iptables-save','-t','mangle')+command('ip6tables-save','-t','mangle'))
    save('endpoint.json',json.dumps(result['endpoint']))
    result['completed_ns']=time.time_ns();save('result.json',json.dumps(result,indent=2)+'\n')
print('T05 Linux ordinary disable/shared observe/two UIDs/network scopes/restart collected')
