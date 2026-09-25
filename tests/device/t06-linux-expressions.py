#!/usr/bin/env python3
"""T06 real NFQUEUE traffic: static AND/OR/NOT, unavailable input and port boundary."""
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
runtime = ROOT/('build-output/product-vpp-runtime-t06-'+output.name)
generation = 25701
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

servers = []
done = threading.Event()
threads = []
for family, address in [(socket.AF_INET, '127.0.0.2'), (socket.AF_INET6, '::1')]:
    server = socket.socket(family, socket.SOCK_DGRAM)
    server.bind((address, 65535)); server.settimeout(.1); servers.append(server)
    def endpoint(server=server):
        while not done.is_set():
            try: data, peer = server.recvfrom(2048)
            except socket.timeout: continue
            result['endpoint'].append(data.decode()); server.sendto(data, peer)
    thread = threading.Thread(target=endpoint); thread.start(); threads.append(thread)
hooks = [[tool, '-t', 'mangle', '-A', 'OUTPUT', '-p', 'udp', '--sport', '65534:65535', '--dport', '65535',
          '-j', 'NFQUEUE', '--queue-num', '176'] for tool in ['iptables', 'ip6tables']]
process = None; log = None; hooked = []
def start(label):
    global process, log, runtime, generation
    generation = 25701 if label == "first" else 25602
    runtime = ROOT/("build-output/product-vpp-runtime-t06-"+output.name+"-"+label)
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

def submit_expression(label, prior, expression, observe=False):
    base = prior.get('config.rule.0.version', '0')
    uid = 4294967295 if observe else 12001
    lines = [f'0 {base} {uid} 4294967295 4294967295 1 0 17 3 2 * * 0 65535 0 65535 {expression}',
             '1966081 0 12001 4294967295 4294967295 100 0 17 3 1 * * 0 65535 0 65535']
    if observe: lines += ['group 10', 'edge 10 1 0', 'bind 1 12001 2 10 1']
    status = submit(label, prior, lines)
    assert status['config.result']=='0' and status['config.saved_revision']==status['config.active_revision'],status
    return status

def probes(label, status, drop_port, observe=False):
    for sport in [65534,65535]:
        hit = sport == drop_port
        winner = 0 if hit else 1
        delivered = not hit or observe
        name = label+'-'+str(sport)
        before = api(name+'-before','rule-query')
        nonce = f't06-{name}-{time.time_ns()}'
        code = """import socket,sys,os,json
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',int(sys.argv[1])));s.settimeout(.6)
s.sendto(sys.argv[2].encode(),('127.0.0.2',65535))
try: received=s.recv(2048).decode()
except socket.timeout: received=None
print(json.dumps(dict(uid=os.getuid(),nonce=sys.argv[2],received=received)))
"""
        sent = subprocess.run(['python3','-c',code,str(sport),nonce], user=12001,group=12001,extra_groups=[],
                              env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=True)
        save(name+'-probe.json',sent.stdout); probe=json.loads(sent.stdout)
        assert (probe['received']==nonce)==delivered,probe
        drain(name+'-drain')
        queried=api(name+'-query','rule-query')
        assert queried['query.winner_version']==status[f'config.rule.{winner}.version'],queried
        assert queried['query.winner_action']==str(2 if hit else 1),queried
        assert int(queried['query.logical_hits'])==int(before['query.logical_hits'])+1,queried
        assert int(queried['query.actual_drops'])==int(before['query.actual_drops'])+int(not delivered),queried
        assert (nonce in result['endpoint'])==delivered
        result['cases'].append(dict(phase=label,uid=12001,mode=int(observe and hit),family=4,nonce=nonce,
            delivered=delivered,declared_action=2 if hit else 1,source_port=sport,destination_port=65535,
            rule_version=int(status[f'config.rule.{winner}.version']),revision=int(status['config.active_revision']),
            query=name+'-query.txt',before=name+'-before.txt',probe=name+'-probe.json',lifetime='first',generation=generation,
            source_file=label+'-source.conf'))

try:
    status=start('first')
    # Full source update, same logical expression rule. No network facts are
    # published: NOT(network=1) is unavailable, not true.
    for label, expression, hit in [
        ('and','0cffffffff0bffffffff01',65535),
        ('or','0701000000030bffffffff02',65535),
        ('not','0bffffffff03',65534),
        ('observe','0bffffffff03',65534)]:
        status=submit_expression(label,status,expression,label=='observe')
        probes(label,status,hit,label=='observe')
    stop('first');result['status']='RAW_COMPLETE';result['process_absent']=True

finally:
    stop('cleanup');done.set()
    for thread in threads:thread.join(2)
    for server in servers:server.close()
    save('hooks-after.txt',command('iptables-save','-t','mangle')+command('ip6tables-save','-t','mangle'))
    save('endpoint.json',json.dumps(result['endpoint']))
    result['completed_ns']=time.time_ns();save('result.json',json.dumps(result,indent=2)+'\n')
print('T06 Linux AND/OR/NOT/unavailable input/boundary ports/observe collected')
