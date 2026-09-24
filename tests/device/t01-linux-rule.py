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
runtime = ROOT/('build-output/product-vpp-runtime-t01-'+output.name)
generation = 25201
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
                                   runtime/'api.sock', generation, *values))
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
log = (output/'vpp.log').open('w')
process = subprocess.Popen(['bash', str(ROOT/'tools/product/run-host-vpp.sh')], env=launch,
                           stdout=log, stderr=subprocess.STDOUT)
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(('127.0.0.2',40608)); server.settimeout(.1)
done = threading.Event()
def endpoint():
    while not done.is_set():
        try: data, peer = server.recvfrom(2048)
        except socket.timeout: continue
        result['endpoint'].append(data.decode()); server.sendto(data, peer)
thread = threading.Thread(target=endpoint); thread.start()
hook = ['iptables','-t','mangle','-A','OUTPUT','-p','udp','--sport','32000','--dport','40608',
        '-j','NFQUEUE','--queue-num','176']
hooked = False
try:
    deadline = time.monotonic()+15
    while not (runtime/'api.sock').exists():
        assert process.poll() is None, (output/'vpp.log').read_text()
        assert time.monotonic() < deadline
        time.sleep(.05)
    # Adapter startup is asynchronous; the status query is an actual product API.
    while True:
        status = api('initial', 'rule-query')
        if status['query.adapter_available'] == 'true': break
        assert time.monotonic() < deadline, status
        time.sleep(.05)
    assert status['config.saved_revision'] == status['config.active_revision'] == '1'
    assert status['config.present'] == '0'
    result['pid']=process.pid
    save('process-exe.txt',os.readlink(f'/proc/{process.pid}/exe')+'\n')
    save('process-stat.txt',Path(f'/proc/{process.pid}/stat').read_text())
    save('process-command.txt',Path(f'/proc/{process.pid}/cmdline').read_bytes().replace(b'\0',b' ').decode())
    cli('startup', 'product packet-trace limit 256', 'show product root lanes', 'show threads')
    command(*hook); hooked = True
    save('hooks.txt', command('iptables-save','-t','mangle'))
    revision = 1
    version = None
    for phase, action, delivered in [('allow', 'allow', True), ('drop','drop',False), ('recover','allow',True)]:
        # NFQA_UID is reported in the initial namespace on this kernel.
        status = api(phase+'-apply', 'rule-replace', revision, uid_map[1], '127.0.0.1', '127.0.0.2', 32000, 40608, action)
        revision += 1
        assert int(status['config.saved_revision']) == int(status['config.active_revision']) == revision
        current_version = int(status['config.saved_rule_version'])
        assert current_version >> 16 and current_version & 65535 == (revision-1)
        if version is not None: assert current_version == version+1
        version = current_version
        nonce = f't01-{phase}-{time.time_ns()}'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(('127.0.0.1',32000)); probe.settimeout(.5)
            probe.sendto(nonce.encode(),('127.0.0.2',40608))
            try: received = probe.recv(2048).decode()
            except socket.timeout: received = None
        assert (received == nonce) == delivered
        drain(phase+'-drain')
        queried = api(phase+'-query','rule-query')
        assert int(queried['query.winner_version']) == version, queried
        assert int(queried['query.winner_revision']) == revision
        assert int(queried['query.winner_action']) == (1 if delivered else 2)
        assert int(queried['query.verdict']) == (1 if delivered else 2)
        assert (nonce in result['endpoint']) == delivered
        result['cases'].append(dict(phase=phase, nonce=nonce, delivered=delivered,
                                    rule_version=version, revision=revision))
        save(phase+'-source.conf',(config_dir/'rules.conf').read_text())
        cli(phase+'-graph','show product flows','show product completion')
    result['status'] = 'RAW_COMPLETE'
except Exception as error:
    result['error']=repr(error)
    raise
finally:
    if hooked:
        removal=hook.copy();removal[3]='-D';command(*removal)
    done.set();thread.join(2);server.close()
    if process.poll() is None and (runtime/'cli.sock').exists():
        drain('final-drain');assert 'root.stop=ok' in cli('stop','product root stop')
        cli('stopped','show product completion','show product root lanes','show product flows')
        free={}
        for queue in range(176,180):
            with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12) as channel:
                channel.bind((0,0));channel.settimeout(2)
                payload=struct.pack('!BBH',0,0,queue)+struct.pack('HH',8,1)+struct.pack('!BBH',1,0,2)
                channel.send(struct.pack('IHHII',16+len(payload),0x302,5,1,0)+payload)
                reply=channel.recv(4096)
                assert struct.unpack_from('H',reply,4)[0]==2
                free[queue]=struct.unpack_from('i',reply,16)[0]
        save('queues-free.json',json.dumps(free));assert all(code==0 for code in free.values())
    if process.poll() is None:
        process.terminate()
        try: process.wait(timeout=10)
        except subprocess.TimeoutExpired: process.kill();process.wait(timeout=5)
    log.close()
    result['process_absent'] = not Path(f'/proc/{process.pid}').exists()
    save('process-stopped.txt',f'pid={process.pid}\nexit_code={process.returncode}\nabsent={result["process_absent"]}\n')
    save('endpoint.json',json.dumps(result['endpoint']))
    save('hooks-after.txt',command('iptables-save','-t','mangle'))
    result['completed_ns'] = time.time_ns()
    save('result.json',json.dumps(result,indent=2)+'\n')
print('T01 Linux real API/NFQUEUE chain complete')
