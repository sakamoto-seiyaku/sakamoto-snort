#!/usr/bin/env python3
"""SAKAMOTO-296: Product Root N=1/2/3 packet, owner, affinity and stop seam."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import socket
import struct
import subprocess
import threading
import time
from collections import Counter

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--artifact', type=Path, required=True)
parser.add_argument('--stage', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--build', type=Path, required=True)
parser.add_argument('--owners', type=int, choices=(1, 2, 3), default=3)
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
              owners=args.owners,
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
allowed = sorted(os.sched_getaffinity(0))
assert {0, 1, 2}.issubset(allowed), 'N=3 1,2,1 affinity requires CPUs 0,1,2 allowed'
owner_cpus = [1] if args.owners == 1 else [1, 2] if args.owners == 2 else [1, 2, 1]
launch = dict(env, PRODUCT_ARTIFACT_DIR=str(artifact), PRODUCT_RUNTIME_DIR=str(runtime),
              PRODUCT_RULE_CONFIG_DIR=str(config_dir), PRODUCT_GENERATION=str(generation),
              PRODUCT_WORKER_COUNT=str(args.owners), SAKAMOTO_RUNTIME_PROFILE='root',
              SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0', SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4',
              PRODUCT_MAIN_CPU='0', PRODUCT_WORKER_CPUS=','.join(map(str, owner_cpus)))
log = (output/'vpp.log').open('w')
process = subprocess.Popen(['bash', str(ROOT/'tools/product/run-host-vpp.sh')], env=launch,
                           stdout=log, stderr=subprocess.STDOUT)
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(('127.0.0.2',40608)); server.settimeout(.1)
server_v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
if server_v6:
    server_v6.bind(('::1',40610)); server_v6.settimeout(.1)
done = threading.Event()
def endpoint(channel):
    while not done.is_set():
        try: data, peer = channel.recvfrom(2048)
        except socket.timeout: continue
        result['endpoint'].append(data.decode()); channel.sendto(data, peer)
threads = [threading.Thread(target=endpoint, args=(server,))]
if server_v6: threads.append(threading.Thread(target=endpoint, args=(server_v6,)))
for thread in threads: thread.start()
hook = ['iptables','-t','mangle','-A','OUTPUT','-p','udp','--dport','40608',
        '-j','NFQUEUE','--queue-num','176']
hooks = [hook,
    ['iptables','-t','mangle','-A','OUTPUT','-p','udp','--sport','40608',
     '-j','NFQUEUE','--queue-num','177'],
    ['ip6tables','-t','mangle','-A','OUTPUT','-p','udp','--dport','40610',
     '-j','NFQUEUE','--queue-num','178'],
    ['ip6tables','-t','mangle','-A','OUTPUT','-p','udp','--sport','40610',
     '-j','NFQUEUE','--queue-num','179']]
installed_hooks = []
observer = None
observer_pending = b''
def observer_line(prefix, timeout=10):
    global observer_pending
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if b'\n' in observer_pending:
            line, observer_pending = observer_pending.split(b'\n', 1)
            decoded = line.decode()
            if decoded.startswith(prefix): return decoded[len(prefix):]
            continue
        assert observer.poll() is None, 'observation consumer exited before '+prefix
        ready, _, _ = select.select([observer.stdout], [], [], max(0, deadline-time.monotonic()))
        if ready:
            chunk = os.read(observer.stdout.fileno(), 65536)
            assert chunk, 'observation consumer closed stdout'
            observer_pending += chunk
    raise TimeoutError('observation consumer did not publish '+prefix)
try:
    deadline = time.monotonic()+15
    while not (runtime/'api.sock').exists():
        assert process.poll() is None, (output/'vpp.log').read_text()
        assert time.monotonic() < deadline
        time.sleep(.05)
    # Adapter startup is asynchronous; the status query is an actual product API.
    while True:
        assert process.poll() is None, (output/'vpp.log').read_text()
        try:
            status = api('initial', 'rule-query')
        except RuntimeError:
            if time.monotonic() >= deadline: raise
            time.sleep(.05)
            continue
        if status['query.adapter_available'] == 'true': break
        assert time.monotonic() < deadline, status
        time.sleep(.05)
    assert status['config.saved_revision'] == status['config.active_revision'] == '1'
    assert status['config.present'] == '0'
    result['pid']=process.pid
    save('process-exe.txt',os.readlink(f'/proc/{process.pid}/exe')+'\n')
    save('process-stat.txt',Path(f'/proc/{process.pid}/stat').read_text())
    save('process-command.txt',Path(f'/proc/{process.pid}/cmdline').read_bytes().replace(b'\0',b' ').decode())
    startup = cli('startup', 'product packet-trace limit 256', 'show product topology',
                  'show product root lanes', 'show threads')
    assert f'owner_count={args.owners} vpp_worker_count={args.owners} actual_vpp_workers={args.owners}' in startup
    assert 'topology.tun_io_lane=none' in startup
    assert 'topology.main thread_index=0 actual_core=0' in startup
    for owner, expected_cpu in enumerate(owner_cpus):
        assert f'topology.owner={owner} thread_index={owner+1} actual_core={expected_cpu}' in startup
    thread_ids = []
    for name, expected_cpu in [('vpp_main', 0)] + [
            (f'vpp_wk_{owner}', cpu) for owner, cpu in enumerate(owner_cpus)]:
        row = next(line for line in startup.splitlines() if name in line)
        tid = next(int(field) for field in row.split()[2:] if field.isdecimal())
        thread_ids.append(tid)
        assert os.sched_getaffinity(tid) == {expected_cpu}, (name, tid, expected_cpu)
    assert len(set(thread_ids)) == args.owners + 1
    reported = api('topology-api', 'query')
    assert int(reported['query.flow_owners']) == args.owners
    assert int(reported['query.vpp_workers']) == args.owners
    assert int(reported['query.main_core']) == 0
    for owner, cpu in enumerate(owner_cpus):
        assert int(reported[f'query.owner.{owner}.thread_index']) == owner + 1
        assert int(reported[f'query.owner.{owner}.actual_core']) == cpu
    observer = subprocess.Popen([str(artifact/'bin/sakamoto-product-core-host'),
        'observation-serve', str(runtime/'api.sock'), str(generation),
        str(output/'observation-store.json')], env=env, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert observer_line('observation.ready=') == str(generation)
    for selected_hook in hooks:
        command(*selected_hook); installed_hooks.append(selected_hook)
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
        (output/(phase+'-source.conf')).write_bytes((config_dir/'rules.conf').read_bytes())
        cli(phase+'-graph','show product flows','show product completion')
    if server_v6:
        nonce = f't01-ipv6-{time.time_ns()}'
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as probe:
            probe.bind(('::1',32002)); probe.settimeout(.5)
            probe.sendto(nonce.encode(),('::1',40610))
            received = probe.recv(2048).decode()
        assert received == nonce and nonce in result['endpoint']
        drain('ipv6-drain')
        ipv6_graph = cli('ipv6-graph','show product root lanes','show product flows',
                         'show product completion')
        flow_entries = [line for line in ipv6_graph.splitlines()
                        if line.startswith('flow.entry worker=')]
        for family in (4, 6):
            matching = [line for line in flow_entries if f'family={family} ' in line]
            assert len(matching) == 1, matching
            assert 'decision=1 ' in matching[0] and 'orig_packets=' in matching[0]
            assert int(matching[0].split('orig_packets=',1)[1].split()[0]) >= 1
            assert int(matching[0].split('reply_packets=',1)[1].split()[0]) >= 1
        lanes = [line for line in ipv6_graph.splitlines() if line.startswith('root.lane ')]
        assert len(lanes) == 4
        for lane in lanes:
            fields = dict(part.split('=',1) for part in lane.split()[1:] if '=' in part)
            assert int(fields['captured']) >= 1 and fields['captured'] == fields['verdicts']
            assert fields['captured'] == fields['returns'] and fields['failed'] == '0'
        completion = next(line for line in ipv6_graph.splitlines()
                          if line.startswith('completion.status '))
        for key in ('pending', 'frames', 'buffers', 'obligations'):
            assert f'{key}=0' in completion, completion
        trace = (output/'vpp.log').read_text()
        for family in (4, 6):
            lines = [line for line in trace.splitlines()
                     if 's207 stage=admit ' in line and f'key_family={family} ' in line]
            assert len(lines) >= 2 and len({line.split(' owner=',1)[1].split()[0] for line in lines}) == 1, lines
            hashes = {line.split(' hash=',1)[1].split(' ',1)[0] for line in lines}
            assert len(hashes) == 1, lines
        identities = {}
        for label, pattern in (
                ('captured', r's203 event=capture .*? obligation=(\d+)'),
                ('verdict', r's242 event=verdict_syscall .*? token=(\d+) .*? outcome=0'),
                ('returned', r's203 event=buffer_free .*? obligation=(\d+)')):
            identities[label] = Counter(re.findall(pattern, trace))
        assert identities['captured'] and identities['captured'] == identities['verdict']
        assert identities['captured'] == identities['returned']
        assert all(count == 1 for count in identities['captured'].values())
        result['cases'].append(dict(phase='ipv6-bidirectional', nonce=nonce, delivered=True,
                                    canonical_hash_symmetric=True))
    observer.stdin.write(b'query\n'); observer.stdin.flush()
    consumer_initial = json.loads(observer_line('observation.response='))
    save('consumer-initial.json', json.dumps(consumer_initial, indent=2))
    assert consumer_initial['health']['owners'] == args.owners
    assert len(consumer_initial['health']['channels']) == args.owners * 2
    if args.owners == 3:
        for port in range(32010, 32050):
            nonce = f's296-{port}-{time.time_ns()}'
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind(('127.0.0.1', port)); probe.settimeout(.5)
                probe.sendto(nonce.encode(), ('127.0.0.2', 40608))
                assert probe.recv(2048).decode() == nonce
        drain('n3-drain')
        observed = cli('n3-observed', 'show product topology', 'show product flows',
                       'show product flow-end', 'show product expiry',
                       'show product observation', 'show product completion',
                       'show product root lanes')
        def fields(line):
            return dict(part.split('=', 1) for part in line.split() if '=' in part)
        entries = [fields(line) for line in observed.splitlines()
                   if line.startswith('flow.entry ')]
        samples = [entry for entry in entries
                   if 32010 <= int(entry['port_a']) < 32050]
        assert len(samples) == 40, (len(samples), samples)
        by_owner = {owner: [] for owner in range(3)}
        for entry in samples:
            owner = int(entry['worker'])
            assert owner == int(entry['hash']) % 3
            assert int(entry['orig_packets']) >= 1 and int(entry['reply_packets']) >= 1
            assert entry['decision'] == '1' and entry['revision'] == '4'
            by_owner[owner].append(entry)
        assert all(len(items) >= 2 for items in by_owner.values()), by_owner
        result['owner_samples'] = {str(owner): len(items) for owner, items in by_owner.items()}
        pool_rows = [fields(line) for line in observed.splitlines()
                     if line.startswith('flow.pool ')]
        policy_rows = [fields(line) for line in observed.splitlines()
                       if line.startswith('policy.worker ')]
        expiry_rows = [fields(line) for line in observed.splitlines()
                       if line.startswith('expiry.owner=')]
        assert len(pool_rows) == len(policy_rows) == len(expiry_rows) == 3
        assert all(row['wrong_owner'] == '0' for row in pool_rows)
        assert all(row['mismatches'] == '0' and row['revision'] == '4'
                   for row in policy_rows)
        obs_rows = [fields(line) for line in observed.splitlines()
                    if line.startswith('observation.channel=')]
        assert len(obs_rows) == 6 and int(obs_rows[4]['attempted']) >= 2
        observer.stdin.write(b'query\n'); observer.stdin.flush()
        consumer = json.loads(observer_line('observation.response='))
        save('n3-consumer.json', json.dumps(consumer, indent=2))
        assert consumer['health']['owners'] == 3
        assert len(consumer['health']['channels']) == 6
        assert any(record and record['owner'] == 2 for record in
                   consumer['consumer']['overview']['records'])
        for owner, items in by_owner.items():
            entry = items[0]
            cli(f'n3-close-{owner}', f'product flow-end close owner {owner} '
                f'slot {entry["slot"]} generation {generation} '
                f'incarnation {entry["incarnation"]}')
        deadline = time.monotonic() + 10
        while True:
            closed = cli('n3-closed', 'show product flow-end', 'show product flows')
            closed_rows = [fields(line) for line in closed.splitlines()
                           if line.startswith('flow-end.owner=')]
            if len(closed_rows) == 3 and all(int(row['released']) >= 1 for row in closed_rows):
                break
            assert time.monotonic() < deadline, closed
            time.sleep(.05)
        deadline = time.monotonic() + 42
        while True:
            expired = cli('n3-expired', 'show product expiry', 'show product flows',
                          'show product flow-end', 'show product completion')
            expiry_rows = [fields(line) for line in expired.splitlines()
                           if line.startswith('expiry.owner=')]
            pools = [fields(line) for line in expired.splitlines()
                     if line.startswith('flow.pool ')]
            if len(pools) == len(expiry_rows) == 3 and all(
                    row['entries'] == '0' for row in pools):
                assert all(int(row['closed']) >= 1 for row in expiry_rows), expiry_rows
                break
            assert time.monotonic() < deadline, expired
            time.sleep(.2)
        drain('n3-expired-drain')
        result['expiry'] = [int(row['closed']) for row in expiry_rows]
        trace = (output/'vpp.log').read_text()
        identities = {label: Counter(re.findall(pattern, trace)) for label, pattern in (
            ('captured', r's203 event=capture .*? obligation=(\d+)'),
            ('verdict', r's242 event=verdict_syscall .*? token=(\d+) .*? outcome=0'),
            ('freed', r's203 event=buffer_free .*? obligation=(\d+)'))}
        assert len(identities['captured']) >= 87
        assert identities['captured'] == identities['verdict'] == identities['freed']
        assert all(count == 1 for count in identities['captured'].values())
        result['exact_tokens'] = len(identities['captured'])
    result['status'] = 'RUN_ASSERTIONS_COMPLETE'
except Exception as error:
    result['error']=repr(error)
    raise
finally:
    if observer is not None:
        if observer.poll() is None:
            observer.stdin.write(b'quit\n'); observer.stdin.flush()
            observer.wait(timeout=10)
        save('observer-exit.txt', f'exit_code={observer.returncode}\n'
             + observer.stderr.read().decode())
    for installed in reversed(installed_hooks):
        removal=installed.copy();removal[3]='-D';command(*removal)
    done.set()
    for thread in threads: thread.join(2)
    server.close()
    if server_v6: server_v6.close()
    if process.poll() is None and (runtime/'cli.sock').exists():
        drain('final-drain')
        stopped_command = cli('stop','product root stop')
        assert 'root.stop=ok queues=0 buffers=0 obligations=0' in stopped_command
        stopped = cli('stopped','show product completion','show product root lanes',
                      'show product flows')
        if args.owners in (1, 3):
            completion = next(line for line in stopped.splitlines()
                              if line.startswith('completion.status '))
            assert all(f'{field}=0' in completion for field in
                       ('pending', 'frames', 'buffers', 'obligations')), completion
            for line in stopped.splitlines():
                if line.startswith('root.lane '):
                    assert 'fd=-1 ' in line and 'ready=0 ' in line and 'pending=0 ' in line
            assert re.search(r's242 event=stop_native_zero .*?pending=0 buffers=0 '
                             r'obligations=0 handoffs=0 completion_frames=0',
                             (output/'vpp.log').read_text())
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
    if result['status'] == 'RUN_ASSERTIONS_COMPLETE' and result['process_absent']:
        result['status'] = 'RAW_COMPLETE'
    result['completed_ns'] = time.time_ns()
    save('result.json',json.dumps(result,indent=2)+'\n')
print('SAKAMOTO-296 Linux Product Root packet chain complete')
