#!/usr/bin/env python3
"""Real NFQUEUE fail-open, resource-loss and recovery evidence on Linux/Pixel.

Linux must run in a disposable rootless user+network namespace. Pixel operates
only exact private loopback rules, addresses and owned native processes while
RuntimeService is stopped. No packet-domain implementation or graph injector.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import socket
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
PKG = 'com.sakamoto.snort.androidruntime'
SERIAL = '28201JEGR0XPAJ'
PORT = 40633


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(value)
    return value


def rows(value, prefix):
    return [dict(p.split('=', 1) for p in line.split()[1:] if '=' in p)
            for line in value.splitlines() if line.startswith(prefix)]


def props(value):
    return dict(line.split('=', 1) for line in value.splitlines() if '=' in line)


def invoke(argv, check=True, timeout=35, **kwargs):
    result = subprocess.run(list(map(str, argv)), text=True, errors='replace',
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=timeout, **kwargs)
    result.stdout = result.stdout.replace('\r', '')
    if check and result.returncode:
        raise RuntimeError(result.stdout)
    return result


class Target:
    def __init__(self, args, build, helper):
        self.args, self.build, self.helper = args, build, helper
        self.pixel = args.platform == 'pixel'
        self.children = {}
        self.environment = dict(os.environ)
        if self.pixel:
            before = save(args.output/'app-before.properties', self.adb(
                'shell', 'run-as', PKG, 'cat', 'files/runtime-state/snapshot.properties').stdout)
            assert props(before).get('state') == 'stopped' and props(before).get('mayBeActive') == 'false'
            processes = save(args.output/'processes-before.txt', self.adb('shell', 'ps', '-A', '-o', 'PID,NAME,ARGS').stdout)
            assert not any(len(p := line.split(None, 2)) == 3 and p[2].split()
                           and Path(p[2].split()[0]).name == 'libvpp_runtime.so'
                           for line in processes.splitlines())
            assert digest(build['apk']) == build['apk_sha256']
            save(args.output/'install.txt', self.adb('install', '-r', build['apk'], timeout=60).stdout)
            package = save(args.output/'package.txt', self.adb('shell', 'dumpsys', 'package', PKG).stdout)
            self.native = re.search(r'codePath=(\S+)', package)[1]+'/lib/arm64'
            installed = save(args.output/'installed-native.txt', self.adb('shell', 'sha256sum',
                *[self.native+'/'+n for n in sorted(build['native_sha256'])]).stdout)
            assert {Path(l.split()[1]).name: l.split()[0] for l in installed.splitlines()} == build['native_sha256']
            apk_hash = save(args.output/'installed-apk.txt', self.adb('shell', 'sha256sum',
                self.native.removesuffix('/lib/arm64')+'/base.apk').stdout)
            assert apk_hash.split()[0] == build['apk_sha256']
            self.uid = self.adb('shell', 'run-as', PKG, 'id', '-u').stdout.strip()
            assert self.uid.isdigit()
            self.policy_uid = self.uid
            self.temporary = self.adb('shell', 'mktemp', '-d', '/data/local/tmp/s233.XXXXXX').stdout.strip()
            assert re.fullmatch(r'/data/local/tmp/s233\.[A-Za-z0-9]+', self.temporary)
            for name in ('s223-udp', 's217-policy'):
                self.adb('push', args.helpers.parent/name, self.temporary+'/'+name)
                self.run('chmod 755 '+shlex.quote(self.temporary+'/'+name))
                actual = save(args.output/(name+'-installed.txt'), self.run(
                    'sha256sum '+shlex.quote(self.temporary+'/'+name)).stdout)
                assert actual.split()[0] == helper['files'][name]
            self.helpers = self.temporary
        else:
            assert os.getuid() == 0
            uid_map = Path('/proc/self/uid_map').read_text().split()
            assert len(uid_map) == 3 and uid_map[0] == '0' and uid_map[1] != '0' and uid_map[2] == '1', 'requires a rootless namespace'
            save(args.output/'uid-map.txt', ' '.join(uid_map)+'\n')
            save(args.output/'namespace.txt', os.readlink('/proc/self/ns/net')+'\n')
            self.uid = '0'
            # This kernel exports NFQA_UID in its initial user namespace;
            # --uid-owner and the endpoint syscall use the nested namespace.
            # Keep both identities explicit; never rewrite captured facts.
            self.policy_uid = uid_map[1]
            self.artifact = Path(build['artifact'])
            for name, expected in build['artifact_hashes'].items():
                assert digest(self.artifact/name) == expected, name
            assert 'product.host.evidence=OFF' in (self.artifact/'product-vpp-artifact.properties').read_text()
            self.native = str(self.artifact/'lib')
            self.helpers = str(args.helpers.parent)
            self.environment['LD_LIBRARY_PATH'] = self.native
            self.temporary = tempfile.mkdtemp(prefix='s233-')
            self.run('ip link set lo up')
        save(args.output/'kernel.txt', self.run('uname -a').stdout)

    def adb(self, *argv, **kwargs):
        return invoke([ROOT/'dev/adb', '-s', SERIAL, *argv], **kwargs)

    def run(self, command, check=True, timeout=35):
        started = time.time_ns()
        if self.pixel:
            result = self.adb('shell', 'su', '-c', shlex.quote(command), check=False, timeout=timeout)
        else:
            result = invoke(['sh', '-c', command], check=False, timeout=timeout, env=self.environment)
        with (self.args.output/'commands.jsonl').open('a') as log:
            log.write(json.dumps(dict(started_ns=started, completed_ns=time.time_ns(), command=command,
                                      returncode=result.returncode))+'\n')
        if check and result.returncode:
            raise RuntimeError(command+'\n'+result.stdout)
        return result

    def read(self, path):
        return self.run('cat '+shlex.quote(str(path))).stdout

    def cli(self, runtime, commands):
        if not self.pixel:
            return ''.join(self.run(shlex.join([str(self.args.vppctl), '-s', runtime+'/cli.sock', c])).stdout for c in commands)
        marker = 'S233_DONE_'+str(time.time_ns())
        command = 'exec toybox nc -U -w 15 '+shlex.quote(runtime+'/cli.sock')
        process = subprocess.Popen([str(ROOT/'dev/adb'), '-s', SERIAL, 'shell', '-T', 'su', '-c', shlex.quote(command)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        data = b''
        try:
            # VPP's Telnet negotiation can discard input sent before its
            # first prompt. The no-hooks timing regression reproduces this
            # with immediate input and passes with prompt-before-command.
            sent = False
            end = time.monotonic()+30
            while time.monotonic() < end:
                if not sent and b'vpp# ' in data:
                    process.stdin.write(('\n'+'\n'.join(['set terminal pager off', *commands, 'echo '+marker])+'\n').encode())
                    process.stdin.flush()
                    sent = True
                if not selector.select(1):
                    continue
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                data += chunk
                if b'\n'+marker.encode()+b'\n' in data.replace(b'\r', b''):
                    break
            else:
                raise RuntimeError('CLI timed out '+data.decode(errors='replace')[-1000:])
            assert b'\n'+marker.encode()+b'\n' in data.replace(b'\r', b''), 'incomplete CLI response'
            process.stdin.write(b'quit\n')
            process.stdin.flush()
            remainder, _ = process.communicate(timeout=5)
            assert process.returncode == 0
            return (data+remainder).decode(errors='replace').replace('\r', '')
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            selector.close()

    def spawn(self, argv, logfile, environment=None):
        if self.pixel:
            exports = '; '.join('export '+shlex.quote(k+'='+str(v)) for k, v in (environment or {}).items())
            command = (exports+'; ' if exports else '')+'exec '+shlex.join(argv)
            # The subshell backgrounds the complete exported exec command.
            pid = self.run('( '+command+' ) > '+shlex.quote(logfile)+' 2>&1 < /dev/null & echo $!').stdout.strip()
            assert pid.isdigit(), pid
            return int(pid)
        log = open(logfile, 'w')
        process = subprocess.Popen(argv, env=dict(self.environment, **(environment or {})),
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        log.close()
        self.children[process.pid] = process
        return process.pid

    def stop_process(self, pid):
        if not self.pixel:
            process = self.children[pid]
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
            return not Path(f'/proc/{pid}').exists()
        self.run('kill '+str(pid), check=False)
        end = time.monotonic()+10
        while time.monotonic() < end:
            if self.run('test -d /proc/'+str(pid), check=False).returncode:
                return True
            time.sleep(.1)
        return False

    def queue_witness(self, run, label):
        table = self.run('cat /proc/net/netfilter/nfnetlink_queue', check=False)
        save(run/(label+'-queues.txt'), table.stdout)
        save(run/(label+'-netlink.txt'), self.run('cat /proc/net/netlink').stdout)
        if self.pixel:
            assert table.returncode == 0
            return
        bound = {}
        for queue in range(176, 180):
            with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12) as sock:
                sock.bind((0, 0))
                sock.settimeout(2)
                payload = struct.pack('!BBH', 0, 0, queue)+struct.pack('HH', 8, 1)+struct.pack('!BBH', 1, 0, 2)
                sock.send(struct.pack('IHHII', 16+len(payload), 0x302, 5, 1, 0)+payload)
                reply = sock.recv(4096)
                assert struct.unpack_from('H', reply, 4)[0] == 2
                bound[queue] = struct.unpack_from('i', reply, 16)[0]
        save(run/(label+'-queue-bind.json'), json.dumps(bound, indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', choices=('linux', 'pixel'), required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--helpers', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--vppctl', type=Path)
    args = parser.parse_args()
    for name in ('build', 'helpers', 'output'):
        setattr(args, name, getattr(args, name).resolve())
    if args.platform == 'linux':
        assert args.vppctl
        args.vppctl = args.vppctl.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    build, helper = json.loads(args.build.read_text()), json.loads(args.helpers.read_text())
    assert helper['build_sha256'] == digest(args.build) and helper['platform'] == args.platform
    for name, expected in helper['files'].items():
        assert digest(args.helpers.parent/name) == expected, name
    result = dict(status='HOLD', platform=args.platform, build=str(args.build), build_sha256=digest(args.build),
                  helpers=str(args.helpers), helpers_sha256=digest(args.helpers), source_sha256=build['source_sha256'],
                  runner_sha256=digest(__file__), started_ns=time.time_ns(), runs=[])
    target, addresses, endpoints = None, [], []
    try:
        target = Target(args, build, helper)
        result.update(uid=target.uid, policy_uid=target.policy_uid, temporary=target.temporary)
        initial_hooks = save(args.output/'hooks-before.txt', target.run('iptables-save -t mangle').stdout+target.run('ip6tables-save -t mangle').stdout)
        assert 'SAKAMOTO_S233_' not in initial_hooks
        initial_addresses = save(args.output/'addresses-before.txt', target.run('ip -6 addr show dev lo').stdout)
        for number in range(2, 18):
            address = f'fd20:6233::{number:x}'
            if address+'/128' not in initial_addresses:
                target.run(f'ip -6 addr add {address}/128 dev lo nodad')
                addresses.append(address)
        endpoint_addresses = set()

        def endpoint_log(family):
            return '\n'.join(target.read(path) for f, _, path in endpoints if f == family)

        def ensure_endpoint(family, host):
            if (family, host) in endpoint_addresses:
                return
            # Bind the real destination, not ANY: connected UDP correctly
            # rejects an echo sent with a different kernel-chosen source IP.
            logfile = target.temporary+f'/endpoint-{family}-{len(endpoints)}.log'
            endpoint_pid = target.spawn([target.helpers+'/s223-udp', 'server', target.uid, str(family), host, str(PORT)], logfile)
            endpoints.append((family, endpoint_pid, logfile))
            end = time.monotonic()+5
            while 'listen ' not in target.read(logfile):
                assert time.monotonic() < end, 'endpoint startup timeout'
                time.sleep(.05)
            endpoint_addresses.add((family, host))
        for index, (label, maxlen) in enumerate((('resources', 1024), ('pressure', 1), ('restart', 1024))):
            run = args.output/label
            run.mkdir()
            generation = 23310+index
            record = dict(label=label, generation=generation, maxlen=maxlen, cases=[])
            result['runs'].append(record)
            runtime = (target.temporary+'/'+label) if target.pixel else str(ROOT/'build-output'/f'product-vpp-runtime-s233-{args.output.name}-{label}')
            logfile = target.temporary+'/'+label+'-vpp.log'
            environment = dict(SAKAMOTO_PRODUCT_GENERATION=str(generation), SAKAMOTO_RUNTIME_PROFILE='root',
                SAKAMOTO_PRODUCT_ROOT_NFQUEUE_QUEUE='176', SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4',
                SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID=target.uid, SAKAMOTO_PRODUCT_ROOT_NFQUEUE_MAXLEN=str(maxlen))
            if target.pixel:
                target.adb('shell', 'mkdir', '-p', runtime+'/shm')
                config = f'''plugin_path {target.native}
cpu {{ main-core 0 corelist-workers 1-2 }}
unix {{ nodaemon nobanner cli-no-pager runtime-dir {runtime} cli-listen {runtime}/cli.sock }}
socksvr {{ socket-name {runtime}/api.sock }}
api-segment {{ prefix sakamoto-s233-{generation} }}
statseg {{ socket-name {runtime}/statseg.sock }}
plugins {{ path {target.native} plugin default {{ disable }} plugin libproduct_core_plugin.so {{ enable }} }}
'''
                save(run/'startup.conf', config)
                target.adb('push', run/'startup.conf', runtime+'/startup.conf')
                environment.update(LD_LIBRARY_PATH=target.native, SAKAMOTO_VPP_SVM_DIR=runtime+'/shm',
                    SAKAMOTO_VPP_RUNTIME_DIR=runtime, SAKAMOTO_VPP_OWNER_TOKEN=f's233-native-{generation}')
                launch = [target.native+'/libvpp_runtime.so', '-c', runtime+'/startup.conf']
            else:
                environment.update(PRODUCT_ARTIFACT_DIR=str(target.artifact), PRODUCT_RUNTIME_DIR=runtime,
                                   PRODUCT_GENERATION=str(generation), PRODUCT_WORKER_COUNT='2')
                launch = ['bash', str(ROOT/'tools/product/run-host-vpp.sh')]
            save(run/'launch.json', json.dumps(dict(argv=launch, environment=environment, runtime=runtime), indent=2)+'\n')
            pid = target.spawn(launch, logfile, environment)
            record['pid'] = pid
            rules = []
            revision = 0
            source_port = 31000

            def cli(name, *commands):
                return save(run/(name+'.txt'), target.cli(runtime, commands))

            def drain(name):
                end = time.monotonic()+20
                while time.monotonic() < end:
                    text = cli(name, 'show product completion')
                    states = rows(text, 'completion.status ')
                    if len(states) == 1 and all(states[0][k] == '0' for k in ('pending', 'frames', 'buffers', 'obligations')):
                        return
                    time.sleep(.05)
                raise RuntimeError('drain timeout '+text)

            def snapshot(name):
                drain(name+'-drain')
                text = cli(name, 'show product root receive', 'show product root lanes', 'show product completion')
                save(run/(name+'-vpp.log'), target.read(logfile))
                for family in (4, 6):
                    save(run/(name+f'-endpoint-{family}.log'), endpoint_log(family))
                target.queue_witness(run, name)
                return text

            def policy(mode):
                nonlocal revision
                revision += 1
                answer = target.run('env '+shlex.quote('LD_LIBRARY_PATH='+target.native)+' '+shlex.join([
                    target.helpers+'/s217-policy', runtime+'/api.sock', str(generation), runtime+'/policy',
                    str(revision), str(mode), target.policy_uid, '0']))
                save(run/f'policy-{revision}.txt', answer.stdout)
                assert 'policy rc=0 ' in answer.stdout

            def fault(mode):
                # Each CLI command releases the worker barrier independently.
                # Unpausing one bound lane admits its old queued packet; wait
                # for that real work before modifying another lane's pools.
                for lane in range(4):
                    for attempt in range(5):
                        drain(f'fault-{mode}-lane-{lane}-drain')
                        text = cli(f'fault-{len(record["cases"])}-{mode}-lane-{lane}-{attempt}',
                                   f'product root receive-fault {lane} {mode}')
                        if len(rows(text, 'root.receive_fault ')) == 1:
                            break
                    else:
                        raise RuntimeError(text)

            def probe(family, host, phase, expected, lane=None):
                nonlocal source_port
                source_port += 1
                ensure_endpoint(family, host)
                nonce = f's233-{generation}-{phase}-{len(record["cases"])}-{time.time_ns()}'
                answer = target.run(shlex.join([target.helpers+'/s223-udp', 'client', target.uid, str(family),
                    '127.0.0.1' if family == 4 else '::1', str(source_port), host, str(PORT), '1', nonce, '1',
                    '500' if not expected else '5000']), check=False, timeout=15)
                save(run/f'client-{len(record["cases"])}.txt', answer.stdout)
                delivered = answer.returncode == 0 and len(rows(answer.stdout, 'endpoint ')) == 1
                observed = nonce+'-0' in endpoint_log(family)
                case = dict(phase=phase, family=family, host=host, source_port=source_port, nonce=nonce,
                            expected=expected, returncode=answer.returncode, delivered=delivered,
                            endpoint_observed=observed, policy_revision=revision, lane=lane)
                record['cases'].append(case)
                assert delivered == expected and observed == expected, case
                return case

            def batch(seeds, phase, expected):
                for lane, seed in sorted(seeds.items()):
                    probe(seed['family'], seed['host'], phase, expected, lane)

            def remove_rules():
                while rules:
                    command = list(rules[-1])
                    command[5] = '-D'
                    target.run(shlex.join(command))
                    rules.pop()

            try:
                end = time.monotonic()+30
                while time.monotonic() < end:
                    if target.run('test -S '+shlex.quote(runtime+'/cli.sock'), check=False).returncode == 0:
                        ready = cli('ready', 'show product root lanes')
                        lanes = rows(ready, 'root.lane ')
                        if len(lanes) == 4 and all(lane['ready'] == '1' for lane in lanes):
                            break
                    assert target.run('kill -0 '+str(pid), check=False).returncode == 0, target.read(logfile)
                    time.sleep(.1)
                else:
                    raise RuntimeError('startup timeout '+target.read(logfile))
                cli('trace', 'product packet-trace limit 4096', 'show threads')
                snapshot('initial')
                save(run/'fds-before.txt', target.run('ls -l /proc/'+str(pid)+'/fd').stdout)
                for tool, span in (('iptables', '176:177'), ('ip6tables', '178:179')):
                    for hook in ('OUTPUT', 'INPUT'):
                        extra = ['--dport', str(PORT), '-m', 'owner', '--uid-owner', target.uid] if hook == 'OUTPUT' else ['--sport', str(PORT)]
                        rule = [tool, '-w', '5', '-t', 'mangle', '-A', hook, '-o' if hook == 'OUTPUT' else '-i',
                                'lo', '-p', 'udp', *extra, '-m', 'comment', '--comment', 'SAKAMOTO_S233_'+label,
                                '-j', 'NFQUEUE', '--queue-balance', span, '--queue-bypass']
                        target.run(shlex.join(rule))
                        rules.append(rule)
                save(run/'hooks.txt', target.run('iptables-save -t mangle').stdout+target.run('ip6tables-save -t mangle').stdout)
                policy(0)
                seeds = {}
                for family in (4, 6):
                    for number in range(2, 18):
                        host = f'127.0.0.{number}' if family == 4 else f'fd20:6233::{number:x}'
                        case = probe(family, host, 'seed', True)
                        drain('seed-drain')
                        raw = rows(target.read(logfile), 's231 ')
                        selected = [row for row in raw if row.get('event') == 'nfq_payload' and
                                    row.get('hook') == '3' and (case['nonce']+'-0').encode().hex() in row['raw']]
                        assert len(selected) == 1, (case, selected)
                        lane = int(selected[0]['lane'])
                        case['lane'] = lane
                        seeds.setdefault(lane, dict(family=family, host=host))
                        if len([lane for lane in seeds if lane//2 == (family == 6)]) == 2:
                            break
                assert set(seeds) == set(range(4)), seeds
                record['seeds'] = seeds
                uid_facts = [row for row in rows(target.read(logfile), 's217 ')
                             if row.get('event') == 'nfq_facts' and row.get('raw_hook') == '3']
                assert uid_facts and all(row['raw_uid_present'] == '1' and row['raw_uid'] == target.policy_uid
                                         and row['normalized_uid'] == target.policy_uid and row['fault'] == '0'
                                         for row in uid_facts), uid_facts
                snapshot('baseline')
                policy(1)
                batch(seeds, 'policy-drop', False)
                snapshot('policy-drop')
                if label == 'resources':
                    fault(1)
                    snapshot('normal-held')
                    batch(seeds, 'normal-exhausted', True)
                    snapshot('normal-exhausted')
                    fault(0)
                    batch(seeds, 'normal-recovery-drop', False)
                    snapshot('normal-recovery-drop')
                    fault(2)
                    snapshot('reserve-held')
                    batch(seeds, 'reserve-exhausted', False)
                    snapshot('reserve-exhausted')
                    fault(0)
                    batch(seeds, 'reserve-recovery-drop', False)
                    snapshot('reserve-recovery-drop')
                    fault(3)
                    snapshot('identity-armed')
                    batch(seeds, 'missing-identity', False)
                    snapshot('missing-identity')
                    fault(0)
                    batch(seeds, 'identity-recovery-drop', False)
                    snapshot('identity-recovery-drop')
                elif label == 'pressure':
                    fault(4)
                    snapshot('paused-empty')
                    batch(seeds, 'queued-before-full', False)
                    snapshot('paused-full')
                    batch(seeds, 'kernel-full-bypass', True)
                    snapshot('kernel-full-bypass')
                    fault(0)
                    snapshot('unpaused-drop')
                    batch(seeds, 'pressure-recovery-drop', False)
                    snapshot('pressure-recovery-drop')
                    fault(4)
                    batch(seeds, 'queued-before-close', False)
                    snapshot('close-queued')
                    cli('lane-close', *[f'product root lane close {lane}' for lane in range(4)])
                    snapshot('listeners-closed')
                    batch(seeds, 'no-listener-bypass', True)
                    snapshot('no-listener-bypass')
                    log = '\n'.join(target.read(p) for _, _, p in endpoints)
                    for case in record['cases']:
                        if case['phase'] in ('queued-before-full', 'queued-before-close'):
                            assert case['nonce'] not in log, 'previously queued packet incorrectly claimed as bypass'
                if label != 'pressure':
                    policy(0)
                    batch(seeds, 'policy-allow-recovery', True)
                snapshot('final')
                record['raw_complete'] = True
            finally:
                remove_rules()
                save(run/'hooks-after.txt', target.run('iptables-save -t mangle').stdout+target.run('ip6tables-save -t mangle').stdout)
                try:
                    if target.run('kill -0 '+str(pid), check=False).returncode == 0 and target.run('test -S '+shlex.quote(runtime+'/cli.sock'), check=False).returncode == 0:
                        end = time.monotonic()+20
                        while time.monotonic() < end:
                            if 'root.stop=ok' in cli('stop', 'product root stop'):
                                break
                            time.sleep(.1)
                        else:
                            raise RuntimeError('stop did not drain')
                        snapshot('closed')
                        save(run/'fds-closed.txt', target.run('ls -l /proc/'+str(pid)+'/fd').stdout)
                finally:
                    absent = target.stop_process(pid)
                    save(run/'vpp.log', target.read(logfile))
                    save(run/'stop.json', json.dumps(dict(pid=pid, process_absent=absent))+'\n')
                    assert absent
            print(args.platform, label, 'raw complete', len(record['cases']), 'endpoint cases', flush=True)
        result['status'] = 'RAW_COMPLETE'
    except Exception as error:
        result['error'] = repr(error)
        raise
    finally:
        if target:
            final_endpoints = {4: [], 6: []}
            for family, pid, logfile in endpoints:
                absent = target.stop_process(pid)
                final_endpoints[family].append(target.read(logfile))
                result.setdefault('endpoint_cleanup', []).append(dict(family=family, pid=pid, process_absent=absent))
            for family, texts in final_endpoints.items():
                save(args.output/f'endpoint-{family}.log', '\n'.join(texts))
            for address in addresses:
                target.run(f'ip -6 addr del {address}/128 dev lo', check=False)
            save(args.output/'addresses-after.txt', target.run('ip -6 addr show dev lo').stdout)
            save(args.output/'hooks-after.txt', target.run('iptables-save -t mangle').stdout+target.run('ip6tables-save -t mangle').stdout)
            save(args.output/'processes-after.txt', target.run('ps -A -o PID,NAME,ARGS' if target.pixel else 'ps -eo pid,comm,args').stdout)
        result['completed_ns'] = time.time_ns()
        save(args.output/'result.json', json.dumps(result, indent=2)+'\n')


if __name__ == '__main__':
    main()
