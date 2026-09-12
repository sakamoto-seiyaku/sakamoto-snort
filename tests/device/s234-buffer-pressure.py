#!/usr/bin/env python3
"""Actual small-pool END exhaustion, not an allocator return-value override.

Linux uses an isolated rootless network namespace. Pixel native mode uses
private hooks; supervisor mode uses RuntimeService's own production hooks.
Only the independent verifier decides acceptance.
"""
import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT/relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


base = module('s234_target', 'tests/device/s242-root-lifecycle.py')
chain = module('s234_chain', 'tests/evidence/product_chain.py')
owner_oracle = module('s234_owner', 'tests/device/s207-owner-oracle.py')
Target, save, digest, rows, props = base.Target, base.save, base.digest, base.rows, base.props
PKG, STATE = base.base.PKG, 'files/runtime-state/snapshot.properties'
BASE = '/data/user/0/'+PKG+'/files/profiles/root/vpp'
UDP, TCP = 40634, 40635
HOSTS = {4: '127.0.0.2', 6: 'fd20:6234::2'}
LOCAL = {4: '127.0.0.1', 6: '::1'}


def pools(text):
    result, current = [], None
    for line in text.splitlines():
        parts = line.split()
        if parts and parts[0].startswith('default-numa-'):
            assert len(parts) == 9, line
            current = dict(zip(('index', 'numa', 'size', 'data', 'total', 'available', 'cached', 'used'), map(int, parts[1:])))
            current['threads'] = {}
            result.append(current)
        elif parts and parts[0] == 'thread' and current is not None:
            current['threads'][int(parts[1])] = int(parts[2])
    assert len(result) == 1, 'this experiment requires one actual NUMA pool'
    return result[0]


class Campaign:
    def __init__(self, args, build, helper):
        self.args, self.build = args, build
        self.target = Target(args, build, helper)
        self.supervisor = args.mode == 'supervisor'
        self.records, self.rules, self.endpoints, self.host_endpoints, self.addresses = [], [], [], [], []
        self.next_port = 33000
        self.result = dict(status='HOLD', platform=args.platform, mode=args.mode, source='NFQ_CAPTURED',
            build=str(args.build), build_sha256=digest(args.build), helpers=str(args.helpers),
            helpers_sha256=digest(args.helpers), source_sha256=build['source_sha256'],
            uid=self.target.uid, policy_uid=self.target.policy_uid, started_ns=time.time_ns(),
            requested_buffers=512, generations=self.records)
        names = ['tests/device/s234-buffer-pressure.py', 'tests/device/s242-root-lifecycle.py',
                 'tests/device/s233-fail-open.py', 'tests/device/s207-owner-oracle.py',
                 'tests/evidence/product_chain.py', 'docs/testing/2026-09-12_S234_BUFFER_PRESSURE.md']
        self.result['test_inputs'] = {name: digest(ROOT/name) for name in names}
        for name in names:
            path = args.output/'test-source'/name
            path.parent.mkdir(parents=True, exist_ok=True)
            save(path, (ROOT/name).read_text())

    def write(self, record, name, value):
        return save(self.args.output/record['label']/name, value)

    def hooks(self):
        return self.target.run('iptables-save -t mangle').stdout+self.target.run('ip6tables-save -t mangle').stdout

    def app(self, path=STATE):
        return self.target.adb('shell', 'run-as', PKG, 'cat', path, check=False).stdout

    def action(self, *extras):
        return self.target.adb('shell', 'am', 'start', '-n', PKG+'/.DebugControlActivity', *extras).stdout

    def clock(self):
        return 'env '+shlex.quote('LD_LIBRARY_PATH='+self.target.native)+' '+shlex.join([self.target.helpers+'/s242-stop', 'clock'])

    def prepare(self):
        memory = save(self.args.output/'memory-before.txt', self.target.run('cat /proc/meminfo').stdout)
        assert int(re.search(r'^MemAvailable:\s+(\d+) kB', memory, re.M)[1]) >= 512*1024
        assert 'SAKAMOTO_S234_' not in save(self.args.output/'hooks-before.txt', self.hooks())
        listeners = save(self.args.output/'listeners-before.txt', self.target.run('ss -lnut').stdout)
        assert not re.search(r':(?:40634|40635)\b', listeners), 'endpoint port occupied'
        initial = save(self.args.output/'addresses-before.txt', self.target.run('ip -6 addr show dev lo').stdout)
        if HOSTS[6]+'/128' not in initial:
            self.target.run('ip -6 addr add '+HOSTS[6]+'/128 dev lo nodad')
            self.addresses.append(HOSTS[6])
        for family, host in HOSTS.items():
            path = self.target.temporary+f'/udp-{family}.log'
            pid = self.target.spawn([self.target.helpers+'/s223-udp', 'server', self.target.uid, str(family), host, str(UDP)], path)
            self.endpoints.append((pid, path))
        path = self.target.temporary+'/tcp.log'
        pid = self.target.spawn([self.target.helpers+'/s222-tcp', 'server', str(TCP), *HOSTS.values()], path)
        self.endpoints.append((pid, path))
        for pid, path in self.endpoints:
            deadline = time.monotonic()+5
            while 'listen ' not in self.target.read(path):
                assert self.target.alive(pid) and time.monotonic() < deadline
                time.sleep(.02)
        if self.args.lan4:
            assert self.target.pixel and self.args.lan6 and self.args.host_helpers
            witness = json.loads(self.args.host_helpers.read_text())
            assert witness['platform'] == 'linux' and witness['source_sha256'] == self.build['source_sha256']
            self.result['host_helpers'] = str(self.args.host_helpers)
            self.result['host_helpers_sha256'] = digest(self.args.host_helpers)
            self.result['lan'] = {4: self.args.lan4, 6: self.args.lan6}
            for family, address in self.result['lan'].items():
                value = ipaddress.ip_address(address)
                assert value.version == family and not (value.is_loopback or value.is_unspecified or value.is_link_local)
                binary = self.args.host_helpers.parent/'s223-udp'
                assert digest(binary) == witness['files'][binary.name]
                log = self.args.output/f'lan-udp-{family}.log'
                with log.open('w') as output:
                    process = subprocess.Popen([str(binary), 'server', str(os.getuid()), str(family), address, str(UDP)], stdout=output, stderr=subprocess.STDOUT)
                self.host_endpoints.append((process, log))
            binary = self.args.host_helpers.parent/'s222-tcp'
            assert digest(binary) == witness['files'][binary.name]
            log = self.args.output/'lan-tcp.log'
            with log.open('w') as output:
                process = subprocess.Popen([str(binary), 'server', str(TCP), self.args.lan4, self.args.lan6], stdout=output, stderr=subprocess.STDOUT)
            self.host_endpoints.append((process, log))
            for process, path in self.host_endpoints:
                deadline = time.monotonic()+5
                while 'listen ' not in path.read_text():
                    assert process.poll() is None and time.monotonic() < deadline
                    time.sleep(.01)

    def cli(self, record, label, *commands):
        return self.write(record, label+'.txt', self.target.cli(record['runtime'], commands))

    def snapshot(self, record, label):
        return self.cli(record, label, 'show buffers detail', 'show product flow-end', 'show product flows',
                        'show product root lanes', 'show product completion', 'show product primary')

    def drain(self, record, label):
        deadline = time.monotonic()+8
        while time.monotonic() < deadline:
            text = self.snapshot(record, label)
            values = rows(text, 'completion.status ')
            if values and all(values[0][k] == '0' for k in ('pending', 'frames', 'buffers', 'obligations')):
                assert 'flow-end.buffers=0' in text
                return text
            assert self.target.alive(record['pid'])
            time.sleep(.02)
        raise RuntimeError('native drain deadline')

    def wait_state(self, record, label, predicate, timeout=45):
        deadline = time.monotonic()+timeout
        while time.monotonic() < deadline:
            text = self.write(record, label+'.poll', self.app())
            state = props(text)
            if predicate(state):
                self.write(record, label+'.properties', text)
                return state
            assert state.get('errorCode') != 'root_authorization_required', 'restore KernelSU grant'
            time.sleep(.05)
        raise RuntimeError(label+' state deadline '+str(state))

    def start(self, label, index):
        (self.args.output/label).mkdir()
        record = dict(label=label, probes=[], closed=False)
        self.records.append(record)
        if self.supervisor:
            record.update(runtime=BASE+'/runtime', log=BASE+'/logs/vpp-stdout.log')
            assert props(self.app()).get('mayBeActive') == 'false'
            deadline = time.monotonic()+10
            while 'ServiceRecord{' in self.target.adb('shell', 'dumpsys', 'activity', 'services', PKG).stdout:
                assert time.monotonic() < deadline, 'old service did not retire'
                time.sleep(.1)
            self.write(record, 'start.txt', self.action('--ei', 'debugNativeBuffers', '512', '--es', 'runtimeProfile', 'root'))
            state = self.wait_state(record, 'running', lambda s: s.get('state') == 'running' and s.get('protectionRunning') == 'true' and not s.get('errorCode'))
            record['generation'] = int(state['generation'])
            owner = props(self.write(record, 'owner.properties', self.target.read(BASE+'/owner.properties')))
            processes = self.write(record, 'processes-before.txt', self.target.run('ps -A -o PID,UID,ARGS').stdout)
            matches = [int(p[0]) for line in processes.splitlines() if len(p := line.split(None, 2)) == 3
                       and p[0].isdigit() and p[1] == '0' and Path(p[2].split()[0]).name == 'libvpp_runtime.so']
            assert len(matches) == 1
            record['pid'] = matches[0]
            executable = self.write(record, 'exe.txt', self.target.run('readlink /proc/'+str(record['pid'])+'/exe').stdout).strip()
            assert executable == self.target.native+'/libvpp_runtime.so'
            self.target.owned_executables[record['pid']] = executable
            env = self.write(record, 'environment.txt', self.target.run("tr '\\0' '\\n' </proc/"+str(record['pid'])+
                "/environ | grep -E '^SAKAMOTO_(VPP_OWNER_TOKEN|PRODUCT_GENERATION|VPP_RUNTIME_DIR|RUNTIME_PROFILE)='").stdout)
            values = props(env)
            assert values['SAKAMOTO_PRODUCT_GENERATION'] == str(record['generation']) and values['SAKAMOTO_VPP_OWNER_TOKEN'] == owner['token']
            self.write(record, 'startup.conf', self.target.read(BASE+'/startup.conf'))
        else:
            record.update(generation=23410+index, runtime=self.target.temporary+'/'+label, log=self.target.temporary+'/'+label+'.log')
            runtime = record['runtime']
            if self.target.pixel:
                self.target.adb('shell', 'mkdir', '-p', runtime+'/shm')
                config = f'plugin_path {self.target.native}\ncpu {{ main-core 0 corelist-workers 1-2 }}\n'
                plugins, plugin, binary = self.target.native, 'libproduct_core_plugin.so', self.target.native+'/libvpp_runtime.so'
            else:
                self.target.run('mkdir -p '+shlex.quote(runtime+'/shm'))
                config = 'cpu { workers 2 }\n'
                plugins, plugin, binary = str(self.target.artifact/'lib/vpp_plugins'), 'product_core_plugin.so', str(self.target.artifact/'bin/vpp')
            config += f'''unix {{ nodaemon cli-no-pager runtime-dir {runtime} cli-listen {runtime}/cli.sock }}
socksvr {{ socket-name {runtime}/api.sock }}
statseg {{ socket-name {runtime}/stats.sock }}
plugins {{ path {plugins} plugin default {{ disable }} plugin {plugin} {{ enable }} }}
buffers {{ buffers-per-numa 512 }}
product-flow-runtime {{ entries 1024 }}
'''
            local_config = self.args.output/label/'startup.conf'
            save(local_config, config)
            if self.target.pixel:
                self.target.adb('push', local_config, runtime+'/startup.conf')
                config_path = runtime+'/startup.conf'
            else:
                config_path = str(local_config)
            environment = dict(SAKAMOTO_PRODUCT_GENERATION=str(record['generation']), SAKAMOTO_RUNTIME_PROFILE='root',
                SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID=self.target.uid, SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4',
                LD_LIBRARY_PATH=self.target.native, SAKAMOTO_VPP_RUNTIME_DIR=runtime,
                SAKAMOTO_VPP_SVM_DIR=runtime+'/shm', SAKAMOTO_VPP_OWNER_TOKEN='s234-'+label)
            record['pid'] = self.target.spawn([binary, '-c', config_path], record['log'], environment)
            self.write(record, 'launch.json', json.dumps(dict(argv=[binary, '-c', config_path], environment=environment, pid=record['pid']), indent=2)+'\n')
            deadline = time.monotonic()+25
            while time.monotonic() < deadline:
                assert self.target.alive(record['pid']), self.target.read(record['log'])
                if not self.target.run('test -S '+shlex.quote(runtime+'/cli.sock'), check=False).returncode:
                    text = self.cli(record, 'ready', 'show product root lanes')
                    if len(lanes := rows(text, 'root.lane ')) == 4 and all(l['ready'] == '1' for l in lanes):
                        break
                time.sleep(.05)
            else:
                raise RuntimeError('native startup deadline')
            for tool, span in (('iptables', '176:177'), ('ip6tables', '178:179')):
                for hook in ('OUTPUT', 'INPUT'):
                    extra = ['--dport', str(UDP), '-m', 'owner', '--uid-owner', self.target.uid] if hook == 'OUTPUT' else ['--sport', str(UDP)]
                    rule = [tool, '-w', '5', '-t', 'mangle', '-A', hook, '-o' if hook == 'OUTPUT' else '-i', 'lo',
                            '-p', 'udp', *extra, '-m', 'comment', '--comment', 'SAKAMOTO_S234_'+label,
                            '-j', 'NFQUEUE', '--queue-balance', span, '--queue-bypass']
                    self.target.run(shlex.join(rule))
                    self.rules.append(rule)
        self.cli(record, 'layout', 'product packet-trace limit 4096', 'show threads', 'show physmem')
        initial = self.snapshot(record, 'initial')
        record['initial_pool'] = pools(initial)
        record['usable'] = record['initial_pool']['available']+record['initial_pool']['threads'][1]
        assert 8 < record['usable'] < 1024, 'actual pool does not fit registered experiment'
        self.write(record, 'memory.txt', self.target.run('cat /proc/meminfo /proc/'+str(record['pid'])+'/status /proc/'+str(record['pid'])+'/smaps_rollup').stdout)
        self.write(record, 'fds-before.txt', self.target.run('ls -l /proc/'+str(record['pid'])+'/fd').stdout)
        self.write(record, 'hooks.txt', self.hooks())
        self.policy(record, 0, initial)
        return record

    def policy(self, record, mode, current=None):
        if current is None:
            current = self.cli(record, 'policy-before-'+str(mode), 'show product flows')
        revision = int(rows(current, 'policy.snapshot ')[0]['revision'])+1
        argv = [self.target.helpers+'/s217-policy', record['runtime']+'/api.sock', str(record['generation']),
                self.target.temporary+'/'+record['label']+'-policy', str(revision), str(mode), self.target.policy_uid, '0']
        output = self.target.run('env '+shlex.quote('LD_LIBRARY_PATH='+self.target.native)+' '+shlex.join(argv)).stdout
        assert 'policy rc=0 ' in output
        self.write(record, 'policy-'+str(revision)+'.txt', output)

    def plan(self, record, owner, number, label):
        result = []
        for index in range(number):
            family = (4, 6)[index % 2]
            while self.next_port < 60000:
                port = self.next_port
                self.next_port += 1
                facts = dict(l3=1, l4=1, family=family, protocol=17,
                    src=ipaddress.ip_address(LOCAL[family]).packed.rjust(16, b'\0').hex(),
                    dst=ipaddress.ip_address(HOSTS[family]).packed.rjust(16, b'\0').hex(),
                    src_port=port, dst_port=UDP, icmp_known=0)
                if owner_oracle.owner(facts) == owner:
                    break
            else:
                raise RuntimeError('source port plan exhausted')
            result.append(dict(family=family, owner=owner, port=port,
                nonce=f's234-{record["generation"]}-{label}-{index}-{time.time_ns()}'))
        return result

    def client(self, probe, timeout=2000):
        family = probe['family']
        return shlex.join([self.target.helpers+'/s223-udp', 'client', self.target.uid, str(family),
            LOCAL[family], str(probe['port']), HOSTS[family], str(UDP), '1', probe['nonce'], '1', str(timeout)])

    def seed(self, record, label, probes):
        record['probes'] += [dict(p, label=label) for p in probes]
        output = self.target.run('set -e; '+'; '.join(self.client(p) for p in probes), timeout=90).stdout
        self.write(record, label+'-clients.txt', output)
        assert len(rows(output, 'endpoint ')) == len(probes)
        assert all(r['received'] == '1' for r in rows(output, 'endpoint '))
        return self.drain(record, label+'-drained')

    def batch(self, record, count, on_packet=False, owner=0):
        command = f'product flow-end close owner {owner} generation {record["generation"]} batch {count} udp-port {UDP}'
        if on_packet:
            command += ' on-packet'
        text = self.cli(record, 'batch-request-'+str(owner), command)
        assert 'flow-end.close=queued' in text

    def recovery_probes(self, record, trigger):
        # One target-side command: the first new request does not wait for
        # supervisor restart, polling, CLI, or host-side ADB round trips.
        probes = []
        commands = [self.client(trigger, 200), 'trigger_rc=$?', 'printf "trigger_exit=%s\\n" "$trigger_rc"', self.clock()]
        destinations = self.result.get('lan', HOSTS)
        for protocol in ('udp', 'tcp'):
            for family in (4, 6):
                port = self.next_port
                self.next_port += 1
                nonce = f's234-recovery-{record["generation"]}-{protocol}-{family}-{time.time_ns()}'
                address = destinations[family]
                local = ('0.0.0.0' if family == 4 else '::') if self.args.lan4 else LOCAL[family]
                argv = [self.target.helpers+'/s242-traffic', self.target.uid, protocol, str(family), local,
                    str(port), address, str(UDP if protocol == 'udp' else TCP), '1', '1000', nonce, '-', '2000']
                commands += [shlex.join(argv), self.clock()]
                probes.append(dict(protocol=protocol, family=family, port=port, nonce=nonce, destination=address))
        output = self.target.run('; '.join(commands), check=False, timeout=15)
        self.write(record, 'trigger-and-recovery.txt', output.stdout)
        record['recovery_probes'] = probes
        assert re.search(r'^trigger_exit=[1-9]\d*$', output.stdout, re.M), 'trigger was not interrupted by fatal'
        assert len(rows(output.stdout, 'traffic_end ')) == 4, output.stdout
        assert all(int(r['received']) > 0 and r['failed'] == '0' for r in rows(output.stdout, 'traffic_end ')), output.stdout

    def remove_rules(self):
        while self.rules:
            rule = list(self.rules[-1])
            rule[5] = '-D'
            self.target.run(shlex.join(rule))
            self.rules.pop()

    def stop(self, record, fatal=False):
        if self.supervisor:
            if fatal:
                self.wait_state(record, 'failed', lambda s: s.get('errorCode') == 'unexpected_exit' and s.get('mayBeActive') == 'false', timeout=10)
                self.write(record, 'cleanup-clock.txt', self.target.run(self.clock()).stdout)
                self.write(record, 'vpp.log', self.app('files/product-state/root-last-failure.log'))
                self.write(record, 'hooks-fatal.txt', self.hooks())
                self.target.queue_witness(self.args.output/record['label'], 'fatal-closed')
                self.write(record, 'failed-service.log', self.app('files/logs/runtime-service.log'))
            self.write(record, 'stop.txt', self.action('--ez', 'runtimeStop', 'true'))
            self.wait_state(record, 'stopped', lambda s: s.get('state') == 'stopped' and s.get('mayBeActive') == 'false' and not s.get('errorCode'))
            if not fatal:
                self.write(record, 'vpp.log', self.app('files/product-state/s242-last-stop.log'))
            self.write(record, 'service.log', self.app('files/logs/runtime-service.log'))
        else:
            if not fatal:
                deadline = time.monotonic()+2
                while True:
                    stopped = self.cli(record, 'native-stop', 'product root stop')
                    if 'root.stop=ok ' in stopped:
                        break
                    assert 'root.stop=draining ' in stopped and time.monotonic() < deadline, stopped
                    time.sleep(.01)
                closed = self.snapshot(record, 'native-closed')
                assert pools(closed)['used'] == 0 and all(e['entries'] == '0' for e in rows(closed, 'flow.pool '))
                self.write(record, 'fds-closed.txt', self.target.run('ls -l /proc/'+str(record['pid'])+'/fd').stdout)
            self.write(record, 'vpp.log', self.target.read(record['log']))
            if fatal:
                deadline = time.monotonic()+5
                while self.target.alive(record['pid']):
                    assert time.monotonic() < deadline, 'fatal runtime did not exit'
                    time.sleep(.01)
                self.write(record, 'cleanup-clock.txt', self.target.run(self.clock()).stdout)
                self.write(record, 'hooks-fatal.txt', self.hooks())
                self.target.queue_witness(self.args.output/record['label'], 'fatal-closed')
                if not self.target.pixel:
                    record['exit_code'] = self.target.children[record['pid']].returncode
            else:
                assert self.target.stop_process(record['pid'])
            self.remove_rules()
        record['process_absent'] = not self.target.alive(record['pid'])
        assert record['process_absent']
        record['termination'] = 'FATAL_OS_RECLAIM' if fatal else 'ORDERLY_DRAIN'
        record['closed'] = True
        self.write(record, 'hooks-after.txt', self.hooks())
        self.target.queue_witness(self.args.output/record['label'], 'closed')
        self.write(record, 'processes-after.txt', self.target.run('ps -A -o PID,UID,ARGS' if self.target.pixel else 'ps -eo pid,uid,args').stdout)

    def run(self):
        self.prepare()
        for index, label in enumerate(('normal', 'near', 'fatal', 'recovery')):
            self.next_port = 33000
            record = self.start(label, index)
            count = 8 if label in ('normal', 'recovery') else record['usable']+(-1 if label == 'near' else 1)
            record['batch_count'] = count
            seed = self.plan(record, 0, count, 'seed')+self.plan(record, 1, 2, 'peer')
            snapshot = self.seed(record, 'seed', seed)
            actual = pools(snapshot)
            assert actual['available']+actual['threads'][1] == record['usable'], 'pool changed while seeding'
            entries = rows(snapshot, 'flow.entry ')
            assert sum(e['worker'] == '0' and e['protocol'] == '17' and UDP in (int(e['port_a']), int(e['port_b'])) for e in entries) == count
            if label == 'fatal':
                trigger = self.plan(record, 0, 1, 'trigger')[0]
                record['trigger'] = trigger
                self.batch(record, count, on_packet=True)
                self.recovery_probes(record, trigger)
                self.stop(record, fatal=True)
            else:
                self.batch(record, count)
                self.drain(record, 'batch-drained')
                self.seed(record, 'after-close', self.plan(record, 0, 2, 'after')+self.plan(record, 1, 2, 'after-peer'))
                self.cli(record, 'runtime', 'show runtime')
                self.stop(record)
            print(self.args.platform, self.args.mode, label, 'captured', flush=True)
        self.result['status'] = 'RAW_COMPLETE'

    def cleanup(self):
        errors = []
        if self.supervisor:
            try:
                if props(self.app()).get('mayBeActive') != 'false' or props(self.app()).get('state') != 'stopped':
                    self.action('--ez', 'runtimeStop', 'true')
                    record = self.records[-1]
                    self.wait_state(record, 'cleanup-stop', lambda s: s.get('state') == 'stopped' and s.get('mayBeActive') == 'false')
            except Exception as error:
                errors.append(repr(error))
        else:
            try:
                self.remove_rules()
                for record in self.records:
                    if 'log' in record:
                        self.write(record, 'vpp-cleanup.log', self.target.read(record['log']))
                    if record.get('pid') and self.target.alive(record['pid']):
                        assert self.target.stop_process(record['pid'])
            except Exception as error:
                errors.append(repr(error))
        self.result['endpoint_cleanup'] = []
        for pid, path in self.endpoints:
            try:
                absent = self.target.stop_process(pid)
                self.result['endpoint_cleanup'].append(dict(pid=pid, process_absent=absent))
                save(self.args.output/Path(path).name, self.target.read(path))
            except Exception as error:
                errors.append(repr(error))
        self.result['host_endpoint_cleanup'] = []
        for process, path in self.host_endpoints:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=3)
            self.result['host_endpoint_cleanup'].append(dict(pid=process.pid, returncode=process.returncode,
                                                             process_absent=not Path('/proc/'+str(process.pid)).exists()))
        for address in self.addresses:
            try:
                self.target.run('ip -6 addr del '+address+'/128 dev lo')
            except Exception as error:
                errors.append(repr(error))
        save(self.args.output/'hooks-after.txt', self.hooks())
        save(self.args.output/'addresses-after.txt', self.target.run('ip -6 addr show dev lo').stdout)
        if self.target.pixel:
            save(self.args.output/'app-after.properties', self.app())
        self.result['cleanup_errors'] = errors
        if errors:
            self.result['status'] = 'HOLD'
        self.result['completed_ns'] = time.time_ns()
        self.result['raw_hashes'] = {str(p.relative_to(self.args.output)): digest(p) for p in self.args.output.rglob('*') if p.is_file() and p.name != 'result.json'}
        save(self.args.output/'result.json', json.dumps(self.result, indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', choices=('linux', 'pixel'), required=True)
    parser.add_argument('--mode', choices=('native', 'supervisor'), default='native')
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--helpers', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--vppctl', type=Path)
    parser.add_argument('--lan4')
    parser.add_argument('--lan6')
    parser.add_argument('--host-helpers', type=Path)
    args = parser.parse_args()
    assert args.platform == 'pixel' or args.mode == 'native'
    assert bool(args.lan4) == bool(args.lan6) == bool(args.host_helpers)
    for name in ('build', 'helpers', 'output', 'vppctl', 'host_helpers'):
        if getattr(args, name):
            setattr(args, name, getattr(args, name).resolve())
    assert args.platform == 'pixel' or args.vppctl
    args.output.mkdir(parents=True, exist_ok=False)
    build, helper = json.loads(args.build.read_text()), json.loads(args.helpers.read_text())
    assert chain.source_files() == build['files'] and helper['build_sha256'] == digest(args.build)
    assert helper['platform'] == args.platform
    for name, expected in helper['files'].items():
        assert digest(args.helpers.parent/name) == expected
    campaign = Campaign(args, build, helper)
    try:
        campaign.run()
    except Exception as error:
        campaign.result['error'] = repr(error)
        raise
    finally:
        campaign.cleanup()


if __name__ == '__main__':
    main()
