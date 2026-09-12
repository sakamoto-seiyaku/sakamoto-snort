#!/usr/bin/env python3
"""Source-bound real Echo endpoints on Linux NFQUEUE and installed Pixel Root."""
import argparse
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import shlex
import time

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT/path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


base = module('s224_target', 'tests/device/s242-root-lifecycle.py')
chain = module('s224_chain', 'tests/evidence/product_chain.py')
oracle = module('s224_owner', 'tests/device/s207-owner-oracle.py')
Target, save, digest = base.Target, base.save, base.digest
LOCAL = {4: '127.0.0.1', 6: '::1'}
REMOTE = {4: '127.0.0.2', 6: 'fd20:6224::2'}
PING = {4: '127.0.0.3', 6: 'fd20:6224::3'}


def rows(value, prefix):
    return [dict(part.split('=', 1) for part in line.split() if '=' in part)
            for line in value.splitlines() if line.startswith(prefix)]


def assignment(family, identifier):
    return oracle.assignment(dict(l3=1, l4=2, family=family, protocol=1 if family == 4 else 58,
        src=ipaddress.ip_address(LOCAL[family]).packed.rjust(16, b'\0').hex(),
        dst=ipaddress.ip_address(REMOTE[family]).packed.rjust(16, b'\0').hex(),
        src_port=0, dst_port=0, icmp_known=1, icmp_code=0,
        icmp_type=8 if family == 4 else 128, icmp_id=identifier))


class Campaign:
    def __init__(self, args, build, helpers):
        self.args, self.build = args, build
        self.target = Target(args, build, helpers)
        self.records, self.rules, self.addresses, self.endpoints = [], [], [], []
        self.result = dict(status='HOLD', platform=args.platform, source='NFQ_CAPTURED',
            build=str(args.build), build_sha256=digest(args.build), source_sha256=build['source_sha256'],
            helpers=str(args.helpers), helpers_sha256=digest(args.helpers),
            uid=self.target.uid, policy_uid=self.target.policy_uid, started_ns=time.time_ns(),
            generations=self.records)
        names = ['tests/device/s224-icmp-tracker.py', 'tests/device/s242-root-lifecycle.py',
            'tests/device/s233-fail-open.py', 'tests/device/s207-owner-oracle.py',
            'tests/evidence/product_chain.py', 'docs/testing/2026-09-13_S224_ICMP_TRACKER.md']
        self.result['test_inputs'] = {name: digest(ROOT/name) for name in names}
        for name in names:
            path = args.output/'test-source'/name
            path.parent.mkdir(parents=True, exist_ok=True)
            save(path, (ROOT/name).read_text())
        if self.target.pixel:
            self.target.adb('push', args.helpers.parent/'s224-icmp', self.target.helpers+'/s224-icmp')
            self.target.run('chmod 755 '+shlex.quote(self.target.helpers+'/s224-icmp'))
            actual = save(args.output/'s224-icmp-installed.txt', self.target.run(
                'sha256sum '+shlex.quote(self.target.helpers+'/s224-icmp')).stdout)
            assert actual.split()[0] == helpers['files']['s224-icmp']

    def write(self, record, name, text):
        return save(self.args.output/record['label']/name, text)

    def hooks(self):
        return self.target.run('iptables-save -t mangle').stdout+self.target.run('ip6tables-save -t mangle').stdout

    def prepare(self):
        assert 'SAKAMOTO_S224_' not in save(self.args.output/'hooks-before.txt', self.hooks())
        before = save(self.args.output/'addresses-before.txt', self.target.run('ip -6 addr show dev lo').stdout)
        for address in (REMOTE[6], PING[6]):
            if address+'/128' not in before:
                self.target.run('ip -6 addr add '+address+'/128 dev lo nodad')
                self.addresses.append(address)
        for family in (4, 6):
            for index, address in enumerate((LOCAL[family], REMOTE[family], PING[family])):
                log = self.target.temporary+f'/echo-{family}-{index}.log'
                argv = [self.target.helpers+'/s224-icmp', 'listen', self.target.uid, str(family), address]
                pid = self.target.spawn(argv, log)
                self.endpoints.append(dict(family=family, address=address, pid=pid, logfile=log,
                                           output=f'echo-{family}-{index}.log'))
                deadline = time.monotonic()+5
                while 'listen ' not in self.target.read(log):
                    assert self.target.alive(pid) and time.monotonic() < deadline, 'Echo listener not ready'
                    time.sleep(.02)

    def cli(self, record, name, *commands):
        return self.write(record, name+'.txt', self.target.cli(record['runtime'], commands))

    def snapshot(self, record, name):
        value = self.cli(record, name, 'show product flows', 'show product flow-end', 'show product expiry',
            'show product root lanes', 'show product completion', 'show product primary', 'show buffers')
        self.write(record, name+'-vpp.log', self.target.read(record['logfile']))
        return value

    def drain(self, record, name):
        end = time.monotonic()+8
        while time.monotonic() < end:
            value = self.snapshot(record, name)
            completion = rows(value, 'completion.status ')
            if len(completion) == 1 and all(completion[0][k] == '0' for k in ('pending', 'frames', 'buffers', 'obligations')):
                assert 'flow-end.buffers=0' in value
                return value
            assert self.target.alive(record['pid'])
            time.sleep(.02)
        raise RuntimeError('packet/END drain timeout')

    def start(self, label, generation):
        out = self.args.output/label
        out.mkdir()
        runtime = self.target.temporary+'/'+label
        if self.target.pixel:
            self.target.adb('shell', 'mkdir', '-p', runtime+'/shm')
            config = f'''plugin_path {self.target.native}
cpu {{ main-core 0 corelist-workers 1-2 }}
unix {{ nodaemon nobanner cli-no-pager runtime-dir {runtime} cli-listen {runtime}/cli.sock }}
socksvr {{ socket-name {runtime}/api.sock }}
api-segment {{ prefix sakamoto-s224-{generation} }}
statseg {{ socket-name {runtime}/stats.sock }}
plugins {{ path {self.target.native} plugin default {{ disable }} plugin libproduct_core_plugin.so {{ enable }} }}
product-flow-runtime {{ entries 32 }}
'''
            save(out/'startup.conf', config)
            self.target.adb('push', out/'startup.conf', runtime+'/startup.conf')
            argv = [self.target.native+'/libvpp_runtime.so', '-c', runtime+'/startup.conf']
        else:
            self.target.run('mkdir -p '+shlex.quote(runtime+'/shm'))
            config = f'''cpu {{ workers 2 }}
unix {{ nodaemon cli-no-pager poll-sleep-usec 0 runtime-dir {runtime} cli-listen {runtime}/cli.sock }}
socksvr {{ socket-name {runtime}/api.sock }}
statseg {{ socket-name {runtime}/stats.sock }}
plugins {{ path {self.target.artifact}/lib/vpp_plugins plugin default {{ disable }} plugin product_core_plugin.so {{ enable }} }}
product-flow-runtime {{ entries 32 }}
'''
            save(out/'startup.conf', config)
            argv = [str(self.target.artifact/'bin/vpp'), '-c', str(out/'startup.conf')]
        environment = dict(SAKAMOTO_PRODUCT_GENERATION=str(generation), SAKAMOTO_RUNTIME_PROFILE='root',
            SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID=self.target.uid, SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4',
            LD_LIBRARY_PATH=self.target.native, SAKAMOTO_VPP_SVM_DIR=runtime+'/shm',
            SAKAMOTO_VPP_RUNTIME_DIR=runtime, SAKAMOTO_VPP_OWNER_TOKEN=f's224-native-{generation}')
        pid = self.target.spawn(argv, self.target.temporary+'/'+label+'-vpp.log', environment)
        record = dict(label=label, generation=generation, hook=label.upper(), runtime=runtime, pid=pid,
            logfile=self.target.temporary+'/'+label+'-vpp.log', cases=[], pings=[])
        self.records.append(record)
        self.write(record, 'launch.json', json.dumps(dict(argv=argv, environment=environment, pid=pid), indent=2)+'\n')
        deadline = time.monotonic()+25
        while time.monotonic() < deadline:
            assert self.target.alive(pid), self.target.read(record['logfile'])
            if not self.target.run('test -S '+shlex.quote(runtime+'/cli.sock'), check=False).returncode:
                ready = rows(self.cli(record, 'ready', 'show product root lanes'), 'root.lane ')
                if len(ready) == 4 and all(r['ready'] == '1' for r in ready):
                    break
            time.sleep(.05)
        else:
            raise RuntimeError('Product startup timeout')
        self.cli(record, 'layout', 'product packet-trace limit 4096', 'show threads', 'show files')
        initial = self.snapshot(record, 'initial')
        self.write(record, 'fds-before.txt', self.target.run('ls -l /proc/'+str(pid)+'/fd').stdout)
        for owner in rows(initial, 'expiry.owner='):
            fd = int(owner['timer_fd'])
            self.write(record, 'timer-'+owner['expiry.owner']+'.txt', self.target.read(f'/proc/{pid}/fdinfo/{fd}'))
        self.target.queue_witness(out, 'initial')
        return record

    def remove_rules(self):
        while self.rules:
            rule = list(self.rules[-1])
            rule[5] = '-D'
            self.target.run(shlex.join(rule))
            self.rules.pop()

    def rules_for(self, record, family, placement, request_only=False, destination=None):
        self.remove_rules()
        tool = 'iptables' if family == 4 else 'ip6tables'
        protocol = 'icmp' if family == 4 else 'ipv6-icmp'
        destination = destination or REMOTE[family]
        for reply in (False, True):
            if reply and request_only:
                continue
            source, target = (destination, LOCAL[family]) if reply else (LOCAL[family], destination)
            kind = (0 if reply else 8) if family == 4 else (129 if reply else 128)
            rule = [tool, '-w', '5', '-t', 'mangle', '-A', record['hook'],
                '-o' if record['hook'] == 'OUTPUT' else '-i', 'lo', '-p', protocol,
                '-s', source, '-d', target, '--icmp-type' if family == 4 else '--icmpv6-type', str(kind),
                '-m', 'comment', '--comment', 'SAKAMOTO_S224_'+record['label'],
                '-j', 'NFQUEUE', '--queue-num', str(176+(family == 6)*2+placement), '--queue-bypass']
            self.target.run(shlex.join(rule))
            self.rules.append(rule)

    def probe(self, record, case, label, sequence, count, reply=False):
        family = case['family']
        source, destination = (REMOTE[family], LOCAL[family]) if reply else (LOCAL[family], REMOTE[family])
        nonce = f's224-{record["generation"]}-{case["identifier"]}-{label}-{time.time_ns()}'
        argv = [self.target.helpers+'/s224-icmp', 'probe', self.target.uid, str(family), source, destination,
                str(case['identifier']), str(sequence), str(count), 'reply' if reply else 'echo', nonce]
        path = case['label']+'-'+label
        answer = self.target.run(shlex.join(argv), check=False, timeout=15)
        self.write(record, path+'-client.txt', answer.stdout)
        phase = dict(label=label, path=path, nonce=nonce, sequence=sequence, count=count,
                     reply=reply, returncode=answer.returncode)
        case['phases'].append(phase)
        assert answer.returncode == 0 and len(rows(answer.stdout, 'endpoint ')) == count, answer.stdout
        endpoint = next(e for e in self.endpoints if e['family'] == family and e['address'] == destination)
        expected = [(nonce+'-'+str(i)).encode().hex() for i in range(count)]
        deadline = time.monotonic()+5
        while time.monotonic() < deadline:
            received = self.target.read(endpoint['logfile'])
            if all(value in received for value in expected):
                break
            time.sleep(.02)
        else:
            raise RuntimeError('independent Echo endpoint did not receive nonce')
        self.write(record, path+'-endpoint.txt', received)
        self.drain(record, path)

    def exercise(self, record):
        identifier = 24000
        for family in (4, 6):
            for owner in (0, 1):
                for placement in (owner, owner ^ 1):
                    for reply_first in (False, True):
                        while assignment(family, identifier)['owner'] != owner:
                            identifier += 1
                        case = dict(label='case-'+str(len(record['cases'])), family=family, owner=owner,
                            placement=placement, identifier=identifier, reply_first=reply_first, phases=[])
                        identifier += 1
                        record['cases'].append(case)
                        self.rules_for(record, family, placement, request_only=not reply_first)
                        self.write(record, case['label']+'-first-hooks.txt', self.hooks())
                        if reply_first:
                            self.probe(record, case, 'first-reply', 10, 2, reply=True)
                        else:
                            self.probe(record, case, 'first', 10, 1)
                            self.probe(record, case, 'repeat', 65535, 2)
                        self.rules_for(record, family, placement)
                        self.write(record, case['label']+'-bidir-hooks.txt', self.hooks())
                        self.probe(record, case, 'bidir', 20, 1 if reply_first else 2)
                        self.remove_rules()
            self.rules_for(record, family, 0, destination=PING[family])
            pattern = f'224{record["generation"]:08x}{family}abcdef'.ljust(32, '0')[:32]
            if self.target.pixel:
                argv = ['run-as', base.base.PKG, 'ping' if family == 4 else 'ping6', '-I', LOCAL[family],
                        '-c', '3', '-i', '0.2', '-W', '3', '-p', pattern, PING[family]]
                answer = self.target.adb('shell', *argv, check=False, timeout=20)
            else:
                argv = ['ping', '-4' if family == 4 else '-6', '-I', LOCAL[family], '-c', '3',
                        '-i', '0.2', '-W', '3', '-p', pattern, PING[family]]
                answer = self.target.run(shlex.join(argv), check=False, timeout=20)
            name = 'ping-'+str(family)
            self.write(record, name+'-client.txt', answer.stdout)
            record['pings'].append(dict(family=family, pattern=pattern, destination=PING[family],
                                       path=name, argv=argv, returncode=answer.returncode))
            assert answer.returncode == 0 and re.search(r'3 (?:packets )?received', answer.stdout), answer.stdout
            self.drain(record, name)
            self.remove_rules()
        self.drain(record, 'final')
        self.cli(record, 'runtime', 'show runtime', 'show threads', 'show files')
        record['raw_complete'] = True

    def stop(self, record):
        self.remove_rules()
        try:
            if self.target.alive(record['pid']):
                self.drain(record, 'before-stop')
                assert 'root.stop=ok' in self.cli(record, 'stop', 'product root stop')
                self.snapshot(record, 'closed')
                self.write(record, 'fds-closed.txt', self.target.run('ls -l /proc/'+str(record['pid'])+'/fd').stdout)
        finally:
            try:
                self.write(record, 'vpp.log', self.target.read(record['logfile']))
            finally:
                record['process_absent'] = self.target.stop_process(record['pid'])
                assert record['process_absent']
        self.target.queue_witness(self.args.output/record['label'], 'closed')
        self.write(record, 'hooks-after.txt', self.hooks())

    def cleanup(self):
        errors = []
        try:
            self.remove_rules()
        except Exception as error:
            errors.append(repr(error))
        for record in self.records:
            try:
                if self.target.alive(record['pid']):
                    self.stop(record)
            except Exception as error:
                errors.append(repr(error))
        for endpoint in self.endpoints:
            try:
                save(self.args.output/endpoint['output'], self.target.read(endpoint['logfile']))
            except Exception as error:
                errors.append(repr(error))
            finally:
                try:
                    endpoint['process_absent'] = self.target.stop_process(endpoint['pid'])
                    assert endpoint['process_absent']
                except Exception as error:
                    errors.append(repr(error))
        self.result['endpoints'] = self.endpoints
        for address in self.addresses:
            try:
                self.target.run('ip -6 addr del '+address+'/128 dev lo')
            except Exception as error:
                errors.append(repr(error))
        save(self.args.output/'hooks-after.txt', self.hooks())
        save(self.args.output/'addresses-after.txt', self.target.run('ip -6 addr show dev lo').stdout)
        if self.target.pixel:
            save(self.args.output/'app-after.properties', self.target.adb('shell', 'run-as', base.base.PKG,
                'cat', 'files/runtime-state/snapshot.properties').stdout)
        self.result['cleanup_errors'] = errors
        if errors:
            raise RuntimeError('cleanup errors: '+repr(errors))


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
    args.output.mkdir(parents=True, exist_ok=False)
    build, helpers = json.loads(args.build.read_text()), json.loads(args.helpers.read_text())
    assert chain.source_files() == build['files']
    assert helpers['build_sha256'] == digest(args.build) and helpers['platform'] == args.platform
    for name, expected in helpers['files'].items():
        assert digest(args.helpers.parent/name) == expected
    campaign = Campaign(args, build, helpers)
    try:
        campaign.prepare()
        for index, label in enumerate(('output', 'input')):
            record = campaign.start(label, 22410+index)
            campaign.exercise(record)
            campaign.stop(record)
            print('captured real Echo tracker: '+label, flush=True)
        campaign.result['status'] = 'RAW_COMPLETE'
    except Exception as error:
        campaign.result['error'] = repr(error)
        raise
    finally:
        try:
            campaign.cleanup()
        except Exception as error:
            campaign.result['cleanup_error'] = repr(error)
            campaign.result['status'] = 'HOLD'
        campaign.result['completed_ns'] = time.time_ns()
        campaign.result['raw_hashes'] = {str(path.relative_to(args.output)): digest(path)
            for path in args.output.rglob('*') if path.is_file() and path.name != 'result.json'}
        save(args.output/'result.json', json.dumps(campaign.result, indent=2)+'\n')
    assert campaign.result['status'] == 'RAW_COMPLETE'


if __name__ == '__main__':
    main()
