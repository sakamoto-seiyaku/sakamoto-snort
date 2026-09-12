#!/usr/bin/env python3
"""Real endpoint evidence for the default-on owner-local UDP expiry driver."""
import argparse
import importlib.util
import ipaddress
import itertools
import json
from pathlib import Path
import re
import shlex
import time

ROOT = Path(__file__).resolve().parents[2]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT/relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


base = module('s227_target', 'tests/device/s242-root-lifecycle.py')
chain = module('s227_chain', 'tests/evidence/product_chain.py')
oracle = module('s227_oracle', 'tests/device/s207-owner-oracle.py')
Target, save, digest = base.Target, base.save, base.digest
PORT = 40627
LOCAL = {4: '127.0.0.1', 6: '::1'}
REMOTE = {4: '127.0.0.2', 6: 'fd20:6227::2'}
COUNTS = {'first': 2, 'renew-first': 2, 'shorten': 2, 'renew-bidir': 2,
          'bulk': 512, 'lookup': 4096, 'stop': 2}
PLAN = 'docs/testing/2026-09-13_S227_UDP_EXPIRY.md'


def rows(value, prefix):
    # Unlike event-label lines, expiry.owner=N has a field in token zero.
    # Preserve it rather than dropping the first whitespace token.
    return [dict(part.split('=', 1) for part in line.split() if '=' in part)
            for line in value.splitlines() if line.startswith(prefix)]


def tuples(count):
    result = []
    for owner in (0, 1):
        for family in (4, 6):
            found = 0
            for port in range(10000, 60000):
                if found == count//2: break
                ip = lambda value: ipaddress.ip_address(value).packed.rjust(16, b'\0').hex()
                facts = dict(l3=1, l4=1, family=family, protocol=17,
                    src=ip(LOCAL[family]), dst=ip(REMOTE[family]),
                    src_port=port, dst_port=PORT, icmp_known=0)
                assigned = oracle.assignment(facts)
                if assigned['owner'] == owner:
                    result.append(dict(owner=owner, family=family, port=port, expected=assigned))
                    found += 1
            assert found == count//2
    middle = (min(r['port'] for r in result)+max(r['port'] for r in result))//2
    low = sorted((r for r in result if r['port'] <= middle), key=lambda r: (r['port'], r['family']))
    high = sorted((r for r in result if r['port'] > middle), key=lambda r: (r['port'], r['family']))
    return [row for pair in itertools.zip_longest(low, high) for row in pair if row is not None]


class Campaign:
    def __init__(self, args, build, helper):
        self.args, self.build = args, build
        self.target = Target(args, build, helper)
        self.records, self.rules, self.addresses, self.endpoints = [], [], [], []
        self.result = dict(status='HOLD', platform=args.platform, source='NFQ_CAPTURED',
            build=str(args.build), build_sha256=digest(args.build), source_sha256=build['source_sha256'],
            helpers=str(args.helpers), helpers_sha256=digest(args.helpers),
            uid=self.target.uid, policy_uid=self.target.policy_uid, started_ns=time.time_ns(),
            requested_cases=args.cases.split(','), generations=self.records)
        names = ['tests/device/s227-udp-expiry.py', 'tests/device/s242-root-lifecycle.py',
                 'tests/device/s233-fail-open.py', 'tests/device/s207-owner-oracle.py',
                 'tests/evidence/product_chain.py', PLAN]
        self.result['test_sources'] = {name: digest(ROOT/name) for name in names}
        for name in names:
            destination = args.output/'test-source'/name
            destination.parent.mkdir(parents=True, exist_ok=True)
            save(destination, (ROOT/name).read_text())
        if self.target.pixel:
            self.target.adb('push', args.helpers.parent/'s227-udp', self.target.helpers+'/s227-udp')
            self.target.run('chmod 755 '+shlex.quote(self.target.helpers+'/s227-udp'))
            actual = save(args.output/'s227-udp-installed.txt', self.target.run(
                'sha256sum '+shlex.quote(self.target.helpers+'/s227-udp')).stdout)
            assert actual.split()[0] == helper['files']['s227-udp']

    def write(self, record, name, text):
        return save(self.args.output/record['label']/name, text)

    def cli(self, record, label, *commands):
        return self.write(record, label+'.txt', self.target.cli(record['runtime'], commands))

    def snapshot(self, record, label):
        return self.cli(record, label, 'show product expiry', 'show product flows',
            'show product flow-end', 'show product root lanes', 'show product completion',
            'show buffers detail', 'show runtime', 'show threads')

    def hooks(self):
        return self.target.run('iptables-save -t mangle').stdout+self.target.run('ip6tables-save -t mangle').stdout

    def prepare(self):
        assert 'SAKAMOTO_S227_' not in save(self.args.output/'hooks-before.txt', self.hooks())
        text = save(self.args.output/'listeners-before.txt', self.target.run('ss -lnut').stdout)
        assert not re.search(r':40627\b', text), 'S227 endpoint occupied'
        text = save(self.args.output/'addresses-before.txt', self.target.run('ip -6 addr show dev lo').stdout)
        if REMOTE[6]+'/128' not in text:
            self.target.run('ip -6 addr add '+REMOTE[6]+'/128 dev lo nodad')
            self.addresses.append(REMOTE[6])
        for family in (4, 6):
            log = self.target.temporary+f'/s227-server-{family}.log'
            pid = self.target.spawn([self.target.helpers+'/s223-udp', 'server', self.target.uid,
                                    str(family), REMOTE[family], str(PORT)], log)
            self.endpoints.append((pid, log))
            deadline = time.monotonic()+5
            while 'listen ' not in self.target.read(log):
                assert self.target.alive(pid) and time.monotonic() < deadline
                time.sleep(.05)

    def fds(self, record, label):
        self.write(record, label+'-fds.txt', self.target.run('ls -l /proc/'+str(record['pid'])+'/fd').stdout)
        expiry = rows(self.cli(record, label+'-expiry', 'show product expiry'), 'expiry.owner=')
        for owner in expiry:
            fd = int(owner['timer_fd'])
            if fd >= 0:
                self.write(record, label+'-fdinfo-'+owner['expiry.owner']+'.txt',
                    self.target.run('cat /proc/'+str(record['pid'])+'/fdinfo/'+str(fd)).stdout)

    def start(self, name):
        out = self.args.output/name
        out.mkdir()
        generation = 22710+len(self.records)
        runtime, log = self.target.temporary+'/'+name, self.target.temporary+'/'+name+'.log'
        if self.target.pixel:
            self.target.adb('shell', 'mkdir', '-p', runtime+'/shm')
            cpu = 'cpu { main-core 0 corelist-workers 1-2 }\n'
            plugins = f'path {self.target.native} plugin default {{ disable }} plugin libproduct_core_plugin.so {{ enable }}'
            prefix = 'plugin_path '+self.target.native+'\n'
        else:
            self.target.run('mkdir -p '+shlex.quote(runtime+'/shm'))
            cpu, prefix = 'cpu { workers 2 }\n', ''
            plugins = f'path {self.target.artifact}/lib/vpp_plugins plugin default {{ disable }} plugin product_core_plugin.so {{ enable }}'
        capacity = 4096 if name == 'lookup' else 1024
        config = prefix+cpu+f'''unix {{ nodaemon nobanner cli-no-pager runtime-dir {runtime} cli-listen {runtime}/cli.sock }}
socksvr {{ socket-name {runtime}/api.sock }}
api-segment {{ prefix sakamoto-s227-{generation} }}
statseg {{ socket-name {runtime}/stats.sock }}
plugins {{ {plugins} }}
product-flow-runtime {{ entries {capacity} }}
product-flow-expiry {{ trace-all }}
'''
        save(out/'startup.conf', config)
        if self.target.pixel:
            self.target.adb('push', out/'startup.conf', runtime+'/startup.conf')
            argv = [self.target.native+'/libvpp_runtime.so', '-c', runtime+'/startup.conf']
        else: argv = [str(self.target.artifact/'bin/vpp'), '-c', str(out/'startup.conf')]
        environment = dict(SAKAMOTO_PRODUCT_GENERATION=str(generation), SAKAMOTO_RUNTIME_PROFILE='root',
            SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID=self.target.uid, SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4',
            LD_LIBRARY_PATH=self.target.native, SAKAMOTO_VPP_SVM_DIR=runtime+'/shm',
            SAKAMOTO_VPP_RUNTIME_DIR=runtime, SAKAMOTO_VPP_OWNER_TOKEN=f's227-native-{generation}')
        pid = self.target.spawn(argv, log, environment)
        record = dict(label=name, case=name, generation=generation, pid=pid, runtime=runtime,
                      log=log, count_per_owner=COUNTS[name], capacity=capacity)
        self.records.append(record)
        self.write(record, 'launch.json', json.dumps(dict(argv=argv, environment=environment, pid=pid), indent=2)+'\n')
        deadline = time.monotonic()+25
        while time.monotonic() < deadline:
            assert self.target.alive(pid), self.target.read(log)
            if not self.target.run('test -S '+shlex.quote(runtime+'/cli.sock'), check=False).returncode:
                lanes = rows(self.cli(record, 'ready', 'show product root lanes'), 'root.lane ')
                if len(lanes) == 4 and all(r['ready'] == '1' for r in lanes): break
            time.sleep(.05)
        else: raise RuntimeError('native startup deadline')
        value = self.snapshot(record, 'initial')
        assert not rows(value, 'flow.entry ')
        expiry = rows(value, 'expiry.owner=')
        assert len(expiry) == 2 and all(r['mode'] == '2' and r['initialize'] == '0'
            and r['experiment'] == '0' and r['timers'] == '0' for r in expiry), 'production driver not default-on'
        self.fds(record, 'initial')
        policy = [self.target.helpers+'/s217-policy', runtime+'/api.sock', str(generation),
                  runtime+'/policy', '1', '0', self.target.policy_uid, '0']
        if self.target.pixel: policy = ['env', 'LD_LIBRARY_PATH='+self.target.native, *policy]
        self.write(record, 'policy.txt', self.target.run(shlex.join(policy)).stdout)
        selected = tuples(COUNTS[name])
        self.write(record, 'tuples.json', json.dumps(selected, indent=2)+'\n')
        self.write(record, 'tuples.txt', ''.join(f'{r["owner"]} {r["family"]} {r["port"]}\n' for r in selected))
        low, high = min(r['port'] for r in selected), max(r['port'] for r in selected)
        middle = (low+high)//2
        for tool, first_queue in (('iptables', 176), ('ip6tables', 178)):
            for hook in ('OUTPUT', 'INPUT'):
                extra = ['--dport', str(PORT), '-m', 'owner', '--uid-owner', self.target.uid] if hook == 'OUTPUT' else ['--sport', str(PORT)]
                for index, (first, last) in enumerate(((low, middle), (middle+1, high))):
                    rule = [tool, '-w', '5', '-t', 'mangle', '-A', hook, '-o' if hook == 'OUTPUT' else '-i',
                        'lo', '-p', 'udp', *extra, '--sport' if hook == 'OUTPUT' else '--dport', f'{first}:{last}',
                        '-m', 'comment', '--comment', 'SAKAMOTO_S227_'+name,
                        '-j', 'NFQUEUE', '--queue-num', str(first_queue+index), '--queue-bypass']
                    self.target.run(shlex.join(rule))
                    self.rules.append(rule)
        self.write(record, 'hooks.txt', self.hooks())
        self.target.queue_witness(out, 'running')
        return record

    def seed(self, record):
        path = self.args.output/record['label']/'tuples.txt'
        remote = record['runtime']+'/tuples.txt'
        if self.target.pixel: self.target.adb('push', path, remote)
        else: remote = str(path)
        record['nonce'] = 's227-'+str(record['generation'])+'-'+str(time.time_ns())
        record['client_log'] = record['runtime']+'/client.log'
        argv = [self.target.helpers+'/s227-udp', record['case'], self.target.uid, remote,
            LOCAL[4], LOCAL[6], REMOTE[4], REMOTE[6], str(PORT), record['nonce']]
        record['client_pid'] = self.target.spawn(argv, record['client_log'])
        # The host syscall broker takes ~85s to prepare 8192 bound sockets
        # (also measured in S226). No UDP is sent until preparation finishes;
        # this is not a protocol-timeout extension or a slower expiry gate.
        preparation = time.monotonic()
        self.wait_phase(record, 1 if record['case'] == 'lookup' else 0, timeout=180)
        record['endpoint_prepare_and_initial_phase_wait_s'] = time.monotonic()-preparation
        text = self.snapshot(record, 'seeded')
        entries = rows(text, 'flow.entry ')
        assert len(entries) == record['count_per_owner']*2, 'incomplete actual initial flow set'
        assert all(r['capacity_drops'] == '0' for r in rows(text, 'flow.pool '))
        echo = record['case'] in ('bulk', 'lookup', 'renew-bidir')
        assert all(int(r['packets']) >= (2 if echo else 1) for r in entries)
        assert all(r['captured'] == r['submitted'] == r['verdicts'] == r['succeeded']
                   for r in rows(text, 'root.lane ')), 'initial capture used processing bypass'
        assert sum(int(r['timers']) for r in rows(text, 'expiry.owner=')) == len(entries)
        self.fds(record, 'armed')

    def wait_phase(self, record, phase, timeout=75):
        deadline = time.monotonic()+timeout
        while time.monotonic() < deadline:
            text = self.target.read(record['client_log'])
            if any(int(r['phase']) == phase for r in rows(text, 'stage ')):
                self.write(record, 'client-phase'+str(phase)+'.txt', text)
                return
            if not self.target.alive(record['client_pid']):
                self.write(record, 'client-failed.txt', text)
                raise RuntimeError('UDP endpoint exited before phase '+str(phase))
            time.sleep(.2)
        self.write(record, 'client-failed.txt', self.target.read(record['client_log']))
        raise RuntimeError('UDP phase deadline')

    def quiet(self, record, label, seconds):
        print(json.dumps(dict(event='quiet', case=record['case'], interval=label, seconds=seconds)), flush=True)
        started = time.monotonic()
        time.sleep(seconds)
        record.setdefault('quiet_intervals', []).append(dict(label=label, seconds=seconds,
                                                           actual_s=time.monotonic()-started))

    def exercise(self, record):
        self.seed(record)
        name = record['case']
        if name == 'stop':
            for owner in (0, 1):
                value = self.cli(record, 'stale-'+str(owner),
                    f'product expiry validate stale-wake owner {owner} generation {record["generation"]-1}')
                assert 'expiry.stale=queued' in value
            deadline = time.monotonic()+5
            while time.monotonic() < deadline:
                text = self.snapshot(record, 'after-stale')
                if all(r['stale_wakes'] == '1' for r in rows(text, 'expiry.owner=')): break
                time.sleep(.05)
            else: raise RuntimeError('old generation wake was not rejected')
            assert len(rows(text, 'flow.entry ')) == 4
            self.fds(record, 'before-stop')
        elif name == 'first':
            self.quiet(record, 'first-real-60s', 65)
        elif name in ('renew-first', 'shorten', 'renew-bidir'):
            self.wait_phase(record, 1)
            self.snapshot(record, 'refreshed')
            self.fds(record, 'refreshed')
            if name != 'shorten':
                self.quiet(record, 'past-original-deadline', 42 if name == 'renew-first' else 12)
                text = self.snapshot(record, 'past-original-deadline')
                assert len(rows(text, 'flow.entry ')) == 4, 'renewed entries expired at the original deadline'
                assert all(r['released'] == '0' for r in rows(text, 'expiry.owner='))
                self.quiet(record, 'renewed-deadline', 25)
            else: self.quiet(record, 'shortened-real-30s', 35)
        elif name == 'bulk':
            self.quiet(record, 'bulk-real-30s', 35)
        elif name == 'lookup':
            self.wait_phase(record, 2)
            self.snapshot(record, 'after-lookup')
            self.quiet(record, 'original-backlog', 6)
            text = self.snapshot(record, 'backlog-drained')
            assert len(rows(text, 'flow.entry ')) == 4, 'old backlog or missing new logical-expiry instances'
            assert all(r['logical_expired'] == '2' for r in rows(text, 'expiry.owner=')), 'no real expired lookup on both owners'
            self.quiet(record, 'new-instance-real-30s', 31)
        else: raise AssertionError(name)
        text = self.snapshot(record, 'completed')
        if name != 'stop':
            assert not rows(text, 'flow.entry '), 'flow residue after actual deadline'
            assert all(r['timers'] == '0' for r in rows(text, 'expiry.owner='))
            self.fds(record, 'disarmed')
        self.write(record, 'client-final.txt', self.target.read(record['client_log']))
        self.write(record, 'vpp.log', self.target.read(record['log']))

    def remove_rules(self):
        while self.rules:
            command = list(self.rules[-1])
            command[5] = '-D'
            self.target.run(shlex.join(command))
            self.rules.pop()

    def stop(self, record):
        self.remove_rules()
        if self.target.alive(record['pid']):
            try:
                text = self.cli(record, 'stop', 'product root stop')
                assert 'root.stop=ok' in text
                self.snapshot(record, 'closed')
                self.fds(record, 'closed')
                self.target.queue_witness(self.args.output/record['label'], 'closed')
            finally:
                self.write(record, 'vpp.log', self.target.read(record['log']))
                assert self.target.stop_process(record['pid'])
        record['process_closed'] = True
        if record.get('client_pid'):
            self.write(record, 'client-closed.txt', self.target.read(record['client_log']))
            assert self.target.stop_process(record['client_pid'])
            record['client_closed'] = True
        self.write(record, 'hooks-after.txt', self.hooks())
        print(json.dumps(dict(event='case_complete', case=record['case'], generation=record['generation'])), flush=True)

    def cleanup(self):
        self.remove_rules()
        errors = []
        for record in self.records:
            if self.target.alive(record['pid']):
                try: self.stop(record)
                except Exception as error: errors.append(repr(error))
            if record.get('client_pid') and not record.get('client_closed'):
                self.write(record, 'client-closed.txt', self.target.read(record['client_log']))
                assert self.target.stop_process(record['client_pid'])
                record['client_closed'] = True
        for pid, log in self.endpoints:
            save(self.args.output/Path(log).name, self.target.read(log))
            assert self.target.stop_process(pid)
        for address in self.addresses:
            self.target.run('ip -6 addr del '+address+'/128 dev lo')
        save(self.args.output/'hooks-after.txt', self.hooks())
        save(self.args.output/'addresses-after.txt', self.target.run('ip -6 addr show dev lo').stdout)
        if errors: raise RuntimeError('cleanup errors: '+repr(errors))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', choices=('linux', 'pixel'), required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--helpers', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--vppctl', type=Path)
    parser.add_argument('--cases', default=','.join(COUNTS))
    args = parser.parse_args()
    cases = args.cases.split(',')
    assert cases and len(cases) == len(set(cases)) and all(name in COUNTS for name in cases)
    for name in ('build', 'helpers', 'output'):
        setattr(args, name, getattr(args, name).resolve())
    if args.vppctl: args.vppctl = args.vppctl.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    build, helper = json.loads(args.build.read_text()), json.loads(args.helpers.read_text())
    assert chain.source_files() == build['files'], 'Product source differs from artifact'
    assert helper['build_sha256'] == digest(args.build) and helper['platform'] == args.platform
    for name, expected in helper['files'].items(): assert digest(args.helpers.parent/name) == expected
    campaign = Campaign(args, build, helper)
    try:
        campaign.prepare()
        for name in cases:
            record = campaign.start(name)
            campaign.exercise(record)
            campaign.stop(record)
        assert chain.source_files() == build['files'], 'Product source changed during collection'
        campaign.result['status'] = 'RAW_COMPLETE'
    except Exception as error:
        campaign.result['error'] = repr(error)
        raise
    finally:
        try: campaign.cleanup()
        except Exception as error:
            campaign.result['status'] = 'HOLD'
            campaign.result['cleanup_error'] = repr(error)
            raise
        finally:
            campaign.result['completed_ns'] = time.time_ns()
            campaign.result['raw_hashes'] = {p.relative_to(args.output).as_posix(): digest(p)
                for p in args.output.rglob('*') if p.is_file() and p.name != 'result.json'}
            save(args.output/'result.json', json.dumps(campaign.result, indent=2)+'\n')
    print(json.dumps(dict(status=campaign.result['status'], output=str(args.output)), indent=2))


if __name__ == '__main__':
    main()
