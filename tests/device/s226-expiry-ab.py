#!/usr/bin/env python3
"""Collect default-off Product expiry arms on real Linux NFQUEUE / Pixel Root.

This collector does not decide a winner. The preregistration and independent
verifier own acceptance. No CLI/ADB polling occurs inside measured intervals.
"""
import argparse
import importlib.util
import itertools
import ipaddress
import json
import os
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


base = module('s226_target', 'tests/device/s242-root-lifecycle.py')
chain = module('s226_chain', 'tests/evidence/product_chain.py')
oracle = module('s226_oracle', 'tests/device/s207-owner-oracle.py')
Target, save, digest, rows, props = base.Target, base.save, base.digest, base.rows, base.props
PORT = 40626
LOCAL, REMOTE = {4: '127.0.0.1', 6: '::1'}, {4: '127.0.0.2', 6: 'fd20:6226::2'}
CASES = {'empty': (0, 60, False), 'long': (2, 45, False),
         'bulk100': (100, 40, True), 'bulk1000': (1000, 40, True),
         'maximum': (4096, 45, True), 'screen-off': (2, 65, False),
         'forced-doze': (2, 65, False)}
REGISTRATION = 'docs/testing/2026-09-12_S226_EXPIRY_AB_REGISTRATION.md'
REGISTERED_SHA256 = '8231814b508fd7b5f082d3e2df2b25c6acae6fe1a61de4315fa9ad30a005e29a'


def events(text, event):
    return rows(text, 's226 event='+event+' ')


def tuples(count):
    result = []
    for owner in range(2):
        for family in (4, 6):
            got = 0
            for port in range(10000, 60000):
                if got == count // 2:
                    break
                ip = lambda value: ipaddress.ip_address(value).packed.rjust(16, b'\0').hex()
                facts = dict(l3=1, l4=1, family=family, protocol=17,
                    src=ip(LOCAL[family]), dst=ip(REMOTE[family]),
                    src_port=port, dst_port=PORT, icmp_known=0)
                expected = oracle.assignment(facts)
                if expected['owner'] == owner:
                    result.append(dict(owner=owner, family=family, port=port, expected=expected))
                    got += 1
            assert got == count // 2
    # Balance the private capture across the existing four queues. The
    # kernel's address-only loopback queue hash otherwise hits just two.
    # Original Product owner assignment remains the independent typed key.
    if not result: return []
    midpoint = (min(row['port'] for row in result)+max(row['port'] for row in result))//2
    low = sorted((r for r in result if r['port'] <= midpoint), key=lambda r: (r['port'], r['family']))
    high = sorted((r for r in result if r['port'] > midpoint), key=lambda r: (r['port'], r['family']))
    return [row for pair in itertools.zip_longest(low, high) for row in pair if row is not None]


class Campaign:
    def __init__(self, args, build, helper):
        self.args, self.build = args, build
        self.target = Target(args, build, helper)
        self.records, self.rules, self.endpoints, self.addresses = [], [], [], []
        self.changed_screen = self.changed_doze = False
        self.result = dict(status='HOLD', platform=args.platform, build=str(args.build),
            build_sha256=digest(args.build), source_sha256=build['source_sha256'],
            helpers=str(args.helpers), helpers_sha256=digest(args.helpers),
            uid=self.target.uid, policy_uid=self.target.policy_uid, source='NFQ_CAPTURED',
            started_ns=time.time_ns(), generations=self.records,
            generation_start=args.generation_start,
            requested_cases=args.cases.split(','), repetitions=args.repetitions)
        sources = ['tests/device/s226-expiry-ab.py', 'tests/device/s242-root-lifecycle.py',
                   'tests/device/s233-fail-open.py', 'tests/device/s207-owner-oracle.py',
                   'tests/evidence/product_chain.py', REGISTRATION]
        self.result['test_sources'] = {name: digest(ROOT/name) for name in sources}
        for name in sources:
            destination = args.output/'test-source'/name
            destination.parent.mkdir(parents=True, exist_ok=True)
            save(destination, (ROOT/name).read_text())
        if self.target.pixel:
            for name in ('s226-seed', 's226-monitor'):
                self.target.adb('push', args.helpers.parent/name, self.target.helpers+'/'+name)
                self.target.run('chmod 755 '+shlex.quote(self.target.helpers+'/'+name))
                actual = save(args.output/(name+'-installed.txt'), self.target.run(
                    'sha256sum '+shlex.quote(self.target.helpers+'/'+name)).stdout)
                assert actual.split()[0] == helper['files'][name]

    def write(self, record, name, value):
        return save(self.args.output/record['label']/name, value)

    def cli(self, record, label, *commands):
        return self.write(record, label+'.txt', self.target.cli(record['runtime'], commands))

    def snapshot(self, record, label):
        return self.cli(record, label, 'show product expiry', 'show product flows',
            'show product flow-end', 'show product root lanes', 'show product completion',
            'show buffers detail', 'show runtime', 'show threads')

    def hooks(self):
        return self.target.run('iptables-save -t mangle').stdout + self.target.run('ip6tables-save -t mangle').stdout

    def environment(self, label):
        if self.target.pixel:
            for name in ('battery', 'thermalservice', 'deviceidle', 'power'):
                save(self.args.output/(label+'-'+name+'.txt'), self.target.adb('shell', 'dumpsys', name).stdout)

    def prepare(self):
        assert 'SAKAMOTO_S226_' not in save(self.args.output/'hooks-before.txt', self.hooks())
        value = save(self.args.output/'listeners-before.txt', self.target.run('ss -lnut').stdout)
        assert not re.search(r':40626\b', value), 'experiment endpoint occupied'
        value = save(self.args.output/'addresses-before.txt', self.target.run('ip -6 addr show dev lo').stdout)
        if REMOTE[6]+'/128' not in value:
            self.target.run('ip -6 addr add '+REMOTE[6]+'/128 dev lo nodad')
            self.addresses.append(REMOTE[6])
        self.environment('initial')
        if self.target.pixel:
            idle = (self.args.output/'initial-deviceidle.txt').read_text()
            assert 'mForceIdle=false' in idle and 'mScreenOn=true' in idle
        for family, host in REMOTE.items():
            log = self.target.temporary+f'/s226-server-{family}.log'
            pid = self.target.spawn([self.target.helpers+'/s223-udp', 'server',
                self.target.uid, str(family), host, str(PORT)], log)
            self.endpoints.append((pid, log))
            deadline = time.monotonic()+5
            while 'listen ' not in self.target.read(log):
                assert self.target.alive(pid) and time.monotonic() < deadline
                time.sleep(.02)

    def screen(self, case):
        self.screen_transition = None
        if not self.target.pixel:
            return
        transition = None
        if case in ('screen-off', 'forced-doze'):
            self.target.adb('shell', 'input', 'keyevent', '223')
            self.changed_screen = True
            # KEYCODE_SLEEP returns before Android has completed its display
            # transition. A dump ~600ms later can still say mScreenOn=true.
            # Confirm the requested state outside all measured intervals;
            # do not relabel an early pre-window snapshot as screen-off.
            started = time.monotonic()
            transition = []
            self.screen_transition = transition
            while time.monotonic() - started < 10:
                idle = self.target.adb('shell', 'dumpsys', 'deviceidle').stdout
                power = self.target.adb('shell', 'dumpsys', 'power').stdout
                transition.append(dict(elapsed_s=time.monotonic()-started,
                                       deviceidle=idle, power=power))
                if ('mScreenOn=false' in idle and 'mWakefulnessChanging=false' in power
                        and re.search(r'^\s*mWakefulness=(?:Dozing|Asleep)\s*$', power, re.M)):
                    break
                time.sleep(.1)
            else:
                raise RuntimeError('screen transition deadline')
        if case == 'forced-doze':
            self.target.adb('shell', 'dumpsys', 'deviceidle', 'force-idle', 'deep')
            self.changed_doze = True
        return transition

    def restore(self):
        if self.changed_doze:
            self.target.adb('shell', 'dumpsys', 'deviceidle', 'unforce')
            self.changed_doze = False
        if self.changed_screen:
            self.target.adb('shell', 'input', 'keyevent', '224')
            self.changed_screen = False

    def start(self, case, arm, repetition):
        label = f'{case}-{repetition}-{arm}'
        out = self.args.output/label
        out.mkdir()
        generation = self.args.generation_start+len(self.records)
        runtime, log = self.target.temporary+'/'+label, self.target.temporary+'/'+label+'.log'
        if self.target.pixel:
            self.target.adb('shell', 'mkdir', '-p', runtime+'/shm')
            config = f'plugin_path {self.target.native}\ncpu {{ main-core 0 corelist-workers 1-2 }}\n'
            plugins = f'path {self.target.native} plugin default {{ disable }} plugin libproduct_core_plugin.so {{ enable }}'
        else:
            self.target.run('mkdir -p '+shlex.quote(runtime+'/shm'))
            config = 'cpu { workers 2 }\n'
            plugins = f'path {self.target.artifact}/lib/vpp_plugins plugin default {{ disable }} plugin product_core_plugin.so {{ enable }}'
        config += f'''unix {{ nodaemon nobanner cli-no-pager runtime-dir {runtime} cli-listen {runtime}/cli.sock }}
socksvr {{ socket-name {runtime}/api.sock }}
api-segment {{ prefix sakamoto-s226-{generation} }}
statseg {{ socket-name {runtime}/stats.sock }}
plugins {{ {plugins} }}
product-flow-runtime {{ entries 4096 }}
'''
        save(out/'startup.conf', config)
        if self.target.pixel:
            self.target.adb('push', out/'startup.conf', runtime+'/startup.conf')
            argv = [self.target.native+'/libvpp_runtime.so', '-c', runtime+'/startup.conf']
        else:
            argv = [str(self.target.artifact/'bin/vpp'), '-c', str(out/'startup.conf')]
        environment = dict(SAKAMOTO_PRODUCT_GENERATION=str(generation), SAKAMOTO_RUNTIME_PROFILE='root',
            SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID=self.target.uid, SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4',
            LD_LIBRARY_PATH=self.target.native, SAKAMOTO_VPP_SVM_DIR=runtime+'/shm',
            SAKAMOTO_VPP_RUNTIME_DIR=runtime, SAKAMOTO_VPP_OWNER_TOKEN=f's226-native-{generation}')
        pid = self.target.spawn(argv, log, environment)
        record = dict(label=label, case=case, arm=arm, repetition=repetition, generation=generation,
                      runtime=runtime, log=log, pid=pid, count_per_owner=CASES[case][0])
        self.records.append(record)
        save(out/'launch.json', json.dumps(dict(argv=argv, environment=environment, pid=pid), indent=2)+'\n')
        deadline = time.monotonic()+25
        while time.monotonic() < deadline:
            assert self.target.alive(pid), self.target.read(log)
            if not self.target.run('test -S '+shlex.quote(runtime+'/cli.sock'), check=False).returncode:
                value = self.cli(record, 'ready', 'show product root lanes')
                lanes = rows(value, 'root.lane ')
                if len(lanes) == 4 and all(r['ready'] == '1' for r in lanes): break
            time.sleep(.05)
        else: raise RuntimeError('native startup deadline')
        value = self.snapshot(record, 'initial')
        assert len(rows(value, 'flow.entry ')) == 0
        assert len(rows(value, 'expiry.owner=')) == 2
        assert all(r['mode'] == '0' and r['timer_fd'] == '-1' for r in rows(value, 'expiry.owner='))
        status = self.write(record, 'setup-status.txt', self.target.run('cat /proc/'+str(pid)+'/status').stdout)
        assert int(re.search(r'^VmHWM:\s+(\d+) kB', status, re.M)[1]) < 256*1024, 'startup RSS exceeds registration'
        policy = [self.target.helpers+'/s217-policy', runtime+'/api.sock', str(generation),
                  runtime+'/policy', '1', '0', self.target.policy_uid, '0']
        if self.target.pixel:
            policy = ['env', 'LD_LIBRARY_PATH='+self.target.native, *policy]
        self.write(record, 'policy.txt', self.target.run(shlex.join(policy)).stdout)
        selected = tuples(CASES[case][0])
        lower = min((r['port'] for r in selected), default=10000)
        upper = max((r['port'] for r in selected), default=59999)
        midpoint = (lower+upper)//2
        record['capture_port_ranges'] = [[lower, midpoint], [midpoint+1, upper]]
        for tool, first_queue in (('iptables', 176), ('ip6tables', 178)):
            for hook in ('OUTPUT', 'INPUT'):
                extra = ['--dport', str(PORT), '-m', 'owner', '--uid-owner', self.target.uid] if hook == 'OUTPUT' else ['--sport', str(PORT)]
                for index, (low, high) in enumerate(record['capture_port_ranges']):
                    rule = [tool, '-w', '5', '-t', 'mangle', '-A', hook,
                        '-o' if hook == 'OUTPUT' else '-i', 'lo', '-p', 'udp', *extra,
                        '--sport' if hook == 'OUTPUT' else '--dport', f'{low}:{high}',
                        '-m', 'comment', '--comment', 'SAKAMOTO_S226_'+label,
                        '-j', 'NFQUEUE', '--queue-num', str(first_queue+index), '--queue-bypass']
                    self.target.run(shlex.join(rule)); self.rules.append(rule)
        self.write(record, 'hooks.txt', self.hooks())
        self.write(record, 'fds-before.txt', self.target.run('ls -l /proc/'+str(pid)+'/fd').stdout)
        self.target.queue_witness(out, 'running')
        return record

    def seed(self, record):
        selected = tuples(record['count_per_owner'])
        self.write(record, 'tuples.json', json.dumps(selected, indent=2)+'\n')
        path = self.args.output/record['label']/'tuples.txt'
        save(path, ''.join(f'{t["family"]} {t["port"]}\n' for t in selected))
        remote = record['runtime']+'/tuples.txt'
        if self.target.pixel:
            self.target.adb('push', path, remote)
        else:
            remote = str(path)
        if not selected:
            self.write(record, 'seed-client.txt', '')
            return
        nonce = 's226-'+str(record['generation'])+'-'+str(time.time_ns())
        record['nonce'] = nonce
        argv = [self.target.helpers+'/s226-seed', self.target.uid, remote, LOCAL[4], LOCAL[6],
                REMOTE[4], REMOTE[6], str(PORT), nonce, str(int(CASES[record['case']][2]))]
        record['seed_log'] = record['runtime']+'/seed-client.log'
        record['seed_pid'] = self.target.spawn(argv, record['seed_log'])
        deadline = time.monotonic()+180
        while True:
            value = self.target.read(record['seed_log'])
            if rows(value, 'seed-summary '): break
            if not self.target.alive(record['seed_pid']):
                self.write(record, 'seed-client.txt', value)
                raise RuntimeError('seed helper exited: '+value[-300:])
            assert time.monotonic() < deadline, 'seed setup/send deadline'
            time.sleep(.2)
        self.write(record, 'seed-client.txt', value)
        assert len(rows(value, 'seed ')) == len(selected)
        summary = rows(value, 'seed-summary ')[0]
        assert int(summary['count']) == len(selected) and int(summary['retained_fds']) == len(selected)

    def measure(self, record, label, seconds, quiet_since=None):
        self.environment(record['label']+'-'+label+'-before')
        if quiet_since is not None:
            # Count the actual no-test-packet interval from the confirmed
            # seed snapshot. Setup/endpoint reads send no test packets and
            # stay outside measurement. Adding a fresh ten-second sleep
            # before those reads delayed Pixel's 45s idle window past the
            # unmodified FIRST 60s deadline.
            time.sleep(max(0, quiet_since + 10 - time.monotonic()))
            record['quiet_before_main_s'] = time.monotonic() - quiet_since
        # Keep the node-counter envelope adjacent to the monitor endpoints;
        # it must not include the remaining quiet wait above.
        before = self.cli(record, label+'-before', 'show product expiry', 'show product root lanes', 'show runtime')
        argv = [self.target.helpers+'/s226-monitor', str(record['pid']), str(seconds*1000)]
        print(json.dumps(dict(event='interval', label=record['label'], interval=label, seconds=seconds)), flush=True)
        self.write(record, label+'-monitor.txt', self.target.run(shlex.join(argv), timeout=seconds+20).stdout)
        after = self.cli(record, label+'-after', 'show product expiry', 'show product root lanes', 'show runtime')
        self.environment(record['label']+'-'+label+'-after')
        record.setdefault('intervals', []).append(dict(label=label, seconds=seconds))
        assert sum(int(l['captured']) for l in rows(before, 'root.lane ')) == \
               sum(int(l['captured']) for l in rows(after, 'root.lane ')), 'new traffic during no-packet interval'

    def exercise(self, record):
        if record['case'] == 'maximum':
            memory = self.write(record, 'maximum-memory.txt', self.target.run('cat /proc/meminfo').stdout)
            assert int(re.search(r'^MemAvailable:\s+(\d+) kB', memory, re.M)[1]) >= 512*1024
        self.seed(record)
        value = self.snapshot(record, 'seeded')
        quiet_since = time.monotonic()
        entries = rows(value, 'flow.entry ')
        assert len(entries) == 2*record['count_per_owner'], 'incomplete real flow set'
        expected = {str(i): record['count_per_owner'] for i in (0, 1)}
        assert {r['worker']: int(r['entries']) for r in rows(value, 'flow.pool ')} == expected
        assert all(r['captured'] == r['submitted'] == r['verdicts'] == r['succeeded']
                   for r in rows(value, 'root.lane ')), 'seed used receive-side bypass'
        if CASES[record['case']][2]:
            assert all(r['packets'] == '2' and r['orig_packets'] == r['reply_packets'] == '1'
                       for r in entries), 'seed not fully bidirectional'
            spreads = {owner: max(int(e['last_seen']) for e in entries if int(e['worker']) == owner)
                       - min(int(e['last_seen']) for e in entries if int(e['worker']) == owner) for owner in (0, 1)}
            record['seed_spread_us'] = spreads
            assert max(spreads.values()) <= 1000000, 'simultaneous deadline spread exceeded: '+repr(spreads)
        command = f'product expiry experiment {record["arm"]} udp-port {PORT} generation {record["generation"]}'
        assert 'expiry.experiment=queued' in self.cli(record, 'enable', command)
        deadline = time.monotonic()+5
        while time.monotonic() < deadline:
            value = self.cli(record, 'initialized', 'show product expiry')
            if all(r['initialize'] == '0' for r in rows(value, 'expiry.owner=')): break
            time.sleep(.02)
        else: raise RuntimeError('owner initialization deadline')
        self.write(record, 'fds-enabled.txt', self.target.run('ls -l /proc/'+str(record['pid'])+'/fd').stdout)
        try:
            self.screen(record['case'])
        finally:
            transition = getattr(self, 'screen_transition', None)
            if transition is not None:
                self.write(record, 'screen-transition.json', json.dumps(transition, indent=2)+'\n')
        self.measure(record, 'main', CASES[record['case']][1], quiet_since=quiet_since)
        if record['case'] == 'long':
            # First 45 seconds are the registered idle interval. This later
            # wait observes the actual 60-second timeout, not a fake clock.
            self.measure(record, 'expiry-tail', 20)
        value = self.snapshot(record, 'expired')
        self.write(record, 'vpp.log', self.target.read(record['log']))
        record['observed_releases'] = len(events((self.args.output/record['label']/'vpp.log').read_text(), 'release'))
        assert all(e['entries'] == '0' for e in rows(value, 'flow.pool ')), 'entries did not expire'
        assert all(e['timers'] == '0' for e in rows(value, 'expiry.owner=')), 'timer residue'
        self.restore()

    def remove_rules(self):
        while self.rules:
            removal = list(self.rules[-1]); removal[5] = '-D'
            self.target.run(shlex.join(removal)); self.rules.pop()

    def stop(self, record):
        self.remove_rules()
        if self.target.alive(record['pid']):
            try:
                value = self.cli(record, 'stop', 'product root stop')
                assert 'root.stop=ok' in value
                self.snapshot(record, 'closed')
                self.target.queue_witness(self.args.output/record['label'], 'closed')
                self.write(record, 'fds-closed.txt', self.target.run('ls -l /proc/'+str(record['pid'])+'/fd').stdout)
            finally:
                self.write(record, 'vpp.log', self.target.read(record['log']))
                assert self.target.stop_process(record['pid'])
        record['process_closed'] = True
        if record.get('seed_pid'):
            self.write(record, 'seed-client-final.txt', self.target.read(record['seed_log']))
            assert self.target.stop_process(record['seed_pid'])
            record['seed_closed'] = True
        self.write(record, 'hooks-after.txt', self.hooks())
        print(json.dumps(dict(event='case_complete', label=record['label'], releases=record.get('observed_releases'))), flush=True)

    def cleanup(self):
        self.restore()
        self.remove_rules()
        failures = []
        for record in self.records:
            if self.target.alive(record['pid']):
                try: self.stop(record)
                except Exception as error: failures.append(repr(error))
            if record.get('seed_pid') and not record.get('seed_closed'):
                self.write(record, 'seed-client-final.txt', self.target.read(record['seed_log']))
                assert self.target.stop_process(record['seed_pid'])
                record['seed_closed'] = True
        for pid, log in self.endpoints:
            save(self.args.output/Path(log).name, self.target.read(log))
            assert self.target.stop_process(pid)
        for address in self.addresses:
            self.target.run('ip -6 addr del '+address+'/128 dev lo')
        save(self.args.output/'hooks-after.txt', self.hooks())
        save(self.args.output/'addresses-after.txt', self.target.run('ip -6 addr show dev lo').stdout)
        self.environment('final')
        if failures: raise RuntimeError('cleanup required abnormal stop: '+repr(failures))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', choices=('linux', 'pixel'), required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--helpers', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--vppctl', type=Path)
    parser.add_argument('--cases', default='empty,long,bulk100,bulk1000,maximum')
    parser.add_argument('--repetitions', type=int, default=1)
    parser.add_argument('--generation-start', type=int, default=22610)
    args = parser.parse_args()
    assert 1 <= args.repetitions <= 3
    assert 0 < args.generation_start < 2**63-42
    assert all(name in CASES for name in args.cases.split(','))
    for name in ('build', 'helpers', 'output'):
        setattr(args, name, getattr(args, name).resolve())
    if args.vppctl: args.vppctl = args.vppctl.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    build, helper = json.loads(args.build.read_text()), json.loads(args.helpers.read_text())
    assert digest(ROOT/REGISTRATION) == REGISTERED_SHA256, 'preregistration changed'
    assert chain.source_files() == build['files']
    assert helper['build_sha256'] == digest(args.build) and helper['platform'] == args.platform
    for name, expected in helper['files'].items(): assert digest(args.helpers.parent/name) == expected
    campaign = Campaign(args, build, helper)
    try:
        campaign.prepare()
        for case in args.cases.split(','):
            for repetition in range(args.repetitions):
                for arm in (('poll', 'deadline') if repetition % 2 == 0 else ('deadline', 'poll')):
                    record = campaign.start(case, arm, repetition)
                    campaign.exercise(record)
                    campaign.stop(record)
        assert chain.source_files() == build['files'], 'Product source changed during collection'
        campaign.result['status'] = 'RAW_COMPLETE'
    except Exception as error:
        campaign.result['error'] = repr(error)
        raise
    finally:
        try:
            campaign.cleanup()
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
