#!/usr/bin/env python3
"""Real default TCP/ICMP expiry. Explicit capture windows are not fake clocks."""
import argparse
import importlib.util
import ipaddress
import json
from pathlib import Path
import shlex
import time

ROOT = Path(__file__).resolve().parents[2]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT/relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


base = module('s236_base', 'tests/device/s227-udp-expiry.py')
Target, save, digest, rows = base.Target, base.save, base.digest, base.rows
chain, oracle = base.chain, base.oracle
LOCAL, REMOTE = {4: '127.0.0.1', 6: '::1'}, {4: '127.0.0.2', 6: 'fd20:6236::2'}
PORT = 40636
PLAN = 'docs/testing/2026-09-13_S236_PROTOCOL_EXPIRY.md'
CASES = ['tcp-first', 'tcp-opening', 'tcp-fin-wait', 'tcp-closed', 'tcp-invalid',
         'icmp-first', 'icmp-reply', 'icmp-renew', 'icmp-shorten', 'long']
TIMEOUTS = {'tcp-first': 4, 'tcp-opening': 5, 'tcp-fin-wait': 8, 'tcp-closed': 9,
            'tcp-invalid': 4, 'icmp-first': 10, 'icmp-reply': 11, 'icmp-renew': 10,
            'icmp-shorten': 11, 'long': 6}
DURATION = {4: 30, 5: 30, 6: 86400, 7: 900, 8: 45, 9: 30, 10: 60, 11: 30}


def assigned(family, value, protocol):
    packed = lambda text: ipaddress.ip_address(text).packed.rjust(16, b'\0').hex()
    facts = dict(l3=1, l4=1 if protocol == 6 else 2, family=family, protocol=protocol,
        src=packed(LOCAL[family]), dst=packed(REMOTE[family]), src_port=value, dst_port=PORT,
        icmp_known=protocol != 6, icmp_type=8 if family == 4 else 128, icmp_code=0,
        icmp_id=value, icmp_seq=1)
    return oracle.assignment(facts)


class Campaign(base.Campaign):
    def __init__(self, args, build, helper):
        self.args, self.build = args, build
        self.target = Target(args, build, helper)
        self.records, self.rules, self.filters, self.addresses, self.endpoints = [], [], [], [], []
        self.controls = None
        self.result = dict(status='HOLD', platform=args.platform, source='NFQ_CAPTURED',
            build=str(args.build), build_sha256=digest(args.build), source_sha256=build['source_sha256'],
            helpers=str(args.helpers), helpers_sha256=digest(args.helpers),
            uid=self.target.uid, policy_uid=self.target.policy_uid, started_ns=time.time_ns(),
            requested_cases=args.cases.split(','), generations=self.records, endpoints=[])
        names = ['tests/device/s236-protocol-expiry.py', 'tests/device/s227-udp-expiry.py',
            'tests/device/s242-root-lifecycle.py', 'tests/device/s233-fail-open.py',
            'tests/device/s207-owner-oracle.py', 'tests/evidence/product_chain.py', PLAN]
        self.result['test_sources'] = {name: digest(ROOT/name) for name in names}
        for name in names:
            destination = args.output/'test-source'/name
            destination.parent.mkdir(parents=True, exist_ok=True)
            save(destination, (ROOT/name).read_text())
        if self.target.pixel:
            for name in ('s236-tcp', 's224-icmp', 's227-udp'):
                self.target.adb('push', args.helpers.parent/name, self.target.helpers+'/'+name)
                self.target.run('chmod 755 '+shlex.quote(self.target.helpers+'/'+name))
                actual = save(args.output/(name+'-installed.txt'), self.target.run(
                    'sha256sum '+shlex.quote(self.target.helpers+'/'+name)).stdout)
                assert actual.split()[0] == helper['files'][name]

    def prepare(self):
        assert 'SAKAMOTO_S236_' not in save(self.args.output/'hooks-before.txt', self.hooks())
        save(self.args.output/'filter-before.txt', self.filter_hooks())
        if self.target.pixel:
            self.controls = self.target.run('mktemp -d /data/local/tmp/s236-control.XXXXXX').stdout.strip()
            assert self.controls.startswith('/data/local/tmp/s236-control.') and '/' not in self.controls[16:]
            self.target.run(shlex.join(['chown', self.target.uid+':'+self.target.uid, self.controls]))
            self.target.run(shlex.join(['chmod', '700', self.controls]))
            self.result['controls'] = self.controls
        listeners = save(self.args.output/'listeners-before.txt', self.target.run('ss -lnut').stdout)
        assert not any(':'+str(PORT+i) in listeners for i in (0, 1)), 'test endpoint occupied'
        initial = save(self.args.output/'addresses-before.txt', self.target.run('ip -6 addr show dev lo').stdout)
        if REMOTE[6]+'/128' not in initial:
            self.target.run('ip -6 addr add '+REMOTE[6]+'/128 dev lo nodad')
            self.addresses.append(REMOTE[6])
        for family in (4, 6):
            for mode, port in (('close', PORT), ('hold', PORT+1)):
                self.endpoint(f's236-tcp-{family}-{mode}', [self.target.helpers+'/s236-tcp', 'server',
                    self.target.uid, str(family), REMOTE[family], str(port), mode])
            self.endpoint(f's224-icmp-{family}', [self.target.helpers+'/s224-icmp', 'listen',
                self.target.uid, str(family), REMOTE[family]])

    def endpoint(self, name, argv):
        log = self.target.temporary+'/'+name+'.log'
        pid = self.target.spawn(argv, log)
        self.endpoints.append((pid, log))
        self.result['endpoints'].append(dict(pid=pid, log=log, argv=argv))
        self.wait_log(pid, log, 'listen ', 5)

    def wait_log(self, pid, log, marker, seconds=20):
        deadline = time.monotonic()+seconds
        while time.monotonic() < deadline:
            text = self.target.read(log)
            if marker in text: return text
            assert self.target.alive(pid), text
            time.sleep(.05)
        raise RuntimeError('endpoint wait deadline '+marker+' '+self.target.read(log))

    def filter_hooks(self):
        return self.target.run('iptables-save -t filter').stdout+self.target.run('ip6tables-save -t filter').stdout

    def snapshot(self, record, label):
        return self.cli(record, label, 'show product expiry', 'show product flows',
            'show product flow-end', 'show product root lanes', 'show product completion',
            'show product primary', 'show buffers detail', 'show runtime', 'show threads')

    def remove_filters(self):
        while self.filters:
            rule = list(self.filters[-1]); rule[5] = '-D'
            self.target.run(shlex.join(rule)); self.filters.pop()

    def start(self, name):
        out = self.args.output/name; out.mkdir()
        generation = 23610+CASES.index(name)
        capacity = getattr(self, 'runtime_capacity', 64)
        runtime, log = self.target.temporary+'/'+name, self.target.temporary+'/'+name+'.log'
        if self.target.pixel:
            self.target.adb('shell', 'mkdir', '-p', runtime+'/shm')
            cpu, prefix = 'main-core 0 corelist-workers 1-2', 'plugin_path '+self.target.native+'\n'
            plugins = f'path {self.target.native} plugin default {{ disable }} plugin libproduct_core_plugin.so {{ enable }}'
        else:
            self.target.run('mkdir -p '+shlex.quote(runtime+'/shm'))
            cpu, prefix = 'workers 2', ''
            plugins = f'path {self.target.artifact}/lib/vpp_plugins plugin default {{ disable }} plugin product_core_plugin.so {{ enable }}'
        config = prefix+f'''cpu {{ {cpu} }}
unix {{ nodaemon nobanner cli-no-pager runtime-dir {runtime} cli-listen {runtime}/cli.sock }}
socksvr {{ socket-name {runtime}/api.sock }}
api-segment {{ prefix sakamoto-s236-{generation} }}
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
            SAKAMOTO_VPP_RUNTIME_DIR=runtime, SAKAMOTO_VPP_OWNER_TOKEN=f's236-native-{generation}')
        pid = self.target.spawn(argv, log, environment)
        record = dict(label=name, case=name, generation=generation, pid=pid, runtime=runtime, log=log,
                      capacity=capacity, flows=[], clients=[], count_per_owner=4 if name == 'long' else 2)
        self.records.append(record)
        self.write(record, 'launch.json', json.dumps(dict(argv=argv, environment=environment, pid=pid), indent=2)+'\n')
        deadline = time.monotonic()+25
        while time.monotonic() < deadline:
            assert self.target.alive(pid), self.target.read(log)
            if not self.target.run('test -S '+shlex.quote(runtime+'/cli.sock'), check=False).returncode:
                lanes = rows(self.cli(record, 'ready', 'show product root lanes'), 'root.lane ')
                if len(lanes) == 4 and all(r['ready'] == '1' for r in lanes): break
            time.sleep(.05)
        else: raise RuntimeError('Product startup deadline')
        self.cli(record, 'layout', 'product packet-trace limit '+str(getattr(self, 'trace_limit', 4096)), 'show files', 'show threads')
        initial = self.snapshot(record, 'initial')
        assert not rows(initial, 'flow.entry ')
        assert all(r['mode'] == '2' and r['experiment'] == '0' and r['timers'] == '0'
                   for r in rows(initial, 'expiry.owner='))
        self.fds(record, 'initial')
        self.target.queue_witness(out, 'running')
        policy = [self.target.helpers+'/s217-policy', runtime+'/api.sock', str(generation),
                  runtime+'/policy', '1', '0', self.target.policy_uid, '0']
        if self.target.pixel: policy = ['env', 'LD_LIBRARY_PATH='+self.target.native, *policy]
        self.write(record, 'policy.txt', self.target.run(shlex.join(policy)).stdout)
        return record

    def captures(self, record, flow, mode='all'):
        family, protocol = flow['family'], flow['protocol']
        for reply in (False, True):
            if reply and mode in ('first', 'invalid'): continue
            src, dst = (REMOTE[family], LOCAL[family]) if reply else (LOCAL[family], REMOTE[family])
            rule = ['iptables' if family == 4 else 'ip6tables', '-w', '5', '-t', 'mangle', '-A',
                'OUTPUT', '-o', 'lo', '-s', src, '-d', dst, '-p', 'tcp' if protocol == 6 else
                'icmp' if family == 4 else 'ipv6-icmp']
            if protocol == 6:
                rule += ['--sport', str(flow['destination'] if reply else flow['value']),
                         '--dport', str(flow['value'] if reply else flow['destination'])]
                if mode in ('first', 'opening'): rule += ['--tcp-flags', 'SYN', 'SYN']
                elif mode == 'fin': rule += ['--tcp-flags', 'FIN', 'FIN']
                elif mode == 'invalid': rule += ['--tcp-flags', 'SYN,FIN', 'SYN,FIN']
            else:
                rule += ['--icmp-type' if family == 4 else '--icmpv6-type',
                         str((0 if reply else 8) if family == 4 else (129 if reply else 128))]
            rule += ['-m', 'comment', '--comment', 'SAKAMOTO_S236_'+record['label'], '-j', 'NFQUEUE',
                     '--queue-num', str(176+(family == 6)*2+flow['placement']), '--queue-bypass']
            self.target.run(shlex.join(rule)); self.rules.append(rule)

    def echo(self, record, flow, phase):
        nonce = flow['nonce']+'-'+phase
        command = [self.target.helpers+'/s224-icmp', 'probe', self.target.uid, str(flow['family']),
            LOCAL[flow['family']], REMOTE[flow['family']], str(flow['value']), str(len(flow['echoes'])),
            '1', 'echo', nonce]
        received = self.target.run(shlex.join(command)).stdout
        self.write(record, flow['label']+'-'+phase+'-client.txt', received)
        assert len(rows(received, 'endpoint ')) == 1
        flow['echoes'].append(dict(phase=phase, nonce=nonce))

    def command(self, record, flow, command):
        flow['commands'].append(command)
        local = self.args.output/record['label']/(flow['label']+'-control.txt')
        save(local, ''.join(c+'\n' for c in flow['commands']))
        if self.target.pixel: self.transfer_control(local, flow['control'])
        # Linux endpoint reads the local evidence file directly.
        self.wait_log(flow['pid'], flow['log'], 'phase='+str(len(flow['commands']))+' action='+command)

    def transfer_control(self, local, destination):
        stage = self.target.temporary+'/control-transfer.txt'
        self.target.adb('push', local, stage)
        self.target.run(shlex.join(['cp', stage, destination]))
        self.target.run(shlex.join(['chown', self.target.uid+':'+self.target.uid, destination]))
        self.target.run(shlex.join(['chmod', '600', destination]))

    def drain(self, record, label):
        deadline = time.monotonic()+10
        while time.monotonic() < deadline:
            text = self.snapshot(record, label)
            pending = rows(text, 'completion.status ')
            if pending and all(pending[0][key] == '0' for key in ('pending', 'frames', 'buffers', 'obligations')):
                return text
            time.sleep(.05)
        raise RuntimeError('completion did not drain')

    def seed(self, record):
        name = record['case']
        value = 15000+CASES.index(name)*400
        record['seed_started_monotonic'] = time.monotonic()
        for half in range(2 if name == 'long' else 1):
            for family in (4, 6):
                for owner in (0, 1):
                    protocol = 6 if name.startswith('tcp-') or name == 'long' else 1 if family == 4 else 58
                    while assigned(family, value, protocol)['owner'] != owner: value += 1
                    flow = dict(label='flow-'+str(len(record['flows'])), family=family, owner=owner,
                        placement=owner ^ ((family == 6) ^ (CASES.index(name) % 2)), value=value,
                        destination=PORT, protocol=protocol, closing=bool(half), echoes=[], commands=[],
                        expected=assigned(family, value, protocol), nonce=f's236-{record["generation"]}-{value}-{time.time_ns()}')
                    value += 1
                    record['flows'].append(flow)
                    if name != 'long': self.remove_rules()
                    mode = 'first' if name in ('tcp-first', 'tcp-invalid', 'icmp-first', 'icmp-renew', 'icmp-shorten') else 'opening' if name == 'tcp-opening' else 'all'
                    self.captures(record, flow, mode)
                    if protocol != 6:
                        self.echo(record, flow, 'seed')
                    else:
                        flow['log'] = record['runtime']+'/'+flow['label']+'.log'
                        local = self.args.output/record['label']/(flow['label']+'-control.txt')
                        save(local, '')
                        flow['control'] = self.controls+'/'+record['label']+'-'+flow['label']+'.control' if self.target.pixel else str(local)
                        if self.target.pixel: self.transfer_control(local, flow['control'])
                        argv = [self.target.helpers+'/s236-tcp', 'client', self.target.uid, str(family),
                            LOCAL[family], str(flow['value']), REMOTE[family], str(PORT), flow['nonce'], flow['control']]
                        flow['pid'] = self.target.spawn(argv, flow['log']); record['clients'].append(flow['pid'])
                        self.wait_log(flow['pid'], flow['log'], 'ready ')
                        self.drain(record, flow['label']+'-established')
                        if name == 'tcp-fin-wait':
                            self.remove_rules(); self.captures(record, flow, 'fin')
                            self.command(record, flow, 'fin')
                        elif name == 'tcp-closed': self.command(record, flow, 'rst')
                        elif half: self.command(record, flow, 'fin')
                    self.drain(record, flow['label']+'-seeded')
        if name != 'long': self.remove_rules()
        # Keep exact capture rules in place during quiet intervals: unsolicited
        # traffic cannot be hidden by removing a long-case flow from capture.
        for flow in record['flows']:
            if name == 'long': continue  # Exact TCP rules already retained from creation.
            if flow['protocol'] != 6:
                # ICMP rules are address/type scoped, not identifier filters;
                # one pair per family captures both owners without duplicates.
                if flow['owner']: continue
            mode = 'first' if name in ('tcp-first', 'tcp-invalid', 'icmp-first', 'icmp-renew', 'icmp-shorten') else 'opening' if name == 'tcp-opening' else 'fin' if name == 'tcp-fin-wait' else 'all'
            self.captures(record, flow, mode)
        self.write(record, 'hooks.txt', self.hooks())
        text = self.drain(record, 'seeded')
        assert len(rows(text, 'flow.entry ')) == len(record['flows']), 'initial flow count'
        timers = rows(text, 'flow.timer ')
        assert sorted(int(t['timeout']) for t in timers) == sorted(
            7 if f['closing'] else TIMEOUTS[name] if name not in ('icmp-shorten',) else 10 for f in record['flows']), 'initial timer class'
        self.fds(record, 'armed')
        record['seeded_monotonic'] = time.monotonic()
        self.write(record, 'vpp-seeded.log', self.target.read(record['log']))
        self.write(record, 'sockets-seeded.txt', self.target.run('ss -tnp').stdout)

    def quiet(self, record, label, seconds):
        started = time.monotonic()
        interval = dict(label=label, seconds=seconds, started_ns=time.time_ns())
        record.setdefault('quiet_intervals', []).append(interval)
        next_report = started
        while time.monotonic() < started+seconds:
            now = time.monotonic()
            if now >= next_report:
                assert self.target.alive(record['pid']), 'Product exited during quiet interval'
                progress = dict(event='quiet', case=record['case'], interval=label,
                    elapsed_s=round(now-started, 3), remaining_s=round(started+seconds-now, 3),
                    started_ns=interval['started_ns'], checked_ns=time.time_ns(), pid=record['pid'],
                    runtime=record['runtime'], output=str(self.args.output))
                save(self.args.output/'progress.json', json.dumps(progress, indent=2)+'\n')
                print(json.dumps(progress), flush=True)
                next_report = now+60
            time.sleep(min(10, max(0, started+seconds-time.monotonic())))
        interval.update(actual_s=time.monotonic()-started, completed_ns=time.time_ns())

    def exercise(self, record):
        name = record['case']
        if name == 'long':
            # Replace only the test's own close-mode listeners before any new
            # connection, keeping the same owner tuples and endpoint port.
            for family in (4, 6):
                item = next(x for x in self.endpoints if Path(x[1]).name == f's236-tcp-{family}-close.log')
                save(self.args.output/Path(item[1]).name, self.target.read(item[1]))
                assert self.target.stop_process(item[0]); self.endpoints.remove(item)
                self.endpoint(f's236-tcp-{family}-long', [self.target.helpers+'/s236-tcp', 'server',
                    self.target.uid, str(family), REMOTE[family], str(PORT), 'hold'])
        self.seed(record)
        if name in ('icmp-renew', 'icmp-shorten'):
            # Shortening must happen within 30 s of each FIRST packet. Device
            # setup itself consumes real time; use a short additional delay.
            self.quiet(record, 'before-refresh', 1 if name == 'icmp-shorten' else 20)
            self.remove_rules()
            for flow in record['flows']:
                self.remove_rules(); self.captures(record, flow, 'first' if name == 'icmp-renew' else 'all')
                self.echo(record, flow, 'refresh')
            text = self.drain(record, 'refreshed'); self.fds(record, 'refreshed')
            assert all(int(t['timeout']) == TIMEOUTS[name] for t in rows(text, 'flow.timer '))
            if name == 'icmp-shorten':
                original = rows((self.args.output/record['label']/'seeded.txt').read_text(), 'flow.timer ')
                key = lambda t: (t['worker'], t['slot'], t['incarnation'])
                deadlines = {key(t): int(t['deadline_us']) for t in original}
                assert all(key(t) in deadlines and int(t['deadline_us']) < deadlines[key(t)]
                           for t in rows(text, 'flow.timer ')), 'shortening stimulus was too late'
            if name == 'icmp-renew':
                self.quiet(record, 'past-original-deadline', 42)
                assert len(rows(self.snapshot(record, 'past-original'), 'flow.entry ')) == 4
                self.quiet(record, 'renewed-deadline', 25)
            else: self.quiet(record, 'shortened-deadline', 35)
        elif name == 'tcp-invalid':
            # Pixel's real shell/CLI setup has already consumed part of the
            # first 30-second deadline. Inject while every original is live;
            # the test must not confuse an expired miss with INVALID renewal.
            self.quiet(record, 'before-invalid', 1)
            self.remove_rules()
            for flow in record['flows']:
                self.captures(record, flow, 'invalid')
                rule = ['iptables' if flow['family'] == 4 else 'ip6tables', '-w', '5', '-t', 'filter', '-A',
                    'INPUT', '-i', 'lo', '-s', LOCAL[flow['family']], '-d', REMOTE[flow['family']], '-p', 'tcp',
                    '--sport', str(flow['value']), '--dport', str(PORT), '--tcp-flags', 'SYN,FIN', 'SYN,FIN',
                    '-m', 'comment', '--comment', 'SAKAMOTO_S236_invalid', '-j', 'DROP']
                self.target.run(shlex.join(rule)); self.filters.append(rule)
                argv = [self.target.helpers+'/s222-tcp', 'raw', str(flow['family']), LOCAL[flow['family']],
                    str(flow['value']), REMOTE[flow['family']], str(PORT), '3', '123', '0', '8192', '0']
                self.write(record, flow['label']+'-invalid.txt', self.target.run(shlex.join(argv)).stdout)
            self.write(record, 'filter-active.txt', self.filter_hooks())
            text = self.drain(record, 'invalid'); self.fds(record, 'invalid')
            assert len(rows(text, 'flow.entry ')) == 4, 'INVALID must observe live originals'
            self.quiet(record, 'original-deadline', 35)
        elif name == 'long':
            self.quiet(record, 'closing-actual-900s', 905)
            assert len(rows(self.snapshot(record, 'closing-expired'), 'flow.entry ')) == 4
            self.quiet(record, 'established-before-86400s', 86380-(time.monotonic()-record['seed_started_monotonic']))
            assert len(rows(self.snapshot(record, 'established-before-deadline'), 'flow.entry ')) == 4
            self.quiet(record, 'established-actual-86400s', record['seeded_monotonic']+86405-time.monotonic())
        else: self.quiet(record, 'actual-default-deadline', DURATION[TIMEOUTS[name]]+5)
        text = self.drain(record, 'completed')
        assert not rows(text, 'flow.entry '), 'residue after actual default deadline'
        assert all(r['timers'] == '0' for r in rows(text, 'expiry.owner='))
        self.fds(record, 'disarmed')
        self.write(record, 'sockets-expired.txt', self.target.run('ss -tnp').stdout)
        if name == 'long':
            for flow in record['flows']:
                if not flow['closing']: self.command(record, flow, 'echo')
            text = self.drain(record, 'post-expiry-echo')
            assert len(rows(text, 'flow.entry ')) == 4, 'held socket did not create a new midstream instance'
        self.write(record, 'vpp.log', self.target.read(record['log']))

    def stop(self, record):
        self.remove_filters()
        super().stop(record)
        for flow in record['flows']:
            if 'pid' in flow:
                self.write(record, flow['label']+'-client.txt', self.target.read(flow['log']))
                assert self.target.stop_process(flow['pid'])
        record['clients_closed'] = True

    def cleanup(self):
        self.remove_filters()
        try: super().cleanup()
        finally:
            for record in self.records:
                for pid in record['clients']:
                    if self.target.alive(pid): assert self.target.stop_process(pid)
                if self.controls:
                    for flow in record['flows']:
                        if 'control' in flow:
                            self.target.run(shlex.join(['rm', '-f', flow['control']]))
            if self.controls:
                self.target.run(shlex.join(['rmdir', self.controls]))
                self.result['controls_removed'] = True
            save(self.args.output/'filter-after.txt', self.filter_hooks())
            for endpoint in self.result['endpoints']:
                endpoint['process_absent'] = not self.target.alive(endpoint['pid'])
                assert endpoint['process_absent']
            if self.target.pixel:
                save(self.args.output/'app-after.properties', self.target.adb('shell', 'run-as',
                    'com.sakamoto.snort.androidruntime', 'cat', 'files/runtime-state/snapshot.properties').stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', choices=('linux', 'pixel'), required=True)
    for name in ('build', 'helpers', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--vppctl', type=Path)
    parser.add_argument('--cases', default=','.join(CASES[:-1]))
    args = parser.parse_args()
    cases = args.cases.split(',')
    assert cases and len(set(cases)) == len(cases) and all(name in CASES for name in cases)
    assert 'long' not in cases or cases[-1] == 'long', 'long case must be last'
    for name in ('build', 'helpers', 'output'): setattr(args, name, getattr(args, name).resolve())
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
            record = campaign.start(name); campaign.exercise(record); campaign.stop(record)
        assert chain.source_files() == build['files'], 'Product source changed during collection'
        campaign.result['status'] = 'RAW_COMPLETE'
    except Exception as error:
        campaign.result['error'] = repr(error)
        raise
    finally:
        try: campaign.cleanup()
        except Exception as error:
            campaign.result.update(status='HOLD', cleanup_error=repr(error)); raise
        finally:
            campaign.result['completed_ns'] = time.time_ns()
            campaign.result['raw_hashes'] = {p.relative_to(args.output).as_posix(): digest(p)
                for p in args.output.rglob('*') if p.is_file() and p.name != 'result.json'}
            save(args.output/'result.json', json.dumps(campaign.result, indent=2)+'\n')
    print(json.dumps(dict(status=campaign.result['status'], output=str(args.output)), indent=2))


if __name__ == '__main__': main()
