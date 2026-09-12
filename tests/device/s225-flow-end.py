#!/usr/bin/env python3
"""Real Linux NFQUEUE / Pixel Root UDP creation followed by owner-local END.

No timer scheduler, graph-injected packet, retained first packet, or substitute
cleanup. The existing target helper confines Linux to a rootless namespace and
Pixel to an idle app, exact temporary loopback rules and owned processes.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shlex
import time

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s242_target', ROOT/'tests/device/s242-root-lifecycle.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
Target, digest, rows, save = base.Target, base.digest, base.rows, base.save
PORT = 40625


class Campaign:
    def __init__(self, args, build, helper):
        self.args, self.build = args, build
        self.target = Target(args, build, helper)
        self.rules, self.addresses, self.endpoints, self.processes = [], [], [], []
        self.result = dict(status='HOLD', platform=args.platform, source='NFQ_CAPTURED',
            build=str(args.build), build_sha256=digest(args.build),
            helpers=str(args.helpers), helpers_sha256=digest(args.helpers),
            source_sha256=build['source_sha256'], started_ns=time.time_ns(),
            uid=self.target.uid, policy_uid=self.target.policy_uid, generations=[])

    def hooks(self):
        return self.target.run('iptables-save -t mangle').stdout+self.target.run('ip6tables-save -t mangle').stdout

    def prepare(self):
        initial = save(self.args.output/'hooks-before.txt', self.hooks())
        assert 'SAKAMOTO_S225_' not in initial
        listeners = save(self.args.output/'listeners-before.txt', self.target.run('ss -lnut').stdout)
        assert not re.search(r':40625\b', listeners), 'test endpoint port already in use'
        initial = save(self.args.output/'addresses-before.txt', self.target.run('ip -6 addr show dev lo').stdout)
        address = 'fd20:6225::2'
        if address+'/128' not in initial:
            self.target.run(f'ip -6 addr add {address}/128 dev lo nodad')
            self.addresses.append(address)
        for family, host in ((4, '127.0.0.2'), (6, address)):
            log = self.target.temporary+f'/s225-endpoint-{family}.log'
            pid = self.target.spawn([self.target.helpers+'/s223-udp', 'server', self.target.uid,
                                    str(family), host, str(PORT)], log)
            self.endpoints.append((pid, log))
            deadline = time.monotonic()+5
            while 'listen ' not in self.target.read(log):
                assert self.target.alive(pid) and time.monotonic() < deadline
                time.sleep(.02)

    def cli(self, record, label, *commands):
        return save(self.args.output/record['label']/(label+'.txt'),
                    self.target.cli(record['runtime'], commands))

    def snapshot(self, record, label):
        value = self.cli(record, label, 'show product flows', 'show product flow-end',
            'show product completion', 'show product root lanes', 'show product primary')
        save(self.args.output/record['label']/(label+'-vpp.log'), self.target.read(record['log']))
        return value

    def start(self, label, generation):
        out = self.args.output/label
        out.mkdir()
        runtime = self.target.temporary+'/'+label
        if self.target.pixel:
            self.target.adb('shell', 'mkdir', '-p', runtime+'/shm')
        else:
            self.target.run('mkdir -p '+shlex.quote(runtime+'/shm'))
        log = self.target.temporary+'/'+label+'-vpp.log'
        if self.target.pixel:
            config = f'''plugin_path {self.target.native}
cpu {{ main-core 0 corelist-workers 1-2 }}
unix {{ nodaemon nobanner cli-no-pager runtime-dir {runtime} cli-listen {runtime}/cli.sock }}
socksvr {{ socket-name {runtime}/api.sock }}
api-segment {{ prefix sakamoto-s225-{generation} }}
statseg {{ socket-name {runtime}/stats.sock }}
plugins {{ path {self.target.native} plugin default {{ disable }} plugin libproduct_core_plugin.so {{ enable }} }}
product-flow-runtime {{ entries 32 }}
'''
            save(out/'startup.conf', config)
            self.target.adb('push', out/'startup.conf', runtime+'/startup.conf')
            argv = [self.target.native+'/libvpp_runtime.so', '-c', runtime+'/startup.conf']
        else:
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
            SAKAMOTO_VPP_RUNTIME_DIR=runtime, SAKAMOTO_VPP_OWNER_TOKEN=f's225-native-{generation}')
        pid = self.target.spawn(argv, log, environment)
        record = dict(label=label, generation=generation, runtime=runtime, log=log, pid=pid, cases=[])
        self.processes.append(record)
        self.result['generations'].append(record)
        save(out/'launch.json', json.dumps(dict(argv=argv, environment=environment, pid=pid), indent=2)+'\n')
        deadline = time.monotonic()+25
        while time.monotonic() < deadline:
            assert self.target.alive(pid), self.target.read(log)
            if not self.target.run('test -S '+shlex.quote(runtime+'/cli.sock'), check=False).returncode:
                text = self.cli(record, 'ready', 'show product root lanes')
                lanes = rows(text, 'root.lane ')
                if len(lanes) == 4 and all(r['ready'] == '1' for r in lanes):
                    break
            time.sleep(.05)
        else:
            raise RuntimeError('native startup timeout '+self.target.read(log))
        self.cli(record, 'layout', 'product packet-trace limit 4096', 'show threads',
            'show node product-flow-consumer', 'show node product-packet-terminal',
            'show node product-flow-end-control')
        self.snapshot(record, 'initial')
        policy = [self.target.helpers+'/s217-policy', runtime+'/api.sock', str(generation),
                  runtime+'/policy', '1', '0', self.target.policy_uid, '0']
        if self.target.pixel:
            policy = ['env', 'LD_LIBRARY_PATH='+self.target.native, *policy]
        save(out/'policy.txt', self.target.run(shlex.join(policy)).stdout)
        for tool, span in (('iptables', '176:177'), ('ip6tables', '178:179')):
            for hook in ('OUTPUT', 'INPUT'):
                extra = ['--dport', str(PORT), '-m', 'owner', '--uid-owner', self.target.uid] if hook == 'OUTPUT' else ['--sport', str(PORT)]
                rule = [tool, '-w', '5', '-t', 'mangle', '-A', hook,
                    '-o' if hook == 'OUTPUT' else '-i', 'lo', '-p', 'udp', *extra,
                    '-m', 'comment', '--comment', 'SAKAMOTO_S225_'+label,
                    '-j', 'NFQUEUE', '--queue-balance', span, '--queue-bypass']
                self.target.run(shlex.join(rule))
                self.rules.append(rule)
        save(out/'hooks.txt', self.hooks())
        return record

    def probe(self, record, family, port, label):
        nonce = f's225-{record["generation"]}-{label}-{family}-{port}-{time.time_ns()}'
        client = [self.target.helpers+'/s223-udp', 'client', self.target.uid, str(family),
            '127.0.0.1' if family == 4 else '::1', str(port),
            '127.0.0.2' if family == 4 else 'fd20:6225::2', str(PORT), '1', nonce, '1', '3000']
        value = save(self.args.output/record['label']/(label+'-client.txt'), self.target.run(shlex.join(client)).stdout)
        assert len(rows(value, 'endpoint ')) == 1 and rows(value, 'endpoint ')[0]['received'] == '1'
        record.setdefault('probes', []).append(dict(label=label, nonce=nonce, family=family, port=port))
        return self.drain(record, label+'-after-probe')

    def drain(self, record, label, released=None):
        deadline = time.monotonic()+8
        while time.monotonic() < deadline:
            value = self.snapshot(record, label)
            completion = rows(value, 'completion.status ')
            ends = rows(value, 'flow-end.owner=')
            end_debt = re.search(r'^flow-end.buffers=(\d+)', value, re.M)
            if len(completion) == 1 and all(completion[0][k] == '0' for k in ('pending', 'frames', 'buffers', 'obligations')) \
                    and end_debt and end_debt[1] == '0' and len(ends) == 2 \
                    and (released is None or sum(int(e['released']) for e in ends) == released):
                return value
            assert self.target.alive(record['pid']), self.target.read(record['log'])
            time.sleep(.02)
        raise RuntimeError('packet/END drain timeout '+value)

    @staticmethod
    def entry(value, family, port):
        matches = [e for e in rows(value, 'flow.entry ') if int(e['family']) == family
            and e['protocol'] == '17' and port in (int(e['port_a']), int(e['port_b']))]
        assert len(matches) == 1, (family, port, matches)
        return matches[0]

    def exercise(self, record):
        seeds = [(family, 32500+i) for family in (4, 6) for i in range(6)]
        for number, (family, port) in enumerate(seeds):
            self.probe(record, family, port, f'seed-{number}')
        initial = self.snapshot(record, 'seeded')
        entries = [self.entry(initial, family, port) for family, port in seeds]
        assert {e['worker'] for e in entries} == {'0', '1'}
        released = 0
        for number, ((family, port), old) in enumerate(zip(seeds[:9], entries[:9])):
            mode = ('normal', 'early', 'replacement')[number % 3]
            label = f'close-{number}-{mode}'
            before = self.snapshot(record, label+'-before')
            command = f'product flow-end close owner {old["worker"]} slot {old["slot"]} generation {record["generation"]} incarnation {old["incarnation"]}'
            if mode == 'early': command += ' early expire'
            if mode == 'replacement': command += ' on-packet'
            assert 'flow-end.close=queued' in self.cli(record, label+'-request', command)
            if mode == 'replacement':
                self.probe(record, family, port, label)
            released += 1
            after = self.drain(record, label+'-after', released)
            if mode == 'replacement':
                new = self.entry(after, family, port)
                assert new['incarnation'] != old['incarnation'] and new['slot'] != old['slot']
            else:
                assert not any(e['worker'] == old['worker'] and e['incarnation'] == old['incarnation']
                               for e in rows(after, 'flow.entry '))
                previous = {r['lane']: r['verdicts'] for r in rows(before, 'root.lane ')}
                assert {r['lane']: r['verdicts'] for r in rows(after, 'root.lane ')} == previous
            record['cases'].append(dict(label=label, mode=mode, old=old, family=family, port=port))
        # Commands are delivered on the owner, but stale identities cannot
        # close or release its current entry. No deliberately invalid native
        # free or synthetic metadata is needed for these checks.
        current = self.snapshot(record, 'before-rejected')
        old = self.entry(current, *seeds[-1])
        for label, generation, incarnation in (
            ('stale-generation', record['generation']-1, int(old['incarnation'])),
            ('stale-incarnation', record['generation'], int(old['incarnation'])+100000)):
            command = f'product flow-end close owner {old["worker"]} slot {old["slot"]} generation {generation} incarnation {incarnation}'
            self.cli(record, label+'-request', command)
            deadline = time.monotonic()+5
            while time.monotonic() < deadline:
                value = self.snapshot(record, label+'-after')
                if all(e['control'] == '0' for e in rows(value, 'flow-end.owner=')):
                    break
                time.sleep(.02)
            else: raise RuntimeError('rejected control did not execute')
            assert self.entry(value, *seeds[-1]) == old
            assert sum(int(e['released']) for e in rows(value, 'flow-end.owner=')) == released
        self.snapshot(record, 'before-stop')
        self.cli(record, 'runtime', 'show runtime', 'show threads')

    def remove_rules(self):
        while self.rules:
            removal = list(self.rules[-1])
            removal[5] = '-D'
            self.target.run(shlex.join(removal))
            self.rules.pop()

    def stop(self, record):
        self.remove_rules()
        out = self.args.output/record['label']
        save(out/'hooks-after.txt', self.hooks())
        if self.target.alive(record['pid']):
            before = self.snapshot(record, 'drain-before-stop')
            deadline = time.monotonic()+5
            while time.monotonic() < deadline:
                response = self.cli(record, 'stop', 'product root stop')
                if 'root.stop=ok' in response: break
                time.sleep(.02)
            else: raise RuntimeError('Root did not stop')
            after = self.snapshot(record, 'closed')
            assert all(e['entries'] == '0' for e in rows(after, 'flow.pool '))
            assert 'flow-end.buffers=0' in after
            assert sum(int(e['allocated']) for e in rows(before, 'flow-end.owner=')) == \
                sum(int(e['allocated']) for e in rows(after, 'flow-end.owner='))
            assert all(e['ending'] == '0' and e['active_entries'] == '0' for e in rows(after, 'flow-end.owner='))
            self.target.queue_witness(out, 'closed')
            save(out/'fds-closed.txt', self.target.run('ls -l /proc/'+str(record['pid'])+'/fd').stdout)
        save(out/'vpp.log', self.target.read(record['log']))
        record['process_closed'] = self.target.stop_process(record['pid'])
        assert record['process_closed']

    def cleanup(self):
        self.remove_rules()
        for record in self.processes:
            if self.target.alive(record['pid']):
                self.stop(record)
        for pid, logfile in self.endpoints:
            save(self.args.output/Path(logfile).name, self.target.read(logfile))
            assert self.target.stop_process(pid)
        for address in self.addresses:
            self.target.run(f'ip -6 addr del {address}/128 dev lo')
        save(self.args.output/'hooks-after.txt', self.hooks())
        save(self.args.output/'addresses-after.txt', self.target.run('ip -6 addr show dev lo').stdout)


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
    if args.vppctl: args.vppctl = args.vppctl.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    build, helper = json.loads(args.build.read_text()), json.loads(args.helpers.read_text())
    assert helper['build_sha256'] == digest(args.build) and helper['platform'] == args.platform
    for name, expected in helper['files'].items():
        assert digest(args.helpers.parent/name) == expected
    campaign = Campaign(args, build, helper)
    sources = [Path(__file__).relative_to(ROOT).as_posix(),
               'tests/device/s242-root-lifecycle.py', 'tests/device/s233-fail-open.py']
    campaign.result['test_sources'] = {name: digest(ROOT/name) for name in sources}
    for name in sources:
        destination = args.output/'test-source'/name
        destination.parent.mkdir(parents=True, exist_ok=True)
        save(destination, (ROOT/name).read_text())
    try:
        campaign.prepare()
        for index in range(2):
            record = campaign.start('generation-'+str(index), 22510+index)
            campaign.exercise(record)
            campaign.stop(record)
        campaign.result['status'] = 'RAW_COMPLETE'
    except Exception as error:
        campaign.result['status'] = 'HOLD'
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
