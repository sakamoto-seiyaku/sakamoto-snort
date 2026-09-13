#!/usr/bin/env python3
"""One real W2 heap: mixed default deadlines, renewal and expired lookup."""
import argparse
import importlib.util
import ipaddress
import itertools
import json
from pathlib import Path
import shlex
import time

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s236_protocol_collector', ROOT/'tests/device/s236-protocol-expiry.py')
base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
save, digest, rows, chain = base.save, base.digest, base.rows, base.chain
CASES = ['mixed-batch', 'mixed-renew', 'mixed-lookup']
base.CASES += CASES
LOCAL, REMOTE, PORT = base.LOCAL, base.REMOTE, base.PORT


def assigned(family, value, protocol):
    if protocol != 17: return base.assigned(family, value, protocol)
    ip = lambda text: ipaddress.ip_address(text).packed.rjust(16, b'\0').hex()
    return base.oracle.assignment(dict(l3=1, l4=1, family=family, protocol=17,
        src=ip(LOCAL[family]), dst=ip(REMOTE[family]), src_port=value, dst_port=PORT, icmp_known=0))


class Campaign(base.Campaign):
    runtime_capacity = 1024

    def __init__(self, args, build, helper):
        super().__init__(args, build, helper)
        name = 'tests/device/s236-mixed-expiry.py'
        self.result['test_sources'][name] = digest(ROOT/name)
        save(args.output/'test-source'/name, (ROOT/name).read_text())
        if self.target.pixel:
            for name in ('s236-mixed', 's236-wire'):
                self.target.adb('push', args.helpers.parent/name, self.target.helpers+'/'+name)
                self.target.run('chmod 755 '+shlex.quote(self.target.helpers+'/'+name))
                actual = save(args.output/(name+'-installed.txt'), self.target.run(
                    'sha256sum '+shlex.quote(self.target.helpers+'/'+name)).stdout)
                assert actual.split()[0] == helper['files'][name]

    def prepare(self):
        super().prepare()
        for family in (4, 6):
            self.endpoint(f's236-udp-{family}', [self.target.helpers+'/s223-udp', 'server',
                self.target.uid, str(family), REMOTE[family], str(PORT)])

    def select(self, record):
        groups = 4 if record['case'] == 'mixed-batch' else 1
        value = 21000+CASES.index(record['case'])*1000
        for _ in range(groups):
            for family in (4, 6):
                for owner in (0, 1):
                    for protocol in (6, 1 if family == 4 else 58):
                        while assigned(family, value, protocol)['owner'] != owner: value += 1
                        record['flows'].append(dict(label='flow-'+str(len(record['flows'])), protocol=protocol,
                            family=family, owner=owner, value=value, destination=PORT,
                            placement=owner ^ (family == 6), expected=assigned(family, value, protocol)))
                        value += 1
        count = 2048 if record['case'] == 'mixed-lookup' else groups
        selected = []
        for owner in (0, 1):
            for family in (4, 6):
                found = 0
                for value in range(10000, 20000):
                    if assigned(family, value, 17)['owner'] != owner: continue
                    selected.append(dict(owner=owner, family=family, port=value, expected=assigned(family, value, 17)))
                    found += 1
                    if found == count: break
                assert found == count
        # Balanced physical capture lanes keep the complete run under each
        # lane's 1024-packet trace bound (the global bound is 4096).
        selected.sort(key=lambda e: (e['port'], e['family']))
        if record['case'] == 'mixed-lookup':
            middle = (selected[0]['port']+selected[-1]['port'])//2
            low = [e for e in selected if e['port'] <= middle]
            high = [e for e in selected if e['port'] > middle]
            selected = [e for pair in itertools.zip_longest(low, high) for e in pair if e is not None]
        else:
            ordered = []
            for flow in record['flows'][::2]:
                match = next(e for e in selected if e['family'] == flow['family'] and
                             e['owner'] == flow['owner'] and e not in ordered)
                ordered.append(match)
            selected = ordered
        record['udp'] = selected
        record['count_per_owner'] = len(selected)//2+len(record['flows'])//2
        return selected

    def capture_udp(self, record):
        values = [e['port'] for e in record['udp']]
        low, high = min(values), max(values); middle = (low+high)//2
        for family in (4, 6):
            for reply in (False, True):
                for lane, (first, last) in enumerate(((low, middle), (middle+1, high))):
                    if first > last: continue
                    src, dst = (REMOTE[family], LOCAL[family]) if reply else (LOCAL[family], REMOTE[family])
                    rule = ['iptables' if family == 4 else 'ip6tables', '-w', '5', '-t', 'mangle', '-A',
                        'OUTPUT', '-o', 'lo', '-s', src, '-d', dst, '-p', 'udp',
                        '--sport' if reply else '--dport', str(PORT), '--dport' if reply else '--sport',
                        f'{first}:{last}', '-m', 'comment', '--comment', 'SAKAMOTO_S236_'+record['case'],
                        '-j', 'NFQUEUE', '--queue-num', str(176+(family == 6)*2+lane), '--queue-bypass']
                    self.target.run(shlex.join(rule)); self.rules.append(rule)

    def start(self, name):
        self.runtime_capacity = 4160 if name == 'mixed-lookup' else 1024
        self.trace_limit = 256 if name == 'mixed-lookup' else 4096
        record = super().start(name)
        record['trace_limit'] = self.trace_limit
        selected = self.select(record)
        self.write(record, 'tuples.json', json.dumps(selected, indent=2)+'\n')
        self.write(record, 'tuples.txt', ''.join(f'{e["owner"]} {e["family"]} {e["port"]}\n' for e in selected))
        self.write(record, 'mixed-tuples.txt', ''.join(f'{e["owner"]} {e["family"]} {e["protocol"]} {e["value"]}\n' for e in record['flows']))
        self.capture_udp(record)
        seen = set()
        for flow in record['flows']:
            if flow['protocol'] != 6:
                if flow['family'] in seen: continue
                seen.add(flow['family'])
            self.captures(record, flow, 'first' if name == 'mixed-lookup' and flow['protocol'] == 6 else 'all')
        self.write(record, 'hooks.txt', self.hooks())
        return record

    def phase(self, record, phase, seconds=180):
        text = self.wait_log(record['client_pid'], record['client_log'], f'mixed_stage phase={phase} ', seconds)
        self.write(record, f'client-phase{phase}.txt', text)

    def exercise(self, record):
        files = {}
        for name in ('tuples.txt', 'mixed-tuples.txt'):
            local = self.args.output/record['label']/name
            files[name] = record['runtime']+'/'+name if self.target.pixel else str(local)
            if self.target.pixel: self.target.adb('push', local, files[name])
        local = self.args.output/record['label']/'control.txt'
        save(local, '' if record['case'] == 'mixed-lookup' else 'capture-ready\n')
        record['control'] = self.controls+'/'+record['label']+'.control' if self.target.pixel else str(local)
        record['flows'][0]['control'] = record['control']
        if self.target.pixel: self.transfer_control(local, record['control'])
        if record['case'] == 'mixed-lookup':
            targets, seen = [], set()
            for e in record['udp']:
                pair = e['owner'], e['family']
                if pair in seen: continue
                seen.add(pair)
                targets.append(dict(owner=e['owner'], family=e['family'], protocol=17, value=e['port']))
            record['wire_targets'] = record['flows']+targets
            source = self.args.output/record['label']/'wire-tuples.txt'
            save(source, ''.join(f'{e["owner"]} {e["family"]} {e["protocol"]} {e["value"]}\n' for e in record['wire_targets']))
            remote = record['runtime']+'/wire-tuples.txt' if self.target.pixel else str(source)
            if self.target.pixel: self.target.adb('push', source, remote)
            self.endpoint('s236-wire-'+record['case'], [self.target.helpers+'/s236-wire', self.target.uid,
                remote, record['control'], str(PORT)])
            record['wire_pid'], record['wire_log'] = self.endpoints[-1]
        record['nonce'] = f's236-{record["generation"]}-{time.time_ns()}'
        record['client_log'] = record['runtime']+'/client.log'
        argv = [self.target.helpers+'/s236-mixed', record['case'].removeprefix('mixed-'), self.target.uid,
            files['tuples.txt'], record['control'], LOCAL[4], LOCAL[6], REMOTE[4], REMOTE[6],
            str(PORT), record['nonce'], files['mixed-tuples.txt']]
        record['client_pid'] = self.target.spawn(argv, record['client_log'])
        record['clients'].append(record['client_pid'])
        self.phase(record, 0)
        text = self.drain(record, 'seeded')
        assert len(rows(text, 'flow.entry ')) == record['count_per_owner']*2
        assert all(e['capacity_drops'] == '0' for e in rows(text, 'flow.pool '))
        assert all(e['captured'] == e['submitted'] == e['verdicts'] == e['succeeded']
                   for e in rows(text, 'root.lane ')), 'not every captured packet reached Product'
        self.fds(record, 'armed')
        if record['case'] == 'mixed-lookup':
            # Add exact all-packet capture only after the initial SYN-only
            # window. Earlier rules remain in place; no quiet gap is created.
            for flow in record['flows']:
                if flow['protocol'] == 6: self.captures(record, flow)
            self.write(record, 'lookup-hooks.txt', self.hooks())
            save(local, 'capture-ready\n')
            if self.target.pixel: self.transfer_control(local, record['control'])
            self.wait_log(record['wire_pid'], record['wire_log'], 'window full=1 ')
        if record['case'] != 'mixed-batch':
            self.phase(record, 1)
            self.drain(record, 'refreshed')
            self.fds(record, 'refreshed')
        self.quiet(record, 'actual-default-deadline', 35)
        text = self.drain(record, 'completed')
        # Renew/lookup TCP remains physically established with its true 24h
        # deadline; the independent long campaign proves actual expiry.
        expected = 0 if record['case'] == 'mixed-batch' else 4
        assert len(rows(text, 'flow.entry ')) == expected
        assert all(e['protocol'] == '6' for e in rows(text, 'flow.entry '))
        self.fds(record, 'disarmed' if not expected else 'remaining')
        self.write(record, 'client-final.txt', self.target.read(record['client_log']))
        if record.get('wire_log'): self.write(record, 'wire-final.txt', self.target.read(record['wire_log']))
        self.write(record, 'vpp.log', self.target.read(record['log']))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', choices=('linux', 'pixel'), required=True)
    for name in ('build', 'helpers', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--vppctl', type=Path)
    parser.add_argument('--cases', default=','.join(CASES))
    args = parser.parse_args()
    cases = args.cases.split(',')
    assert cases and len(set(cases)) == len(cases) and set(cases) <= set(CASES)
    for name in ('build', 'helpers', 'output', 'vppctl'):
        if getattr(args, name): setattr(args, name, getattr(args, name).resolve())
    args.output.mkdir(parents=True, exist_ok=False)
    build, helper = json.loads(args.build.read_text()), json.loads(args.helpers.read_text())
    assert chain.source_files() == build['files'] and helper['build_sha256'] == digest(args.build)
    campaign = Campaign(args, build, helper)
    try:
        campaign.prepare()
        for name in cases:
            record = campaign.start(name); campaign.exercise(record); campaign.stop(record)
        assert chain.source_files() == build['files']
        campaign.result['status'] = 'RAW_COMPLETE'
    except Exception as error:
        campaign.result['error'] = repr(error); raise
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
