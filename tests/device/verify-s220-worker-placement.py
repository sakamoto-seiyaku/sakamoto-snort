#!/usr/bin/env python3
"""Independent CPU/OS/packet oracle and native lifecycle check for S220."""
import argparse
from collections import Counter
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import shlex

ROOT = Path(__file__).resolve().parents[2]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'tests/device'/filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


native = module('s220_native_verify', 'verify-s242-root-lifecycle.py')
oracle = module('s220_owner_verify', 's207-owner-oracle.py')
need, digest, rows = native.need, native.digest, native.rows


def allrows(text, prefix):
    return [dict(p.split('=', 1) for p in line.split() if '=' in p)
            for line in text.splitlines() if line.startswith(prefix)]


def cpu_set(text):
    result = set()
    for token in text.strip().split(','):
        bounds = list(map(int, token.split('-')))
        need(len(bounds) in (1, 2), 'CPU-set syntax')
        result.update(range(bounds[0], bounds[-1]+1))
    return result


def assigned(facts):
    packed = lambda value: ipaddress.ip_address(value).packed.rjust(16, b'\0').hex()
    return oracle.assignment(dict(l3=1, l4=1, family=facts['family'], protocol=facts['protocol'],
        src=packed(facts['source']), dst=packed(facts['destination']), src_port=facts['sport'],
        dst_port=facts['dport'], icmp_known=0))


def affinity(folder, label, expected, pid):
    text = (folder/(label+'-threads.txt')).read_text()
    found = re.findall(r'^\s*(\d+)\s+(vpp_main|vpp_wk_[01])\s+(?:workers\s+)?(\d+)\s+\S+\s+\([^)]*\)\s+(\d+)\s', text, re.M)
    need(len(found) == 3 and {int(e[0]) for e in found} == {0, 1, 2} and
         len({e[2] for e in found}) == 3, 'VPP thread/TID completeness')
    for index, name, tid, cpu in found:
        index = int(index)
        need(name == ('vpp_main' if index == 0 else 'vpp_wk_'+str(index-1)), 'logical worker identity')
        status = (folder/f'{label}-thread-{index}-status.txt').read_text()
        stat = (folder/f'{label}-thread-{index}-stat.txt').read_text()
        fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
        need(int(fields['Pid']) == int(tid) and int(fields['Tgid']) == pid and
             fields['Name'].strip() == name, 'OS task belongs to another process/worker')
        need(cpu_set(fields['Cpus_allowed_list']) == {expected[index]}, 'OS affinity differs from ordered mapping')
        need(int(stat.split('(', 1)[0]) == int(tid) and
             stat.split('(', 1)[1].rsplit(')', 1)[0] == name and
             int(stat.rsplit(')', 1)[1].split()[36]) == int(cpu) == expected[index], 'actual last CPU/VPP CPU differs')
    return {int(e[0]): int(e[2]) for e in found}


def invalid_starts(run, result):
    main, (a, b) = result['main_cpu'], result['worker_cpus']
    common = f'main-core {main} workers 2 '
    good = common+f'ordered-workers {a},{b}'
    present = cpu_set((run/'cpu-present.txt').read_text()); absent = max(present)+1
    online = cpu_set((run/'cpu-online.txt').read_text())
    need(result['present_offline_cpus'] == sorted(present-online), 'physical offline availability fabricated')
    expected = {
        'empty': (common+'ordered-workers', 'CPU list required', None),
        'duplicate': (common+f'ordered-workers {a},{a}', 'duplicate CPU', None),
        'count-one': (common+f'ordered-workers {a}', 'CPU count must equal', None),
        'count-three': (common+f'ordered-workers {a},{b},{absent}', 'CPU count must equal', None),
        'count-missing': (f'main-core {main} ordered-workers {a},{b}', 'CPU count must equal', None),
        'main-conflict': (common+f'ordered-workers {main},{a}', 'conflicts with main-core', None),
        'absent': (common+f'ordered-workers {a},{absent}', 'absent or offline', None),
        'overflow': (common+f'ordered-workers 4294967297,{b}', 'out of range', None),
        'range': (common+f'ordered-workers {a}-{b}', 'expected comma', None),
        'trailing-comma': (common+f'ordered-workers {a},{b},', 'expected comma', None),
        'negative': (common+f'ordered-workers -1,{b}', 'expected decimal', None),
        'unknown': (good+' unknown-setting', 'unknown CPU input', None),
        'relative': (good+' relative', 'conflict', None),
        'pthreads': (good+' use-pthreads', 'conflict', None),
        'skip': (good+' skip-cores 1', 'conflict', None),
        'corelist': (f'main-core {main} corelist-workers {a},{b} ordered-workers {a},{b}', 'conflict', None),
        'forbidden-worker': (good, 'outside inherited allowed affinity', f'{main},{a}'),
        'forbidden-main': (good, 'outside inherited allowed affinity', f'{a},{b}'),
    }
    if present-online:
        expected['offline'] = (common+f'ordered-workers {a},{min(present-online)}', 'absent or offline', None)
    need(Counter(e['case'] for e in result['invalid_starts']) == Counter({k: 1 for k in expected}), 'native negative census')
    commands = [json.loads(line) for line in (run/'commands.jsonl').read_text().splitlines()]
    for entry in result['invalid_starts']:
        config, message, allowed = expected[entry['case']]
        need((entry['config'], entry['expected_error'], entry['allowed']) == (config, message, allowed), 'negative precondition altered')
        folder = run/('invalid-'+entry['case']); text = (folder/'native.txt').read_text()
        need('cpu { '+config+' }\n' in (folder/'startup.conf').read_text(), 'wrong executed CPU config')
        need(entry['returncode'] not in (0, 124, 137) and message in text and
             's231 event=nfq_payload' not in text, 'native accepted/timed out or admitted on invalid placement')
        recorded = [e for e in commands if e['command'] == shlex.join(entry['argv'])]
        need(len(recorded) == 1 and recorded[0]['returncode'] == entry['returncode'], 'native rejection execution absent')
        if allowed:
            at = entry['argv'].index('taskset')
            mask = format(sum(1 << cpu for cpu in cpu_set(allowed)), 'x')
            need(entry['argv'][at:at+2] == ['taskset', mask], 'actual process restriction missing')
        native.queue_state(folder, 'after', result['platform'], set())
    return len(expected)


def verify(run):
    result = json.loads((run/'result.json').read_text())
    need(result['task'] == 'SAKAMOTO-220' and not result.get('error'), 'wrong/incomplete task')
    for name in result['raw_hashes']:
        need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'raw path escapes scope')
    native.authority(run, result)
    need(digest(ROOT/'tests/device/s220-worker-placement.py') == result['s220_runner_sha256'] ==
         digest(run/'s220-runner.py') and digest(run/'plan.md') == result['plan_sha256'], 'collector/plan identity')
    need(result['endpoint_cleanup'] and all(e['process_absent'] for e in result['endpoint_cleanup']), 'endpoint residue')
    need('SAKAMOTO_S242_' not in (run/'hooks-after.txt').read_text(), 'private hook residue')
    addresses = lambda path: set(re.findall(r'inet6\s+(\S+)', path.read_text()))
    need(addresses(run/'addresses-before.txt') == addresses(run/'addresses-after.txt'), 'temporary address residue')
    if result['platform'] == 'pixel':
        for name in ('app-before.properties', 'app-after.properties'):
            state = dict(line.split('=', 1) for line in (run/name).read_text().splitlines() if '=' in line)
            need(state['state'] == 'stopped' and state['mayBeActive'] == 'false', 'standalone test interfered with RuntimeService')
    main, cpus = result['main_cpu'], result['worker_cpus']
    need(len(cpus) == 2 and len({main, *cpus}) == 3 and abs(cpus[0]-cpus[1]) > 1, 'noncontiguous placement precondition')
    allowed = cpu_set(re.search(r'^Cpus_allowed_list:\s*(.+)$', (run/'launcher-status.txt').read_text(), re.M)[1])
    need({main, *cpus} <= allowed & cpu_set((run/'cpu-online.txt').read_text()), 'selected CPUs unavailable at launch')
    negatives = invalid_starts(run, result)
    records = result['generations']
    need([e['label'] for e in records] == ['forward', 'reverse'] and
         [e['generation'] for e in records] == [22020, 22021], 'ordered restart census')
    endpoints = '\n'.join(p.read_text() for p in run.glob('endpoint-final-*.txt'))
    reports, seeds = [], []
    for number, record in enumerate(records):
        mapping = cpus if number == 0 else list(reversed(cpus))
        need(record['worker_cpus'] == mapping and record['process_absent'] and
             record['termination'] == 'DRAIN_THEN_TERM', 'restart/stop/sequence identity')
        folder = run/record['label']; log = (folder/'vpp.log').read_text()
        config = (folder/'startup.conf').read_text()
        need('cpu { main-core '+str(main)+' workers 2 ordered-workers '+','.join(map(str, mapping))+' }\n' in config,
             'startup sequence differs from requested sequence')
        tids = affinity(folder, 'initial', [main, *mapping], record['pid'])
        need(affinity(folder, 'active', [main, *mapping], record['pid']) == tids, 'worker TID changed within generation')
        initial = (folder/'initial.txt').read_text(); closed = (folder/'native-closed.txt').read_text()
        need(not rows(initial, 'flow.entry '), 'old generation FlowEntry survived restart')
        lanes = rows(initial, 'root.lane ')
        native.worker_layout((folder/'layout.txt').read_text(), (folder/'initial-fds.txt').read_text(), lanes)
        # Lane cpu is last receive-callback CPU, explicitly unknown before
        # the first packet; it is not the configured worker CPU field.
        active_lanes = rows((folder/'before-stop.txt').read_text(), 'root.lane ')
        need(len(active_lanes) == 4 and all(int(e['captured']) > 0 and
             int(e['cpu']) == mapping[int(e['worker'])] and
             int(e['callback_thread']) == int(e['callback_tls']) == int(e['worker'])+1
             for e in active_lanes), 'actual native callback CPU/thread differs')
        cap, sends, decoded = native.completions(log, record, closed, lanes)
        native.cases(folder, record, cap, sends, decoded, endpoints)
        steps = native.normal_stop(folder, record, log)
        native.queue_state(folder, 'native-closed', result['platform'], set())
        native.queue_state(folder, 'process-closed', result['platform'], set())
        stale = rows((folder/'stale-stop.txt').read_text(), 'stop_step ')
        need(len(stale) == 1 and stale[0]['code'] == '5' and stale[0]['stopped'] == '0' and
             int(stale[0]['expected']) == record['generation']-1, 'old generation stop was not fenced')
        need(all(e['ready'] == '1' for e in rows((folder/'after-stale-stop.txt').read_text(), 'root.lane ')), 'stale stop changed live generation')
        assignments = allrows(log, 's207 ')
        coverage = set()
        for key, facts in decoded.items():
            expected = assigned(facts)
            observed = [e for e in assignments if int(e['token']) == key[2] and e['stage'] == 'policy']
            need(len(observed) == 1 and all(str(observed[0][k]) == str(v) for k, v in expected.items()) and
                 int(observed[0]['thread']) == expected['owner']+1 and
                 int(observed[0]['generation']) == record['generation'], 'canonical oracle/owner-thread mismatch')
            coverage.add((facts['protocol'], facts['family'], expected['owner']))
        need(coverage == {(p, f, o) for p in (6, 17) for f in (4, 6) for o in (0, 1)}, 'missing real dual-stack TCP/UDP owner execution')
        need(len(record['clients']) == 8, 'bounded cohort missing')
        for index, client in enumerate(record['clients']):
            need(client['process_absent'], 'traffic client still live')
            text = (folder/f'traffic-{index}.txt').read_text()
            events, ended = rows(text, 'traffic '), rows(text, 'traffic_end ')
            need(events and len(ended) == 1 and int(ended[0]['sent']) == int(ended[0]['received']) == len(events)
                 and ended[0]['failed'] == '0', 'real endpoint did not complete every echo')
            need([int(e['sequence']) for e in events] == list(range(len(events))), 'endpoint sequence gap')
            need(any(int(e['end_ns']) < int(steps[0]['begin_ns']) for e in events) and
                 any(int(e['end_ns']) > int(steps[-1]['end_ns']) for e in events), 'stop did not overlap the live endpoint cohort')
            for event in events:
                need(event['nonce'] == client['nonce'] and event['received'] == '1', 'endpoint nonce mismatch')
                wire = ('E'+client['nonce']+':'+format(int(event['sequence']), '08d')).encode()
                need((wire[1:].decode() if client['protocol'] == 'udp' else wire.hex()) in endpoints, 'independent endpoint receipt missing')
            seen = [f for f in decoded.values() if f['family'] == client['family'] and
                    f['protocol'] == (6 if client['protocol'] == 'tcp' else 17) and f['sport'] == client['source_port']
                    and f['destination'] == client['host'] and f['payload'].startswith(('E'+client['nonce']+':').encode())]
            need(seen and all(assigned(f)['owner'] == client['owner'] for f in seen), 'cohort never executed on its real owner')
        resources = (folder/'native-closed-resources.txt').read_text()
        expiry = allrows(resources, 'expiry.owner=')
        need(len(expiry) == 2 and all(e['mode'] == e['timers'] == '0' and e['timer_fd'] == '-1' for e in expiry), 'expiry backing residue')
        need('timerfd' not in (folder/'native-closed-fds.txt').read_text() and 'flow-end.buffers=0' in resources, 'timer/END descriptor or buffer residue')
        pools = re.findall(r'^default-numa-\d+\s+(.+)$', resources, re.M)
        need(pools and all(line.split()[-1] == '0' for line in pools), 'native buffer pool residue')
        seeds.append({(e['family'], e['host'], e['source_port']): e['owner'] for e in record['seeds']})
        reports.append(dict(generation=record['generation'], worker_cpus=mapping, os_tids=tids,
            captured_packets=len(cap), verdicts=len(sends), real_protocol_family_owner_cells=len(coverage), cleanup_zero=True))
    need(seeds[0] == seeds[1] and len(seeds[0]) == 8, 'same-tuple owners changed with CPU placement')
    files = ['tests/device/verify-s220-worker-placement.py', 'tests/device/verify-s242-root-lifecycle.py',
             'tests/device/s207-owner-oracle.py']
    return dict(status='PASS', scope='S220-native-ordered-startup-and-Root-endpoints-not-supervisor',
        platform=result['platform'], source_sha256=result['source_sha256'], result_sha256=digest(run/'result.json'),
        native_invalid_starts=negatives, physical_offline_case='verified' if result['present_offline_cpus'] else 'not-available',
        runs=reports, verifier_files={name: digest(ROOT/name) for name in files}, readiness_expansion=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('run', type=Path); parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try: result = verify(args.run.resolve())
    except (AssertionError, ValueError, KeyError, OSError) as error: result = dict(status='HOLD', error=repr(error))
    if args.output: args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
    if result['status'] != 'PASS': raise SystemExit(1)
