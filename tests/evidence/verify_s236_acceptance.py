#!/usr/bin/env python3
"""Full S236 gate, with an explicit user-approved deferred-long scope."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'tests/device'/filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


protocol = module('s236_acceptance_protocol', 'verify-s236-protocol-expiry.py')
mixed = module('s236_acceptance_mixed', 'verify-s236-mixed-expiry.py')
need, digest = protocol.need, protocol.digest


def local(path):
    value = Path(path)
    return value.resolve() if value.is_absolute() else (ROOT/value).resolve()


def host_baseline(config):
    path = local(config['junit'])
    xml = ET.parse(path).getroot()
    cases = {e.attrib['name']: e for e in xml.findall('testcase')}
    failed = {name for name, e in cases.items() if e.find('failure') is not None}
    need(len(cases) == 39 and xml.attrib['disabled'] == xml.attrib['skipped'] == '0', 'full repository test census')
    need(failed == set(config['unchanged_failures']), 'new or unaccounted repository regression')
    required = {'sakamoto-product-flow-'+name+'-test' for name in ('icmp', 'udp', 'tcp', 'entry', 'end', 'expiry', 'timeout')}
    required.add('sakamoto-product-diagnostic-hex-test')
    need(required <= cases.keys() and not required & failed, 'focused S236 host regression failed')
    head = config['baseline_head']
    need(re.fullmatch('[0-9a-f]{40}', head), 'baseline commit identity')
    for name, expected in config['unchanged_files'].items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'baseline path escaped repo')
        committed = subprocess.run(['git', 'show', head+':'+name], cwd=ROOT, capture_output=True, check=True).stdout
        need(hashlib.sha256(committed).hexdigest() == digest(ROOT/name) == expected,
             'baseline static-contract failure is no longer unchanged '+name)
    for name in config['unchanged_absent_files']:
        need(not (ROOT/name).exists() and subprocess.run(['git', 'cat-file', '-e', head+':'+name], cwd=ROOT,
             capture_output=True).returncode != 0, 'removed baseline input changed')
    return dict(focused_tests=len(required), focused_passed=True, whole_repo_passed=False, total=39,
        passed=39-len(failed), unchanged_failed=sorted(failed), baseline_head=head, junit_sha256=digest(path),
        focused_test_sources={name: digest(ROOT/name) for name in
            ('tests/host/product_flow_expiry_test.c', 'tests/host/product_flow_timeout_test.c')})


def deferred_long(run, platform):
    """Verify cancellation cleanup, never promote interrupted expiry to PASS."""
    result = json.loads((run/'result.json').read_text())
    need(result['status'] == 'HOLD' and not result.get('cleanup_error') and
         result['platform'] == platform and result['requested_cases'] == ['long'], 'deferred collector identity')
    need(result['raw_hashes'], 'cancelled raw inventory absent')
    for name, expected in result['raw_hashes'].items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts and
             digest(run/name) == expected, 'cancelled raw file '+name)
    need(len(result['generations']) == 1 and result['endpoints'] and
         all(e['process_absent'] for e in result['endpoints']), 'cancelled endpoint residue')
    record = result['generations'][0]
    need(record['case'] == record['label'] == 'long' and record['process_closed'] and
         record['clients_closed'], 'cancelled runtime/client residue')
    for name in ('hooks-after.txt', 'filter-after.txt'):
        need('SAKAMOTO_S236_' not in (run/name).read_text(), 'cancelled private hook residue')
    need(('fd20:6236::2/128' in (run/'addresses-before.txt').read_text()) ==
         ('fd20:6236::2/128' in (run/'addresses-after.txt').read_text()), 'cancelled address residue')
    if platform == 'pixel': need(result['controls_removed'], 'cancelled control directory residue')
    folder = run/'long'; read = lambda name: (folder/name).read_text()
    closed, log = read('closed.txt'), read('vpp.log')
    need('root.stop=ok queues=0 buffers=0 obligations=0' in read('stop.txt'), 'cancelled native stop failed')
    need(not protocol.rows(closed, 'flow.entry ') and 'flow-end.buffers=0' in closed and
         protocol.udp.pool(closed)['used'] == 0, 'cancelled flow/buffer residue')
    for prefix, count, fields in (
        ('expiry.owner=', 2, ('timers', 'mode')),
        ('flow.pool ', 2, ('entries',)),
        ('completion.status ', 1, ('pending', 'frames', 'buffers', 'obligations')),
        ('root.lane ', 4, ('ready', 'pending'))):
        entries = protocol.rows(closed, prefix)
        need(len(entries) == count and all(e[k] == '0' for e in entries for k in fields), 'cancelled residue '+prefix)
        if prefix == 'root.lane ': need(all(e['fd'] == '-1' for e in entries), 'cancelled queue FD residue')
    protocol.fd_lifecycle(read, record['generation'])
    protocol.native.queue_state(folder, 'closed', platform, set())
    zero = protocol.rows(log, 's242 event=stop_native_zero ')
    need(len(zero) == 1 and all(zero[0][k] == '0' for k in
         ('ready_mask', 'graph_enabled', 'graph_accepting', 'pending', 'buffers', 'obligations',
          'handoffs', 'completion_frames')), 'cancelled native stop incomplete')
    # Real CLOSING observations are retained, but the interrupted ESTABLISHED
    # interval and post-expiry socket reuse remain explicitly unverified.
    intervals = record['quiet_intervals']
    need(len(intervals) == 2 and intervals[0]['actual_s'] >= 900 and
         'completed_ns' not in intervals[1], 'not the approved interrupted long interval')
    releases = protocol.rows(log, 's227 event=release ')
    need(len(releases) == 4 and all(e['timeout'] == '7' and
         0 <= int(e['release_us'])-int(e['deadline_us']) <= 1500000 for e in releases), 'CLOSING observation mismatch')
    need(len(protocol.rows(read('closing-expired.txt'), 'flow.entry ')) == 4, 'established retention observation absent')
    return dict(status='DEFERRED_UNVERIFIED', platform=platform, case='long', cleanup_verified=True,
        observed_closing_releases=4, established_86400s_verified=False, post_expiry_socket_verified=False,
        source_sha256=result['source_sha256'], result_sha256=digest(run/'result.json'))


def verify(path, allow_deferred_long=False):
    config = json.loads(path.read_text())
    need(config['schema'] == 's236-real-default-expiry-acceptance/v1', 'acceptance manifest schema')
    expected = set(protocol.CLASSES) | set(mixed.CASES)
    declared = {platform: Counter() for platform in ('linux', 'pixel')}
    for row in config['runs']:
        need(row['platform'] in declared and row['kind'] in ('protocols', 'mixed') and row['cases'], 'run scope')
        declared[row['platform']].update(row['cases'])
    need(all(set(counts) == expected and set(counts.values()) == {1} for counts in declared.values()),
         'exact two-platform short/long/mixed coverage required')
    missing = [row['run'] for row in config['runs'] if not (local(row['run'])/'result.json').is_file()]
    need(not missing, 'actual long/run completion still pending: '+', '.join(missing))
    reports, lineage, run_sources, deferred = [], set(), {}, []
    if allow_deferred_long:
        need(config.get('long_deferral') == {
            'approved_by': 'user', 'date': '2026-09-13', 'tracker': 'SAKAMOTO-236',
            'scope': 'real-86400s-expiry-and-post-expiry-held-socket',
            'reason': 'User declined interactive day-long waiting; deferred, not passed.'}, 'explicit user deferral record required')
    ovs = local(config['ovs'])
    for row in config['runs']:
        if allow_deferred_long and row['kind'] == 'protocols' and row['cases'] == ['long']:
            result = deferred_long(local(row['run']), row['platform'])
            lineage.add(result['source_sha256']); deferred.append(dict(run=row['run'], **result))
            continue
        verifier = protocol if row['kind'] == 'protocols' else mixed
        result = verifier.verify(local(row['run']), ovs, row['cases'])
        need(result['status'] == 'VALID_PARTIAL' and result['platform'] == row['platform'], 'run did not verify exact declared platform')
        need({e['case'] for e in result['cases']} == set(row['cases']), 'selected case missing from verified report')
        lineage.add(result['source_sha256'])
        run_sources[(row['platform'], row['kind'], result['result_sha256'])] = row['run']
        reports.append(dict(run=row['run'], kind=row['kind'], **result))
    need(len(lineage) == 1, 'different Product source across acceptance runs')
    negative_coverage, negative_reports = set(), []
    script_sha = digest(ROOT/'tests/evidence/test_s236_expiry_negatives.py')
    for name in config['negatives']:
        file = local(name); result = json.loads(file.read_text())
        scope = result['platform'], result['suite']
        need(result['status'] == 'PASS' and result['script_sha256'] == script_sha and
             result['verifier_files'] == protocol.verifier_closure(), 'negative verifier/source closure changed')
        need((*scope, result['source_result_sha256']) in run_sources and scope not in negative_coverage and
             result['semantic_negatives'] == len(result['rejected']) >= 39 and
             len({e['case'] for e in result['rejected']}) == len(result['rejected']), 'negative population/run identity')
        negative_coverage.add(scope)
        negative_reports.append(dict(file=name, sha256=digest(file), suite=result['suite'], platform=result['platform'], count=result['semantic_negatives']))
    need(negative_coverage == {(p, s) for p in declared for s in ('protocols', 'mixed')}, 'missing platform/suite semantic negatives')
    host = host_baseline(config['host'])
    need(not allow_deferred_long or {e['platform'] for e in deferred} == set(declared), 'both deferred long runs required')
    return dict(status='PASS_WITH_DEFERRED_LONG' if allow_deferred_long else 'PASS',
        full_original_acceptance=not allow_deferred_long, deferred=deferred,
        scope='S236-real-Root-shared-TCP-UDP-ICMP-default-expiry',
        source_sha256=next(iter(lineage)), input_sha256=digest(path), verifier_sha256=digest(__file__),
        coverage={p: sorted(set(c)-({'long'} if allow_deferred_long else set())) for p, c in declared.items()},
        runs=reports, negatives=negative_reports,
        semantic_negative_tests=sum(e['count'] for e in negative_reports), host=host,
        readiness_expansion=False, vpn_expiry_claim=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', type=Path, required=True); parser.add_argument('--output', type=Path)
    parser.add_argument('--allow-deferred-long', action='store_true',
        help='Require the explicit user deferral record; never report full original PASS')
    args = parser.parse_args()
    try: answer = verify(args.input.resolve(), args.allow_deferred_long)
    except (AssertionError, KeyError, ValueError, OSError, subprocess.SubprocessError, ET.ParseError) as error:
        answer = dict(status='HOLD', error=repr(error))
    if args.output: args.output.write_text(json.dumps(answer, indent=2)+'\n')
    print(json.dumps(answer, indent=2))
    if answer['status'] not in ('PASS', 'PASS_WITH_DEFERRED_LONG'): raise SystemExit(1)
