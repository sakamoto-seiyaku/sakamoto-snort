#!/usr/bin/env python3
"""Fresh combined S199/S201/S202 verification, without release/long-wait claims."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
VERIFIERS = {
    'linux_root': 'verify-s242-root-lifecycle.py',
    'pixel_root': 'verify-s242-supervisor.py',
    'vpn_active': 'verify-s243-active.py',
    'vpn_underlay': 'verify-s243-underlay.py',
    'vpn_capacity': 'verify-s241-capacity.py',
    'vpn_credit': 'verify-s241-capacity.py',
    'vpn_tcp': 'verify-s240-tcp.py',
    'vpn_recovery': 'verify-s243-recovery.py',
}
CAPACITY = ('flow-capacity', 'session-capacity', 'pcb-capacity', 'socket-capacity',
            'packet-credit', 'pbuf-capacity', 'protect', 'bind', 'refusal', 'unreachable', 'drop')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def verify_one(name, directory, build, ovs=None):
    verifier = module('joint_' + name, ROOT/'tests/device'/VERIFIERS[name])
    if name in ('linux_root', 'pixel_root'):
        answer = verifier.verify(directory)
    elif name == 'vpn_tcp':
        answer = verifier.verify(build, directory, ovs)
    else:
        answer = verifier.verify(build, directory)
    assert answer['status'] == 'PASS', (name, answer)
    return answer


def verify(recipe):
    inputs = json.loads(Path(recipe).read_text())
    paths = {name: Path(value).resolve() for name, value in inputs.items()}
    linux = json.loads(paths['linux_build'].read_text())
    pixel = json.loads(paths['pixel_build'].read_text())
    assert linux['source_sha256'] == pixel['source_sha256'], 'joint artifacts differ in Product source'
    results, raw = {}, {}
    for name in VERIFIERS:
        directory = paths[name]
        record = json.loads((directory/'result.json').read_text())
        build = paths['linux_build' if name == 'linux_root' else 'pixel_build']
        assert record['build_sha256'] == digest(build), 'joint run references another build: ' + name
        expected = 'RAW_COMPLETE' if name.endswith('_root') else (
            'COLLECTED' if name in ('vpn_capacity', 'vpn_credit') else 'CAPTURE_COMPLETE')
        assert record['status'] == expected, 'incomplete collector: ' + name
        raw[name] = record
        results[name] = verify_one(name, directory, build, paths['ovs_reference'])
    assert {r['case'] for r in raw['vpn_active']['runs']} == {'stop', 'crash', 'broker0', 'broker1'}
    for record in raw['linux_root']['generations']:
        if record['partial'] or record['termination'] == 'SIGKILL_OS_RECLAIM':
            continue
        log = (paths['linux_root']/record['label']/'vpp.log').read_text()
        closed = re.findall(r'^s235 event=collector_closed generation='+str(record['generation'])+
                            r' route_fd=-1 query_fd=-1 timer_fd=-1 subscriptions=0$', log, re.M)
        assert len(closed) == 1, 'Linux network collector did not close its resources'
    for record in raw['pixel_root']['generations']:
        phase = paths['pixel_root']/record['label']
        service = (phase/'service.log').read_text()
        assert len(re.findall(r's243 network_subscription_closed generation='+str(record['generation'])+
                              r' native_tun_drain=true\b', service)) == 1
        pids = [fields[0] for line in (phase/'processes-before.txt').read_text().splitlines()
                if len(fields := line.split(None, 2)) == 3
                and fields[2] == 'com.sakamoto.snort.androidruntime:runtime']
        assert len(pids) == 1
        owned = re.compile(r'\s'+pids[0]+r'\s+\d+\s+I SakamotoNetwork:')
        before = [l for l in (phase/'network-before.log').read_text().splitlines() if owned.search(l)]
        after = [l for l in (phase/'network-events.log').read_text().splitlines() if owned.search(l)]
        assert after[:len(before)] == before, 'Android subscription observation lost its initial window'
        current = after[len(before):]
        assert sum('event=initial_networks ' in l and 'code=0' in l for l in current) == 1
        closed = [l for l in current if 'event=subscription_stopped ' in l]
        assert len(closed) == 1 and closed[0].endswith('thread_alive=false')
    assert results['vpn_underlay']['same_socket_policy_drop_checked'] is True
    expected = {(protocol, family, case) for protocol in ('tcp', 'udp') for family in (4, 6)
                for case in CAPACITY if protocol != 'udp' or case != 'refusal'}
    cards = raw['vpn_capacity']['runs']
    assert len(cards) == len(expected) == 42
    assert {(c['protocol'], c['family'], c['case']) for c in cards} == expected
    assert all(c['expected']['owner'] == 0 and c['completion_slots'] == 128 for c in cards)
    cards = raw['vpn_credit']['runs']
    assert len(cards) == 2 and {(c['protocol'], c['family'], c['case']) for c in cards} == {
        ('udp', 4, 'drop'), ('udp', 6, 'drop')}
    assert all(c['expected']['owner'] == 1 and c['completion_slots'] == 2 for c in cards)
    assert all(c['completion_deferred'] > 0 for c in results['vpn_credit']['runs'])
    assert raw['vpn_tcp']['case'] == 'matrix'
    recovery = results['vpn_recovery']
    assert recovery['startup_preparation_failure_checked'] and recovery['ordinary_app_echoes'] == 8
    # One Product artifact, distinct lifetimes; no old generation is relabelled as
    # a fresh member of another campaign. Retain the different crash semantics.
    generations = [r['generation'] for r in raw['pixel_root']['generations']]
    for name in ('vpn_active', 'vpn_underlay', 'vpn_capacity', 'vpn_credit', 'vpn_tcp'):
        for record in raw[name]['runs']:
            generations.append(record['generation'])
            replacement = record.get('replacement_generation', record['generation'])
            if replacement != record['generation']:
                generations.append(replacement)
    generations += recovery['generations']
    startup = raw['vpn_recovery']['startup_failure']
    generations += list(range(int(startup['previous_generation'])+1, int(startup['generation'])+1))
    assert len(generations) == len(set(generations)), 'generation reused across joint campaigns'
    junit = ET.parse(paths['hev_junit']).getroot()
    cases = list(junit.iter('testcase'))
    assert len(cases) == 36 and all(c.find('failure') is None and c.find('error') is None
                                  and c.find('skipped') is None for c in cases)
    host_cases = list(ET.parse(paths['host_junit']).getroot().iter('testcase'))
    failures = {c.attrib['name'] for c in host_cases if c.find('failure') is not None}
    assert len(host_cases) == 40 and failures == {
        'sakamoto-product-vpp-contract', 'sakamoto-s176-root-nfqueue-output-contract',
        'sakamoto-s189-root-network-gate-contract', 'sakamoto-s190-vpn-network-gate-contract',
        'sakamoto-s191-root-tcp4-l4-contract'}
    assert all(c.find('error') is None and c.find('skipped') is None for c in host_cases)
    negative_reports = {}
    for name, key, count in [('linux_root', 'linux_negatives', 8),
                             ('pixel_root', 'pixel_negatives', 11),
                             ('vpn_active', 'vpn_negatives', 10)]:
        negative = json.loads(paths[key].read_text())
        assert negative['status'] == 'PASS' and negative['kind'] == name
        assert negative['negatives'] == len(negative['rejected']) == count
        assert negative['original_result_sha256'] == digest(paths[name]/'result.json')
        assert negative['script_sha256'] == digest(ROOT/'tests/evidence/test_foundation_joint_negatives.py')
        assert negative['verifier_sha256'] == digest(ROOT/'tests/device'/VERIFIERS[name])
        negative_reports[name] = dict(cases=count, sha256=digest(paths[key]))
    source_names = [Path(__file__).relative_to(ROOT), Path('tests/evidence/product_chain.py'),
                    Path('tests/device/verify-s237.py'), Path('tests/device/s207-owner-oracle.py'),
                    Path('tests/host/product_flow_tcp_ovs_test.py'),
                    Path('tests/evidence/test_foundation_joint_negatives.py')]
    source_names += [Path('tests/device')/name for name in sorted(set(VERIFIERS.values()))]
    return dict(status='PASS_WITH_EXPLICIT_LIMITS', scope='S199-S201-S202-foundation-joint',
        source_sha256=linux['source_sha256'], apk_sha256=pixel['apk_sha256'],
        build_sha256={name: digest(paths[name]) for name in ('linux_build', 'pixel_build')},
        recipe_sha256=digest(recipe), verifier_files={str(n): digest(ROOT/n) for n in source_names},
        results=results, pixel_generations=sorted(generations),
        raw_files={name: {str(p.relative_to(paths[name])): digest(p)
                         for p in sorted(paths[name].rglob('*')) if p.is_file()} for name in VERIFIERS},
        hev_host_tests=36, hev_junit_sha256=digest(paths['hev_junit']),
        host_ctest=dict(passed=35, total=40, failures=sorted(failures), sha256=digest(paths['host_junit'])),
        negatives=negative_reports,
        limits=dict(real_86400_second_tcp_expiry='USER_DEFERRED_UNVERIFIED',
                    linux_physical_wifi_wired_mobile='UNVERIFIED',
                    mobile_underlay_handover='UNVERIFIED_NO_SIM',
                    fragment_reassembly='LEAF_EVIDENCE_ONLY_NOT_REPLAYED_BY_THIS_JOINT_MATRIX',
                    release_readiness=False, performance_qualification=False,
                    whole_repository_ctest='35/40: five recorded pre-existing static-contract failures'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.input)
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k: result[k] for k in ('status', 'scope', 'source_sha256', 'apk_sha256',
                                           'pixel_generations', 'limits')}, indent=2))
