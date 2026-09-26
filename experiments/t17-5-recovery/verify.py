#!/usr/bin/env python3
"""Independent oracle, identity, completeness and recovery-evidence checks."""
import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'experiments/t17-domain-matcher'))
from generate import oracle
from provenance import closure


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def workload_expected(path, files):
    assert files == {p.name: sha(p) for p in path.glob('*.tsv')}, 'workload hashes'
    exact, descendants, shifted_exact, shifted_descendants = {}, {}, {}, {}
    entries = path.joinpath('entries.tsv').read_text().splitlines()
    for line in entries:
        name, ex, desc = line.split('\t')
        key = tuple(name.split('.'))
        assert key not in exact, 'duplicate canonical key'
        exact[key] = {i for i in range(64) if int(ex, 16) & (1 << i)}
        descendants[key] = {i for i in range(64) if int(desc, 16) & (1 << i)}
        shifted_exact[key] = {(i + 1) % 64 for i in exact[key]}
        shifted_descendants[key] = {(i + 1) % 64 for i in descendants[key]}
    masks = []
    changed = 0
    for line in path.joinpath('queries.tsv').read_text().splitlines():
        raw, status, mask = line.split('\t')
        query = bytes.fromhex(raw).decode()
        expected = oracle(query, exact, descendants)
        assert expected == (int(status), int(mask, 16)), 'input oracle mismatch'
        shifted = oracle(query, shifted_exact, shifted_descendants)
        assert shifted[0] == expected[0], 'shift changed validity'
        changed += shifted[1] != expected[1]
        masks.append(shifted[1])
    assert changed, 'new configuration has no observable change'
    checksum = 0
    for mask in masks:
        checksum ^= mask
    checksum = (checksum + 20 * sum(masks)) % (1 << 64)
    return {'entries': len(entries), 'queries': len(masks), 'checksum': checksum, 'changed': changed}


def verify_records(meta, expected):
    assert meta['schema'] == 't17-5-run-v1' and meta['completed_ns'] > meta['started_ns']
    focused = meta['focused']
    cases = [('cost', 'small-shared', 0)] if focused else [
        ('cost', shape, repeat) for repeat in range(3) for shape in ('shared', 'entropy', 'deep')]
    cases += [('cost', 'edges', 0), ('faults', 'small-shared', 0), ('faults', 'edges', 0),
              ('exhaustion', 'small-shared', 0)]
    if not focused:
        cases += [('targeted', shape, 0) for shape in ('shared', 'entropy', 'deep')]
    assert [(r['mode'], r['workload'], r['repeat']) for r in meta['runs']] == cases, 'run completeness'
    if meta['android']:
        assert meta['cleanup_returncode'] == 0, 'remote cleanup'
    for record in meta['runs']:
        assert record['returncode'] == 0 and not record['stderr'], 'native failure'
        if meta['android']:
            assert record['remote_exit_confirmed'] is True, 'remote exit'
        run_id = f"{meta['nonce']}-{record['mode']}-{record['workload']}-{record['repeat']}"
        assert record['run_id'] == run_id, 'record identity'
        result = json.loads(record['stdout'])
        assert result == record['measurement'], 'raw/parsed mismatch'
        assert result['run_id'] == run_id and result['mode'] == record['mode'], 'native identity'
        assert result['final_live'] == 0, 'cleanup ledger'
        if record['mode'] != 'exhaustion':
            for field in ('entries', 'queries'):
                assert result[field] == expected[record['workload']][field], 'dimensions'
        if record['mode'] == 'cost':
            assert result['checksum'] == expected[record['workload']]['checksum'], 'changed oracle checksum'
            assert result['query_allocations'] == 0
            assert result['batch_queries'] == result['queries'] * 20
            # Usable size may differ with allocator placement/fragmentation even
            # when both snapshots request the same payload/node sizes.
            assert result['old_bytes'] > 0 and result['active_bytes'] > 0
            assert result['coexist_bytes'] == result['old_bytes'] + result['active_bytes'] <= result['peak_bytes']
            assert 0 <= result['p50_ns'] <= result['p95_ns'] <= result['p99_ns']
            assert all(result[name] > 0 for name in ('old_build_ns', 'new_build_ns', 'retire_ns', 'batch_ns'))
            assert all(result[name] > 0 for name in ('input_rss_kib', 'old_rss_kib', 'coexist_rss_kib', 'active_rss_kib', 'peak_rss_kib'))
        else:
            assert result['old_preserved'] is True and result['retry_published'] is True, 'recovery behavior'
            assert result['saved_version'] == result['active_version'], 'retry version'
            if record['mode'] == 'exhaustion':
                assert result['injected'] == 0 and result['failed_after_inserts'] > 0
                assert result['active_version'] == 3 and result['failure_ns'] >= result['cleanup_ns'] > 0
            else:
                assert result['allocation_points'] > 5
                expected_attempts = result['allocation_points'] + 2 if record['mode'] == 'faults' else 11
                assert result['attempts'] == expected_attempts
                assert result['rejected_builds'] + result['tolerated_failures'] == expected_attempts
                assert result['rejected_builds'] >= 6 and result['tolerated_failures'] == 0
                assert result['active_version'] == expected_attempts + 2
                assert 0 < result['max_cleanup_ns'] <= result['cleanup_ns']
                assert result['max_attempt_ns'] >= result['max_cleanup_ns']


def negative_checks(meta, expected):
    """Mutate independent facts, including raw output, so checks are exercised."""
    def native_field(obj, index, field, value):
        record = obj['runs'][index]
        record['measurement'][field] = value
        record['stdout'] = json.dumps(record['measurement'])
    mutations = {
        'missing_run': lambda m: m['runs'].pop(),
        'wrong_identity': lambda m: m['runs'][0].update(run_id='foreign'),
        'native_failure': lambda m: m['runs'][0].update(returncode=3),
        'wrong_checksum': lambda m: native_field(m, 0, 'checksum', m['runs'][0]['measurement']['checksum'] ^ 1),
        'leaked_allocation': lambda m: native_field(m, 0, 'final_live', 1),
        'query_allocation': lambda m: native_field(m, 0, 'query_allocations', 1),
        'wrong_dimensions': lambda m: native_field(m, 0, 'entries', 1),
    }
    fault_index = next(i for i, r in enumerate(meta['runs']) if r['mode'] == 'faults')
    mutations['old_changed'] = lambda m: native_field(m, fault_index, 'old_preserved', False)
    mutations['retry_not_published'] = lambda m: native_field(m, fault_index, 'retry_published', False)
    mutations['missed_allocation'] = lambda m: native_field(m, fault_index, 'attempts', 1)
    if meta['android']:
        mutations['remote_still_running'] = lambda m: m['runs'][0].update(remote_exit_confirmed=False)
        mutations['remote_cleanup_failed'] = lambda m: m.update(cleanup_returncode=1)
    for name, mutate in mutations.items():
        altered = copy.deepcopy(meta)
        mutate(altered)
        try:
            verify_records(altered, expected)
        except AssertionError:
            continue
        raise AssertionError('mutation accepted: ' + name)
    return list(mutations)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('build', type=Path)
    parser.add_argument('runs', type=Path)
    args = parser.parse_args()
    build = json.loads((args.build / 'build.json').read_text())
    meta = json.loads((args.runs / 'index.json').read_text())
    assert meta['build_sha256'] == sha(args.build / 'build.json')
    assert build['android'] == meta['android']
    assert build['binary_sha256'] == sha(args.build / 'recovery')
    assert build['vpp_library']['sha256'] == sha(Path(build['vpp_library']['path']))
    assert meta['runner_sha256'] == sha(args.runs / 'runner.py')
    for name, digest in build['experiment_sources'].items():
        assert sha(args.build / 'source-snapshot' / name) == digest, 'experiment source changed'
    assert build['source_closure_sha256'] == sha(args.build / 'source-closure.json')
    actual_closure = closure(ROOT / 'build-output/t17-20260926/upstream', args.build, meta['android'])
    assert actual_closure == json.loads((args.build / 'source-closure.json').read_text())
    if meta['android']:
        hashes = {Path(line.split()[1]).name: line.split()[0] for line in meta['device_hashes'].splitlines()}
        assert hashes == {'recovery': build['binary_sha256'], 'libvppinfra.so': build['vpp_library']['sha256']}
        remote = '/data/local/tmp/t175-' + meta['nonce']
        hashes = {line.split()[1]: line.split()[0] for line in meta['device_workload_hashes'].splitlines()}
        assert hashes == {remote + '/' + name + '/' + file: digest for name, item in meta['workloads'].items()
                          for file, digest in item['files'].items()}, 'device workload identity'
    expected = {name: workload_expected(Path(item['path']), item['files']) for name, item in meta['workloads'].items()}
    verify_records(meta, expected)
    result = {'passed': True, 'runs': len(meta['runs']), 'expected': expected,
              'rejected_mutations': negative_checks(meta, expected)}
    (args.runs / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'passed': True, 'runs': result['runs'], 'rejected_mutations': len(result['rejected_mutations'])}))


if __name__ == '__main__':
    main()
