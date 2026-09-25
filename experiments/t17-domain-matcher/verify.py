#!/usr/bin/env python3
"""Evidence verifier independent of benchmark process success reporting."""
import argparse
import hashlib
import json
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(run_dir, build_dir, workloads, repeats=3):
    index = json.loads((run_dir / 'index.json').read_text())
    build = json.loads((build_dir / 'build.json').read_text())
    assert index['build_sha256'] == digest(build_dir / 'build.json'), 'build identity'
    assert index.get('completed_ns', 0) >= index['started_ns'], 'incomplete run'
    expected = {(w.name, c, r) for w in workloads.iterdir() if w.is_dir()
                for c in ('datrie', 'rax', 'vpp') for r in range(repeats)}
    found = set()
    checksums = {}
    failures = []
    for name, candidate in build['candidates'].items():
        assert candidate['returncode'] == 0, 'compile failure'
        assert digest(build_dir / name) == candidate['binary_sha256'], 'binary identity'
    assert digest(Path(build['vpp_library']['path'])) == build['vpp_library']['sha256'], 'runtime library identity'
    source_file = build_dir / 'source-closure.json'
    sources = json.loads(source_file.read_text())
    for project, archive in sources['archives'].items():
        assert archive['sha256'] == build['upstream_archives'][project + '.tar.gz'], 'compiled archive identity'
    for name, value in sources['files'].items():
        assert digest(Path(name)) == value, 'consumed source identity'
    for name, value in build['sources'].items():
        if Path(name).suffix in ('.c', '.h'):
            assert digest(Path(name)) == value, 'adapter source identity'
    if 'source_closure_sha256' in build:
        assert digest(source_file) == build['source_closure_sha256'], 'source closure identity'
    if index['android']:
        lines = index['device_binary_hashes'].splitlines()
        remote = {Path(line.split()[1]).name: line.split()[0] for line in lines}
        for name in ('datrie', 'rax', 'vpp'):
            assert remote[name] == build['candidates'][name]['binary_sha256'], 'device binary identity'
        assert remote['libvppinfra.so'] == build['vpp_library']['sha256'], 'device library identity'
        assert index['cleanup_returncode'] == 0, 'device cleanup'
    for run in index['runs']:
        key = run['workload'], run['candidate'], run['repeat']
        assert key in expected and key not in found, 'duplicate/unexpected run'
        found.add(key)
        w = workloads / run['workload']
        manifest = json.loads((w / 'manifest.json').read_text())
        assert run['manifest_sha256'] == digest(w / 'manifest.json'), 'workload manifest identity'
        for name, value in manifest['files'].items():
            assert value == digest(w / name), 'workload content identity'
        if run.get('returncode') != 0:
            failures.append({'key': key, 'failure': run.get('failure', run.get('stderr'))})
            continue
        m = run['measurement']
        assert m == json.loads(run['stdout']), 'raw measurement mismatch'
        assert m['run_id'] == run['run_id'] and index['nonce'] in m['run_id'], 'run identity'
        assert m['entries'] == manifest['entries'] and m['queries'] == manifest['queries'], 'workload dimensions'
        assert m['query_allocations_wrapped'] == 0, 'query allocation'
        assert m['batch_queries'] == m['queries'] * 20, 'batch workload'
        assert 0 < m['p50_ns'] <= m['p95_ns'] <= m['p99_ns'], 'latency ordering'
        assert m['build_ns'] > 0 and m['replacement_build_ns'] > 0, 'build timing'
        # Independent expected checksum ties the complete result masks to output.
        masks = [int(line.rstrip().split('\t')[2], 16) for line in (w / 'queries.tsv').read_text().splitlines()]
        checksum = 0
        for mask in masks:
            checksum ^= mask
        checksum = (checksum + sum(masks) * 20) % (1 << 64)
        assert m['checksum'] == checksum, 'oracle result checksum'
        checksums.setdefault(run['workload'], set()).add(m['checksum'])
    assert found == expected, 'missing runs'
    assert all(len(values) == 1 for values in checksums.values()), 'candidate disagreement'
    return {'schema': 't17-verified-v1', 'runs': len(found), 'successful': len(found) - len(failures),
            'failures': failures, 'index_sha256': digest(run_dir / 'index.json')}


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('runs', type=Path)
    p.add_argument('build', type=Path)
    p.add_argument('workloads', type=Path)
    args = p.parse_args()
    result = verify(args.runs, args.build, args.workloads)
    print(json.dumps(result, indent=2))
