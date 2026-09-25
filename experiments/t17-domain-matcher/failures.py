#!/usr/bin/env python3
"""Bounded negative tests: native oracle rejection and evidence tamper rejection."""
import argparse
import copy
import json
import subprocess
import tempfile
from pathlib import Path
from verify import verify


def native_checks(build, workload):
    results = []
    with tempfile.TemporaryDirectory(prefix='t17-negative-') as directory:
        root = Path(directory)
        entries = root / 'entries.tsv'
        queries = root / 'queries.tsv'
        entries.write_bytes((workload / 'entries.tsv').read_bytes())
        valid_queries = (workload / 'queries.tsv').read_text()
        lines = valid_queries.splitlines()
        parts = lines[0].split('\t')
        parts[2] = f'{int(parts[2], 16) ^ 1:x}'
        lines[0] = '\t'.join(parts)
        cases = [('wrong-oracle', '\n'.join(lines) + '\n', 3),
                 ('odd-hex', 'abc\t0\t0\n', 2),
                 ('empty-query-file', '', 2)]
        for candidate in ('datrie', 'rax', 'vpp'):
            for name, content, expected in cases:
                queries.write_text(content)
                result = subprocess.run([str(build / candidate), str(entries), str(queries), name],
                                        text=True, capture_output=True, timeout=15)
                assert result.returncode == expected, (candidate, name, result.returncode)
                results.append({'candidate': candidate, 'case': name,
                                'returncode': result.returncode, 'stderr': result.stderr})
    return results


def evidence_checks(runs, build, workloads):
    original = json.loads((runs / 'index.json').read_text())
    mutations = []
    missing = copy.deepcopy(original); missing['runs'].pop(); mutations.append(('missing-run', missing))
    duplicate = copy.deepcopy(original); duplicate['runs'].append(duplicate['runs'][0]); mutations.append(('duplicate-run', duplicate))
    wrong_build = copy.deepcopy(original); wrong_build['build_sha256'] = '0' * 64; mutations.append(('build-identity', wrong_build))
    for field in ('checksum', 'queries', 'query_allocations_wrapped'):
        changed = copy.deepcopy(original)
        changed['runs'][0]['measurement'][field] += 1
        changed['runs'][0]['stdout'] = json.dumps(changed['runs'][0]['measurement'])
        mutations.append((field, changed))
    changed = copy.deepcopy(original); changed['runs'][0]['manifest_sha256'] = '0' * 64
    mutations.append(('workload-identity', changed))
    changed = copy.deepcopy(original); del changed['completed_ns']; mutations.append(('incomplete', changed))
    changed = copy.deepcopy(original); changed['runs'][0]['run_id'] = 'wrong'; mutations.append(('run-identity', changed))
    results = []
    with tempfile.TemporaryDirectory(prefix='t17-evidence-') as directory:
        root = Path(directory)
        for name, changed in mutations:
            (root / 'index.json').write_text(json.dumps(changed))
            try:
                verify(root, build, workloads)
            except AssertionError as error:
                results.append({'case': name, 'rejected': str(error)})
            else:
                raise AssertionError('accepted corrupt evidence: ' + name)
    return results


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('build', type=Path)
    p.add_argument('workloads', type=Path)
    p.add_argument('runs', type=Path)
    p.add_argument('out', type=Path)
    args = p.parse_args()
    result = {'native': native_checks(args.build, args.workloads / 'shared-1000'),
              'evidence': evidence_checks(args.runs, args.build, args.workloads)}
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    print(len(result['native']), 'native negatives;', len(result['evidence']), 'evidence mutations rejected')
