#!/usr/bin/env python3
"""Supplemental correctness fixtures, separate from preregistered cost workloads."""
import hashlib
import json
import random
import sys
from pathlib import Path
from generate import oracle

out = Path(sys.argv[1]) / 'edges'
out.mkdir(parents=True, exist_ok=False)
entries = {}
for depth in range(64):
    name = '.'.join(['a'] * depth + ['t'])
    entries[name] = (1 << ((depth + 1) % 64), 1 << depth)
maximum = '.'.join(['b' * 63] * 3 + ['c' * 61])
entries[maximum] = (1 << 63, 0)
entries['only.exact'] = (1, 0)
entries['-'.join(['valid', 'hyphen']) + '.a1'] = (2, 4)
exact = {tuple(name.split('.')): {i for i in range(64) if masks[0] & (1 << i)} for name, masks in entries.items()}
descendants = {tuple(name.split('.')): {i for i in range(64) if masks[1] & (1 << i)} for name, masks in entries.items()}
queries = ['.'.join(['a'] * 126 + ['t']), '.'.join(['a'] * 127 + ['t']),
           maximum, maximum.upper(), 'x.' + maximum, 'only.exact',
           'a.only.exact', 'notonly.exact', 'valid-hyphen.A1', 'z.valid-hyphen.a1']
rng = random.Random(1268)
for _ in range(1000):
    depth = rng.randrange(1, 128)
    labels = ['a'] * (depth - 1) + ['t']
    if rng.randrange(2):
        labels[rng.randrange(depth)] = 'b'
    queries.append('.'.join(labels))
queries += [chr(byte) + '.test' for byte in range(128)]
(out / 'entries.tsv').write_text(''.join(f'{name}\t{ex:x}\t{desc:x}\n' for name, (ex, desc) in entries.items()))
(out / 'queries.tsv').write_text(''.join(f'{q.encode().hex()}\t{s}\t{m:x}\n' for q in queries for s, m in [oracle(q, exact, descendants)]))
meta = {'schema': 't17-workload-v1', 'shape': 'supplemental-correctness', 'entries': len(entries),
        'queries': len(queries), 'seed': 1268,
        'files': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in out.glob('*.tsv')}}
(out / 'manifest.json').write_text(json.dumps(meta, indent=2) + '\n')
