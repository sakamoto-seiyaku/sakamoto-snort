#!/usr/bin/env python3
"""Deterministic inputs and independent label-list oracle; no candidate imports."""
import argparse
import hashlib
import json
import random
from pathlib import Path


def normalize(value, config=False):
    if config and value.endswith('.'):
        value = value[:-1]
    if not 1 <= len(value) <= 253 or not value.isascii():
        return None
    labels = value.lower().split('.')
    if any(not 1 <= len(x) <= 63 or x[0] == '-' or x[-1] == '-'
           or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in x)
           for x in labels):
        return None
    return '.'.join(labels)


def oracle(query, exact, descendants):
    name = normalize(query)
    if name is None:
        return -1, 0
    labels = name.split('.')
    matches = set(exact.get(tuple(labels), ()))
    for start in range(len(labels)):
        matches.update(descendants.get(tuple(labels[start:]), ()))
    return 0, sum(1 << n for n in matches)


def generate(out, size, shape):
    rng = random.Random(268 + size)
    entries = [('example.com', 1, 2), ('a.example.com', 4, 8),
               ('com', 16, 32), ('exact.test', 64, 0),
               ('xn--bcher-kva.example', 128, 256)]
    for i in range(size - len(entries)):
        if shape == 'shared':
            name = f'h{i}.service{i % 64}.example.net'
        elif shape == 'entropy':
            name = ''.join(rng.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=24)) + f'.d{i}.test'
        else:
            name = f'h{i}.' + '.'.join(f'label{j:02d}' for j in range(16)) + '.' + 'z' * 63 + '.test'
        entries.append((name, 1 << (i % 64) if i % 3 else 0,
                        1 << ((i + 7) % 64) if i % 3 != 1 else 0))
    # Shared apex entries and duplicate/case import merge are explicit semantics.
    entries += [('EXAMPLE.COM.', 512, 1024), ('service1.example.net', 2048, 4096)]
    merged = {}
    for name, ex, desc in entries:
        key = normalize(name, True)
        assert key is not None
        old = merged.get(key, (0, 0))
        merged[key] = (old[0] | ex, old[1] | desc)
    exact, descendants = {}, {}
    for name, (ex, desc) in merged.items():
        labels = tuple(name.split('.'))
        exact[labels] = {i for i in range(64) if ex & (1 << i)}
        descendants[labels] = {i for i in range(64) if desc & (1 << i)}
    queries = ['example.com', 'A.EXAMPLE.COM', 'b.a.example.com', 'badexample.com',
               'exact.test', 'x.exact.test', 'EXAMPLE.COM.', '', '.', 'a..com',
               '-bad.com', 'bad-.com', '*.com', 'https://example.com',
               'bücher.example', 'a' * 64 + '.com', 'a' * 254,
               '.'.join(['a' * 63] * 3 + ['b' * 61]), 'xn--bcher-kva.example',
               'a\x00.example.com']
    keys = list(merged)
    for _ in range(5000):
        name = rng.choice(keys)
        queries.extend([name, name.upper(), 'x.' + name, 'bad' + name, 'absent.' + name + '.invalid'])
    out.mkdir(parents=True, exist_ok=True)
    (out / 'entries.tsv').write_text(''.join(f'{n}\t{e:x}\t{d:x}\n' for n, (e, d) in merged.items()))
    # Hex input transports embedded NUL/empty input without ambiguity.
    (out / 'queries.tsv').write_text(''.join(f'{q.encode().hex()}\t{s}\t{m:x}\n' for q in queries for s, m in [oracle(q, exact, descendants)]))
    meta = {'schema': 't17-workload-v1', 'requested_size': size, 'entries': len(merged),
            'shape': shape, 'queries': len(queries), 'seed': 268 + size,
            'files': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in out.glob('*.tsv')}}
    (out / 'manifest.json').write_text(json.dumps(meta, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('out', type=Path)
    args = parser.parse_args()
    for count in (1000, 10000, 100000):
        for distribution in ('shared', 'entropy', 'deep'):
            generate(args.out / f'{distribution}-{count}', count, distribution)
