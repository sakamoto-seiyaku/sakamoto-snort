#!/usr/bin/env python3
"""Rehashed semantic corruptions of S220 evidence, without changing original files."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'tests/device'/filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def run(directory, supervisor):
    verifier = module('s220_negative_verifier', 'verify-s220-supervisor.py' if supervisor else 'verify-s220-worker-placement.py')
    baseline = verifier.verify(directory)
    result = json.loads((directory/'result.json').read_text())
    changes = [
        ('startup-order', 'forward/startup.conf', lambda text: text.replace('ordered-workers 1,3', 'ordered-workers 3,1')),
        ('os-affinity', 'forward/active-thread-1-status.txt', lambda text: re.sub(r'Cpus_allowed_list:\s*1\b', 'Cpus_allowed_list:\t3', text)),
        ('owner-thread', 'forward/vpp.log', lambda text: re.sub(r'(s207 stage=policy [^\n]*?thread=)[12]', lambda m: m[1]+('2' if m[0][-1]=='1' else '1'), text, count=1)),
    ]
    if supervisor:
        changes += [
            ('saved-choice', 'saved/preferences.xml', lambda text: text.replace('1,3', '3,1')),
            ('active-after-stop', 'forward/stopped.properties', lambda text: text.replace('mayBeActive=false', 'mayBeActive=true')),
            ('native-stop-debt', 'forward/vpp.log', lambda text: re.sub(r'(s242 event=stop_native_zero [^\n]*?buffers=)0', r'\g<1>1', text)),
            ('missing-rejection', 'forward/worker_placement_requires_restart.log', lambda text: text.replace('error=worker_placement_requires_restart', 'error=unrelated')),
            ('owner-seed', 'forward/guard.properties', lambda text: re.sub(r'product_graph_hash_seed=\d+', 'product_graph_hash_seed=1', text)),
        ]
    else:
        changes += [
            ('expiry-residue', 'forward/native-closed-resources.txt', lambda text: text.replace('timers=0', 'timers=1', 1)),
            ('handoff-credit', 'forward/native-closed.txt', lambda text: text.replace('credit0=32', 'credit0=31', 1)),
            ('wrong-native-error', 'invalid-forbidden-worker/native.txt', lambda text: text.replace('outside inherited allowed affinity', 'successfully bound')),
        ]
    rejected = []
    read_text, read_bytes = Path.read_text, Path.read_bytes
    for label, name, transform in changes:
        original = read_text(directory/name)
        altered = transform(original)
        assert altered != original, 'mutation did not alter its target: '+label
        modified = copy.deepcopy(result)
        modified['raw_hashes'][name] = hashlib.sha256(altered.encode()).hexdigest()
        # Virtual file contents model a fully rehashed input; original raw
        # evidence is neither edited nor shared through writable hardlinks.
        files = {directory/name: altered.encode(), directory/'result.json': json.dumps(modified).encode()}
        def bytes_for(path, *args, **kwargs):
            return files[path] if path in files else read_bytes(path, *args, **kwargs)
        def text_for(path, *args, **kwargs):
            return files[path].decode() if path in files else read_text(path, *args, **kwargs)
        with patch.object(Path, 'read_bytes', bytes_for), patch.object(Path, 'read_text', text_for):
            try: verifier.verify(directory)
            except AssertionError as error:
                assert 'raw evidence changed' not in str(error), 'hash-only rejection: '+label
                rejected.append(dict(case=label, error=str(error)))
            else: raise AssertionError('semantic corruption accepted: '+label)
    return dict(status='PASS', suite='supervisor' if supervisor else 'native', platform=result['platform'],
        source_result_sha256=baseline['result_sha256'], source_sha256=baseline['source_sha256'],
        verifier_files=baseline['verifier_files'], semantic_negatives=len(rejected), rejected=rejected,
        script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('directory', type=Path)
    parser.add_argument('--supervisor', action='store_true'); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); answer = run(args.directory.resolve(), args.supervisor)
    args.output.write_text(json.dumps(answer, indent=2)+'\n')
    print(json.dumps(answer, indent=2))
