#!/usr/bin/env python3
"""Corrupt current real-device witnesses in memory; never alter raw evidence."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import traceback
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('joint_negatives', ROOT/'tests/evidence/verify_foundation_joint.py')
joint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(joint)


def check(kind, directory, build):
    positive = joint.verify_one(kind, directory, build)
    record = json.loads((directory/'result.json').read_text())
    root = kind != 'vpn_active'
    pixel = kind == 'pixel_root'
    logname = ('stop' if pixel else 'faults-stop')+'/vpp.log' if root else 'stop/replacement-native-stop.log'
    log = (directory/logname).read_text()
    changes = [
        ('wrong-build-hash', 'result.json', lambda s: s.replace(record['build_sha256'], '0'*64)),
        ('missing-native-log', logname, lambda s: ''),
        ('graph-injection-as-ingress', logname,
         lambda s: s.replace('source=NFQ_CAPTURED' if root else 'source=TUN_CAPTURED', 'source=GRAPH_INJECTED')),
    ]
    if root:
        changes += [
            ('duplicate-native-verdict', logname, lambda s: s+'\n'+next(l for l in s.splitlines()
                if l.startswith('s242 event=verdict_syscall '))+'\n'),
            ('wrong-origin-fd', logname, lambda s: re.sub(r'(s242 event=verdict_syscall [^\n]*?fd=)\d+', r'\g<1>9999', s, count=1)),
            ('stop-buffer-debt', logname, lambda s: re.sub(r'(s242 event=stop_native_zero [^\n]*?buffers=)0', r'\g<1>1', s)),
            ('lane-fd-residue', logname, lambda s: re.sub(r'(s242 event=lane_closed [^\n]*?fd=)-1', r'\g<1>77', s, count=1)),
        ]
        if pixel:
            changes += [
                ('poc-readiness', 'stop/running.properties', lambda s: s.replace(
                    'adapterReadiness=root-nfqueue-tcp-udp-echo-dualstack-q2w2', 'adapterReadiness=poc-handcrafted-direct-bridge')),
                ('active-after-stop', 'stop/stopped.properties', lambda s: s.replace('mayBeActive=false', 'mayBeActive=true')),
                ('wrong-installed-apk', 'installed-apk.txt', lambda s: '0'*64+s[64:]),
            ]
    else:
        changes += [
            ('poc-return-as-transport', logname, lambda s: s.replace('source=FLOW_STACK_RETURN', 'source=POC_RETURN')),
            ('old-node-generation', logname, lambda s: re.sub(r'\bgeneration=\d+', 'generation=1', s, count=1)),
            ('owner-session-residue', logname, lambda s: re.sub(r'(s237 event=owner_stopped [^\n]*?sessions=)0', r'\g<1>1', s, count=1)),
            ('tun-fd-residue', logname, lambda s: re.sub(r'(s213 event=stop [^\n]*?tun_fd=)-1', r'\g<1>77', s)),
            ('wrong-installed-apk', 'installed-apk.txt', lambda s: '0'*64+s[64:]),
            ('false-release-protection', 'stop/initial.properties', lambda s: s.replace('protectionRunning=false', 'protectionRunning=true')),
        ]
    read_text, read_bytes = Path.read_text, Path.read_bytes
    rejected = []

    def reject(name, files):
        def text_for(path, *args, **kwargs):
            return files[path].decode() if path in files else read_text(path, *args, **kwargs)
        def bytes_for(path, *args, **kwargs):
            return files[path] if path in files else read_bytes(path, *args, **kwargs)
        with patch.object(Path, 'read_text', text_for), patch.object(Path, 'read_bytes', bytes_for):
            try:
                joint.verify_one(kind, directory, build)
            except AssertionError as error:
                assert 'raw evidence changed' not in str(error), 'hash-only rejection: '+name
                frame = traceback.extract_tb(error.__traceback__)[-1]
                rejected.append(dict(case=name, rejection=str(error), location=Path(frame.filename).name+':'+str(frame.lineno)))
            else:
                raise AssertionError('accepted corrupt evidence: '+name)

    for name, filename, transform in changes:
        original = read_text(directory/filename)
        changed = transform(original)
        assert changed != original, 'no mutation: '+name
        modified = copy.deepcopy(record)
        files = {directory/filename: changed.encode()}
        if filename != 'result.json' and root:
            modified['raw_hashes'][filename] = hashlib.sha256(changed.encode()).hexdigest()
            files[directory/'result.json'] = json.dumps(modified).encode()
        reject(name, files)
    # A internally consistent source/build identity is still stale if it does
    # not describe the current Product. Rehash both build and run declarations.
    old = json.loads(read_text(build))
    key = next(k for k, value in old['files'].items() if value and k.startswith('src/product/'))
    old['files'][key] = '0'*64
    chain = joint.module('negative_chain', ROOT/'tests/evidence/product_chain.py')
    old['source_sha256'] = hashlib.sha256(chain.encode(old['files'])).hexdigest()
    old_bytes = json.dumps(old).encode()
    modified = copy.deepcopy(record)
    modified['build_sha256'] = hashlib.sha256(old_bytes).hexdigest()
    if root:
        modified['source_sha256'] = old['source_sha256']
    reject('stale-source-rehashed-build', {build: old_bytes, directory/'result.json': json.dumps(modified).encode()})
    return dict(status='PASS', kind=kind, positive_scope=positive.get('scope'),
                original_result_sha256=joint.digest(directory/'result.json'),
                negatives=len(rejected), rejected=rejected,
                script_sha256=joint.digest(__file__),
                verifier_sha256=joint.digest(ROOT/'tests/device'/joint.VERIFIERS[kind]))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--kind', choices=('linux_root', 'pixel_root', 'vpn_active'), required=True)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.kind, args.run.resolve(), args.build.resolve())
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
