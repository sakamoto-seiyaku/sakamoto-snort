#!/usr/bin/env python3
"""Rehashed semantic corruptions; original raw evidence is never modified."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s235_negative_verify', ROOT/'tests/device/verify-s235-network.py')
verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)


def check(directory):
    baseline = verifier.verify(directory)
    result = json.loads((directory/'result.json').read_text())
    pixel = result['platform'] == 'pixel'; label = 'smoke' if pixel else 'kernel'
    logname = label+'/vpp.log'
    log = (directory/logname).read_text()
    token = result['generations'][0]['cases'][0]['token'] if pixel else int(verifier.rows(log, 's231 ', 'nfq_payload')[0]['token'])
    changes = [
        ('duplicate-verdict', logname, lambda s: s+'\n'+next(l for l in s.splitlines() if l.startswith('s242 event=verdict_syscall '))+'\n'),
        ('owner-thread', logname, lambda s: re.sub(r'(s207 stage=policy token='+str(token)+r' [^\n]*?thread=)([12])',
             lambda m: m[1]+('2' if m[2] == '1' else '1'), s, count=1)),
        ('native-stop-debt', logname, lambda s: re.sub(r'(s242 event=stop_native_zero [^\n]*?buffers=)0', r'\g<1>1', s)),
        ('lane-fd-residue', logname, lambda s: re.sub(r'(s242 event=lane_closed [^\n]*?fd=)-1', r'\g<1>77', s, count=1)),
    ]
    if pixel:
        changes += [
            ('app-still-active', 'smoke/stopped.properties', lambda s: s.replace('mayBeActive=false', 'mayBeActive=true')),
            ('android-subscription-live', 'network-events.log', lambda s: s.replace('subscription_stopped thread_alive=false', 'subscription_stopped thread_alive=true')),
        ]
    else:
        changes += [
            ('wrong-packet-context', logname, lambda s: re.sub(r'(s232 event=packet_snapshot [^\n]*?context=)4', r'\g<1>8', s, count=1)),
            ('raw-nfq-interface-altered', logname, lambda s: re.sub(r'(s217 event=nfq_facts [^\n]*?raw_outdev=)\d+', r'\g<1>9999', s, count=1)),
            ('loss-not-observed', logname, lambda s: s.replace('reason=receive_loss ', 'reason=not_observed ')),
            ('subscription-residue', logname, lambda s: re.sub(r'(s235 event=collector_closed [^\n]*?subscriptions=)0', r'\g<1>1', s)),
            ('virtual-classified-as-vpn', 'links-initial.json', lambda s: s.replace('"info_kind":"veth"', '"info_kind":"wireguard"')),
            ('wrong-injected-category', 'controlled/control-4-1001.txt', lambda s: s.replace('context=1 ', 'context=8 ')),
        ]
    rejected = []; read_text, read_bytes = Path.read_text, Path.read_bytes
    for name, path, transform in changes:
        original = read_text(directory/path); changed = transform(original)
        assert changed != original, 'no mutation: '+name
        modified = copy.deepcopy(result)
        modified['raw_hashes'][path] = hashlib.sha256(changed.encode()).hexdigest()
        files = {directory/path: changed.encode(), directory/'result.json': json.dumps(modified).encode()}
        def bytes_for(p, *args, **kwargs): return files[p] if p in files else read_bytes(p, *args, **kwargs)
        def text_for(p, *args, **kwargs): return files[p].decode() if p in files else read_text(p, *args, **kwargs)
        with patch.object(Path, 'read_bytes', bytes_for), patch.object(Path, 'read_text', text_for):
            try: verifier.verify(directory)
            except AssertionError as error:
                assert 'raw evidence changed' not in str(error), 'hash-only rejection: '+name
                rejected.append(dict(case=name, error=str(error)))
            else: raise AssertionError('accepted corrupt evidence: '+name)
    return dict(status='PASS', platform=result['platform'], source_sha256=baseline['source_sha256'],
        source_result_sha256=baseline['result_sha256'], verifier_files=baseline['verifier_files'],
        semantic_negatives=len(rejected), rejected=rejected, script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('directory', type=Path); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); answer = check(args.directory.resolve())
    args.output.write_text(json.dumps(answer, indent=2)+'\n'); print(json.dumps(answer, indent=2))
