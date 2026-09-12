#!/usr/bin/env python3
"""Lock down the current reassembly/original-buffer regression oracle."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('oracle', ROOT/'tests/device/verify-s231-fragments.py')
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)
p = argparse.ArgumentParser()
p.add_argument('run', type=Path)
p.add_argument('--build', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
assert oracle.verify(a.run, a.build, 'linux', True)['status'] == 'PASS'
report = dict(status='HOLD', cases=[], verifier_sha256=oracle.digest(oracle.__file__),
              semantic_verifier_sha256=oracle.digest(ROOT/'tests/device/s231-fragment-verify.py'))
mutations = (
    ('missing-original-release', 's212 event=origin_release ', lambda line: '', 'fragment original return conservation'),
    ('nonexclusive-original', 's212 event=origin_release ', lambda line: line.replace('refs=1', 'refs=2'), 'exclusive original fragment buffer'),
    ('missing-original-completion', 's212 event=completion_publish ', lambda line: '', 'fragment original return conservation'),
    ('wrong-bundle-size', 's229 event=product_reassembled ', lambda line: line.replace('originals=2', 'originals=1'), 'real NFQUEUE fragment bundle'),
    ('wrong-survivor', 's229 event=product_reassembled ', lambda line: ' '.join('survivor=0' if word.startswith('survivor=') else word for word in line.split()), 'original first-fragment survivor'),
)
for name, prefix, transform, expected in mutations:
    with tempfile.TemporaryDirectory(prefix='s233-fragment-negative-') as temporary:
        copy = Path(temporary)/'run'
        shutil.copytree(a.run, copy)
        path = copy/'g1/vpp.log'
        text = path.read_text()
        line = next(line for line in text.splitlines() if line.startswith(prefix))
        path.write_text(text.replace(line, transform(line), 1))
        result = oracle.verify(copy, a.build, 'linux', True)
        assert result['status'] == 'HOLD' and any(expected in error for error in result['errors']), (name, result)
        report['cases'].append(dict(name=name, rejected=True, errors=result['errors']))
report['status'] = 'PASS'
a.output.write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report, indent=2))
