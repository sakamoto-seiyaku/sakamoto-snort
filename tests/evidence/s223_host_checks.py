#!/usr/bin/env python3
"""Record bounded standalone UDP/FlowRuntime regressions and sanitizer output."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser(); p.add_argument('--output', type=Path, required=True)
a = p.parse_args(); a.output = a.output.resolve(); a.output.mkdir(parents=True, exist_ok=False)
report = dict(status='HOLD', checks=[])
def run(name, command):
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=60)
    (a.output/(name+'.log')).write_text(result.stdout)
    report['checks'].append(dict(name=name, command=command, returncode=result.returncode))
    assert result.returncode == 0, (name, result.stdout[-2000:])
try:
    with tempfile.TemporaryDirectory(prefix='s223-host-checks-') as temporary:
        run('configure', ['cmake', '-S', str(ROOT), '-B', temporary])
        run('build', ['cmake', '--build', temporary, '-j', '4'])
        run('ctest', ['ctest', '--test-dir', temporary, '-R',
            's174|s175-product-packet|flow-|s209|s210', '--output-on-failure'])
        binary = temporary+'/udp-sanitized'
        run('sanitizer-build', ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-g',
            '-Isrc/product/vpp', 'tests/host/product_flow_udp_test.c',
            'src/product/vpp/product_flow_udp.c', 'src/product/vpp/product_flow_entry.c',
            'src/product/vpp/product_packet.c', '-o', binary])
        run('sanitizer', ['timeout', '15s', 'env', 'ASAN_OPTIONS=detect_leaks=0', binary])
        report['leak_sanitizer'] = 'disabled; not claimed'
        report['status'] = 'PASS'
finally:
    sources = ['src/product/vpp/product_flow_tracker.h', 'src/product/vpp/product_flow_udp.c',
               'src/product/vpp/product_flow_entry.h', 'src/product/vpp/product_flow_entry.c',
               'src/product/vpp/product_packet.c', 'tests/host/product_flow_udp_test.c',
               'tests/host/product_flow_entry_test.c', 'tests/evidence/s223_host_checks.py']
    report['sources'] = {name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sources}
    (a.output/'verification.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
