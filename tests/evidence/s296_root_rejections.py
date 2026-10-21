#!/usr/bin/env python3
"""SAKAMOTO-296: Product Root startup rejects invalid worker resources before capture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--artifact', type=Path, required=True)
parser.add_argument('--stage', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
artifact, stage, output = (p.resolve() for p in (args.artifact, args.stage, args.output))
output.mkdir(parents=True, exist_ok=False)
assert {0, 1, 2}.issubset(os.sched_getaffinity(0))
vppctl = stage/'source/build-root/install-vpp-native/vpp/bin/vppctl'
base = dict(os.environ, LD_LIBRARY_PATH=str(artifact/'lib'),
            PRODUCT_ARTIFACT_DIR=str(artifact), PRODUCT_MAIN_CPU='0',
            PRODUCT_GENERATION='29601', SAKAMOTO_RUNTIME_PROFILE='root',
            SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0',
            SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4')
cases = [
    ('owner-count-over-vpp-limit', '3', '1,2,1', '63',
     'owner count rejected before adapter capture', True),
    ('owner-count-mismatch', '3', '1,2,1', '4',
     'topology rejected before adapter capture: expected 4 VPP workers, found 3', True),
    ('worker-count-over-vpp-limit', '63', ','.join(['1']*63), '63',
     'ordered-workers: too many CPUs', False),
    ('cpu-out-of-range', '3', '1,2,9999', '3',
     'ordered-workers: CPU ID out of range', False),
    ('cpu-conflicts-main', '3', '1,2,0', '3',
     'ordered-workers: CPU 0 conflicts with main-core', False),
    ('binding-count-mismatch', '3', '1,2', '3',
     'PRODUCT_WORKER_CPUS count must equal PRODUCT_WORKER_COUNT', False),
]
summary = []
runtime_id = hashlib.sha256(str(output).encode()).hexdigest()[:16]
for name, worker_count, cpus, owners, expected, stays_running in cases:
    location = output/name
    location.mkdir()
    runtime = ROOT/'build-output'/f'product-vpp-runtime-s296-{runtime_id}-{len(summary)}'
    env = dict(base, PRODUCT_RUNTIME_DIR=str(runtime),
               PRODUCT_RULE_CONFIG_DIR=str(location/'rules'),
               PRODUCT_WORKER_COUNT=worker_count, PRODUCT_WORKER_CPUS=cpus,
               SAKAMOTO_PRODUCT_OWNER_COUNT=owners)
    with (location/'log.txt').open('w') as log:
        process = subprocess.Popen(['bash', str(ROOT/'tools/product/run-host-vpp.sh')],
                                   env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic()+10
            while time.monotonic() < deadline:
                if process.poll() is not None or (runtime/'cli.sock').exists():
                    break
                time.sleep(.05)
            if stays_running:
                assert process.poll() is None and (runtime/'cli.sock').exists(), name
                def cli(command):
                    result = subprocess.run([str(vppctl), '-s', str(runtime/'cli.sock'), command],
                                            env=env, text=True, capture_output=True, timeout=10)
                    assert result.returncode == 0, result.stderr
                    return result.stdout
                topology = cli('show product topology')
                lanes = cli('show product root lanes')
                (location/'topology.txt').write_text(topology)
                (location/'lanes.txt').write_text(lanes)
                assert 'ready=0' in topology
                assert all('ready=0 ' in line and 'captured=0 ' in line
                           for line in lanes.splitlines() if line.startswith('root.lane ')), name
                assert not any('ready=1 ' in line for line in lanes.splitlines())
            else:
                assert process.wait(timeout=10) != 0, name
                assert not (runtime/'api.sock').exists(), name
        finally:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)
    observed = (location/'log.txt').read_text()
    assert expected in observed, (name, observed[-1500:])
    assert not Path(f'/proc/{process.pid}').exists(), name
    summary.append(dict(case=name, startup_rejected=True, capture_started=False,
                        exit_code=process.returncode, expected=expected))
(output/'result.json').write_text(json.dumps(dict(status='RAW_COMPLETE', cases=summary), indent=2)+'\n')
print('SAKAMOTO-296 startup rejection cases complete')
