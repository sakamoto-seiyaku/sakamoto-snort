#!/usr/bin/env python3
"""Real Product startup rejects malformed Root owner selection before NFQUEUE capture."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument('--artifact', type=Path, required=True)
parser.add_argument('--stage', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
artifact, stage, output = (path.resolve() for path in
                           (args.artifact, args.stage, args.output))
output.mkdir(parents=True, exist_ok=False)
allowed = sorted(os.sched_getaffinity(0))
assert len(allowed) >= 2
vppctl = stage/'source/build-root/install-vpp-native/vpp/bin/vppctl'
assert vppctl.is_file() and (artifact/'bin/vpp').is_file()
(output/'artifact.sha256').write_text(hashlib.sha256(
    (artifact/'lib/vpp_plugins/product_core_plugin.so').read_bytes()).hexdigest()+'\n')

for selected in ('01', '3'):
    case = output/('leading-zero' if selected == '01' else 'unsupported-three')
    case.mkdir()
    runtime = case/'runtime'
    runtime.mkdir()
    config = case/'startup.conf'
    config.write_text(f'''cpu {{ main-core {allowed[0]} workers 1 ordered-workers {allowed[1]} }}
unix {{ nodaemon cli-no-pager runtime-dir {runtime} cli-listen {runtime}/cli.sock }}
socksvr {{ socket-name {runtime}/api.sock }}
plugins {{ path {artifact}/lib/vpp_plugins plugin default {{ disable }} plugin product_core_plugin.so {{ enable }} }}
''')
    env = dict(os.environ, LD_LIBRARY_PATH=str(artifact/'lib'),
               SAKAMOTO_PRODUCT_GENERATION='29501', SAKAMOTO_RUNTIME_PROFILE='root',
               SAKAMOTO_PRODUCT_OWNER_COUNT=selected,
               SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0',
               SAKAMOTO_RULE_CONFIG_PATH=str(case/'rules.conf'))
    with (case/'vpp.log').open('w') as log:
        process = subprocess.Popen([str(artifact/'bin/vpp'), '-c', str(config)],
                                   env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic()+10
            while not (runtime/'cli.sock').exists():
                assert process.poll() is None, (case/'vpp.log').read_text()
                assert time.monotonic() < deadline
                time.sleep(.05)
            while True:
                assert process.poll() is None, (case/'vpp.log').read_text()
                queried = subprocess.run([str(vppctl), '-s', str(runtime/'cli.sock'),
                                          'show product topology'], env=env,
                                         text=True, capture_output=True)
                if queried.returncode == 0 and 'topology.profile=root' in queried.stdout:
                    break
                assert time.monotonic() < deadline
                time.sleep(.05)
            (case/'topology.txt').write_text(queried.stdout)
            assert ('owner_count=0 vpp_worker_count=0 actual_vpp_workers=1'
                    in queried.stdout), queried.stdout
            assert 'ready=0' in queried.stdout and 'topology.tun_io_lane=none' in queried.stdout
            status = subprocess.run([str(artifact/'bin/sakamoto-product-core-host'),
                                     'rule-query', str(runtime/'api.sock'), '29501'],
                                    env=env, text=True, capture_output=True, check=True)
            (case/'status.txt').write_text(status.stdout)
            assert 'query.adapter_available=false' in status.stdout
            assert 'query.protection_running=false' in status.stdout
        finally:
            process.terminate()
            process.wait(timeout=5)
    (case/'exit.txt').write_text(f'pid={process.pid} exit={process.returncode}\n')
    assert not Path(f'/proc/{process.pid}').exists()

print('Product Root invalid owner selection rejected before capture')
