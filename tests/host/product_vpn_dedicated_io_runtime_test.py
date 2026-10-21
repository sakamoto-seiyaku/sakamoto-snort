#!/usr/bin/env python3
"""Product VPP startup verifies explicit VPN TUN CPU and distinct worker role."""
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
artifact, stage, output = (p.resolve() for p in
                           (args.artifact, args.stage, args.output))
output.mkdir(parents=True, exist_ok=False)
cpus = sorted(os.sched_getaffinity(0))
assert len(cpus) >= 4, 'need distinct main, two owners, and TUN I/O CPUs'
vppctl = stage/'source/build-root/install-vpp-native/vpp/bin/vppctl'
(output/'plugin.sha256').write_text(hashlib.sha256(
    (artifact/'lib/vpp_plugins/product_core_plugin.so').read_bytes()).hexdigest()+'\n')

for label, owner_count, configured in [('missing', 2, False),
                                       ('dedicated', 2, True),
                                       ('single-owner', 1, True),
                                       ('shared-three', 3, True),
                                       ('shared-four', 4, True)]:
    case = output/label
    case.mkdir()
    runtime = case/'runtime'
    runtime.mkdir()
    assert len(os.fsencode(runtime/'tun-control.sock')) < 108, \
        'output path is too long for the Product TUN Unix socket'
    config = case/'startup.conf'
    owners = [cpus[1], cpus[2], cpus[1], cpus[2]][:owner_count] \
        if owner_count >= 3 else cpus[1:1+owner_count]
    io_cpu = cpus[3] if owner_count >= 3 else cpus[1+owner_count]
    config.write_text(f'''cpu {{ main-core {cpus[0]} workers {owner_count+1} ordered-workers {','.join(map(str, owners))},{io_cpu} }}
unix {{ nodaemon cli-no-pager runtime-dir {runtime} cli-listen {runtime}/cli.sock }}
socksvr {{ socket-name {runtime}/api.sock }}
plugins {{ path {artifact}/lib/vpp_plugins plugin default {{ disable }} plugin product_core_plugin.so {{ enable }} }}
''')
    env = dict(os.environ, LD_LIBRARY_PATH=str(artifact/'lib'),
               SAKAMOTO_PRODUCT_GENERATION='29701', SAKAMOTO_RUNTIME_PROFILE='vpn',
               SAKAMOTO_PRODUCT_OWNER_COUNT=str(owner_count), SAKAMOTO_PRODUCT_VPN_GRAPH_VALIDATION='1',
               SAKAMOTO_VPP_RUNTIME_DIR=str(runtime),
               SAKAMOTO_RULE_CONFIG_PATH=str(case/'rules.conf'))
    env.pop('SAKAMOTO_PRODUCT_TUN_IO_CPU_ID', None)
    if configured:
        env['SAKAMOTO_PRODUCT_TUN_IO_CPU_ID'] = str(io_cpu)
    with (case/'vpp.log').open('w') as log:
        process = subprocess.Popen([str(artifact/'bin/vpp'), '-c', str(config)],
                                   env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic()+15
            while not (runtime/'cli.sock').exists():
                assert process.poll() is None, (case/'vpp.log').read_text()
                assert time.monotonic() < deadline, (case/'vpp.log').read_text()
                time.sleep(.05)
            while True:
                assert process.poll() is None, (case/'vpp.log').read_text()
                query = subprocess.run([str(vppctl), '-s', str(runtime/'cli.sock'),
                                        'show product topology'], env=env,
                                       text=True, capture_output=True)
                if query.returncode == 0 and 'topology.profile=vpn' in query.stdout:
                    break
                assert time.monotonic() < deadline, query.stderr
                time.sleep(.05)
            (case/'topology.txt').write_text(query.stdout)
            if configured:
                assert (f'owner_count={owner_count} vpp_worker_count={owner_count+1} '
                        f'actual_vpp_workers={owner_count+1}') in query.stdout
                assert 'ready=1' in query.stdout, query.stdout
                assert (f'topology.tun_io_lane=0 worker={owner_count} '
                        f'thread_index={owner_count+1} actual_core={io_cpu} '
                        'is_flow_owner=0') in query.stdout
                assert f'topology.main thread_index=0 actual_core={cpus[0]}' in query.stdout
                for owner, cpu in enumerate(owners):
                    assert (f'topology.owner={owner} thread_index={owner+1} '
                            f'actual_core={cpu}') in query.stdout
                assert f'topology.owner={owner_count} ' not in query.stdout
                while not (runtime/'tun-control.sock').exists():
                    assert process.poll() is None, (case/'vpp.log').read_text()
                    assert time.monotonic() < deadline, (case/'vpp.log').read_text()
                    time.sleep(.05)
                stop = subprocess.run([str(vppctl), '-s', str(runtime/'cli.sock'),
                                       'product tun stop'], env=env,
                                      text=True, capture_output=True)
                (case/'tun-stop.txt').write_text(stop.stdout + stop.stderr)
                assert stop.returncode == 0 and 'tun.stop result=0' in stop.stdout, \
                    (stop.returncode, stop.stdout, stop.stderr, (case/'vpp.log').read_text())
            else:
                assert 'owner_count=0 vpp_worker_count=0 actual_vpp_workers=3' in query.stdout
                assert 'ready=0' in query.stdout
                assert not (runtime/'tun-control.sock').exists()
        finally:
            process.terminate()
            process.wait(timeout=5)
    (case/'exit.txt').write_text(f'pid={process.pid} exit={process.returncode}\n')
    assert not Path(f'/proc/{process.pid}').exists()
print('Product VPN N=1/2/3/4 dedicated I/O startup, shared CPU, and missing-setting rejection: PASS')
