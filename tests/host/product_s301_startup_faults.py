#!/usr/bin/env python3
"""Real Product VPP startup rejection before Root/VPN packet capture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time


def cpu_set(text):
    values = set()
    for field in text.strip().split(','):
        if not field:
            continue
        bounds = [int(value) for value in field.split('-')]
        values.update(range(bounds[0], bounds[-1] + 1))
    return values


def run_case(label, artifact, stage, output, cpus, owners, io, *, selected=None,
             worker_count=None, ordered=None, capacity=None, allowed=None,
             fault_after=None, startup_error=None, product_error=None, profile='vpn'):
    case = output / label
    case.mkdir()
    runtime = case / 'r'
    runtime.mkdir()
    configured = ordered if ordered is not None else owners + ([io] if profile == 'vpn' else [])
    workers = worker_count if worker_count is not None else len(configured)
    config = case / 'startup.conf'
    config.write_text(
        f"cpu {{ main-core {cpus[0]} workers {workers} "
        f"ordered-workers {','.join(map(str, configured))} }}\n"
        f"unix {{ nodaemon cli-no-pager runtime-dir {runtime} "
        f"cli-listen {runtime}/cli.sock }}\n"
        f"socksvr {{ socket-name {runtime}/api.sock }}\n"
        f"plugins {{ path {artifact}/lib/vpp_plugins plugin default {{ disable }} "
        "plugin product_core_plugin.so { enable } }\n"
        + (f"product-flow-runtime {{ entries {capacity} }}\n" if capacity else ''))
    env = dict(os.environ, LD_LIBRARY_PATH=str(artifact / 'lib'),
               SAKAMOTO_PRODUCT_GENERATION='30101', SAKAMOTO_RUNTIME_PROFILE=profile,
               SAKAMOTO_PRODUCT_OWNER_COUNT=str(selected if selected is not None else len(owners)),
               SAKAMOTO_PRODUCT_VPN_GRAPH_VALIDATION='1',
               SAKAMOTO_VPP_RUNTIME_DIR=str(runtime),
               SAKAMOTO_RULE_CONFIG_PATH=str(case / 'rules.conf'))
    env.pop('SAKAMOTO_PRODUCT_TUN_IO_CPU_ID', None)
    if profile == 'vpn': env['SAKAMOTO_PRODUCT_TUN_IO_CPU_ID'] = str(io)
    else: env['SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID'] = '0'
    env.pop('SAKAMOTO_PRODUCT_HOST_START_FAIL_AFTER_OWNER', None)
    if fault_after is not None:
        env['SAKAMOTO_PRODUCT_HOST_STARTUP_FAULTS'] = '1'
        env['SAKAMOTO_PRODUCT_HOST_START_FAIL_AFTER_OWNER'] = str(fault_after)
    def restrict():
        if allowed is not None:
            os.sched_setaffinity(0, allowed)
    with (case / 'vpp.log').open('w') as log:
        process = subprocess.Popen([str(artifact / 'bin/vpp'), '-c', str(config)],
                                   env=env, stdout=log, stderr=subprocess.STDOUT,
                                   preexec_fn=restrict if allowed is not None else None)
        try:
            deadline = time.monotonic() + 12
            if startup_error:
                while process.poll() is None and time.monotonic() < deadline:
                    time.sleep(.05)
                assert process.poll() is not None, label + ': VPP unexpectedly stayed alive'
                logs = (case / 'vpp.log').read_text(errors='replace')
                assert startup_error in logs, (label, logs)
                assert not (runtime / 'tun-control.sock').exists()
                return dict(case=label, startup_rejected=startup_error,
                            exit=process.returncode)
            while not (runtime / 'cli.sock').exists():
                assert process.poll() is None, (label, (case / 'vpp.log').read_text())
                assert time.monotonic() < deadline, label + ': CLI startup timeout'
                time.sleep(.05)
            vppctl = stage / 'source/build-root/install-vpp-native/vpp/bin/vppctl'
            def cli(command):
                result = subprocess.run([str(vppctl), '-s', str(runtime / 'cli.sock'),
                                         command], env=env, text=True, capture_output=True)
                assert result.returncode == 0, (label, command, result.stderr)
                return result.stdout
            while product_error not in (case / 'vpp.log').read_text(errors='replace'):
                assert process.poll() is None and time.monotonic() < deadline, label
                time.sleep(.05)
            topology = cli('show product topology')
            tun = cli('show product tun')
            primary = cli('show product primary')
            root = cli('show product root lanes') if profile == 'root' else ''
            (case / 'topology.txt').write_text(topology)
            (case / 'tun.txt').write_text(tun)
            (case / 'primary.txt').write_text(primary)
            if profile == 'vpn':
                assert 'enabled=0 attached=0' in tun and 'captured=0 submitted=0 completed=0' in tun
            else:
                (case / 'root.txt').write_text(root)
                assert all('ready=0' in row and 'captured=0' in row for row in
                           root.splitlines() if row.startswith('root.lane ')), root
            assert not (runtime / 'tun-control.sock').exists()
            assert re.search(r'\bbuffers=0 obligations=0\b', tun), tun
            assert 'handoff_debt=0' in primary and 'pending_returns=0' in primary, primary
            if fault_after is not None:
                flows = cli('show product flows')
                (case / 'flows.txt').write_text(flows)
                pool_rows = re.findall(r'^flow\.pool worker=\d+ pool=\S+ entries=\d+',
                                       flows, re.MULTILINE)
                assert len(pool_rows) == len(owners) and all(
                    'pool=0x0 entries=0' in row for row in pool_rows), flows
            return dict(case=label, product_rejected=product_error,
                        no_capture=True, no_debt=True)
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            (case / 'exit.txt').write_text(f'pid={process.pid} exit={process.returncode}\n')
            assert not Path(f'/proc/{process.pid}').exists()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifact', required=True, type=Path)
    parser.add_argument('--stage', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    artifact, stage, output = (p.resolve() for p in
                               (args.artifact, args.stage, args.output))
    output.mkdir(parents=True, exist_ok=False)
    cpus = sorted(os.sched_getaffinity(0))
    assert len(cpus) >= 3
    online = cpu_set(Path('/sys/devices/system/cpu/online').read_text())
    present = cpu_set(Path('/sys/devices/system/cpu/present').read_text())
    offline = min(present - online) if present - online else max(present) + 1
    owners, io = [cpus[1]], cpus[2]
    (output / 'artifact.sha256').write_text(hashlib.sha256(
        (artifact / 'lib/vpp_plugins/product_core_plugin.so').read_bytes()).hexdigest() + '\n')
    records = []
    records.append(run_case('offline-or-absent', artifact, stage, output, cpus,
                            owners, offline, startup_error='absent or offline'))
    records.append(run_case('disallowed', artifact, stage, output, cpus,
                            owners, io, allowed={cpus[0], cpus[1]},
                            startup_error='outside inherited allowed affinity'))
    records.append(run_case('binding-count', artifact, stage, output, cpus,
                            owners, io, worker_count=3,
                            startup_error='CPU count must equal workers'))
    records.append(run_case('io-owner-conflict', artifact, stage, output, cpus,
                            owners, cpus[1], product_error='tunIoCpuId rejected before adapter capture'))
    records.append(run_case('thread-limit', artifact, stage, output, cpus,
                            [cpus[1]] * 62, io, selected=62,
                            startup_error='ordered-workers: too many CPUs'))
    records.append(run_case('capacity-overflow', artifact, stage, output, cpus,
                            [cpus[1]] * 5, io, capacity=1073741823,
                            product_error='per-owner state resource rejected before capture'))
    records.append(run_case('partial-start-rollback', artifact, stage, output, cpus,
                            [cpus[1]] * 3, io, fault_after=1,
                            product_error='injected per-owner startup failure after owner=1'))
    records.append(run_case('root-offline-or-absent', artifact, stage, output, cpus,
                            [offline], io, profile='root', startup_error='absent or offline'))
    records.append(run_case('root-disallowed', artifact, stage, output, cpus,
                            [cpus[1]], io, profile='root', allowed={cpus[0]},
                            startup_error='outside inherited allowed affinity'))
    records.append(run_case('root-binding-count', artifact, stage, output, cpus,
                            [cpus[1]], io, profile='root', worker_count=2,
                            startup_error='CPU count must equal workers'))
    records.append(run_case('root-thread-limit', artifact, stage, output, cpus,
                            [cpus[1]] * 63, io, profile='root', selected=63,
                            startup_error='ordered-workers: too many CPUs'))
    records.append(run_case('root-capacity-overflow', artifact, stage, output, cpus,
                            [cpus[1]] * 5, io, profile='root', capacity=1073741823,
                            product_error='per-owner state resource rejected before capture'))
    records.append(run_case('root-partial-start-rollback', artifact, stage, output, cpus,
                            [cpus[1]] * 3, io, profile='root', fault_after=1,
                            product_error='injected per-owner startup failure after owner=1'))
    (output / 'result.json').write_text(json.dumps(records, indent=2) + '\n')
    print('Product Root/VPN startup rejection and partial rollback: PASS')


if __name__ == '__main__':
    main()
