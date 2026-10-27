#!/usr/bin/env python3
"""Replay the real observation shutdown regression with persistent Host caches.

Requires an existing Product Host artifact, pinned VPP includes and the matching
Product builder's persistent Cargo target. No Android device is used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host-artifact', type=Path, required=True)
    parser.add_argument('--vpp-include', type=Path, required=True)
    parser.add_argument('--cargo-target-dir', type=Path, required=True)
    parser.add_argument('--host-tests', type=Path, default=ROOT / 'build-output/host-tests')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    artifact, include, target, host, out = (p.resolve() for p in (
        args.host_artifact, args.vpp_include, args.cargo_target_dir, args.host_tests, args.output))
    cache = ROOT / 'build-output/product-build-cache'
    assert target.is_relative_to(cache) and target.name == 'cargo-target' and target.is_dir()
    assert (include / 'vppinfra/mem.h').is_file()
    assert (artifact / 'include/vapi/product_core.api.vapi.h').is_file()
    out.mkdir(parents=True, exist_ok=False)
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    names = set()
    for directory in ('src/product', 'crates/product-core'):
        names.update(p for p in (ROOT / directory).rglob('*')
                     if p.is_file() and p.suffix in ('.c', '.h', '.inc', '.rs', '.toml'))
    names.update(ROOT / name for name in (
        'tests/host/product_observation_producer.c',
        'tests/host/product_observation_wait_gate.c',
        'tests/host/product_root_dns_adapter_test.c',
        'tests/host/product_root_dns_adapter_test.py',
        'tests/evidence/s319_shutdown_prefix.py'))
    sources = {str(p.relative_to(ROOT)): digest(p) for p in sorted(names)}
    with zipfile.ZipFile(out / 'source.zip', 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sources:
            archive.write(ROOT / name, name)
    report = dict(status='RUNNING', source=sources, operations=[],
                  started_monotonic_ns=time.monotonic_ns(),
                  host_artifact=str(artifact), cargo_target_dir=str(target))

    def save():
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')

    def run(label, command, environment):
        row = dict(label=label, command=list(map(str, command)))
        report['operations'].append(row)
        save()
        with (out / (label + '.log')).open('x') as log:
            result = subprocess.run(row['command'], cwd=ROOT, env=environment,
                                    stdout=log, stderr=subprocess.STDOUT, timeout=600)
        row['exit_code'] = result.returncode
        save()
        assert result.returncode == 0, label

    try:
        environment = dict(os.environ, LD_LIBRARY_PATH=str(artifact / 'lib'))
        run('host-libraries', ['cmake', '--build', host, '--target',
            'sakamoto_product_dns', 'sakamoto_product_l4_policy',
            'sakamoto_product_domains', 'sakamoto_dns_wire', '-j', '8'], environment)
        libraries = [host / name for name in (
            'libsakamoto_product_dns.a', 'libsakamoto_product_l4_policy.a',
            'libsakamoto_product_domains.a', 'third_party/cares/libsakamoto_dns_wire.a')]
        report['adapter_library_sha256'] = {str(p): digest(p) for p in libraries}
        run('actual-adapter-stopped16', ['python3', ROOT / 'tests/host/product_root_dns_adapter_test.py',
            *libraries, '--case', 'shutdown-prefix', '--records', out / 'stop-records.bin',
            '--evidence', out / 'adapter-execution'], environment)
        assert (out / 'stop-records.bin').stat().st_size == 16 * 704
        report['stop_records_sha256'] = digest(out / 'stop-records.bin')
        run('poll-gate-build', ['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
            '-shared', '-fPIC', ROOT / 'tests/host/product_observation_wait_gate.c',
            '-ldl', '-pthread', '-o', out / 'poll-gate.so'], environment)
        run('producer-build', ['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
            '-fno-strict-aliasing', '-I' + str(ROOT / 'src/product/include'), '-isystem', include,
            ROOT / 'tests/host/product_observation_producer.c',
            ROOT / 'src/product/native/product_observation_transport.c',
            '-L' + str(artifact / 'lib'), '-lsvm', '-lvppinfra', '-lpthread', '-ldl', '-lm',
            '-o', out / 'producer'], environment)
        environment.update(CARGO_TARGET_DIR=str(target),
            SAKAMOTO_PRODUCT_VAPI_INCLUDE_DIR=str(include),
            SAKAMOTO_PRODUCT_VAPI_LIBRARY_DIR=str(artifact / 'lib'),
            SAKAMOTO_PRODUCT_VAPI_GENERATED_DIR=str(artifact / 'include/vapi'),
            SAKAMOTO_PRODUCT_VAPI_REQUIRED='1',
            SAKAMOTO_OBSERVATION_PRODUCER=str(out / 'producer'),
            SAKAMOTO_DNS_STOP_PREFIX_RECORDS=str(out / 'stop-records.bin'),
            SAKAMOTO_SHUTDOWN_WAIT_DIR=str(out / 'poll-gate'),
            LD_PRELOAD=str(out / 'poll-gate.so'),
            SAKAMOTO_SHUTDOWN_EVIDENCE_DIR=str(out))
        for label, pattern in (
            ('shutdown-prefix-controls', 'native_shutdown_'),
            ('normal-capacity-lifecycle', 'native_process_capacity_isolation_end_and_exit')):
            run(label, ['cargo', 'test', '--release', '-p', 'sakamoto-product-core',
                '--lib', pattern, '--', '--ignored', '--nocapture', '--test-threads=1'], environment)
        report['source_unchanged'] = all(digest(ROOT / name) == sha for name, sha in sources.items())
        assert report['source_unchanged']
        report['status'] = 'PASS_BOUNDED_SHUTDOWN_PREFIX_AND_STOPPED16'
    except BaseException as error:
        report.update(status='HOLD', error=repr(error))
        raise
    finally:
        report['completed_monotonic_ns'] = time.monotonic_ns()
        save()
    print(json.dumps({key: report[key] for key in ('status', 'stop_records_sha256')}))


if __name__ == '__main__':
    main()
