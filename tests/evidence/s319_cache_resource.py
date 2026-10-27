#!/usr/bin/env python3
"""Run real Adapter allocation failures through DNS decoding and normal SQLite.

Uses an existing Product Host artifact and its persistent Cargo target. The
source-linked Adapter controls socket completion, without an Android device.
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
    assert target.is_relative_to(ROOT / 'build-output/product-build-cache')
    assert target.name == 'cargo-target' and target.is_dir()
    assert (include / 'vppinfra/mem.h').is_file()
    assert (artifact / 'include/vapi/product_core.api.vapi.h').is_file()
    out.mkdir(parents=True, exist_ok=False)
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    names = set()
    for directory in ('src/product', 'crates/product-core'):
        names.update(p for p in (ROOT / directory).rglob('*')
                     if p.is_file() and p.suffix in ('.c', '.h', '.inc', '.rs', '.toml'))
    names.update(ROOT / name for name in (
        'tests/host/product_root_dns_adapter_test.c',
        'tests/host/product_root_dns_adapter_test.py', 'tests/evidence/s319_cache_resource.py'))
    sources = {str(p.relative_to(ROOT)): digest(p) for p in sorted(names)}
    with zipfile.ZipFile(out / 'source.zip', 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sources:
            archive.write(ROOT / name, name)
    report = dict(status='RUNNING', source=sources, operations=[],
                  started_monotonic_ns=time.monotonic_ns(), host_artifact=str(artifact),
                  cargo_target_dir=str(target))

    def save():
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')

    def run(label, command, environment):
        row = dict(label=label, command=list(map(str, command)))
        report['operations'].append(row); save()
        with (out / (label + '.log')).open('x') as log:
            result = subprocess.run(row['command'], cwd=ROOT, env=environment,
                                    stdout=log, stderr=subprocess.STDOUT, timeout=600)
        row['exit_code'] = result.returncode; save()
        assert result.returncode == 0, label

    environment = dict(os.environ, LD_LIBRARY_PATH=str(artifact / 'lib'))
    try:
        run('host-libraries', ['cmake', '--build', host, '--target',
            'sakamoto_product_dns', 'sakamoto_product_l4_policy',
            'sakamoto_product_domains', 'sakamoto_dns_wire', '-j', '8'], environment)
        libraries = [host / name for name in (
            'libsakamoto_product_dns.a', 'libsakamoto_product_l4_policy.a',
            'libsakamoto_product_domains.a', 'third_party/cares/libsakamoto_dns_wire.a')]
        report['adapter_library_sha256'] = {str(p): digest(p) for p in libraries}
        run('actual-adapter-failures24', ['python3', ROOT / 'tests/host/product_root_dns_adapter_test.py',
            *libraries, '--case', 'cache-resource', '--records', out / 'records.bin',
            '--evidence', out / 'adapter-execution'], environment)
        assert (out / 'records.bin').stat().st_size == 120 * 704
        report['records_sha256'] = digest(out / 'records.bin')
        environment.update(CARGO_TARGET_DIR=str(target),
            SAKAMOTO_PRODUCT_VAPI_INCLUDE_DIR=str(include),
            SAKAMOTO_PRODUCT_VAPI_LIBRARY_DIR=str(artifact / 'lib'),
            SAKAMOTO_PRODUCT_VAPI_GENERATED_DIR=str(artifact / 'include/vapi'),
            SAKAMOTO_PRODUCT_VAPI_REQUIRED='1',
            SAKAMOTO_DNS_CACHE_RESOURCE_RECORDS=str(out / 'records.bin'),
            SAKAMOTO_DNS_CODEC_EVIDENCE_DIR=str(out / 'normal-store'))
        # The normal test profile is unwind, while Product release is abort.
        # Cargo's release integration-test graph can collide on the crate's
        # un-hashed rlib/cdylib outputs for those two panic strategies.
        run('decode-normal-store-reopen', ['cargo', 'test', '-p', 'sakamoto-product-core',
            '--test', 'dns_observation', 'source_linked_cache_resource_failures_', '--', '--ignored',
            '--nocapture', '--test-threads=1'], environment)
        report['status'] = 'PASS_ACTUAL_ALLOCATOR_DNS_HISTORY'
    except BaseException as error:
        report.update(status='HOLD', error=repr(error))
        raise
    finally:
        report['source_unchanged'] = all(digest(ROOT / name) == sha for name, sha in sources.items())
        report['completed_monotonic_ns'] = time.monotonic_ns(); save()
    assert report['source_unchanged']
    print(json.dumps({key: report[key] for key in ('status', 'records_sha256')}))


if __name__ == '__main__':
    main()
