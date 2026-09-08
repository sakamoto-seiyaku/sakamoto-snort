#!/usr/bin/env python3
"""Source/artifact, actual NFQUEUE semantics, and native stop evidence for S210."""
import argparse
import hashlib
import importlib.util
import json
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT/path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


oracle = module('capacity', 'tests/device/s210-capacity-verify.py')
chain = module('chain', 'tests/evidence/product_chain.py')
digest, rows = chain.digest, oracle.rows


def props(path):
    return dict(line.split('=', 1) for line in path.read_text().splitlines() if '=' in line and not line.startswith('#'))


def verify(out, build_file, platform):
    out, build_file = Path(out), Path(build_file)
    errors, summaries = [], []
    result, build = {}, {}
    try:
        result = json.loads((out/'result.json').read_text())
        build = json.loads(build_file.read_text())
        assert result['status'] == 'RAW_COMPLETE', 'collector incomplete'
        assert build['files'] == chain.source_files(), 'current product source differs'
        assert hashlib.sha256(chain.encode(build['files'])).hexdigest() == build['source_sha256'], 'source hash'
        assert digest(build_file.parent/'dirty.diff') == build['dirty_diff_sha256'], 'dirty diff'
        for name, expected in build['files'].items():
            if expected is not None: assert digest(build_file.parent/'source'/name) == expected, 'source snapshot '+name
        assert build['started_ns'] < build['completed_ns'] < result['started_ns'] < result['completed_ns'], 'fresh build/run'
        pixel = platform == 'pixel'
        if pixel:
            assert result['source'] == 'NFQ_CAPTURED' and result['profile'] == 'root' and result['serial'] == '28201JEGR0XPAJ'
            assert digest(build['apk']) == build['apk_sha256'] == result['apk_sha256'] == (out/'installed-apk-sha256.txt').read_text().split()[0]
            installed = {Path(l.split()[1]).name:l.split()[0] for l in (out/'installed-native-sha256.txt').read_text().splitlines()}
            assert installed == build['native_sha256'] == result['native_sha256'], 'installed native hashes'
            with zipfile.ZipFile(build['apk']) as apk:
                assert {Path(n).name:hashlib.sha256(apk.read(n)).hexdigest() for n in apk.namelist()
                        if n.startswith('lib/arm64-v8a/') and n.endswith('.so')} == installed, 'APK native hashes'
            assert result['wifi_before'] == result['wifi_after'] == (out/'final-wifi.txt').read_text().strip(), 'Wi-Fi restoration'
            assert not re.search(r'libvpp_runtime.so|s210-udp-client|s210-echo', (out/'final-processes.txt').read_text()), 'device process residue'
            assert int(result['generations'][0]) > int(props(out/'before.properties')['generation']), 'fresh device generation'
            stage = props(build_file.parent/'stage/product-stage.properties')
            helpers = {'s210-udp-client':ROOT/'build-output/s210-capacity/udp-client',
                       's210-policy':ROOT/'build-output/s210-capacity/policy-client',
                       's210-echo':ROOT/'build-output/s207-owner/echo'}
            assert result['helper_sha256'] == {n:digest(p) for n,p in helpers.items()}, 'endpoint/control helper hashes'
        else:
            artifact = Path(build['artifact'])
            assert build['host_evidence'] is False
            for name, expected in build['artifact_hashes'].items(): assert digest(artifact/name) == expected, 'artifact '+name
            for name, expected in build['control_hashes'].items(): assert digest(build_file.parent/name) == expected, 'control '+name
            for name, expected in build['build_inputs'].items():
                assert digest(build_file.parent/'source'/name) == expected == digest(ROOT/name), 'build input '+name
            assert digest(artifact/'product-vpp-artifact.properties') == result['artifact_manifest_sha256']
            assert 'SAKAMOTO_PRODUCT_HOST_EVIDENCE:BOOL=OFF' in (artifact/'plugin-build/CMakeCache.txt').read_text()
            uid_map = (out/'uid-map.txt').read_text().split()
            assert uid_map[0] == '0' and uid_map[1] != '0' and uid_map[2] == '1', 'isolated real endpoint namespace'
        assert {(c['family'],c['owner']) for c in result['cases']} == {(f,w) for f in (4,6) for w in (0,1)}
        assert len({str(c['generation']) for c in result['cases']}) == len(result['cases']) == 4, 'fresh W2 dual-stack cases'
        for index, case in enumerate(result['cases']):
            label = f'g{index}'
            def path(name): return out/(label+'-'+name) if pixel else out/label/name
            def read(name): return path(name).read_text()
            assert json.loads(read('case.json')) == case, 'case/result binding '+label
            if pixel:
                endpoint = [l.split('nonce=',1)[1] for l in read('endpoint.log').splitlines() if 'nonce=' in l]
                running = props(out/(label+'.properties'))
                assert running['generation'] == str(case['generation']) and running['artifact'] == stage['artifactId'] and running['version'] == stage['vppRevision']
            else:
                endpoint = json.loads(read('endpoint.json'))
            summaries.append(oracle.verify_case(case, read('vpp.log'), read('runtime.txt'), endpoint))
            initial = rows(read('initial.txt'), 'root.lane ')
            assert len(initial) == 4 and len({d['fd'] for d in initial}) == 4 and all(d['ready'] == '1' for d in initial), 'independent live native lanes'
            assert rows(read('initial.txt'), 'capacity.status ')[0] == dict(credits='32',primary_slots='64',completion_slots='128'), 'restart default capacities'
            assert 'root.stop=ok' in read('close.txt'), 'native Root stop'
            closed = read('closed.txt')
            assert all(d['fd'] == '-1' and d['ready'] == d['pending'] == '0' for d in rows(closed,'root.lane ')), 'native lanes closed'
            completion = rows(closed,'completion.status ')[0]
            assert all(completion[k] == '0' for k in ('pending','frames','buffers','obligations','duplicate','stale')), 'native completion residue'
            primary = rows(closed,'primary.status ')[0]
            assert primary['pending_returns'] == primary['handoff_debt'] == primary['flows'] == '0' and primary['credit0'] == primary['credit1'] == '32', 'handoff/credit/flow residue'
            assert all(d['entries'] == '0' for d in rows(closed,'flow.pool ')), 'flow pools flushed'
            snapshot = rows(closed,'policy.snapshot ')[0]
            assert snapshot['readers0'] == snapshot['readers1'] == snapshot['packet_lock_acquisitions'] == '0'
            before, after = read('fds-before.txt'), read('fds-closed.txt')
            for lane in initial:
                line = next(l for l in before.splitlines() if (' '+lane['fd']+' -> ' in l if pixel else l.startswith(lane['fd']+' ')))
                inode = re.search(r'socket:\[\d+\]',line)
                assert inode and inode[0] not in after, 'actual NFQUEUE fd inode survived native stop'
            if pixel:
                assert props(path('stopped.properties'))['state'] == 'stopped'
                assert 'productRootNfqueueResidueClean=true' in read('cleanup.properties')
                assert not read('nfqueue-after.txt').strip(), 'kernel queues remained'
                assert 'libvpp_runtime.so' not in read('process-after.txt'), 'native process remained'
                assert 'SAKAMOTO' not in read('hooks-after.txt'), 'Product hooks remained'
            else:
                assert all(v == 0 for v in json.loads(read('queues-free.json')).values()), 'kernel queue rebind failed'
                assert json.loads(read('stop.json'))['process_absent'] is True
                assert not any(l.startswith('-A ') for l in read('hooks-after.txt').splitlines()), 'namespace hooks remained'
    except (AssertionError, OSError, KeyError, ValueError, IndexError, StopIteration) as error:
        errors.append(str(error) or repr(error))
    return dict(status='HOLD' if errors else 'PASS', errors=errors, source_sha256=build.get('source_sha256'),
                cases=summaries, packets=sum(c['packets'] for c in summaries),
                verifier_sha256=digest(__file__), semantic_verifier_sha256=digest(ROOT/'tests/device/s210-capacity-verify.py'),
                owner_oracle_sha256=digest(ROOT/'tests/device/s207-owner-oracle.py'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--platform', choices=['linux','pixel'], required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = verify(args.run, args.build, args.platform)
    output = json.dumps(result, indent=2)+'\n'
    if args.output: args.output.write_text(output)
    print(output)
    raise SystemExit(result['status'] != 'PASS')
