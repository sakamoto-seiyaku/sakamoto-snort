#!/usr/bin/env python3
"""Independent S303 Root N=1/N=3 fragment and completion evidence check."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def module(path):
    spec = importlib.util.spec_from_file_location('s303_fragment_oracle', ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def props(path):
    return dict(line.split('=', 1) for line in path.read_text().splitlines()
                if '=' in line and not line.startswith('#'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    parser.add_argument('--apk', type=Path, required=True)
    args = parser.parse_args()
    run = args.run.resolve()
    result = json.loads((run / 'result.json').read_text())
    assert result['status'] == 'RAW_COMPLETE' and result['fragment_only']
    assert result['runner_sha256'] == digest(ROOT / 'tests/device/s231-pixel-fragments.py')
    assert result['oracle_sha256'] == digest(ROOT / 'tests/device/s231-fragment-verify.py')
    assert result['cli_helper_sha256'] == digest(ROOT / 'tests/device/s233-fail-open.py')
    owner_cpus = list(map(int, result['worker_cpus'].split(',')))
    assert owner_cpus in ([1], [1, 2, 1])
    assert result['apk_sha256'] == digest(args.apk)
    assert result['apk_sha256'] == (run / 'installed-apk-sha256.txt').read_text().split()[0]
    with zipfile.ZipFile(args.apk) as archive:
        native = {Path(name).name: hashlib.sha256(archive.read(name)).hexdigest()
                  for name in archive.namelist()
                  if name.startswith('lib/arm64-v8a/') and name.endswith('.so')}
    installed = {Path(line.split()[1]).name: line.split()[0]
                 for line in (run / 'installed-native-sha256.txt').read_text().splitlines()}
    assert native == installed == result['native_sha256']
    assert result['wifi_before'] == result['wifi_after'] == '1'
    assert 's231tx' not in (run / 'links-after.txt').read_text()
    assert 's231rx' not in (run / 'links-after.txt').read_text()
    assert '198.18.231' not in (run / 'rules-after.txt').read_text()
    assert 'fd20:6231' not in (run / 'routes-after.txt').read_text()
    assert len(result['cases']) == 4
    assert {(case['family'], case['hook']) for case in result['cases']} == {
        (family, hook) for family in (4, 6) for hook in ('INPUT', 'OUTPUT')}
    assert len(set(result['generations'])) == 4
    oracle = module('tests/device/s231-fragment-verify.py')
    summaries = []
    for index, case in enumerate(result['cases']):
        label = f'g{index}'
        assert json.loads((run / (label + '-case.json')).read_text()) == case
        running = props(run / (label + '.properties'))
        assert running['generation'] == str(case['generation'])
        assert running['state'] == 'running' and running['profile'] == 'root'
        assert running['protectionRunning'] == 'true'
        initial = (run / (label + '-initial.txt')).read_text(errors='replace')
        threads = re.findall(r'^\d+\s+vpp_wk_\d+\s+workers\s+\d+', initial, re.M)
        assert len(threads) == len(owner_cpus), (label, threads)
        trace = (run / (label + '-vpp.log')).read_text()
        runtime = (run / (label + '-runtime.txt')).read_bytes().replace(b'\0', b'').decode(errors='replace')
        capture = (run / (label + '-capture.log')).read_text()
        wire = (run / (label + '-wire.pcap')).read_bytes()
        assert hashlib.sha256(wire).hexdigest() == \
            (run / (label + '-pcap-sha256.txt')).read_text().strip()
        sends = {fragment['nonce']: (run / (label + '-raw-'
                 + str(fragment['reverse']) + '.txt')).read_text()
                 for fragment in case['fragments']}
        endpoint = [line.split('nonce=', 1)[1] for line in
                    (run / (label + '-endpoint.log')).read_text().splitlines()
                    if 'nonce=' in line]
        summary = oracle.verify_case(case, trace, runtime, wire, capture, sends,
            endpoint, product_reassembly=True, owner_count=len(owner_cpus))
        summaries.append(summary)
        assert 'root.stop=ok' in (run / (label + '-close.txt')).read_text()
        stopped = props(run / (label + '-stopped.properties'))
        assert stopped['state'] == 'stopped' and stopped['mayBeActive'] == 'false'
        assert 'productRootNfqueueResidueClean=true' in \
            (run / (label + '-cleanup.properties')).read_text()
        assert not (run / (label + '-nfqueue-after.txt')).read_text().strip()
        assert 'SAKAMOTO' not in (run / (label + '-hooks-after.txt')).read_text()
    print(f"S303 Root N={len(owner_cpus)} IPv4/IPv6 INPUT/OUTPUT fragments, "
          f"{sum(row['packets'] for row in summaries)} NFQUEUE carriers, "
          "exactly-once completion and zero residue: PASS")


if __name__ == '__main__':
    main()
