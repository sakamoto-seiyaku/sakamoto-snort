#!/usr/bin/env python3
"""Independent real-history migration, final APK and process-replacement oracle."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import zipfile

ROOT = Path(__file__).resolve().parents[2]
digest = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify(directory, overrides=None):
    directory = Path(directory)
    overrides = overrides or {}
    raw = lambda name: overrides.get(name, (directory/name).read_bytes())
    data = lambda name: json.loads(raw(name))
    props = lambda name: dict(line.split('=', 1) for line in raw(name).decode().splitlines()
                             if '=' in line and not line.startswith('#'))
    try:
        result = data('result.json')
        assert result['status'] == 'RAW_COMPLETE' and not result['cleanup_errors']
        for name, wanted in result['files'].items():
            assert hashlib.sha256(raw(name)).hexdigest() == wanted, 'evidence seal '+name
        build_path = Path(result['build'])
        build = json.loads(build_path.read_text())
        assert digest(build_path) == result['build_sha256']
        assert build['completed_ns'] < result['started_ns'] < result['completed_ns']
        spec = importlib.util.spec_from_file_location('chain', ROOT/'tests/evidence/product_chain.py')
        chain = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(chain)
        assert chain.source_files() == build['files'], 'final Product source identity'
        assert hashlib.sha256(chain.encode(build['files'])).hexdigest() == result['source_sha256'] == build['source_sha256']
        for name, wanted in build['files'].items():
            if wanted:
                assert digest(build_path.parent/'source'/name) == wanted
        assert digest(build_path.parent/'dirty.diff') == build['dirty_diff_sha256']
        assert 'e01_startup_config' not in (build_path.parent/'source/src/product/vpp/product_observation.c').read_text()
        assert 'struct E01Metrics' not in (build_path.parent/'source/crates/product-core/src/observation_service.rs').read_text()
        assert digest(build['apk']) == build['apk_sha256'] == result['apk_sha256']
        assert raw('installed-apk.txt').decode().split()[0] == build['apk_sha256']
        installed = {Path(line.split()[1]).name: line.split()[0]
                     for line in raw('installed-native.txt').decode().splitlines()}
        assert installed == build['native_sha256'] == result['native_sha256']
        with zipfile.ZipFile(build['apk']) as apk:
            assert {Path(name).name: hashlib.sha256(apk.read(name)).hexdigest()
                    for name in apk.namelist() if name.startswith('lib/arm64-v8a/') and name.endswith('.so')} == installed
        origin = json.loads((ROOT/'build-output/e01-20260926/device-restoration/result.json').read_text())
        assert digest(result['baseline']) == result['baseline_sha256'] == origin['history_sha256']
        original = raw('original.json')
        assert hashlib.sha256(original).hexdigest() == origin['history_sha256']
        assert original == raw('final-original.json') and result['history_preserved'], 'original bytes retained'
        old = json.loads(original)
        assert old['totals'] == origin['history_totals'], 'historical source totals'
        assert raw('sqlite-before.txt').strip() == b'absent'
        assert len(result['lifetimes']) == 2 and len({row['app_pid'] for row in result['lifetimes']}) == 2
        assert len({row['generation'] for row in result['lifetimes']}) == 2
        previous = old
        for index, life in enumerate(result['lifetimes']):
            label = 'life-'+str(index)
            running = props(label+'-running.properties')
            assert running['profile'] == 'vpn' and running['protectionRunning'] == 'false'
            assert int(running['generation']) == life['generation'] and life['process_absent']
            stopped = props(label+'-stopped.properties')
            assert stopped['state'] == 'stopped' and stopped['mayBeActive'] == 'false'
            query = data(label+'-query.json')
            persistent = query['consumer']['persistent']
            assert query['health']['generation'] == life['generation'] and query['consumer']['store_error'] is None
            assert query['consumer']['overview']['packets'] == [0, 0]
            assert persistent['storage'] == 'sqlite' and persistent['visibility'] == 'live_including_pending'
            for field in ('packets', 'bytes'):
                assert persistent[field] == persistent['persistence'][field] == old['totals'][field], 'migration API total'
            assert not persistent['persistence']['pending'] and not persistent['persistence']['maintenance_pending']
            database = directory/(label+'.sqlite3')
            assert digest(database) == life['database_sha256']
            with sqlite3.connect(database.resolve().as_uri()+'?mode=ro&immutable=1', uri=True) as db:
                assert db.execute('PRAGMA integrity_check').fetchone() == ('ok',)
                state = {'baselines': {}, 'recent': {}, 'minutes': {}}
                for kind, key, value in db.execute('SELECT kind,key,value FROM observation'):
                    if kind == 0:
                        assert key == ''
                        state.update(json.loads(value))
                    else:
                        state[{1: 'baselines', 2: 'recent', 3: 'minutes'}[kind]][key] = json.loads(value)
            assert state == data(label+'-store.json'), 'raw database identity'
            for field in ('baselines', 'recent', 'minutes', 'totals', 'ended', 'accepted', 'rejected',
                          'clock_changes', 'first_activity_us', 'last_activity_us'):
                assert state[field] == old[field], 'retained historical '+field
            assert state['gaps'] == life['gaps'] >= previous['gaps']+1 and not state['open_session']
            assert state['recoveries'] == life['recoveries'] == previous['recoveries']+int(previous['open_session'])
            assert persistent['coverage']['gaps'] == previous['gaps']+int(previous['open_session']), 'SQLite, not repeated JSON import'
            previous = state
        final = props('final-state.properties')
        assert final['state'] == 'stopped' and final['mayBeActive'] == 'false'
        assert b'libvpp_runtime.so' not in raw('final-processes.txt') and b'tcpdump' not in raw('final-processes.txt')
        assert not raw('final-queues.txt').strip()
        assert b'NFQUEUE' not in raw('final-rules.txt')+raw('final-rules6.txt')
        assert all(address.get('local') != '10.111.0.2' for interface in data('final-addresses.json')
                   for address in interface.get('addr_info', [])), 'owned TUN released'
        return dict(status='VALID_EVIDENCE', packets=old['totals']['packets'], bytes=old['totals']['bytes'],
                    generations=[row['generation'] for row in result['lifetimes']],
                    original_sha256=origin['history_sha256'], errors=[])
    except (AssertionError, OSError, KeyError, ValueError, TypeError, sqlite3.Error) as error:
        return dict(status='INVALID_EVIDENCE', errors=[str(error)])


def mutations(directory):
    directory = Path(directory)
    original = json.loads((directory/'result.json').read_text())
    cases = []

    def check(label, name, edit):
        value = json.loads((directory/name).read_text())
        edit(value)
        raw = json.dumps(value).encode()
        result = copy.deepcopy(original)
        result['files'][name] = hashlib.sha256(raw).hexdigest()
        overrides = {name: raw, 'result.json': json.dumps(result).encode()}
        if name == 'result.json':
            overrides = {name: raw}
        answer = verify(directory, overrides)
        assert answer['status'] == 'INVALID_EVIDENCE', 'mutation escaped '+label
        cases.append(dict(mutation=label, rejected=True, reason=answer['errors']))

    check('false live total', 'life-0-query.json', lambda v: v['consumer']['persistent']['packets'].__setitem__(0, 319))
    check('false durable total', 'life-1-query.json', lambda v: v['consumer']['persistent']['persistence']['bytes'].__setitem__(0, 0))
    check('dropped baseline', 'life-0-store.json', lambda v: v['baselines'].pop(next(iter(v['baselines']))))
    check('duplicate import gap reset', 'life-1-query.json', lambda v: v['consumer']['persistent']['coverage'].__setitem__('gaps', 0))
    check('wrong runtime generation', 'life-0-query.json', lambda v: v['health'].__setitem__('generation', 0))
    check('same process claimed replaced', 'result.json', lambda v: v['lifetimes'][1].__setitem__('app_pid', v['lifetimes'][0]['app_pid']))
    check('wrong final APK', 'result.json', lambda v: v.__setitem__('apk_sha256', '0'*64))
    return cases


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mutations', action='store_true')
    args = parser.parse_args()
    result = verify(args.directory)
    result['verifier_sha256'] = digest(__file__)
    if args.mutations and result['status'] == 'VALID_EVIDENCE':
        result['mutations'] = mutations(args.directory)
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
    raise SystemExit(result['status'] != 'VALID_EVIDENCE')
