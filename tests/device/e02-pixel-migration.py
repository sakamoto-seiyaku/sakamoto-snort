#!/usr/bin/env python3
"""Migrate the preserved real Pixel history using the unmodified Product APK."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
PKG = 'com.sakamoto.snort.androidruntime'
parser = argparse.ArgumentParser()
parser.add_argument('--serial-from', type=Path, required=True)
parser.add_argument('--build', type=Path, required=True)
parser.add_argument('--baseline-from', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
out = args.output.resolve()
out.mkdir(parents=True, exist_ok=False)
serial = json.loads(args.serial_from.read_text())['serial']
build = json.loads(args.build.read_text())
digest = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
result = dict(status='HOLD', serial=serial, started_ns=time.time_ns(),
              build=str(args.build.resolve()), build_sha256=digest(args.build),
              baseline=str(args.baseline_from.resolve()), baseline_sha256=digest(args.baseline_from),
              source_sha256=build['source_sha256'], lifetimes=[])
(out/'runner.py').write_bytes(Path(__file__).read_bytes())
helper = ROOT/'tests/evidence/e02_sqlite.py'
(out/helper.name).write_bytes(helper.read_bytes())
spec = importlib.util.spec_from_file_location('sqlite_evidence', helper)
sqlite_evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sqlite_evidence)


def save(name, value):
    (out/name).write_text(value if isinstance(value, str) else json.dumps(value, indent=2)+'\n')
    return value


def adb(*arguments, binary=False, check=True):
    started = time.time_ns()
    response = subprocess.run([str(ROOT/'dev/adb'), '-s', serial, *map(str, arguments)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
    with (out/'operations.jsonl').open('a') as log:
        log.write(json.dumps(dict(started_ns=started, completed_ns=time.time_ns(),
                                 argv=list(map(str, arguments)), exit_code=response.returncode))+'\n')
    if check and response.returncode:
        raise RuntimeError(response.stderr.decode()+response.stdout.decode(errors='replace'))
    return response.stdout if binary else response.stdout.decode().replace('\r', '')


def root(command, check=True):
    return adb('shell', 'su', '-c', shlex.quote(command), check=check)


def app(path):
    return adb('exec-out', 'run-as', PKG, 'cat', path, binary=True)


def properties(raw):
    return dict(line.split('=', 1) for line in raw.splitlines() if '=' in line and not line.startswith('#'))


def action(*arguments):
    return adb('shell', 'am', 'start', '-n', PKG+'/.DebugControlActivity', *arguments)


def state(label, wanted):
    deadline = time.monotonic()+45
    while time.monotonic() < deadline:
        raw = app('files/runtime-state/snapshot.properties').decode()
        value = properties(raw)
        if value.get('state') == wanted:
            save(label+'.properties', raw)
            return value
        assert value.get('errorCode') != 'root_authorization_required', 'restore KernelSU grant'
        time.sleep(.2)
    raise RuntimeError('runtime state deadline: '+str(value))


def query(label, generation):
    nonce = 'e02-migrate-'+str(time.time_ns())
    action('--es', 'observationNonce', nonce, '--ei', 'observationOperation', '0')
    deadline = time.monotonic()+20
    while time.monotonic() < deadline:
        raw = adb('shell', 'run-as', PKG, 'cat', 'files/product-state/observation-'+nonce+'.json', check=False)
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            time.sleep(.1)
            continue
        assert 'error' not in value and value['health']['generation'] == generation
        return save(label+'.json', value)
    raise RuntimeError('normal observation query deadline')


started = False
try:
    before = state('before', 'stopped')
    assert before['mayBeActive'] == 'false'
    original = app('files/observation/overall.json')
    (out/'original.json').write_bytes(original)
    assert original == args.baseline_from.read_bytes(), 'preserved real history changed before migration'
    old = json.loads(original)
    absence = adb('shell', 'run-as', PKG, 'sh', '-c', shlex.quote('test ! -e files/observation/overall.sqlite3 && echo absent'))
    assert save('sqlite-before.txt', absence).strip() == 'absent'
    assert digest(build['apk']) == build['apk_sha256']
    save('install.txt', adb('install', '-r', build['apk']))
    save('root-grant.txt', adb('shell', 'run-as', PKG, 'su', '-c', 'id'))
    assert 'uid=0' in (out/'root-grant.txt').read_text()
    package = save('package.txt', adb('shell', 'dumpsys', 'package', PKG))
    native = re.search(r'codePath=(\S+)', package)[1]+'/lib/arm64'
    installed = save('installed-native.txt', adb('shell', 'sha256sum',
                     *[native+'/'+name for name in sorted(build['native_sha256'])]))
    assert {Path(line.split()[1]).name: line.split()[0] for line in installed.splitlines()} == build['native_sha256']
    assert save('installed-apk.txt', adb('shell', 'sha256sum', native.removesuffix('/lib/arm64')+'/base.apk')).split()[0] == build['apk_sha256']
    result.update(apk_sha256=build['apk_sha256'], native_sha256=build['native_sha256'])
    previous = old
    previous_pid = None
    for index in range(2):
        label = 'life-'+str(index)
        started = True
        action('--ez', 'debugVpnHevValidation', 'true')
        running = state(label+'-running', 'running')
        generation = int(running['generation'])
        assert running['profile'] == 'vpn' and running['protectionRunning'] == 'false'
        pid = int(adb('shell', 'pidof', PKG+':runtime').strip())
        assert previous_pid is None or pid != previous_pid, 'actual service process replacement'
        value = query(label+'-query', generation)
        persistent = value['consumer']['persistent']
        assert value['consumer']['store_error'] is None
        assert value['consumer']['overview']['packets'] == [0, 0], 'no new test Flow traffic'
        assert persistent['storage'] == 'sqlite' and persistent['visibility'] == 'live_including_pending'
        assert persistent['packets'] == old['totals']['packets'] and persistent['bytes'] == old['totals']['bytes']
        assert persistent['persistence']['packets'] == persistent['packets']
        assert not persistent['persistence']['pending'] and not persistent['persistence']['maintenance_pending']
        assert persistent['coverage']['gaps'] == previous['gaps']+int(previous['open_session'])
        assert persistent['baselines'] == len(old['baselines']) and persistent['ended'] == old['ended']
        action('--ez', 'runtimeStop', 'true')
        stopped = state(label+'-stopped', 'stopped')
        assert stopped['mayBeActive'] == 'false'
        started = False
        wal = adb('shell', 'run-as', PKG, 'sh', '-c', shlex.quote('if [ -f files/observation/overall.sqlite3-wal ]; then stat -c %s files/observation/overall.sqlite3-wal; else echo 0; fi'))
        assert int(wal.strip()) == 0, 'closed Product store still has WAL work'
        database = out/(label+'.sqlite3')
        database.write_bytes(app('files/observation/overall.sqlite3'))
        stored = sqlite_evidence.closed_state(database)
        save(label+'-store.json', stored)
        for field in ('baselines', 'recent', 'minutes', 'totals', 'ended', 'accepted', 'rejected',
                      'clock_changes', 'first_activity_us', 'last_activity_us'):
            assert stored[field] == old[field], 'migration/restart changed '+field
        assert not stored['open_session'] and stored['gaps'] >= persistent['coverage']['gaps']+1
        assert stored['recoveries'] == previous['recoveries']+int(previous['open_session'])
        assert app('files/observation/overall.json') == original, 'migration predecessor bytes changed'
        save(label+'-force-stop.txt', adb('shell', 'am', 'force-stop', PKG))
        deadline = time.monotonic()+10
        while root('test ! -d /proc/'+str(pid)+' && echo absent', check=False).strip() != 'absent':
            assert time.monotonic() < deadline, 'service process exit deadline'
            time.sleep(.1)
        result['lifetimes'].append(dict(generation=generation, app_pid=pid, process_absent=True,
                                        database_sha256=digest(database), packets=stored['totals']['packets'],
                                        gaps=stored['gaps'], recoveries=stored['recoveries']))
        previous, previous_pid = stored, pid
    assert len({row['generation'] for row in result['lifetimes']}) == 2
    result['status'] = 'RAW_COMPLETE'
except Exception as error:
    result['error'] = repr(error)
    raise
finally:
    errors = []
    if started:
        try:
            action('--ez', 'runtimeStop', 'true')
            state('cleanup-stopped', 'stopped')
        except Exception as error:
            errors.append(repr(error))
    try:
        final = app('files/observation/overall.json')
        (out/'final-original.json').write_bytes(final)
        result['history_preserved'] = final == args.baseline_from.read_bytes()
        save('final-state.properties', app('files/runtime-state/snapshot.properties').decode())
        save('final-processes.txt', root('ps -A -o PID,UID,ARGS'))
        save('final-queues.txt', root('cat /proc/net/netfilter/nfnetlink_queue'))
        save('final-rules.txt', root('iptables-save'))
        save('final-rules6.txt', root('ip6tables-save'))
        save('final-addresses.json', root('ip -j address show'))
        save('final-observation-files.txt', adb('shell', 'run-as', PKG, 'ls', '-l', 'files/observation'))
    except Exception as error:
        errors.append(repr(error))
    result['cleanup_errors'] = errors
    if errors or not result.get('history_preserved'):
        result['status'] = 'HOLD'
    result['completed_ns'] = time.time_ns()
    result['files'] = {str(path.relative_to(out)): digest(path) for path in out.rglob('*') if path.is_file()}
    save('result.json', result)
print(json.dumps({'status': result['status'], 'lifetimes': result['lifetimes'], 'history_preserved': result['history_preserved']}))
