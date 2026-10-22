#!/usr/bin/env python3
"""S311 normal VPN original-resolver UDP53 wire and caller qualification.

Uses a sealed pretest backup. The independent controlled resolver and read-only
underlay witness retain raw payloads. Device restoration is a separate receipt.
"""
import argparse
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import shlex
import subprocess
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
PKG = 'com.sakamoto.snort.androidruntime'
SERIAL = '28201JEGR0XPAJ'
BASE = '/data/user/0/' + PKG + '/files/profiles/vpn/vpp/'
shared_spec = importlib.util.spec_from_file_location('s310_shared', ROOT / 'tests/device/s310-root-dns.py')
shared = importlib.util.module_from_spec(shared_spec)
shared_spec.loader.exec_module(shared)
digest, props, query, Resolver = shared.digest, shared.props, shared.query, shared.Resolver

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--stage', type=Path, required=True)
    parser.add_argument('--backup', type=Path, required=True)
    parser.add_argument('--endpoint4', required=True)
    parser.add_argument('--endpoint6', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--owners', default='1,3', choices=('1', '3', '1,3'))
    parser.add_argument('--public4', default='1.1.1.1')
    parser.add_argument('--public6', default='2606:4700:4700::1111')
    parser.add_argument('--stop-only', action='store_true')
    parser.add_argument('--installed', action='store_true')
    args = parser.parse_args()
    args.apk = args.apk.resolve()
    args.stage = args.stage.resolve()
    args.backup = args.backup.resolve()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'runner.py').write_bytes(Path(__file__).read_bytes())
    manifest = json.loads((args.backup / 'manifest.json').read_text())
    assert manifest['state'] == 'stopped' and manifest['serial'] == SERIAL
    result = dict(status='HOLD', task='SAKAMOTO-311', serial=SERIAL,
                  source='normal RuntimeService VPN TUN/HEV + real Java App UDP socket',
                  apk_sha256=digest(args.apk), runner_sha256=digest(__file__),
                  backup_manifest_sha256=digest(args.backup / 'manifest.json'),
                  runs=[], cases=[], started_ns=time.time_ns())

    def save(name, value):
        (args.output / name).write_text(value)
        return value

    def adb(*command, check=True):
        started = time.time_ns()
        p = subprocess.run([str(ROOT / 'dev/adb'), '-s', SERIAL, *map(str, command)],
                           capture_output=True, text=True, errors='replace', timeout=60)
        with (args.output / 'operations.jsonl').open('a') as log:
            log.write(json.dumps(dict(started_ns=started, completed_ns=time.time_ns(),
                                     argv=list(map(str, command)), code=p.returncode)) + '\n')
        value = (p.stdout + p.stderr).replace('\r', '')
        if p.returncode and check:
            raise RuntimeError(value)
        return value

    def app(path):
        return adb('shell', 'run-as', PKG, 'cat', path, check=False)

    def source_file(label):
        path = 'files/rule-configuration/rules.conf'
        process = subprocess.run([str(ROOT / 'dev/adb'), '-s', SERIAL, 'exec-out',
                                  'run-as', PKG, 'cat', path], capture_output=True, timeout=30)
        assert process.returncode == 0, process.stderr.decode(errors='replace')
        destination = args.output / (label + '-source.conf')
        destination.write_bytes(process.stdout)
        device_hash = save(label + '-source-sha256.txt',
                           adb('shell', 'run-as', PKG, 'sha256sum', path)).split()[0]
        assert digest(destination) == device_hash

    def action(*extras):
        return adb('shell', 'am', 'start', '-n', PKG + '/.DebugControlActivity', *extras)

    def root(command):
        return adb('shell', 'su', '-c', shlex.quote(command))

    spec = importlib.util.spec_from_file_location('s233_target', ROOT / 'tests/device/s233-fail-open.py')
    transport = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transport)
    transport.SERIAL = SERIAL
    target = object.__new__(transport.Target)
    target.pixel = True

    def cli(label, *commands):
        return save(label + '.txt', target.cli(BASE + 'runtime', list(commands)))

    def wait(label, path, predicate, timeout=30, json_value=False):
        end = time.monotonic() + timeout
        value = {}
        while time.monotonic() < end:
            text = app(path)
            try:
                value = json.loads(text) if json_value else props(text)
            except json.JSONDecodeError:
                value = {}
            if predicate(value):
                save(label + ('.json' if json_value else '.properties'), text)
                return value
            if value.get('errorCode') == 'root_authorization_required':
                raise RuntimeError('Verify KernelSU Superuser grant for the installed APK')
            time.sleep(.15)
        raise RuntimeError(f'{label} deadline: {value}')

    def tap(label, text):
        for attempt in range(8):
            remote = '/sdcard/s311-ui.xml'
            adb('shell', 'uiautomator', 'dump', remote)
            xml = adb('shell', 'cat', remote)
            save(f'{label}-{attempt}.xml', xml)
            nodes = [n for n in ET.fromstring(xml).iter('node')
                     if n.get('text') == text and n.get('enabled') == 'true']
            if len(nodes) == 1:
                bounds = list(map(int, re.findall(r'\d+', nodes[0].get('bounds'))))
                adb('shell', 'input', 'tap', (bounds[0] + bounds[2]) // 2,
                    (bounds[1] + bounds[3]) // 2)
                return
            adb('shell', 'input', 'swipe', '550', '1700', '550', '600', '250')
        raise RuntimeError('UI action unavailable: ' + text)

    config_path = 'files/product-state/complete-rule-config.properties'

    def configure(label, variant='block', mode=0, subject_uid=None):
        old = props(app(config_path)).get('queryElapsedMillis')
        action()
        tap(label + '-baseline', 'Query all rules')
        wait(label + '-baseline', config_path,
             lambda c: c.get('queryElapsedMillis') not in (None, old))
        # Two competing domain candidates plus a normal App packet fallback.
        expression = '11001101010c3500350001'  # list0 AND list1 AND actual dport53
        if variant == 'business-port':
            expression = '11000cbb01bb0101'  # list0 AND actual dport443
        elif variant == 'sni-or':
            expression = '1001110002'  # explicit SNI absent OR list0; whole rule TLS/QUIC only
        elif variant in ('not', 'empty-not'):
            expression = '110003'  # NOT list0
        elif variant == 'or':
            expression = '1100110102'  # list0 OR list1
        elif variant == 'unknown-generic':
            expression = '1100051102'  # list0 OR actual UDP protocol
        subject = uid if subject_uid is None else subject_uid
        ranks = (20, 10) if variant == 'rank-allow' else (10, 20)
        lines = ['lists 2', 'domain 0 exact blocked.test', 'domain 1 descendants test',
                 f'0 0 4294967295 4294967295 4294967295 {ranks[0]} 0 17 0 2 * * 0 65535 0 65535 {expression}',
                 f'0 0 4294967295 4294967295 4294967295 {ranks[1]} 0 17 0 1 * * 0 65535 0 65535 1101',
                 f'0 0 4294967295 4294967295 4294967295 100 0 17 0 {2 if variant == "generic-drop" else 1} * * 0 65535 0 65535',
                 'group 10', 'edge 10 1 0', 'group 20', 'edge 20 1 1', 'group 30', 'edge 30 1 2',
                 f'bind 1 {subject} 2 10 {mode}', f'bind 2 {subject} 2 20 0', f'bind 3 {subject} 2 30 0']
        if variant == 'empty-not':
            lines = [line for line in lines if not line.startswith('domain ')]
        text = '\n'.join(lines)
        old = props(app(config_path)).get('queryElapsedMillis')
        save(label + '-request.txt', text + '\n')
        # Windows adb/cmd cannot carry literal newlines in shell argv. Let
        # the remote shell read the exact request into one quoted am extra.
        remote = '/data/local/tmp/s311-rules.txt'
        adb('push', args.output / (label + '-request.txt'), remote)
        command = 'am start -n ' + PKG + '/.DebugControlActivity --es completeRuleText "$(cat ' + remote + ')"'
        save(label + '-prefill.txt', adb('shell', 'sh', '-c', shlex.quote(command)))
        adb('shell', 'rm', remote)
        tap(label, 'Replace all rules')
        status = wait(label + '-applied', config_path,
                      lambda c: c.get('queryElapsedMillis') not in (None, old))
        assert status['result'] == '0' and status['savedRevision'] == status['activeRevision'], status
        source_file(label)
        return status

    def observation(label):
        nonce = 's311-observe-' + str(time.time_ns())
        save(label + '-query.txt', action('--es', 'observationNonce', nonce,
                                         '--ei', 'observationOperation', '0'))
        return wait(label + '-observation', 'files/product-state/observation-' + nonce + '.json',
                    lambda c: c.get('consumer', {}).get('query_fresh') is True,
                    timeout=15, json_value=True)

    number = 100

    def wire_rows(label):
        raw = save(label + '-underlay.jsonl', adb('shell', 'cat', '/data/local/tmp/s311-wire.jsonl'))
        return [json.loads(line) for line in raw.splitlines() if line.startswith('{')]

    def exchange(label, address, names, denied, status, source, expected_rules, *, public=False, truncate=0):
        nonlocal number
        # The first datagram on a fresh socket intentionally has no admitted
        # incarnation/UID result. Its decision stays Unknown forever. Later
        # messages use the same socket after ordinary broker progress.
        messages = [('blocked.test', 1), *names]
        wires = []
        for i, (name, qtype) in enumerate(messages):
            number += 1
            wire = query(number, name, qtype)
            if i and truncate:
                wire = wire[:truncate]
            wires.append(wire)
        nonce = 's311-' + label + '-' + str(time.time_ns())
        plan = dict(nonce=nonce, endpoint=address, port=53, source=source, bindDefault=True,
                    dnsQueries=[wire.hex() for wire in wires], dnsTimeoutMs=1000,
                    dnsQueryDelayMs=150)
        save(label + '-launch.txt', action('--es', 't12ProbePlan', shlex.quote(json.dumps(plan))))
        client = wait(label + '-client', 'files/product-state/t12-' + nonce + '.json',
                      lambda c: c.get('phase') == 'finished', timeout=35, json_value=True)
        assert not client.get('error'), client
        native = cli(label + '-native', 'show product dns', 'show product completion',
                     'show product tun', 'show product flow-stack')
        save(label + '-broker.log', adb('logcat', '-d', '-s', 'SakamotoSocketBroker:I', '*:S'))
        underlay = wire_rows(label)
        all_denied, all_rules = [False, *denied], [2, *expected_rules]
        records = []
        observed = observation(label)
        recent = observed['consumer']['persistent']['dns']['recent'].values()
        for i, wire in enumerate(wires):
            identifier = int.from_bytes(wire[:2], 'big') if len(wire) >= 4 else 0
            record, = [row['record'] for row in recent
                       if row['record']['generation'] == result['runs'][-1]['generation']
                       and row['record']['source_port'] == source and row['record']['id'] == identifier]
            records.append(record)
            assert record['caller'] == (0 if i == 0 else 1), (label, i, record)
            assert record['uid'] == (4294967295 if i == 0 else uid), (label, i, record)
            assert record['resolver_port'] == 53 and record['source_port'] == source
            raw_address = bytes(record['resolver_address'][:4 if record['family'] == 4 else 16])
            assert str(ipaddress.ip_address(raw_address)) == address
            assert record['policy_revision'] == int(status['activeRevision']) and record['delivery'] == 0
            assert record['actual_action'] == (2 if all_denied[i] else 1)
            # Cold Unknown cannot use the App-scoped fallback rule either.
            expected = 0 if i == 0 else int(status[f'rule.{all_rules[i]}.version'])
            assert record['winner'] == expected, (label, i, record, expected)
            assert record['coverage'] == (2 if i and truncate else 1)
            sent = [row for row in underlay if row.get('destination') == address
                    and row.get('destination_port') == 53 and row.get('payload_hex') == wire.hex()]
            exchange = client['dnsExchanges'][i]
            peer = [row for row in resolver.rows if row['request_hex'] == wire.hex()]
            if all_denied[i]:
                assert exchange.get('timedOut') is True and not sent and not peer, (label, i, exchange, sent, peer)
            else:
                if not (public and ':' in address):
                    assert sent, (label, i, 'original underlay query absent', underlay)
                returned = [row for row in underlay if row.get('source') == address
                            and row.get('source_port') == 53
                            and row.get('payload_hex') == exchange.get('replyHex')]
                if public and not returned:
                    # A real query may reach an unroutable public IPv6 view.
                    # Retain the transport result without claiming delivery.
                    assert exchange.get('timedOut') is True
                else:
                    assert returned and exchange.get('replyHex'), (label, i, exchange, returned)
                if not public:
                    assert len(peer) == 1 and peer[0]['resolver'] == [address, 53]
                    assert exchange['replyHex'] == peer[0]['reply_hex']
        assert 'dns.profile=original-udp enabled=1' in native
        assert 'codec_live_bytes=0 active_operations=0' in native
        result['cases'].append(dict(label=label, address=address, plan=plan,
                                    denied=all_denied, expected_rule_indices=[None, *expected_rules],
                                    revision=int(status['activeRevision']), dns_records=records,
                                    configuration=status, public=public,
                                    transport_complete=all(d or bool(c.get('replyHex')) for d, c
                                        in zip(all_denied, client['dnsExchanges']))))

    def system_socket_fixture(label, denied):
        status = configure(label, 'unknown-generic' if denied else 'block', subject_uid=2000)
        wires = [query(51001 if denied else 50001, 'blocked.test'),
                 query(51002 if denied else 50002, 'blocked.test')]
        source = 49702 if denied else 49701
        helper = '/data/local/tmp/s311-query'
        client = json.loads(save(label + '-client.json', adb('shell', helper,
                        args.endpoint4, str(source), *(wire.hex() for wire in wires))))
        assert client['uid'] == 2000
        observed = observation(label)
        recent = observed['consumer']['persistent']['dns']['recent'].values()
        records = []
        for i, wire in enumerate(wires):
            record, = [row['record'] for row in recent
                       if row['record']['generation'] == result['runs'][-1]['generation']
                       and row['record']['source_port'] == source
                       and row['record']['id'] == int.from_bytes(wire[:2], 'big')]
            records.append(record)
            assert record['caller'] == 0 and not record['domain_available']
            assert record['uid'] == (4294967295 if i == 0 else 2000)
            blocked = denied and i != 0
            assert record['actual_action'] == (2 if blocked else 1)
            assert record['winner'] == (int(status[f'rule.{0 if denied else 2}.version']) if i else 0)
            peer = [row for row in resolver.rows if row['request_hex'] == wire.hex()]
            if blocked:
                assert client['exchanges'][i]['timed_out'] and not peer
            else:
                assert len(peer) == 1 and client['exchanges'][i]['reply_hex'] == peer[0]['reply_hex']
        wire_rows(label)
        result['cases'].append(dict(label=label, source='known shell/system UID socket fixture; not resolver IPC',
                                    source_port=source, denied=[False, denied], dns_records=records,
                                    revision=int(status['activeRevision']), configuration=status))

    def real_system_resolver(label):
        status = configure(label)
        # This is Android's actual resolver API on the VPN's original network
        # DNS view, with cache lookup/storage disabled; no fixture UID is set.
        name = 'blocked.test'
        baseline = observation(label + '-before')
        prior = {(row['record']['generation'], row['record']['owner'], row['record']['token'])
                 for row in baseline['consumer']['persistent']['dns']['recent'].values()}
        nonce = 's311-system-' + str(time.time_ns())
        plan = dict(nonce=nonce, endpoint=args.endpoint4, port=53, source=49800,
                    bindDefault=True, systemDnsName=name)
        save(label + '-launch.txt', action('--es', 't12ProbePlan', shlex.quote(json.dumps(plan))))
        client = wait(label + '-client', 'files/product-state/t12-' + nonce + '.json',
                      lambda c: c.get('phase') == 'finished', timeout=20, json_value=True)
        observed = observation(label)
        records = [row['record'] for row in observed['consumer']['persistent']['dns']['recent'].values()
                   if row['record']['generation'] == result['runs'][-1]['generation']
                   and row['record']['name'] == name
                   and (row['record']['generation'], row['record']['owner'], row['record']['token']) not in prior]
        assert records, (label, client, observed)
        assert all(record['caller'] == 0 and not record['domain_available']
                   and record['actual_action'] == 1 for record in records), records
        result['cases'].append(dict(label=label, source='actual Android DnsResolver rawQuery; no cache lookup/store',
                                    plan=plan, dns_records=records, configuration=status,
                                    actual_result=client))

    def ordinary_cases(label, owners):
        status = configure(label + '-block')
        exchange(label + '-lan4', args.endpoint4,
                 [('allowed.test', 1), ('blocked.test', 1), ('allowed.test', 65000)],
                 [False, True, False], status, 49300 + owners, [1, 0, 1])
        exchange(label + '-lan6', args.endpoint6,
                 [('blocked.test', 28), ('allowed.test', 16)],
                 [True, False], status, 49400 + owners, [0, 1])
        if owners == 1:
            for variant, denied in [('rank-allow', False), ('business-port', False),
                                    ('sni-or', False), ('not', False)]:
                status = configure(variant, variant)
                exchange(variant, args.endpoint4, [('blocked.test', 65)], [denied], status,
                         49500 + len(result['cases']), [1])
            status = configure('observe', mode=1)
            exchange('observe', args.endpoint4, [('blocked.test', 33)], [False], status, 49600, [0])
            real_system_resolver('system-resolver')
        if owners == 3:
            for variant, name, denied, winner in [('or', 'allowed.test', True, 0),
                                                 ('not', 'allowed.test', True, 0),
                                                 ('empty-not', 'blocked.test', True, 0)]:
                status = configure('logical-' + variant, variant)
                exchange('logical-' + variant, args.endpoint4, [(name, 15)], [denied], status,
                         49620 + len(result['cases']), [winner])
            for variant, denied in [('block', False), ('generic-drop', True), ('unknown-generic', True)]:
                status = configure('malformed-' + variant, variant)
                exchange('malformed-' + variant, args.endpoint4, [('ignored', 1)], [denied], status,
                         49640 + len(result['cases']), [0 if variant == 'unknown-generic' else 2], truncate=11)
            system_socket_fixture('known-system-pass', False)
            system_socket_fixture('known-system-generic-drop', True)
            status = configure('public-block')
            exchange('public4', args.public4, [('blocked.test', 1), ('example.com', 1)],
                     [True, False], status, 49820, [0, 2], public=True)
            exchange('public6', args.public6, [('blocked.test', 28), ('example.com', 28)],
                     [True, False], status, 49821, [0, 2], public=True)

    resolver, active, wire_pid = None, False, None
    try:
        before = props(save('before-state.properties', app('files/runtime-state/snapshot.properties')))
        assert before['state'] == 'stopped' and before['mayBeActive'] == 'false'
        if not args.installed:
            save('install.txt', adb('install', '-r', args.apk))
        package = save('package.txt', adb('shell', 'dumpsys', 'package', PKG))
        code = re.search(r'codePath=(\S+)', package)[1]
        assert save('installed-apk.txt', adb('shell', 'sha256sum', code + '/base.apk')).split()[0] == result['apk_sha256']
        native = {path.name: digest(path) for path in (args.stage / 'lib/arm64-v8a').glob('*.so')}
        installed = save('installed-native.txt', adb('shell', 'sha256sum',
                          *(code + '/lib/arm64/' + name for name in sorted(native))))
        assert {Path(line.split()[1]).name: line.split()[0] for line in installed.splitlines()} == native
        result['native_sha256'] = native
        result['shared_runner_sha256'] = digest(ROOT / 'tests/device/s310-root-dns.py')
        uid = int(adb('shell', 'run-as', PKG, 'id', '-u'))
        result['uid'] = uid
        assert 'uid=0' in save('root-grant.txt', adb('shell', 'run-as', PKG, 'su', '-c', 'id'))
        save('network.txt', adb('shell', 'ip', 'address'))
        save('routes6.txt', adb('shell', 'ip', '-6', 'route', 'show', 'table', 'all'))
        save('wifi.txt', adb('shell', 'cmd', 'wifi', 'status'))
        compiler = '/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang'
        result['helpers'] = {}
        for stem, remote in [('s311_dns_wire', 's311-wire'), ('s311_dns_query', 's311-query')]:
            source = ROOT / 'tests/device/helpers' / (stem + '.c')
            binary = args.output / remote
            (args.output / source.name).write_bytes(source.read_bytes())
            subprocess.run([compiler, '-O2', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(binary)], check=True)
            adb('push', binary, '/data/local/tmp/' + remote)
            adb('shell', 'chmod', '755', '/data/local/tmp/' + remote)
            assert adb('shell', 'sha256sum', '/data/local/tmp/' + remote).split()[0] == digest(binary)
            result['helpers'][remote] = dict(source_sha256=digest(source), binary_sha256=digest(binary))
        adb('shell', 'rm', '-f', '/data/local/tmp/s311-wire.stop', '/data/local/tmp/s311-wire.jsonl')
        command = ('/data/local/tmp/s311-wire wlan0 /data/local/tmp/s311-wire.stop '
                   + ' '.join(map(shlex.quote, [args.endpoint4, args.endpoint6, args.public4, args.public6]))
                   + ' > /data/local/tmp/s311-wire.jsonl 2>&1 < /dev/null & echo $!')
        wire_pid = int(save('wire-start.txt', root(command)).strip())
        result['wire_pid'] = wire_pid
        for _ in range(20):
            if '"kind":"ready"' in adb('shell', 'cat', '/data/local/tmp/s311-wire.jsonl', check=False): break
            time.sleep(.1)
        else: raise RuntimeError('underlay witness did not start')
        resolver = Resolver([args.endpoint4, args.endpoint6], args.output)
        adb('shell', 'input', 'keyevent', '224')
        adb('shell', 'wm', 'dismiss-keyguard')
        for owners in map(int, args.owners.split(',')):
            label = f'n{owners}'
            active = True
            save(label + '-start.txt', action('--ez', 'runtimeStart', 'true', '--es', 'runtimeProfile', 'vpn',
                    '--es', 'runtimeWorkerCpuIds', '1' if owners == 1 else '1,2,1',
                    '--es', 'runtimeTunIoCpuId', '2' if owners == 1 else '3'))
            running = wait(label + '-running', 'files/runtime-state/snapshot.properties',
                           lambda c: c.get('state') == 'running' and c.get('protectionRunning') == 'true')
            result['runs'].append(dict(owners=owners, generation=int(running['generation'])))
            topology = cli(label + '-topology', 'show product topology', 'show product dns',
                           'show product tun', 'show product flow-stack', 'product metadata check')
            assert 'dns.profile=original-udp enabled=1' in topology
            assert 'metadata.udp_check roundtrip=1 bounds_guard=1 variants=3 ip_padding_excluded=5 buffer_return=1' in topology
            if args.stop_only:
                status = configure(label + '-block')
                exchange(label + '-stop-check', args.endpoint4,
                         [('blocked.test', 1), ('allowed.test', 1)], [True, False], status,
                         49900 + owners, [0, 1])
            else:
                ordinary_cases(label, owners)
            cli(label + '-final', 'show product dns', 'show product completion', 'show product tun',
                'show product flow-stack', 'show product primary')
            save(label + '-before-stop.log', app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
            # Normal stop removes the profile and does not refresh validation
            # archives. Keep an open read-only fd across unlink and bound its
            # lifetime; stale historical s237/s242 files are never witnesses.
            stop_path = args.output / (label + '-stop.log')
            with stop_path.open('wb') as log, (args.output / (label + '-stop-collector.stderr')).open('wb') as errors:
                collector = subprocess.Popen([str(ROOT / 'dev/adb'), '-s', SERIAL, 'exec-out',
                    'run-as', PKG, 'timeout', '20', 'tail', '-n', '+1', '-f',
                    'files/profiles/vpn/vpp/logs/vpp-stdout.log'], stdout=log, stderr=errors)
                for _ in range(30):
                    if stop_path.stat().st_size: break
                    time.sleep(.1)
                else: raise RuntimeError('normal stop log reader did not open the current profile')
                save(label + '-stop.txt', action('--ez', 'runtimeStop', 'true'))
                wait(label + '-stopped', 'files/runtime-state/snapshot.properties',
                     lambda c: c.get('state') == 'stopped' and c.get('mayBeActive') == 'false')
                active = False
                collector.wait(timeout=25)
                assert collector.returncode in (0, 124, 143), collector.returncode
            stop = stop_path.read_text()
            assert ('s213 event=stop generation=' + running['generation']
                    + ' pending=0 buffers=0 frames=0 obligations=0 tun_fd=-1') in stop
            result['runs'][-1]['stop_log_sha256'] = digest(stop_path)
            process = save(label + '-processes-after.txt', root('ps -A -o PID,UID,ARGS'))
            assert not any(len(parts := line.split()) >= 3 and Path(parts[2]).name == 'libvpp_runtime.so'
                           for line in process.splitlines())
            result['runs'][-1]['process_absent'] = True
        if not args.stop_only:
            assert all(case.get('transport_complete', True) for case in result['cases'] if case.get('address') == args.public4)
        result['limits'] = [case['label'] + ': original public IPv6 query did not complete on this underlay'
                            for case in result['cases'] if case.get('public') and not case['transport_complete']]
        result['status'] = 'PASS_WITH_EXPLICIT_LIMITS' if result['limits'] else 'PASS'
    except Exception as error:
        result['error'] = repr(error)
        raise
    finally:
        if active:
            save('failure-vpp.log', app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
            save('cleanup-stop.txt', action('--ez', 'runtimeStop', 'true'))
            try:
                wait('cleanup-stopped', 'files/runtime-state/snapshot.properties',
                     lambda c: c.get('state') == 'stopped' and c.get('mayBeActive') == 'false')
            except Exception as error:
                result['cleanup_error'] = repr(error)
        if resolver:
            resolver.close()
        if wire_pid:
            adb('shell', 'touch', '/data/local/tmp/s311-wire.stop')
            for _ in range(30):
                raw = adb('shell', 'cat', '/data/local/tmp/s311-wire.jsonl', check=False)
                if '"kind":"stopped"' in raw: break
                time.sleep(.2)
            save('underlay-final.jsonl', raw)
            result['wire_stopped'] = '"kind":"stopped"' in raw
            if not result['wire_stopped']:
                command = root('cat /proc/' + str(wire_pid) + '/cmdline 2>/dev/null || true')
                if command.startswith('/data/local/tmp/s311-wire\x00'):
                    root('kill -TERM ' + str(wire_pid))
                result['cleanup_error'] = 'underlay witness needed termination; inspect retained log'
        adb('shell', 'rm', '-f', '/data/local/tmp/s311-wire', '/data/local/tmp/s311-query',
            '/data/local/tmp/s311-wire.stop', '/data/local/tmp/s311-wire.jsonl', '/sdcard/s311-ui.xml')
        result['completed_ns'] = time.time_ns()
        save('result.json', json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(status=result['status'], output=str(args.output), cases=len(result['cases']))))


if __name__ == '__main__':
    main()

