#!/usr/bin/env python3
"""S310 real Java App UDP DNS under normal Root startup/configuration.

The controlled resolver records original UDP payloads independently. This is a
Root original-path slice, not VPN, TCP, response/CNAME or system IPC coverage.
Run with an already sealed pretest backup; restore that backup separately.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import socket
import struct
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
PKG = 'com.sakamoto.snort.androidruntime'
SERIAL = '28201JEGR0XPAJ'
BASE = '/data/user/0/' + PKG + '/files/profiles/root/vpp/'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def props(text):
    return dict(line.split('=', 1) for line in text.splitlines()
                if '=' in line and not line.startswith('#'))


def query(number, name, qtype=1):
    labels = b''.join(bytes([len(label)]) + label.encode('ascii') for label in name.split('.'))
    return struct.pack('!HHHHHH', number, 0x0100, 1, 0, 0, 0) + labels + b'\0' + struct.pack('!HH', qtype, 1)


class Resolver:
    def __init__(self, addresses, output):
        self.sockets, self.threads, self.rows = [], [], []
        self.lock, self.closed = threading.Lock(), False
        self.log = (output / 'resolver.jsonl').open('w')
        self.process = None
        try:
            for address in addresses:
                sock = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_DGRAM)
                self.sockets.append(sock)
                sock.settimeout(.2)
                sock.bind((address, 53))
        except PermissionError:
            for sock in self.sockets:
                sock.close()
            self.sockets = []
            self.windows(addresses, output)
        else:
            for sock in self.sockets:
                thread = threading.Thread(target=self.serve, args=(sock,), daemon=True)
                thread.start()
                self.threads.append(thread)

    def windows(self, addresses, output):
        # Windows permits a normal user to bind port53. Use the same WSL
        # bridge as dev/adb, without root or a host firewall/sysctl change.
        helper = ROOT / 'tests/device/helpers/s310_dns_resolver.ps1'
        self.stop_path = output / 'resolver.stop'
        winpath = lambda p: subprocess.check_output(['wslpath', '-w', str(p)], text=True).strip()
        quote = lambda s: "'" + s.replace("'", "''") + "'"
        command = '& ' + quote(winpath(helper)) + ' -Addresses @(' + ','.join(map(quote, addresses)) + ') -StopPath ' + quote(winpath(self.stop_path))
        encoded = base64.b64encode(command.encode('utf-16le')).decode('ascii')
        self.process = subprocess.Popen(['/init', '/mnt/c/Windows/System32/cmd.exe', '/C',
            'powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
            '-EncodedCommand', encoded], cwd='/mnt/c', stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, errors='replace')
        ready = threading.Event()

        def read():
            with (output / 'windows-resolver.log').open('w') as log:
                for line in self.process.stdout:
                    log.write(line)
                    log.flush()
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if row.get('kind') == 'ready':
                        ready.set()
                    elif row.get('kind') == 'exchange':
                        with self.lock:
                            self.rows.append(row)
                            self.log.write(json.dumps(row) + '\n')
                            self.log.flush()

        thread = threading.Thread(target=read, daemon=True)
        thread.start()
        self.threads.append(thread)
        if not ready.wait(10):
            self.close()
            raise RuntimeError('Windows controlled resolver did not bind; inspect windows-resolver.log')

    def serve(self, sock):
        while not self.closed:
            try:
                wire, peer = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            # A valid response retains the exact original ID/Question and all
            # opaque payload bytes. The Product must forward it unchanged.
            reply = wire[:2] + bytes([wire[2] | 0x80, wire[3]]) + wire[4:] if len(wire) >= 4 else wire
            row = dict(received_ns=time.time_ns(), peer=peer, resolver=sock.getsockname(),
                       request_hex=wire.hex(), reply_hex=reply.hex())
            with self.lock:
                self.rows.append(row)
                self.log.write(json.dumps(row) + '\n')
                self.log.flush()
            sock.sendto(reply, peer)

    def close(self):
        self.closed = True
        if self.process:
            self.stop_path.touch()
            self.process.wait(timeout=10)
        for sock in self.sockets:
            sock.close()
        for thread in self.threads:
            thread.join(timeout=1)
        self.log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--stage', type=Path, required=True)
    parser.add_argument('--backup', type=Path, required=True)
    parser.add_argument('--endpoint4', required=True)
    parser.add_argument('--endpoint6', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--owners', default='1,3', choices=('1', '3', '1,3'))
    parser.add_argument('--extended', action='store_true')
    args = parser.parse_args()
    args.apk = args.apk.resolve()
    args.stage = args.stage.resolve()
    args.backup = args.backup.resolve()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    manifest = json.loads((args.backup / 'manifest.json').read_text())
    assert manifest['state'] == 'stopped' and manifest['serial'] == SERIAL
    result = dict(status='HOLD', task='SAKAMOTO-310', serial=SERIAL,
                  source='normal RuntimeService Root NFQUEUE + real Java App UDP socket',
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
            remote = '/sdcard/s310-ui.xml'
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
        remote = '/data/local/tmp/s310-rules.txt'
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
        nonce = 's310-observe-' + str(time.time_ns())
        save(label + '-query.txt', action('--es', 'observationNonce', nonce,
                                         '--ei', 'observationOperation', '0'))
        return wait(label + '-observation', 'files/product-state/observation-' + nonce + '.json',
                    lambda c: c.get('consumer', {}).get('query_fresh') is True,
                    timeout=15, json_value=True)

    number = 100

    def exchange(label, address, names, denied, status, source, expected_rules=None, truncate=False):
        nonlocal number
        wires = []
        for name, qtype in names:
            number += 1
            wire = query(number, name, qtype)
            wires.append(wire[:11 if truncate is True else truncate] if truncate else wire)
        nonce = 's310-' + label + '-' + str(time.time_ns())
        plan = dict(nonce=nonce, endpoint=address, port=53, source=source, bindDefault=True,
                    dnsQueries=[wire.hex() for wire in wires], dnsTimeoutMs=700)
        save(label + '-launch.txt', action('--es', 't12ProbePlan', shlex.quote(json.dumps(plan))))
        reply = wait(label + '-client', 'files/product-state/t12-' + nonce + '.json',
                     lambda c: c.get('phase') == 'finished', timeout=20, json_value=True)
        assert not reply.get('error'), reply
        for i, wire in enumerate(wires):
            found = [row for row in resolver.rows if row['request_hex'] == wire.hex()]
            client = reply['dnsExchanges'][i]
            if denied[i]:
                assert client.get('timedOut') is True and not found, (label, i, client, found)
            else:
                assert len(found) == 1, (label, i, found)
                assert found[0]['resolver'][0] == address
                assert client['replyHex'] == found[0]['reply_hex']
                assert found[0]['peer'][1] == source
        value = observation(label)
        rows = value['consumer']['persistent']['dns']['recent'].values()
        ids = [int.from_bytes(wire[:2], 'big') if len(wire) >= 4 else 0 for wire in wires]
        records = [row['record'] for row in rows if row['record']['generation'] == result['runs'][-1]['generation']
                   and row['record']['source_port'] == source and row['record']['id'] in ids]
        assert len(records) == len(wires), (label, value)
        for record in records:
            assert record['caller'] == 1 and record['uid'] == uid and record['resolver_port'] == 53
            assert record['policy_revision'] == int(status['activeRevision']) and record['delivery'] == 0
            index = ids.index(record['id'])
            assert record['actual_action'] == (2 if denied[index] else 1)
            if expected_rules is not None:
                expected = expected_rules[index]
                assert record['winner'] == int(status[f'rule.{expected}.version']), (label, record)
                assert record['declared_action'] == int(status[f'rule.{expected}.action'])
            assert record['coverage'] == (2 if truncate else 1)
        cli(label + '-native', 'show product dns', 'show product completion')
        result['cases'].append(dict(label=label, address=address, plan=plan, denied=denied,
                                    revision=int(status['activeRevision']), dns_records=records))

    def unknown_fixture(label, denied):
        # Deliberate real NFQUEUE fixture for a known system socket UID. This
        # exact shell/peer/port capture rule is separate from normal startup's
        # debug-App-only OUTPUT capture; it does not model netd IPC recovery.
        status = configure(label, 'unknown-generic' if denied else 'block', subject_uid=2000)
        wire = query(50002 if denied else 50001, 'blocked.test')
        source = 49702 if denied else 49701
        local = args.output / (label + '-request.bin')
        local.write_bytes(wire)
        remote = '/data/local/tmp/s310-query.bin'
        adb('push', local, remote)
        rule = ('-d ' + args.endpoint4 + ' -p udp --dport 53 --sport ' + str(source)
                + ' -m owner --uid-owner 2000 -m comment --comment S310_UNKNOWN_FIXTURE'
                  ' -j NFQUEUE --queue-num 176 --queue-bypass')
        save(label + '-capture-before.txt', root('iptables-save -t mangle'))
        root('iptables -t mangle -I OUTPUT 1 ' + rule)
        try:
            command = f'cat {remote} | toybox nc -u -n -q 1 -W 2 -p {source} {args.endpoint4} 53'
            encoded = save(label + '-socket-base64.txt',
                           adb('shell', 'sh', '-c', shlex.quote(command + ' | toybox base64')))
            response = base64.b64decode(''.join(encoded.split()), validate=True)
            (args.output / (label + '-response.bin')).write_bytes(response)
            found = [row for row in resolver.rows if row['request_hex'] == wire.hex()]
            if denied:
                assert not response and not found
            else:
                assert len(found) == 1 and response.hex() == found[0]['reply_hex']
            value = observation(label)
            records = [row['record'] for row in value['consumer']['persistent']['dns']['recent'].values()
                       if row['record']['generation'] == result['runs'][-1]['generation']
                       and row['record']['id'] == int.from_bytes(wire[:2], 'big')]
            assert len(records) == 1, records
            record = records[0]
            assert record['uid'] == 2000 and record['availability'] & 1
            assert record['caller'] == 0 and not record['domain_available']
            assert record['actual_action'] == (2 if denied else 1)
            assert record['winner'] == int(status[f'rule.{0 if denied else 2}.version'])
            result['cases'].append(dict(label=label, source='known system-UID real NFQUEUE fixture; not netd IPC',
                                        capture_rule=rule, denied=denied, dns_records=records))
        finally:
            root('iptables -t mangle -D OUTPUT ' + rule)
            adb('shell', 'rm', '-f', remote)
            save(label + '-capture-after.txt', root('iptables-save -t mangle'))

    resolver = None
    active = False
    try:
        before = props(save('before-state.properties', app('files/runtime-state/snapshot.properties')))
        assert before['state'] == 'stopped' and before['mayBeActive'] == 'false'
        save('install.txt', adb('install', '-r', args.apk))
        package = save('package.txt', adb('shell', 'dumpsys', 'package', PKG))
        code = re.search(r'codePath=(\S+)', package)[1]
        assert save('installed-apk.txt', adb('shell', 'sha256sum', code + '/base.apk')).split()[0] == result['apk_sha256']
        native = {path.name: digest(path) for path in (args.stage / 'lib/arm64-v8a').glob('*.so')}
        installed = save('installed-native.txt', adb('shell', 'sha256sum',
                          *(code + '/lib/arm64/' + name for name in sorted(native))))
        assert {Path(line.split()[1]).name: line.split()[0] for line in installed.splitlines()} == native
        result['native_sha256'] = native
        uid = int(adb('shell', 'run-as', PKG, 'id', '-u'))
        result['uid'] = uid
        assert 'uid=0' in save('root-grant.txt', adb('shell', 'run-as', PKG, 'su', '-c', 'id'))
        save('network.txt', adb('shell', 'ip', 'address'))
        save('wifi.txt', adb('shell', 'cmd', 'wifi', 'status'))
        resolver = Resolver([args.endpoint4, args.endpoint6], args.output)
        adb('shell', 'input', 'keyevent', '224')
        adb('shell', 'wm', 'dismiss-keyguard')
        for owners in map(int, args.owners.split(',')):
            cpus = '1' if owners == 1 else '1,2,1'
            label = f'n{owners}'
            active = True
            save(label + '-start.txt', action('--ez', 'runtimeStart', 'true', '--es', 'runtimeProfile', 'root',
                                             '--es', 'runtimeWorkerCpuIds', cpus))
            running = wait(label + '-running', 'files/runtime-state/snapshot.properties',
                           lambda c: c.get('state') == 'running' and c.get('protectionRunning') == 'true')
            process = save(label + '-processes.txt', root('ps -A -o PID,UID,ARGS'))
            pids = [line.split()[0] for line in process.splitlines() if line.split() and
                    Path(line.split()[-1]).name == 'libvpp_runtime.so']
            # Full command lines include runtime arguments; use executable identity.
            pids = [line.split()[0] for line in process.splitlines() if len(line.split()) >= 3
                    and Path(line.split()[2]).name == 'libvpp_runtime.so']
            assert len(pids) == 1, process
            result['runs'].append(dict(owners=owners, generation=int(running['generation']), pid=int(pids[0])))
            cli(label + '-topology', 'show product topology', 'show product root lanes', 'show product dns')
            status = configure(label + '-block')
            exchange(label + '-v4-block', args.endpoint4,
                     [('allowed.test', 1), ('blocked.test', 1), ('allowed.test', 65000)],
                     [False, True, False], status, 49300 + owners, [1, 0, 1])
            exchange(label + '-v6-block', args.endpoint6,
                     [('blocked.test', 28), ('allowed.test', 16)], [True, False], status, 49400 + owners, [0, 1])
            if owners == 1:
                for variant, denied in [('rank-allow', False), ('business-port', False),
                                        ('sni-or', False), ('not', False)]:
                    status = configure(variant, variant)
                    exchange(variant, args.endpoint4, [('blocked.test', 65)], [denied], status,
                             49500 + len(result['cases']), [1])
                status = configure('observe', mode=1)
                exchange('observe', args.endpoint4, [('blocked.test', 33)], [False], status, 49600, [0])
            if args.extended and owners == 3:
                status = configure('logical-or', 'or')
                exchange('logical-or', args.endpoint4, [('blocked.test', 15), ('allowed.test', 33)],
                         [True, True], status, 49710, [0, 0])
                status = configure('logical-not', 'not')
                exchange('logical-not', args.endpoint4, [('allowed.test', 1)], [True], status, 49711, [0])
                status = configure('malformed-pass')
                exchange('malformed-pass', args.endpoint4, [('ignored', 1)], [False], status,
                         49712, [2], truncate=True)
                status = configure('malformed-generic-drop', 'generic-drop')
                exchange('malformed-generic-drop', args.endpoint4, [('ignored', 1)], [True], status,
                         49713, [2], truncate=True)
                status = configure('short-generic-or', 'unknown-generic')
                exchange('short-generic-or', args.endpoint4, [('ignored', 1)], [True], status,
                         49714, [0], truncate=3)
                status = configure('empty-list-not', 'empty-not')
                exchange('empty-list-not', args.endpoint4, [('blocked.test', 1)], [True], status,
                         49715, [0])
                unknown_fixture('unknown-caller-pass', False)
                unknown_fixture('unknown-independent-generic-drop', True)
            status_text = cli(label + '-final', 'show product dns', 'show product completion')
            assert 'codec_live_bytes=0 active_operations=0' in status_text, status_text
            save(label + '-before-stop.log', app('files/profiles/root/vpp/logs/vpp-stdout.log'))
            save(label + '-stop.txt', action('--ez', 'runtimeStop', 'true'))
            wait(label + '-stopped', 'files/runtime-state/snapshot.properties',
                 lambda c: c.get('state') == 'stopped' and c.get('mayBeActive') == 'false')
            active = False
            assert root('test ! -d /proc/' + pids[0] + ' && echo absent').strip() == 'absent'
            result['runs'][-1]['process_absent'] = True
            save(label + '-stop.log', app('files/product-state/s242-last-stop.log'))
            save(label + '-hooks-after.txt', root('iptables-save -t mangle; ip6tables-save -t mangle'))
            save(label + '-queues-after.txt', root('cat /proc/net/netfilter/nfnetlink_queue'))
        result['status'] = 'PASS'
    except Exception as error:
        result['error'] = repr(error)
        raise
    finally:
        if active:
            save('failure-vpp.log', app('files/profiles/root/vpp/logs/vpp-stdout.log'))
            save('cleanup-stop.txt', action('--ez', 'runtimeStop', 'true'))
            try:
                wait('cleanup-stopped', 'files/runtime-state/snapshot.properties',
                     lambda c: c.get('state') == 'stopped' and c.get('mayBeActive') == 'false')
            except Exception as error:
                result['cleanup_error'] = repr(error)
        if resolver:
            resolver.close()
        result['completed_ns'] = time.time_ns()
        save('result.json', json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(status=result['status'], output=str(args.output), cases=len(result['cases']))))


if __name__ == '__main__':
    main()
