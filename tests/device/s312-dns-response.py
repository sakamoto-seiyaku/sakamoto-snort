#!/usr/bin/env python3
"""S312 original UDP answers through normal Android Root/VPN adapters."""
import argparse
import base64
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import shlex
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
PKG = 'com.sakamoto.snort.androidruntime'
SERIAL = '28201JEGR0XPAJ'
FIXTURE_PATH = ROOT / 'tests/device/helpers/s312_dns_fixtures.py'
spec = importlib.util.spec_from_file_location('s312_fixture', FIXTURE_PATH)
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


class PreparedStopCaptureMismatch(RuntimeError): pass
class PreparedStopCaptureExpired(RuntimeError): pass


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def props(text):
    return dict(line.split('=', 1) for line in text.splitlines()
                if '=' in line and not line.startswith('#'))


def winpath(path, timeout=5):
    return subprocess.check_output(['wslpath', '-w', str(path)], text=True, timeout=timeout).strip()


class Peer:
    """Owned, bounded, independent Windows UDP53 wire peer; no Product codec."""
    def __init__(self, addresses, out, deadline=None):
        self.out, self.rows, self.messages, self.responses = out, [], [], {}
        self.deadline = deadline
        self.start_timeout(12)
        self.lock, self.ready = threading.Lock(), threading.Event()
        self.plan = out / 'peer-plan.json'
        self.stop_path = out / 'peer.stop'
        self.publish()
        helper = ROOT / 'tests/device/helpers/s312_dns_peer.ps1'
        quote = lambda value: "'" + value.replace("'", "''") + "'"
        command = ('& ' + quote(self.path(helper)) + ' -Addresses @('
                   + ','.join(map(quote, addresses)) + ') -StopPath '
                   + quote(self.path(self.stop_path)) + ' -PlanPath ' + quote(self.path(self.plan)))
        encoded = base64.b64encode(command.encode('utf-16le')).decode('ascii')
        self.start_timeout(12)
        self.process = subprocess.Popen(['/init', '/mnt/c/Windows/System32/cmd.exe', '/C',
            'powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
            '-EncodedCommand', encoded], cwd='/mnt/c', stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, errors='replace')
        self.thread = threading.Thread(target=self.read, daemon=True)
        self.thread.start()
        try:
            if not self.ready.wait(self.budget_timeout(12)):
                raise RuntimeError('independent CNAME peer did not bind; inspect peer.log')
        except BaseException as error:
            try:self.close()
            except BaseException as cleanup:error.add_note('peer constructor cleanup retained HOLD: '+repr(cleanup))
            raise

    def publish(self):
        temp = self.out / 'peer-plan.tmp'
        temp.write_text(json.dumps({'responses': list(self.responses.values())}))
        temp.replace(self.plan)

    def budget_timeout(self, maximum):
        deadline=getattr(self,'cleanup_deadline',None)
        if deadline is None:deadline=self.deadline
        if deadline is None:return maximum
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('peer lifecycle budget exhausted')
        return min(maximum,remaining)

    def start_timeout(self, maximum):
        timeout=self.budget_timeout(maximum)
        if timeout<1:raise TimeoutError('insufficient remaining peer budget to start an external client')
        return timeout

    def path(self, value):
        return winpath(value,timeout=self.start_timeout(5))

    def external(self, command, maximum=20, cwd='/mnt/c'):
        # The same recorder owns short-lived transports, including timeout
        # partials and an independent finite local reap after the caller expires.
        recorder=getattr(self,'local_recorder',None)
        if recorder is None:
            path=Path(__file__).resolve().parent/'helpers/s314_adb_trace.py'
            spec=importlib.util.spec_from_file_location('peer_local_trace',path)
            module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            recorder=self.local_recorder=module.AdbTrace(self.out,[])
        recorder.operation_deadline=getattr(self,'cleanup_deadline',None)
        if recorder.operation_deadline is None:recorder.operation_deadline=self.deadline
        stdout,stderr,code,_=recorder.execute(command,command,self.start_timeout(maximum),check=False,kind='owned-peer-transport',cwd=cwd)
        from types import SimpleNamespace
        return SimpleNamespace(stdout=stdout.decode(errors='replace'),stderr=stderr.decode(errors='replace'),returncode=code)

    def reap_launcher(self):
        # Local launcher ownership is independent of remote process identity.
        # Terminating this bridge never authorizes a signal to a remote PID.
        if self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill();self.process.wait(timeout=2)
        else:self.process.wait(timeout=2)
        self.thread.join(timeout=2)

    def begin_cleanup(self, seconds=45):
        if getattr(self,'cleanup_deadline',None) is None:
            self.cleanup_deadline=time.monotonic()+seconds

    def register(self, request, reply, gate=None):
        self.responses[request.hex()] = dict(request_hex=request.hex(), reply_hex=reply.hex(),
                                            gate=self.path(gate) if gate else '')
        self.publish()

    def read(self):
        with (self.out / 'peer.log').open('w') as log:
            for line in self.process.stdout:
                log.write(line); log.flush()
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if row.get('kind') == 'ready': self.ready.set()
                with self.lock:
                    self.messages.append(row)
                    if row.get('kind') == 'exchange': self.rows.append(row)

    def received(self, request):
        with self.lock:
            return any(r.get('kind') == 'received' and r.get('request_hex') == request.hex()
                       for r in self.messages)

    def close(self):
        self.begin_cleanup()
        self.stop_path.touch()
        try:
            self.process.wait(timeout=self.budget_timeout(15))
            self.thread.join(timeout=self.budget_timeout(2))
            assert self.process.returncode == 0, 'independent peer exited unsuccessfully'
            assert any(r.get('kind') == 'stopped' for r in self.messages), 'peer stop acknowledgement absent'
        except BaseException as error:
            try:self.reap_launcher()
            except BaseException as cleanup:error.add_note('local peer launcher reap failed: '+repr(cleanup))
            (self.out/'peer-close-hold.json').write_text(json.dumps(dict(status='HOLD',error=repr(error),
                local_pid=self.process.pid,local_returncode=self.process.returncode,
                reader_alive=self.thread.is_alive()),indent=2)+'\n')
            raise


class Device:
    def __init__(self, args):
        self.args, self.out = args, args.output
        self.profile = args.profile
        self.base = f'/data/user/0/{PKG}/files/profiles/{self.profile}/vpp/'
        self.active, self.witness_pid, self.reader = False, None, None
        spec = importlib.util.spec_from_file_location('s233_transport', ROOT / 'tests/device/s233-fail-open.py')
        transport = importlib.util.module_from_spec(spec); spec.loader.exec_module(transport)
        transport.SERIAL = SERIAL
        self.target = object.__new__(transport.Target); self.target.pixel = True

    def save(self, name, value):
        recorder = getattr(self, 'local_adb_recorder', None)
        if recorder is not None:
            recorder.save_capture(self.out / name, value.encode())
        else:
            (self.out / name).write_text(value)
        return value

    def adb(self, *command, check=True):
        started = time.time_ns()
        p = subprocess.run([str(ROOT / 'dev/adb'), '-s', SERIAL, *map(str, command)],
                           capture_output=True, text=True, errors='replace', timeout=60)
        with (self.out / 'operations.jsonl').open('a') as log:
            log.write(json.dumps(dict(started_ns=started, completed_ns=time.time_ns(),
                argv=list(map(str, command)), code=p.returncode)) + '\n')
        text = (p.stdout + p.stderr).replace('\r', '')
        if check and p.returncode: raise RuntimeError(text)
        return text

    def root(self, command):
        return self.adb('shell', 'su', '-c', shlex.quote(command))

    def app(self, path):
        return self.adb('shell', 'run-as', PKG, 'cat', path, check=False)

    def action(self, *extras):
        return self.adb('shell', 'am', 'start', '-n', PKG + '/.DebugControlActivity', *extras)

    def cli(self, label, *commands):
        return self.save(label + '.txt', self.target.cli(self.base + 'runtime', list(commands)))

    def wait(self, label, path, predicate, timeout=30, json_value=False):
        end = time.monotonic() + timeout
        previous=getattr(self,'capture_deadline',None)
        if previous is not None:self.capture_deadline=min(previous,end)
        value = {}
        try:
            while time.monotonic() < end:
                text = self.app(path)
                try: value = json.loads(text) if json_value else props(text)
                except json.JSONDecodeError: value = {}
                if predicate(value):
                    self.save(label + ('.json' if json_value else '.properties'), text)
                    return value
                if value.get('errorCode') == 'root_authorization_required':
                    raise RuntimeError('KernelSU Superuser grant requires verification/restoration')
                time.sleep(.1)
            raise RuntimeError(f'{label} deadline: {value}')
        finally:
            if previous is not None:self.capture_deadline=previous

    def tap(self, label, text, *, click=True):
        for attempt in range(8):
            self.adb('shell', 'uiautomator', 'dump', '/sdcard/s312-ui.xml')
            xml = self.adb('shell', 'cat', '/sdcard/s312-ui.xml')
            self.save(f'{label}-{attempt}.xml', xml)
            tree=ET.fromstring(xml)
            validate=getattr(self,'validate_tap_ui',None)
            if validate:validate(f'{label}-{attempt}',tree,text)
            nodes = [n for n in tree.iter('node')
                     if n.get('text') == text and n.get('enabled') == 'true']
            if len(nodes) == 1:
                bounds = list(map(int, re.findall(r'\d+', nodes[0].get('bounds'))))
                point = ((bounds[0] + bounds[2]) // 2, (bounds[1] + bounds[3]) // 2)
                if click: self.adb('shell', 'input', 'tap', *point)
                return point
            self.adb('shell', 'input', 'swipe', '550', '1700', '550', '600', '250')
        raise RuntimeError('normal UI action unavailable: ' + text)

    def install(self):
        before = props(self.save('before-state.properties', self.app('files/runtime-state/snapshot.properties')))
        assert before['state'] == 'stopped' and before['mayBeActive'] == 'false'
        if not self.args.installed: self.save('install.txt', self.adb('install', '-r', self.args.apk))
        package = self.save('package.txt', self.adb('shell', 'dumpsys', 'package', PKG))
        code = re.search(r'codePath=(\S+)', package)[1]
        assert self.save('installed-apk.txt', self.adb('shell', 'sha256sum', code + '/base.apk')).split()[0] == digest(self.args.apk)
        native = {path.name: digest(path) for path in (self.args.stage / 'lib/arm64-v8a').glob('*.so')}
        hashes = self.save('installed-native.txt', self.adb('shell', 'sha256sum',
                      *(code + '/lib/arm64/' + name for name in sorted(native))))
        assert {Path(line.split()[1]).name: line.split()[0] for line in hashes.splitlines()} == native
        self.uid = int(self.adb('shell', 'run-as', PKG, 'id', '-u'))
        assert 'uid=0' in self.save('root-grant.txt', self.adb('shell', 'run-as', PKG, 'su', '-c', 'id'))
        assert 'Wifi is connected to "Openwrt_5G"' in self.save('wifi.txt', self.adb('shell', 'cmd', 'wifi', 'status'))
        self.adb('shell', 'input', 'keyevent', '224'); self.adb('shell', 'wm', 'dismiss-keyguard')
        return native

    def start(self, owners):
        label = f'n{owners}'; self.active = True
        extras = ['--ez', 'runtimeStart', 'true', '--es', 'runtimeProfile', self.profile,
                  '--es', 'runtimeWorkerCpuIds', '1' if owners == 1 else '1,2,1']
        if self.profile == 'vpn': extras += ['--es', 'runtimeTunIoCpuId', '2' if owners == 1 else '3']
        self.save(label + '-start.txt', self.action(*extras))
        running = self.wait(label + '-running', 'files/runtime-state/snapshot.properties',
            lambda c: c.get('state') == 'running' and c.get('protectionRunning') == 'true')
        self.generation = int(running['generation'])
        topology = self.cli(label + '-topology', 'show product topology', 'show product dns',
                            'show product completion', 'product metadata check')
        assert 'dns.profile=original-udp enabled=1' in topology and 'response=1' in topology
        assert 'metadata.udp_check roundtrip=1 bounds_guard=1 variants=3 ip_padding_excluded=5 buffer_return=1' in topology
        return dict(owners=owners, generation=self.generation, profile=self.profile)

    def prepare_stop_capture(self, label):
        # Prepare this owned reader before a deadline-sensitive query. Product
        # Stop remains a later independent action; cleanup may consume it too.
        assert not getattr(self,'prepared_stop_capture',None) and not self.reader
        self.save(label+'-before-stop.log',self.app(f'files/profiles/{self.profile}/vpp/logs/vpp-stdout.log'))
        path=self.out/(label+'-stop.log');log=path.open('wb')
        try:errors=(self.out/(label+'-stop-reader.stderr')).open('wb')
        except BaseException:log.close();raise
        try:
            self.reader=subprocess.Popen([str(ROOT/'dev/adb'),'-s',SERIAL,'exec-out',
                'run-as',PKG,'timeout','20','tail','-n','+1','-f',
                f'files/profiles/{self.profile}/vpp/logs/vpp-stdout.log'],stdout=log,stderr=errors)
        except BaseException:log.close();errors.close();raise
        self.prepared_stop_capture=dict(label=label,path=path,log=log,errors=errors,reader=self.reader)

    def stop(self, label):
        if not getattr(self,'prepared_stop_capture',None):self.prepare_stop_capture(label)
        capture=self.prepared_stop_capture
        reader=self.validate_stop_capture(capture)
        self.prepared_stop_capture=None
        path=capture['path']
        with capture['log'] as log,capture['errors'] as errors:
            try:
                for _ in range(30):
                    if path.stat().st_size: break
                    time.sleep(.1)
                else: raise RuntimeError('bounded normal-stop reader did not open the current log')
                self.save(label + '-stop.txt', self.action('--ez', 'runtimeStop', 'true'))
                self.wait(label + '-stopped', 'files/runtime-state/snapshot.properties',
                    lambda c: c.get('state') == 'stopped' and c.get('mayBeActive') == 'false')
                self.active = False
                reader.wait(timeout=getattr(self,'budget_timeout',lambda value:value)(25))
                assert reader.returncode in (0, 124, 143)
            finally:
                settlement = dict(status='PASS', local_reader_started=reader is not None)
                if reader is not None:
                    try:
                        if reader.poll() is None:
                            reader.wait(timeout=getattr(self,'budget_timeout',lambda value:value)(20))
                            settlement['natural_tail_wait'] = True
                        settlement['returncode'] = reader.returncode
                    except BaseException as error:
                        settlement.update(status='HOLD', cleanup_error=repr(error), remote_completion='unknown')
                    if reader.poll() is not None and self.reader is reader:
                        self.reader = None
                self.save(label + '-stop-reader-settlement.json', json.dumps(settlement, indent=2)+'\n')
                if path!=self.out/(label+'-stop.log'):
                    self.save(label+'-stop.log',path.read_text())
        raw = path.read_text()
        for owner in range(self.owners):
            assert f'dns event=stop generation={self.generation} owner={owner} requests=0 codec_live_bytes=0 active_operations=0' in raw
        if self.profile == 'vpn':
            assert f's213 event=stop generation={self.generation} pending=0 buffers=0 frames=0 obligations=0 tun_fd=-1' in raw
        else:
            assert f's242 event=stop_native_zero generation={self.generation} ready_mask=0 graph_enabled=0 graph_accepting=0 pending=0 buffers=0 obligations=0 handoffs=0 completion_frames=0' in raw
            self.save(label + '-hooks-after.txt', self.root('iptables-save -t mangle; ip6tables-save -t mangle'))
            assert not self.save(label + '-queues-after.txt', self.root('cat /proc/net/netfilter/nfnetlink_queue')).strip()
        processes = self.save(label + '-processes-after.txt', self.root('ps -A -o PID,UID,ARGS'))
        assert not any(len(parts := line.split()) >= 3 and Path(parts[2]).name == 'libvpp_runtime.so'
                       for line in processes.splitlines())
        return dict(stop_log_sha256=digest(path), process_absent=True)

    def validate_stop_capture(self, capture):
        reader=capture.get('reader')
        if reader is None or reader is not self.reader:
            raise PreparedStopCaptureMismatch('prepared stop capture reader identity mismatch')
        if reader.poll() is not None:
            raise PreparedStopCaptureExpired('prepared stop capture reader exited before Stop')
        return reader

    def configure(self, label, variant='alias-drop', *, mode=0, subject=None, prefill_only=False):
        path = 'files/product-state/complete-rule-config.properties'
        old = props(self.app(path)).get('queryElapsedMillis')
        self.action(); self.tap(label + '-query', 'Query all rules')
        self.wait(label + '-baseline', path, lambda c: c.get('queryElapsedMillis') not in (None, old))
        bases = {'alias-drop':'1101', 'alias-allow':'1101', 'rank-qname':'1101',
                 'and':'1100110101', 'or':'1100110102', 'not':'110103',
                 'sni-or':'1001110102', 'business-port':'11010cbb01bb0101',
                 'generic-or':'1101051102', 'allow':'1102'}
        expression = bases[variant] + '060101'  # Entire rule AND actual INPUT.
        rank0, rank1 = (20, 10) if variant == 'rank-qname' else (10, 20)
        alias_allow = variant in ('alias-allow', 'rank-qname')
        action0, action1 = (1, 2) if alias_allow else (2, 1)
        second = '1100060101' if alias_allow else '1102060101'
        uid = self.uid if subject is None else subject
        lines = ['lists 3', 'domain 0 exact qname.test', 'domain 1 exact alias.test',
            f'0 0 4294967295 4294967295 4294967295 {rank0} 0 17 0 {action0} * * 0 65535 0 65535 {expression}',
            f'0 0 4294967295 4294967295 4294967295 {rank1} 0 17 0 {action1} * * 0 65535 0 65535 {second}',
            '0 0 4294967295 4294967295 4294967295 100 0 17 0 1 * * 0 65535 0 65535',
            'group 10', 'edge 10 1 0', 'group 20', 'edge 20 1 1', 'group 30', 'edge 30 1 2',
            f'bind 1 {uid} 2 10 {mode}', f'bind 2 {uid} 2 20 0', f'bind 3 {uid} 2 30 0']
        request = self.out / (label + '-request.txt'); request.write_text('\n'.join(lines) + '\n')
        remote = '/data/local/tmp/s312-rules.txt'; self.adb('push', request, remote)
        command = f'am start -n {PKG}/.DebugControlActivity --es completeRuleText "$(cat {remote})"'
        self.save(label + '-prefill.txt', self.adb('shell', 'sh', '-c', shlex.quote(command)))
        self.adb('shell', 'rm', remote)
        if prefill_only: return self.tap(label + '-point', 'Replace all rules', click=False)
        old = props(self.app(path)).get('queryElapsedMillis')
        self.tap(label + '-replace', 'Replace all rules')
        return self.applied(label, old)

    def applied(self, label, old, *, previous_revision=None):
        path = 'files/product-state/complete-rule-config.properties'
        status = self.wait(label + '-applied', path,
                           lambda c: c.get('queryElapsedMillis') not in (None, old)
                           and (previous_revision is None
                                or int(c.get('activeRevision', 0)) > previous_revision))
        assert status['result'] == '0' and status['savedRevision'] == status['activeRevision'], status
        remote = 'files/rule-configuration/rules.conf'
        raw = subprocess.check_output([str(ROOT / 'dev/adb'), '-s', SERIAL, 'exec-out', 'run-as', PKG, 'cat', remote])
        source = self.out / (label + '-source.conf'); source.write_bytes(raw)
        assert digest(source) == self.save(label + '-source-sha256.txt', self.adb('shell', 'run-as', PKG, 'sha256sum', remote)).split()[0]
        return status

    def observation(self, label):
        nonce = 's312-' + str(time.time_ns())
        self.save(label + '-observation-request.txt', self.action('--es', 'observationNonce', nonce,
                                                               '--ei', 'observationOperation', '0'))
        remote = 'files/product-state/observation-' + nonce + '.json'
        result = self.wait(label + '-observation', remote,
            lambda c: c.get('consumer', {}).get('query_fresh') is True, timeout=15, json_value=True)
        # wait() has already persisted the complete qualifying reply locally.
        # Retire this exact generated nonce only; never sweep older App data.
        self.adb('shell', 'run-as', PKG, 'rm', '--', remote)
        return result

    def launch(self, label, address, source, wires, *, timeout=1500, preserve_ui=False):
        assert 100 <= timeout <= 3000  # Existing ordinary App probe contract.
        nonce = 's312-' + label + '-' + str(time.time_ns())
        plan = dict(nonce=nonce, endpoint=address, port=53, source=source, bindDefault=True,
                    dnsQueries=[wire.hex() for wire in wires], dnsTimeoutMs=timeout, dnsQueryDelayMs=150)
        self.save(label + '-plan.json', json.dumps(plan, indent=2) + '\n')
        # A headless singleTop intent finishes the receiving Activity. Moving
        # it to the background first forces a fresh temporary task; restore the
        # pending interactive task after that headless instance finishes.
        if preserve_ui: self.adb('shell', 'input', 'keyevent', '3')
        flags = ['-f', '0x18000000'] if preserve_ui else []
        launch = self.save(label + '-launch.txt', self.action(*flags, '--es', 't12ProbePlan', shlex.quote(json.dumps(plan))))
        if preserve_ui:
            assert 'delivered to currently running' not in launch, launch
            self.save(label + '-return-ui.txt', self.action())
        return nonce

    def client(self, label, nonce):
        value = self.wait(label + '-client', 'files/product-state/t12-' + nonce + '.json',
                         lambda c: c.get('phase') == 'finished', timeout=35, json_value=True)
        assert not value.get('error'), value
        return value

    def wire(self, label):
        raw = self.save(label + '-underlay.jsonl', self.adb('shell', 'cat', '/data/local/tmp/s312-wire.jsonl'))
        return [json.loads(line) for line in raw.splitlines() if line.startswith('{')]

    def witness_start(self):
        compiler = '/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang'
        source = ROOT / 'tests/device/helpers/s312_dns_wire.c'
        binary = self.out / 's312-wire'
        subprocess.run([compiler, '-O2', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(binary)], check=True)
        self.adb('push', binary, '/data/local/tmp/s312-wire')
        self.adb('shell', 'chmod', '755', '/data/local/tmp/s312-wire')
        assert self.adb('shell', 'sha256sum', '/data/local/tmp/s312-wire').split()[0] == digest(binary)
        self.adb('shell', 'rm', '-f', '/data/local/tmp/s312-wire.stop', '/data/local/tmp/s312-wire.jsonl')
        command = ('/data/local/tmp/s312-wire wlan0 /data/local/tmp/s312-wire.stop '
                   + ' '.join(map(shlex.quote, [self.args.endpoint4, self.args.endpoint6,
                                               self.args.public4, self.args.public6]))
                   + ' > /data/local/tmp/s312-wire.jsonl 2>&1 < /dev/null & echo $!')
        self.witness_pid = int(self.save('wire-start.txt', self.root(command)).strip())
        for _ in range(25):
            if '"kind":"ready"' in self.adb('shell', 'cat', '/data/local/tmp/s312-wire.jsonl', check=False): return
            time.sleep(.1)
        raise RuntimeError('read-only underlay witness not ready')

    def witness_stop(self):
        if self.witness_pid:
            self.adb('shell', 'touch', '/data/local/tmp/s312-wire.stop')
            for _ in range(30):
                raw = self.adb('shell', 'cat', '/data/local/tmp/s312-wire.jsonl', check=False)
                if '"kind":"stopped"' in raw: break
                time.sleep(.2)
            self.save('underlay-final.jsonl', raw)
            assert '"kind":"stopped"' in raw, 'owned witness did not acknowledge stop'
            self.witness_pid = None
        self.adb('shell', 'rm', '-f', '/data/local/tmp/s312-wire', '/data/local/tmp/s312-wire.stop',
                 '/data/local/tmp/s312-wire.jsonl', '/data/local/tmp/s312-rules.txt', '/sdcard/s312-ui.xml')


def number(text, key):
    match = re.search(r'\b' + re.escape(key) + r'=(\d+)', text)
    assert match, (key, text)
    return int(match[1])


class Qualification:
    def __init__(self, device, peer, result):
        self.d, self.peer, self.result, self.identifier = device, peer, result, 20000

    def request(self, name, qtype=1, **options):
        self.identifier += 1
        return fixtures.question(self.identifier, name, qtype, **options)

    def exchange(self, label, address, status, *, variant='alias', denied=True,
                 winner=0, qtype=1, aliases=1, coverage=1, chain_status=0,
                 edns=False, public=False, hot=False):
        d = self.d
        source = (d.reserve_source_port(label) if hasattr(d, 'reserve_source_port') else
                  49000 + len(self.result['cases']) + (1000 if d.profile == 'vpn' else 0))
        warm_name = 'example.com' if public else ('qname.test' if d.profile == 'vpn' else 'allowed.test')
        names = [(warm_name, 1), ('example.com' if public else 'qname.test', qtype),
                 ('example.com' if public else 'allowed.test', 65000 if not public else 28)]
        wires = [self.request(name, kind, edns=edns and index == 1)
                 for index, (name, kind) in enumerate(names)]
        replies, actual_names, expected_coverage, expected_chain = [], [], [], []
        gate = d.out / (label + '.gate') if hot else None
        for index, wire in enumerate(wires):
            kind = variant if index == 1 or (index == 0 and d.profile == 'vpn'
                                             and not public and variant != 'short') else 'ordinary'
            reply, chain = fixtures.answer(wire, kind, aliases=aliases)
            if not public: self.peer.register(wire, reply, gate if index == 1 else None)
            replies.append(reply); actual_names.append(chain)
            expected_coverage.append(coverage if kind == variant else 1)
            expected_chain.append(chain_status if kind == variant else 0)
        native_before = d.cli(label + '-before', 'show product dns', 'show product batch', 'show product tun')
        old_status = status
        point = None
        if hot:
            point = d.configure(label + '-hot-prefill', 'alias-drop', prefill_only=True)
            old_stamp = props(d.app('files/product-state/complete-rule-config.properties')).get('queryElapsedMillis')
        nonce = d.launch(label, address, source, wires, timeout=3000 if hot else 1500,
                         preserve_ui=hot)
        if hot:
            deadline = time.monotonic() + 5
            while not self.peer.received(wires[1]):
                assert time.monotonic() < deadline, 'gated query did not reach independent peer'
                time.sleep(.01)
            d.save(label + '-hot-tap.txt', d.adb('shell', 'input', 'tap', *point))
            status = d.applied(label + '-hot', old_stamp,
                               previous_revision=int(old_status['activeRevision']))
            assert int(status['activeRevision']) > int(old_status['activeRevision'])
            gate.touch()
        client = d.client(label, nonce)
        native = d.cli(label + '-after', 'show product dns', 'show product batch',
                       'show product completion', 'show product tun', 'show product flow-stack')
        underlay = d.wire(label)
        observed = d.observation(label)
        recent = [row['record'] for row in observed['consumer']['persistent']['dns']['recent'].values()]
        checked = []
        for index, wire in enumerate(wires):
            identifier = int.from_bytes(wire[:2], 'big')
            query, = [r for r in recent if r['generation'] == d.generation and r['stage'] == 1
                       and r['source_port'] == source and r['id'] == identifier]
            response_id = 0 if variant == 'short' and index == 1 else identifier
            answers = sorted([r for r in recent if r['generation'] == d.generation and r['stage'] == 2
                              and r['source_port'] == source and r['id'] == response_id], key=lambda r:r['name_index'])
            # The denied hot answer uses the full 3s client deadline. The
            # existing UDP UID cache lives 2s, so its following control query
            # is cold again; keep that query's original Unknown on its reply.
            expected_caller = 0 if d.profile == 'vpn' and (index == 0 or (hot and index == 2)) else 1
            assert query['caller'] == expected_caller and query['coverage'] == 1
            # The hot query is admitted under the old snapshot; the control
            # query following its answer uses the new one.
            query_status = status if hot and index == 2 else old_status
            assert query['policy_revision'] == int(query_status['activeRevision'])
            assert query['actual_action'] == 1 and query['winner'] == (0 if not expected_caller else int(query_status['rule.2.version']))
            response_status = old_status if hot and index == 0 else status
            caller = expected_caller
            expected_drop = denied and index == 1
            expected_rule = winner if index == 1 else 2
            expected_cover = expected_coverage[index]
            expected_correl = 1
            if not public and expected_cover == 2 and (
                    (variant == 'malformed' and index in (1, 0 if d.profile == 'vpn' else -1))
                    or (variant == 'short' and index == 1)):
                expected_correl, caller = 2, 0
                actual_names[index] = ['']
            if expected_cover != 1:
                expected_drop, expected_rule = False, 2
            if not caller: expected_rule = 2
            assert answers, (label, index, 'normal response records absent', recent)
            assert all(r['correlation'] == expected_correl and r['caller'] == caller for r in answers), (label, index, answers)
            if expected_correl == 1:
                assert all(r['query_token'] == query['token'] and r['query_policy_revision'] == query['policy_revision']
                           and r['query_policy_hash'] == query['policy_hash'] and r['query_winner'] == query['winner']
                           and r['query_incarnation'] == query['incarnation'] for r in answers)
                if d.profile == 'vpn': assert all(r['transport_session'] and r['underlay_epoch'] for r in answers)
            else: assert all(r['query_token'] == 0 for r in answers)
            if not public:
                expected_names = actual_names[index][:33]
                assert [r['name'] for r in answers] == expected_names, (label, index, answers, expected_names)
                assert all(r['candidate_count'] == (0 if expected_names == [''] else len(expected_names)) for r in answers)
            for ordinal, record in enumerate(answers):
                assert record['name_source'] == (0 if ordinal == 0 else 1)
                assert record['coverage'] == expected_cover and record['chain_status'] == expected_chain[index]
                assert record['actual_action'] == (2 if expected_drop else 1), (label, index, record)
                if caller:
                    assert record['uid'] == d.uid
                    assert record['winner'] == int(response_status[f'rule.{expected_rule}.version']), (label, index, record, response_status)
                assert record['domain_available'] == (bool(caller) and expected_cover == 1)
                if not public:
                    expected_lists = {'qname.test':1,'alias.test':2}.get(record['name'],0)
                    assert record['domain_lists'] == (expected_lists if record['domain_available'] else 0)
                    if label.endswith('-observe') and index == 1:
                        assert record['mode'] == 1 and record['declared_action'] == 2
                assert record['policy_revision'] == int(response_status['activeRevision']) and record['delivery'] == 0
                assert record['resolver_port'] == 53 and record['source_port'] == source
                family = 4 if ':' not in address else 6
                assert str(ipaddress.ip_address(bytes(record['resolver_address'][:4 if family == 4 else 16]))) == address
            sent = [r for r in underlay if r.get('destination') == address and r.get('destination_port') == 53
                    and r.get('payload_hex') == wire.hex()]
            assert sent, (label, index, 'original query wire not observed')
            exchange = client['dnsExchanges'][index]
            assert exchange['sentHex'] == wire.hex()
            if public:
                reply_hex = exchange.get('replyHex')
                assert reply_hex, (label, index, 'public DNS transport did not return an answer', exchange)
            else:
                peer, = [r for r in self.peer.rows if r['request_hex'] == wire.hex()]
                reply_hex = peer['reply_hex']
                assert reply_hex == replies[index].hex() and peer['sent_bytes'] == len(replies[index])
                assert peer['resolver'] == [address, 53]
            assert all(r['rcode'] == (bytes.fromhex(reply_hex)[3] & 15) for r in answers if r['coverage'] == 1)
            returned = [r for r in underlay if r.get('source') == address and r.get('source_port') == 53
                        and r.get('payload_hex') == reply_hex]
            assert returned, (label, index, 'independent answer absent from actual underlay')
            if expected_drop:
                assert exchange.get('timedOut') is True and not exchange.get('replyHex'), exchange
            else:
                assert exchange.get('replyHex') == reply_hex, (label, index, exchange, reply_hex)
            checked.append(dict(query=query, responses=answers, denied=expected_drop, request_hex=wire.hex(), reply_hex=reply_hex))
        count_drop = sum(row['denied'] for row in checked)
        if d.profile == 'root':
            assert number(native, 'policy_qualified_matched_drop_succeeded') - number(native_before, 'policy_qualified_matched_drop_succeeded') >= count_drop
        else:
            assert number(native, 'policy_drops') - number(native_before, 'policy_drops') >= count_drop
            assert number(native, 'write_failed') == 0
        assert 'codec_live_bytes=0 active_operations=0' in native
        case = dict(label=label, profile=d.profile, generation=d.generation, address=address,
                    source_port=source, variant=variant, policy=old_status, response_policy=status,
                    records=checked, public=public, owner_count=d.owners)
        self.result['cases'].append(case)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ('apk', 'stage', 'backup', 'output'): parser.add_argument('--' + flag, type=Path, required=True)
    parser.add_argument('--profile', choices=('root','vpn'), required=True)
    parser.add_argument('--owners', default='1,3', choices=('1','3','1,3'))
    parser.add_argument('--case-set', default='full', choices=('full','hot-and-errors','errors-only'))
    parser.add_argument('--endpoint4', required=True); parser.add_argument('--endpoint6', required=True)
    parser.add_argument('--public4', default='1.1.1.1'); parser.add_argument('--public6', default='2606:4700:4700::1111')
    parser.add_argument('--installed', action='store_true')
    args = parser.parse_args()
    for key in ('apk','stage','backup','output'): setattr(args,key,getattr(args,key).resolve())
    args.output.mkdir(parents=True,exist_ok=False)
    for address in (args.endpoint4,args.endpoint6,args.public4,args.public6): ipaddress.ip_address(address)
    manifest = json.loads((args.backup/'manifest.json').read_text())
    assert manifest['state']=='stopped' and manifest['serial']==SERIAL
    result = dict(status='HOLD', task='SAKAMOTO-312', profile=args.profile, case_set=args.case_set, serial=SERIAL,
                  started_ns=time.time_ns(), apk_sha256=digest(args.apk), runner_sha256=digest(__file__),
                  fixture_sha256=digest(FIXTURE_PATH), backup_manifest_sha256=digest(args.backup/'manifest.json'),
                  cases=[],runs=[])
    (args.output/'runner.py').write_bytes(Path(__file__).read_bytes())
    for name in ('s312_dns_peer.ps1','s312_dns_fixtures.py','s312_dns_wire.c'):
        (args.output/name).write_bytes((ROOT/'tests/device/helpers'/name).read_bytes())
    d, peer = Device(args), None
    try:
        result['native_sha256']=d.install(); result['uid']=d.uid
        d.witness_start(); result['witness_pid']=d.witness_pid
        peer=Peer([args.endpoint4,args.endpoint6],args.output)
        q=Qualification(d,peer,result)
        for owners in map(int,args.owners.split(',')):
            d.owners=owners; label=f'n{owners}'; result['runs'].append(d.start(owners))
            if args.case_set != 'errors-only':
                status=d.configure(label+'-alias-drop')
                q.exchange(label+'-v4-alias-drop',args.endpoint4,status)
                q.exchange(label+'-v6-alias-drop',args.endpoint6,status,qtype=28)
            if args.case_set == 'errors-only':
                status=d.configure(label+'-short-coverage')
                q.exchange(label+'-short',args.endpoint4,status,variant='short',
                           coverage=2,denied=False,winner=2)
            elif args.case_set == 'hot-and-errors':
                status=d.configure(label+'-old-hot','allow')
                q.exchange(label+'-current-policy',args.endpoint4,status,hot=True)
                status=d.configure(label+'-short-coverage')
                q.exchange(label+'-short',args.endpoint4,status,variant='short',
                           coverage=2,denied=False,winner=2)
            elif owners==1:
                for variant,denied,winner in [('alias-allow',False,0),('rank-qname',True,1),
                                               ('and',False,2),('or',True,0),
                                               ('sni-or',False,2),('business-port',False,2)]:
                    status=d.configure(label+'-'+variant,variant)
                    q.exchange(label+'-'+variant,args.endpoint4,status,denied=denied,winner=winner,qtype=16)
                status=d.configure(label+'-observe',mode=1)
                q.exchange(label+'-observe',args.endpoint4,status,denied=False,winner=0,qtype=65)
                status=d.configure(label+'-old-hot','allow')
                q.exchange(label+'-current-policy',args.endpoint4,status,hot=True)
                status=d.configure(label+'-short-coverage')
                q.exchange(label+'-short',args.endpoint4,status,variant='short',
                           coverage=2,denied=False,winner=2)
            else:
                status=d.configure(label+'-transparent','allow')
                for qtype in (1,28,16,15,33,65,65000):
                    q.exchange(f'{label}-rr{qtype}',args.endpoint6 if qtype%2 else args.endpoint4,
                               status,denied=False,winner=2,qtype=qtype,edns=qtype==65000)
                status=d.configure(label+'-codec')
                for variant,aliases,coverage,chain,winner,denied in [
                    ('long',32,1,0,0,True),('overflow',33,4,3,2,False),
                    ('loop',1,2,1,2,False),('unrelated',1,1,0,2,False),
                    ('tc',1,5,0,2,False),('malformed',1,2,0,2,False),
                    ('short',1,2,0,2,False),
                    ('nxdomain',1,1,0,2,False)]:
                    q.exchange(label+'-'+variant,args.endpoint4,status,variant=variant,aliases=aliases,
                               coverage=coverage,chain_status=chain,winner=winner,denied=denied)
                status=d.configure(label+'-public','allow')
                q.exchange(label+'-public4',args.public4,status,denied=False,winner=2,public=True)
                q.exchange(label+'-public6',args.public6,status,denied=False,winner=2,public=True)
            d.cli(label+'-final','show product dns','show product completion','show product tun','show product flow-stack')
            result['runs'][-1].update(d.stop(label))
        result['status']='PASS'
    except Exception as error:
        result['error']=repr(error)
        raise
    finally:
        if d.active:
            d.save('failure-vpp.log',d.app(f'files/profiles/{d.profile}/vpp/logs/vpp-stdout.log'))
            try: d.stop('failure-cleanup')
            except Exception as error: result['cleanup_error']=repr(error)
        if peer:
            try: peer.close()
            except Exception as error: result['peer_cleanup_error']=repr(error)
        try: d.witness_stop()
        except Exception as error: result['witness_cleanup_error']=repr(error)
        if any(key.endswith('cleanup_error') for key in result): result['status']='HOLD'
        result['completed_ns']=time.time_ns()
        d.save('result.json',json.dumps(result,indent=2)+'\n')
    assert result['status']=='PASS', result
    print(json.dumps(dict(status=result['status'],output=str(args.output),cases=len(result['cases']))))


if __name__=='__main__': main()
