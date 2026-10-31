"""Independent finite Android HTTPS DoH fixture (ALPN http/1.1) with exact owned-file settlement."""
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import time
import zipfile


class Peer:
    def __init__(self, device, out, certificates, port=15353):
        self.device, self.out, self.port = device, out, port
        self.remote = '/data/local/tmp/s323-doh-peer-' + str(time.monotonic_ns())
        self.pid = self.start = None
        self.mode = 'ok'
        self.files = set()
        self.launch_pid = None
        self.created = False
        self.certificates = certificates

    def start_peer(self):
        device, out, certificates, port = self.device, self.out, self.certificates, self.port
        root = Path(__file__).resolve().parents[3]
        source = Path(__file__).with_name('S323DoHPeer.java')
        cache = root / 'build-output/device-fixture-cache/s323-doh-peer'
        cache.mkdir(parents=True, exist_ok=True)
        jar = cache / 'peer.jar'
        android = Path('/home/js/android/lineage/prebuilts/sdk/36/public/android.jar')
        d8 = Path('/home/js/android/lineage/prebuilts/sdk/tools/linux/lib/d8.jar')
        digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
        inputs = {str(p): digest(p) for p in (source, android, d8)}
        receipt = cache / 'inputs.json'
        compiled = not (jar.exists() and receipt.exists() and json.loads(receipt.read_text()) == inputs)
        if compiled:
            classes, dex = cache / 'classes', cache / 'dex'
            classes.mkdir(exist_ok=True); dex.mkdir(exist_ok=True)
            commands = [
                ['javac', '-source', '8', '-target', '8', '-bootclasspath', str(android), '-d', str(classes), str(source)],
                ['java', '-cp', str(d8), 'com.android.tools.r8.D8', '--lib', str(android), '--min-api', '31',
                 '--output', str(dex), str(classes / 'S323DoHPeer.class')],
            ]
            with (out / 'build.log').open('x') as log:
                for command in commands:
                    subprocess.run(['rtk', 'proxy', *command], check=True, stdout=log, stderr=log)
            with zipfile.ZipFile(jar, 'w') as archive:
                archive.write(dex / 'classes.dex', 'classes.dex')
            receipt.write_text(json.dumps(inputs, indent=2) + '\n')
        (out / 'build.json').write_text(json.dumps(dict(compiled=compiled, inputs=inputs,
            jar=str(jar), jar_sha256=digest(jar)), indent=2) + '\n')
        assert not device.adb('shell', 'sh', '-c', shlex.quote('if [ -e ' + self.remote + ' ]; then echo PRESENT; fi')).strip()
        device.adb('shell', 'mkdir', self.remote)
        self.created = True
        for source_file, name in ((jar, 'peer.jar'), (certificates / 'peer.p12', 'peer.p12')):
            device.adb('push', str(source_file), self.remote + '/' + name)
            assert device.adb('shell', 'sha256sum', self.remote + '/' + name).split()[0] == digest(source_file)
            self.files.add(name)
        command = ('CLASSPATH=' + self.remote + '/peer.jar app_process /system/bin S323DoHPeer '
            + self.remote + ' ' + str(port) + ' 900 > ' + self.remote + '/log 2>&1 < /dev/null & echo $!')
        self.files.add('log')
        self.launch_pid = int(device.adb('shell', 'sh', '-c', shlex.quote(command)).strip())
        for _ in range(50):
            rows = self.rows()
            ready = [row for row in rows if row['kind'] == 'ready']
            if ready:
                self.pid = ready[0]['pid']
                assert self.pid == self.launch_pid
                identity = device.adb('shell', 'cat', f'/proc/{self.pid}/stat')
                self.start = int(identity.split(') ', 1)[1].split()[19])
                (out / 'identity.json').write_text(json.dumps(dict(pid=self.pid, start=self.start,
                    remote=self.remote, command=command, stat=identity), indent=2) + '\n')
                break
            time.sleep(.1)
        assert self.pid, 'independent Android TLS peer failed before ready: ' + self.raw()

    def raw(self):
        return self.device.adb('shell', 'cat', self.remote + '/log', check=False)

    def rows(self):
        raw = self.raw()
        (self.out / 'peer-android.jsonl').write_text(raw)
        return [json.loads(line) for line in raw.splitlines() if line.startswith('{')]

    def register(self, query, reply, *, protocol='tcp', drop=False, **options):
        assert protocol == 'tcp' and not options
        name = 'plan-' + hashlib.sha256(query[2:]).hexdigest()
        path = self.out / name
        path.write_text('DROP' if drop else self.mode + ' ' + reply.hex())
        self.device.adb('push', str(path), self.remote + '/' + name)
        self.files.add(name)

    def cursor(self):
        return max((row['request'] for row in self.rows() if row['kind'] == 'received'), default=0)

    def received(self, query, protocol='tcp', port=None, *, after=0):
        assert protocol == 'tcp' and port in (None, self.port)
        return [row for row in self.rows() if row['kind'] == 'received' and row['request'] > after
                and bytes.fromhex(row['request_hex'])[2:] == query[2:]]

    def close(self):
        if not self.created: return
        self.device.adb('shell', 'touch', self.remote + '/stop'); self.files.add('stop')
        deadline = time.monotonic() + 8
        terminal = self.launch_pid is None
        while self.launch_pid is not None and time.monotonic() < deadline:
            rows = self.rows()
            stat = self.device.adb('shell', 'cat', f'/proc/{self.launch_pid}/stat', check=False)
            if not stat.startswith(str(self.launch_pid) + ' ') or (self.start is not None and
                    int(stat.split(') ', 1)[1].split()[19]) != self.start):
                terminal = True; break
            time.sleep(.1)
        rows = self.rows()
        assert terminal and (self.start is None or sum(row['kind'] == 'stopped' for row in rows) == 1), rows
        received = [row for row in rows if row['kind'] == 'received']
        settled = [row for row in rows if row['kind'] in ('exchange', 'cancelled')]
        assert sorted(row['request'] for row in received) == sorted(row['request'] for row in settled)
        names = set(self.device.adb('shell', 'ls', '-1', self.remote).splitlines())
        assert names == self.files, (names, self.files)
        self.device.adb('shell', 'rm', *[self.remote + '/' + name for name in sorted(self.files)])
        self.device.adb('shell', 'rmdir', self.remote)
        (self.out / 'cleanup.json').write_text(json.dumps(dict(status='PASS', terminal=True,
            pid=self.launch_pid, start=self.start, no_signals=True, exact_owned_files_removed=sorted(names),
            received=len(received), settled=len(settled)), indent=2) + '\n')
