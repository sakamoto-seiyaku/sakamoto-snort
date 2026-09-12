#!/usr/bin/env python3
"""No-hooks real-VPP startup regression for the native receive partition.

Run inside a disposable rootless user/network namespace. The unoptimized
Linux build previously overflowed the default 32 KiB VPP process stack before
it could emit even one NFQUEUE configuration ACK.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

p = argparse.ArgumentParser()
p.add_argument('--build', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
assert os.getuid() == 0 and Path('/proc/self/uid_map').read_text().split()[1] != '0'
build = json.loads(a.build.read_text())
artifact = Path(build['artifact'])
vppctl = Path(build['stage'])/'source/build-root/install-vpp-native/vpp/bin/vppctl'
report = dict(status='HOLD', cases=[])
try:
    for maximum in (1024, 1):
        with tempfile.TemporaryDirectory(prefix='s233-start-') as temporary:
            runtime = Path(temporary)
            config = a.output/f'maxlen-{maximum}.conf'
            config.write_text(f'''cpu {{ workers 2 }}
unix {{ nodaemon cli-no-pager runtime-dir {runtime} cli-listen {runtime}/cli.sock }}
socksvr {{ socket-name {runtime}/api.sock }}
plugins {{ path {artifact}/lib/vpp_plugins plugin default {{ disable }} plugin product_core_plugin.so {{ enable }} }}
''')
            env = dict(os.environ, LD_LIBRARY_PATH=str(artifact/'lib'), SAKAMOTO_PRODUCT_GENERATION='23319',
                       SAKAMOTO_RUNTIME_PROFILE='root', SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0',
                       SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4', SAKAMOTO_PRODUCT_ROOT_NFQUEUE_MAXLEN=str(maximum))
            log = a.output/f'maxlen-{maximum}.log'
            with log.open('w') as stream:
                process = subprocess.Popen([str(artifact/'bin/vpp'), '-c', str(config)], env=env,
                                           stdout=stream, stderr=subprocess.STDOUT)
            record = dict(maxlen=maximum, pid=process.pid)
            report['cases'].append(record)
            try:
                end = time.monotonic()+10
                while 'lane=3 family=6 queue=179 flags=9' not in log.read_text():
                    assert process.poll() is None and time.monotonic() < end, (process.returncode, log.read_text())
                    time.sleep(.05)
                for label, command in (('open', 'show product root receive'), ('stop', 'product root stop'),
                                       ('closed', 'show product root receive')):
                    text = subprocess.check_output([str(vppctl), '-s', str(runtime/'cli.sock'), command], env=env, text=True)
                    (a.output/f'{maximum}-{label}.txt').write_text(text)
                    expected = 'allocated=72 normal_free=64 reserve_free=8 loans=0' if label == 'open' else 'allocated=0 normal_free=0 reserve_free=0 loans=0'
                    if label == 'stop':
                        assert 'root.stop=ok' in text, text
                    else:
                        assert text.count(expected) == 4, text
            finally:
                record['exit_before_stop'] = process.poll()
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
                record['exit_code'] = process.returncode
                record['process_absent'] = not Path(f'/proc/{process.pid}').exists()
    report['status'] = 'PASS'
finally:
    (a.output/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
