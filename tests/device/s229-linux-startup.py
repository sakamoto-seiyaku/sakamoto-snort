#!/usr/bin/env python3
"""Verify Product startup-only reassembly configuration in a disposable netns."""
import argparse
import hashlib
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
assert os.getuid() == 0 and Path('/proc/self/uid_map').read_text().split()[1] != '0'
a.output.mkdir(parents=True, exist_ok=False)
build = json.loads(a.build.read_text())
artifact = Path(build['artifact'])
plugin = artifact/'lib/vpp_plugins/product_core_plugin.so'
assert hashlib.sha256(plugin.read_bytes()).hexdigest() == build['artifact_hashes']['lib/vpp_plugins/product_core_plugin.so']
vppctl = Path(build['stage'])/'source/build-root/install-vpp-native/vpp/bin/vppctl'
env = dict(os.environ, LD_LIBRARY_PATH=str(artifact/'lib'),
           SAKAMOTO_PRODUCT_GENERATION='22990', SAKAMOTO_RUNTIME_PROFILE='root',
           SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0', SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4')
results = []
for label, capacity, originals in [('valid', 65, 33), ('zero', 0, 33),
                                   ('overflow', 4294967294, 4294967294)]:
    with tempfile.TemporaryDirectory(prefix='s229-config-') as runtime:
        runtime = Path(runtime)
        config = f'''cpu {{ workers 2 }}
unix {{ nodaemon cli-no-pager runtime-dir {runtime} cli-listen {runtime}/cli.sock }}
socksvr {{ socket-name {runtime}/api.sock }}
plugins {{ path {artifact}/lib/vpp_plugins plugin default {{ disable }} plugin product_core_plugin.so {{ enable }} }}
product-reassembly {{ contexts {capacity} originals {originals} timeout-ms 750 }}
'''
        configuration = a.output/(label+'.conf')
        configuration.write_text(config)
        with (a.output/(label+'.log')).open('w') as log:
            process = subprocess.Popen([str(artifact/'bin/vpp'), '-c', str(configuration.resolve())],
                                       env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                if label == 'valid':
                    deadline = time.monotonic() + 15
                    while not (runtime/'cli.sock').exists():
                        assert process.poll() is None and time.monotonic() < deadline
                        time.sleep(.03)
                    status = subprocess.check_output([str(vppctl), '-s', str(runtime/'cli.sock'),
                                                      'show product reassembly'], env=env, text=True)
                    (a.output/'valid-status.txt').write_text(status)
                    assert 'timeout_ms=750 max_originals=33' in status and 'accepting=1' in status
                    stopped = subprocess.check_output([str(vppctl), '-s', str(runtime/'cli.sock'),
                                                       'product root stop'], env=env, text=True)
                    (a.output/'valid-stop.txt').write_text(stopped)
                    assert 'root.stop=ok' in stopped
                else:
                    # VPP can return zero for a configuration-parser error.
                    # Require its explicit diagnostic and process retirement,
                    # not a particular OS exit-code convention.
                    process.wait(timeout=15)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=8)
        error_log = (a.output/(label+'.log')).read_text()
        if label == 'zero':
            assert 'configuration must be positive' in error_log
        if label == 'overflow':
            assert 'startup allocation/configuration failed' in error_log
        results.append(dict(case=label, process_absent=process.poll() is not None,
                            returncode=process.returncode))
report = dict(status='PASS', build_sha256=hashlib.sha256(a.build.read_bytes()).hexdigest(), cases=results)
(a.output/'verification.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report, indent=2))
