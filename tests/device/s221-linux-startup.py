#!/usr/bin/env python3
"""Source-bound startup-only capacity and rejected configuration checks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();a.output=a.output.resolve();a.output.mkdir(parents=True,exist_ok=False)
assert os.getuid()==0 and Path('/proc/self/uid_map').read_text().split()[1]!='0'
build=json.loads(a.build.read_text());artifact=Path(build['artifact'])
digest=lambda path:hashlib.sha256(Path(path).read_bytes()).hexdigest()
assert digest(artifact/'lib/vpp_plugins/product_core_plugin.so')==build['artifact_hashes']['lib/vpp_plugins/product_core_plugin.so']
vppctl=Path(build['stage'])/'source/build-root/install-vpp-native/vpp/bin/vppctl'
env=dict(os.environ,LD_LIBRARY_PATH=str(artifact/'lib'),SAKAMOTO_PRODUCT_GENERATION='22190',
         SAKAMOTO_RUNTIME_PROFILE='root',SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0',SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4')
cases=[]
for label,capacity in [('valid',65),('zero',0),('overflow',4294967295),
                       ('parse-overflow',4294967297)]:
    with tempfile.TemporaryDirectory(prefix='s221-config-') as temporary:
        runtime=Path(temporary)
        config=f'''cpu {{ workers 2 }}
unix {{ nodaemon cli-no-pager runtime-dir {runtime} cli-listen {runtime}/cli.sock }}
socksvr {{ socket-name {runtime}/api.sock }}
plugins {{ path {artifact}/lib/vpp_plugins plugin default {{ disable }} plugin product_core_plugin.so {{ enable }} }}
product-flow-runtime {{ entries {capacity} }}
'''
        configuration=a.output/(label+'.conf');configuration.write_text(config)
        with (a.output/(label+'.log')).open('w') as log:
            process=subprocess.Popen([str(artifact/'bin/vpp'),'-c',str(configuration)],env=env,stdout=log,stderr=subprocess.STDOUT)
            try:
                if label=='valid':
                    end=time.monotonic()+15
                    while not (runtime/'cli.sock').exists():
                        assert process.poll() is None and time.monotonic()<end
                        time.sleep(.05)
                    status=subprocess.check_output([str(vppctl),'-s',str(runtime/'cli.sock'),'show product flows'],env=env,text=True)
                    (a.output/'valid-status.txt').write_text(status)
                    assert status.count('capacity=65 ')==2 and status.count('entries=0 ')==2
                    stop=subprocess.check_output([str(vppctl),'-s',str(runtime/'cli.sock'),'product root stop'],env=env,text=True)
                    (a.output/'valid-stop.txt').write_text(stop);assert 'root.stop=ok' in stop
                    rejected=subprocess.check_output([str(vppctl),'-s',str(runtime/'cli.sock'),
                        'product flow capacity 4294967297'],env=env,text=True)
                    (a.output/'cli-parse-overflow.txt').write_text(rejected)
                    assert 'expected a positive startup entry capacity' in rejected
                else:
                    process.wait(timeout=15)
            finally:
                if process.poll() is None:process.terminate();process.wait(timeout=8)
        if label!='valid':
            assert 'product-flow-runtime: expected entries <positive capacity>' in (a.output/(label+'.log')).read_text()
        cases.append(dict(label=label,capacity=capacity,process_absent=process.poll() is not None))
report=dict(status='PASS',build_sha256=digest(a.build),runner_sha256=digest(__file__),cases=cases)
(a.output/'verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
