#!/usr/bin/env python3
"""Run assertion-enabled owner-seam tests and bounded R2 costs on actual ARM64."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--serial-from',type=Path,required=True)
p.add_argument('--build',type=Path,required=True);p.add_argument('--binary',type=Path,required=True)
p.add_argument('--output',type=Path,required=True);args=p.parse_args()
serial=json.loads(args.serial_from.read_text())['serial'];out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
binary=args.binary.resolve();source=ROOT/'tests/host/product_flow_lpi_test.c'
digest=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
remote='/data/local/tmp/r2-mail-cost-'+str(time.time_ns())
run=dict(started_ns=time.time_ns(),binary_sha256=digest(binary),test_source_sha256=digest(source),
         build_config_sha256=digest(binary.parent/'CMakeCache.txt'),samples=[],
         source_sha256=json.loads(args.build.read_text())['source_sha256'],build=str(args.build.resolve()))
(out/'test-source.c').write_bytes(source.read_bytes())
def adb(*argv):
    return subprocess.check_output([str(ROOT/'dev/adb'),'-s',serial,*map(str,argv)],text=True,stderr=subprocess.STDOUT,timeout=30).replace('\r','')
try:
    run['platform']=adb('shell','uname','-m').strip();assert run['platform']=='aarch64'
    adb('push',binary,remote);adb('shell','chmod','755',remote)
    run['executed_sha256']=adb('shell','sha256sum',remote).split()[0];assert run['executed_sha256']==run['binary_sha256']
    (out/'semantic-tests.log').write_text(adb('shell',remote))
    for repetition in range(3):
        text=adb('shell','env','R2_COST=1',remote);(out/f'run-{repetition}.json').write_text(text)
        rows=[json.loads(line) for line in text.splitlines() if line.startswith('{')]
        assert len(rows)==4 and [r['shape'] for r in rows]==list(range(4))
        assert all(r['calls']==40000 and r['lpi_bytes']==56 and r['entry_bytes']==288 and r['elapsed_ns']>0 for r in rows)
        run['samples'].append(rows)
finally:
    adb('shell','rm','-f',remote)
    run['cleanup']=adb('shell','test','!','-e',remote)==''
    run['completed_ns']=time.time_ns();(out/'result.json').write_text(json.dumps(run,indent=2)+'\n')
print(json.dumps(dict(status='PASS',platform=run['platform'],samples=len(run['samples']),cleanup=run['cleanup'])))
