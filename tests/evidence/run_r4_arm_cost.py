#!/usr/bin/env python3
"""Rebuild, bind and execute assertion-enabled R4 ARM64 owner tests/costs."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import time

ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser()
p.add_argument('--serial-from',type=Path,required=True)
p.add_argument('--build',type=Path,required=True)
p.add_argument('--binary',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
args=p.parse_args()
serial=json.loads(args.serial_from.read_text())['serial']
out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
binary=args.binary.resolve();source=ROOT/'tests/host/product_flow_lpi_test.c'
digest=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
spec=importlib.util.spec_from_file_location('r4_chain',ROOT/'tests/evidence/product_chain.py')
chain=importlib.util.module_from_spec(spec);spec.loader.exec_module(chain)
build=json.loads(args.build.read_text())
assert chain.source_files()==build['files'],'Product source differs from claimed build'
assert hashlib.sha256(chain.encode(build['files'])).hexdigest()==build['source_sha256']
inputs={name:digest(ROOT/name) for name in ('tests/host/product_flow_lpi_test.c','CMakeLists.txt')}
for name in inputs:
    destination=out/'source'/name;destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_bytes((ROOT/name).read_bytes())
(out/'CMakeCache.txt').write_bytes((binary.parent/'CMakeCache.txt').read_bytes())
run=dict(started_ns=time.time_ns(),test_source_sha256=digest(source),
         build_config_sha256=digest(binary.parent/'CMakeCache.txt'),samples=[],
         source_sha256=build['source_sha256'],build=str(args.build.resolve()),
         build_sha256=digest(args.build),test_inputs=inputs,runner_sha256=digest(__file__))
(out/'runner.py').write_bytes(Path(__file__).read_bytes())
command=['cmake','--build',str(binary.parent),'--target','sakamoto-product-flow-lpi-test',
         '--clean-first','--verbose','-j6']
run['compile_started_ns']=time.time_ns()
with (out/'compile.log').open('w') as log:
    subprocess.run(command,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=600)
assert chain.source_files()==build['files'],'Product source changed while compiling'
assert inputs=={name:digest(ROOT/name) for name in inputs},'test inputs changed while compiling'
assert run['build_config_sha256']==digest(binary.parent/'CMakeCache.txt')
run['compile_completed_ns']=time.time_ns()
log=(out/'compile.log').read_text()
commands=[line for line in log.splitlines() if str(source) in line and ' -c ' in line]
assert len(commands)==1,'unique test translation-unit compile witness required'
compile_args=__import__('shlex').split(commands[0])
assert '-O2' in compile_args and not any(x.startswith('-DNDEBUG') for x in compile_args)
compiler=Path(compile_args[0]);assert compiler.is_file()
assert 'aarch64' in commands[0] or '--target=aarch64' in commands[0]
run['compilation']=dict(command=command,translation_unit=commands[0],log_sha256=digest(out/'compile.log'),
    compiler=str(compiler),compiler_sha256=digest(compiler),
    version=subprocess.check_output([str(compiler),'--version'],text=True),assertions_enabled=True)
run['binary_sha256']=digest(binary)
remote='/data/local/tmp/r4-realtime-cost-'+str(time.time_ns())
def adb(*argv):
    return subprocess.check_output([str(ROOT/'dev/adb'),'-s',serial,*map(str,argv)],
                                   text=True,stderr=subprocess.STDOUT,timeout=30).replace('\r','')
try:
    run['platform']=adb('shell','uname','-m').strip();assert run['platform']=='aarch64'
    adb('push',binary,remote);adb('shell','chmod','755',remote)
    run['executed_sha256']=adb('shell','sha256sum',remote).split()[0]
    assert run['executed_sha256']==run['binary_sha256']
    (out/'semantic-tests.log').write_text(adb('shell',remote))
    for repetition in range(3):
        text=adb('shell','env','R4_COST=1',remote)
        (out/f'run-{repetition}.json').write_text(text)
        rows=[json.loads(line) for line in text.splitlines() if line.startswith('{')]
        assert len(rows)==7 and [r['shape'] for r in rows]==list(range(7))
        assert all(r['calls']==40000 and r['lpi_bytes']==160 and r['entry_bytes']==392 and r['elapsed_ns']>0 for r in rows)
        run['samples'].append(rows)
finally:
    adb('shell','rm','-f',remote)
    run['cleanup']=adb('shell','test','!','-e',remote)==''
    run['completed_ns']=time.time_ns()
    (out/'result.json').write_text(json.dumps(run,indent=2)+'\n')
print(json.dumps(dict(status='PASS',platform=run['platform'],samples=len(run['samples']),cleanup=run['cleanup'])))
