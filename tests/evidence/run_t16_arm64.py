#!/usr/bin/env python3
"""Serial physical ARM64 public-Flow vectors and bounded load measurements."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/host'))
import quic_crypto_sequences as sequences
import quic_initial_vectors as wire

def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--serial-from',type=Path,required=True)
    parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    selector=json.loads(args.serial_from.read_text())['serial']
    prefix=[str(ROOT/'dev/adb'),'-s',selector]
    env=dict(os.environ,SAKAMOTO_ADB='/tmp/sakamoto-r3-platform-tools/adb-client')
    def adb(*command):
        result=subprocess.run(prefix+list(map(str,command)),env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,check=True)
        return result.stdout
    bundle=out/'inputs';bundle.mkdir()
    binary=bundle/'flow-test';binary.write_bytes(args.binary.read_bytes())
    commands=[]
    for name,steps in sequences.cases():
        sequences.write(bundle/(name+'.seq'),steps)
        commands.append('./flow-test --sequence '+shlex.quote(name+'.seq'))
    sequence_count=len(commands)
    for name,packet,result,stop,sni in wire.cases():
        (bundle/(name+'.wire')).write_bytes(packet)
        commands.append('./flow-test '+shlex.quote(name+'.wire')+f' {result} {stop} '+shlex.quote(sni))
    vector_count=len(commands)-sequence_count
    (bundle/'vectors.sh').write_text('set -eu\n'+ '\n'.join(commands)+'\necho ARM64_VECTORS_PASS\n')
    loads=[]
    for count in (1,8,16,32):
        name=f'ranges-{count}'
        sequences.write(bundle/(name+'.seq'),[sequences.step(b''.join(wire.crypto(b'x',i*2+1) for i in range(count)),retained=count)])
        loads.append(name)
    for count in (512,2048,4000):
        name=f'bytes-{count}'
        sequences.write(bundle/(name+'.seq'),[sequences.step(wire.crypto(bytes(count),1),retained=count,minimum=max(1200,count+64))])
        loads.append(name)
    loads+=['work-budget','duplicate-overlap','coalesced-initials']
    remote='/data/local/tmp/sakamoto-t16-arm64-'+str(time.time_ns())
    report=dict(started_ns=time.time_ns(),binary_sha256=digest(binary),independent_sequences=sequence_count,
        independent_single_initials=vector_count,loads=[],files={})
    try:
        adb('push',bundle,remote);adb('shell','chmod','700',remote+'/flow-test')
        report['installed_sha256']=adb('shell','sha256sum',remote+'/flow-test').split()[0]
        assert report['installed_sha256']==report['binary_sha256']
        (out/'device.txt').write_text(adb('shell','getprop','ro.product.device')+adb('shell','uname','-a'))
        result=adb('shell','sh','-c',shlex.quote('cd '+remote+' && sh vectors.sh'))
        (out/'vectors.log').write_text(result);assert 'ARM64_VECTORS_PASS' in result
        for name in loads:
            for capacity in (1,64,1024):
                for sample in range(3):
                    text=adb('shell',remote+'/flow-test','--load',remote+'/'+name+'.seq',capacity,10)
                    value=json.loads(text);value.update(case=name,sample=sample)
                    report['loads'].append(value)
        report['status']='PASS'
    finally:
        adb('shell','rm','-rf',remote)
        report['completed_ns']=time.time_ns()
        report['files']={str(p.relative_to(out)):digest(p) for p in out.rglob('*') if p.is_file()}
        (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ('files','loads')},indent=2))
if __name__=='__main__':main()
