#!/usr/bin/env python3
"""Run the fixed T20 matrix; retain raw output and process exit outcomes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
p=argparse.ArgumentParser()
p.add_argument('--target',choices=['host','android'],required=True)
p.add_argument('--build',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
p.add_argument('--smoke',action='store_true')
a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
build=a.build.resolve();android=a.target=='android'
env=dict(os.environ,SAKAMOTO_ADB='/tmp/sakamoto-r3-platform-tools/adb-client')
adb=[]
if android:
    serial=json.loads((ROOT/'build-output/t19-20260926/pixel-root-final/result.json').read_text())['serial']
    adb=[str(ROOT/'dev/adb'),'-s',serial]
def call(args,timeout=30):
    started=time.time_ns()
    try:
        r=subprocess.run([str(x) for x in args],env=env,text=True,capture_output=True,timeout=timeout)
        return dict(started_ns=started,completed_ns=time.time_ns(),exit=r.returncode,stdout=r.stdout,stderr=r.stderr)
    except subprocess.TimeoutExpired as e:
        return dict(started_ns=started,completed_ns=time.time_ns(),exit=124,stdout=str(e.stdout),stderr=str(e.stderr))
nonce=secrets.token_hex(4);remote='/data/local/tmp/t20-'+nonce
if android:
    setup=[]
    setup.append(call([*adb,'shell','mkdir',remote]))
    for candidate in ['aeron','vpp','minimal']:
        setup.append(call([*adb,'push',build/candidate,remote+'/'+candidate]))
        setup.append(call([*adb,'shell','chmod','755',remote+'/'+candidate+'/producer',remote+'/'+candidate+'/consumer',remote+'/'+candidate+'/query']))
        if candidate=='minimal':
            setup.append(call([*adb,'shell','chmod','755',remote+'/'+candidate+'/minimal-test']))
    (out/'setup.json').write_text(json.dumps(setup,indent=2))
    assert all(x['exit']==0 for x in setup)
    installed=[]
    for candidate in ['aeron','vpp','minimal']:
        for f in sorted((build/candidate).iterdir()):
            if f.name not in ['producer','consumer','query','libsvm.so','libvppinfra.so','minimal-test']:
                continue
            witness=call([*adb,'shell','sha256sum',remote+'/'+candidate+'/'+f.name])
            expected=hashlib.sha256(f.read_bytes()).hexdigest()
            installed.append(dict(candidate=candidate,file=f.name,expected_sha256=expected,readback=witness))
            assert witness['exit']==0 and witness['stdout'].split()[0]==expected,'installed artifact mismatch'
    (out/'installed-artifacts.json').write_text(json.dumps(installed,indent=2)+'\n')
    environment={name:call([*adb,'shell',*cmd]) for name,cmd in {
        'uname':['uname','-a'],'identity':['id'],'fingerprint':['getprop','ro.build.fingerprint'],
        'cpu':['cat','/proc/cpuinfo'],'battery':['dumpsys','battery'],
        'thermal':['dumpsys','thermalservice'],'processes':['ps','-A'],
        'page_size':['getconf','PAGESIZE']}.items()}
else:
    environment={name:call(cmd) for name,cmd in {'uname':['uname','-a'],'cpu':['cat','/proc/cpuinfo'],'page_size':['getconf','PAGESIZE']}.items()}
(out/'environment.json').write_text(json.dumps(environment,indent=2))
primitive=call([*adb,'shell','timeout','20',remote+'/minimal/minimal-test'] if android else ['timeout','20',build/'minimal/minimal-test'])
(out/'primitive-test.json').write_text(json.dumps(primitive,indent=2)+'\n')
assert primitive['exit']==0,'minimal ring primitive tests failed'
matrix=[('steady',32000,32,1000,'normal'),('batch1',1000,1,1000,'normal'),
        ('batch128',128000,128,1000,'normal'),('sparse',100,1,20000,'normal'),
        ('idle',1,1,0,'idle'),('burst',200000,128,0,'normal'),
        ('pause',100000,32,0,'pause'),('stopped',100000,32,0,'stopped'),
        ('absent',100000,32,0,'absent'),('isolation',32000,32,1000,'isolation'),
        ('crash',100000,32,0,'crash'),
        ('corrupt',10,1,1000,'corrupt'),('restart',1000,32,1000,'normal'),
        ('boundary',20000,32,1000,'boundary'),('wake_race',10000,1,100,'wake_race')]
if a.smoke:matrix=[('smoke',10000,32,1000,'normal')]
results=[]
for rep in range(1 if a.smoke else 3):
    for name,count,batch,interval,scenario in matrix:
        candidates=['aeron','vpp','minimal']
        for candidate in candidates[rep:]+candidates[:rep]:
            run_id=f'{rep}-{name}-{candidate}'
            generation=time.time_ns()&0x7fffffffffffffff
            path=(remote if android else '/tmp')+'/t20-'+nonce+'-'+run_id
            base=remote+'/'+candidate if android else str(build/candidate)
            args=[base+'/producer',path,base+'/consumer',str(generation),str(count),str(batch),str(interval),scenario]
            r=call([*adb,'shell','timeout','15',*args] if android else ['timeout','15',*args],timeout=20)
            r.update(id=run_id,candidate=candidate,name=name,rep=rep,generation=generation,count=count,batch=batch,interval_us=interval,scenario=scenario)
            query=[base+'/query',path,str(generation)]
            r['query']=call([*adb,'shell',*query] if android else query)
            r['stale_query']=call([*adb,'shell',base+'/query',path,str(generation+1)] if android else [base+'/query',path,str(generation+1)])
            results.append(r)
            (out/(run_id+'.json')).write_text(json.dumps(r,indent=2)+'\n')
            print(run_id,r['exit'],flush=True)
            if android:call([*adb,'shell','rm',path])
            else:Path(path).unlink(missing_ok=True)
if android:
    cleanup=call([*adb,'shell','rm','-r',remote])
    absence=call([*adb,'shell','test','!','-e',remote])
    processes=call([*adb,'shell','ps','-A','-o','PID,ARGS'])
    clean=cleanup['exit']==0 and absence['exit']==0 and processes['exit']==0 and remote not in processes['stdout']
    (out/'cleanup.json').write_text(json.dumps(dict(clean=clean,remove=cleanup,absence=absence,processes=processes),indent=2))
    assert clean,'owned device files/processes remain'
manifest={'schema':'t20-runs/v2','target':a.target,'nonce':nonce,'build_manifest_sha256':hashlib.sha256((build/'build.json').read_bytes()).hexdigest(),
          'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'runs':[r['id'] for r in results]}
(out/'runs.json').write_text(json.dumps(manifest,indent=2)+'\n')
