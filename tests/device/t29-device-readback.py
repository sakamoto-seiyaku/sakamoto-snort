#!/usr/bin/env python3
"""Read-only stopped Pixel closure for T29 without touching ordinary history."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import sqlite3
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[2]
PKG = 'com.sakamoto.snort.androidruntime'
p = argparse.ArgumentParser()
p.add_argument('--serial-from',type=Path,required=True)
p.add_argument('--build',type=Path,required=True)
p.add_argument('--baseline',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a = p.parse_args()
out = a.output.resolve();out.mkdir(parents=True,exist_ok=False)
serial = json.loads(a.serial_from.read_text())['serial']
build = json.loads(a.build.read_text())
baseline = json.loads(a.baseline.read_text())
digest = lambda b: hashlib.sha256(b).hexdigest()
def adb(*args,check=True):
    call = subprocess.run([str(ROOT/'dev/adb'),'-s',serial,*args],capture_output=True,timeout=45)
    if check and call.returncode:raise RuntimeError((call.stdout+call.stderr).decode(errors='replace'))
    return call.stdout
def save(name,content):
    (out/name).write_bytes(content if isinstance(content,bytes) else content.encode())
    return content
state_text=save('state.properties',adb('shell','run-as',PKG,'cat','files/runtime-state/snapshot.properties'))
state=dict(line.split('=',1) for line in state_text.decode().splitlines() if '=' in line)
assert state['state']=='stopped' and state['mayBeActive']=='false' and state['protectionRunning']=='false'
assert not adb('shell','pidof',PKG+':runtime',check=False).strip()
processes=save('processes.txt',adb('shell','su','-c',shlex.quote('ps -A -o PID,UID,ARGS')))
assert b'libvpp_runtime.so' not in processes
grant=save('root-grant.txt',adb('shell','run-as',PKG,'su','-c','id'))
assert b'uid=0' in grant
hooks=save('hooks.txt',adb('shell','su','-c',shlex.quote('iptables-save; ip6tables-save')))
assert b'NFQUEUE' not in hooks and b'SAKAMOTO' not in hooks
selector=subprocess.run([str(ROOT/'dev/adb'),'-s',serial,'shell','run-as',PKG,'test','-e',
                         'files/observation/t27-test.enabled'],capture_output=True,timeout=45)
assert selector.returncode != 0

device_hashes={}
for name in ('files/observation/overall.sqlite3','files/observation/overall.json'):
    content=adb('exec-out','run-as',PKG,'cat',name)
    device_hashes[name]=digest(content)
    if name.endswith('.sqlite3'):save('overall.sqlite3',content)
assert device_hashes==baseline['ordinary_history_hashes']
db=sqlite3.connect(out/'overall.sqlite3')
integrity=db.execute('PRAGMA integrity_check').fetchone()[0]
rows=db.execute('SELECT kind,COUNT(*) FROM observation GROUP BY kind ORDER BY kind').fetchall()
db.close()
assert integrity=='ok' and sum(count for kind,count in rows if kind!=0)==1575
package=save('package.txt',adb('shell','dumpsys','package',PKG)).decode(errors='replace')
code_path=re.search(r'codePath=(\S+)',package)[1]
installed=save('installed-apk.txt',adb('shell','sha256sum',code_path+'/base.apk')).decode().split()[0]
assert installed==build['apk_sha256'] and digest(Path(build['apk']).read_bytes())==installed
with zipfile.ZipFile(build['apk']) as archive:
    native={Path(name).name:hashlib.sha256(archive.read(name)).hexdigest() for name in archive.namelist()
            if name.startswith('lib/arm64-v8a/') and name.endswith('.so')}
actual=save('installed-native.txt',adb('shell','sha256sum',*[code_path+'/lib/arm64/'+name for name in sorted(native)])).decode()
assert {Path(line.split()[1]).name:line.split()[0] for line in actual.splitlines()}==native==build['native_sha256']
answer=dict(status='PASS',source_sha256=build['source_sha256'],apk_sha256=installed,
            stopped_generation=int(state['generation']),root_grant=True,vpp_absent=True,
            service_absent=True,owned_nfqueue_hooks_absent=True,test_selector_removed=True,
            ordinary_history_hashes=device_hashes,sqlite_integrity=integrity,sqlite_rows=rows,
            native_hashes_match=True,root_and_vpn_original_history_unchanged=True,
            verifier_sha256=digest(Path(__file__).read_bytes()))
save('summary.json',json.dumps(answer,indent=2)+'\n')
print(json.dumps({k:answer[k] for k in ('status','source_sha256','apk_sha256','stopped_generation',
                                       'sqlite_integrity','test_selector_removed')},indent=2))
