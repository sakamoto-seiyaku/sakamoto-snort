#!/usr/bin/env python3
"""Sample Product process resource counters while an unchanged live runner executes.

This collector does not inject traffic or write configuration. The runner owns
all lifecycle and cleanup; samples are descriptive and may miss short peaks.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--platform', choices=('linux', 'pixel'), required=True)
parser.add_argument('--run', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--serial')
parser.add_argument('--serial-from', type=Path)
parser.add_argument('--interval', type=float, default=.5)
parser.add_argument('command', nargs=argparse.REMAINDER)
args = parser.parse_args()
command = args.command[1:] if args.command[:1] == ['--'] else args.command
assert command and .2 <= args.interval <= 5
if args.platform == 'pixel':
    if args.serial_from:
        args.serial=json.loads(args.serial_from.read_text())['serial']
    assert args.serial and all(ch.isalnum() or ch in '._:-' for ch in args.serial)
args.output.mkdir(parents=True, exist_ok=False)
(args.output/'collector.py').write_bytes(Path(__file__).read_bytes())
(args.output/'command.json').write_text(json.dumps(command, indent=2)+'\n')
samples = args.output/'samples.jsonl'
run = args.run.resolve()
adb = [str(ROOT/'dev/adb'), '-s', args.serial] if args.platform == 'pixel' else None

def device(*cmd, timeout=20):
    return subprocess.run(adb+list(cmd), stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True, timeout=timeout).stdout

def environment(label):
    if adb:
        for name, argv in [('battery', ('shell','dumpsys','battery')),
                           ('thermal', ('shell','dumpsys','thermalservice')),
                           ('uptime', ('shell','cat','/proc/uptime'))]:
            (args.output/f'{label}-{name}.txt').write_text(device(*argv))
    else:
        (args.output/f'{label}-uptime.txt').write_text(Path('/proc/uptime').read_text())

def linux_pids():
    found = {}
    for label in ('first',):
        path=run/f'{label}-process.txt'
        if path.exists():
            for line in path.read_text().splitlines():
                if line.startswith('pid='):
                    found['vpp']=int(line.partition('=')[2])
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            cmd=(path/'cmdline').read_bytes().replace(b'\0',b' ').decode()
            if 'sakamoto-product-core-host' in cmd and 'observation' in cmd:
                found['consumer']=int(path.name)
        except (OSError, UnicodeDecodeError):
            pass
    return found

def pixel_pids():
    found={}
    for profile in ('root','vpn'):
        path=run/f'{profile}-processes.txt'
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            fields=line.split(None,2)
            if (len(fields)==3 and fields[0].isdigit() and
                    Path(fields[2].split()[0]).name=='libvpp_runtime.so'):
                found['vpp']=int(fields[0])
    for name in ('com.sakamoto.snort.androidruntime',):
        raw=device('shell','pidof',name).strip()
        if raw.split() and raw.split()[0].isdigit():found['runtime']=int(raw.split()[0])
    return found

def parse_proc(text):
    parts=text.split('\n@@\n')
    if len(parts)!=3:return {'raw':text[:200], 'error':'incomplete_proc'}
    status, stat, io=parts
    values={}
    for line in status.splitlines():
        for key in ('VmRSS','VmHWM','VmSize','Threads','voluntary_ctxt_switches',
                    'nonvoluntary_ctxt_switches'):
            if line.startswith(key+':'):
                values[key]=int(line.split()[1]);break
    fields=stat[stat.rfind(')')+2:].split()
    if len(fields)>13:
        values['utime_ticks']=int(fields[11]);values['stime_ticks']=int(fields[12])
    for line in io.splitlines():
        if line.startswith(('read_bytes:', 'write_bytes:')):
            key,value=line.split(':',1);values[key]=int(value.strip())
    return values

def proc(pid):
    paths=[f'/proc/{pid}/{name}' for name in ('status','stat','io')]
    if adb:
        # Numeric PID only; batch status and CPU fields to limit observer cost.
        cmd='; printf "\\n@@\\n"; '.join('cat '+path for path in paths)
        raw=device('shell','su','-c',cmd)
        values=parse_proc(raw)
        # adb shell drops /proc/io from the compound su -c command on this
        # device. Read it separately; absence remains explicit if denied.
        for line in device('shell','su','-c','cat '+paths[2]).splitlines():
            if line.startswith(('read_bytes:', 'write_bytes:')):
                key,value=line.split(':',1);values[key]=int(value.strip())
        return values
    else:
        try:raw='\n@@\n'.join(Path(path).read_text() for path in paths)
        except OSError as error:return {'error':repr(error)}
    return parse_proc(raw)

def store_files():
    if adb:
        raw=device('shell','run-as','com.sakamoto.snort.androidruntime',
                   'ls','-l','files/observation/t27-test')
        files={}
        for line in raw.splitlines():
            pieces=line.split()
            if len(pieces)>=8 and pieces[4].isdigit() and pieces[-1].startswith('overall'):
                files[pieces[-1]]=int(pieces[4])
        return files
    return {str(path):path.stat().st_size for path in (run/'observation').glob('overall*')
            if path.is_file()}

environment('before')
started=time.monotonic_ns()
with (args.output/'runner.log').open('w') as log, samples.open('w') as stream:
    child=subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
    try:
        number=0
        while child.poll() is None:
            begin=time.monotonic_ns()
            try:
                pids=pixel_pids() if adb else linux_pids()
                row={'monotonic_ns':begin,'wall_ns':time.time_ns(),
                     'pids':pids,'processes':{key:proc(pid) for key,pid in pids.items()}}
                if number % (3 if adb else 1)==0:
                    row['store_files']=store_files()
            except Exception as error:
                row={'monotonic_ns':begin,'wall_ns':time.time_ns(),'error':repr(error)}
            stream.write(json.dumps(row)+'\n');stream.flush()
            number+=1
            time.sleep(max(0,args.interval-(time.monotonic_ns()-begin)/1e9))
    except BaseException:
        child.terminate()
        try:child.wait(timeout=10)
        except subprocess.TimeoutExpired:child.kill();child.wait()
        raise
    code=child.wait()
environment('after')
summary={'platform':args.platform,'started_ns':started,'completed_ns':time.monotonic_ns(),
         'returncode':code,'sample_count':sum(1 for _ in samples.open()),
         'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
         'command':command}
(args.output/'result.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2))
raise SystemExit(code)
