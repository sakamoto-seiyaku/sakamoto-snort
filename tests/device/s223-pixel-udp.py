#!/usr/bin/env python3
"""S223 installed Product ELF with explicit startup capacities and app lifecycle smoke.

The native acceptance uses only private loopback hooks and kernel endpoints.
It is not a graph injector or a replacement implementation of FlowRuntime.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import subprocess
import threading
import time
import zipfile

ROOT=Path(__file__).resolve().parents[2];PKG='com.sakamoto.snort.androidruntime';SERIAL='28201JEGR0XPAJ'
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def rows(text,prefix):
    return [dict(part.split('=',1) for part in line.split()[1:] if '=' in part)
            for line in text.splitlines() if line.startswith(prefix)]
def props(text):return dict(l.split('=',1) for l in text.splitlines() if '=' in l and not l.startswith('#'))
def native_processes(text):
    found=[]
    for line in text.splitlines():
        parts=line.split(None,2)
        if len(parts)==3 and parts[0].isdigit() and parts[2].split():
            if Path(parts[2].split()[0]).name=='libvpp_runtime.so':found.append(line)
    return found
def save(path,text):path.write_text(text);return text
def adb(*args,check=True,timeout=35):
    r=subprocess.run([str(ROOT/'dev/adb'),'-s',SERIAL,*map(str,args)],text=True,errors='replace',
                     stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
    r.stdout=r.stdout.replace('\r','')
    if check and r.returncode:raise RuntimeError(r.stdout)
    return r
audit_lock=threading.Lock()
def root(command,check=True,timeout=35):
    started=time.time_ns()
    wrapped='printf "__S223_SHELL_PID=%s\\n" "$$"; '+command
    r=adb('shell','su','-c',shlex.quote(wrapped),check=False,timeout=timeout)
    match=re.search(r'^__S223_SHELL_PID=(\d+)\n',r.stdout,re.M)
    shell_pid=int(match.group(1)) if match else None
    if match:r.stdout=r.stdout[:match.start()]+r.stdout[match.end():]
    with audit_lock:
        with (a.output/'root-commands.jsonl').open('a') as log:
            log.write(json.dumps(dict(started_ns=started,completed_ns=time.time_ns(),shell_pid=shell_pid,command=command,returncode=r.returncode))+'\n')
    if check and r.returncode:raise RuntimeError(r.stdout)
    return r
def cli_exchange(socket_path,commands):
    # Do not queue quit behind a large snapshot: VPP may discard still-pending
    # nonblocking socket output when it processes quit. Drain an explicit echo
    # marker first, with stdin kept open, then close the session.
    marker='S223_CLI_DONE_'+str(time.time_ns())
    shell='exec toybox nc -U -w 15 '+shlex.quote(socket_path)
    process=subprocess.Popen([str(ROOT/'dev/adb'),'-s',SERIAL,'shell','-T','su','-c',shlex.quote(shell)],
                             stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
    started=time.time_ns();data=b'';complete=False
    try:
        process.stdin.write(('\n'.join(['set terminal pager off',*commands,'echo '+marker])+'\n').encode());process.stdin.flush()
        end=time.monotonic()+30
        while time.monotonic()<end:
            if not selector.select(min(1,max(0,end-time.monotonic()))):continue
            chunk=os.read(process.stdout.fileno(),65536)
            if not chunk:break
            data+=chunk
            if b'\n'+marker.encode()+b'\n' in data.replace(b'\r',b''):
                complete=True;break
        if not complete:raise RuntimeError('incomplete CLI response '+data.decode(errors='replace')[-1000:])
        process.stdin.write(b'quit\n');process.stdin.flush()
        remaining,_=process.communicate(timeout=5);data+=remaining
        if process.returncode:raise RuntimeError(data.decode(errors='replace'))
        return data.decode(errors='replace').replace('\r','')
    finally:
        if process.poll() is None:process.terminate();process.wait(timeout=5)
        selector.close()
        with audit_lock:
            with (a.output/'root-commands.jsonl').open('a') as log:
                log.write(json.dumps(dict(kind='cli',started_ns=started,completed_ns=time.time_ns(),
                    command=shell,commands=list(commands),returncode=process.returncode,marker_complete=complete))+'\n')
def action(*args):return adb('shell','am','start','-n',PKG+'/.DebugControlActivity',*args).stdout
def app(path):return adb('shell','run-as',PKG,'cat',path,check=False).stdout
STATE='files/runtime-state/snapshot.properties'
p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();a.build=a.build.resolve();a.output=a.output.resolve();a.output.mkdir(parents=True,exist_ok=False)
build=json.loads(a.build.read_text());apk=Path(build['apk']);helpers=a.build.parent/'helpers'
assert digest(apk)==build['apk_sha256']
for name,value in build['s221_helpers'].items():assert digest(a.build.parent/name)==value,name
udp_helper=a.build.parent/'s223-helper'
helper=json.loads((udp_helper/'helper.json').read_text())
assert helper['build_sha256']==digest(a.build)
for name,value in helper['files'].items():assert digest(udp_helper/name)==value,name
result=dict(status='HOLD',source='NFQ_CAPTURED',platform='pixel',serial=SERIAL,
            started_ns=time.time_ns(),build=str(a.build),build_sha256=digest(a.build),
            runner_sha256=digest(__file__),source_sha256=build['source_sha256'],
            helper_manifest_sha256=digest(udp_helper/'helper.json'),runs=[])
before=save(a.output/'before.properties',app(STATE))
assert props(before).get('mayBeActive')=='false' and props(before).get('state')=='stopped',before
processes=save(a.output/'processes-before.txt',adb('shell','ps','-A','-o','PID,NAME,ARGS').stdout)
assert not native_processes(processes),processes
wifi=adb('shell','settings','get','global','wifi_on').stdout.strip();result['wifi_before']=wifi
save(a.output/'device.txt',adb('shell','getprop','ro.product.device').stdout+adb('shell','uname','-a').stdout)
save(a.output/'install.txt',adb('install','-r',apk,timeout=60).stdout)
package=save(a.output/'package.txt',adb('shell','dumpsys','package',PKG).stdout)
native=re.search(r'codePath=(\S+)',package).group(1)+'/lib/arm64'
installed=save(a.output/'installed-native-sha256.txt',adb('shell','sha256sum',*[native+'/'+n for n in sorted(build['native_sha256'])]).stdout)
assert {Path(l.split()[1]).name:l.split()[0] for l in installed.splitlines()}==build['native_sha256']
installed_apk=save(a.output/'installed-apk-sha256.txt',adb('shell','sha256sum',native.removesuffix('/lib/arm64')+'/base.apk').stdout)
assert installed_apk.split()[0]==build['apk_sha256']
result['apk_sha256']=build['apk_sha256'];result['native_sha256']=build['native_sha256']
uid=adb('shell','run-as',PKG,'id','-u').stdout.strip();assert uid.isdigit();result['uid']=uid
save(a.output/'foreground.txt',action())
assert props(app(STATE)).get('mayBeActive')=='false'
# The Activity's initial idle QUERY service must retire before a separately
# owned native diagnostic starts, matching the existing device runner boundary.
deadline=time.monotonic()+20
while time.monotonic()<deadline:
    services=save(a.output/'foreground-services.txt',adb('shell','dumpsys','activity','services',PKG).stdout)
    if not any('ServiceRecord{' in line and '.RuntimeService' in line for line in services.splitlines()):break
    time.sleep(.2)
else:raise RuntimeError('foreground idle query did not retire')
temporary=adb('shell','mktemp','-d','/data/local/tmp/s223-flow.XXXXXX').stdout.strip()
assert re.fullmatch(r'/data/local/tmp/s223-flow\.[A-Za-z0-9]+',temporary),temporary
result['device_temporary']=temporary
host={4:'127.0.0.2',6:'fd20:6223::2'};added=False;app_active=False
seeds=[(family,31000+i) for family in (4,6) for i in range(8)]

def wait_app(label,expected):
    end=time.monotonic()+60
    while time.monotonic()<end:
        text=save(a.output/(label+'.properties'),app(STATE));state=props(text)
        if all(state.get(k)==v for k,v in expected.items()):return state
        if state.get('errorCode')=='root_authorization_required':raise RuntimeError('Restore the app KernelSU Superuser grant')
        time.sleep(.3)
    raise RuntimeError(label+' '+text)

try:
    for name in ('s223-udp','s217-policy'):
        save(a.output/(name+'-push.txt'),adb('push',(udp_helper if name=='s223-udp' else helpers)/name,temporary+'/'+name).stdout)
        root('chmod 755 '+shlex.quote(temporary+'/'+name))
        actual=save(a.output/(name+'-installed.txt'),root('sha256sum '+shlex.quote(temporary+'/'+name)).stdout)
        assert actual.split()[0]==(helper['files'][name] if name=='s223-udp' else build['s221_helpers']['helpers/'+name])
    addresses=root('ip -6 addr show dev lo').stdout
    if host[6] not in addresses:
        root('ip -6 addr add '+host[6]+'/128 dev lo nodad');added=True
    initial_hooks=save(a.output/'hooks-before.txt',root('iptables-save -t mangle; ip6tables-save -t mangle').stdout)
    assert 'SAKAMOTO_S223_' not in initial_hooks
    for index,(label,capacity) in enumerate([('output',64),('input',64)]):
        run=a.output/label;run.mkdir();generation=22410+index
        record=dict(label=label,generation=generation,capacity=capacity,hook=label.upper(),cases=[],launch='installed-native-startup-config')
        result['runs'].append(record);runtime=temporary+'/'+label
        adb('shell','mkdir','-p',runtime+'/runtime',runtime+'/shm')
        config=f'''plugin_path {native}
cpu {{ main-core 0 corelist-workers 1-2 }}
unix {{ nodaemon nobanner cli-no-pager runtime-dir {runtime}/runtime cli-listen {runtime}/runtime/cli.sock }}
socksvr {{ socket-name {runtime}/runtime/api.sock }}
api-segment {{ prefix sakamoto-s223-{generation} }}
statseg {{ socket-name {runtime}/runtime/statseg.sock }}
plugins {{ path {native} plugin default {{ disable }} plugin libproduct_core_plugin.so {{ enable }} }}
product-flow-runtime {{ entries {capacity} }}
'''
        save(run/'startup.conf',config);adb('push',run/'startup.conf',runtime+'/startup.conf')
        environment=dict(LD_LIBRARY_PATH=native,SAKAMOTO_PRODUCT_GENERATION=str(generation),
                         SAKAMOTO_RUNTIME_PROFILE='root',SAKAMOTO_PRODUCT_ROOT_NFQUEUE_QUEUE='176',
                         SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4',SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID=uid,
                         SAKAMOTO_VPP_SVM_DIR=runtime+'/shm',SAKAMOTO_VPP_RUNTIME_DIR=runtime+'/runtime',
                         SAKAMOTO_VPP_OWNER_TOKEN='s223-native-'+str(generation))
        # Android package paths contain '='; toybox env can interpret that
        # executable path as another assignment. Match RuntimeService exports.
        launch='; '.join('export '+shlex.quote(k+'='+v) for k,v in environment.items())+'; exec '+shlex.quote(native+'/libvpp_runtime.so')+' -c '+shlex.quote(runtime+'/startup.conf')
        save(run/'launch.txt',launch+'\n')
        pid=root(launch+' > '+shlex.quote(runtime+'/vpp.log')+' 2>&1 < /dev/null & echo $!').stdout.strip()
        assert pid.isdigit(),pid
        endpoint_pids=[];rules=[]
        def remove_rules():
            while rules:
                removal=list(rules[-1]);removal[5]='-D';root(shlex.join(removal));rules.pop()
        def cli(name,*commands):
            return save(run/(name+'.txt'),cli_exchange(runtime+'/runtime/cli.sock',commands))
        def drain(name):
            end=time.monotonic()+25
            while time.monotonic()<end:
                state=rows(cli(name,'show product completion'),'completion.status ')
                if len(state)==1 and all(state[0][k]=='0' for k in ('pending','frames','buffers','obligations')):return
                time.sleep(.05)
            raise RuntimeError('completion drain timeout')
        def policy(revision,mode):
            command='env '+shlex.quote('LD_LIBRARY_PATH='+native)+' '+shlex.join([temporary+'/s217-policy',runtime+'/runtime/api.sock',str(generation),runtime+'/policy',str(revision),str(mode),uid,'0'])
            r=root(command,check=False);save(run/f'policy-{revision}.txt',r.stdout)
            assert r.returncode==0 and 'policy rc=0 ' in r.stdout,r.stdout
        def execute_probe(n,case):
            family=case['family'];number=case['number'];nonce=case['nonce']
            wait_ms=2000 if case['blocked'] else 35000
            loopback='127.0.0.1' if family==4 else '::1'
            source,destination=(host[family],loopback) if case['phase']=='reverse-first' else (loopback,host[family])
            r=root(shlex.join([temporary+'/s223-udp','client',uid,str(family),
                source,str(number),destination,'40621',
                str(case['count']),nonce,str(int(case['echo'])),str(wait_ms)]),check=False,timeout=110)
            save(run/f'client-{n}.txt',r.stdout)
            case['returncode']=r.returncode;case['timeout_ms']=wait_ms
            if case['blocked']:assert r.returncode!=0 and 'endpoint ' not in r.stdout,(case,r.stdout)
            else:assert r.returncode==0 and len(rows(r.stdout,'endpoint '))==case['count'],(case,r.stdout)
        def endpoint_text():
            return root(shlex.join(['cat',*[runtime+f'/endpoint{family}-{side}.log'
                for family in (4,6) for side in (0,1)]])).stdout
        def probe_batch(specifications):
            pending=[]
            for family,number,phase,count,echo,blocked in specifications:
                n=len(record['cases']);nonce=f's223-{generation}-{phase}-{n}-{time.time_ns()}'
                case=dict(family=family,protocol='udp',number=number,phase=phase,nonce=nonce,
                    count=count,echo=echo,blocked=blocked)
                record['cases'].append(case);pending.append((n,case))
            with ThreadPoolExecutor(max_workers=8) as executor:
                futures=[executor.submit(execute_probe,n,case) for n,case in pending]
                for future in futures:future.result()
            deadline=time.monotonic()+40
            while time.monotonic()<deadline:
                received=rows(endpoint_text(),'received ')
                if all(sum(x['nonce'].startswith(case['nonce']+'-') for x in received)
                    ==(0 if case['blocked'] else case['count']) for _,case in pending):break
                time.sleep(.2)
            else:raise RuntimeError('independent endpoint receive accounting failed')
            print(label,specifications[0][2],len(specifications),'cases complete',flush=True)
        def snapshot(name,phase,packets):
            drain(name+'-drain');text=cli(name,'show product flows')
            entries=rows(text,'flow.entry ');udp=rows(text,'flow.udp ')
            for family,number in seeds:
                matches=[e for e in entries if int(e['family'])==family
                    and number in (int(e['port_a']),int(e['port_b']))]
                assert len(matches)==1,(name,family,number,matches)
                e=matches[0];u=next(x for x in udp if x['worker']==e['worker'] and x['slot']==e['slot'])
                assert int(u['phase'])==phase and int(e['packets'])==packets,(name,e,u)
            return text
        try:
            deadline=time.monotonic()+25
            while time.monotonic()<deadline:
                ready=root('test -S '+shlex.quote(runtime+'/runtime/cli.sock'),check=False)
                if ready.returncode==0:
                    lanes=rows(cli('ready','show product root lanes'),'root.lane ')
                    if len(lanes)==4 and all(x['ready']=='1' for x in lanes):break
                alive=root('kill -0 '+pid,check=False)
                assert alive.returncode==0,root('cat '+shlex.quote(runtime+'/vpp.log')).stdout
                time.sleep(.1)
            else:raise RuntimeError('Product startup timeout '+root('cat '+shlex.quote(runtime+'/vpp.log')).stdout)
            cli('initial','show product flows','show product root lanes','show threads','product packet-trace limit 4096')
            assert all(int(x['capacity'])==capacity for x in rows((run/'initial.txt').read_text(),'flow.runtime '))
            cli('live-resize-rejected','product flow capacity 7')
            assert 'require stopped' in (run/'live-resize-rejected.txt').read_text()
            save(run/'queues-busy.txt',root('cat /proc/net/netfilter/nfnetlink_queue').stdout)
            for family in (4,6):
                for side,address in enumerate((host[family],'127.0.0.1' if family==4 else '::1')):
                    endpoint_pid=root(shlex.join([temporary+'/s223-udp','server',uid,str(family),
                        address,'40621'])+' > '+shlex.quote(runtime+f'/endpoint{family}-{side}.log')+' 2>&1 < /dev/null & echo $!').stdout.strip()
                    assert endpoint_pid.isdigit();endpoint_pids.append(endpoint_pid)
            deadline=time.monotonic()+5
            while endpoint_text().count('listen ')<4:
                assert time.monotonic()<deadline
                time.sleep(.05)
            baseline=root(shlex.join([temporary+'/s223-udp','client',uid,'4','127.0.0.1',
                str(29990+index),host[4],'40621','1',f's223-{generation}-unhooked','1','2000']))
            save(run/'unhooked-endpoint.txt',baseline.stdout)
            assert len(rows(baseline.stdout,'endpoint '))==1,'app endpoint unavailable before Product hooks'
            # Scoped loopback traffic only; retain every unrelated device rule.
            for family,tool,span in [(4,'iptables','176:177'),(6,'ip6tables','178:179')]:
                for hook in (label.upper(),):
                    for protocol in ('udp',):
                        for address_field in ('-s','-d'):
                            rule=[tool,'-w','5','-t','mangle','-A',hook,'-i' if hook=='INPUT' else '-o','lo',
                                  '-p',protocol,address_field,host[family],'-m','comment','--comment','SAKAMOTO_S223_'+label,
                                  '-j','NFQUEUE','--queue-balance',span]
                            root(shlex.join(rule));rules.append(rule)
            save(run/'hooks.txt',root('iptables-save -t mangle; ip6tables-save -t mangle').stdout)
            policy(1,0)
            probe_batch([(f,n,'first',1,False,False) for f,n in seeds]);snapshot('first',1,1)
            probe_batch([(f,n,'same',2,False,False) for f,n in seeds]);snapshot('same',2,3)
            policy(2,0)
            probe_batch([(f,n,'revision',1,False,False) for f,n in seeds]);snapshot('revision',2,4)
            probe_batch([(f,n,'bidir',1,True,False) for f,n in seeds]);snapshot('bidir',3,6)
            policy(3,1 if label=='output' else 0)
            if label=='output':probe_batch([(f,31000,'gate',1,True,True) for f in (4,6)])
            else:record['gate_scope']='not-app-attributable-input'
            snapshot('gate',3,6)
            policy(4,0)
            probe_batch([(f,n,'recovered',1,True,False) for f,n in seeds]);snapshot('recovered',3,8)
            probe_batch([(f,32000+i,'direct-bidir',1,True,False) for f in (4,6) for i in range(4)])
            probe_batch([(f,33000+i,'single-only',1,False,False) for f in (4,6) for i in range(2)])
            probe_batch([(f,34000+i,'same-only',3,False,False) for f in (4,6) for i in range(2)])
            probe_batch([(f,35000+i,'reverse-first',1,True,False) for f in (4,6) for i in range(4)])
            # Close admission before taking a multi-command final snapshot.
            # TCP close/ACK traffic may otherwise arrive between its commands.
            remove_rules()
            save(run/'quiesced-hooks.txt',root('iptables-save -t mangle; ip6tables-save -t mangle').stdout)
            drain('final-drain')
            cli('final','show product flows','show product root lanes','show product primary','show product completion',
                'show runtime','show threads','show node product-packet-policy','show node product-packet-origin-completion')
            record['raw_complete']=True
        finally:
            remove_rules()
            save(run/'hooks-after.txt',root('iptables-save -t mangle; ip6tables-save -t mangle').stdout)
            for endpoint_pid in endpoint_pids:root('kill '+endpoint_pid,check=False)
            save(run/'endpoint.log',endpoint_text())
            try:
                if (root('kill -0 '+pid,check=False).returncode==0
                    and root('test -S '+shlex.quote(runtime+'/runtime/cli.sock'),check=False).returncode==0):
                    drain('stop-drain');save(run/'fds-before.txt',root('ls -l /proc/'+pid+'/fd').stdout)
                    assert 'root.stop=ok' in cli('stop','product root stop')
                    closed=cli('closed','show product flows','show product root lanes','show product primary','show product completion')
                    assert all(x['entries']=='0' for x in rows(closed,'flow.pool '))
                    save(run/'fds-closed.txt',root('ls -l /proc/'+pid+'/fd').stdout)
                    queues=save(run/'queues-free.txt',root('cat /proc/net/netfilter/nfnetlink_queue').stdout)
                    assert not any(int(line.split()[0]) in range(176,180) for line in queues.splitlines() if line.strip())
            finally:
                root('kill '+pid,check=False)
                deadline=time.monotonic()+10
                while root('test -d /proc/'+pid,check=False).returncode==0 and time.monotonic()<deadline:time.sleep(.1)
                absent=root('test -d /proc/'+pid,check=False).returncode!=0
                save(run/'vpp.log',root('cat '+shlex.quote(runtime+'/vpp.log'),check=False).stdout)
                save(run/'stop.json',json.dumps(dict(pid=int(pid),process_absent=absent)))
                assert absent,'owned native process survived termination'
        print(label,'complete',len(record['cases']),'endpoint cases',flush=True)
    # Separate ordinary RuntimeService smoke, using the same installed APK.
    adb('shell','pm','grant',PKG,'android.permission.POST_NOTIFICATIONS',check=False)
    if wifi=='1':adb('shell','svc','wifi','disable');time.sleep(2)
    save(a.output/'app-start.txt',action('--ez','runtimeStart','true','--es','runtimeProfile','root'));app_active=True
    running=wait_app('app-running',{'state':'running','protectionRunning':'true'})
    result['app_generation']=running['generation']
    save(a.output/'app-empty-policy.txt',action('--ez','debugApplyEmptyPolicy','true'))
    time.sleep(.5)
    base='/data/user/0/'+PKG+'/files/profiles/root/vpp/'
    commands=['show product flows','show product root lanes','show product completion']
    save(a.output/'app-runtime.txt',cli_exchange(base+'runtime/cli.sock',commands))
    assert all(x['capacity']=='1024' for x in rows((a.output/'app-runtime.txt').read_text(),'flow.runtime '))
    save(a.output/'app-stop.txt',action('--ez','runtimeStop','true'))
    wait_app('app-stopped',{'state':'stopped','mayBeActive':'false','errorCode':''});app_active=False
    cleanup=save(a.output/'app-cleanup.properties',app('files/product-state/s176-root-nfqueue-cleanup.properties'))
    assert 'productRootNfqueueResidueClean=true' in cleanup
    result['status']='RAW_COMPLETE'
except Exception as error:
    result['error']=repr(error);raise
finally:
    if app_active:
        save(a.output/'failure-app-stop.txt',action('--ez','runtimeStop','true'))
        wait_app('failure-app-stopped',{'state':'stopped','mayBeActive':'false'})
    if added:root('ip -6 addr del '+host[6]+'/128 dev lo',check=False)
    if wifi=='1':adb('shell','svc','wifi','enable',check=False)
    result['wifi_after']=adb('shell','settings','get','global','wifi_on').stdout.strip()
    save(a.output/'processes-after.txt',adb('shell','ps','-A','-o','PID,NAME,ARGS').stdout)
    save(a.output/'hooks-after.txt',root('iptables-save -t mangle; ip6tables-save -t mangle').stdout)
    result['completed_ns']=time.time_ns();save(a.output/'result.json',json.dumps(result,indent=2)+'\n')
    # Keep the unique device directory for failure inspection; its exact path
    # is in result.json. No process, hook, socket or address may remain active.
