#!/usr/bin/env python3
"""Real kernel TCP through Product NFQUEUE on Linux or an installed Pixel APK.

Raw invalid packets target only this test's loopback connections. Normal,
retransmit, midstream, FIN and RST cases use kernel TCP sockets, not graph input.
"""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import struct
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parents[2]
PKG='com.sakamoto.snort.androidruntime'
ADB=[str(ROOT/'dev/adb'),'-s','28201JEGR0XPAJ']
HOST={4:'127.0.0.2',6:'fd20:6222::2'}
SOURCE={4:'127.0.0.1',6:'::1'}
PORT=40622
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def fields(line): return dict(re.findall(r'(\w+)=([^\s]+)',line))
def rows(text,prefix): return [fields(line) for line in text.splitlines() if line.startswith(prefix)]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

def queue_bind(queue):
    # Rootless user namespaces cannot necessarily read procfs queue listings.
    # A real bind/ACK probes whether the Product released that exact queue.
    with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12) as descriptor:
        descriptor.bind((0,0));descriptor.settimeout(2)
        payload=struct.pack('!BBH',0,0,queue)+struct.pack('HH',8,1)+struct.pack('!BBH',1,0,2)
        descriptor.send(struct.pack('IHHII',16+len(payload),0x302,5,1,0)+payload)
        reply=descriptor.recv(4096)
        assert struct.unpack_from('H',reply,4)[0]==2
        return struct.unpack_from('i',reply,16)[0]

p=argparse.ArgumentParser();p.add_argument('--platform',choices=['linux','pixel'],required=True)
p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();a.build=a.build.resolve();a.output=a.output.resolve();a.output.mkdir(parents=True,exist_ok=False)
build=json.loads(a.build.read_text());chain=module('chain','tests/evidence/product_chain.py')
assert chain.source_files()==build['files'],'Product build is stale'
oracle=module('owner','tests/device/s207-owner-oracle.py')
helper_dir=a.build.parent/'s222-helper';helper=json.loads((helper_dir/'helper.json').read_text())
assert helper['build_sha256']==digest(a.build)
for name,value in helper['files'].items(): assert digest(helper_dir/name)==value
result=dict(status='HOLD',platform=a.platform,source='NFQ_CAPTURED',build_sha256=digest(a.build),
            source_sha256=build['source_sha256'],helper_sha256=digest(helper_dir/'helper.json'),
            started_ns=time.time_ns(),runs=[])
test_files=['tests/device/s222-tcp.py','tests/device/helpers/s222-tcp.c','tests/device/s207-owner-oracle.py','tests/evidence/build_s222_helper.py']
result['test_inputs']={name:digest(ROOT/name) for name in test_files}
for name in test_files:
    target=a.output/'test-source'/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,target)
def save(name,text): (a.output/name).write_text(text);return text
def adb(*args,check=True):
    r=subprocess.run(ADB+list(map(str,args)),capture_output=True,text=True,errors='replace',timeout=35)
    r.stdout=(r.stdout+r.stderr).replace('\r','')
    if check and r.returncode: raise RuntimeError(r.stdout)
    return r

class Backend:
    def __init__(self): self.children=[];self.logs=[];self.environment=dict(os.environ)
    def command(self,argv,check=True): return self.shell(shlex.join(list(map(str,argv))),check)
    def shell(self,text,check=True):
        start=time.time_ns()
        r=(adb('shell','su','-c',shlex.quote(text),check=False) if a.platform=='pixel' else
           subprocess.run(['sh','-c',text],capture_output=True,text=True,env=self.environment,timeout=35))
        if a.platform=='linux': r.stdout+=r.stderr
        with (a.output/'commands.jsonl').open('a') as log:
            log.write(json.dumps(dict(started_ns=start,completed_ns=time.time_ns(),command=text,returncode=r.returncode))+'\n')
        if check and r.returncode: raise RuntimeError(text+'\n'+r.stdout)
        return r
    def read(self,path): return self.command(['cat',path],False).stdout
    def put(self,path,text):
        if a.platform=='linux': Path(path).write_text(text)
        else:
            local=a.output/'transfer.txt';local.write_text(text)
            # adb's shell UID cannot write root-owned runtime subdirectories.
            adb('push',local,base+'/transfer.conf');self.command(['cp',base+'/transfer.conf',path])
    def stat(self,pid):
        text=self.read(f'/proc/{pid}/stat')
        return text.split(') ',1)[1].split()[19] if ') ' in text else None
    def spawn(self,argv,log,environment=None):
        env=dict(self.environment,**(environment or {}))
        if a.platform=='linux':
            stream=open(log,'w');self.logs.append(stream)
            process=subprocess.Popen(list(map(str,argv)),env=env,stdout=stream,stderr=subprocess.STDOUT)
            child=dict(pid=process.pid,process=process)
        else:
            exports='; '.join('export '+shlex.quote(k+'='+str(v)) for k,v in (environment or {}).items())
            launch=(exports+'; ' if exports else '')+'exec '+shlex.join(list(map(str,argv)))
            pid=self.shell('( '+launch+' ) >'+shlex.quote(str(log))+' 2>&1 </dev/null & echo $!').stdout.strip()
            assert pid.isdigit(),pid
            child=dict(pid=int(pid),process=None)
        child['start']=self.stat(child['pid']);self.children.append(child);return child
    def alive(self,child):
        if child['process'] is not None: return child['process'].poll() is None
        current=self.stat(child['pid'])
        if current is None: return False
        assert current==child['start'],'PID identity changed'
        return True
    def stop(self,child):
        if child['process'] is not None:
            process=child['process']
            if process.poll() is None: process.terminate()
            try: process.wait(timeout=8)
            except subprocess.TimeoutExpired: process.kill();process.wait(timeout=5)
        elif self.alive(child):
            self.command(['kill',str(child['pid'])],False)
            deadline=time.monotonic()+8
            while self.alive(child) and time.monotonic()<deadline: time.sleep(.1)
            if self.alive(child): self.command(['kill','-9',str(child['pid'])],False);time.sleep(.2)
        assert not self.alive(child),'owned process survived stop'
    def cli(self,socket,commands):
        if a.platform=='linux':
            return ''.join(self.command([vppctl,'-s',socket,c]).stdout for c in commands)
        marker='S222_DONE_'+str(time.time_ns())
        command='toybox nc -U -w 20 '+shlex.quote(socket)
        process=subprocess.Popen(ADB+['shell','-T','su','-c',shlex.quote(command)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        import select
        text=b''
        try:
            process.stdin.write(('\n'.join(['set terminal pager off',*commands,'echo '+marker])+'\n').encode());process.stdin.flush()
            deadline=time.monotonic()+25
            while time.monotonic()<deadline:
                if not select.select([process.stdout],[],[],.2)[0]: continue
                chunk=os.read(process.stdout.fileno(),65536)
                if not chunk: break
                text+=chunk
                if b'\n'+marker.encode()+b'\n' in text.replace(b'\r',b''): break
            else: raise RuntimeError('CLI deadline')
            assert marker.encode() in text,'CLI response truncated'
            process.stdin.write(b'quit\n');process.stdin.flush();rest,_=process.communicate(timeout=5);text+=rest
            return text.decode(errors='replace').replace('\r','')
        finally:
            if process.poll() is None: process.terminate();process.wait(timeout=5)

b=Backend();added=False;temporary=None;rules=[];filter_rules=[]
def remove_rules(collection):
    while collection:
        rule=list(collection[-1]);rule[rule.index('-A')]='-D';b.command(rule);collection.pop()
try:
    if a.platform=='linux':
        uid_map=Path('/proc/self/uid_map').read_text().split()
        assert os.getuid()==0 and len(uid_map)==3 and uid_map[0]=='0' and uid_map[1]!='0' and uid_map[2]=='1'
        save('uid-map.txt',' '.join(uid_map));save('device.txt',b.command(['uname','-a']).stdout)
        temporary=tempfile.TemporaryDirectory(prefix='s222-native-');base=temporary.name
        artifact=Path(build['artifact'])
        for name,value in build['artifact_hashes'].items(): assert digest(artifact/name)==value
        executable=str(artifact/'bin/vpp');libraries=str(artifact/'lib');plugins=libraries+'/vpp_plugins'
        plugin='product_core_plugin.so';endpoint=str(helper_dir/'s222-tcp')
        vppctl=str(Path(build['stage'])/'source/build-root/install-vpp-native/vpp/bin/vppctl')
        b.environment['LD_LIBRARY_PATH']=libraries
        b.command(['ip','link','set','lo','up'])
    else:
        state=adb('shell','run-as',PKG,'cat','files/runtime-state/snapshot.properties').stdout
        assert 'mayBeActive=false' in state,'existing runtime must be stopped'
        save('previous-state.txt',state);save('install.txt',adb('install','-r',build['apk']).stdout)
        package=save('package.txt',adb('shell','dumpsys','package',PKG).stdout)
        code=re.search(r'codePath=(\S+)',package).group(1)
        assert save('installed-apk.txt',adb('shell','sha256sum',code+'/base.apk').stdout).split()[0]==build['apk_sha256']
        libraries=code+'/lib/arm64';plugins=libraries;plugin='libproduct_core_plugin.so';executable=libraries+'/libvpp_runtime.so'
        actual=save('installed-native.txt',adb('shell','sha256sum',*[libraries+'/'+name for name in sorted(build['native_sha256'])]).stdout)
        assert {Path(line.split()[1]).name:line.split()[0] for line in actual.splitlines()}==build['native_sha256']
        base=adb('shell','mktemp','-d','/data/local/tmp/s222-XXXXXX').stdout.strip()
        assert re.fullmatch('/data/local/tmp/s222-[A-Za-z0-9]+',base),base
        result['device_directory']=base;endpoint=base+'/s222-tcp';adb('push',helper_dir/'s222-tcp',endpoint);b.command(['chmod','755',endpoint])
        assert b.command(['sha256sum',endpoint]).stdout.split()[0]==helper['files']['s222-tcp']
        save('device.txt',adb('shell','uname','-a').stdout)
    if HOST[6] not in b.command(['ip','-6','addr','show','dev','lo']).stdout:
        b.command(['ip','-6','addr','add',HOST[6]+'/128','dev','lo','nodad']);added=True
    save('hooks-before.txt',b.command(['iptables-save','-t','mangle']).stdout+b.command(['ip6tables-save','-t','mangle']).stdout)
    used=set()
    def source_port(family,owner):
        for port in range(44000,45000):
            if (family,port) in used: continue
            facts=dict(l3=1,l4=1,family=family,protocol=6,
                       src=ipaddress.ip_address(SOURCE[family]).packed.rjust(16,b'\0').hex(),
                       dst=ipaddress.ip_address(HOST[family]).packed.rjust(16,b'\0').hex(),
                       src_port=port,dst_port=PORT,icmp_known=0)
            if oracle.owner(facts)==owner: used.add((family,port));return port
        raise RuntimeError('source-port oracle exhausted')
    for index,label in enumerate(['normal','restart']):
        run=a.output/label;run.mkdir();runtime=base+'/'+label
        b.command(['mkdir','-p',runtime+'/runtime',runtime+'/shm'])
        generation=(22220 if a.platform=='linux' else 22230)+index
        record=dict(label=label,generation=generation,cases=[]);result['runs'].append(record)
        cpu='workers 2' if a.platform=='linux' else 'main-core 0 corelist-workers 1-2'
        config=f'''cpu {{ {cpu} }}
unix {{ nodaemon cli-no-pager runtime-dir {runtime}/runtime cli-listen {runtime}/runtime/cli.sock }}
socksvr {{ socket-name {runtime}/runtime/api.sock }}
api-segment {{ prefix sakamoto-s222-{generation} }}
statseg {{ socket-name {runtime}/runtime/statseg.sock }}
plugins {{ path {plugins} plugin default {{ disable }} plugin {plugin} {{ enable }} }}
product-flow-runtime {{ entries 128 }}
'''
        (run/'startup.conf').write_text(config);b.put(runtime+'/startup.conf',config)
        env=dict(LD_LIBRARY_PATH=libraries,SAKAMOTO_PRODUCT_GENERATION=str(generation),SAKAMOTO_RUNTIME_PROFILE='root',
                 SAKAMOTO_PRODUCT_ROOT_NFQUEUE_QUEUE='176',SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4',
                 SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0',SAKAMOTO_VPP_RUNTIME_DIR=runtime+'/runtime',
                 SAKAMOTO_VPP_SVM_DIR=runtime+'/shm',SAKAMOTO_VPP_OWNER_TOKEN='s222-native-'+str(generation))
        record['launch_environment']=env
        process=b.spawn([executable,'-c',runtime+'/startup.conf'],runtime+'/vpp.log',env);record['pid']=process['pid']
        server=None
        def cli(name,*commands): return save(Path(label)/(name+'.txt'),b.cli(runtime+'/runtime/cli.sock',commands))
        def drain(name):
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                status=rows(cli(name,'show product completion'),'completion.status ')
                if len(status)==1 and all(status[0][k]=='0' for k in ('pending','frames','buffers','obligations')): return
                time.sleep(.05)
            raise RuntimeError('native completion did not drain')
        def captures():
            for family in (4,6):
                tool='iptables' if family==4 else 'ip6tables';span='176:177' if family==4 else '178:179'
                for hook in ('OUTPUT','INPUT'):
                    for reply in (False,True):
                        src,dst=(HOST[family],SOURCE[family]) if reply else (SOURCE[family],HOST[family])
                        rule=[tool,'-w','5','-t','mangle','-A',hook,'-s',src,'-d',dst,'-p','tcp',
                              '--sport' if reply else '--dport',str(PORT)+':'+str(PORT+1),'-j','NFQUEUE','--queue-balance',span]
                        b.command(rule);rules.append(rule)
        def drop_input(family,port,syn_only=False):
            rule=['iptables' if family==4 else 'ip6tables','-w','5','-t','filter','-A','INPUT',
                  '-s',SOURCE[family],'-d',HOST[family],'-p','tcp','--sport',str(port),'--dport',str(PORT)]
            if syn_only: rule+=['--tcp-flags','SYN,ACK','SYN']
            rule+=['-j','DROP'];b.command(rule);filter_rules.append(rule)
        def raw(family,port,flags,seq,ack,window=8192,length=1):
            return b.command([endpoint,'raw',family,SOURCE[family],port,HOST[family],PORT,flags,seq,ack,window,length]).stdout
        def probe(family,owner,mode,port=None):
            port=port or source_port(family,owner);case_index=len(record['cases']);nonce=f's222-{generation}-{case_index}-{time.time_ns()}'
            case=dict(family=family,owner=owner,mode=mode,source=port,destination=PORT,nonce=nonce);record['cases'].append(case)
            log=runtime+f'/client-{case_index}.log';gate=runtime+f'/gate-{case_index}' if mode in ('midstream','invalid') else '-'
            if mode=='invalid-new':
                drop_input(family,port);case['raw']=raw(family,port,18,123,456,length=0);drain('invalid-new-drain');remove_rules(filter_rules);return
            if mode=='midstream': remove_rules(rules);drain('midstream-quiesce')
            if mode=='retransmit': drop_input(family,port,True)
            client_mode='rst' if mode=='rst' else 'refused' if mode=='refused' else 'fin'
            destination=PORT+1 if mode=='refused' else PORT;case['destination']=destination
            child=b.spawn([endpoint,'client',family,SOURCE[family],port,HOST[family],destination,client_mode,nonce,gate],log)
            if mode=='retransmit':
                time.sleep(1.4);save(Path(label)/f'retransmit-{case_index}.log',b.read(runtime+'/vpp.log'));remove_rules(filter_rules)
            deadline=time.monotonic()+25
            if gate!='-':
                while 'connected ' not in b.read(log):
                    assert b.alive(child),'client exited before gate'
                    if time.monotonic()>deadline: raise RuntimeError('connection gate deadline')
                    time.sleep(.1)
                if mode=='midstream': captures()
                else:
                    trace=b.read(runtime+'/vpp.log');save(Path(label)/f'before-invalid-{case_index}.log',trace)
                    packets=rows(trace,'s216 stage=admit ')
                    outgoing=[x for x in packets if x.get('src_port')==str(port) and x.get('dst_port')==str(PORT) and int(x['tcp_flags'])&2]
                    incoming=[x for x in packets if x.get('src_port')==str(PORT) and x.get('dst_port')==str(port) and int(x['tcp_flags'])&2]
                    assert outgoing and incoming,'actual handshake trace missing'
                    seq=(int(outgoing[-1]['tcp_seq'])+1)&0xffffffff;ack=(int(incoming[-1]['tcp_seq'])+1)&0xffffffff
                    case['raw_sequence']=raw(family,port,16,(seq+0x40000000)&0xffffffff,ack)
                    case['raw_ack']=raw(family,port,16,seq,(ack+0x40000000)&0xffffffff)
                b.command(['touch',gate])
            while True:
                text=b.read(log)
                if 'client_closed ' in text or 'refused ' in text: break
                if not b.alive(child):
                    # The client may finish between reading its partial log and
                    # observing process exit. Re-read the now-final file.
                    text=b.read(log)
                    if 'client_closed ' in text or 'refused ' in text: break
                    raise RuntimeError(text or 'client exited without result')
                if time.monotonic()>deadline: raise RuntimeError(text or 'client deadline')
                time.sleep(.1)
            save(Path(label)/f'client-{case_index}.log',text)
            assert text.count('received ')==(0 if mode=='refused' else 3),text
            b.stop(child);drain('case-drain');time.sleep(.1)
            cli(f'case-{case_index}','show product flows')
        try:
            deadline=time.monotonic()+25
            while time.monotonic()<deadline:
                assert b.alive(process),'native startup exited'
                if b.command(['test','-S',runtime+'/runtime/cli.sock'],False).returncode==0:
                    ready=cli('ready','show product root lanes','show threads')
                    if len(rows(ready,'root.lane '))==4 and all(x.get('ready')=='1' for x in rows(ready,'root.lane ')): break
                time.sleep(.1)
            else: raise RuntimeError('native ready deadline')
            cli('trace-limit','product packet-trace limit 4096')
            server=b.spawn([endpoint,'server',PORT,HOST[4],HOST[6]],runtime+'/endpoint.log')
            deadline=time.monotonic()+5
            while b.read(runtime+'/endpoint.log').count('listen ')!=2:
                assert b.alive(server) and time.monotonic()<deadline,'server startup'
                time.sleep(.1)
            captures();save(Path(label)/'hooks.txt',b.command(['iptables-save','-t','mangle']).stdout+b.command(['ip6tables-save','-t','mangle']).stdout)
            for family in (4,6):
                for owner in (0,1):
                    probe(family,owner,'fin')
                    if label=='normal':
                        port=source_port(family,owner);probe(family,owner,'rst',port);probe(family,owner,'reuse',port)
                if label=='normal':
                    owner=0 if family==4 else 1
                    for mode in ('retransmit','midstream','invalid','invalid-new'): probe(family,owner,mode)
            remove_rules(rules);drain('final-drain')
            cli('final','show product flows','show product root lanes','show product completion','show runtime','show threads')
            record['raw_complete']=True
        finally:
            remove_rules(filter_rules);remove_rules(rules)
            if server: b.stop(server)
            if b.alive(process):
                drain('stop-drain');save(Path(label)/'fds-before.txt',b.command(['ls','-l',f'/proc/{process["pid"]}/fd']).stdout)
                assert 'root.stop=ok' in cli('stop','product root stop')
                closed=cli('closed','show product flows','show product completion','show product root lanes')
                assert all(x['entries']=='0' for x in rows(closed,'flow.pool '))
                assert all(x[k]=='0' for x in rows(closed,'completion.status ') for k in ('pending','frames','buffers','obligations'))
                if a.platform=='linux':
                    available={q:queue_bind(q) for q in range(176,180)}
                    save(Path(label)/'queues-free.json',json.dumps(available))
                    assert all(status==0 for status in available.values())
                save(Path(label)/'fds-closed.txt',b.command(['ls','-l',f'/proc/{process["pid"]}/fd']).stdout)
                b.stop(process)
            save(Path(label)/'vpp.log',b.read(runtime+'/vpp.log'));save(Path(label)/'endpoint.log',b.read(runtime+'/endpoint.log'))
            save(Path(label)/'stop.json',json.dumps(dict(pid=process['pid'],process_absent=not b.alive(process))))
        print(label,'complete',len(record['cases']),'cases',flush=True)
    result['status']='RAW_COMPLETE'
except Exception as error:
    result['error']=repr(error);raise
finally:
    remove_rules(filter_rules);remove_rules(rules)
    for child in reversed(b.children):
        try: b.stop(child)
        except Exception as error: result.setdefault('cleanup_errors',[]).append(repr(error))
    if added: b.command(['ip','-6','addr','del',HOST[6]+'/128','dev','lo'],False)
    save('hooks-after.txt',b.command(['iptables-save','-t','mangle']).stdout+b.command(['ip6tables-save','-t','mangle']).stdout)
    save('queues-after.txt',b.read('/proc/net/netfilter/nfnetlink_queue'))
    for log in b.logs: log.close()
    if temporary: temporary.cleanup()
    result['completed_ns']=time.time_ns();save('result.json',json.dumps(result,indent=2)+'\n')
