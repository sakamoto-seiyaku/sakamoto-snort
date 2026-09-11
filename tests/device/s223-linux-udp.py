#!/usr/bin/env python3
"""S223 finite UDP state transitions on actual Linux NFQUEUE endpoints."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parents[2]
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def rows(text,prefix):
    return [dict(part.split('=',1) for part in line.split()[1:] if '=' in part)
            for line in text.splitlines() if line.startswith(prefix)]
def save(path,text):path.write_text(text);return text
def queue_bind(queue):
    with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12) as s:
        s.bind((0,0));s.settimeout(2)
        payload=struct.pack('!BBH',0,0,queue)+struct.pack('HH',8,1)+struct.pack('!BBH',1,0,2)
        s.send(struct.pack('IHHII',16+len(payload),0x302,5,1,0)+payload)
        reply=s.recv(4096)
        assert struct.unpack_from('H',reply,4)[0]==2
        return struct.unpack_from('i',reply,16)[0]

p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True)
p.add_argument('--output',type=Path,required=True);a=p.parse_args()
a.build=a.build.resolve();a.output=a.output.resolve();a.output.mkdir(parents=True,exist_ok=False)
build=json.loads(a.build.read_text());artifact=Path(build['artifact']);helpers=a.build.parent/'helpers'
assert not build['host_evidence']
for name,value in build['artifact_hashes'].items():assert digest(artifact/name)==value,name
for name,value in build['s221_helpers'].items():assert digest(a.build.parent/name)==value,name
udp_helper=a.build.parent/'s223-helper'
helper=json.loads((udp_helper/'helper.json').read_text())
assert helper['build_sha256']==digest(a.build)
for name,value in helper['files'].items():assert digest(udp_helper/name)==value,name
env=dict(os.environ,LD_LIBRARY_PATH=str(artifact/'lib')+':'+str(helpers))
def command(*argv,check=True):
    r=subprocess.run(list(map(str,argv)),env=env,text=True,stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT,timeout=25)
    if check and r.returncode:raise RuntimeError(str(argv)+'\n'+r.stdout)
    return r
assert os.getuid()==0
uid_map=Path('/proc/self/uid_map').read_text().split()
assert len(uid_map)==3 and uid_map[0]=='0' and uid_map[1]!='0' and uid_map[2]=='1'
save(a.output/'kernel.txt',command('uname','-a').stdout+command('id').stdout+'netns='+os.readlink('/proc/self/ns/net')+'\n')
save(a.output/'uid-map.txt',' '.join(uid_map)+'\n')
command('ip','link','set','lo','up')
host={4:'127.0.0.2',6:'fd20:6223::2'}
command('ip','-6','addr','add',host[6]+'/128','dev','lo','nodad')
vppctl=Path(build['stage'])/'source/build-root/install-vpp-native/vpp/bin/vppctl'
result=dict(status='HOLD',source='NFQ_CAPTURED',platform='linux',started_ns=time.time_ns(),
            build=str(a.build),build_sha256=digest(a.build),runner_sha256=digest(__file__),helper_manifest_sha256=digest(udp_helper/'helper.json'),
            source_sha256=build['source_sha256'],runs=[])
seeds=[(family,31000+i) for family in (4,6) for i in range(8)]
try:
    for run_index,(label,capacity) in enumerate([('output',64),('input',64)]):
        run=a.output/label;run.mkdir();generation=22310+run_index
        record=dict(label=label,generation=generation,capacity=capacity,hook=label.upper(),cases=[]);result['runs'].append(record)
        with tempfile.TemporaryDirectory(prefix='s223-runtime-') as temporary:
            runtime=Path(temporary)
            config=f'''cpu {{ workers 2 }}
unix {{ nodaemon cli-no-pager poll-sleep-usec 0 runtime-dir {runtime} cli-listen {runtime}/cli.sock }}
socksvr {{ socket-name {runtime}/api.sock }}
plugins {{ path {artifact}/lib/vpp_plugins plugin default {{ disable }} plugin product_core_plugin.so {{ enable }} }}
product-flow-runtime {{ entries {capacity} }}
'''
            configuration=run/'startup.conf';configuration.write_text(config)
            launch=dict(env,SAKAMOTO_PRODUCT_GENERATION=str(generation),SAKAMOTO_RUNTIME_PROFILE='root',
                        SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0',SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4')
            log=(run/'vpp.log').open('w');endpoint_log=(run/'endpoint.log').open('w')
            process=subprocess.Popen([str(artifact/'bin/vpp'),'-c',str(configuration)],env=launch,stdout=log,stderr=subprocess.STDOUT)
            endpoints=[];rules=[]
            def remove_rules():
                while rules:
                    removal=list(rules[-1]);removal[3]='-D';command(*removal);rules.pop()
            def cli(name,*commands):
                text=''.join(command(vppctl,'-s',runtime/'cli.sock',c).stdout for c in commands)
                return save(run/(name+'.txt'),text)
            def drain(name):
                end=time.monotonic()+15
                while time.monotonic()<end:
                    values=rows(cli(name,'show product completion'),'completion.status ')
                    if len(values)==1 and all(values[0][k]=='0' for k in ('pending','frames','buffers','obligations')):return
                    time.sleep(.02)
                raise RuntimeError('completion drain timeout')
            def policy(revision,mode):
                # NFQA_UID is reported in the initial user namespace, not
                # rewritten to this rootless namespace's effective UID 0.
                r=command(helpers/'s217-policy',runtime/'api.sock',generation,run/'policy',revision,mode,uid_map[1],0)
                save(run/f'policy-{revision}.txt',r.stdout)
            def probe(family,number,phase,count=1,echo=False,blocked=False):
                index=len(record['cases']);nonce=f's223-{generation}-{phase}-{index}-{time.time_ns()}'
                loopback='127.0.0.1' if family==4 else '::1'
                source,destination=(host[family],loopback) if phase=='reverse-first' else (loopback,host[family])
                r=command(udp_helper/'s223-udp','client',0,family,
                    source,number,destination,40621,
                    count,nonce,int(echo),2000,check=False)
                save(run/f'client-{index}.txt',r.stdout)
                case=dict(family=family,protocol='udp',number=number,phase=phase,
                    nonce=nonce,count=count,echo=echo,blocked=blocked,returncode=r.returncode)
                record['cases'].append(case)
                if blocked:
                    assert r.returncode!=0 and 'endpoint ' not in r.stdout,(phase,r.stdout)
                else:
                    assert r.returncode==0 and len(rows(r.stdout,'endpoint '))==count,(phase,r.stdout)
                    end=time.monotonic()+5
                    while time.monotonic()<end:
                        received=rows((run/'endpoint.log').read_text(),'received ')
                        if sum(x['nonce'].startswith(nonce+'-') for x in received)==count:break
                        time.sleep(.01)
                    else:raise RuntimeError('independent UDP endpoint did not receive '+nonce)
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
                end=time.monotonic()+20
                while time.monotonic()<end:
                    if process.poll() is not None:raise RuntimeError((run/'vpp.log').read_text())
                    if (runtime/'cli.sock').exists():
                        r=command(vppctl,'-s',runtime/'cli.sock','show product root lanes',check=False)
                        lanes=rows(r.stdout,'root.lane ')
                        if len(lanes)==4 and all(x['ready']=='1' for x in lanes):break
                    time.sleep(.04)
                else:raise RuntimeError('Product lanes did not start')
                cli('initial','show product flows','show product root lanes','show threads','product packet-trace limit 4096')
                assert all(int(x['capacity'])==capacity for x in rows((run/'initial.txt').read_text(),'flow.runtime '))
                save(run/'queues-busy.json',json.dumps({q:queue_bind(q) for q in range(176,180)}))
                cli('live-resize-rejected','product flow capacity 7')
                assert 'require stopped' in (run/'live-resize-rejected.txt').read_text()
                for family in (4,6):
                    for address in (host[family],'127.0.0.1' if family==4 else '::1'):
                        endpoints.append(subprocess.Popen([str(udp_helper/'s223-udp'),'server','0',
                            str(family),address,'40621'],env=env,stdout=endpoint_log,stderr=subprocess.STDOUT))
                end=time.monotonic()+5
                while (run/'endpoint.log').read_text().count('listen ')<4:
                    assert all(p.poll() is None for p in endpoints) and time.monotonic()<end
                    time.sleep(.02)
                # Exactly one hook per message, including the echo direction.
                for family,tool,span in [(4,'iptables','176:177'),(6,'ip6tables','178:179')]:
                    rule=[tool,'-t','mangle','-A',label.upper(),'-p','udp',
                          '-j','NFQUEUE','--queue-balance',span]
                    command(*rule);rules.append(rule)
                save(run/'hooks.txt',command('iptables-save','-t','mangle').stdout+command('ip6tables-save','-t','mangle').stdout)
                policy(1,0)
                for family,number in seeds:probe(family,number,'first')
                snapshot('first',1,1)
                for family,number in seeds:probe(family,number,'same',count=2)
                snapshot('same',2,3)
                policy(2,0)
                for family,number in seeds:probe(family,number,'revision')
                snapshot('revision',2,4)
                for family,number in seeds:probe(family,number,'bidir',echo=True)
                snapshot('bidir',3,6)
                # INPUT NFQA_UID is unavailable for these local datagrams.
                # App-scoped early Gate coverage belongs to OUTPUT, while the
                # INPUT arm still publishes revisions and updates the tracker.
                policy(3,1 if label=='output' else 0)
                if label=='output':
                    for family in (4,6):probe(family,31000,'gate',echo=True,blocked=True)
                else:record['gate_scope']='not-app-attributable-input'
                snapshot('gate',3,6)
                policy(4,0)
                for family,number in seeds:probe(family,number,'recovered',echo=True)
                snapshot('recovered',3,8)
                for family in (4,6):
                    for i in range(4):probe(family,32000+i,'direct-bidir',echo=True)
                    for i in range(2):probe(family,33000+i,'single-only')
                    for i in range(2):probe(family,34000+i,'same-only',count=3)
                    for i in range(4):probe(family,35000+i,'reverse-first',echo=True)
                remove_rules()
                save(run/'quiesced-hooks.txt',command('iptables-save','-t','mangle').stdout+command('ip6tables-save','-t','mangle').stdout)
                drain('final-drain')
                cli('final','show product flows','show product root lanes','show product primary','show product completion',
                    'show runtime','show threads','show node product-packet-policy','show node product-packet-origin-completion')
                record['raw_complete']=True
            finally:
                remove_rules()
                save(run/'hooks-after.txt',command('iptables-save','-t','mangle').stdout+command('ip6tables-save','-t','mangle').stdout)
                for endpoint in endpoints:
                    endpoint.terminate();endpoint.wait(timeout=5)
                endpoint_log.close()
                try:
                    if process.poll() is None and (runtime/'cli.sock').exists():
                        drain('stop-drain')
                        save(run/'fds-before.txt','\n'.join(f'{p.name} {os.readlink(p)}' for p in Path(f'/proc/{process.pid}/fd').iterdir()))
                        assert 'root.stop=ok' in cli('stop','product root stop')
                        closed=cli('closed','show product flows','show product root lanes','show product primary','show product completion')
                        assert all(x['entries']=='0' for x in rows(closed,'flow.pool '))
                        save(run/'fds-closed.txt','\n'.join(f'{p.name} {os.readlink(p)}' for p in Path(f'/proc/{process.pid}/fd').iterdir()))
                        free={q:queue_bind(q) for q in range(176,180)}
                        save(run/'queues-free.json',json.dumps(free));assert all(v==0 for v in free.values())
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:process.wait(timeout=8)
                        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                    log.close()
                    save(run/'stop.json',json.dumps(dict(pid=process.pid,process_absent=not Path(f'/proc/{process.pid}').exists(),returncode=process.returncode)))
        print(label,'complete',len(record['cases']),'endpoint cases',flush=True)
    result['status']='RAW_COMPLETE'
except Exception as error:
    result['error']=repr(error);raise
finally:
    result['completed_ns']=time.time_ns();save(a.output/'result.json',json.dumps(result,indent=2)+'\n')
