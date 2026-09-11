#!/usr/bin/env python3
"""S221 real kernel endpoints through the source-bound Linux Product artifact."""
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
host={4:'127.0.0.2',6:'fd20:6221::2'}
command('ip','-6','addr','add',host[6]+'/128','dev','lo','nodad')
vppctl=Path(build['stage'])/'source/build-root/install-vpp-native/vpp/bin/vppctl'
result=dict(status='HOLD',source='NFQ_CAPTURED',platform='linux',started_ns=time.time_ns(),
            build=str(a.build),build_sha256=digest(a.build),runner_sha256=digest(__file__),
            source_sha256=build['source_sha256'],runs=[])
seeds=[]
try:
    for run_index,(label,capacity) in enumerate([('normal',128),('small',3),('restart',128)]):
        run=a.output/label;run.mkdir();generation=22110+run_index
        record=dict(label=label,generation=generation,capacity=capacity,cases=[]);result['runs'].append(record)
        with tempfile.TemporaryDirectory(prefix='s221-runtime-') as temporary:
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
            endpoint=None;rules=[]
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
            def probe(family,protocol,number,phase='allow',blocked=False):
                index=len(record['cases']);nonce=f's221-{generation}-{phase}-{index}-{time.time_ns()}'
                r=command(helpers/'s221-flow-client',0,family,protocol,host[family],number,2,nonce,check=False)
                save(run/f'client-{index}.txt',r.stdout)
                if blocked:assert r.returncode!=0 and 'endpoint ' not in r.stdout,(phase,r.stdout)
                else:assert r.returncode==0 and len(rows(r.stdout,'endpoint '))==2,(phase,r.stdout)
                record['cases'].append(dict(family=family,protocol=protocol,number=number,phase=phase,
                                           nonce=nonce,returncode=r.returncode,blocked=blocked))
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
                endpoint=subprocess.Popen([str(helpers/'s207-echo'),'40621',host[4],host[6]],env=env,stdout=endpoint_log,stderr=subprocess.STDOUT)
                end=time.monotonic()+5
                while (run/'endpoint.log').read_text().count('listen ')<4:
                    assert endpoint.poll() is None and time.monotonic()<end
                    time.sleep(.02)
                for family,tool,span in [(4,'iptables','176:177'),(6,'ip6tables','178:179')]:
                    for hook in ('INPUT','OUTPUT'):
                        for protocol in ('tcp','udp','icmp' if family==4 else 'ipv6-icmp'):
                            rule=[tool,'-t','mangle','-A',hook,'-p',protocol,'-j','NFQUEUE','--queue-balance',span]
                            command(*rule);rules.append(rule)
                save(run/'hooks.txt',command('iptables-save','-t','mangle').stdout+command('ip6tables-save','-t','mangle').stdout)
                policy(1,1);probe(4,'udp',49000,'early-gate',True);drain('early-drain')
                early=rows(cli('early-flows','show product flows'),'flow.pool ')
                assert all(x['entries']=='0' and x['allocations']=='0' for x in early)
                policy(2,0)
                if label=='normal':
                    for attempt in range(18):
                        for family in (4,6):
                            for protocol in ('tcp','udp','icmp'):
                                probe(family,protocol,30000+attempt)
                    for attempt in range(84):probe(4,'udp',35000+attempt,'over-64')
                    drain('normal-drain');entries=rows(cli('filled','show product flows'),'flow.entry ')
                    counts={owner:sum(int(x['worker'])==owner for x in entries) for owner in (0,1)}
                    assert all(64<n<=128 for n in counts.values()),counts
                    for owner in (0,1):
                        for protocol,number in [('tcp',6),('udp',17),('icmp',1)]:
                            entry=next(x for x in entries if int(x['worker'])==owner and int(x['family'])==4 and int(x['protocol'])==number)
                            identity=int(entry['identifier']) if protocol=='icmp' else next(int(entry[k]) for k in ('port_a','port_b') if int(entry[k])!=40621)
                            seeds.append(dict(family=4,protocol=protocol,number=identity,owner=owner))
                    record['seeds']=seeds
                elif label=='small':
                    for seed in seeds:probe(seed['family'],seed['protocol'],seed['number'],'fill')
                    drain('fill-drain');filled=rows(cli('filled','show product flows'),'flow.pool ')
                    assert len(filled)==2 and all(x['entries']=='3' for x in filled),filled
                    for family in (4,6):
                        for protocol in ('tcp','udp','icmp'):
                            for attempt in range(4):probe(family,protocol,38000+attempt,'capacity')
                    for seed in seeds:
                        if seed['protocol']=='udp':probe(4,'udp',seed['number'],'existing')
                    drain('capacity-drain');cli('pressure','show product flows')
                    for revision,mode in ((3,1),(4,4)):
                        policy(revision,mode)
                        for family in (4,6):probe(family,'udp',49000+revision,'full-gate' if mode==1 else 'full-l4',True)
                        drain(f'drop-{revision}-drain');cli(f'drop-{revision}-flows','show product flows')
                    policy(5,0)
                    for family in (4,6):probe(family,'udp',49005,'recovery')
                else:
                    for seed in seeds:probe(seed['family'],seed['protocol'],seed['number'],'new-generation')
                remove_rules()
                save(run/'quiesced-hooks.txt',command('iptables-save','-t','mangle').stdout+command('ip6tables-save','-t','mangle').stdout)
                drain('final-drain')
                cli('final','show product flows','show product root lanes','show product primary','show product completion',
                    'show runtime','show threads','show node product-packet-policy','show node product-packet-origin-completion')
                record['raw_complete']=True
            finally:
                remove_rules()
                save(run/'hooks-after.txt',command('iptables-save','-t','mangle').stdout+command('ip6tables-save','-t','mangle').stdout)
                if endpoint is not None:
                    endpoint.terminate();endpoint.wait(timeout=5)
                endpoint_log.close()
                try:
                    if process.poll() is None and (runtime/'cli.sock').exists():
                        drain('stop-drain')
                        save(run/'fds-before.txt','\n'.join(f'{p.name} {os.readlink(p)}' for p in Path(f'/proc/{process.pid}/fd').iterdir()))
                        assert 'root.stop=ok' in cli('stop','product root stop')
                        closed=cli('closed','show product flows','show product root lanes','show product primary','show product completion')
                        assert all(x['entries']=='0' for x in rows(closed,'flow.pool '))
                        if label=='normal':
                            assert 'queued=2' in cli('collision-arm','product flow collision-check')
                            end=time.monotonic()+15
                            while time.monotonic()<end:
                                check=cli('collision-check','show product flow collision-check')
                                if 'done=3' in check:break
                                time.sleep(.05)
                            owners=rows(check,'flow.check.owner ')
                            assert len(owners)==2 and all(x['failed_step']=='0' for x in owners),check
                            assert 'runtimes=0 carriers=0 normal_flow_entries=0' in check
                            cli('collision-runtime','show runtime','show node product-flow-collision-check','show product flows')
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
