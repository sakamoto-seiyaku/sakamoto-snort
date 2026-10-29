#!/usr/bin/env python3
"""Root ordinary UDP DNS takeover on actual App sockets and system resolver IPC.

The controlled peer is independent of Product. Host fixtures, shell-UID resource
probes and Java App/system paths are reported separately. A sealed fresh backup
is required; final original-APK/private-data restoration is a separate operation.
"""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import sqlite3
import struct
import subprocess
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s315_shared', ROOT/'tests/device/s313-root-dns-tcp.py')
tcp = importlib.util.module_from_spec(spec); spec.loader.exec_module(tcp)
support, fixtures, PKG, SERIAL = tcp.support, tcp.fixtures, tcp.PKG, tcp.SERIAL
digest, props = tcp.digest, tcp.props


def grouped_timeout(error):
    if isinstance(error, subprocess.TimeoutExpired): return error
    if isinstance(error, BaseExceptionGroup):
        for nested in error.exceptions:
            if found:=grouped_timeout(nested): return found
    return None


def grouped_exception(error, kind):
    if isinstance(error, kind): return error
    if isinstance(error, BaseExceptionGroup):
        for nested in error.exceptions:
            if found:=grouped_exception(nested, kind): return found
    return None


class CleanupEnvelope:
    """Reserve finite, non-extending cleanup phases behind one Interface."""
    def __init__(self, seconds, phases):
        self.end=time.monotonic()+seconds
        self.phases=list(phases)

    @contextmanager
    def phase(self, device, name):
        index=next(index for index,(label,_)in enumerate(self.phases)if label==name)
        seconds=self.phases[index][1]
        later=sum(value for _,value in self.phases[index+1:])
        remaining=self.end-time.monotonic()
        assert remaining>0,'cleanup envelope exhausted before '+name
        deadline=time.monotonic()+min(seconds,max(0,remaining-later))
        previous=getattr(device,'capture_deadline',None); cleanup=getattr(device,'cleanup_deadline',None)
        device.capture_deadline=device.cleanup_deadline=deadline
        try:yield deadline
        finally:device.capture_deadline=previous; device.cleanup_deadline=cleanup


class Peer(tcp.Peer):
    def __init__(self, addresses, out, deadline=None):
        super().__init__(addresses, out, ROOT/'tests/device/helpers/s315_dns_peer.ps1', deadline)

    def register(self, query, reply, *, protocol='udp', port=53053, gate=None,
                 delay=0, drop=False, split=False, gate_seconds=30):
        assert 1 <= gate_seconds <= 120 and (gate or gate_seconds == 30)
        key = protocol+':'+str(port)+':'+query[2:].hex()
        self.responses[key] = dict(key=key, reply_hex=reply.hex(),
            gate=self.path(gate) if gate else '', gate_budget_ms=int(gate_seconds*1000), delay_ms=delay, drop=drop,
            split_bytes=[1, 5] if split else [], split_delay_ms=40 if split else 0)
        self.publish()

    def cursor(self):
        with self.lock:
            return max((r['request']for r in self.messages if r.get('kind')=='received'),default=0)

    def received(self, query, protocol='udp', port=53053, *, after=0):
        with self.lock:
            return [r for r in self.messages if r.get('kind')=='received'
                and r['request']>after
                and r['protocol']==protocol and int(r['resolver'][1])==port
                and bytes.fromhex(r['request_hex'])[2:]==query[2:]]

    def close(self):
        support.Peer.close(self)
        ready, = [r for r in self.messages if r.get('kind')=='ready']
        stopped, = [r for r in self.messages if r.get('kind')=='stopped']
        assert stopped['pending']==stopped['connections']==0
        received=[r['request'] for r in self.messages if r.get('kind')=='received']
        settled=[r['request'] for r in self.messages if r.get('kind') in ('exchange','cancelled')]
        assert len(received)==len(set(received)) and sorted(received)==sorted(settled)
        assert stopped['received']==len(received)==stopped['exchanged']+stopped['cancelled']
        process=ready['process_id']
        actual=self.remote_read('peer-physical-after',
            "@{process_present=[bool](Get-Process -Id "+str(process)+" -ErrorAction SilentlyContinue); "
            "tcp=@(Get-NetTCPConnection | Where-Object {$_.LocalPort -in @(53,53053)} | Select-Object LocalAddress,LocalPort,OwningProcess); "
            "udp=@(Get-NetUDPEndpoint | Where-Object {$_.LocalPort -in @(53,53053)} | Select-Object LocalAddress,LocalPort,OwningProcess)} | ConvertTo-Json -Depth 4 -Compress")
        assert not actual['process_present'] and not any(r['OwningProcess']==process for r in actual['tcp']+actual['udp'])
        (self.out/'peer-cleanup.json').write_text(json.dumps(dict(status='PASS',process_id=process,
            launcher_exit=self.process.returncode,stopped=stopped,actual_remote=actual),indent=2)+'\n')


class Device(tcp.Device):
    physical_interface='wlan0'

    def select_physical_interface(self,label):
        routes={family:self.save(label+f'-physical-route{family}.txt',self.root(
            f'ip -{family} route get '+shlex.quote(endpoint)))for family,endpoint in(
                (4,self.args.endpoint4),(6,self.args.endpoint6))}
        selected=[re.search(r'\bdev (\S+)',route)for route in routes.values()]
        assert all(selected) and len({item[1]for item in selected})==1,'selected peers use different physical interfaces'
        interface=selected[0][1]
        assert re.fullmatch(r'wlan\d+',interface),'selected peer is outside the physical Wi-Fi test path'
        if self.witnesses:assert interface==self.physical_interface,'physical interface changed while collector is active'
        self.physical_interface=interface
        return interface

    def pin_wire_interface(self,interface,rows):
        ready,=[row for row in rows if row.get('kind')=='ready']
        assert ready['interface']==interface and isinstance(ready['ifindex'],int)and ready['ifindex']>0
        item=self.witnesses[interface]
        assert item.setdefault('ifindex',ready['ifindex'])==ready['ifindex'],'owned collector binding changed'
        return ready['ifindex']

    def __init__(self, args):
        super().__init__(args)
        self.capture_deadline=time.monotonic()+1200
        self.witnesses={}
        self.forbidden_udp_returns=[]
        self.next_identifier=31500
        self.expected_durable=[]
        self.required_durable=[]
        self.stop_owed=False

    @contextmanager
    def cleanup_budget(self, seconds=45):
        """Keep failure cleanup bounded but independent of test-case deadlines."""
        previous = getattr(self, 'capture_deadline', None)
        self.capture_deadline = min(getattr(self,'cleanup_deadline',None) or float('inf'),time.monotonic()+seconds)
        try:
            yield
        finally:
            self.capture_deadline = previous

    @contextmanager
    def control_budget(self, seconds):
        """Bound one foreground control transaction without extending the matrix."""
        previous = getattr(self, 'capture_deadline', None)
        self.capture_deadline = min(previous or float('inf'),time.monotonic()+seconds)
        try:
            yield
        finally:
            self.capture_deadline = previous

    def settle_reader(self, label):
        reader=getattr(self,'reader',None)
        capture=getattr(self,'prepared_stop_capture',None)
        mismatch=bool(capture and capture.get('reader') is not reader)
        owned=capture.get('reader') if capture else reader
        if owned is None:
            if mismatch:raise RuntimeError('prepared stop capture has no owned reader')
            return
        receipt=dict(status='HOLD' if mismatch else 'PASS',remote_completion='unknown',pid=owned.pid)
        if mismatch:receipt['error']='prepared stop capture reader identity mismatch'
        try:
            owned.wait(timeout=self.budget_timeout(5))
            receipt['returncode']=owned.returncode
        except BaseException as error:
            receipt.update(status='HOLD',local_wait_error=repr(error))
            try:
                owned.terminate(); owned.wait(timeout=self.budget_timeout(3))
                receipt.update(termination_requested=True,returncode=owned.returncode)
            except BaseException as cleanup:
                receipt['local_reap_error']=repr(cleanup)
                self.save(label+'-reader-settlement.json',json.dumps(receipt,indent=2)+'\n')
                raise
        if self.reader is owned:self.reader=None
        if capture and capture.get('reader') is owned:
            capture['log'].close();capture['errors'].close();self.prepared_stop_capture=None
        self.save(label+'-reader-settlement.json',json.dumps(receipt,indent=2)+'\n')
        if mismatch:raise RuntimeError('prepared stop capture identity mismatch; owned capture reader reaped')
        if receipt['status']!='PASS':raise RuntimeError('reader reaped after unknown remote completion')

    def reconcile_stop_timeout(self, label):
        trace=getattr(self,'adb_trace',None)
        item=next((value for value in reversed(trace.items) if value['original_argv'][1:4]==['am','start','-n']
            and '--ez' in value['original_argv'] and 'runtimeStop' in value['original_argv']),None) if trace else None
        assert item is not None, 'timed stop has no retained trace operation to reconcile'
        trace.collect(item,self.capture_deadline)
        witness=item['witness']; assert not witness['gaps'] and witness['exit_code']==0,witness
        assert getattr(self,'capture_deadline',None) is not None, 'stop reconciliation requires an owned phase deadline'
        state=props(self.app('files/runtime-state/snapshot.properties'))
        ledger=props(self.app('files/product-state/product-core-generation.properties'))
        processes=self.root('ps -A -o PID,UID,ARGS')
        hooks=self.root('iptables-save -t mangle; ip6tables-save -t mangle')
        queues=self.root('cat /proc/net/netfilter/nfnetlink_queue')
        generation=str(self.generation)
        native=not any(len(row:=line.split())>=3 and Path(row[2]).name=='libvpp_runtime.so'for line in processes.splitlines())
        stopped=(state.get('state')=='stopped'and state.get('mayBeActive')=='false'
            and state.get('generation')==ledger.get('generation')==generation and native
            and 'SAKAMOTO_PRODUCT_'not in hooks and not queues.strip())
        running=(state.get('state')=='running'and state.get('mayBeActive')=='true'
            and state.get('generation')==ledger.get('generation')==generation)
        assert stopped or running, 'stop reconciliation has no validated terminal/runtime state'
        self.save(label+'-stop-timeout-reconciliation.json',json.dumps(dict(
            status='STOPPED_CONFIRMED'if stopped else'RUNNING_RETRY_PERMITTED',
            witness=witness,runtime=state,ledger=ledger,native_absent=native,
            owned_hooks_absent='SAKAMOTO_PRODUCT_'not in hooks,queues_absent=not queues.strip()),indent=2)+'\n')
        self.active=not stopped; self.stop_retry_owed=not stopped; self.stop_retry_authorized=not stopped
        return stopped

    def question(self,label,qtype=1,**options):
        self.next_identifier+=1
        return fixtures.question(self.next_identifier,label+'.qname.test',qtype,**options)

    def query_rules(self, label):
        path='files/product-state/complete-rule-config.properties'
        # Staging, normal UI input and independent completion readback share
        # one finite scope; the immutable matrix deadline still wins.
        with self.control_budget(60):
            before=props(self.app(path)).get('queryElapsedMillis')
            self.foreground_ui(label+'-ui')
            self.tap(label+'-query','Query all rules')
            status=self.wait(label+'-config',path,lambda c:c.get('queryElapsedMillis')not in(None,before),timeout=60)
        self.valid_config(status);return status

    def valid_config(self,status):
        assert status['transportCode']=='0'and int(status['generation'])==self.generation,status
        assert all(status[k]=='0'for k in('result','saveError','compileError','compilerStatus')),status
        assert int(status['savedRevision'])==int(status['activeRevision'])>0,status

    def applied_status(self,label,old,*,previous_revision=None):
        status=self.wait(label+'-applied','files/product-state/complete-rule-config.properties',
            lambda c:c.get('queryElapsedMillis')not in(None,old)and(previous_revision is None
                or int(c.get('activeRevision',0))>previous_revision))
        self.valid_config(status)
        return status

    def verify_saved_source(self,label):
        source=self.binary(label+'-source.conf','files/rule-configuration/rules.conf',limit=4*1024*1024)
        actual=self.save(label+'-source-sha256.txt',self.adb('shell','run-as',PKG,'sha256sum','files/rule-configuration/rules.conf'))
        assert digest(source)==actual.split()[0]

    def applied(self,label,old,*,previous_revision=None):
        status=self.applied_status(label,old,previous_revision=previous_revision)
        self.verify_saved_source(label)
        return status

    def binary(self,label,path,*,limit):
        local=self.out/label;command=[str(ROOT/'dev/adb'),'-s',SERIAL,'exec-out','run-as',PKG,'cat',path]
        deadline=min(30,self.capture_deadline-time.monotonic()-10);assert deadline>0
        receipt=dict(started_ns=time.time_ns(),argv=command,timeout_seconds=deadline,status='HOLD')
        try:
            # adb exec-out's raw transport can return0 when remote cat fails.
            # Pin an actual existing file before interpreting its stdout as data.
            remote=self.adb('shell','run-as',PKG,'sha256sum',path)
            match=re.fullmatch(r'([0-9a-f]{64})\s+'+re.escape(path)+r'\s*',remote)
            assert match, 'binary source hash unavailable: '+remote
            receipt['remote_sha256']=match[1]
            with local.open('xb')as stream,(self.out/(label+'.stderr')).open('xb')as errors:
                process=subprocess.run(command,stdout=stream,stderr=errors,timeout=deadline)
            receipt['returncode']=process.returncode
            assert process.returncode==0 and local.stat().st_size<=limit,(label,receipt)
            assert digest(local)==receipt['remote_sha256'], 'binary read differs from the actual source file'
            receipt['status']='PASS';return local
        except BaseException as error:receipt['error']=repr(error);raise
        finally:
            receipt['completed_ns']=time.time_ns()
            if local.exists():receipt.update(bytes=local.stat().st_size,sha256=digest(local))
            self.save(label+'.read.json',json.dumps(receipt,indent=2)+'\n')

    def upstream(self, label, address=None, port=53053):
        old=self.query_rules(label+'-before');text='off'if address is None else'udp '+address+' '+str(port)
        self.save(label+'-request.txt',text+'\n')
        self.save(label+'-action.txt',self.action('--es','dnsUpstream',shlex.quote(text),
            '--el','expectedSavedRevision',old['savedRevision']))
        status=self.wait(label+'-applied','files/product-state/complete-rule-config.properties',
            lambda c:c.get('queryElapsedMillis')not in(None,old.get('queryElapsedMillis')))
        self.valid_config(status)
        assert status['dns.enabled']==status['dns.active.enabled']==str(int(address is not None))
        if address is not None:
            ip=ipaddress.ip_address(address);packed=ip.packed+bytes(12)if ip.version==4 else ip.packed
            for prefix in('dns','dns.active'):
                assert status[prefix+'.family']==str(ip.version)and status[prefix+'.port']==str(port)
                assert status[prefix+'.address']==packed.hex(),status
        changed=any(old.get(key)!=status.get(key)for key in('dns.enabled','dns.family','dns.port','dns.address'))
        previous=getattr(self,'selected_dns',None)
        endpoint=(address,port if address else 0)
        revision=int(status['activeRevision'])if changed else previous['route_revision']if previous and previous['endpoint']==endpoint else None
        self.selected_dns=dict(endpoint=endpoint,route_revision=revision,active_revision=int(status['activeRevision']))
        return status

    def rules(self, label, variant='allow', *, prefill=False, mode=0):
        baseline=self.query_rules(label+'-before')
        expression={'query-deny':'1100060301','alias-deny':'1101060101','input-deny':'0601'}.get(variant)
        lines=['lists 3','domain 0 descendants qname.test','domain 1 exact alias.test']
        if expression:
            lines += [f'0 0 4294967295 4294967295 4294967295 10 0 17 0 2 * * 0 65535 0 65535 {expression}',
                'group 10','edge 10 1 0',f'bind 1 {self.uid} 2 10 {mode}']
        index=int(expression is not None)
        lines += ['0 0 4294967295 4294967295 4294967295 1000 0 17 0 1 * * 0 65535 0 65535',
            'group 20',f'edge 20 1 {index}',f'bind 2 {self.uid} 2 20 0']
        request=self.out/(label+'-rules.txt');request.write_text('\n'.join(lines)+'\n')
        remote='/data/local/tmp/s315-rules.txt';self.adb('push',request,remote)
        command=f'am start -n {PKG}/.DebugControlActivity --es completeRuleText "$(cat {remote})"'
        self.save(label+'-prefill.txt',self.adb('shell','sh','-c',shlex.quote(command)));self.adb('shell','rm',remote)
        if prefill:
            return self.tap(label+'-point','Replace all rules',click=False),baseline
        old=props(self.app('files/product-state/complete-rule-config.properties')).get('queryElapsedMillis')
        self.tap(label+'-replace','Replace all rules');status=self.applied(label,old)
        assert int(status['count'])==int(status['activeCount'])==1+index
        assert int(status['bindingCount'])==1+index and status['binding.'+str(index)]==f'2,{self.uid},2,20,0'
        if expression:assert status['binding.0']==f'1,{self.uid},2,10,{mode}'
        assert status['domain.0.mode']=='1'and status['domain.0.name']=='qname.test'
        for key in baseline:
            if key.startswith(('dns.','dns.active.')):assert status[key]==baseline[key],(key,status,baseline)
        return status

    def start(self, owners):
        if hasattr(self,'generation'):del self.generation
        if hasattr(self,'selected_dns'):del self.selected_dns
        before=props(self.save(f'n{owners}-before-start-state.properties',
            self.app('files/runtime-state/snapshot.properties')))
        self.before_start_generation=int(before['generation'])
        assert before['state']=='stopped'and before['mayBeActive']=='false',before
        self.stop_owed=True
        result=super().start(owners)
        state=props((self.out/f'n{owners}-running.properties').read_text())
        assert state['profile']=='root'and state['health']=='ok'and state['coreHealth']=='ok',state
        assert self.generation>self.before_start_generation
        ledger=props(self.save(f'n{owners}-running-ledger.properties',self.app('files/product-state/product-core-generation.properties')))
        assert int(ledger['generation'])==self.generation
        self.cli('n'+str(owners)+'-proxy-start','show product dns proxy')
        return result

    def proxy_ready(self, label, enabled=True):
        # Applied route readiness includes a clean idle socket that can reopen.
        # Current authorization is separate and remains visible in every row.
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            raw=self.cli(label+'-proxy','show product dns proxy')
            rows=[props(line.replace(' ','\n')) for line in raw.splitlines()if'dns.proxy owner='in line]
            expected=self.selected_dns
            ready=(len(rows)==self.owners and{int(r['owner'])for r in rows}==set(range(self.owners))
                and len({int(r['network_revision'])for r in rows})==1
                and all(int(r['generation'])==self.generation and r['enabled']==str(int(enabled))and r.get('route_ready')=='1'
                    and r.get('profile')==str(2 if self.profile=='vpn'else 1)
                    and r['stopping']=='0'and int(r['network_revision'])>0 and int(r['route_revision'])>0 for r in rows))
            if ready and enabled:
                ready=all(ipaddress.ip_address(r['upstream'])==ipaddress.ip_address(expected['endpoint'][0])
                    and int(r['port'])==expected['endpoint'][1]
                    and r.get('udp_state')in('authorized','idle')and int(r['proxy_bytes'])>0
                    and r['socket_ready']==r['authorized_udp']==str(int(r['udp_state']=='authorized'))for r in rows)
            elif ready:
                ready=all(r.get('udp_state')=='disabled'and r['socket_ready']==r['authorized_udp']=='0'for r in rows)
            if ready:
                revisions={int(r['route_revision'])for r in rows};ready=len(revisions)==1
                if ready and expected['route_revision']is not None:ready=revisions=={expected['route_revision']}
                if ready and expected['route_revision']is None:
                    ready=next(iter(revisions))<=expected['active_revision']
                    if ready:expected['route_revision']=next(iter(revisions))
            if ready:return rows
            time.sleep(.1)
        raise AssertionError('Root DNS owner did not reach its actual route/socket readiness: '+raw)

    def launch_queries(self,label,address,source,wires,*,timeout=4000,pipeline=False,system_name=None,preserve_ui=False,initial_delay=0):
        nonce='s315-'+label+'-'+str(time.time_ns())
        plan=dict(nonce=nonce,endpoint=address,port=53,source=source,bindDefault=True,
            dnsQueries=[wire.hex()for wire in wires],dnsProxyTimeoutMs=timeout,dnsQueryDelayMs=0,dnsPipeline=pipeline)
        if initial_delay:plan['dnsInitialDelayMs']=initial_delay
        if system_name:
            del plan['dnsQueries'];plan['systemDnsName']=system_name
        self.save(label+'-plan.json',json.dumps(plan,indent=2)+'\n')
        if preserve_ui:self.adb('shell','input','keyevent','3')
        flags=['-f','0x18000000']if preserve_ui else[]
        self.save(label+'-launch.txt',self.action(*flags,'--es','t12ProbePlan',shlex.quote(json.dumps(plan))))
        if preserve_ui:self.save(label+'-return-ui.txt',self.action())
        return nonce

    def await_peer_query(self,peer,label,query,*,port=53053,after=0,initial_delay=0):
        # Acquisition includes the deliberate interval before the first send.
        # This does not extend Product's deadline for an admitted query.
        started=time.monotonic();end=min(self.capture_deadline,started+initial_delay/1000+2)
        receipt=dict(status='HOLD',started_monotonic=started,deadline_monotonic=end,
            pre_send_delay_ms=initial_delay,arrival_budget_seconds=2)
        try:
            while True:
                rows=peer.received(query,port=port,after=after)
                if rows:
                    receipt.update(status='PASS',requests=[row['request']for row in rows]);return rows
                assert time.monotonic()<end,'current gated request absent at independent peer: '+label
                time.sleep(min(.01,max(0,end-time.monotonic())))
        finally:
            receipt['completed_monotonic']=time.monotonic()
            self.save(label+'-peer-acquisition.json',json.dumps(receipt,indent=2)+'\n')

    def wire_start(self):
        self.select_physical_interface('wire-start')
        source=ROOT/'tests/device/helpers/s315_dns_wire.c';binary=self.out/'s315-wire'
        subprocess.run([self.args.cc,'-O2','-Wall','-Wextra','-Werror',str(source),'-o',str(binary)],check=True)
        self.adb('push',binary,'/data/local/tmp/s315-wire');self.adb('shell','chmod','755','/data/local/tmp/s315-wire')
        assert self.adb('shell','sha256sum','/data/local/tmp/s315-wire').split()[0]==digest(binary)
        stale_source=ROOT/'tests/device/helpers/s315_dns_stale_return.c';stale_binary=self.out/'s315-stale-return'
        subprocess.run([self.args.cc,'-O2','-Wall','-Wextra','-Werror',str(stale_source),'-o',str(stale_binary)],check=True)
        self.adb('push',stale_binary,'/data/local/tmp/s315-stale-return');self.adb('shell','chmod','755','/data/local/tmp/s315-stale-return')
        assert self.adb('shell','sha256sum','/data/local/tmp/s315-stale-return').split()[0]==digest(stale_binary)
        for interface in (self.physical_interface,'lo'):
            stop='/data/local/tmp/s315-wire-'+interface+'.stop';log='/data/local/tmp/s315-wire-'+interface+'.jsonl'
            self.witnesses[interface]=dict(pid=None,start=None,uid=None,exe=None,stop=stop,log=log,
                launch_pending=True)
            self.adb('shell','rm','-f',stop,log)
            command='/data/local/tmp/s315-wire '+interface+' '+stop+' '+self.args.endpoint4+' '+self.args.endpoint6+' 192.168.4.1 1.1.1.1 '+self.args.stale6+' > '+log+' 2>&1 < /dev/null & echo $!'
            pid=int(self.save('wire-'+interface+'-start.txt',self.root(command)).strip())
            self.witnesses[interface].update(pid=pid,launch_pending=False)
            identity=self.save('wire-'+interface+'-identity.txt',self.root(
                f'cat /proc/{pid}/stat; grep "^Uid:" /proc/{pid}/status; readlink /proc/{pid}/exe'))
            rows=identity.splitlines(); assert len(rows)==3 and ') ' in rows[0],identity
            start=int(rows[0].split(') ',1)[1].split()[19]); uid=int(rows[1].split()[2])
            assert uid==0 and rows[2]=='/data/local/tmp/s315-wire',identity
            self.witnesses[interface].update(start=start,uid=uid,exe=rows[2])
            deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                raw=self.adb('shell','cat',log,check=False)
                if'"kind":"ready"'in raw:
                    self.pin_wire_interface(interface,[json.loads(line)for line in raw.splitlines()if line.startswith('{')]);break
                time.sleep(.1)
            else:raise AssertionError('owned wire witness did not start: '+interface)

    def wire(self, label, interface=None):
        interface=self.physical_interface if interface is None else interface
        raw=self.save(label+'-'+interface+'.jsonl',self.adb('shell','cat',self.witnesses[interface]['log']))
        rows=[json.loads(line)for line in raw.splitlines()if line.startswith('{')]
        if any(row.get('kind')=='ready'for row in rows):self.pin_wire_interface(interface,rows)
        return rows

    def observation(self,label):
        value=super().observation(label)
        assert all(int(value[section]['generation'])==self.generation for section in('vpp','health','policy_source','runtime')),value.keys()
        consumer=value['consumer'];assert consumer['query_fresh']and consumer['live']
        assert all(consumer.get(key)is None for key in('error','store_error','query_error')),consumer
        assert consumer['persistent']['storage']=='sqlite'and value['health']['version']==8
        assert value['health']['owners']==self.owners
        return value

    def wire_coverage(self,label,interfaces=None):
        result={}
        selected=list(self.witnesses if interfaces is None else interfaces)
        assert interfaces is None or(selected and set(selected)<=set(self.witnesses))
        for interface in selected:
            rows=self.wire(label,interface)
            assert any(row.get('kind')=='ready'for row in rows)and not any(row.get('kind')=='stopped'for row in rows),'wire capture ended during episode'
            result[interface]=rows
        return result

    def prepare_late_wire(self,label):
        return self.wire_coverage(label+'-before-late-release')

    def late_wire_coverage(self,label):
        return self.wire_coverage(label,interfaces=[self.physical_interface])

    def forbid_udp_return(self,label,interface,before,source,reply):
        assert interface in self.witnesses
        identity={key:self.witnesses[interface][key]for key in('pid','start','uid','exe')}
        self.forbidden_udp_returns.append(dict(label=label,interface=interface,generation=self.generation,
            witness=identity,baseline_rows=len(before),source=source,reply=reply.hex()if reply is not None else None))

    def verify_udp_return_fences(self,interface,rows):
        for fence in list(self.forbidden_udp_returns):
            if fence['interface']!=interface:continue
            identity={key:self.witnesses[interface][key]for key in('pid','start','uid','exe')}
            assert identity==fence['witness'],'wire witness changed during late-return interval'
            forbidden=[row for row in rows[fence['baseline_rows']:]if row.get('kind')=='udp'
                and row['source_port']==53 and row['destination_port']==fence['source']
                and(fence['reply']is None or row['payload_hex']==fence['reply'])]
            self.save(fence['label']+'-terminal-'+interface+'-no-return.json',json.dumps(dict(
                fence,status='HOLD'if forbidden else'PASS',observed_rows=len(rows),forbidden=forbidden),indent=2)+'\n')
            assert not forbidden,'late old reply appeared during complete return-capture interval'
            self.forbidden_udp_returns.remove(fence)

    def durable(self,label):
        first=self.observation(label+'-target');target=first['consumer']['persistent']['dns']['accepted']
        value=self.observation_matching(label+'-committed',lambda v:
            v['consumer']['persistent']['persistence']['dns_accepted']>=target,timeout=10)
        self.durable_target=target
        return dict(target=target,committed=value['consumer']['persistent']['persistence']['dns_accepted'])

    def durable_readback(self,label):
        # The ordinary stop closes the only writer. Read the actual committed
        # SQLite file independently; do not substitute the live pending view.
        local=self.binary(label+'-overall.sqlite3','files/observation/overall.sqlite3',limit=1024*1024*1024)
        with sqlite3.connect(local.as_uri()+'?mode=ro&immutable=1',uri=True)as database:
            assert database.execute('pragma integrity_check').fetchone()==('ok',)
            metadata=json.loads(database.execute("select value from observation where kind=0 and key='' ").fetchone()[0])
            assert metadata['dns_accepted']>=self.durable_target,metadata
            rows=[json.loads(value)['record']for value, in database.execute('select value from observation where kind=20')]
        current=[r for r in rows if r['generation']==self.generation]
        for expected in self.expected_durable:
            if expected['generation']==self.generation:assert expected in current,expected
        for required in self.required_durable:
            if required['generation']!=self.generation:continue
            for stage in required['stages']:
                assert any(r['id']==required['id']and r['source_port']==required['source']
                    and r['stage']==stage and bool(r['proxy_flags']&1)==required['proxy']for r in current),required
        report=dict(status='PASS',generation=self.generation,sha256=digest(local),bytes=local.stat().st_size,
            metadata_dns_accepted=metadata['dns_accepted'],target=self.durable_target,current_generation_records=current,
            verified_case_records=sum(r['generation']==self.generation for r in self.expected_durable))
        self.save(label+'-sqlite-readback.json',json.dumps(report,indent=2)+'\n');return report

    def wire_stop(self,interfaces=None):
        errors=[]
        for interface,item in list(self.witnesses.items()):
            if interfaces is not None and interface not in interfaces:continue
            with self.cleanup_budget(10):
                try:
                    self.adb('shell','touch',item['stop'])
                    if item['pid'] is None:
                        raise RuntimeError('wire launch acknowledgement/PID is unresolved after cooperative marker; no signal is authorized')
                    deadline=time.monotonic()+8
                    while time.monotonic()<deadline:
                        rows=self.wire('wire-final',interface)
                        if any(r.get('kind')=='stopped'for r in rows):break
                        time.sleep(.1)
                    else:raise AssertionError('owned wire witness did not acknowledge stop')
                    stopped,=[r for r in rows if r.get('kind')=='stopped']
                    assert stopped['reason']=='requested'and stopped['stats_ok']and stopped['socket_drops']==0,stopped
                    processes=self.save('wire-'+interface+'-processes-after.txt',self.root('ps -A -o PID,UID,ARGS'))
                    assert not any((v:=line.split())and v[0]==str(item['pid'])for line in processes.splitlines())
                    self.verify_udp_return_fences(interface,rows)
                    self.adb('shell','rm','-f',item['stop'],item['log']);del self.witnesses[interface]
                except BaseException as error:
                    errors.append(error)
                    if None in (item['start'],item['uid'],item['exe']):
                        errors.append(RuntimeError('exact wire identity was not captured; forced PID termination is disallowed'))
                        continue
                    command=(f'if [ "$(sed "s/^.*) //" /proc/{item["pid"]}/stat 2>/dev/null | awk \'{{print $20}}\')" = "{item["start"]}" ] && '
                        f'[ "$(awk \'/^Uid:/{{print $3}}\' /proc/{item["pid"]}/status 2>/dev/null)" = "{item["uid"]}" ] && '
                        f'[ "$(readlink /proc/{item["pid"]}/exe 2>/dev/null)" = "{item["exe"]}" ]; then kill -TERM {item["pid"]}; fi')
                    try:
                        self.save('wire-'+interface+'-failed-stop.txt',self.root(command)); deadline=time.monotonic()+5
                        while True:
                            processes=self.save('wire-'+interface+'-forced-processes-after.txt',self.root('ps -A -o PID,UID,ARGS'))
                            if not any((v:=line.split())and v[0]==str(item['pid'])for line in processes.splitlines()):break
                            assert time.monotonic()<deadline,'owned wire witness still exists after exact termination'
                            time.sleep(.1)
                        self.wire('wire-forced-final',interface)
                        self.adb('shell','rm','-f',item['stop'],item['log']);del self.witnesses[interface]
                    except BaseException as cleanup:errors.append(cleanup)
        if not self.witnesses:
            self.adb('shell','rm','-f','/data/local/tmp/s315-wire','/data/local/tmp/s315-stale-return','/data/local/tmp/s315-rules.txt')
        if errors:raise BaseExceptionGroup('independent wire cleanup/qualification',errors)

    def stop(self, label):
        try:result=self.qualified_stop(label)
        except BaseException as error:
            if grouped_exception(error,tcp.support.PreparedStopCaptureExpired):
                # No Stop was sent. Retire the exact expired capture so the
                # failure cleanup may create a fresh reader and stop safely.
                try:self.settle_reader(label+'-expired-capture')
                except BaseException as cleanup:
                    self.stop_retry_authorized=False;self.stop_owed=True
                    error.add_note('expired capture cleanup retained HOLD: '+repr(cleanup))
                else:self.stop_retry_authorized=True;self.stop_owed=True
                raise
            timeout=grouped_timeout(error)
            if not timeout:
                self.stop_retry_authorized=False; self.stop_owed=True;raise
            try:self.reconcile_stop_timeout(label)
            except BaseException as reconciliation:
                # A local timeout with no complete remote witness is not an
                # authorization to replay the stop mutation during finally.
                self.stop_retry_authorized=False; self.stop_owed=True
                error.add_note('stop reconciliation retained HOLD: '+repr(reconciliation)); raise error
            self.stop_owed=getattr(self,'stop_retry_owed',True);raise
        self.stop_owed=False;self.active=False;return result

    def qualified_stop(self, label):
        capture=getattr(self,'prepared_stop_capture',None)
        if capture:
            self.validate_stop_capture(capture)
        elif self.reader:
            # Retain the obligation independently of the STOPPED projection.
            # A failed prior stop must not abandon its owned local log reader.
            if self.reader.poll()is None:self.reader.terminate()
            try:self.reader.wait(timeout=self.budget_timeout(3))
            except subprocess.TimeoutExpired:self.reader.kill();self.reader.wait(timeout=self.budget_timeout(3))
            self.save(label+'-previous-reader.json',json.dumps(dict(pid=self.reader.pid,returncode=self.reader.returncode))+'\n')
            self.reader=None
        if not hasattr(self,'generation'):
            state=props(self.save(label+'-failed-start-state.properties',
                self.app('files/runtime-state/snapshot.properties')))
            before_processes=self.save(label+'-failed-start-processes-before.txt',self.root('ps -A -o PID,UID,ARGS'))
            before_native=any(len(v:=line.split())>=3 and Path(v[2]).name=='libvpp_runtime.so'for line in before_processes.splitlines())
            before_ledger=props(self.save(label+'-failed-start-ledger-before.properties',self.app('files/product-state/product-core-generation.properties')))
            preallocation=(int(state['generation'])==int(before_ledger.get('generation','0'))==self.before_start_generation and state['state']=='stopped'
                and state['mayBeActive']=='false'and not before_native)
            if not preallocation:
                self.save(label+'-partial-start-stop.txt',self.action('--ez','runtimeStop','true'))
                state=self.wait(label+'-partial-start-stopped','files/runtime-state/snapshot.properties',
                    lambda value:value.get('state')=='stopped'and value.get('mayBeActive')=='false')
            assert state['state']=='stopped'and state['mayBeActive']=='false',state
            ledger=props(self.save(label+'-failed-start-ledger.properties',self.app('files/product-state/product-core-generation.properties')))
            assert int(state['generation'])==int(ledger['generation'])>=self.before_start_generation
            processes=self.save(label+'-failed-start-processes.txt',self.root('ps -A -o PID,UID,ARGS'))
            assert not any(len(v:=line.split())>=3 and Path(v[2]).name=='libvpp_runtime.so'for line in processes.splitlines())
            assert not self.save(label+'-failed-start-queues.txt',self.root('cat /proc/net/netfilter/nfnetlink_queue')).strip()
            hooks=self.save(label+'-failed-start-hooks.txt',self.root('iptables-save -t mangle; ip6tables-save -t mangle'))
            assert'SAKAMOTO_PRODUCT_'not in hooks
            self.active=False
            return dict(scope='proven preallocation rejection'if preallocation else'partial start explicitly stopped before qualification',native_process_absent=True,
                owned_hooks_and_queues_absent=True,observed_generation=int(state['generation']))
        result=super().stop(label)
        raw=(self.out/(label+'-stop.log')).read_text()
        assert'SAKAMOTO_PRODUCT_'not in(self.out/(label+'-hooks-after.txt')).read_text()
        for owner in range(self.owners):
            rows=[props(line.replace(' ','\n'))for line in raw.splitlines()
                if f'dns.proxy event=stop generation={self.generation} owner={owner} 'in line]
            assert rows and all(r['transactions']==r['upstream_sockets']==r['raw_sockets']==r['replies']=='0'
                and r['raw_opened']==r['raw_closed']for r in rows),rows
        processes=(self.out/(label+'-processes-after.txt')).read_text()
        assert not any('tail -n +1 -f files/profiles/root/vpp/logs/vpp-stdout.log'in line for line in processes.splitlines())
        return result


def dns_rows(observation):
    return [row['record']for row in observation['consumer']['persistent']['dns']['recent'].values()]


def root_receive(d,label):
    raw=d.cli(label,'show product root receive')
    return [props(line.replace(' ','\n'))for line in raw.splitlines()if'root.receive 'in line]


def receive_total(rows,key):
    return sum(int(row[key])for row in rows)


def query_wire_prefix(row,query,*,ignore_id=False):
    if row.get('kind')not in('udp','udp_fragment_first'):return False
    payload=bytes.fromhex(row['payload_hex'])
    if ignore_id:
        return len(payload)>2 and query[2:].startswith(payload[2:])
    return bool(payload)and query.startswith(payload)


def checksum(data):
    if len(data)%2:data+=b'\0'
    total=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
    while total>>16:total=(total&65535)+(total>>16)
    return total


def legal_reply(reply,query,*,rcode=None,truncated=False,capacity=None):
    assert len(reply)>=12 and reply[:2]==query[:2]
    flags,qd,an,ns,ar=struct.unpack('!5H',reply[2:12]);qflags=int.from_bytes(query[2:4],'big')
    assert flags&0x8000 and(flags&0x7800)==(qflags&0x7800)
    assert flags&0x0110==qflags&0x0110
    if rcode is not None:assert flags&15==rcode,(reply.hex(),rcode)
    if truncated:assert flags&0x0200 and an==ns==0 and len(reply)<=capacity
    if rcode is not None or truncated:
        assert qd<=1 and an==ns==0 and ar<=1
        if qd:
            _,_,end=fixtures.decode_question(query)
            assert reply[12:end]==query[12:end]
        if capacity is not None:
            assert qd==1 and len(reply)<=capacity
            if int.from_bytes(query[10:12],'big'):
                assert ar==1 and len(reply)==end+11
                assert reply[end:]==b'\0\0)'+struct.pack('!H',capacity)+b'\0\0'+bytes([query[end+7]&0x80,0,0,0])
            else:
                assert ar==0 and len(reply)==end


def legal_return_packet(row,query,reply,address,source):
    packet=bytes.fromhex(row['packet_hex']);family=packet[0]>>4
    header=(packet[0]&15)*4 if family==4 else 40
    udp=packet[header:];length=int.from_bytes(udp[4:6],'big')
    assert len(udp)==length and udp[8:]==reply and udp[:4]==struct.pack('!HH',53,source)
    assert row['source']==address and row['source_port']==53 and row['destination_port']==source
    if family==4:
        assert packet[8]==1 and packet[9]==17 and checksum(packet[:header])==65535
        assert int.from_bytes(packet[2:4],'big')==len(packet)
        pseudo=packet[12:20]+b'\0\x11'+struct.pack('!H',length)
    else:
        assert family==6 and packet[6]==17 and packet[7]==1 and int.from_bytes(packet[4:6],'big')==len(udp)
        pseudo=packet[8:40]+struct.pack('!I',length)+b'\0\0\0\x11'
    assert udp[6:8]!=b'\0\0'and checksum(pseudo+udp)==65535
    assert reply[:2]==query[:2]


def exchange(d,peer,result,label,address,wires,replies,*,local_rcodes=None,selected_port=53053,
             original=False,expected_udp=1,tcp_retry=False,truncated=False,capacities=None,timeout=5000,
             hot=None,check=None):
    source=d.reserve_source_port(label);cursor=peer.cursor();before=d.wire_coverage(label+'-before')
    if hot:d.verify_ui_state(label+'-hot-prepared')
    began=time.monotonic();nonce=d.launch_queries(label,address,source,wires,timeout=timeout,pipeline=len(wires)>1,
        preserve_ui=hot is not None,initial_delay=3000 if hot else 0)
    if hot:
        point,gate,old=hot
        # Power/keyguard/input preparation precedes actual query transmission.
        # The visible window stays awake; verify its current focus after the
        # ordinary probe Activity returns, then publish through the same button.
        d.verify_ui_focus(label+'-hot-ready')
        d.await_peer_query(peer,label,wires[0],port=selected_port,after=cursor,initial_delay=3000)
        d.save(label+'-hot-tap.txt',d.adb('shell','input','tap',*map(str,point)))
        applied=d.applied_status(label+'-hot',old['queryElapsedMillis'],previous_revision=int(old['activeRevision']))
        pending=d.proxy_ready(label+'-hot-published-pending')
        assert sum(int(row['transactions'])for row in pending)==1,pending
        gate.touch();d.save(label+'-hot-revision.json',json.dumps(applied,indent=2)+'\n')
        d.save(label+'-hot-pending-at-publication.json',json.dumps(pending,indent=2)+'\n')
        # Retain the independent saved-source assertion after releasing the
        # controlled response; file capture must not consume its real deadline.
        d.verify_saved_source(label+'-hot')
    client=d.client(label,nonce);assert client['uid']==d.uid and len(client['dnsExchanges'])==len(wires),client
    actual=[]
    for index,(query,expected,item)in enumerate(zip(wires,replies,client['dnsExchanges'])):
        assert item.get('sentHex')==query.hex()and item.get('replyHex'),item
        reply=bytes.fromhex(item['replyHex']);actual.append(reply)
        if expected is not None:assert reply==expected,(label,item,expected.hex())
        legal_reply(reply,query,rcode=local_rcodes[index]if local_rcodes else None,
            truncated=truncated,capacity=capacities[index]if capacities else None)
    ids={int.from_bytes(q[:2],'big')for q in wires}
    selected=lambda value:[r for r in dns_rows(value)if r['generation']==d.generation and r['id']in ids
        and r['source_port']==source and bool(r['proxy_flags']&1)!=original]
    observation=d.observation_matching(label,lambda value:all(any(r['id']==identifier and r['stage']==(2 if original else 4)
        for r in selected(value))for identifier in ids))
    records=selected(observation);d.expected_durable.extend(records)
    for query in wires:
        received=peer.received(query,port=selected_port,after=cursor)
        assert len(received)in(expected_udp if isinstance(expected_udp,tuple)else(expected_udp,)),(label,received,expected_udp)
        assert all(bytes.fromhex(row['request_hex'])[2:]==query[2:]for row in received)
        if tcp_retry:
            stream=peer.received(query,'tcp',selected_port,after=cursor);assert len(stream)==1 and bytes.fromhex(stream[0]['request_hex'])[2:]==query[2:]
        else:assert not peer.received(query,'tcp',selected_port,after=cursor)
    after=d.wire_coverage(label+'-after');wire={k:rows[len(before[k]):]for k,rows in after.items()}
    for query,reply in zip(wires,actual):
        original_wire=[r for r in wire[d.physical_interface]if r.get('kind')=='udp'and r['source_port']==source
            and r['destination_port']==53 and r['payload_hex']==query.hex()]
        assert bool(original_wire)==original,(label,'original underlay wire',original_wire)
        if not original:
            returned=[r for r in wire['lo']if r.get('kind')=='udp'and r['source_port']==53
                and r['destination_port']==source and r['payload_hex']==reply.hex()]
            assert returned,(label,'generated return absent at independent loopback capture')
            for row in returned:legal_return_packet(row,query,reply,address,source)
    if not original:
        assert all(r['upstream_port']==selected_port for r in records)
        assert all(r['return_provenance']==5 and r['return_packet_uid']==0 and r['delivery']==2
            for r in records if r['stage']==4),records
    if check:check(records,observation)
    case=dict(label=label,status='PASS',generation=d.generation,owners=d.owners,
        source='ordinary Java App DatagramSocket',source_port=source,original=original,
        queries=[q.hex()for q in wires],replies=[r.hex()for r in actual],peer_cursor=cursor,
        peer_received={str(i):peer.received(q,port=selected_port,after=cursor)for i,q in enumerate(wires)},
        elapsed=time.monotonic()-began,records=records,passive_counts={k:len(v)for k,v in wire.items()})
    d.required_durable += [dict(generation=d.generation,id=identifier,source=source,
        proxy=not original,stages=[1,2]if original else[1,4])for identifier in ids]
    result['cases'].append(case)
    d.save('progress.json',json.dumps(dict(status='IN_PROGRESS',generation=d.generation,
        cases=[r['label']for r in result['cases']],updated_ns=time.time_ns()),indent=2)+'\n')
    return case


def padded_resource(d,peer,result,label):
    query=d.question(label,padding=2048);reply,_=fixtures.answer(query,'ordinary')
    peer.register(query,reply,port=53);peer.register(query,reply,port=53053)
    source=d.reserve_source_port(label);cursor=peer.cursor()
    counters_before=root_receive(d,label+'-receive-before')
    wire_before=d.wire_coverage(label+'-wire-before')
    nonce=d.launch_queries(label,d.args.endpoint4,source,[query],timeout=1800)
    client=d.client(label,nonce);item=client['dnsExchanges'][0]
    assert client['uid']==d.uid and item.get('sentHex')==query.hex(),client
    assert item.get('timedOut')and not item.get('replyHex'),client
    identifier=int.from_bytes(query[:2],'big')
    selected=lambda value:[r for r in dns_rows(value)if r['generation']==d.generation
        and r['id']==identifier and r['source_port']==source and r['stage']==3
        and r['proxy_flags']==9 and r['proxy_result']==6]
    observation=d.observation_matching(label,lambda value:bool(selected(value)))
    rows=selected(observation);assert rows
    for row in rows:
        assert row['delivery']==6 and row['request_attempt']==0,row
        assert row['winner']==row['query_winner']==row['return_winner']==0,row
        assert row['rcode']==row['reply_rcode']==0,row
        assert row['upstream_family']==row['upstream_port']==row['upstream_transport']==0,row
        assert row['upstream_session']==row['output_bytes']==0,row
        assert row['uid']==row['packet_uid']==d.uid and row['packet_availability']&1,row
    d.expected_durable.extend(rows)
    d.required_durable.append(dict(generation=d.generation,id=identifier,source=source,proxy=True,stages=[3]))
    assert not peer.received(query,port=53,after=cursor)
    assert not peer.received(query,port=53053,after=cursor)
    counters_after=root_receive(d,label+'-receive-after')
    assert receive_total(counters_after,'ingress_dns_drop_attempts')>receive_total(counters_before,'ingress_dns_drop_attempts')
    assert receive_total(counters_after,'ingress_envelope')>receive_total(counters_before,'ingress_envelope')
    wire_after=d.wire_coverage(label+'-wire-after')
    wlan=wire_after[d.physical_interface][len(wire_before[d.physical_interface]):]
    escaped=[row for row in wlan if query_wire_prefix(row,query,ignore_id=True)
        and row['destination_port']in(53,53053)]
    returned=[row for row in wire_after['lo'][len(wire_before['lo']):]if row.get('kind')=='udp'
        and row['source_port']==53 and row['destination_port']==source]
    assert not escaped and not returned,(escaped,returned)
    result['cases'].append(dict(status='PASS',label=label,generation=d.generation,owners=d.owners,
        source='ordinary Java App DatagramSocket; valid 2048-byte EDNS padding beyond Root receive envelope',
        source_port=source,query_bytes=len(query),client=client,records=rows,
        receive_before=counters_before,receive_after=counters_after,
        scope='active replacement terminates the captured obligation locally; neither original53 nor selected53053 receives it'))


def padded_off_original(d,peer,result,label):
    query=d.question(label,padding=2048);reply,_=fixtures.answer(query,'ordinary')
    peer.register(query,reply,port=53);source=d.reserve_source_port(label);cursor=peer.cursor()
    counters_before=root_receive(d,label+'-receive-before')
    wire_before=d.wire_coverage(label+'-wire-before')
    nonce=d.launch_queries(label,d.args.endpoint4,source,[query],timeout=4000)
    client=d.client(label,nonce);item=client['dnsExchanges'][0]
    assert client['uid']==d.uid and item.get('sentHex')==query.hex(),client
    actual=bytes.fromhex(item['replyHex']);assert actual==reply;legal_reply(actual,query)
    received=peer.received(query,port=53,after=cursor)
    assert len(received)==1 and not peer.received(query,port=53053,after=cursor),received
    counters_after=root_receive(d,label+'-receive-after')
    assert receive_total(counters_after,'ingress_accepts')>receive_total(counters_before,'ingress_accepts')
    assert receive_total(counters_after,'ingress_envelope')>receive_total(counters_before,'ingress_envelope')
    wire_after=d.wire_coverage(label+'-wire-after')
    wlan=wire_after[d.physical_interface][len(wire_before[d.physical_interface]):]
    original=[row for row in wlan if query_wire_prefix(row,query)
        and row['source_port']==source and row['destination_port']==53]
    assert original
    result['cases'].append(dict(status='PASS',label=label,generation=d.generation,owners=d.owners,
        source='ordinary Java App DatagramSocket; same valid padded query with replacement disabled',
        source_port=source,query_bytes=len(query),client=client,peer=received,
        receive_before=counters_before,receive_after=counters_after,
        scope='off control preserves original resolver path for the same oversized envelope'))


def stale_return_confinement(d,result,label):
    before=d.wire_coverage(label+'-before')
    raw=d.save(label+'-send.json',d.root('/data/local/tmp/s315-stale-return '
        +d.args.endpoint6+' '+d.args.stale6))
    sent=json.loads(raw);assert sent['sent']==sent['expected']==60 and sent['errno']==0,sent
    deadline=time.monotonic()+2;after=None;loop=[]
    while time.monotonic()<deadline:
        after=d.wire_coverage(label+'-after')
        loop=[row for row in after['lo'][len(before['lo']):]
            if row.get('kind')=='udp'and ipaddress.ip_address(row['destination'])==ipaddress.ip_address(d.args.stale6)]
        if loop:break
        time.sleep(.05)
    assert loop,'loopback-bound stale-address probe was not visible on lo'
    time.sleep(.3);after=d.wire_coverage(label+'-settled')
    underlay=[row for row in after[d.physical_interface][len(before[d.physical_interface]):]
        if row.get('kind')in('udp','udp_fragment_first')
        and ipaddress.ip_address(row['destination'])==ipaddress.ip_address(d.args.stale6)]
    assert not underlay,underlay
    for row in loop:
        packet=bytes.fromhex(row['packet_hex']);assert packet[0]>>4==6 and packet[7]==1
    result['cases'].append(dict(status='PASS',label=label,generation=d.generation,owners=d.owners,
        source='privileged controlled raw IPv6 negative probe mirroring the Product route/header boundary',
        route_destination='::1',header_destination=d.args.stale6,loopback_packets=loop,underlay_packets=underlay,
        scope='obsolete/non-local generated-return header is confined to lo with hop-limit1; no App/Product semantic claim'))


def ordinary_rr(d,peer,result,owners):
    prefix=f'n{owners}';d.rules(prefix+'-allow');d.upstream(prefix+'-selected4',d.args.endpoint4);d.proxy_ready(prefix+'-ready4')
    for family,address in((4,d.args.endpoint4),(6,d.args.endpoint6)):
        if family==6:d.upstream(prefix+'-selected6',d.args.endpoint6);d.proxy_ready(prefix+'-ready6')
        label=prefix+f'-v{family}-ordinary';query=d.question(label);reply,_=fixtures.answer(query,'ordinary');peer.register(query,reply)
        exchange(d,peer,result,label,address,[query],[reply])
        if family==6 and owners==1:stale_return_confinement(d,result,label+'-stale-confinement')
    d.upstream(prefix+'-selected4-again',d.args.endpoint4);d.proxy_ready(prefix+'-ready4-again')
    padded_resource(d,peer,result,prefix+'-padded-resource')
    if owners==1:
        wires=[d.question(prefix+'-rr'+str(kind),kind,edns=True)for kind in(28,16,15,33,65,65000)]
        replies=[fixtures.answer(q,'ordinary')[0]for q in wires]
        for q,r in zip(wires,replies):peer.register(q,r)
        exchange(d,peer,result,prefix+'-rr-edns',d.args.endpoint4,wires,replies)


def matrix(d,peer,result,owners):
    ordinary_rr(d,peer,result,owners)
    prefix=f'n{owners}'
    if owners==1:
        malformed=d.question(prefix+'-malformed');malformed=malformed[:4]+bytes(8)
        wires=[malformed,d.question(prefix+'-opcode')]
        wires[1]=wires[1][:2]+b'\x09\x00'+wires[1][4:]
        exchange(d,peer,result,prefix+'-local-errors',d.args.endpoint4,wires,[None,None],local_rcodes=[1,4],expected_udp=0)
    for variant,response_variant,mode in(('query-deny','ordinary',0),('alias-deny','alias',0),('query-deny','ordinary',1)):
        label=prefix+'-'+variant+'-mode'+str(mode);d.rules(label+'-rules',variant,mode=mode)
        q=d.question(label);r,_=fixtures.answer(q,response_variant);peer.register(q,r)
        denied=mode==0
        exchange(d,peer,result,label,d.args.endpoint4,[q],[None if denied else r],local_rcodes=[5]if denied else None,
            expected_udp=0 if variant=='query-deny'and denied else 1,
            check=lambda rows,observation,mode=mode:assert_policy(rows,mode))
    d.rules(prefix+'-clear-policy')
    hot_policy(d,peer,result,prefix)
    d.rules(prefix+'-after-hot')
    label=prefix+'-udp-tc-tcp';q=d.question(label);truncated_reply=struct.pack('!6H',int.from_bytes(q[:2],'big'),0x8380,1,0,0,0)+q[12:]
    r,_=fixtures.answer(q,'ordinary');peer.register(q,truncated_reply);peer.register(q,r,protocol='tcp',split=True)
    exchange(d,peer,result,label,d.args.endpoint4,[q],[r],tcp_retry=True,
        check=lambda rows,observation:assert_tcp(rows))
    if owners==1:
        wires=[];replies=[]
        for code in(0,3,5,2):
            q=d.question(prefix+'-rcode'+str(code));_,_,end=fixtures.decode_question(q)
            r=struct.pack('!6H',int.from_bytes(q[:2],'big'),0x8180|code,1,0,0,0)+q[12:end]
            wires.append(q);replies.append(r);peer.register(q,r)
        exchange(d,peer,result,prefix+'-upstream-rcodes',d.args.endpoint4,wires,replies)
        for edns,client_capacity in((False,512),(True,1232)):
            label=prefix+'-client-tc'+str(client_capacity);q=d.question(label,16,edns=edns);qname,_,end=fixtures.decode_question(q)
            data=(b'\xff'+b'Z'*255)*7;r=struct.pack('!6H',int.from_bytes(q[:2],'big'),0x8180|(0x10 if edns else 0),1,1,0,0)+q[12:end]+fixtures.rr(qname,16,data)
            peer.register(q,r);exchange(d,peer,result,label,d.args.endpoint4,[q],[None],truncated=True,capacities=[client_capacity])
        d.upstream(prefix+'-selected-port53',d.args.endpoint4,53);d.proxy_ready(prefix+'-port53-ready')
        label=prefix+'-selected-port53';q=d.question(label);r,_=fixtures.answer(q,'ordinary');peer.register(q,r,port=53)
        exchange(d,peer,result,label,d.args.endpoint4,[q],[r],selected_port=53)
        d.upstream(prefix+'-after-port53',d.args.endpoint4);d.proxy_ready(prefix+'-after-port53-ready')
        label=prefix+'-deadline-late';q=d.question(label);r,_=fixtures.answer(q,'ordinary');peer.register(q,r,delay=3400)
        exchange(d,peer,result,label,d.args.endpoint4,[q],[None],local_rcodes=[2],expected_udp=2,timeout=6000,
            check=lambda rows,observation:assert_resource(rows,3))
        hot_upstream(d,peer,result,prefix)
    for family,address in((4,d.args.endpoint4),(6,d.args.endpoint6)):
        label=prefix+f'-off-v{family}';d.upstream(label+'-disable');d.proxy_ready(label+'-off-ready',False)
        q=d.question(label);r,_=fixtures.answer(q,'ordinary');peer.register(q,r,port=53)
        exchange(d,peer,result,label,address,[q],[r],selected_port=53,original=True)
        if family==4:padded_off_original(d,peer,result,prefix+'-off-v4-padded')
    d.upstream(prefix+'-restore-selected',d.args.endpoint4);d.proxy_ready(prefix+'-restore-ready')
    if owners==1:
        system_unknown(d,peer,result,prefix+'-system-unknown')
        capacity(d,peer,result,prefix+'-capacity')


def assert_policy(rows,mode):
    assert any(r['stage']in(1,2)and r['winner']and r['mode']==mode and r['declared_action']==2
        and r['actual_action']==(1 if mode else 2)for r in rows),rows


def assert_tcp(rows):
    assert any(r['stage']==2 and r['upstream_transport']==2 and r['upstream_session']for r in rows),rows


def assert_resource(rows,result):
    assert any(r['stage']==3 and r['proxy_result']==result and not r['winner']and r['reply_rcode']==2 for r in rows),rows


def assert_hot(rows):
    assert any(r['stage']==2 and r['query_policy_revision']<r['policy_revision']and r['actual_action']==2 and r['winner']for r in rows),rows


def record_late_release(d,label,gate):
    """Keep a conservative host-clock release boundary before touching the gate."""
    receipt=dict(status='RELEASE_INTENT',release_intent_monotonic=time.monotonic())
    d.save(label+'-release-boundary.json',json.dumps(receipt,indent=2)+'\n')
    try:
        gate.touch()
        receipt.update(status='GATE_RELEASED',release_done_monotonic=time.monotonic())
    except BaseException as error:
        receipt.update(status='HOLD_GATE_RELEASE',error=repr(error));raise
    finally:d.save(label+'-release-boundary.json',json.dumps(receipt,indent=2)+'\n')
    return receipt['release_intent_monotonic']


def await_late_wire(d,label,before,writes,*,complete_coverage=True):
    """Observe the exact peer write at Device; send completion alone is insufficient."""
    assert writes
    with d.control_budget(2):
        deadline=d.capture_deadline;captures=[]
        while True:
            assert time.monotonic()<deadline,'actual late old resolver wire reply absent'
            try:after=d.late_wire_coverage(label+'-capture-'+str(len(captures)))
            except BaseException as error:
                d.save(label+'-arrival-observation.json',json.dumps(dict(status='HOLD_CAPTURE_EXCEPTION',
                    generation=d.generation,writes=writes,captures=captures,error=repr(error),
                    physical_only_arrival_boundary=True,deadline_monotonic=deadline,
                    failed_monotonic=time.monotonic()),indent=2)+'\n')
                raise
            observed=time.monotonic()
            arrived=[row for row in after[d.physical_interface][len(before[d.physical_interface]):]if row.get('kind')=='udp'
                and any(row['source']==write['resolver'][0]and row['source_port']==int(write['resolver'][1])
                    and row['destination']==write['peer'][0]and row['destination_port']==int(write['peer'][1])
                    and row['payload_hex']==write['reply_hex']for write in writes)]
            captures.append(dict(monotonic=observed,wlan_rows=len(after[d.physical_interface]),arrived=len(arrived)))
            status='HOLD_OBSERVER_DEADLINE'if observed>=deadline else'PASS'if arrived else'IN_PROGRESS'
            d.save(label+'-arrival-observation.json',json.dumps(dict(status=status,
                generation=d.generation,writes=writes,captures=captures,arrived_exact=arrived,
                physical_only_arrival_boundary=True,deadline_monotonic=deadline),indent=2)+'\n')
            assert observed<deadline,'late-wire observation deadline exhausted'
            if arrived:break
            assert time.monotonic()<deadline,'actual late old resolver wire reply absent'
            time.sleep(.05)
    # Complete return/fence coverage remains mandatory for default callers,
    # under the surrounding episode budget after the physical-arrival scope.
    # Root/VPN TCP callers do this after leaving their outer release-to-arrival
    # two-second scope too, while retaining the same physical assertion.
    if complete_coverage:after=d.wire_coverage(label+'-full-interval-after-arrival')
    return after,arrived


def late_peer_arrival(d,peer,label,query,gate,cursor,before):
    """One shared Root/VPN TCP release-to-physical-arrival boundary."""
    d.prepare_late_wire(label)
    evidence=dict(status='HOLD',generation=d.generation,physical_arrival_bound_seconds=2)
    with d.control_budget(2):
        released=record_late_release(d,label,gate)
        evidence['released_monotonic']=released
        try:
            while True:
                with peer.lock:
                    sent=[row for row in peer.messages if row.get('kind')=='exchange'and row['request']>cursor
                        and bytes.fromhex(row['request_hex'])[2:]==query[2:]]
                if sent:break
                assert time.monotonic()<d.capture_deadline,'released old upstream reply did not actually send'
                time.sleep(.01)
            _,arrived=await_late_wire(d,label,before,sent,complete_coverage=False)
            observed=time.monotonic()
            assert observed-released<2
            evidence.update(status='PASS_PHYSICAL_ARRIVAL',observed_monotonic=observed,writes=sent,arrived=arrived)
        except BaseException as error:
            evidence.update(status='HOLD_PHYSICAL_ARRIVAL',error=repr(error));raise
        finally:
            evidence['physical_scope_completed_monotonic']=time.monotonic()
            d.save(label+'-lifecycle-observation.json',json.dumps(evidence,indent=2)+'\n')
    try:
        after=d.wire_coverage(label+'-full-interval-after-arrival')
        evidence.update(status='PASS',full_coverage_interfaces=list(after),
            full_coverage_completed_monotonic=time.monotonic())
    except BaseException as error:
        evidence.update(status='HOLD_FULL_INTERVAL_COVERAGE',error=repr(error));raise
    finally:d.save(label+'-lifecycle-observation.json',json.dumps(evidence,indent=2)+'\n')
    return evidence


def hot_policy(d,peer,result,prefix):
    label=prefix+'-hot-policy';q=d.question(label);r,_=fixtures.answer(q,'alias')
    gate=d.out/(label+'.gate');peer.register(q,r,gate=gate)
    point,old=d.rules(label+'-prefill','alias-deny',prefill=True)
    exchange(d,peer,result,label,d.args.endpoint4,[q],[None],local_rcodes=[5],expected_udp=(1,2),
        hot=(point,gate,old),check=lambda rows,observation:assert_hot(rows))


def hot_upstream(d,peer,result,prefix):
    """Publish a new route through its normal button while the old query waits."""
    label=prefix+'-hot-upstream';path='files/product-state/complete-rule-config.properties'
    old=d.query_rules(label+'-before');text='udp '+d.args.endpoint4+' 53'
    d.save(label+'-prefill.txt',d.action('--es','completeRuleText',shlex.quote(text)))
    d.foreground_ui(label+'-prepared');point=d.tap(label+'-point','Set DNS upstream',click=False)
    source=d.reserve_source_port(label);query=d.question(label);reply,_=fixtures.answer(query,'ordinary')
    gate=d.out/(label+'.gate');peer.register(query,reply,gate=gate)
    cursor=peer.cursor();before=d.wire_coverage(label+'-before')
    nonce=d.launch_queries(label,d.args.endpoint4,source,[query],timeout=5000,preserve_ui=True,initial_delay=2000)
    d.verify_ui_focus(label+'-ready')
    d.await_peer_query(peer,label,query,after=cursor,initial_delay=2000)
    d.save(label+'-tap.txt',d.adb('shell','input','tap',*point))
    status=d.applied_status(label,old['queryElapsedMillis'],previous_revision=int(old['activeRevision']))
    assert status['dns.enabled']==status['dns.active.enabled']=='1'
    assert status['dns.port']==status['dns.active.port']=='53'
    selected=lambda value:[r for r in dns_rows(value)if r['generation']==d.generation and r['id']==int.from_bytes(query[:2],'big')
        and r['source_port']==source and r['proxy_flags']&1]
    observation=d.observation_matching(label+'-view-changed',lambda value:any(r['stage']==3 and r['proxy_result']==9 for r in selected(value)))
    rows=selected(observation);d.expected_durable.extend(rows)
    assert any(r['stage']==1 and r['policy_revision']==int(old['activeRevision'])for r in rows),rows
    d.prepare_late_wire(label+'-late');record_late_release(d,label+'-late',gate);d.verify_saved_source(label)
    client=d.client(label,nonce);item,=client['dnsExchanges']
    if item.get('replyHex'):legal_reply(bytes.fromhex(item['replyHex']),query,rcode=2)
    else:assert item.get('timedOut'),client
    deadline=time.monotonic()+2
    while True:
        with peer.lock:
            sent=[r for r in peer.messages if r.get('kind')=='exchange'and r['request']>cursor
                and bytes.fromhex(r['request_hex'])[2:]==query[2:]]
        if sent:break
        assert time.monotonic()<deadline,'old resolver did not actually send after route publication';time.sleep(.01)
    d.forbid_udp_return(label,'lo',before['lo'],source,reply)
    after,arrived=await_late_wire(d,label+'-late',before,sent)
    assert not any(r.get('kind')=='udp'and r['source_port']==53 and r['destination_port']==source
        and r['payload_hex']==reply.hex()for r in after['lo'][len(before['lo']):])
    result['cases'].append(dict(status='PASS',label=label,generation=d.generation,owners=d.owners,
        source='normal upstream UI publication while the old ordinary App query is pending',records=rows,
        client=client,old_revision=old['activeRevision'],new_revision=status['activeRevision'],late_old_resolver=sent,late_device_underlay=arrived,
        scope='native VIEW_CHANGED proves pending at publication; old resolver answer cannot return to App'))
    d.upstream(label+'-restore',d.args.endpoint4);d.proxy_ready(label+'-restored')


def system_unknown(d,peer,result,label):
    selected_port=getattr(d.args,'upstream_port',53053)
    d.rules(label+'-app-deny','query-deny');name=label+'.qname.test';cursor=peer.cursor();before=d.wire_coverage(label+'-before')
    nonce=d.launch_queries(label,d.args.endpoint4,d.reserve_source_port(label),[],system_name=name)
    client=d.client(label,nonce);assert client['uid']==d.uid and client.get('systemDnsRcode')==3,client
    selected=lambda value:[r for r in dns_rows(value)if r['generation']==d.generation and r['name']==name and r['proxy_flags']&1]
    observation=d.observation_matching(label,lambda value:any(r['stage']==4 for r in selected(value)))
    rows=selected(observation);assert rows and any(r['stage']==1 for r in rows)
    assert all(r['caller']==0 and not r['domain_available']and not r['winner']for r in rows if r['stage']in(1,2)),rows
    with peer.lock:
        received=[r for r in peer.messages if r.get('kind')=='received'and r['request']>cursor
            and fixtures.decode_question(bytes.fromhex(r['request_hex']))[0]==name]
    assert len(received)==1 and int(received[0]['resolver'][1])==selected_port,received
    after=d.wire_coverage(label+'-after');request=bytes.fromhex(received[0]['request_hex'])
    assert any(r.get('kind')=='udp'and r['destination_port']==selected_port and bytes.fromhex(r['payload_hex'])==request
        for r in after[d.physical_interface][len(before[d.physical_interface]):])
    d.expected_durable.extend(rows)
    result['cases'].append(dict(status='PASS',label=label,generation=d.generation,
        source='ordinary App Android DnsResolver.rawQuery IPC; native packet caller remains Unknown',client=client,records=rows,peer=received))
    d.rules(label+'-allow-after')


def capacity(d,peer,result,label):
    assert d.owners==1
    batches=[];cursor=peer.cursor();before=d.wire_coverage(label+'-before')
    for batch,count in enumerate((32,33)):
        source=d.reserve_source_port(label+'-'+str(batch));wires=[d.question(label+'-'+str(batch)+'-'+str(i))for i in range(count)]
        for q in wires:peer.register(q,fixtures.answer(q,'ordinary')[0],drop=True)
        batches.append(dict(source=source,wires=wires))
    began=time.monotonic()
    for i,batch in enumerate(batches):
        batch['nonce']=d.launch_queries(label+'-'+str(i),d.args.endpoint4,batch['source'],batch['wires'],timeout=6000,pipeline=True)
    ids={int.from_bytes(q[:2],'big')for batch in batches for q in batch['wires']};sources={b['source']for b in batches}
    selected=lambda value:[r for r in dns_rows(value)if r['generation']==d.generation and r['id']in ids
        and r['source_port']in sources and r['proxy_flags']&1]
    early=d.observation_matching(label+'-early',lambda value:len({r['id']for r in selected(value)if r['stage']==1})==65
        and any(r['stage']==3 and r['proxy_result']==6 for r in selected(value)),timeout=2)
    early_rows=selected(early);d.expected_durable.extend(early_rows)
    status=d.proxy_ready(label+'-high-water')[0]
    assert int(status['transaction_high_water'])==64 and int(status['transaction_limit'])==64 and int(status['proxy_capacity'])>=1,status
    assert int(status['proxy_high_water_bytes'])<=int(status['owner_work_bound'])and int(status['socket_high_water_bytes'])<=int(status['socket_byte_bound']),status
    assert int(status['upstream_socket_high_water'])<=int(status['upstream_socket_limit'])and int(status['sockets'])<=int(status['socket_limit']),status
    clients=[]
    for i,batch in enumerate(batches):
        client=d.client(label+'-'+str(i),batch['nonce']);clients.append(client)
        assert client['pipelineReceived']==len(batch['wires'])and not client['pipelineUnmatched'],client
        for q,item in zip(batch['wires'],client['dnsExchanges']):
            reply=bytes.fromhex(item['replyHex']);legal_reply(reply,q,rcode=2)
            d.required_durable.append(dict(generation=d.generation,id=int.from_bytes(q[:2],'big'),source=batch['source'],proxy=True,stages=[1,3,4]))
    terminal=d.observation_matching(label+'-terminal',lambda value:any(r['stage']==3 and r['proxy_result']==3 for r in selected(value)),timeout=5)
    terminal_rows=selected(terminal);d.expected_durable.extend(terminal_rows)
    received=[peer.received(q,after=cursor)for batch in batches for q in batch['wires']]
    assert sum(bool(r)for r in received)==64 and sum(len(r)for r in received)==128,[len(r)for r in received]
    after=d.wire_coverage(label+'-after')
    for batch,client in zip(batches,clients):
        for q,item in zip(batch['wires'],client['dnsExchanges']):
            reply=bytes.fromhex(item['replyHex']);matches=[r for r in after['lo'][len(before['lo']):]if r.get('kind')=='udp'
                and r['source_port']==53 and r['destination_port']==batch['source']and r['payload_hex']==reply.hex()]
            assert matches
            for row in matches:legal_return_packet(row,q,reply,d.args.endpoint4,batch['source'])
    settled=d.proxy_ready(label+'-settled')[0];assert settled['transactions']=='0'and settled['replies']=='0',settled
    result['cases'].append(dict(label=label,status='PASS',generation=d.generation,owners=1,
        source='two ordinary Java App DatagramSocket batches of32+33',early_records=early_rows,terminal_records=terminal_rows,
        query_limit=early['consumer']['persistent']['dns']['query_limit'],capacity_status=status,settled=settled,
        clients=clients,unique_upstream_requests=64,total_upstream_datagrams=128,elapsed=time.monotonic()-began,
        final_full_record_coverage='independent committed SQLite readback after ordinary stop; public recent bound128 retained'))


def arm_cancellation(d,peer,label):
    query=d.question(label);reply,_=fixtures.answer(query,'ordinary');gate=d.out/(label+'.gate')
    peer.register(query,reply,gate=gate);source=d.reserve_source_port(label);cursor=peer.cursor()
    # Let the launch transport settle before the actual in-flight deadline.
    before=d.wire_coverage(label+'-before');nonce=d.launch_queries(label,d.args.endpoint4,source,[query],timeout=5000,initial_delay=1000)
    d.await_peer_query(peer,label,query,after=cursor,initial_delay=1000)
    status=d.proxy_ready(label+'-active');assert sum(int(row['transactions'])for row in status)==1,status
    return dict(query=query,reply=reply,source=source,cursor=cursor,gate=gate,nonce=nonce,before=before,status=status,label=label)


def settled_cancellation(d,peer,result,pending):
    label=pending['label'];client=d.client(label,pending['nonce'])
    assert client['dnsExchanges'][0].get('timedOut')and not client['dnsExchanges'][0].get('replyHex'),client
    d.prepare_late_wire(label+'-late');record_late_release(d,label+'-late',pending['gate']);deadline=time.monotonic()+2
    while True:
        with peer.lock:
            completed=[r for r in peer.messages if r.get('kind')=='exchange'and r['request']>pending['cursor']
                and bytes.fromhex(r['request_hex'])[2:]==pending['query'][2:]]
        if completed:break
        assert time.monotonic()<deadline,'old upstream did not actually send after Product stop';time.sleep(.01)
    d.forbid_udp_return(label,'lo',pending['before']['lo'],pending['source'],None)
    after,arrived=await_late_wire(d,label+'-late',pending['before'],completed)
    assert not any(r.get('kind')=='udp'and r['source_port']==53 and r['destination_port']==pending['source']
        for r in after['lo'][len(pending['before']['lo']):])
    result['cases'].append(dict(status='PASS',label=label,generation=d.generation,owners=d.owners,
        source='ordinary Java App socket with independently gated upstream',client=client,
        active_before_stop=pending['status'],upstream_writes_after_native_stop=completed,late_device_underlay=arrived,
        scope='normal stop cancelled an actual active proxy; late upstream wire produced no generated App return'))


def smoke(device, peer, result, owners):
    d=device;label=f'n{owners}-v4-ordinary';d.rules(label+'-allow');d.upstream(label+'-upstream',d.args.endpoint4);d.proxy_ready(label)
    query=d.question(label);reply,_=fixtures.answer(query,'ordinary');peer.register(query,reply)
    exchange(d,peer,result,label,d.args.endpoint4,[query],[reply])


def control_smoke(device, peer, result, owners):
    """Regress a normal UI query delayed beyond the device inactivity timeout."""
    d=device;label=f'n{owners}-delayed-ui-control'
    path='files/product-state/complete-rule-config.properties'
    before=props(d.save(label+'-before.properties',d.app(path)))
    d.foreground_ui(label+'-foreground')
    point=d.tap(label+'-query','Query all rules',click=False)
    time.sleep(32)
    power=d.save(label+'-at-input-power.txt',d.adb('shell','dumpsys','power'))
    d.save(label+'-input.txt',d.adb('shell','input','tap',*point))
    status=d.wait(label+'-after',path,
        lambda value:value.get('queryElapsedMillis')not in(None,before.get('queryElapsedMillis')))
    d.valid_config(status)
    assert re.search(r'(?m)^\s*mWakefulness=Awake\s*$',power),power
    assert status['savedRevision']==before['savedRevision']
    assert status['activeRevision']==before['activeRevision']
    result['cases'].append(dict(status='PASS',label=label,generation=d.generation,
        source='normal foreground UI tap after32s inactivity; independent VPP completion projection',
        before_timestamp=before.get('queryElapsedMillis'),after_timestamp=status['queryElapsedMillis']))


def timing_smoke(d,peer,result,owners):
    assert owners==1
    prefix='n1-timing';d.rules(prefix+'-allow');d.upstream(prefix+'-selected',d.args.endpoint4);d.proxy_ready(prefix+'-ready')
    hot_policy(d,peer,result,prefix)
    d.rules(prefix+'-after-hot');capacity(d,peer,result,prefix+'-capacity')
    hot_upstream(d,peer,result,prefix)


def hot_smoke(d,peer,result,owners):
    assert owners==1
    prefix='n1-hot-smoke';d.rules(prefix+'-allow');d.upstream(prefix+'-selected',d.args.endpoint4);d.proxy_ready(prefix+'-ready')
    hot_policy(d,peer,result,prefix)


def edns_smoke(d,peer,result,owners):
    assert owners==1
    prefix='n1-edns';d.rules(prefix+'-allow');d.upstream(prefix+'-selected4',d.args.endpoint4);d.proxy_ready(prefix+'-ready4')
    label=prefix+'-local-deadline';q=d.question(label,28,edns=True);r,_=fixtures.answer(q,'ordinary')
    peer.register(q,r,drop=True)
    exchange(d,peer,result,label,d.args.endpoint4,[q],[None],local_rcodes=[2],expected_udp=2,capacities=[1232],timeout=6000)
    # Keep the route transition that preceded the original failed pipeline.
    d.upstream(prefix+'-selected6',d.args.endpoint6);d.proxy_ready(prefix+'-ready6')
    label=prefix+'-v6';q=d.question(label);r,_=fixtures.answer(q,'ordinary');peer.register(q,r)
    exchange(d,peer,result,label,d.args.endpoint6,[q],[r])
    d.upstream(prefix+'-selected4-again',d.args.endpoint4);d.proxy_ready(prefix+'-ready4-again')
    label=prefix+'-v4-again';q=d.question(label);r,_=fixtures.answer(q,'ordinary');peer.register(q,r)
    exchange(d,peer,result,label,d.args.endpoint4,[q],[r])
    wires=[d.question(prefix+'-rr'+str(kind),kind,edns=True)for kind in(28,16,15,33,65,65000)]
    replies=[fixtures.answer(q,'ordinary')[0]for q in wires]
    for q,r in zip(wires,replies):peer.register(q,r)
    exchange(d,peer,result,prefix+'-rr-pipeline',d.args.endpoint4,wires,replies)
    label=prefix+'-client-tc';q=d.question(label,16,edns=True);qname,_,end=fixtures.decode_question(q)
    data=(b'\xff'+b'Z'*255)*7
    r=struct.pack('!6H',int.from_bytes(q[:2],'big'),0x8190,1,1,0,0)+q[12:end]+fixtures.rr(qname,16,data)
    peer.register(q,r);exchange(d,peer,result,label,d.args.endpoint4,[q],[None],truncated=True,capacities=[1232])


def padded_smoke(device,peer,result,owners):
    d=device;prefix=f'n{owners}-padded-smoke'
    d.rules(prefix+'-allow');d.upstream(prefix+'-selected',d.args.endpoint4);d.proxy_ready(prefix+'-ready')
    padded_resource(d,peer,result,prefix+'-active')
    d.upstream(prefix+'-disable');d.proxy_ready(prefix+'-off-ready',False)
    padded_off_original(d,peer,result,prefix+'-off')
    d.upstream(prefix+'-restore',d.args.endpoint4);d.proxy_ready(prefix+'-restore-ready')


def v6_smoke(device,peer,result,owners):
    d=device;label=f'n{owners}-v6-smoke'
    d.rules(label+'-allow');d.upstream(label+'-selected',d.args.endpoint6);d.proxy_ready(label+'-ready')
    query=d.question(label);reply,_=fixtures.answer(query,'ordinary');peer.register(query,reply)
    exchange(d,peer,result,label,d.args.endpoint6,[query],[reply])
    stale_return_confinement(d,result,label+'-stale-confinement')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('apk','stage','backup','output'):parser.add_argument('--'+key,type=Path,required=True)
    parser.add_argument('--endpoint4',required=True);parser.add_argument('--endpoint6',required=True)
    parser.add_argument('--stale6',default='fd76:d462:c4e3::dead:beef')
    parser.add_argument('--owners',default='1',choices=('1','3','1,3'))
    parser.add_argument('--trace',action='store_true')
    parser.add_argument('--installed',action='store_true')
    parser.add_argument('--peer-only',action='store_true')
    parser.add_argument('--matrix',choices=('control','hot','timing','edns','rr','smoke','padded','v6','full'),default='full')
    parser.add_argument('--cc',default='/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang')
    args=parser.parse_args();args.profile='root';run_deadline=time.monotonic()+1200
    for key in ('apk','stage','backup','output'):setattr(args,key,getattr(args,key).resolve())
    args.output.mkdir(parents=True,exist_ok=False)
    baseline=json.loads((args.backup/'manifest.json').read_text())
    runtime=props((args.backup/'runtime.properties').read_text())
    ledger=props((args.backup/'generation.properties').read_text())
    baseline_generation=int(baseline['generation'])
    assert baseline['status']=='PASS'and baseline['state']=='stopped'and baseline['serial']==SERIAL
    assert baseline_generation==int(runtime['generation'])==int(ledger['generation'])>=2697
    result=dict(status='HOLD',task='SAKAMOTO-315',serial=SERIAL,started_ns=time.time_ns(),
        apk_sha256=digest(args.apk),stage_manifest_sha256=digest(args.stage/'product-stage.properties'),
        backup_manifest_sha256=digest(args.backup/'manifest.json'),cases=[],runs=[])
    closure=[Path(__file__),ROOT/'tests/device/s313-root-dns-tcp.py',ROOT/'tests/device/s312-dns-response.py',
        ROOT/'tests/device/s233-fail-open.py',ROOT/'tests/device/helpers/s312_dns_fixtures.py',
        ROOT/'tests/device/helpers/s314_adb_trace.py',ROOT/'tests/device/helpers/s314_adb_route.py',
        ROOT/'tests/device/helpers/s315_dns_peer.ps1',ROOT/'tests/device/helpers/s315_dns_wire.c',
        ROOT/'tests/device/helpers/s315_dns_stale_return.c',ROOT/'dev/adb']
    result['source_sha256']={str(file.relative_to(ROOT)):digest(file)for file in closure}
    for file in closure:(args.output/('source-'+str(file.relative_to(ROOT)).replace('/','__'))).write_bytes(file.read_bytes())
    device=Device(args);device.capture_deadline=run_deadline;peer=None;failure=None
    result['trace']=dict(requested=args.trace,active=bool(device.adb_trace))
    assert not args.trace or device.adb_trace is not None, 'requested trace activation is unavailable'
    try:
        peer=Peer([args.endpoint4,args.endpoint6],args.output,run_deadline)
        if args.peer_only:
            for family,address in ((socket.AF_INET,args.endpoint4),(socket.AF_INET6,args.endpoint6)):
                for protocol,kind in (('udp',socket.SOCK_DGRAM),('tcp',socket.SOCK_STREAM)):
                    wire=fixtures.question(30000+family+kind);reply,_=fixtures.answer(wire,'ordinary')
                    peer.register(wire,reply,protocol=protocol,split=protocol=='tcp')
                    with socket.socket(family,kind)as client:
                        client.settimeout(3);client.connect((address,53053))
                        client.sendall((struct.pack('!H',len(wire))if protocol=='tcp'else b'')+wire)
                        if protocol=='udp':received=client.recv(65535)
                        else:
                            received=b''
                            while len(received)<2+len(reply):
                                part=client.recv(2+len(reply)-len(received))
                                if not part:raise EOFError('independent peer closed a partial DNS frame')
                                received+=part
                            assert received[:2]==struct.pack('!H',len(reply));received=received[2:]
                        assert received==reply
            result['status']='PASS_INDEPENDENT_PEER_ONLY'
            return
        result['native']=device.install();device.wire_start()
        for owners in map(int,args.owners.split(',')):
            device.owners=owners;run=device.start(owners);result['runs'].append(run)
            runner=(control_smoke if args.matrix=='control'else hot_smoke if args.matrix=='hot'else timing_smoke if args.matrix=='timing'else edns_smoke if args.matrix=='edns'else ordinary_rr if args.matrix=='rr'else smoke if args.matrix=='smoke'else padded_smoke if args.matrix=='padded'
                else v6_smoke if args.matrix=='v6'else matrix)
            runner(device,peer,result,owners)
            run['durable_before_stop']=device.durable(f'n{owners}-durable')
            pending=arm_cancellation(device,peer,f'n{owners}-stop-outstanding')if args.matrix in('full','timing')else None
            run.update(device.stop(f'n{owners}'))
            if pending:settled_cancellation(device,peer,result,pending)
            run['sqlite_after_stop']=device.durable_readback(f'n{owners}')
        result['status']='PASS_ACTUAL_APP_'+args.matrix.upper()
    except BaseException as error:
        failure=error;result['error']=repr(error);result['traceback']=traceback.format_exc()
    finally:
        cleanup=[]
        envelope=CleanupEnvelope(65,[('stop',25),('reader',5),('wire',20),('peer',10),('trace',5)])
        def finish_phase(name, action):
            try:
                with envelope.phase(device,name) as deadline: action(deadline)
            except BaseException as error:
                cleanup.append(name+': '+repr(error))
        if (device.active or device.stop_owed) and getattr(device,'stop_retry_authorized',True):
            finish_phase('stop',lambda _:device.stop('failure-cleanup'))
        elif device.active or device.stop_owed:
            cleanup.append('runtime: unresolved timed stop is fenced from replay')
        if getattr(device,'reader',None) or getattr(device,'prepared_stop_capture',None):
            finish_phase('reader',lambda _:device.settle_reader('failure-cleanup'))
        if device.witnesses:
            finish_phase('wire',lambda _:device.wire_stop())
        if peer:
            def finish_peer(deadline):
                previous=getattr(peer,'cleanup_deadline',None);peer.cleanup_deadline=deadline
                try:peer.close()
                finally:peer.cleanup_deadline=previous
            finish_phase('peer',finish_peer)
        finish_phase('trace',lambda _:device.close_trace())
        if cleanup:result['cleanup_errors']=cleanup;result['status']='HOLD'
        result['completed_ns']=time.time_ns();(args.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(status=result['status'],cases=len(result['cases']),error=result.get('error'),cleanup_errors=result.get('cleanup_errors'))))
    if failure or result.get('cleanup_errors'):raise SystemExit(1)


if __name__=='__main__':main()
