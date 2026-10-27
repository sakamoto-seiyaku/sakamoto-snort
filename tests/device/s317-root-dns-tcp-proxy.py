#!/usr/bin/env python3
"""S317 ordinary Root TCP53 replacement: real App, independent peer/wire/SQLite.

Reuses the existing Product lifecycle/UI/configuration and bounded collectors.
A fresh complete original backup plus routing baseline is required externally.
Host dependency fixtures are not counted as Device executions by this runner.
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
import struct
import subprocess
import time
import traceback

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('s317_root_udp',ROOT/'tests/device/s315-root-dns-proxy.py')
shared=importlib.util.module_from_spec(spec);spec.loader.exec_module(shared)
tcp,support,fixtures=shared.tcp,shared.support,shared.fixtures
PKG,SERIAL=shared.PKG,shared.SERIAL
digest,props=shared.digest,shared.props

class Peer(shared.Peer):
    def __init__(self,addresses,out,deadline=None):
        tcp.Peer.__init__(self,addresses,out,ROOT/'tests/device/helpers/s317_dns_peer.ps1',deadline)

class Device(shared.Device):
    def __init__(self,args):
        super().__init__(args);self.tcp_fences=[];self.tcp_route_fences=[]

    def forbid_original_tcp(self,label,before,source,resolver):
        item=self.witnesses[self.physical_interface]
        self.tcp_route_fences.append(dict(label=label,generation=self.generation,source=source,resolver=resolver,
            baseline_rows=len(before[self.physical_interface]),witness={key:item[key]for key in('pid','start','uid','exe')}))

    def verify_tcp_route_fences(self,rows):
        for fence in self.tcp_route_fences:
            item=self.witnesses[self.physical_interface]
            assert {key:item[key]for key in('pid','start','uid','exe')}==fence['witness']
            escaped=[r for r in rows[fence['baseline_rows']:]if r.get('kind')=='tcp'
                and r['source_port']==fence['source']and r['destination_port']==53
                and ipaddress.ip_address(r['destination'])==ipaddress.ip_address(fence['resolver'])]
            assert not escaped,(fence,escaped)
            self.save(fence['label']+'-original-tcp-fence.json',json.dumps(dict(status='PASS',fence=fence,
                full_rows_through=len(rows),interval='same owned collector from original connection through final Stop'),indent=2)+'\n')

    def release_tcp_phase(self,label,nonce,phase):
        self.save(label+'-release-'+phase+'.txt',self.adb('shell','run-as',PKG,'touch',
            'files/product-state/t12-release-'+nonce+'-'+phase))

    def release_probe(self,label,nonce):
        super().release_probe(label,nonce)
        self.release_tcp_phase(label,nonce,'dns_tcp_written')

    def forbid_tcp_return(self,label,before,source,reply=None):
        item=self.witnesses['lo']
        self.tcp_fences.append(dict(label=label,generation=self.generation,source=source,
            baseline_rows=len(before['lo']),reply_hex=reply.hex()if reply is not None else None,
            witness={key:item[key]for key in('pid','start','uid','exe')}))

    def verify_tcp_fences(self,rows):
        for fence in self.tcp_fences:
            item=self.witnesses['lo']
            assert {key:item[key]for key in('pid','start','uid','exe')}==fence['witness']
            relevant=[r for r in rows[fence['baseline_rows']:]if r.get('kind')=='tcp'
                and r['source_port']==53 and r['destination_port']==fence['source']and r['payload_hex']]
            if fence['reply_hex']is None:assert not relevant,(fence,relevant)
            else:
                reply=bytes.fromhex(fence['reply_hex'])
                assert struct.pack('!H',len(reply))+reply not in stream_bytes(relevant,53,fence['source']),(fence,relevant)
            self.save(fence['label']+'-tcp-return-fence.json',json.dumps(dict(status='PASS',
                fence=fence,full_rows_through=len(rows),permitted_payload_segments=len(relevant),
                interval='same owned collector baseline through this observation; final qualification includes normal Stop'),indent=2)+'\n')

    def wire_coverage(self,label,interfaces=None):
        result=super().wire_coverage(label,interfaces=interfaces)
        if 'lo'in result:self.verify_tcp_fences(result['lo'])
        if self.physical_interface in result:self.verify_tcp_route_fences(result[self.physical_interface])
        return result

    def launch_tcp(self,label,address,source,wires,*,split=False,pipeline=False,repeat=1,
                   timeout=8000,preserve_ui=False,hold=False,options=None):
        nonce='s317-'+label+'-'+str(time.time_ns())
        plan=dict(nonce=nonce,endpoint=address,port=53,source=source,bindDefault=True,
            dnsTcpQueries=[q.hex()for q in wires],dnsTcpRepeat=repeat,dnsProxyTimeoutMs=timeout,
            dnsTcpPipeline=pipeline,dnsTcpWriteSizes=[1,8]if split else[],
            dnsTcpWriteDelayMs=40 if split else 0,dnsTcpHoldAfterReads=hold)
        plan.update(options or {})
        self.save(label+'-plan.json',json.dumps(plan,indent=2)+'\n')
        if preserve_ui:self.adb('shell','input','keyevent','3')
        flags=['-f','0x18000000']if preserve_ui else[]
        if hold or plan.get('dnsTcpGate'):self.active_probe=nonce
        self.save(label+'-launch.txt',self.action(*flags,'--es','t12ProbePlan',shlex.quote(json.dumps(plan))))
        if preserve_ui:self.save(label+'-return-ui.txt',self.action())
        return nonce

    def install(self):
        state=props(self.save('fresh-preinstall-state.properties',self.app('files/runtime-state/snapshot.properties')))
        ledger=props(self.save('fresh-preinstall-ledger.properties',self.app('files/product-state/product-core-generation.properties')))
        assert state['state']=='stopped'and state['mayBeActive']=='false'
        assert int(state['generation'])==int(ledger['generation'])
        processes=self.save('fresh-preinstall-processes.txt',self.root('ps -A -o PID,UID,ARGS'))
        assert not any(len(fields:=line.split())>=3 and Path(fields[2]).name=='libvpp_runtime.so'for line in processes.splitlines())
        package=self.save('fresh-preinstall-package.txt',self.adb('shell','dumpsys','package',PKG))
        code=re.search(r'codePath=(\S+)',package)[1]
        installed=self.save('fresh-preinstall-apk-sha256.txt',self.adb('shell','sha256sum',code+'/base.apk')).split()[0]
        baseline=json.loads((self.args.backup/'manifest.json').read_text())
        expected=digest(self.args.apk)if self.args.installed else baseline['original_apk_sha256']
        if self.args.replace_preserved:
            preservation=json.loads(self.args.replace_preserved.read_text())
            assert not self.args.installed and preservation['status']=='PASS_COMPLETE_CURRENT_TEST_STATE_PRESERVED'
            assert digest(Path(preservation['archive']['path']))==preservation['archive']['sha256']
            assert preservation['fresh']['state']['generation']==state['generation']
            assert preservation['fresh']['ledger']['generation']==ledger['generation']
            expected=preservation['selected_apk_sha256']
        assert installed==expected
        return super().install()

    def rules(self,label,variant='allow',*,prefill=False,mode=0):
        baseline=self.query_rules(label+'-before')
        expression={'query-deny':'1100060301','alias-deny':'1101060101','input-deny':'0601'}.get(variant)
        lines=['lists 3','domain 0 descendants qname.test','domain 1 exact alias.test']
        if expression:
            lines += [f'0 0 4294967295 4294967295 4294967295 10 0 0 0 2 * * 0 65535 0 65535 {expression}',
                'group 10','edge 10 1 0',f'bind 1 {self.uid} 2 10 {mode}']
        index=int(expression is not None)
        lines += ['0 0 4294967295 4294967295 4294967295 1000 0 0 0 1 * * 0 65535 0 65535',
            'group 20',f'edge 20 1 {index}',f'bind 2 {self.uid} 2 20 0']
        request=self.out/(label+'-rules.txt');request.write_text('\n'.join(lines)+'\n')
        remote='/data/local/tmp/s317-rules.txt';self.adb('push',request,remote)
        command=f'am start -n {PKG}/.DebugControlActivity --es completeRuleText "$(cat {remote})"'
        self.save(label+'-prefill.txt',self.adb('shell','sh','-c',shlex.quote(command)));self.adb('shell','rm',remote)
        if prefill:return self.tap(label+'-point','Replace all rules',click=False),baseline
        old=props(self.app('files/product-state/complete-rule-config.properties')).get('queryElapsedMillis')
        self.tap(label+'-replace','Replace all rules');status=self.applied(label,old)
        assert int(status['count'])==int(status['activeCount'])==1+index
        assert status['binding.'+str(index)]==f'2,{self.uid},2,20,0'
        for key in baseline:
            if key.startswith(('dns.','dns.active.')):assert status[key]==baseline[key]
        return status

    def wire_start(self):
        self.select_physical_interface('wire-start')
        source=ROOT/'tests/device/helpers/s317_dns_wire.c';binary=self.out/'s317-wire'
        packet_limit=getattr(self,'wire_packet_limit',1024)
        assert isinstance(packet_limit,int)and 1<=packet_limit<=16384
        subprocess.run([self.args.cc,'-O2','-Wall','-Wextra','-Werror',f'-DS317_WIRE_PACKET_LIMIT={packet_limit}',str(source),'-o',str(binary)],check=True)
        remote='/data/local/tmp/s317-wire'
        paths=[remote]+[remote+'-'+interface+suffix for interface in (self.physical_interface,'lo')for suffix in('.stop','.jsonl')]
        absent=self.root('for p in '+' '.join(map(shlex.quote,paths))+'; do if [ -e "$p" ]; then echo PRESENT:$p; fi; done')
        assert not absent.strip(),'unowned prior witness paths exist: '+absent
        self.adb('push',binary,remote);self.adb('shell','chmod','755',remote)
        assert self.adb('shell','sha256sum',remote).split()[0]==digest(binary)
        addresses=[self.args.endpoint4,self.args.endpoint6,'1.1.1.1','2606:4700:4700::1111','127.0.0.1','::1']
        for interface in (self.physical_interface,'lo'):
            stop=remote+'-'+interface+'.stop';log=remote+'-'+interface+'.jsonl'
            command=remote+' '+interface+' '+stop+' '+' '.join(map(shlex.quote,addresses))+' > '+log+' 2>&1 < /dev/null & echo $!'
            item=dict(pid=None,start=None,uid=None,exe=remote,stop=stop,log=log,launch_pending=True)
            self.witnesses[interface]=item
            pid=int(self.save('wire-'+interface+'-start.txt',self.root(command)).strip());item.update(pid=pid,launch_pending=False)
            raw=self.save('wire-'+interface+'-identity.txt',self.root(f'cat /proc/{pid}/stat; grep "^Uid:" /proc/{pid}/status; readlink /proc/{pid}/exe'))
            lines=raw.splitlines();assert len(lines)==3 and lines[2]==remote
            item.update(start=int(lines[0].split(') ',1)[1].split()[19]),uid=int(lines[1].split()[2]));assert item['uid']==0
            deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                ready_raw=self.adb('shell','cat',log,check=False)
                if'"kind":"ready"'in ready_raw:
                    self.pin_wire_interface(interface,[json.loads(line)for line in ready_raw.splitlines()if line.startswith('{')]);break
                time.sleep(.05)
            else:raise AssertionError('owned TCP wire witness did not become ready')

    def wire_stop(self,interfaces=None,*,defer_files=False):
        errors=[]
        for interface,item in list(self.witnesses.items()):
            if interfaces is not None and interface not in interfaces:continue
            try:
                self.adb('shell','touch',item['stop'])
                deadline=time.monotonic()+8
                while True:
                    rows=self.wire('wire-final',interface)
                    if any(row.get('kind')=='stopped'for row in rows):break
                    assert time.monotonic()<deadline,'owned wire witness did not acknowledge stop'
                    time.sleep(.05)
                stopped,=[row for row in rows if row.get('kind')=='stopped']
                assert stopped['reason']=='requested'and stopped['stats_ok']and stopped['socket_drops']==0,stopped
                if interface=='lo':self.verify_tcp_fences(rows)
                if interface==self.physical_interface:self.verify_tcp_route_fences(rows)
                processes=self.save('wire-'+interface+'-processes-after.txt',self.root('ps -A -o PID,UID,ARGS'))
                assert not any((fields:=line.split())and fields[0]==str(item['pid'])for line in processes.splitlines())
                if defer_files:
                    # Actor completion is proved now. Removing its already
                    # archived files can follow the deadline-sensitive Stop.
                    debt=dict(interface=interface,item=dict(item),raw_sha256=digest(self.out/('wire-final-'+interface+'.jsonl')))
                    self.deferred_wire_files=getattr(self,'deferred_wire_files',[])+[debt]
                else:self.adb('shell','rm','-f',item['stop'],item['log'])
                del self.witnesses[interface]
            except BaseException as error:errors.append(error)
        if not self.witnesses and not getattr(self,'deferred_wire_files',[]):self.adb('shell','rm','-f','/data/local/tmp/s317-wire','/data/local/tmp/s317-rules.txt')
        if errors:raise BaseExceptionGroup('S317 exact owned wire cleanup retained HOLD',errors)

    def settle_deferred_wire_files(self):
        for debt in list(getattr(self,'deferred_wire_files',[])):
            item=debt['item']
            actual=self.adb('shell','sha256sum',item['log']).split()[0]
            assert actual==debt['raw_sha256'],'terminal wire file changed after actor completion'
            self.adb('shell','rm','-f',item['stop'],item['log'])
            self.deferred_wire_files.remove(debt)
            self.save('wire-'+debt['interface']+'-deferred-file-settlement.json',json.dumps(dict(
                status='PASS_ARCHIVED_TERMINAL_FILES_REMOVED',debt=debt,original_actor_already_proved_absent=True),indent=2)+'\n')
        if not self.witnesses:self.adb('shell','rm','-f','/data/local/tmp/s317-wire','/data/local/tmp/s317-rules.txt')

    def qualified_stop(self,label):
        result=super().qualified_stop(label)
        hooks=self.save(label+'-all-hooks-after.txt',self.root('iptables-save -t mangle; ip6tables-save -t mangle; iptables-save -t nat'))
        rules=self.save(label+'-ipv6-rules-after.txt',self.root('ip -6 -o rule show'))
        table=self.save(label+'-ipv6-table-after.txt',self.root('ip -6 route show table 1396985427'))
        assert 'SAKAMOTO_PRODUCT_'not in hooks and not table.strip()
        before=(self.args.backup.parent/'routing-baseline-r1/ipv6-rules.stdout').read_text().replace('\r','')
        assert rules==before,'original IPv6 rules changed or Product-owned rule remains'
        result.update(owned_nat_tproxy_ct_hooks_absent=True,original_ipv6_rules_exact=True,owned_route_table_empty=True)
        return result


def stream_bytes(rows,source_port,destination_port):
    segments={}
    for row in rows:
        if(row.get('kind')!='tcp' or row['source_port']!=source_port or row['destination_port']!=destination_port
            or row['packet_type']!=4 or not row['payload_hex']):continue
        value=bytes.fromhex(row['payload_hex']);seq=row['sequence']
        if seq in segments:assert segments[seq]==value,'wire retransmission changed bytes'
        segments[seq]=value
    if not segments:return b''
    result=bytearray();expected=min(segments)
    for seq,value in sorted(segments.items()):
        if seq<expected:
            overlap=expected-seq;assert overlap<=len(value)and result[-overlap:]==value[:overlap]
            value=value[overlap:];seq=expected
        assert seq==expected,'observed TCP stream has a sequence gap'
        result.extend(value);expected+=len(value)
    return bytes(result)


def smoke(device,peer,result,owners):
    d=device;d.rules('n'+str(owners)+'-allow')
    for family,resolver,upstream in ((4,'1.1.1.1',d.args.endpoint4),(6,'2606:4700:4700::1111',d.args.endpoint6)):
        label=f'n{owners}-tcp{family}-full'
        d.upstream(label+'-upstream',upstream);d.proxy_ready(label+'-ready')
        native=d.cli(label+'-native-before','show product dns proxy','show product root lanes')
        rows=[props(line.replace(' ','\n'))for line in native.splitlines()if'dns.proxy_tcp owner='in line]
        assert len(rows)==owners and all(row['ready']=='1'for row in rows),native
        source=d.reserve_source_port(label);query=d.question(label,65280)
        name,qtype,end=fixtures.decode_question(query)
        full=query[:2]+struct.pack('!5H',0x8180,1,1,0,0)+query[12:end]+fixtures.rr(name,qtype,bytes([0xa5])*600)
        assert len(full)>512
        tc=query[:2]+struct.pack('!5H',0x8380,1,0,0,0)+query[12:end]
        cursor=peer.cursor();peer.register(query,tc,protocol='udp');peer.register(query,full,protocol='tcp',split=True)
        nonce=d.launch_tcp(label,resolver,source,[query],split=True,timeout=2000,hold=True)
        client=None
        try:
            client=d.wait(label+'-client-open','files/product-state/t12-'+nonce+'.json',lambda c:c.get('phase')in('dns_tcp_read_complete','finished'),timeout=30,json_value=True)
            assert client['phase']=='dns_tcp_read_complete'and not client.get('error'),client
            assert client['dnsExchanges']==[dict(sentHex=query.hex(),replyHex=full.hex())],client
            current=lambda row:row['generation']==d.generation and row['id']==int.from_bytes(query[:2],'big')and row['source_port']==source
            observed=d.observation_matching(label,lambda value:any(current(row)and row['stage']==4 for row in shared.dns_rows(value)),timeout=10)
            records=[row for row in shared.dns_rows(observed)if current(row)]
            assert {row['stage']for row in records}=={1,2,4},records
            for record in records:
                assert record['protocol']==6 and record['caller']==1 and record['uid']==d.uid and record['transport_session']!=0
                assert record['generation']==d.generation and record['family']==family and record['reply_capacity']==65535
                assert record['source_port']==source and record['resolver_port']==53
                assert ipaddress.ip_address(bytes(record['resolver_address'][:4]if family==4 else record['resolver_address']))==ipaddress.ip_address(resolver)
            delivered,=[row for row in records if row['stage']==4]
            assert delivered['delivery']==2 and delivered['output_bytes']==len(full)and delivered['upstream_transport']==2
            assert delivered['return_provenance']==0 and delivered['return_policy_revision']==0
            d.expected_durable.extend(records)
            udp=peer.received(query,'udp',53053,after=cursor);tcp_rows=peer.received(query,'tcp',53053,after=cursor)
            assert len(udp)==len(tcp_rows)==1,(udp,tcp_rows)
            wires=d.wire_coverage(label)
            assert not any(row.get('kind')=='tcp'and row.get('source_port')==source and row.get('destination_port')==53 for row in wires[d.physical_interface]), 'ordinary client TCP53 escaped to original resolver'
            local_port=15353+delivered['owner'] if family==4 else 53
            assert stream_bytes(wires['lo'],source,local_port)==struct.pack('!H',len(query))+query,wires['lo']
            reply=stream_bytes(wires['lo'],53,source)
            assert reply==struct.pack('!H',len(full))+full,'complete original-source TCP answer missing on loopback'
            native=d.cli(label+'-native-after','show product dns proxy','show product completion')
            result['cases'].append(dict(status='PASS',label=label,generation=d.generation,owner=delivered['owner'],source_port=source,
                ordinary_app=True,original_resolver=resolver,selected_upstream=upstream,query_hex=query.hex(),reply_hex=full.hex(),records=records,
                app_phase=client['phase'],wire_loopback_query_bytes=len(query)+2,wire_loopback_reply_bytes=len(full)+2,
                original_tcp53_absent_from_underlay=True,same_resolver_udp_tc_tcp=True))
        finally:
            d.release_probe(label,nonce)
            if getattr(d,'active_probe',None)==nonce:d.active_probe=None
        finished=d.client(label,nonce);assert finished['dnsExchanges']==client['dnsExchanges']


def paired_exchange(d,peer,result,label,resolver,queries,replies,*,rcodes=None,options=None,
                    peer_counts=None,reverse=False):
    """One ordinary App socket; assertions include exact complete questions."""
    source=d.reserve_source_port(label);cursor=peer.cursor();before=d.wire_coverage(label+'-before')
    d.forbid_original_tcp(label,before,source,resolver)
    nonce=d.launch_tcp(label,resolver,source,queries,pipeline=True,split=True,hold=True,options=options)
    client=None
    try:
        client=d.wait(label+'-reads','files/product-state/t12-'+nonce+'.json',
            lambda c:c.get('phase')in('dns_tcp_read_complete','finished'),timeout=30,json_value=True)
        assert client['phase']=='dns_tcp_read_complete'and not client.get('error'),client
        actual=[bytes.fromhex(x['replyHex'])for x in client['dnsExchanges']]
        assert len(actual)==len(queries)
        unmatched=list(range(len(queries)))
        for received in actual:
            name,qtype,end=fixtures.decode_question(received)
            matches=[i for i in unmatched if fixtures.decode_question(queries[i])[:2]==(name,qtype)]
            assert len(matches)==1,(label,received.hex(),queries)
            index=matches[0];unmatched.remove(index)
            if replies[index]is not None:assert received==replies[index]
            if rcodes:assert int.from_bytes(received[2:4],'big')&15==rcodes[index]
            # The shared local-error helper requires an empty answer section.
            # Complete upstream answers retain their independently exact bytes.
            shared.legal_reply(received,queries[index],rcode=rcodes[index]
                if replies[index]is None and rcodes else None)
        assert not unmatched
        if reverse:assert actual==list(reversed(replies)),[q.hex()for q in actual]
        ids={int.from_bytes(q[:2],'big')for q in queries}
        selected=lambda value:[r for r in shared.dns_rows(value)if r['generation']==d.generation
            and r['source_port']==source and r['id']in ids and r['protocol']==6]
        observed=d.observation_matching(label,lambda value:len([r for r in selected(value)if r['stage']==4])==len(queries),timeout=10)
        records=selected(observed);delivered=[r for r in records if r['stage']==4]
        assert len({r['token']for r in delivered})==len(queries)
        assert len({r['transport_session']for r in delivered})==1
        for r in delivered:
            assert r['caller']==1 and r['uid']==d.uid and r['delivery']==2 and r['reply_capacity']==65535
            assert r['message_sequence']==r['token']and r['return_provenance']==r['return_policy_revision']==0
        scoped_dispatch=getattr(d,'qualify_peer_dispatches',None)
        received_by_question=[peer.received(query,after=cursor)for query in queries]
        if scoped_dispatch is None:
            for received,count in zip(received_by_question,peer_counts or [1]*len(queries)):
                assert len(received)==count,(label,received,count)
        wires=d.wire_coverage(label+'-after');wire={k:v[len(before[k]):]for k,v in wires.items()}
        dispatch_qualifications=scoped_dispatch(label,queries,records,received_by_question,wire,
            peer_counts or [1]*len(queries))if scoped_dispatch else None
        assert not any(r.get('kind')=='tcp'and r['source_port']==source and r['destination_port']==53 for r in wire[d.physical_interface])
        assert stream_bytes(wire['lo'],53,source)==b''.join(struct.pack('!H',len(r))+r for r in actual)
        d.expected_durable.extend(records)
        case=dict(status='PASS',label=label,generation=d.generation,source_port=source,queries=[q.hex()for q in queries],
            replies=[q.hex()for q in actual],records=records,options=options or{},same_socket=True,
            original_tcp53_absent_from_underlay=True,peer_counts=peer_counts or [1]*len(queries))
        if dispatch_qualifications is not None:
            case.update(dispatch_qualifications=dispatch_qualifications,peer_count_scope='S319 qualified logical dispatches; raw datagrams retained')
        result['cases'].append(case);d.save('progress.json',json.dumps(result,indent=2)+'\n')
        return case
    finally:
        d.release_probe(label,nonce)
        if getattr(d,'active_probe',None)==nonce:d.active_probe=None
        if client and client.get('phase')=='dns_tcp_read_complete':
            finished=d.client(label,nonce);assert finished['dnsExchanges']==client['dnsExchanges']


def core(device,peer,result,owners):
    d=device
    if d.args.matrix=='core':smoke(d,peer,result,owners)
    for family,resolver,upstream in ((4,'1.1.1.1',d.args.endpoint4),(6,'2606:4700:4700::1111',d.args.endpoint6)):
        d.upstream(f'n{owners}-core{family}-upstream',upstream);d.proxy_ready(f'n{owners}-core{family}-ready')
        for variant in ('same-id-ooo','query-deny','alias-deny','half-close','partial-fin'):
            label=f'n{owners}-v{family}-'+variant
            d.rules(label+'-rules',variant if variant in('query-deny','alias-deny')else'allow')
            first=d.question(label+'-first');d.next_identifier+=1
            second=fixtures.question(int.from_bytes(first[:2],'big')if variant=='same-id-ooo'else d.next_identifier,
                label+'-second.allowed.test')
            first_reply,_=fixtures.answer(first,'alias'if variant=='alias-deny'else'ordinary')
            second_reply,_=fixtures.answer(second,'ordinary')
            peer.register(first,first_reply,delay=400 if variant=='same-id-ooo'else 0)
            peer.register(second,second_reply)
            denied=variant in('query-deny','alias-deny')
            paired_exchange(d,peer,result,label,resolver,[first,second],[None if denied else first_reply,second_reply],
                rcodes=[5 if denied else 0,0],peer_counts=[0 if variant=='query-deny'else 1,1],
                reverse=variant=='same-id-ooo',options=dict(dnsTcpShutdownOutput=True,
                    dnsTcpPartialFin=variant=='partial-fin')if variant in('half-close','partial-fin')else None)


def tcp_records(d,value,queries,source):
    ids={int.from_bytes(q[:2],'big')for q in queries}
    rows=[r for r in shared.dns_rows(value)if r['generation']==d.generation and r['protocol']==6
        and r['source_port']==source and r['id']in ids and r['proxy_flags']&1]
    for r in rows:
        assert r['caller']==1 and r['uid']==d.uid and r['transport_session'] and r['token']&(1<<63)
        assert r['message_sequence']==r['token']and r['reply_capacity']==65535
        assert r['return_provenance']==r['return_policy_revision']==0
    return rows


def late_arrival(d,peer,label,query,gate,cursor,before):
    return shared.late_peer_arrival(d,peer,label,query,gate,cursor,before)


def single_positive(d,peer,result,label,resolver):
    query=d.question(label);reply,_=fixtures.answer(query,'ordinary');peer.register(query,reply)
    return paired_exchange(d,peer,result,label,resolver,[query],[reply],rcodes=[0])


def lifecycle(d,peer,result,owners):
    for family,resolver,upstream in ((4,'1.1.1.1',d.args.endpoint4),(6,'2606:4700:4700::1111',d.args.endpoint6)):
        prefix=f'n{owners}-life-v{family}'
        d.rules(prefix+'-allow');d.upstream(prefix+'-upstream',upstream);d.proxy_ready(prefix+'-ready')
        # An actual deadline precedes an independently released old answer.
        # Keep its negative interval through fresh success and normal Stop.
        label=prefix+'-deadline';query=d.question(label);reply,_=fixtures.answer(query,'ordinary')
        gate=d.out/(label+'.gate');peer.register(query,reply,gate=gate)
        source=d.reserve_source_port(label);cursor=peer.cursor();before=d.wire_coverage(label+'-before')
        d.forbid_original_tcp(label,before,source,resolver)
        nonce=d.launch_tcp(label,resolver,source,[query],pipeline=True,hold=True)
        try:
            client=d.wait(label+'-read','files/product-state/t12-'+nonce+'.json',
                lambda c:c.get('phase')in('dns_tcp_read_complete','finished'),timeout=15,json_value=True)
            assert client['phase']=='dns_tcp_read_complete'and not client.get('error'),client
            actual=bytes.fromhex(client['dnsExchanges'][0]['replyHex']);shared.legal_reply(actual,query,rcode=2)
            d.forbid_tcp_return(label,before,source,reply)
            arrival=late_arrival(d,peer,label+'-late',query,gate,cursor,before)
            observed=d.observation_matching(label,lambda value:any(r['stage']==4 for r in tcp_records(d,value,[query],source)))
            records=tcp_records(d,observed,[query],source);d.expected_durable.extend(records)
            assert any(r['stage']==3 and r['proxy_result']==3 for r in records),records
            assert any(r['stage']==4 and r['delivery']==2 and r['reply_rcode']==2 for r in records),records
            assert len(peer.received(query,after=cursor))==2
            result['cases'].append(dict(status='PASS',label=label,generation=d.generation,source_port=source,
                query_hex=query.hex(),reply_hex=actual.hex(),records=records,late=arrival))
        finally:
            gate.touch();d.release_probe(label,nonce);d.active_probe=None
        d.client(label,nonce)
        single_positive(d,peer,result,prefix+'-after-deadline',resolver)

        # A real FIN followed by SO_LINGER(0) RST retires the pending query
        # before the unchanged three-second upstream deadline.
        label=prefix+'-fin-rst';query=d.question(label);reply,_=fixtures.answer(query,'ordinary')
        gate=d.out/(label+'.gate');peer.register(query,reply,gate=gate)
        source=d.reserve_source_port(label);cursor=peer.cursor();before=d.wire_coverage(label+'-before')
        d.forbid_original_tcp(label,before,source,resolver)
        nonce=d.launch_tcp(label,resolver,source,[query],pipeline=True,preserve_ui=True,
            options=dict(dnsTcpShutdownOutput=True,dnsTcpResetAfterWrite=True,dnsTcpGate=True))
        try:
            d.await_peer_query(peer,label,query,after=cursor)
            d.release_tcp_phase(label,nonce,'dns_tcp_written')
            client=d.client(label,nonce);assert client['resetAfterWrite']and client['outputShutdown']
            d.active_probe=None;d.forbid_tcp_return(label,before,source)
            current=d.wire_coverage(label+'-reset')
            packets=[r for r in current['lo'][len(before['lo']):]if r.get('kind')=='tcp'and r['source_port']==source]
            fin=[r for r in packets if r['flags']&1];rst=[r for r in packets if r['flags']&4]
            assert fin and rst and min(r['mono_ns']for r in rst)>=min(r['mono_ns']for r in fin)
            sent=[r for r in packets if r['payload_hex']]
            assert sent and min(r['mono_ns']for r in rst)-min(r['mono_ns']for r in sent)<3_000_000_000
            arrival=late_arrival(d,peer,label+'-late',query,gate,cursor,before)
            observed=d.observation_matching(label,lambda value:any(r['stage']==3 and r['proxy_result']==7
                for r in tcp_records(d,value,[query],source)))
            records=tcp_records(d,observed,[query],source);d.expected_durable.extend(records)
            assert not any(r['stage']==4 and r['delivery']==2 for r in records)
            result['cases'].append(dict(status='PASS',label=label,generation=d.generation,source_port=source,
                query_hex=query.hex(),client=client,records=records,fin=fin,rst=rst,late=arrival))
        finally:
            gate.touch();d.release_probe(label,nonce);d.active_probe=None
        single_positive(d,peer,result,prefix+'-after-rst',resolver)


def capacity(d,peer,result,owners):
    label=f'n{owners}-tcp-65-capacity';d.rules(label+'-allow');d.upstream(label+'-upstream',d.args.endpoint4)
    before_status=d.proxy_ready(label+'-ready');assert all(r['transactions']=='0'for r in before_status),before_status
    queries=[d.question(label+'-'+str(i))for i in range(65)]
    for query in queries:peer.register(query,fixtures.answer(query,'ordinary')[0],drop=True)
    source=d.reserve_source_port(label);cursor=peer.cursor();before=d.wire_coverage(label+'-before')
    d.forbid_original_tcp(label,before,source,'1.1.1.1')
    nonce=d.launch_tcp(label,'1.1.1.1',source,queries,pipeline=True,hold=True)
    try:
        early=d.observation_matching(label+'-early',lambda value:len({r['id']for r in tcp_records(d,value,queries,source)
            if r['stage']==1})==65 and any(r['stage']==3 and r['proxy_result']==6 for r in tcp_records(d,value,queries,source)),timeout=2)
        early_rows=tcp_records(d,early,queries,source);d.expected_durable.extend(early_rows)
        status=d.proxy_ready(label+'-capacity-status')
        assert any(int(r['transaction_high_water'])==64 and int(r['proxy_capacity'])>=1 for r in status),status
        assert all(int(r['transaction_high_water'])<=int(r['transaction_limit'])==64
            and int(r['proxy_high_water_bytes'])<=int(r['owner_work_bound'])for r in status)
        client=d.wait(label+'-reads','files/product-state/t12-'+nonce+'.json',
            lambda c:c.get('phase')in('dns_tcp_read_complete','finished'),timeout=20,json_value=True)
        assert client['phase']=='dns_tcp_read_complete'and not client.get('error'),client
        answers=[bytes.fromhex(item['replyHex'])for item in client['dnsExchanges']]
        assert len(answers)==65
        by_id={int.from_bytes(q[:2],'big'):q for q in queries}
        assert len({int.from_bytes(r[:2],'big')for r in answers})==65
        for reply in answers:shared.legal_reply(reply,by_id[int.from_bytes(reply[:2],'big')],rcode=2)
        received=[peer.received(q,after=cursor)for q in queries]
        assert sum(bool(x)for x in received)==64 and sum(map(len,received))==128,[len(x)for x in received]
        after=d.wire_coverage(label+'-after')
        assert stream_bytes(after['lo'][len(before['lo']):],53,source)==b''.join(struct.pack('!H',len(r))+r for r in answers)
        assert not any(r.get('kind')=='tcp'and r['source_port']==source and r['destination_port']==53
            for r in after[d.physical_interface][len(before[d.physical_interface]):])
        for query in queries:d.required_durable.append(dict(generation=d.generation,id=int.from_bytes(query[:2],'big'),source=source,proxy=True,stages=[1,3,4]))
        settled=d.proxy_ready(label+'-settled');assert all(r['transactions']==r['replies']=='0'for r in settled)
        native=d.cli(label+'-tcp-bounds','show product dns proxy')
        io_rows=[props(line.replace(' ','\n'))for line in native.splitlines()if'dns.proxy_tcp owner='in line]
        assert len(io_rows)==owners and all(int(r['clients'])<=int(r['client_limit'])==8 and
            int(r['outputs'])<=int(r['output_limit'])==128 and int(r['bytes'])<=int(r['byte_limit'])==2*1024*1024 for r in io_rows)
        result['cases'].append(dict(status='PASS',label=label,generation=d.generation,source_port=source,
            queries=[q.hex()for q in queries],replies=[r.hex()for r in answers],early_records=early_rows,
            capacity_status=status,settled=settled,tcp_bounds=io_rows,unique_upstream_requests=64,total_upstream_datagrams=128,
            durable_requirement='each of65 current-generation real query identities retains phase1/3/4 in normal committed MAIN after Stop'))
    finally:d.release_probe(label,nonce);d.active_probe=None
    d.client(label,nonce)
    single_positive(d,peer,result,f'n{owners}-after-capacity','1.1.1.1')


def finish_run(d,result,label,*,pending=False):
    run=result['runs'][-1]
    if not pending:run['durable_before_stop']=d.durable(label+'-durable')
    else:
        d.durable_target=max(getattr(d,'durable_target',0),2)
        run['durable_before_stop']=dict(scope='actual pending query stopped before deadline; independent complete committed MAIN requires both real query and stopped-event identities')
    run.update(d.stop(label));run['sqlite_after_stop']=d.durable_readback(label)
    return run


def stop_late(d,peer,result,owners):
    label=f'n{owners}-pending-stop-oldgen';d.rules(label+'-allow');d.upstream(label+'-upstream',d.args.endpoint4);d.proxy_ready(label+'-ready')
    query=d.question(label);reply,_=fixtures.answer(query,'ordinary');gate=d.out/(label+'.gate')
    peer.register(query,reply,gate=gate,gate_seconds=120)
    source=d.reserve_source_port(label);cursor=peer.cursor();before=d.wire_coverage(label+'-before');old=d.generation
    d.forbid_original_tcp(label,before,source,'1.1.1.1')
    nonce=d.launch_tcp(label,'1.1.1.1',source,[query],pipeline=True)
    try:
        d.await_peer_query(peer,label,query,after=cursor)
        d.required_durable.append(dict(generation=old,id=int.from_bytes(query[:2],'big'),source=source,proxy=True,stages=[1,3]))
        stopped=finish_run(d,result,label,pending=True)
        records=[r for r in stopped['sqlite_after_stop']['current_generation_records']if r['id']==int.from_bytes(query[:2],'big')and r['source_port']==source and r['protocol']==6]
        assert all(r['caller']==1 and r['uid']==d.uid and r['transport_session']and r['token']&(1<<63)
            and r['message_sequence']==r['token']and r['reply_capacity']==65535 for r in records)
        assert any(r['stage']==3 and r['proxy_result']==8 for r in records),records
        raw=(d.out/(label+'-stop.log')).read_text()
        assert re.search(rf'dns.proxy event=quiesce generation={old} owner=\d+ active_before=1 cancelled_now=1',raw)
        client=d.wait(label+'-client','files/product-state/t12-'+nonce+'.json',lambda c:c.get('phase')=='finished',timeout=10,json_value=True)
        assert not any(item.get('replyHex')for item in client['dnsExchanges']),client
        d.forbid_tcp_return(label,before,source)
        result['runs'].append(d.start(owners));assert d.generation>old
        d.upstream(label+'-newgen-upstream',d.args.endpoint4);d.proxy_ready(label+'-newgen-ready')
        arrival=late_arrival(d,peer,label+'-late',query,gate,cursor,before)
        fresh=single_positive(d,peer,result,f'n{owners}-newgen-after-late','1.1.1.1')
        result['cases'].append(dict(status='PASS',label=label,generation=old,new_generation=d.generation,source_port=source,
            query_hex=query.hex(),client=client,records=records,late=arrival,fresh_positive=fresh['label'],
            interval='old query through actual pending Stop, native zero, restart, actual late arrival, fresh positive and final Stop'))
    finally:gate.touch()


def toggle(d,peer,result,owners):
    for family,resolver,upstream in ((4,'1.1.1.1',d.args.endpoint4),(6,'2606:4700:4700::1111',d.args.endpoint6)):
        label=f'n{owners}-toggle-v{family}'
        d.rules(label+'-allow');d.upstream(label+'-upstream',upstream);d.proxy_ready(label+'-ready')
        old=d.query_rules(label+'-before-config')
        d.save(label+'-prefill.txt',d.action('--es','completeRuleText',shlex.quote('off')))
        d.foreground_ui(label+'-prepared');point=d.tap(label+'-off-point','Set DNS upstream',click=False)
        query=d.question(label);reply,_=fixtures.answer(query,'ordinary');gate=d.out/(label+'.gate')
        peer.register(query,reply,gate=gate)
        source=d.reserve_source_port(label);cursor=peer.cursor();before=d.wire_coverage(label+'-before')
        d.forbid_original_tcp(label,before,source,resolver)
        nonce=d.launch_tcp(label,resolver,source,[query],pipeline=True,hold=True,preserve_ui=True)
        try:
            d.await_peer_query(peer,label,query,after=cursor)
            d.save(label+'-off-tap.txt',d.adb('shell','input','tap',*point))
            status=d.applied_status(label+'-off',old['queryElapsedMillis'],previous_revision=int(old['activeRevision']))
            assert status['dns.enabled']==status['dns.active.enabled']=='0'
            d.selected_dns=dict(endpoint=(None,0),route_revision=int(status['activeRevision']),active_revision=int(status['activeRevision']))
            disabled=d.proxy_ready(label+'-off-ready',False)
            client=d.wait(label+'-old-read','files/product-state/t12-'+nonce+'.json',
                lambda c:c.get('phase')in('dns_tcp_read_complete','finished'),timeout=10,json_value=True)
            assert client['phase']=='dns_tcp_read_complete'and not client.get('error'),client
            actual=bytes.fromhex(client['dnsExchanges'][0]['replyHex']);shared.legal_reply(actual,query,rcode=2)
            observed=d.observation_matching(label,lambda value:any(r['stage']==3 and r['proxy_result']==9
                for r in tcp_records(d,value,[query],source)))
            records=tcp_records(d,observed,[query],source);d.expected_durable.extend(records)
            assert any(r['stage']==4 and r['delivery']==2 and r['reply_rcode']==2 for r in records),records
            d.forbid_tcp_return(label,before,source,reply)
            arrival=late_arrival(d,peer,label+'-old-late',query,gate,cursor,before)

            # Off means an ordinary new connection uses its original public
            # destination. Resolver availability is recorded separately from
            # this real original-path SYN and zero selected-upstream admission.
            off_label=label+'-original';off_query=d.question(off_label);off_source=d.reserve_source_port(off_label)
            off_before=d.wire_coverage(off_label+'-before');off_cursor=peer.cursor()
            off_nonce=d.launch_tcp(off_label,resolver,off_source,[off_query],pipeline=True,timeout=1000)
            off_client=d.wait(off_label+'-client','files/product-state/t12-'+off_nonce+'.json',
                lambda c:c.get('phase')=='finished',timeout=10,json_value=True)
            off_after=d.wire_coverage(off_label+'-after')
            original=[r for r in off_after[d.physical_interface][len(off_before[d.physical_interface]):]if r.get('kind')=='tcp'
                and r['source_port']==off_source and r['destination_port']==53 and r['flags']&2
                and ipaddress.ip_address(r['destination'])==ipaddress.ip_address(resolver)]
            assert original and not peer.received(off_query,after=off_cursor),(original,off_client)
            off_observed=d.observation(off_label+'-observed');assert not tcp_records(d,off_observed,[off_query],off_source)
            d.upstream(label+'-on',upstream);enabled=d.proxy_ready(label+'-on-ready')
            fresh=single_positive(d,peer,result,label+'-fresh',resolver)
            result['cases'].append(dict(status='PASS',label=label,generation=d.generation,source_port=source,
                query_hex=query.hex(),reply_hex=actual.hex(),records=records,disabled=disabled,enabled=enabled,
                old_late=arrival,original_path=dict(source_port=off_source,query_hex=off_query.hex(),client=off_client,
                    actual_original_syn=original,selected_upstream_admitted=False,resolver_success_asserted=False),
                fresh_positive=fresh['label'],ordinary_config_publication=True))
        finally:
            gate.touch();d.release_probe(label,nonce);d.active_probe=None
        d.client(label,nonce)


def udp_regression(d,peer,result,owners):
    label=f'n{owners}-shared-root-udp';d.rules(label+'-allow');d.upstream(label+'-upstream',d.args.endpoint4);d.proxy_ready(label+'-ready')
    query=d.question(label);reply,_=fixtures.answer(query,'ordinary');peer.register(query,reply)
    shared.exchange(d,peer,result,label,d.args.endpoint4,[query],[reply])
    label+= '-tc';query=d.question(label,65280);name,qtype,end=fixtures.decode_question(query)
    reply=query[:2]+struct.pack('!5H',0x8180,1,1,0,0)+query[12:end]+fixtures.rr(name,qtype,bytes([0xa5])*600)
    tc=query[:2]+struct.pack('!5H',0x8380,1,0,0,0)+query[12:end]
    peer.register(query,tc);peer.register(query,reply,protocol='tcp',split=True)
    shared.exchange(d,peer,result,label,d.args.endpoint4,[query],[None],tcp_retry=True,truncated=True,capacities=[512])


def client_retry(d,peer,result,owners):
    d.rules(f'n{owners}-client-retry-allow')
    result['client_udp_tcp_retries']=[]
    for family,resolver,upstream in ((4,'1.1.1.1',d.args.endpoint4),(6,'2606:4700:4700::1111',d.args.endpoint6)):
        label=f'n{owners}-client-tc-v{family}'
        d.upstream(label+'-upstream',upstream);d.proxy_ready(label+'-ready')
        query=d.question(label,65280);name,qtype,end=fixtures.decode_question(query)
        full=query[:2]+struct.pack('!5H',0x8180,1,1,0,0)+query[12:end]+fixtures.rr(name,qtype,bytes([0xa5])*600)
        tc=query[:2]+struct.pack('!5H',0x8380,1,0,0,0)+query[12:end]
        assert len(full)>512
        peer.register(query,tc);peer.register(query,full,protocol='tcp',split=True)
        cursor=peer.cursor()
        udp=shared.exchange(d,peer,result,label+'-udp',resolver,[query],[None],
            tcp_retry=True,truncated=True,capacities=[512])
        actual_tc=bytes.fromhex(udp['replies'][0]);assert int.from_bytes(actual_tc[2:4],'big')&0x0200
        tcp=paired_exchange(d,peer,result,label+'-client-tcp',resolver,[query],[full],rcodes=[0])
        assert tcp['queries']==udp['queries']==[query.hex()]
        assert tcp['source_port']!=udp['source_port']and tcp['replies']==[full.hex()]
        assert len(peer.received(query,after=cursor))==len(peer.received(query,'tcp',after=cursor))==2
        assert all(r['protocol']==17 and r['reply_capacity']==512 for r in udp['records'])
        assert all(r['protocol']==6 and r['reply_capacity']==65535 for r in tcp['records'])
        result['client_udp_tcp_retries'].append(dict(status='PASS',family=family,generation=d.generation,
            original_resolver=resolver,query_hex=query.hex(),udp_case=udp['label'],tcp_case=tcp['label'],
            udp_source_port=udp['source_port'],tcp_source_port=tcp['source_port'],
            app_udp_tc_hex=actual_tc.hex(),app_tcp_full_hex=full.hex(),
            sequence='actual ordinary App UDP TC received before launching ordinary App TCP with same ID and complete Question',
            upstream='each client transaction separately continued the same selected UDP-TC candidate on upstream TCP'))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('apk','stage','backup','output'):parser.add_argument('--'+key,type=Path,required=True)
    parser.add_argument('--endpoint4',required=True);parser.add_argument('--endpoint6',required=True)
    parser.add_argument('--owners',choices=('1','3'),default='1');parser.add_argument('--trace',action='store_true')
    parser.add_argument('--installed',action='store_true');parser.add_argument('--matrix',choices=('smoke','core','pipeline','lifecycle','capacity','stop-late','toggle','udp-regression','client-retry'),default='smoke')
    parser.add_argument('--replace-preserved',type=Path)
    parser.add_argument('--cc',default='/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang')
    args=parser.parse_args();args.profile='root'
    for key in ('apk','stage','backup','output'):setattr(args,key,getattr(args,key).resolve())
    args.output.mkdir(parents=True,exist_ok=False)
    baseline=json.loads((args.backup/'manifest.json').read_text());assert baseline['status']=='PASS'and baseline['all_nodes_archived_exact']
    route=json.loads((args.backup.parent/'routing-baseline-r1-receipt.json').read_text());assert route['status']=='PASS_ORIGINAL_ROUTING_NAMESPACE_SAVED'
    result=dict(status='HOLD',task='SAKAMOTO-317',serial=SERIAL,started_monotonic_ns=time.monotonic_ns(),
        apk_sha256=digest(args.apk),stage_manifest_sha256=digest(args.stage/'product-stage.properties'),backup_manifest_sha256=digest(args.backup/'manifest.json'),cases=[],runs=[])
    d=Device(args);d.capture_deadline=time.monotonic()+900;peer=None;failure=None
    closure=[Path(__file__),ROOT/'tests/device/helpers/s317_dns_peer.ps1',ROOT/'tests/device/helpers/s317_dns_wire.c',ROOT/'tests/device/s315-root-dns-proxy.py',ROOT/'tests/device/s313-root-dns-tcp.py',ROOT/'tests/device/s312-dns-response.py',ROOT/'tests/device/helpers/s315_dns_peer.ps1',ROOT/'dev/adb']
    result['source_sha256']={str(path.relative_to(ROOT)):digest(path)for path in closure}
    for path in closure:(args.output/('source-'+str(path.relative_to(ROOT)).replace('/','__'))).write_bytes(path.read_bytes())
    try:
        peer=Peer([args.endpoint4,args.endpoint6],args.output,d.capture_deadline)
        assert [row['ports']for row in peer.messages if row.get('kind')=='ready']==[[53053]]
        result['native']=d.install();d.wire_start();owners=int(args.owners);d.owners=owners
        run=d.start(owners);result['runs'].append(run)
        dict(smoke=smoke,core=core,pipeline=core,lifecycle=lifecycle,capacity=capacity,toggle=toggle,
            **{'stop-late':stop_late,'udp-regression':udp_regression,'client-retry':client_retry})[args.matrix](d,peer,result,owners)
        finish_run(d,result,'n'+str(owners))
        result['status']='PASS_ACTUAL_APP_ROOT_TCP_'+args.matrix.upper()
    except BaseException as error:
        failure=error;result['error']=repr(error);result['traceback']=traceback.format_exc()
    finally:
        cleanup=[]
        envelope=shared.CleanupEnvelope(90,[('stop',35),('reader',5),('wire',20),('peer',20),('trace',10)])
        def phase(name,action):
            try:
                with envelope.phase(d,name)as deadline:action(deadline)
            except BaseException as error:cleanup.append(repr(error))
        if (d.stop_owed or d.active)and getattr(d,'stop_retry_authorized',True):phase('stop',lambda _:d.stop('failure-cleanup'))
        if d.reader:phase('reader',lambda _:d.settle_reader('final'))
        if d.witnesses:phase('wire',lambda _:d.wire_stop())
        if peer:phase('peer',lambda deadline:(setattr(peer,'cleanup_deadline',deadline),peer.close()))
        phase('trace',lambda _:d.close_trace())
        if cleanup:result.update(cleanup_errors=cleanup,status='HOLD')
        result['completed_monotonic_ns']=time.monotonic_ns();(args.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps({key:result.get(key)for key in('status','error','cleanup_errors','cases')}),flush=True)
    return 0 if result['status'].startswith('PASS_')else 1
if __name__=='__main__':raise SystemExit(main())
