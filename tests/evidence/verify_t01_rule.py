#!/usr/bin/env python3
"""Independent T01 evidence reader. It performs no device operation or policy evaluation."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import xml.etree.ElementTree as ET

def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def props(text): return dict(line.split('=',1) for line in text.splitlines() if '=' in line and not line.startswith('#'))
def rows(text,prefix):
    return [dict(item.split('=',1) for item in line.split()[1:] if '=' in item)
            for line in text.splitlines() if line.startswith(prefix)]

def verify_product_build(path):
    path=Path(path);build=json.loads(path.read_text())
    encoded=json.dumps(build['files'],sort_keys=True,separators=(',',':')).encode()
    assert hashlib.sha256(encoded).hexdigest()==build['source_sha256'],'source manifest hash'
    for name,expected in build['files'].items():
        if expected is not None:assert digest(path.parent/'source'/name)==expected,'source snapshot '+name
    spec=importlib.util.spec_from_file_location('t01_source_chain',Path(__file__).with_name('product_chain.py'))
    chain=importlib.util.module_from_spec(spec);spec.loader.exec_module(chain)
    # A pre-commit dirty build records a deleted tracked file as null; after
    # commit git no longer lists it. Compare source bytes/paths, preserving
    # absence without making the bookkeeping tombstone a phantom source file.
    expected={name:value for name,value in build['files'].items() if value is not None}
    current={name:value for name,value in chain.source_files().items() if value is not None}
    assert current==expected,'current Product source differs from accepted build'
    return build

def verify(directory):
    directory=Path(directory)
    errors=[]
    def need(condition,message):
        if not condition:errors.append(message)
    try:
        result=json.loads((directory/'result.json').read_text())
        pixel=result.get('serial') is not None
        need(result.get('status')=='RAW_COMPLETE','collector incomplete')
        need(result.get('source')=='NFQ_CAPTURED' and result.get('profile')=='root','wrong claim scope')
        build_path=Path(result['build']);build=verify_product_build(build_path)
        need(digest(build_path)==result['build_sha256'],'build witness changed')
        need(build['source_sha256']==result['source_sha256'],'source identity mismatch')
        need(build['completed_ns']<result['started_ns']<result['completed_ns'],'build/run order')
        need(digest(directory/'runner.py')==result['runner_sha256'],'collector source missing/changed')
        if pixel:
            need(digest(build['apk'])==build['apk_sha256'],'APK mismatch')
            need((directory/'installed-apk.txt').read_text().split()[0]==build['apk_sha256'],'installed APK mismatch')
            installed={Path(line.split()[1]).name:line.split()[0]
                       for line in (directory/'installed-native.txt').read_text().splitlines()}
            need(installed==build['native_sha256'],'installed native mismatch')
            need(digest(directory/'echo')==result['endpoint_build']['binary_sha256'],'endpoint binary mismatch')
            need(digest(directory/'echo.c')==result['endpoint_build']['source_sha256'],'endpoint source mismatch')
            running=props((directory/'running.properties').read_text())
            need(running.get('generation')==str(result['generation']) and running.get('profile')=='root'
                 and running.get('protectionRunning')=='true','runtime identity/readiness')
            stopped=props((directory/'stopped.properties').read_text())
            need(stopped.get('state')=='stopped' and stopped.get('mayBeActive')=='false','runtime cleanup')
            need(not (directory/'queues-after.txt').read_text().strip(),'NFQUEUE residue')
            need('SAKAMOTO' not in (directory/'hooks-after.txt').read_text(),'Product hook residue')
            uid=result['uid']
            trace=(directory/'stop-vpp.log').read_text()
            need((directory/'source-owner.txt').read_text().strip().split(':')[0]==str(uid),'Root left an inaccessible source owner')
        else:
            artifact=Path(result['artifact'])
            for name,expected in build['artifact_hashes'].items():
                need(digest(artifact/name)==expected,'artifact changed '+name)
            need(digest(artifact/'product-vpp-artifact.properties')==result['manifest_sha256'],'artifact manifest mismatch')
            need(all(value==0 for value in json.loads((directory/'queues-free.json').read_text()).values()),'NFQUEUE release failed')
            need('root.stop=ok' in (directory/'stop.txt').read_text(),'Root stop missing')
            need('NFQUEUE' not in (directory/'hooks-after.txt').read_text(),'test hook residue')
            need(props((directory/'process-stopped.txt').read_text()).get('absent')=='True','process residue')
            uid=result['policy_uid']
            trace=(directory/'vpp.log').read_text()
        need(result.get('process_absent') is True,'process was not retired')
        zero=rows(trace,'s242 event=stop_native_zero ')
        need(any(z.get('generation')==str(result['generation']) and
                 all(z.get(k)=='0' for k in ('pending','buffers','obligations','handoffs','completion_frames')) for z in zero),
             'native settlement debt not zero')
        need([c['phase'] for c in result['cases']]==['allow','drop','recover'],'missing ordered packet phases')
        prior=None
        for case in result['cases']:
            phase=case['phase'];nonce=case['nonce'];version=case['rule_version'];revision=case['revision']
            action=2 if phase=='drop' else 1
            need(case['delivered']==(action==1),'incorrect phase expectation '+phase)
            need(int(nonce.rsplit('-',1)[1])>result['started_ns'],'stale nonce '+phase)
            need(version>>16!=0 and version&65535!=0,'invalid rule version '+phase)
            if prior is not None:need(version==prior+1,'rule revision did not advance '+phase)
            prior=version
            source=(directory/(phase+'-source.conf')).read_text().splitlines()
            need(source[0]=='sakamoto-rule-config/1','wrong source schema '+phase)
            need(list(map(int,source[1].split()))==[revision,version],'source identity '+phase)
            need(list(map(int,source[2].split()))==[1,uid,17,3,action,32000,40608],'source rule '+phase)
            need(source[3]=='7f000001 7f000002','source addresses '+phase)
            if pixel:
                query=props((directory/(phase+'-query.properties')).read_text())
                need(query.get('savedRevision')==query.get('activeRevision')==str(revision),'query revisions '+phase)
                need(query.get('savedRuleVersion')==query.get('activeRuleVersion')==query.get('winnerVersion')==str(version),'query versions '+phase)
                need(query.get('winnerAction')==str(action),'query action '+phase)
                probe=props((directory/(phase+'-probe.properties')).read_text())
                need(probe.get('nonce')==nonce and probe.get('uid')==str(uid),'application probe identity '+phase)
                need((probe.get('result')=='udp_echo_matched')==(action==1),'application outcome '+phase)
                endpoint=(directory/(phase+'-endpoint.txt')).read_text()
                need((nonce in endpoint)==(action==1),'independent endpoint outcome '+phase)
                tree=ET.parse(directory/(phase+'-before.xml'))
                button='Drop UDP' if action==2 else 'Allow UDP'
                need(any(n.get('text')==button and n.get('enabled')=='true' for n in tree.iter('node')),'UI submit control '+phase)
                ET.parse(directory/(phase+'-query-before.xml'))
                for suffix in ('-before.png','-query-before.png','-result.png'):
                    need((directory/(phase+suffix)).read_bytes().startswith(b'\x89PNG\r\n\x1a\n'),'screenshot '+phase+suffix)
            else:
                query=props((directory/(phase+'-query.txt')).read_text())
                need(query.get('config.saved_revision')==query.get('config.active_revision')==str(revision),'query revisions '+phase)
                need(query.get('config.saved_rule_version')==query.get('config.active_rule_version')==query.get('query.winner_version')==str(version),'query versions '+phase)
                need(query.get('query.winner_action')==str(action),'query action '+phase)
                endpoint=json.loads((directory/'endpoint.json').read_text())
                need((nonce in endpoint)==(action==1),'independent endpoint outcome '+phase)
            candidates=[]
            for packet in rows(trace,'s216 stage=admit '):
                if packet.get('direction')!='3' or packet.get('generation')!=str(result['generation']):continue
                raw=bytes.fromhex(packet.get('raw',''))
                if len(raw)<28 or raw[0]>>4!=4 or raw[9]!=17:continue
                offset=(raw[0]&15)*4
                if raw[offset+8:]!=nonce.encode():continue
                need(raw[12:20]==bytes([127,0,0,1,127,0,0,2]),'wire IP endpoints '+phase)
                need(struct.unpack('!HH',raw[offset:offset+4])==(32000,40608),'wire UDP ports '+phase)
                need(struct.unpack('!H',raw[2:4])[0]==len(raw),'wire IP length '+phase)
                need(packet.get('uid')==str(uid),'captured application UID '+phase)
                candidates.append(packet)
            need(len(candidates)==1,'unique actual outgoing packet '+phase)
            if not candidates:continue
            packet=candidates[0];token=packet['token'];generation=packet['generation']
            decisions=[r for r in rows(trace,'s209 event=l4 ') if r.get('token')==token and r.get('generation')==generation]
            need(len(decisions)==1 and decisions[0].get('rule')==str(version)
                 and decisions[0].get('revision')==str(revision) and decisions[0].get('action')==str(action),
                 'packet-bound winner/version '+phase)
            verdicts=[r for r in rows(trace,'s242 event=verdict_syscall ') if r.get('token')==token and r.get('generation')==generation]
            need(len(verdicts)==1 and verdicts[0].get('verdict')==str(action==1 and 1 or 0)
                 and int(verdicts[0].get('result','-1'))>=0 and verdicts[0].get('packet')==packet['packet_id'],
                 'exactly-once native verdict '+phase)
            freed=[r for r in rows(trace,'s203 event=buffer_free ') if r.get('obligation')==token]
            need(len(freed)==1,'exactly-once buffer settlement '+phase)
    except (OSError,ValueError,KeyError,IndexError,AssertionError,ET.ParseError) as error:
        errors.append('incomplete evidence: '+str(error))
    return dict(status='HOLD' if errors else 'PASS',errors=errors,directory=str(directory),
                verifier_sha256=digest(__file__))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--output',type=Path)
    a=p.parse_args();result=verify(a.directory)
    if a.output:a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    raise SystemExit(result['status']!='PASS')
