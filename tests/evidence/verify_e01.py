#!/usr/bin/env python3
"""Independent E01 source, packet, cumulative/window, bounds and metric verifier.

No performance threshold is invented here. Evidence validity is distinct from a
performance or release decision. Rehashed semantic mutations exercise this oracle.
"""
import argparse,copy,hashlib,importlib.util,json,re,subprocess,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def basic(value,field='basic_packets'):return sum(c[field][0] for c in value['health']['channels'])
def capture(path):
    args=['tshark','-r',str(path),'-Y','ip','-T','fields','-E','occurrence=f']
    fields=['frame.time_epoch','frame.interface_name','ip.src','ip.dst','ip.id','ip.len','udp.srcport','udp.dstport','udp.payload','ip.proto','icmp.type','icmp.code']
    for f in fields:args.extend(['-e',f])
    rows=[]
    for line in subprocess.check_output(args,text=True,stderr=subprocess.DEVNULL).splitlines():
        values=line.split('\t')
        if len(values)==len(fields) and values[5]:rows.append(dict(zip(fields,values)))
    return rows

def verify(directory,overrides=None,pcaps=None):
    directory=Path(directory);overrides=overrides or {}
    def read(name):return overrides[name] if name in overrides else (directory/name).read_text()
    def data(name):return json.loads(read(name))
    try:
        result=data('result.json');assert result['status']=='RAW_COMPLETE','collector incomplete'
        assert result['started_ns']<result['completed_ns']
        for name,wanted in result['files'].items():
            actual=hashlib.sha256(overrides[name].encode()).hexdigest() if name in overrides else digest(directory/name)
            assert actual==wanted,'file seal: '+name
        bp=Path(result['build']);b=json.loads(bp.read_text());assert digest(bp)==result['build_sha256'],'build seal'
        assert b['completed_ns']<result['started_ns'],'build before run'
        assert b['source_sha256']==result['source_sha256']==hashlib.sha256(json.dumps(b['files'],sort_keys=True,separators=(',',':')).encode()).hexdigest(),'source closure'
        for name,wanted in b['files'].items():
            if wanted:assert digest(bp.parent/'source'/name)==wanted,'retained source '+name
        assert digest(bp.parent/'dirty.diff')==b['dirty_diff_sha256']
        spec=importlib.util.spec_from_file_location('overlay',ROOT/'tests/evidence/e01_overlay.py');overlay=importlib.util.module_from_spec(spec);spec.loader.exec_module(overlay)
        expected_overlay=overlay.overlay()
        for name,wanted in b['files'].items():
            current=hashlib.sha256(expected_overlay[name]).hexdigest() if name in expected_overlay else (digest(ROOT/name) if (ROOT/name).is_file() else None)
            assert wanted==current,'only documented experiment overlay differs: '+name
        android=result['kind']=='android'
        if android:
            assert result['history_preserved'] and result['original_history_sha256']==result['final_history_sha256'],'accepted history preserved'
            assert hashlib.sha256(read('original-history.json').encode()).hexdigest()==result['original_history_sha256']
            assert read('original-history.json')==read('final-history.json')
            assert digest(b['apk'])==result['apk_sha256']==b['apk_sha256']
            assert read('installed-apk.txt').split()[0]==b['apk_sha256']
            installed={Path(l.split()[1]).name:l.split()[0] for l in read('installed-native.txt').splitlines()}
            assert installed==b['native_sha256']==result['native_sha256']
            with zipfile.ZipFile(b['apk']) as z:
                assert {Path(n).name:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}==installed
            assert 'bluejay' in read('environment.txt')
            for name in ('device-capture.log','host-capture.log'):assert '0 packets dropped by kernel' in read(name),'capture loss '+name
        else:
            for name,wanted in b['artifact_hashes'].items():assert digest(Path(b['artifact'])/name)==wanted,'Host artifact '+name
            assert '0 packets dropped by kernel' in read('capture.log'),'capture loss'
        if pcaps is None:pcaps={name:capture(directory/name) for name in (('host.pcap','device.pcap') if android else ('wire.pcap',))}
        endpoint=[json.loads(l) for l in read('endpoint.jsonl').splitlines() if 'payload' in l]
        endpoints={}
        for row in endpoint:endpoints.setdefault(row['payload'],[]).append(row)
        payload_owner={};summaries=[]
        for index,arm in enumerate(result['arms']):
            assert arm['status']=='RAW_COMPLETE' and arm['process_absent'],'runtime cleanup'
            cfg=arm['config'];prefix=f"{index:02d}-{cfg['arm']}/";generation=arm['generation']
            assert cfg['store']==(cfg['arm'] not in ('A','B')) and cfg['export']==(cfg['arm']!='A'),'arm layer semantics'
            assert cfg['drain']==(16 if cfg['arm']=='D' else 128) and cfg['growth']==(128 if cfg['arm']=='G' else 32) and cfg['flush']==(250000 if cfg['arm']=='F' else 1000000),'single-factor parameters'
            assert f"e01.export={int(cfg['export'])} growth={cfg['growth']} flush_us={cfg['flush']}" in read(prefix+'configure.txt'),'applied producer config'
            seed_count=arm.get('synthetic_seed_baselines',0)
            if seed_count:
                seed=data(prefix+'synthetic-seed.json')
                assert len(seed['baselines'])==seed_count and seed['totals']['packets']==[0,0] and seed['totals']['bytes']==[0,0],'explicit synthetic zero baseline'
                assert len(seed['minutes'])==0 and not seed['open_session']
            packets=[]
            for phase in arm['phases']:
                name=phase['name'];traffic=data(prefix+('e01_'+name+'.json' if android else name+'-traffic.json'))
                if android:traffic=traffic['e01']
                assert len(traffic['exchanges'])==traffic['sent']==phase['sent'],'workload count'
                assert sum(r['echoed'] for r in traffic['exchanges'])==traffic['received']==phase['received'],'echo result count'
                for row in traffic['exchanges']:
                    assert row['sentMonoNs']<=row['endMonoNs'] and len(bytes.fromhex(row['payload']))==64,'packet timing/size'
                    assert row['payload'] not in payload_owner,'unique workload identity'
                    payload_owner[row['payload']]=index;packets.append(row)
                before=data(prefix+name+'-before.json');after=data(prefix+name+'-settled.json')
                for value in (before,after):
                    h=value['health'];consumer=value['consumer'];assert h['generation']==generation and h['version']==2 and h['mapping_bytes']==332544 and h['owners']==2 and h['flow_capacity']==1024,'wire/runtime identity'
                    assert consumer['live'] and consumer['error'] is None and consumer['malformed']==0,'consumer validity'
                    for i,c in enumerate(h['channels']):
                        assert c['capacity']==512 and c['occupancy']<=512 and c['oversize']==c['notify_errors']==0,'queue bounds'
                        if i%2:assert c['attempted']==0,'debug isolation'
                    persistent=consumer['persistent']
                    if not cfg['store']:assert persistent is None and consumer['e01']['batches']==0,'no-store arm'
                    elif persistent:
                        for field in ('packets','bytes'):
                            assert persistent[field]==[sum(m[field][d] for m in persistent['minutes'].values()) for d in (0,1)],'minute conservation'
                        assert all(int(minute)%60==0 for minute in persistent['minutes']),'UTC minute alignment'
                        assert persistent['storage']=='atomic_json_snapshot'
                    if not cfg['export']:
                        assert all(c['attempted']==0 for c in h['channels']) and consumer['overview']['packets']==[0,0],'no-export arm'
                assert basic(after)>=basic(before),'basic monotonicity'
                if (cfg['export'] and name not in ('pause','recovery')
                    and not arm.get('synthetic_seed_baselines',0)
                    and not any(c['full'] for c in after['health']['channels'])
                    and after['consumer']['store_error'] is None):
                    seen={r['payload'] for r in packets}
                    wire=pcaps['device.pcap' if android else 'wire.pcap']
                    expected_flow=[r for r in wire if r['udp.payload'] in seen and r['ip.proto']=='17']
                    if android and result['profile']=='vpn':expected_flow=[r for r in expected_flow if '10.111.0.2' in (r['ip.src'],r['ip.dst'])]
                    assert sum(after['consumer']['overview']['packets'])==len(expected_flow),'settled pre-fault cumulative packet oracle: '+name
                    if cfg['store']:
                        assert sum(after['consumer']['persistent']['packets'])==len(expected_flow),'settled pre-fault durable packet oracle: '+name
                if name=='pause':
                    immediate=data(prefix+name+'-immediate.json')
                    assert immediate['consumer']['overview']['accepted']==before['consumer']['overview']['accepted'],'parked consumer must not ingest'
                    assert basic(immediate)>basic(before),'packets continue while parked'
                resources=data(prefix+name+'-resources.json')
                assert set(resources)=={'before','after'}
                for actor in ('vpp','rust'):
                    x,y=resources['before'][actor],resources['after'][actor]
                    assert x['pid']==y['pid']==arm['vpp_pid' if actor=='vpp' else ('app_pid' if android else 'rust_pid')],'measured process identity'
                    if android:assert y['stats'][0]['cpu_ticks']>=x['stats'][0]['cpu_ticks'],'CPU monotonicity'
                    else:assert y['cpu_ticks']>=x['cpu_ticks'],'CPU monotonicity'
            if not android and prefix+'freshness-traffic.json' in result['files']:
                traffic=data(prefix+'freshness-traffic.json')
                for row in traffic['exchanges']:
                    assert row['payload'] not in payload_owner;payload_owner[row['payload']]=index;packets.append(row)
            if arm.get('storage_fault'):
                before_fault=data(prefix+'burst-before.json')['consumer']['persistent']
                failed=data(prefix+'burst-settled.json')['consumer']
                assert failed['store_error'] and failed['persistent']['save_error'] and failed['persistent']['coverage']['incomplete'],'real write failure exposed'
                assert failed['persistent']['packets']==before_fault['packets'] and failed['persistent']['bytes']==before_fault['bytes'],'failed writes preserve committed baseline'
            final=data(prefix+'final.json');h=final['health'];consumer=final['consumer'];observed=sum(consumer['overview']['packets'])
            for c in h['channels']:
                assert c['attempted']==c['published']+c['full'],'producer conservation'
                assert c['published']==c['consumed']+c['occupancy'],'transport conservation'
            expected=set(r['payload'] for r in packets)
            for row in packets:
                if row['echoed']:assert row['payload'] in endpoints,'echo without endpoint witness'
            relevant={name:[r for r in values if r['udp.payload'] in expected] for name,values in pcaps.items()}
            for rows in relevant.values():assert all(int(r['ip.len'])==92 for r in rows if r['ip.proto']=='17'),'real IP length'
            actual=relevant['device.pcap' if android else 'wire.pcap']
            if android:
                actual=[r for r in pcaps['device.pcap'] if arm['capture_start_device_ns']<=int(float(r['frame.time_epoch'])*1e9)<=arm['capture_end_device_ns']]
            # Root capture has one physical boundary. Controlled VPN has TUN and
            # physical socket packets; VPP counts the TUN-side copies only.
            if android and result['profile']=='vpn':
                actual=[r for r in actual if '10.111.0.2' in (r['ip.src'],r['ip.dst'])]
                assert actual,'VPN TUN capture boundary'
            assert basic(final)==len(actual),'basic counters versus actual packet capture'
            assert basic(final,'basic_bytes')==sum(int(r['ip.len']) for r in actual),'basic IP bytes'
            flow_packets=sum(r['ip.proto']=='17' for r in actual)
            assert observed<=flow_packets,'no cumulative overcount'
            losses=sum(c['full'] for c in h['channels'])
            if losses or observed<flow_packets:
                if cfg['export']:assert consumer['overview']['incomplete'],'gap visibility'
            persistent=consumer['persistent']
            if persistent:
                assert sum(persistent['packets'])<=flow_packets,'no durable overcount'
                if losses or sum(persistent['packets'])<flow_packets:assert persistent['coverage']['incomplete'],'durable gap visibility'
                stored=data(prefix+'final-store.json')
                assert stored['totals']['packets']==persistent['packets'] and stored['totals']['bytes']==persistent['bytes'],'API/store contribution identity'
                assert not stored['open_session'],'closed durable session'
                if seed_count:
                    assert all(stored['baselines'].get(k)==v for k,v in seed['baselines'].items()),'pressure preserves prior baselines'
                assert stored['gaps']>=persistent['coverage']['gaps'],'shutdown cannot erase coverage boundary'
            runtime=read(prefix+'runtime.txt')
            admits=sum(int(m[1]) for m in re.finditer(r'^product-packet-admit\s+active\s+\d+\s+(\d+)',runtime,re.M))
            assert admits==basic(final),'real VPP graph admission counters'
            placement=None
            if cfg['store'] and 'short' in [p['name'] for p in arm['phases']]:
                pre=data(prefix+'short-settled.json')['consumer']['persistent']
                pre_payloads=set()
                for phase in arm['phases']:
                    if phase['name'] in ('pause','recovery'):break
                    tr=data(prefix+('e01_'+phase['name']+'.json' if android else phase['name']+'-traffic.json'))
                    if android:tr=tr['e01']
                    pre_payloads.update(r['payload'] for r in tr['exchanges'])
                exact={}
                for packet in actual:
                    if packet['ip.proto']=='17' and packet['udp.payload'] in pre_payloads:
                        minute=str(int(float(packet['frame.time_epoch']))//60*60)
                        exact[minute]=exact.get(minute,0)+1
                if pre:
                    maintained={k:sum(v['packets']) for k,v in pre['minutes'].items()}
                    placement={'capture_exact_minute_packets':exact,'maintained_minute_packets':maintained,
                        'minute_count_l1_difference':sum(abs(exact.get(k,0)-maintained.get(k,0)) for k in exact.keys()|maintained.keys()),
                        'meaning':'descriptive bucket comparison; coalesced last-activity placement is approximate'}
            summaries.append({'arm':cfg['arm'],'generation':generation,'packets':basic(final),'flow_packets':flow_packets,'non_flow_ip_packets':basic(final)-flow_packets,'observed':observed,'persistent':sum(persistent['packets']) if persistent else None,'full':losses,'sent':len(packets),'echoed':sum(r['echoed'] for r in packets),'store_error':consumer['store_error'],'pre_fault_time_placement':placement})
        assert set(endpoints)<=set(payload_owner),'endpoint witness from another workload'
        return {'status':'VALID_EVIDENCE','performance_decision':'USER_REVIEW_REQUIRED','arms':summaries,'errors':[]}
    except (AssertionError,KeyError,ValueError,OSError,TypeError) as e:
        return {'status':'INVALID_EVIDENCE','errors':[str(e)]}

def mutations(directory):
    directory=Path(directory);r=json.loads((directory/'result.json').read_text());android=r['kind']=='android'
    pcaps={name:capture(directory/name) for name in (('host.pcap','device.pcap') if android else ('wire.pcap',))}
    arm=next((i,a) for i,a in enumerate(r['arms']) if a['config']['arm']=='C');index,a=arm;prefix=f'{index:02d}-C/'
    cases=[]
    def check(label,name,edit):
        value=json.loads((directory/name).read_text());edit(value);raw=json.dumps(value);rr=copy.deepcopy(r);rr['files'][name]=hashlib.sha256(raw.encode()).hexdigest()
        response=verify(directory,{name:raw,'result.json':json.dumps(rr)},pcaps)
        assert response['status']=='INVALID_EVIDENCE','mutation escaped: '+label
        cases.append({'mutation':label,'rejected':True,'reason':response['errors']})
    check('hidden basic packet',prefix+'final.json',lambda v:v['health']['channels'][0]['basic_packets'].__setitem__(0,v['health']['channels'][0]['basic_packets'][0]+1))
    check('hidden queue overflow',prefix+'final.json',lambda v:v['health']['channels'][0].__setitem__('full',v['health']['channels'][0]['full']+1))
    check('wrong wire generation',prefix+'low-settled.json',lambda v:v['health'].__setitem__('generation',0))
    check('store/API mismatch',prefix+'final-store.json',lambda v:v['totals']['packets'].__setitem__(0,v['totals']['packets'][0]+1))
    check('wrong measured process',prefix+'low-resources.json',lambda v:v['after']['vpp'].__setitem__('pid',1))
    check('missing minute contribution',prefix+'low-settled.json',lambda v:v['consumer']['persistent']['packets'].__setitem__(0,v['consumer']['persistent']['packets'][0]+1))
    return cases
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--mutations',action='store_true');p.add_argument('--output',type=Path);a=p.parse_args()
    result=verify(a.directory);result['verifier_sha256']=digest(__file__)
    if a.mutations and result['status']=='VALID_EVIDENCE':result['mutations']=mutations(a.directory)
    if a.output:a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2));raise SystemExit(result['status']!='VALID_EVIDENCE')
