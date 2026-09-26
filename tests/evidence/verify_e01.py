#!/usr/bin/env python3
"""Independent E01 source, packet, cumulative/window, bounds and metric verifier.

No performance threshold is invented here. Evidence validity is distinct from a
performance or release decision. Rehashed semantic mutations exercise this oracle.
"""
import argparse,copy,hashlib,importlib.util,ipaddress,json,re,subprocess,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def basic(value,field='basic_packets'):return sum(c[field][0] for c in value['health']['channels'])
def capture(path):
    args=['tshark','-r',str(path),'-Y','ip or ipv6','-T','fields','-E','occurrence=f']
    fields=['frame.time_epoch','frame.interface_name','ip.src','ip.dst','ip.id','ip.len','udp.srcport','udp.dstport','udp.payload','ip.proto','icmp.type','icmp.code','ipv6.src','ipv6.dst','ipv6.plen','ipv6.nxt']
    for f in fields:args.extend(['-e',f])
    rows=[]
    for line in subprocess.check_output(args,text=True,stderr=subprocess.DEVNULL).splitlines():
        values=line.split('\t')
        if len(values)==len(fields) and (values[5] or values[14]):
            row=dict(zip(fields,values))
            if not row['ip.len']:
                row['ip.len']=str(int(row['ipv6.plen'])+40);row['ip.src']=row['ipv6.src'];row['ip.dst']=row['ipv6.dst'];row['ip.proto']=row['ipv6.nxt'];row['family']=6
            else:row['family']=4
            rows.append(row)
    return rows

def capture_names(result):
    names=['host.pcap','device.pcap'] if result['kind']=='android' else ['wire.pcap']
    return names+sorted(name for name in result['files'] if name.endswith('/tun.pcap'))

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
        java_path='app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProtocolFactsProbe.java'
        java=(bp.parent/'source'/java_path).read_text()
        probe_start=java.index('    // E01 experimental workload overlay only; not a Product capability.')
        probe_end=java.index('\n    private static void observation(Context app',probe_start)
        probe=java[probe_start:probe_end]
        probe_digest=hashlib.sha256(probe.encode()).hexdigest()
        assert probe_digest in {'9a9292dd7241e8b311d35506759d90c0024ce755303475ce60e6a2598185a778',digest(ROOT/'tests/device/helpers/e01_probe.java')},'documented workload fixture revision'
        expected_overlay=overlay.overlay(probe_source=probe,startup_config='e01_startup_config' in (bp.parent/'source/src/product/vpp/product_observation.c').read_text())
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
        if pcaps is None:pcaps={name:capture(directory/name) for name in capture_names(result)}
        endpoint=[json.loads(l) for l in read('endpoint.jsonl').splitlines() if 'payload' in l]
        endpoints={}
        for row in endpoint:endpoints.setdefault(row['payload'],[]).append(row)
        payload_owner={};summaries=[];address_oracles={}
        for index,arm in enumerate(result['arms']):
            assert arm['status']=='RAW_COMPLETE' and arm['process_absent'],'runtime cleanup'
            cfg=arm['config'];prefix=f"{index:02d}-{cfg['arm']}/";generation=arm['generation']
            if android:
                props=lambda name:dict(line.split('=',1) for line in read(prefix+name).splitlines() if '=' in line and not line.startswith('#'))
                running=props('running.properties');stopped=props('stopped.properties')
                assert running['profile']==result['profile'] and int(running['generation'])==generation,'profile/generation state witness'
                assert running['protectionRunning']==('true' if result['profile']=='root' else 'false'),'no controlled VPN release claim'
                assert stopped['state']=='stopped' and stopped['mayBeActive']=='false','stopped ownership witness'
            assert cfg['store']==(cfg['arm'] not in ('A','B')) and cfg['export']==(cfg['arm']!='A'),'arm layer semantics'
            assert cfg['drain']==(16 if cfg['arm']=='D' else 128) and cfg['growth']==(128 if cfg['arm']=='G' else 32) and cfg['flush']==(250000 if cfg['arm']=='F' else 1000000),'single-factor parameters'
            assert f"e01.export={int(cfg['export'])} growth={cfg['growth']} flush_us={cfg['flush']}" in read(prefix+'configure.txt'),'applied producer config'
            seed_count=arm.get('synthetic_seed_baselines',0)
            if seed_count:
                seed=data(prefix+'synthetic-seed.json')
                assert len(seed['baselines'])==seed_count and seed['totals']['packets']==[0,0] and seed['totals']['bytes']==[0,0],'explicit synthetic zero baseline'
                assert len(seed['minutes'])==0 and not seed['open_session']
            wire_name=prefix+'tun.pcap' if prefix+'tun.pcap' in pcaps else ('device.pcap' if android else 'wire.pcap')
            if wire_name not in address_oracles:
                addresses_by_port={}
                for packet in pcaps[wire_name]:
                    if packet['family']==4 and packet['ip.proto']=='17' and packet['udp.dstport']=='42141':
                        addresses_by_port.setdefault(packet['udp.srcport'],set()).add(ipaddress.ip_address(packet['ip.src']).packed+ipaddress.ip_address(packet['ip.dst']).packed)
                address_oracles[wire_name]=addresses_by_port
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
                    overview=consumer['overview']
                    assert len(overview['packets'])==len(overview['bytes'])==2 and all(p>=0 for p in overview['packets'])
                    assert overview['bytes']==[p*92 for p in overview['packets']],'independent fixed-payload cumulative bytes'
                    for record in overview['records']:
                        if record:
                            assert record['generation']==generation and record['family']==4 and record['protocol']==17
                            assert record['ports'][1]==42141 and 43000<=record['ports'][0]<45000,'Flow origin/direction identity'
                            assert record['bytes']==[p*92 for p in record['packets']],'per-Flow cumulative byte oracle'
                            assert all(p>=0 for p in record['packets'])
                            assert len(record['addresses'])==8,'captured Flow tuple'
                            assert bytes(record['addresses']) in address_oracles[wire_name].get(str(record['ports'][0]),set()),'actual Flow address identity'
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
                        assert persistent['bytes']==[p*92 for p in persistent['packets']],'independent durable byte oracle'
                    if not cfg['export']:
                        assert all(c['attempted']==0 for c in h['channels']) and consumer['overview']['packets']==[0,0],'no-export arm'
                assert basic(after)>=basic(before),'basic monotonicity'
                if (cfg['export'] and name not in ('pause','recovery')
                    and not arm.get('synthetic_seed_baselines',0)
                    and not any(c['full'] for c in after['health']['channels'])
                    and after['consumer']['store_error'] is None):
                    seen={r['payload'] for r in packets}
                    wire=pcaps.get(prefix+'tun.pcap',pcaps['device.pcap' if android else 'wire.pcap'])
                    expected_flow=[r for r in wire if r['udp.payload'] in seen and r['ip.proto']=='17']
                    if android and result['profile']=='vpn':expected_flow=[r for r in expected_flow if '10.111.0.2' in (r['ip.src'],r['ip.dst'])]
                    expected_directions=[sum(r['udp.dstport']=='42141' for r in expected_flow),sum(r['udp.srcport']=='42141' for r in expected_flow)]
                    assert after['consumer']['overview']['packets']==expected_directions,'settled pre-fault directional packet oracle: '+name
                    assert after['consumer']['overview']['bytes']==[n*92 for n in expected_directions],'settled pre-fault directional byte oracle: '+name
                    if cfg['store']:
                        assert after['consumer']['persistent']['packets']==expected_directions,'settled pre-fault directional durable oracle: '+name
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
            freshness_interval=None
            if not android and prefix+'freshness-traffic.json' in result['files']:
                traffic=data(prefix+'freshness-traffic.json')
                for row in traffic['exchanges']:
                    assert row['payload'] not in payload_owner;payload_owner[row['payload']]=index;packets.append(row)
                freshness=data(prefix+'freshness-polls.json');polls=freshness['polls']
                if cfg['export']:
                    assert polls and all(p['query_completed_mono_ns']>=traffic['exchanges'][0]['sentMonoNs'] for p in polls),'freshness clock order'
                    baseline_fresh=data(prefix+'freshness-before.json')
                    assert freshness['target']==sum(baseline_fresh['consumer']['overview']['packets'])+2,'freshness independent target'
                    successful=lambda p:p['overview_packets']>=freshness['target'] and (not cfg['store'] or (p['persistent_packets'] is not None and p['persistent_packets']>=freshness['target']))
                    store_available=not cfg['store'] or (baseline_fresh['consumer']['persistent'] and not baseline_fresh['consumer']['persistent']['save_error'])
                    if store_available:assert successful(polls[-1]),'freshness target not reached'
                    freshness_interval={'target_reached':bool(successful(polls[-1])),'upper_ms':(polls[-1]['query_completed_mono_ns']-traffic['exchanges'][0]['sentMonoNs'])/1e6}
            if android and arm.get('freshness'):
                f=arm['freshness'];assert f['target_packets']==40 and f['target_reached'] and f['polls'] and f['polls'][-1]['visible'] and not any(p['visible'] for p in f['polls'][:-1]),'Android freshness target'
                assert digest(directory/'clock-arm64')==result['clock_binary_sha256']==read('installed-clock.txt').split()[0],'device clock helper identity'
                low=data(prefix+'e01_low.json')['e01'];assert f['last_send_mono_ns']==low['exchanges'][-1]['sentMonoNs']
                lower=0;upper=None
                for poll in f['polls']:
                    value=data(prefix+poll['label']+'.json');bounds=data(prefix+poll['label']+'-clock.json')
                    assert f['last_send_mono_ns']<=bounds['before']['monotonic_ns']<=bounds['after']['monotonic_ns'],'Android monotonic API bounds'
                    poll_consumer=value['consumer'];poll_persistent=poll_consumer['persistent'];poll_overview=poll_consumer['overview']
                    assert value['health']['generation']==generation and value['health']['version']==2 and value['health']['connected']==1,'freshness live wire identity'
                    assert poll_consumer['live'] and poll_consumer['error'] is None and poll_consumer['malformed']==0 and poll_consumer['store_error'] is None,'freshness consumer validity'
                    assert poll_overview['generation']==generation and poll_persistent['save_error'] is None,'freshness store validity'
                    for state in (poll_overview,poll_persistent):
                        assert len(state['packets'])==2 and all(0<=n<=20 for n in state['packets']),'freshness directional bounds'
                        assert state['bytes']==[n*92 for n in state['packets']],'freshness byte oracle'
                    assert poll_persistent['packets']==[sum(m['packets'][d] for m in poll_persistent['minutes'].values()) for d in (0,1)],'freshness minute conservation'
                    visible=poll_persistent['packets']==[20,20] and poll_overview['packets']==[20,20]
                    assert poll['visible']==visible,'actual API target visibility'
                    if visible:
                        upper=(bounds['after']['monotonic_ns']-f['last_send_mono_ns'])/1e6;break
                    lower=(bounds['before']['monotonic_ns']-f['last_send_mono_ns'])/1e6
                assert upper is not None and lower<=upper,'bounded target reached'
                freshness_interval={'target_reached':True,'lower_ms':lower,'upper_ms':upper,'meaning':'packet-send to normal API visibility bound; RPC and sampling overhead retained'}
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
                actual=[r for r in pcaps.get(prefix+'tun.pcap',pcaps['device.pcap']) if arm['capture_start_device_ns']<=int(float(r['frame.time_epoch'])*1e9)<=arm['capture_end_device_ns']]
            # Root capture has one physical boundary. Controlled VPN has TUN and
            # physical socket packets; VPP counts the TUN-side copies only.
            if android and result['profile']=='vpn':
                if prefix+'tun.pcap' in pcaps:
                    assert '0 packets dropped by kernel' in read(prefix+'tun-capture.log'),'TUN capture loss'
                    assert data(prefix+'tun-interface.json')['ifname'],'actual TUN interface'
                else:actual=[r for r in actual if '10.111.0.2' in (r['ip.src'],r['ip.dst'])]
                assert actual,'VPN TUN capture boundary'
            base_basic=arm.get('baseline_basic_packets',0);base_bytes=arm.get('baseline_basic_bytes',0)
            assert basic(final)-base_basic==len(actual),'basic counter delta versus actual packet capture'
            assert basic(final,'basic_bytes')-base_bytes==sum(int(r['ip.len']) for r in actual),'basic IP byte delta'
            flow_packets=sum(r['ip.proto']=='17' for r in actual)
            assert observed<=flow_packets,'no cumulative overcount'
            expected_direction_totals=[sum(r['ip.proto']=='17' and r['udp.dstport']=='42141' for r in actual),sum(r['ip.proto']=='17' and r['udp.srcport']=='42141' for r in actual)]
            assert all(0<=p<=limit for p,limit in zip(consumer['overview']['packets'],expected_direction_totals)),'no directional cumulative overcount'
            assert consumer['overview']['bytes']==[p*92 for p in consumer['overview']['packets']],'final cumulative byte oracle'
            losses=sum(c['full'] for c in h['channels'])
            if losses or observed<flow_packets:
                if cfg['export']:assert consumer['overview']['incomplete'],'gap visibility'
            persistent=consumer['persistent']
            if arm.get('expected_snapshot_guard'):
                assert consumer['store_error']=='observation_snapshot_too_large' and persistent is None,'expected bounded store-open failure'
                if android:assert read(prefix+'synthetic-seed.json')==read(prefix+'final-store.json').strip(),'oversize file remains unchanged'
                else:assert digest(directory/prefix/'observation'/('e01-'+cfg['name']+'.json'))==arm['seed_sha256'],'oversize file remains unchanged'
            if cfg['export'] and not losses:
                assert consumer['overview']['packets']==expected_direction_totals,'complete no-loss directional contribution oracle'
                if persistent and not persistent['save_error']:
                    assert persistent['packets']==expected_direction_totals,'complete no-loss durable contribution oracle'
            if persistent:
                assert all(0<=p<=limit for p,limit in zip(persistent['packets'],expected_direction_totals)),'no directional durable overcount'
                assert persistent['bytes']==[p*92 for p in persistent['packets']],'final durable byte oracle'
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
            summaries.append({'arm':cfg['arm'],'generation':generation,'packets':basic(final)-base_basic,'baseline_packets':base_basic,'flow_packets':flow_packets,'non_flow_ip_packets':basic(final)-base_basic-flow_packets,'observed':observed,'persistent':sum(persistent['packets']) if persistent else None,'full':losses,'sent':len(packets),'echoed':sum(r['echoed'] for r in packets),'store_error':consumer['store_error'],'pre_fault_time_placement':placement,'freshness':freshness_interval})
        assert set(endpoints)<=set(payload_owner),'endpoint witness from another workload'
        return {'status':'VALID_EVIDENCE','performance_decision':'USER_REVIEW_REQUIRED','arms':summaries,'errors':[]}
    except (AssertionError,KeyError,ValueError,OSError,TypeError) as e:
        return {'status':'INVALID_EVIDENCE','errors':[str(e)]}

def mutations(directory):
    directory=Path(directory);r=json.loads((directory/'result.json').read_text());android=r['kind']=='android'
    pcaps={name:capture(directory/name) for name in capture_names(r)}
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
    check('wrong Flow address',prefix+'low-settled.json',lambda v:next(r for r in v['consumer']['overview']['records'] if r).__setitem__('addresses',[0]*8))
    check('fabricated cumulative bytes',prefix+'low-settled.json',lambda v:v['consumer']['overview'].__setitem__('bytes',[999999999,999999999]))
    def reverse_direction(v):
        overview=v['consumer']['overview'];overview['packets'][0]+=1;overview['packets'][1]-=1
        overview['bytes']=[p*92 for p in overview['packets']]
    check('direction swap preserving total and byte ratios',prefix+'low-settled.json',reverse_direction)
    if android and a.get('freshness'):
        label=a['freshness']['polls'][-1]['label']
        check('freshness wrong generation',prefix+label+'.json',lambda v:v['health'].__setitem__('generation',0))
        check('freshness false cumulative target',prefix+label+'.json',lambda v:v['consumer']['persistent'].__setitem__('packets',[19,20]))
        check('freshness reversed clock bracket',prefix+label+'-clock.json',lambda v:v['after'].__setitem__('monotonic_ns',v['before']['monotonic_ns']-1))
    elif not android:
        check('freshness target not reached',prefix+'freshness-polls.json',lambda v:v['polls'][-1].__setitem__('persistent_packets',v['target']-1))
    return cases
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--mutations',action='store_true');p.add_argument('--output',type=Path);a=p.parse_args()
    result=verify(a.directory);result['verifier_sha256']=digest(__file__)
    if a.mutations and result['status']=='VALID_EVIDENCE':result['mutations']=mutations(a.directory)
    if a.output:a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2));raise SystemExit(result['status']!='VALID_EVIDENCE')
