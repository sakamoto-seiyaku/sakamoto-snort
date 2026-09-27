#!/usr/bin/env python3
"""Verify 10k physical packet attempts against both wire boundaries and VPP counts."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

p = argparse.ArgumentParser()
p.add_argument('--run', type=Path, required=True)
p.add_argument('--build', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
run, build_path = a.run.resolve(), a.build.resolve()
digest = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
read = lambda name: (run / name).read_text()
data = lambda name: json.loads(read(name))
build, result = json.loads(build_path.read_text()), data('result.json')
assert result['status'] == 'RAW_COMPLETE' and result['ordinary_history_unchanged'] is True
assert not result.get('cleanup_error')
assert result['source_sha256'] == build['source_sha256']
assert result['build_sha256'] == digest(build_path)
assert digest(build['apk']) == build['apk_sha256'] == read('installed-apk.txt').split()[0]
with zipfile.ZipFile(build['apk']) as archive:
    native = {Path(name).name:hashlib.sha256(archive.read(name)).hexdigest()
              for name in archive.namelist() if name.startswith('lib/arm64-v8a/') and name.endswith('.so')}
assert native == build['native_sha256']
installed = {Path(line.split()[1]).name:line.split()[0] for line in read('installed-native.txt').splitlines()}
assert installed == native
assert data('before-ordinary-hashes.json') == data('after-ordinary-hashes.json')
assert '0 packets dropped by kernel' in read('host-capture.log')
assert '0 packets dropped by kernel' in read('device-capture.log')

def packets(name):
    fields = ('ip.src','ip.dst','udp.srcport','udp.dstport','udp.payload')
    cmd = ['tshark','-r',str(run/(name+'.pcap')),'-Y','udp.port==42121','-T','fields']
    for field in fields:cmd += ['-e',field]
    text = subprocess.check_output(cmd,text=True,stderr=subprocess.DEVNULL)
    return [line.split('\t') for line in text.splitlines() if line.count('\t') == 4]
host, device = packets('host'), packets('device')
endpoint = [json.loads(line) for line in read('endpoint.jsonl').splitlines() if line.startswith('{')]
profiles = {}
for profile, port in (('root',42122),('vpn',42123)):
    life = next(x for x in result['lifetimes'] if x['profile'] == profile)
    plan = next(x['plan'] for x in result['plans'] if x['profile'] == profile)
    assert plan['observationFlood'] == 10000 and plan['observationBatch'] == 1
    assert plan['observationTolerateLoss'] is True and plan['observationMaxTimeouts'] == 256
    assert life['process_absent'] and life['mapping_released'] and life['end_only_tail_packets'] > 0
    assert 'state=stopped' in read(profile+'-stopped-latest.properties')
    assert 'sakamoto-observation' in read(profile+'-app-live-maps.txt')
    assert 'sakamoto-observation' in read(profile+'-vpp-live-maps.txt')
    assert 'sakamoto-observation' not in read(profile+'-app-stopped-maps.txt')
    started = data(profile+'-observation_created.json')
    local = started['local'].lstrip('/').rsplit(':',1)[0]
    marker = plan['nonce'].encode()[:22]
    def numbered(source,kind):
        found = {}
        for row in source:
            try:payload=bytes.fromhex(row[4])
            except ValueError:continue
            if marker not in payload:continue
            if kind == 'request' and row[3] != '42121':continue
            if kind == 'reply' and row[2] != '42121':continue
            if source is device:
                if kind == 'request' and (row[0] != local or row[2] != str(port)):continue
                if kind == 'reply' and (row[1] != local or row[3] != str(port)):continue
            number = int(payload[:8])
            assert payload[8:9] == b':'
            found[number] = payload.hex()
        return found
    host_req, host_reply = numbered(host,'request'), numbered(host,'reply')
    device_req, device_reply = numbered(device,'request'), numbered(device,'reply')
    echoed = {}
    for event in endpoint:
        if event.get('kind') != 'echo':continue
        payload = bytes.fromhex(event['payload'])
        if marker in payload:echoed[int(payload[:8])] = event['payload']
    assert set(device_req) == set(range(10006)),(profile,len(device_req))
    assert set(host_req) <= set(device_req)
    assert set(echoed) == set(host_req)
    assert set(host_reply) == set(echoed)
    assert set(device_reply) <= set(host_reply)
    for collection in (host_req,host_reply,device_req,device_reply,echoed):
        assert len(collection) == len(set(collection.values()))
    full_range = set(range(4,10005))
    full_packets = [len(full_range & set(device_req)),len(full_range & set(device_reply))]
    assert life['full_tail_packets'] == full_packets,(profile,life['full_tail_packets'],full_packets)
    final = data(profile+'-finished.json')
    assert final['phase'] == 'finished' and final['sent'] == 10006
    assert final['received'] <= final['sent']
    assert final['transportTimeouts'] <= 256 and final['unresolvedReplies'] <= final['transportTimeouts']
    assert final['received'] == 10006-final['unresolvedReplies']
    assert 'error' not in final
    paused = data(profile+'-paused.json')
    full = data(profile+'-full.json')
    assert full['consumer']['overview']['accepted'] == paused['consumer']['overview']['accepted']
    channel_full = sum(c['full'] for c in full['health']['channels']) - sum(c['full'] for c in paused['health']['channels'])
    assert channel_full > 0
    ended = data(profile+'-full-end-tail.json')
    records = [r for r in ended['consumer']['overview']['records'] if r and r['ended']
               and port in r['ports'] and r['incarnation'] > 0]
    assert any(r['packets'] == full_packets and r['bytes'] == [count*60 for count in full_packets]
               for r in records)
    assert 'pending=0' in read(profile+'-before-stop.txt') and 'obligations=0' in read(profile+'-before-stop.txt')
    assert (run/(profile+'-full-vpp-process.txt')).exists()
    assert (run/(profile+'-full-app-process.txt')).exists()
    underlay_missing = sorted(set(host_reply)-set(device_reply))
    if profile == 'vpn':
        physical = {int(bytes.fromhex(row[4])[:8]) for row in device
                    if row[2] == '42121' and row[1] != local and marker in bytes.fromhex(row[4])}
        assert set(device_reply) <= physical
        assert physical <= set(host_reply)
        assert not (physical-set(device_reply)), 'reply reached device underlay but not the TUN path'
    profiles[profile] = dict(generation=life['generation'],sent=final['sent'],received=final['received'],
        host_requests=len(host_req),host_replies=len(host_reply),device_requests=len(device_req),
        device_replies=len(device_reply),host_to_device_missing_replies=len(underlay_missing),
        transport_timeouts=final['transportTimeouts'],late_replies=final['lateReplies'],
        full_flow_packets=full_packets,channel_full_delta=channel_full)

answer = dict(status='VALID',source_sha256=build['source_sha256'],apk_sha256=build['apk_sha256'],
              profiles=profiles,ordinary_history_unchanged=True,capture_kernel_drops=0,
              verifier_sha256=digest(__file__))
a.output.write_text(json.dumps(answer,indent=2)+'\n')
print(json.dumps(answer,indent=2))
