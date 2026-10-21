#!/usr/bin/env python3
"""Verify Product Pixel UDP return lineage, bytes, placement, and settlement."""
import argparse
import hashlib
import json
import re
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('run', type=Path)
a = p.parse_args()
run = a.run.resolve()
result = json.loads((run / 'result.json').read_text())
assert result['status'] in ('SMOKE_ECHO_COMPLETE', 'SAME_SESSION_RECOVERY_COMPLETE')
fault_write = result.get('fault') == 'write'
assert result.get('fault') in ('none', 'write')
assert hashlib.sha256((run / 'udp-endpoint').read_bytes()).hexdigest() == result['endpoint_sha256']
assert (run / 'installed-apk.txt').read_text().split()[0] == result['apk_sha256']
installed = {Path(line.split()[1]).name: line.split()[0]
             for line in (run / 'installed-native.txt').read_text().splitlines()}
assert all(len(value) == 64 for value in installed.values())
for name, digest in result['test_inputs'].items():
    assert hashlib.sha256((run / 'test-source' / name).read_bytes()).hexdigest() == digest

def fields(line):
    return dict(re.findall(r'(\w+)=([^\s]+)', line))

def records(path, prefix):
    return [fields(line) for line in path.read_bytes().replace(b'\0', b'').decode(errors='replace').splitlines()
            if line.startswith(prefix)]

def one(values, **expected):
    found = [value for value in values if all(value.get(k) == str(v) for k, v in expected.items())]
    assert len(found) == 1, (expected, found)
    return found[0]

def payload(raw):
    packet = bytes.fromhex(raw)
    if len(packet) < 28 or packet[0] >> 4 != 4 or packet[9] != 17:
        return None
    offset = (packet[0] & 15) * 4
    assert len(packet) == int.from_bytes(packet[2:4], 'big')
    return packet[offset + 8:]

owner = result['owner']
owner_thread = str(owner + 1)
generation = str(result['generation'])
topology = one(records(run / 'before.txt', 'topology.profile='), profile='vpn')
lane = one(records(run / 'before.txt', 'topology.tun_io_lane='), worker=2)
assert topology['owner_count'] == '2' and topology['vpp_worker_count'] == '3'
assert lane['thread_index'] == '3' and lane['actual_core'] == '3'
assert lane['is_flow_owner'] == '0'
probe = dict(line.split('=', 1) for line in (run / 'probe.properties').read_text().splitlines() if '=' in line)
assert probe['nonce'] == result['nonce']
assert all(probe['packet.' + str(i)] == ('timeout' if fault_write and i == 1 else 'echo')
           for i in range(3))
assert result['nonce'][1:] + ':0' in (run / 'endpoint.log').read_text()

if result.get('ordinary_product'):
    stack = one(records(run / 'after.txt', 'tun.flow_stack '))
    status = one(records(run / 'after.txt', 'tun.status '), generation=generation)
    assert stack['enabled'] == stack['ready'] == '1'
    assert int(stack['return_packets']) >= 3 and int(stack['write_succeeded']) >= 3
    assert stack['write_failed'] == '0'
    assert status['origin_thread'] == '3' and status['attached'] == '1'
    assert all(status[k] == '0' for k in ('pending', 'frames', 'buffers', 'obligations', 'errors'))
    running = dict(line.split('=', 1) for line in (run / 'running.properties').read_text().splitlines() if '=' in line)
    assert running['protectionRunning'] == 'true'
    stopped = dict(line.split('=', 1) for line in (run / 'stopped.properties').read_text().splitlines() if '=' in line)
    assert stopped['state'] == 'stopped' and stopped['mayBeActive'] == 'false'
    assert 'libvpp_runtime.so' not in (run / 'processes-after.txt').read_text()
    print(f"S298 ordinary Product generation={generation} UDP byte-equal echoes, write/status debt zero, clean stop: PASS")
    raise SystemExit(0)

log = (run / 'vpp.log').read_text()
def events(prefix):
    return [fields(line) for line in log.splitlines() if line.startswith(prefix)]
capture = events('s213 event=capture ')
return_copy = events('s237 event=return_copy ')
return_wire = events('s240 event=return_wire ')
write_wire = events('s298 event=write_wire ')
admit = events('s203 event=admit ')
primary_pub = events('s205 event=primary_publish ')
primary_get = events('s205 event=primary_dequeue ')
policy = events('s203 event=policy ')
completion_pub = events('s204 event=completion_publish ')
return_pub = events('s205 event=completion_return_publish ')
return_get = events('s204 event=completion_consume ')
completion = events('s213 event=completion ')
free = events('s203 event=buffer_free ')

for i in range(3):
    expected = (result['nonce'] + ':' + str(i)).encode()
    origin = one([row for row in capture if payload(row['raw']) == expected])
    assert origin['thread'] == '3' and origin['generation'] == generation
    token, buffer = origin['token'], origin['buffer']
    owner_admit = one(admit, obligation=token)
    assert owner_admit['thread'] == '3' and owner_admit['owner'] == str(owner)
    assert owner_admit['buffer'] == buffer
    assert one(primary_pub, token=token)['buffer'] == buffer
    assert one(primary_get, token=token)['thread'] == owner_thread
    assert one(policy, obligation=token)['thread'] == owner_thread
    assert one(completion_pub, token=token)['buffer'] == buffer
    assert one(return_get, token=token)['thread'] == '3'
    settled = one(completion, token=token)
    assert settled['buffer'] == buffer and settled['thread'] == '3'
    assert settled['transport_outcome'] == 'ADMITTED'
    assert one(free, obligation=token)['thread'] == '3'

    wire = one([row for row in return_wire if payload(row['raw']) == expected])
    return_token, return_buffer = wire['token'], wire['buffer']
    assert wire['thread'] == owner_thread and wire['owner'] == str(owner)
    assert wire['generation'] == generation
    copied = one(return_copy, token=return_token)
    assert copied['buffer'] == return_buffer and copied['thread'] == owner_thread
    assert one(admit, obligation=return_token)['buffer'] == return_buffer
    assert one(policy, obligation=return_token)['thread'] == owner_thread
    assert one(completion_pub, token=return_token)['buffer'] == return_buffer
    assert one(return_pub, token=return_token)['target_thread'] == '3'
    assert one(return_get, token=return_token)['thread'] == '3'
    attempted = one(write_wire, token=return_token)
    assert attempted['thread'] == '3' and attempted['buffer'] == return_buffer
    assert attempted['raw'] == wire['raw']
    assert attempted['requested'] == ('0' if fault_write and i == 1 else wire['bytes'])
    completed = one(completion, token=return_token)
    assert completed['thread'] == '3' and completed['buffer'] == return_buffer
    if fault_write and i == 1:
        assert completed['transport_outcome'] == 'TUN_WRITE_FAILED'
        assert completed['write_result'] == '-1' and completed['write_errno'] == '22'
        assert len([x for x in completion if x['token'] == return_token]) == 1
    else:
        assert completed['transport_outcome'] == 'TUN_WRITE_SUCCEEDED'
        assert completed['write_result'] == wire['bytes'] and completed['write_errno'] == '0'
    assert one(free, obligation=return_token)['thread'] == '3'

if result.get('stress_ingress'):
    assert hashlib.sha256((run / 'tun-ingress-flood').read_bytes()).hexdigest() == result['flood_sha256']
    flood = fields((run / 'flood.txt').read_text())
    started, ended = int(flood['started_ns']), int(flood['ended_ns'])
    assert int(flood['sent']) >= 750 and ended - started >= 1000000000
    overlap = [row for row in write_wire if started <= int(row['mono_ns']) <= ended
               and payload(row['raw']) in
               {(result['nonce'] + ':' + str(i)).encode() for i in range(3)}]
    assert overlap, 'no UDP return write progressed during sustained TUN ingress'
    for row in overlap:
        published = one(return_wire, token=row['token'])
        assert 0 <= int(row['mono_ns']) - int(published['mono_ns']) < 1000000000
    invalid = [row for row in capture if row['raw'].startswith('44')]
    assert len(invalid) >= 100, len(invalid)

status = one(records(run / 'after.txt', 'tun.status '), generation=generation)
for key in ('pending', 'frames', 'buffers', 'obligations', 'rejected'):
    assert status[key] == '0', (key, status[key])
write_status = one(records(run / 'after.txt', 'tun.write_result '))
assert write_status['short'] == write_status['eagain'] == '0'
assert write_status['error'] == ('1' if fault_write else '0')
if fault_write:
    stack = one(records(run / 'after.txt', 'tun.flow_stack '))
    assert stack['write_attempts'] == '3' and stack['write_succeeded'] == '2'
    assert stack['write_failed'] == '1'
if not result.get('ordinary_product'):
    stop = one(records(run / 'native-stop.log', 's213 event=stop '), generation=generation)
    assert all(stop[key] == '0' for key in ('pending', 'buffers', 'frames', 'obligations'))
stopped = dict(line.split('=', 1) for line in (run / 'stopped.properties').read_text().splitlines() if '=' in line)
assert stopped['state'] == 'stopped' and stopped['mayBeActive'] == 'false'
assert 'libvpp_runtime.so' not in (run / 'processes-after.txt').read_text()
print(f"S298 owner={owner} generation={generation} "
      f"{'two echoes and one classified write failure' if fault_write else 'three UDP echoes'}, "
      "exact return bytes/index, one attempt per return, zero debt: PASS")
