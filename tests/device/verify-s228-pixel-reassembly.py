#!/usr/bin/env python3
"""Verify IPv6 native graph evidence without inventing NFQUEUE fragment identity."""
import argparse
import collections
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser()
p.add_argument('--build', type=Path, required=True)
p.add_argument('--run', type=Path, required=True)
p.add_argument('--suite', choices=['main', 'errors'], required=True)
a = p.parse_args()
errors = []
def need(ok, message):
    if not ok: errors.append(message)
def rows(text, prefix):
    return [dict(re.findall(r'(\w+)=([^\s]+)', line))
            for line in text.splitlines() if line.startswith(prefix)]
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

spec = importlib.util.spec_from_file_location('chain', ROOT/'tests/evidence/product_chain.py')
chain = importlib.util.module_from_spec(spec); spec.loader.exec_module(chain)
b = json.loads(a.build.read_text()); r = json.loads((a.run/'result.json').read_text())
need(b['files'] == chain.source_files(), 'current Product source differs from build')
need(r['status'] == 'CAPTURED' and not r.get('cleanup_error'), 'run/cleanup incomplete')
need(r['source'] == 'GRAPH_INJECTED', 'injected evidence mislabelled')
need(r['apk_sha256'] == b['apk_sha256'], 'APK identity mismatch')
need(r['native_sha256'] == b['native_sha256'], 'installed native closure mismatch')
need(digest(Path(b['apk'])) == b['apk_sha256'], 'built APK bytes changed')
generation = r['generation']
log = (a.run/'before-stop-vpp-stdout.log').read_text()
events = rows(log, 's212 ')
by_event = collections.defaultdict(list)
for e in events: by_event[e['event']].append(e)
packets = [packet for case in r['cases'] for packet in case['packets']]
expected = {str(212000000 + packet['case']): packet for packet in packets}
need(len(expected) == len(packets), 'case identifiers reused')
need(all(e.get('family') == '6' for e in by_event['fragment_ingress']+by_event['native_success']), 'IPv6 graph provenance missing')
for name in ('fragment_ingress', 'completion_publish', 'origin_release'):
    counts = collections.Counter(e['token'] for e in by_event[name])
    need(counts == collections.Counter({token: 1 for token in expected}), name+' is not exactly once per original')
    need(all(e['generation'] == generation and e['kind'] == '2' for e in by_event[name]), name+' changed generation/source')
ingress = {e['token']: e for e in by_event['fragment_ingress']}
complete = {e['token']: e for e in by_event['completion_publish']}
release = {e['token']: e for e in by_event['origin_release']}
for token, packet in expected.items():
    if token not in ingress or token not in complete or token not in release: continue
    i, c, f = ingress[token], complete[token], release[token]
    need(i['buffer'] == c['buffer'] == f['buffer'], token+' original buffer changed')
    need(c['refs'] == f['refs'] == '1', token+' retained engine reference')
    need(int(f['thread']) == packet['worker']+1, token+' completed on wrong origin')
    need(c['packet'] == str(packet['case']) and c['origin_worker'] == str(packet['worker']), token+' obligation changed')
for case in r['cases']:
    label = case.get('label', 'success')
    for n, packet in enumerate(case['packets']):
        token = str(212000000+packet['case']); c = complete.get(token, {})
        intent, reason = '1', '0'
        faults = {'timeout': '13', 'malformed-length': '12', 'stop': '14',
                  'conflict': '12', 'oversize': '16', 'policy-drop': '7'}
        if label in faults: intent, reason = '2', faults[label]
        if label == 'capacity' and n == 1: intent, reason = '2', '16'
        need(c.get('intent') == intent and c.get('drop_reason') == reason,
             label+' unexpected disposition for '+token)
        need(c.get('bypass_reason') == '0', label+' invented a graph NFQ return capability')
success_tokens = collections.Counter(e['token'] for e in by_event['native_success'])
for stage in ('admit', 'policy', 'terminal'):
    owner_tokens = collections.Counter(e['token'] for e in rows(log, 's207 stage='+stage+' ') if e['token'] in expected)
    need(owner_tokens == success_tokens, 'assignment/policy must occur once after native success: '+stage)
# Independently reconstruct the complete payload from the registered originals.
admitted = {e['token']: e for e in rows(log, 's216 stage=admit ')}
for success in by_event['native_success']:
    token = success['token']; lead = bytes.fromhex(expected[token]['hex'])
    need(int.from_bytes(lead[42:44], 'big') & 0xfff8 == 0, 'survivor is not offset zero')
    pieces = [bytes.fromhex(v['hex']) for v in expected.values()
              if bytes.fromhex(v['hex'])[44:48] == lead[44:48]]
    end = max((int.from_bytes(v[42:44], 'big') & 0xfff8) + len(v)-48 for v in pieces)
    payload = bytearray(end)
    for v in pieces:
        offset = int.from_bytes(v[42:44], 'big') & 0xfff8
        payload[offset:offset+len(v)-48] = v[48:]
    actual = admitted.get(token, {})
    data = bytes.fromhex(actual.get('raw', ''))
    need(len(data) == end+40 and data[40:] == payload and data[6] == 17, token+' reassembled payload differs')
    need(int.from_bytes(data[4:6], 'big') == end and int.from_bytes(payload[4:6], 'big') == end, token+' declared length differs')
    checksum_data = data[8:40] + struct.pack('!I3xB', end, 17) + payload
    if len(checksum_data) % 2: checksum_data += b'\0'
    checksum = sum(struct.unpack('!'+str(len(checksum_data)//2)+'H', checksum_data))
    while checksum >> 16: checksum = (checksum & 65535) + (checksum >> 16)
    need(checksum == 65535 and payload[6:8] != b'\0\0', token+' invalid IPv6 UDP checksum')
    need(actual.get('l3') == actual.get('l4') == '1' and actual.get('protocol') == '17' and actual.get('family') == '6', token+' incomplete shared parse')
    need(actual.get('uid') == '21200' and actual.get('availability') == '1'
         and actual.get('direction') == '3' and actual.get('provenance') == '4', token+' offset-zero platform facts changed')
pins = collections.Counter(e['token'] for e in by_event['pin'])
pinned_returns = collections.Counter(e['token'] for e in by_event['completion_publish'] if e['pinned'] == '1')
need(pins == pinned_returns and all(n == 1 for n in pins.values()), 'lifetime pins not released exactly once')
status = (a.run/'reassembly-status.txt').read_text()
reassembly = rows(status, 'reassembly.status ')
need(len(reassembly) == 1 and all(reassembly[0].get(k) == '0' for k in ('contexts','originals','retained')), 'native fragment debt remains')
completion = rows((a.run/'complete-drain.txt').read_text(), 'completion.status ')
need(len(completion) == 1 and all(completion[0].get(k) == '0' for k in ('pending','frames','buffers','obligations')), 'completion debt or invented NFQ verdict')
baseline = rows((a.run/'first-quiesce-drain.txt').read_text(), 'completion.status ')
need(len(baseline) == 1 and len(completion) == 1 and baseline[0]['verdicts'] == completion[0]['verdicts'], 'graph injection created NFQUEUE verdicts')
need('productRootNfqueueResidueClean=true' in (a.run/'complete-cleanup.properties').read_text(), 'stop residue')
if a.suite == 'main':
    need(len(packets) == 32, 'main matrix population changed')
    need(any(e['originals'] == '6' for e in by_event['native_success']), 'no larger-than-four native bundle')
    need(len(by_event['native_duplicate_retain']) == 1, 'exact duplicate not retained')
    # Consume executes on the native memory owner; success may resume after
    # native sendout handoff, so its thread is not the memory-owner witness.
    prepared = {e['token']: e for e in by_event['native_finalize_prepare']}
    success = {e['token']: prepared[e['token']] for e in by_event['native_success']}
    delivered = {e['token']: e for e in rows(log, 's207 stage=terminal ')}
    pairs = {(int(e['thread'])-1, int(delivered[t]['owner']))
             for t,e in success.items() if t in delivered}
    need(pairs == {(0,0),(0,1),(1,0),(1,1)}, 'memory-owner/final-owner matrix incomplete')
    need(any(e['thread'] == '0' for e in by_event['completion_publish']), 'no main-thread expiry/flush completion')
    need(0 < r.get('timeout_observed_seconds', 0) < 10, 'unbounded expiry observation')
if a.suite == 'errors':
    need(len(packets) == 17, 'error matrix population changed')
    need('ip6-full-reassembly-custom' in status and 'reass id:' in status,
         'native fragment traces missing')
out = dict(status='PASS' if not errors else 'HOLD', source='GRAPH_INJECTED',
           suite=a.suite, originals=len(packets), generation=generation,
           build_sha256=digest(a.build), errors=errors)
(a.run/'verification.json').write_text(json.dumps(out, indent=2)+'\n')
print(json.dumps(out, indent=2))
raise SystemExit(bool(errors))
