#!/usr/bin/env python3
"""Verify S229 native reassembly fault and pressure evidence."""
import argparse, collections, hashlib, importlib.util, json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser()
p.add_argument('--build', type=Path, required=True)
p.add_argument('--run', type=Path, required=True)
p.add_argument('--platform', choices=['linux', 'pixel'], required=True)
p.add_argument('--suite', choices=['basic', 'geometry', 'ingress-handoff', 'sendout-handoff', 'policy-return'], required=True)
p.add_argument('--verification-output', type=Path)
p.add_argument('--policy-helper', type=Path)
a = p.parse_args()
errors = []
def need(ok, message):
    if not ok: errors.append(message)
def rows(text, prefix):
    return [dict(re.findall(r'(\w+)=([^\s]+)', line))
            for line in text.splitlines() if line.startswith(prefix)]
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def one(records, token, name):
    found = [e for e in records if e.get('token', e.get('obligation')) == token]
    need(len(found) == 1, name+' cardinality '+token)
    return found[0] if len(found) == 1 else {}

b = {}; r = {}; tokens = {}; generation = 'unknown'
try:
    spec = importlib.util.spec_from_file_location('chain', ROOT/'tests/evidence/product_chain.py')
    chain = importlib.util.module_from_spec(spec); spec.loader.exec_module(chain)
    b = json.loads(a.build.read_text()); r = json.loads((a.run/'result.json').read_text())
    need(b['files'] == chain.source_files(), 'current Product source differs from build')
    need(r.get('status') == 'RAW_COMPLETE' and not r.get('cleanup_error'), 'run/cleanup incomplete')
    need(r.get('source') == 'GRAPH_INJECTED', 'source label is not graph injected')
    need(r.get('platform') == a.platform and r.get('suite') == a.suite, 'run platform/suite mismatch')
    need(r.get('cases') and int(r.get('generation', 0)) > 0, 'missing cases/generation')
    if a.policy_helper:
        need(r.get('policy_helper_sha256') == digest(a.policy_helper), 'policy helper identity mismatch')
    if a.platform == 'pixel':
        need(r.get('apk_sha256') == b.get('apk_sha256') == digest(Path(b['apk'])), 'APK identity mismatch')
        need(r.get('native_sha256') == b.get('native_sha256'), 'installed native closure mismatch')
    else:
        need(not b.get('host_evidence'), 'host fixture is not native evidence')
        artifact = Path(b['artifact'])
        need(all(digest(artifact/name) == h for name, h in b['artifact_hashes'].items()), 'runtime artifact changed')
    
    log = (a.run/'vpp.log').read_text()
    tokens = {str(212000000 + packet['case']): (case, packet)
              for case in r['cases'] for packet in case['packets']}
    need(len(tokens) == sum(len(c['packets']) for c in r['cases']), 'case identifiers reused')
    generation = str(r['generation'])
    events = collections.defaultdict(list)
    for entry in rows(log, 's212 '): events[entry['event']].append(entry)
    for event in ('fragment_ingress', 'completion_publish', 'origin_release'):
        counts = collections.Counter(e['token'] for e in events[event] if e['token'] in tokens)
        need(counts == collections.Counter({token: 1 for token in tokens}), event+' is not exactly once per original')
    for token, (case, packet) in tokens.items():
        ingress = one(events['fragment_ingress'], token, 'fragment ingress')
        completion = one(events['completion_publish'], token, 'completion publish')
        release = one(events['origin_release'], token, 'origin release')
        need(ingress.get('generation') == completion.get('generation') == release.get('generation') == generation,
             'generation changed '+token)
        need(ingress.get('kind') == completion.get('kind') == release.get('kind') == '2',
             'adapter kind changed '+token)
        need(ingress.get('buffer') == completion.get('buffer') == release.get('buffer'),
             'buffer identity changed '+token)
        need(completion.get('packet') == str(packet['case']) and completion.get('origin_worker') == str(packet['worker']),
             'completion obligation changed '+token)
        need(release.get('refs') == completion.get('refs') == '1', 'original not exclusive at completion '+token)
    frees = collections.Counter(e['obligation'] for e in rows(log, 's203 event=buffer_free ') if e.get('obligation') in tokens)
    need(frees == collections.Counter({token: 1 for token in tokens}), 'physical buffer free is not exactly once')
    live_buffers = {}
    for line in log.splitlines():
        if line.startswith('s212 event=fragment_ingress '):
            e = rows(line, 's212 ')[0]
            if e.get('token') in tokens:
                need(e.get('buffer') not in live_buffers, 'overlapping buffer allocation intervals')
                live_buffers[e.get('buffer')] = e.get('token')
        elif line.startswith('s203 event=buffer_free '):
            e = rows(line, 's203 ')[0]
            if e.get('obligation') in tokens:
                need(live_buffers.pop(e.get('buffer'), None) == e.get('obligation'),
                     'free outside original allocation interval')
    need(not live_buffers, 'live original allocation intervals')
    
    completed = {e['token']: e for e in events['completion_publish'] if e['token'] in tokens}
    native_errors = rows(log, 's229 event=product_error ')
    handoff_errors = rows(log, 's229 event=product_handoff_rejected ')
    successes = rows(log, 's229 event=product_reassembled ')
    if a.suite == 'basic':
        expected_counts = collections.Counter({('1','0','0'): 12, ('2','12','0'): 10,
                                               ('2','7','0'): 4, ('2','13','0'): 2,
                                               ('2','16','0'): 2, ('2','14','0'): 2})
        need(collections.Counter((e['intent'], e['drop_reason'], e['bypass_reason'])
                                 for e in completed.values()) == expected_counts,
             'basic disposition matrix changed')
        expected_errors = {(str(f), reason) for f in (4,6) for reason in ('1','3','5','9')}
        seen_errors = {(e.get('family'), e.get('reason')) for e in native_errors}
        need(expected_errors <= seen_errors, 'basic native error coverage incomplete')
        need(collections.Counter(e['originals'] for e in successes) == collections.Counter({'2': 4, '4': 2}),
             'basic success bundle coverage changed')
        for token, (case, packet) in tokens.items():
            kind = case['kind']
            expected = {'timeout': ('2','13'), 'malformed': ('2','12'),
                        'conflict': ('2','12'), 'duplicate': ('2','12'),
                        'middle-duplicate': ('1','0'), 'policy-drop': ('2','7'),
                        'stop': ('2','14')}.get(kind)
            if kind == 'context-capacity':
                expected = ('2','16') if packet == case['packets'][1] else ('1','0')
            need(expected is not None and
                 (completed.get(token, {}).get('intent'), completed.get(token, {}).get('drop_reason')) == expected,
                 'basic case disposition mismatch '+token)
    elif a.suite == 'geometry':
        need(len(tokens) == 29 and len(r['cases']) == 8 and len(successes) == 5,
             'fragment geometry coverage incomplete')
        for case in r['cases']:
            expected = case.get('assembled_hex')
            head = str(212000000 + case['packets'][0]['case'])
            if expected:
                success = one(successes, head, 'geometry success')
                need(success.get('originals') == str(len(case['packets'])), 'geometry bundle changed')
                packet = one(rows(log, 's216 stage=admit '), head, 'geometry assembled facts')
                need(packet.get('raw') == expected, 'geometry assembled bytes changed')
                offset = case['transport_offset']; raw = bytes.fromhex(expected)
                need(packet.get('protocol') == '17' and packet.get('src_port') == str(int.from_bytes(raw[offset:offset+2], 'big')),
                     'geometry first-fragment transport identity changed')
            for packet in case['packets']:
                token = str(212000000 + packet['case']); done = completed.get(token, {})
                need((done.get('intent'), done.get('drop_reason')) == (('1','0') if expected else ('2',str(case['drop_reason']))),
                     'geometry disposition changed '+token)
                if not expected and case['drop_reason'] == 16:
                    need(one(native_errors, token, 'extension budget').get('reason') == '7',
                         'extension budget became a protocol fault')
    elif a.suite == 'ingress-handoff':
        handoff = [e for e in handoff_errors if e.get('reason') == '8']
        need({e.get('family') for e in handoff} == {'4','6'}, 'ingress handoff did not cover both families')
        need(all(e.get('prepared') == '0' and e.get('slots') == '2' and int(e.get('occupancy','0')) >= 1 for e in handoff),
             'ingress handoff did not hit the unprepared native ring-full path')
        need(sum(1 for e in completed.values() if (e['intent'], e['drop_reason']) == ('2','16')) >= 10,
             'ingress handoff did not settle rejected originals as no-return')
    elif a.suite == 'policy-return':
        need(all((e['intent'], e['drop_reason'], e['bypass_reason']) == ('2','7','0')
                 for e in completed.values()), 'policy return rewrote DROP disposition')
        primary = rows((a.run/'runtime.txt').read_text(), 'primary.status ')
        need(primary and int(primary[0].get('deferred','0')) > 0 and int(primary[0].get('retries','0')) > 0,
             'policy return did not exercise deferred completion retry')
    elif a.suite == 'sendout-handoff':
        handoff = [e for e in handoff_errors if e.get('reason') == '8' and e.get('prepared') == '1']
        need({e.get('family') for e in handoff} == {'4','6'}, 'sendout handoff prepared path not covered')
        need(all(e.get('slots') == '2' and int(e.get('occupancy','0')) >= 1
                 and e.get('thread') != e.get('target_thread') for e in handoff),
             'prepared rejection did not hit a full remote native ring')
        for rejected in handoff:
            case = tokens.get(rejected.get('token'), ({}, {}))[0]
            need(len(case.get('packets', [])) == int(rejected.get('originals', 0)) == 3,
                 'prepared rejection lost its detached bundle')
            for packet in case.get('packets', []):
                completion = completed.get(str(212000000 + packet['case']), {})
                need((completion.get('intent'), completion.get('drop_reason')) == ('2','5'),
                     'prepared primary rejection changed original disposition')
    
    runtime = (a.run/'runtime.txt').read_text()
    reassembly = rows(runtime, 'reassembly.status ')
    completion = rows(runtime, 'completion.status ')
    lanes = rows(runtime, 'root.lane ')
    need(len(reassembly) == 1, 'missing reassembly status')
    need(len(completion) == 1, 'missing completion status')
    need(len(lanes) == 4 and {e.get('lane') for e in lanes} == {'0','1','2','3'}, 'missing lane status')
    for record in reassembly:
        need(record.get('generation') == generation, 'reassembly status generation mismatch')
        need(all(record.get(k) == '0' for k in ('contexts','originals','retained')), 'native reassembly debt')
    for record in completion:
        need(record.get('generation') == generation, 'completion status generation mismatch')
        need(all(record.get(k) == '0' for k in ('pending','frames','buffers','obligations')), 'completion debt')
    for record in lanes:
        need(record.get('pending') == '0', 'root lane pending debt')
    if a.platform == 'pixel':
        need('productRootNfqueueResidueClean=true' in (a.run/'complete-cleanup.properties').read_text(),
             'Pixel root cleanup residue')
    else:
        queues = json.loads((a.run/'queues-free.json').read_text())
        need(set(queues) == {'176','177','178','179'} and all(v == 0 for v in queues.values()),
             'Linux NFQUEUE descriptors not released')
        need(r.get('process_absent') is True, 'Linux VPP process survived stop')
    need('trace_time_cmp' not in log and 'Segmentation fault' not in log, 'trace output crashed')
except (OSError, KeyError, ValueError, TypeError, IndexError) as error:
    errors.append('incomplete evidence: '+str(error))
out = dict(status='PASS' if not errors else 'HOLD', platform=a.platform, suite=a.suite,
           generation=generation, originals=len(tokens),
           build_sha256=digest(a.build) if a.build.is_file() else None, errors=errors)
with (a.verification_output or a.run/'verification.json').open('x') as output:
    output.write(json.dumps(out, indent=2)+'\n')
print(json.dumps(out, indent=2))
raise SystemExit(bool(errors))
