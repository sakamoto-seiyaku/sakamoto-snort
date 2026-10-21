#!/usr/bin/env python3
"""Verify the real Pixel Product TUN capture -> owner -> origin buffer chain."""
import argparse
import hashlib
import json
from pathlib import Path
import re

parser = argparse.ArgumentParser()
parser.add_argument('run', type=Path)
args = parser.parse_args()
run = args.run.resolve()
result = json.loads((run/'result.json').read_text())
assert result['status'] == 'RAW_COMPLETE' and len(result['generations']) == 2
assert hashlib.sha256((run/'malformed-helper').read_bytes()).hexdigest() == \
       result['malformed_helper_sha256']
assert (run/'installed-malformed-helper.txt').read_text().split()[0] == \
       result['malformed_helper_sha256']

def fields(line):
    return dict(re.findall(r'(\w+)=([^\s]+)', line))

for index, generation in enumerate(result['generations']):
    label = f'g{index}'
    log = (run/f'{label}-vpp.log').read_text()
    lines = log.splitlines()
    events = {}
    for line in lines:
        if 'event=' not in line:
            continue
        f = fields(line)
        token = f.get('token', f.get('obligation'))
        if token:
            events.setdefault((token, f['event']), []).append(f)
    malformed = [f for (token, event), values in events.items()
                 if event == 'capture' for f in values
                 if f.get('raw', '').startswith('44') and f.get('bytes') == '28']
    assert len(malformed) == 1, (label, malformed)
    invalid = malformed[0]
    invalid_token, invalid_buffer = invalid['token'], invalid['buffer']
    assert invalid['thread'] == '3'
    assert 'sent=28 errno=0' in (run/f'{label}-malformed-ihl.txt').read_text()
    invalid_admit = events[(invalid_token, 'admit')]
    assert len(invalid_admit) == 1
    assert invalid_admit[0]['thread'] == '3' and invalid_admit[0]['buffer'] == invalid_buffer
    assert invalid_admit[0]['assignment'] == '0' and invalid_admit[0]['intent'] == '2'
    assert (invalid_token, 'primary_publish') not in events
    assert (invalid_token, 'policy') not in events
    for event in ('terminal', 'completion_publish', 'completion_consume',
                  'completion', 'buffer_free'):
        chain = events[(invalid_token, event)]
        assert len(chain) == 1 and chain[0]['buffer'] == invalid_buffer
        assert chain[0]['thread'] == '3'
    invalid_completion = events[(invalid_token, 'completion')][0]
    assert invalid_completion['drop_reason'] == '1'
    assert invalid_completion['policy_verdict'] == 'NOT_EVALUATED'
    invalid_free = events[(invalid_token, 'buffer_free')][0]
    assert all(invalid_free[key] == '0' for key in
               ('buffer_debt', 'obligation_debt', 'completion_frames'))
    def flow_pools(path):
        text = path.read_bytes().replace(b'\0', b'').decode(errors='replace')
        return {int(f['worker']): (f['entries'], f['allocations'])
                for line in text.splitlines() if line.startswith('flow.pool ')
                for f in [fields(line)]}
    assert flow_pools(run/f'{label}-before-malformed.txt') == \
           flow_pools(run/f'{label}-after-malformed.txt')
    admitted = {int(f['src_port']): f for line in lines
                if 's203 event=admit source=TUN_CAPTURED' in line
                for f in [fields(line)] if f.get('family') == '4'
                and f.get('protocol') == '17'}
    seen_owners = set()
    for case in generation['cases']:
        port = case['port']
        assert case['probe']['outcome'] == 'timeout'
        assert port in admitted, (label, port)
        admit = admitted[port]
        token = admit['obligation']
        owner = int(admit['owner'])
        seen_owners.add(owner)
        buffer = admit['buffer']
        assert admit['thread'] == '3' and admit['worker'] == '2'
        def one(event):
            values = events.get((token, event), [])
            assert len(values) == 1, (label, token, event, values)
            return values[0]
        capture = one('capture')
        assert capture['thread'] == '3' and capture['buffer'] == buffer
        primary = one('primary_publish')
        assert primary['thread'] == '3' and primary['buffer'] == buffer
        assert int(primary['owner']) == owner and int(primary['target_thread']) == owner + 1
        receive = one('primary_dequeue')
        assert receive['thread'] == str(owner + 1) and receive['buffer'] == buffer
        policy = one('policy')
        assert policy['thread'] == str(owner + 1) and policy['buffer'] == buffer
        assert policy['verdict'] == '2'
        published = one('completion_publish')
        assert published['thread'] == str(owner + 1) and published['buffer'] == buffer
        consumed = one('completion_consume')
        assert consumed['thread'] == '3' and consumed['buffer'] == buffer
        completion = one('completion')
        assert completion['thread'] == '3' and completion['buffer'] == buffer
        assert completion['policy_drop'] == '1' and completion['pending'] == '0'
        freed = one('buffer_free')
        assert freed['thread'] == '3' and freed['buffer'] == buffer
        assert all(freed[key] == '0' for key in
                   ('buffer_debt', 'obligation_debt', 'completion_frames'))
    assert seen_owners == {0, 1}, (label, seen_owners)
    status_text = (run/f'{label}-final.txt').read_bytes().replace(b'\0', b'').decode(errors='replace')
    topology = next(fields(line) for line in status_text.splitlines()
                    if line.startswith('topology.profile='))
    lane = next(fields(line) for line in status_text.splitlines()
                if line.startswith('topology.tun_io_lane='))
    assert topology['owner_count'] == '2' and topology['vpp_worker_count'] == '3'
    assert topology['actual_vpp_workers'] == '3' and topology['ready'] == '1'
    assert lane['worker'] == '2' and lane['thread_index'] == '3'
    assert lane['actual_core'] == '3' and lane['is_flow_owner'] == '0'
    status = next(fields(line) for line in status_text.splitlines()
                  if line.startswith('tun.status '))
    primary = next(fields(line) for line in status_text.splitlines()
                   if line.startswith('primary.status '))
    assert int(status['captured']) == int(status['submitted']) == int(status['completed'])
    assert int(status['captured']) == int(status['remote']) + 1
    assert int(status['remote']) == int(primary['published']) == int(primary['received'])
    assert status['local'] == '1' and int(status['runtime_drops']) >= 1
    for field in ('pending', 'frames', 'buffers', 'obligations', 'errors', 'rejected'):
        assert status[field] == '0', (label, field, status[field])
    stopped = dict(line.split('=', 1) for line in
                   (run/f'{label}-stopped.properties').read_text().splitlines()
                   if '=' in line and not line.startswith('#'))
    assert stopped['state'] == 'stopped' and stopped['errorCode'] == ''
    assert stopped['mayBeActive'] == 'false'
    print(f'{label}: generation={generation["generation"]} probes={len(generation["cases"])} '
          f'captured={status["captured"]} owners=0,1 exact-index-chain=PASS '
          f'invalid-origin/no-FlowEntry=PASS clean-stop=PASS')
