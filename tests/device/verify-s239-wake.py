#!/usr/bin/env python3
"""Verify a bounded current-artifact VPN wake regression, not full S239 closure."""
import argparse
import collections
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--build', type=Path, required=True)
parser.add_argument('--run', type=Path, required=True)
args = parser.parse_args()
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value
chain = module('chain', 'tests/evidence/product_chain.py')
oracle = module('oracle', 'tests/device/s207-owner-oracle.py')
build = json.loads(args.build.read_text())
run = json.loads((args.run / 'result.json').read_text())
assert build['files'] == chain.source_files(), 'artifact is not current source'
assert run['apk_sha256'] == build['apk_sha256'] == chain.digest(build['apk'])
assert run['build_sha256'] == chain.digest(args.build)
assert run['status'] in ('SMOKE_ECHO_COMPLETE', 'RETURN_DROP_RECOVERY_COMPLETE',
                         'SAME_SESSION_RECOVERY_COMPLETE', 'OVERLAP_STOP_COMPLETE')
assert not run.get('error') and not run.get('cleanup_error')
for name, digest in run['test_inputs'].items():
    assert chain.digest(args.run / 'test-source' / name) == digest
if run.get('verify_sleep'):
    assert re.search(r'ep_poll|epoll', run['sleep_observation']['wchan'])
log = (args.run / 'native-stop.log').read_text()
events = []
for line in log.splitlines():
    if line.startswith(('s213 ', 's216 ', 's237 ', 's239 ', 's203 ', 's204 ')):
        fields = dict(re.findall(r'(\w+)=([^\s]+)', line))
        fields['_prefix'] = line.split()[0]
        events.append(fields)
owner = run['owner']
admitted = [e for e in events if e.get('stage') == 'admit' and e.get('protocol') == '17'
            and {int(e['src_port']), int(e['dst_port'])} == {run['source_port'], run['endpoint_port']}]
assert admitted, 'missing actual controlled UDP'
delays = []
returns = 0
for packet in admitted:
    token = packet['token']
    facts = {k: int(v) if k not in ('src', 'dst') else v for k, v in packet.items()
             if k in ('l3', 'l4', 'family', 'protocol', 'src', 'dst', 'src_port',
                      'dst_port', 'icmp_known', 'icmp_type', 'icmp_code', 'icmp_id')}
    assert oracle.owner(facts) == int(packet['owner']) == owner
    related = [e for e in events if e.get('token', e.get('obligation')) == token]
    def single(predicate):
        selected = [e for e in related if predicate(e)]
        assert len(selected) == 1, (token, selected)
        return selected[0]
    policy = single(lambda e: e.get('stage') == 'policy')
    terminal = single(lambda e: e.get('stage') == 'terminal')
    complete = single(lambda e: e.get('event') == 'completion_consume')
    freed = single(lambda e: e.get('event') == 'buffer_free')
    assert packet['buffer'] == policy['buffer'] == terminal['buffer'] == complete['buffer'] == freed['buffer']
    assert int(policy['thread']) == int(terminal['thread']) == owner + 1
    assert int(complete['thread']) == int(freed['thread']) == 1
    for earlier, later in ((packet, policy), (terminal, complete)):
        delay = (int(later['mono_ns']) - int(earlier['mono_ns'])) / 1e6
        assert 0 <= delay < 1500, (token, delay)  # Existing failure oracle, not a p99 budget.
        delays.append(delay)
    if packet['source'] == 'FLOW_STACK_RETURN':
        returns += 1
        credit = single(lambda e: e.get('event') == 'return_credit_released')
        assert credit['after_native_free'] == '1' and int(credit['owner']) == owner
        assert credit['buffer'] == packet['buffer'] and int(credit['capacity']) == 128
assert returns, 'no native return completion'
mutable = {'pbuf_alloc', 'pbuf_free', 'socket_created', 'socket_closed', 'output', 'direct_receive'}
for event in events:
    if event.get('event') in mutable and event['_prefix'] == 's237':
        assert int(event['owner']) == owner
        assert int(event['thread']) == int(event['tls']) == owner + 1
stops = [e for e in events if e.get('event') == 'owner_stopped']
assert len(stops) == 2 and {e['owner'] for e in stops} == {'0', '1'}
for stopped in stops:
    assert stopped['generation'] == str(run['generation'])
    assert all(stopped[k] == '0' for k in ('sessions', 'inputs', 'pbufs', 'buffers', 'obligations', 'frames'))
    assert stopped['sockets_created'] == stopped['sockets_closed']
    assert stopped['timer_fd'] == stopped['broker_fd'] == '-1'
result = dict(status='PASS', scope='bounded-vpn-wake-regression-not-full-s239',
              generation=run['generation'], owner=owner, family=run['family'],
              sleep_observed=bool(run.get('verify_sleep')), udp_packets=len(admitted),
              returns=returns, max_measured_leg_ms=max(delays),
              source_sha256=build['source_sha256'], apk_sha256=build['apk_sha256'])
print(json.dumps(result, indent=2))
