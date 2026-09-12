#!/usr/bin/env python3
"""Cross-check installed notifier latch observations with actual kernel I/O."""
import argparse
import collections
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--build', type=Path, required=True)
parser.add_argument('--run', type=Path, required=True)
args = parser.parse_args()
spec = importlib.util.spec_from_file_location('w2', ROOT / 'tests/device/verify-s239-w2.py')
w2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w2)
packet_result = w2.verify(args.build, args.run)
metadata = json.loads((args.run / 'native-notify.json').read_text())
run = json.loads((args.run / 'result.json').read_text())
build = json.loads(args.build.read_text())
assert run['notification_trace'] == metadata
assert metadata['library_sha256'] == build['native_sha256']['libvlib.so']
assert metadata['virtual_address'] == 0x321c8 and metadata['file_offset'] == 0x2e1c8
base = w2.module('base', 'tests/device/verify-s237.py')
assert base.digest(args.run / 'native-notify.perf.data') == metadata['perf_sha256']
assert re.search(r'Samples lost: 0\.', (args.run / 'simpleperf-record.txt').read_text())
sys.path.insert(0, '/home/js/.local/share/android-sdk/ndk/29.0.14206865/simpleperf')
from simpleperf_report_lib import ReportLib
lib = ReportLib()
lib.SetRecordFile(str(args.run / 'native-notify.perf.data'))
events = []
while True:
    sample = lib.GetNextSample()
    if sample is None:
        break
    event = lib.GetEventOfCurrentSample()
    events.append(dict(time=sample.time, pid=sample.pid, tid=sample.tid,
                       event=event.name, data=lib.GetTracingDataOfCurrentSample()))
lib.Close()
assert json.loads(json.dumps(events)) == json.loads((args.run / 'native-notify-events.json').read_text())
assert len(events) == metadata['events']
before = (args.run / 'before.txt').read_text()
tids = {i + 1: int(re.search(r'^' + str(i + 1) + r'\s+vpp_wk_' + str(i)
                            + r'\s+workers\s+(\d+)', before, re.M).group(1)) for i in (0, 1)}
tids[0] = metadata['pid']
wake_fds = {int(k): v for k, v in metadata['wake_fds'].items()}
for line in (args.run / 'native-files.txt').read_text().splitlines():
    if 'wakeup thread ' in line:
        columns = line.split()
        assert wake_fds[int(columns[-1])] == int(columns[0])
fd_target = {fd: target for target, fd in wake_fds.items()}
calls, coalesced, writes, reads, empty_reads = [collections.Counter() for _ in range(5)]
elected, entered = {}, {}
blocking_epolls = []
switches = collections.Counter()
for event in events:
    data, tid = event['data'], event['tid']
    assert event['pid'] == metadata['pid']
    if event['event'] == 'uprobes:s239_notify_latch':
        target, previous = data['target'], data['previous']
        assert target in tids and previous in (0, 1)
        calls[target] += 1
        if previous:
            coalesced[target] += 1
        else:
            assert tid not in elected
            elected[tid] = target
    elif event['event'] == 'raw_syscalls:sys_enter':
        assert tid not in entered
        entered[tid] = event
    elif event['event'] == 'raw_syscalls:sys_exit':
        entry = entered.pop(tid, None)
        if entry is None:
            continue  # Recording may begin inside a syscall; never invent entry time.
        assert entry['data']['id'] == data['id']
        fd, result = entry['data']['args'][0], data['ret']
        if data['id'] == 64 and fd in fd_target:
            assert elected.get(tid) == fd_target[fd], 'write without elected native publisher'
            assert entry['data']['args'][2] == 8
            if result == -4:
                continue  # Actual EINTR would retain election through retry.
            assert result == 8, 'notification write did not complete'
            writes[elected.pop(tid)] += 1
        elif data['id'] == 63 and fd in fd_target:
            target = fd_target[fd]
            assert tid == tids[target], 'non-owner reads wake fd'
            assert entry['data']['args'][2] == 8 and result in (8, -11, -4)
            if result == 8:
                reads[target] += 1
            elif result == -11:
                empty_reads[target] += 1
        elif data['id'] in (22, 441) and entry['data']['args'][3] > 0:
            assert event['time'] >= entry['time']
            blocking_epolls.append(dict(tid=tid, start=entry['time'], end=event['time'], result=result))
    elif event['event'] == 'sched:sched_switch':
        assert data['prev_pid'] == tid
        if data['prev_state'] == 1:
            switches[tid] += 1
assert not elected, 'elected publisher stranded at recording end'
assert sum(coalesced.values()) > 0, 'no actual notification coalescing observed'
assert sum(writes.values()) > 0
for target in (1, 2):
    assert calls[target] == coalesced[target] + writes[target]
    assert 0 < reads[target] <= writes[target] and empty_reads[target] > 0
    assert switches[tids[target]] > 0
    assert any(e['tid'] == tids[target] and e['end'] - e['start'] > 1000000 for e in blocking_epolls)

after_quiet = next((p for p in run['probes'] if p['name'] == 'after-quiet'), None)
sleep_witness = False
if after_quiet:
    assert re.search(r'epoll|ep_poll', (args.run / 'native-quiet.wchan').read_text())
    payload = (after_quiet['nonce'] + '_0:0').encode().hex()
    trace = (args.run / 'native-stop.log').read_text()
    packet = next(e for e in w2.rows(trace, 's216 stage=admit source=TUN_CAPTURED ')
                  if e.get('raw', '').endswith(payload))
    policy = next(e for e in w2.rows(trace, 's216 stage=policy ') if e['token'] == packet['token'])
    admitted, executed = int(packet['mono_ns']), int(policy['mono_ns'])
    assert int(packet['owner']) == 1
    assert any(e['tid'] == tids[2] and e['start'] < admitted < e['end'] <= executed
               for e in blocking_epolls), 'no actual epoll sleep spanning final packet publication'
    assert any(e['event'] == 'uprobes:s239_notify_latch' and e['data']['target'] == 2
               and e['data']['previous'] == 0 and admitted <= e['time'] <= executed for e in events)
    sleep_witness = True
print(json.dumps(dict(status='PASS', generation=run['generation'], packets=packet_result['originals'],
                      native_calls=dict(calls), coalesced=dict(coalesced), actual_writes=dict(writes),
                      successful_reads=dict(reads), empty_reads=dict(empty_reads),
                      interruptible_schedules=dict(switches), after_quiet_sleep_witness=sleep_witness,
                      scope='instrumented-native-notification-correctness-not-performance'), indent=2))
