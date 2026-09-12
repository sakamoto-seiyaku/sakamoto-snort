#!/usr/bin/env python3
"""Bind the real Pixel service/JNI stop to native and endpoint witnesses."""
import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s242_verify', ROOT/'tests/device/verify-s242-root-lifecycle.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
need, rows, digest, integer, identity = native.need, native.rows, native.digest, native.integer, native.identity


def properties(text):
    return dict(line.split('=', 1) for line in text.splitlines() if '=' in line and not line.startswith('#'))


def verify(directory):
    run = Path(directory)
    report = dict(status='HOLD', run=str(run.resolve()), verifier_sha256=digest(__file__), errors=[], generations=[])
    try:
        result = json.loads((run/'result.json').read_text())
        build = native.authority(run, result)
        need(result['platform'] == 'pixel' and result['scope'] == 'Pixel-Root-RuntimeService-JNI-active-stop-and-native-death', 'wrong supervisor scope')
        need(result['supervisor_runner_sha256'] == digest(ROOT/'tests/device/s242-pixel-supervisor.py'), 'supervisor runner changed')
        records = result['generations']
        need([r['label'] for r in records] == ['stop', 'restart-stop', 'crash', 'recovery-stop'], 'incomplete supervisor matrix')
        need(len({r['generation'] for r in records}) == 4 and all(r['generation'] > 0 for r in records), 'supervisor generation reused')
        need(result['endpoint_cleanup'] and all(e['process_absent'] for e in result['endpoint_cleanup']), 'endpoint helpers survived')
        endpoints = '\n'.join((run/f'endpoint-final-{i}.txt').read_text() for i in range(len(result['endpoint_cleanup'])))
        for record in records:
            phase = run/record['label']
            generation = str(record['generation'])
            state = properties((phase/'running.properties').read_text())
            need(state['state'] == 'running' and state['profile'] == 'root' and state['generation'] == generation
                 and state['protectionRunning'] == 'true' and not state['errorCode'], 'app did not publish running Root protection')
            need(state['adapterReadiness'] == 'root-nfqueue-tcp-udp-echo-dualstack-q2w2', 'wrong app-owned Root lane layout')
            owner = properties((phase/'owner.properties').read_text())
            process_owner = properties((phase/'process-owner.properties').read_text())
            process_owner['SAKAMOTO_VPP_RUNTIME_DIR'] = process_owner['SAKAMOTO_VPP_RUNTIME_DIR'].replace('/data/data/', '/data/user/0/', 1)
            need(owner['generation'] == generation and owner['profile'] == 'root'
                 and process_owner == dict(SAKAMOTO_VPP_OWNER_TOKEN=owner['token'], SAKAMOTO_PRODUCT_GENERATION=generation,
                     SAKAMOTO_VPP_RUNTIME_DIR=owner['runtimePath'].replace('/data/data/', '/data/user/0/', 1),
                     SAKAMOTO_RUNTIME_PROFILE='root'), 'native process owner/generation mismatch')
            stopped = properties((phase/'stopped.properties').read_text())
            need(stopped['state'] == 'stopped' and stopped['mayBeActive'] == 'false' and stopped['pid'] == '-1'
                 and not stopped['errorCode'] and record['process_absent'], 'app cleanup did not settle its process')
            processes = [line.split(None, 2) for line in (phase/'processes-after.txt').read_text().splitlines()]
            need(not any(len(p) == 3 and p[0].isdigit() and
                 (int(p[0]) == record['pid'] or Path(p[2].split()[0]).name == 'libvpp_runtime.so') for p in processes),
                 'native process survived app stop')
            need(properties((phase/'cleanup.properties').read_text())['productRootNfqueueResidueClean'] == 'true', 'production hook cleanup failed')
            native.queue_state(phase, 'app-closed', 'pixel', set())
            native.queue_state(phase, 'initial', 'pixel', set(range(176, 180)))
            hooks = (phase/'hooks.txt').read_text()
            rules = [line for line in hooks.splitlines() if line.startswith('-A SAKAMOTO_PRODUCT_') and '-j NFQUEUE' in line]
            need(len(rules) == 16 and all('--queue-bypass' in line for line in rules), 'production Root fail-open hooks not exercised')
            need(native.clean_hooks((phase/'hooks-after.txt').read_text()) == native.clean_hooks((run/'hooks-before.txt').read_text()),
                 'app-owned hooks survived or unrelated hooks changed')
            log = (phase/'vpp.log').read_text()
            service = (phase/'service.log').read_text()
            need('source=GRAPH_INJECTED' not in log and 'SIGSEGV' not in log, 'non-native packet evidence or crash')
            lanes = {r['lane']: r for r in rows((phase/'initial.txt').read_text(), 'root.lane ')}
            need(set(lanes) == {'0', '1', '2', '3'} and all(r['ready'] == '1' for r in lanes.values()), 'missing app-owned lane')
            native.worker_layout((phase/'trace.txt').read_text(), (phase/'initial-fds.txt').read_text(), list(lanes.values()))
            captures = rows(log, 's231 ', 'nfq_payload')
            syscalls = rows(log, 's242 ', 'verdict_syscall')
            cap = {identity(r): r for r in captures}
            sends = {identity(r): r for r in syscalls}
            need(cap and sends and len(cap) == len(captures) and len(sends) == len(syscalls), 'capture identity reused or physical retry')
            need(set(sends) <= set(cap), 'native operation lacks original capture')
            decoded = {}
            for key, capture in cap.items():
                lane = lanes[capture['lane']]
                need(capture['generation'] == lane['generation'] == generation
                     and capture['queue'] == lane['queue'] and capture['thread'] == lane['thread'], 'cross-generation/origin capture')
                if key in sends:
                    send = sends[key]
                    need(all(send[k] == lane[k] for k in ('generation', 'queue', 'thread', 'fd'))
                         and integer(send, 'result') >= 0 and send['errno'] == '0', 'invalid app native operation')
                # Production INPUT also sees unrelated device traffic.
                # Only our decoded independent endpoints are protocol proof.
                try:
                    facts = native.packet(capture['raw'])
                except AssertionError:
                    continue
                if facts['sport'] in (40642, 40643) or facts['dport'] in (40642, 40643):
                    decoded[key] = facts
            native.cases(phase, record, cap, sends, decoded, endpoints)
            need({(c['lane'], c['owner_path']) for c in record['seeds']} ==
                 {(i, path) for i in range(4) for path in ('local', 'remote')}, 'missing observed app local/remote lanes')
            claims = [line for line in service.splitlines() if re.search(r'\bgeneration='+generation+r'\b', line)]
            zero = rows(log, 's242 ', 'stop_native_zero')
            if record['label'] == 'crash':
                need(record['termination'] == 'SIGKILL_OS_RECLAIM' and record['native_log_source'] == 'frozen-before-sigkill', 'wrong crash witness origin')
                need(not zero and not rows(log, 's242 ', 'lane_closed') and set(cap)-set(sends), 'OS reclaim relabelled as successful native drain')
                failed = properties((phase/'failed.properties').read_text())
                need(failed['generation'] == generation and failed['state'] == 'error'
                     and failed['errorCode'] == 'unexpected_exit' and failed['mayBeActive'] == 'false', 'external death cleanup classification')
                need(not any('s242 native_root_drain=true' in line for line in claims), 'crashed generation claimed graceful drain')
                need(any('product_core_close=os_reclaim_after_exit' in line and 'native_drain_claimed=0' in line for line in claims),
                     'missing explicit supervisor OS-reclaim classification')
                clocks = rows((phase/'kill-clock.txt').read_text(), 'clock ')
                need(len(clocks) == 2 and integer(clocks[0], 'mono_ns') <= integer(clocks[1], 'mono_ns'), 'missing real kill bracket')
            else:
                need(record['termination'] == 'JNI_DRAIN_THEN_APP_STOP' and record['native_log_source'] == 'RuntimeService-stop-archive', 'normal stop bypassed RuntimeService/JNI')
                stopped_claims = [line for line in claims if 's242 native_root_drain=true' in line]
                need(len(stopped_claims) == 1 and 'result=1 ' in stopped_claims[0]
                     and int(re.search(r'elapsed_ms=(\d+)', stopped_claims[0])[1]) <= 3000, 'service native drain failed or exceeded bounded budget')
                need(len(zero) == 1 and zero[0]['generation'] == generation
                     and all(zero[0][k] == '0' for k in ('ready_mask', 'graph_enabled', 'graph_accepting', 'pending',
                         'buffers', 'obligations', 'handoffs', 'completion_frames')), 'missing archived native zero')
                need(set(cap) == set(sends), 'normal service stop lost admitted work')
                returned = rows(log, 's203 ', 'buffer_free')
                consumes = rows(log, 's204 ', 'completion_consume')
                need(len(consumes) == len(sends) and {identity(r) for r in consumes} == set(sends)
                     and all(r['source'] == 'NFQ_CAPTURED' and r['generation'] == generation for r in consumes),
                     'app stop consumed an identity zero or multiple times')
                need(Counter((r['thread'], r['buffer'], r['obligation']) for r in returned) ==
                     Counter((r['thread'], r['buffer'], r['token']) for r in consumes), 'app stop did not return every buffer')
                closed = rows(log, 's242 ', 'lane_closed')
                need([r['lane'] for r in closed] == ['3', '2', '1', '0'] and all(r['fd'] == '-1'
                    and all(r[k] == '0' for k in ('pending', 'allocated', 'loans', 'listener', 'socket')) for r in closed), 'app stop lane resources survived')
                lines = log.splitlines()
                cutoff = [i for i, l in enumerate(lines) if l.startswith('s242 event=quiesce ')]
                closed_at = [i for i, l in enumerate(lines) if l.startswith('s242 event=lane_closed ')]
                need(len(cutoff) == 4 and max(i for i, l in enumerate(lines) if l.startswith('s231 event=nfq_payload ')) < min(cutoff)
                     and max(i for i, l in enumerate(lines) if l.startswith('s242 event=verdict_syscall ')) < min(closed_at), 'app closed verdict channel before completion')
            before = rows((phase/'before-stop-clock.txt').read_text(), 'clock ')[0]
            after = rows((phase/'after-stop-clock.txt').read_text(), 'clock ')[0]
            observed = native.traffic(phase, record, cap, decoded, endpoints,
                [dict(begin_ns=before['mono_ns'], end_ns=after['mono_ns'])])
            report['generations'].append(dict(generation=record['generation'], phase=record['label'],
                native_captures=len(cap), native_syscalls=len(sends), captured_continuous_clients=observed))
        final = properties((run/'app-after.properties').read_text())
        need(final['state'] == 'stopped' and final['mayBeActive'] == 'false' and not final['errorCode'], 'final app not cleanly stopped')
        need(native.clean_hooks((run/'hooks-before.txt').read_text()) == native.clean_hooks((run/'hooks-after.txt').read_text()), 'final kernel hook residue')
        report.update(status='PASS', source_sha256=build['source_sha256'], result_sha256=digest(run/'result.json'), scope=result['scope'])
    except (AssertionError, OSError, ValueError, KeyError, IndexError, StopIteration) as error:
        report['errors'].append(str(error))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    answer = verify(args.run)
    if args.output:
        args.output.write_text(json.dumps(answer, indent=2)+'\n')
    print(json.dumps(answer, indent=2))
    raise SystemExit(answer['status'] != 'PASS')
