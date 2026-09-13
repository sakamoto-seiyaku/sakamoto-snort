#!/usr/bin/env python3
"""S220 service configuration/OS affinity and native stop, not broad VPN readiness."""
import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'tests/device'/filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


placement = module('s220_service_placement_verify', 'verify-s220-worker-placement.py')
native = placement.native
need, rows, digest = native.need, native.rows, native.digest


def props(text):
    return dict(line.split('=', 1) for line in text.splitlines() if '=' in line and not line.startswith('#'))


def verify(run):
    result = json.loads((run/'result.json').read_text())
    need(result['task'] == 'SAKAMOTO-220' and result['scope'] == 'Pixel-Root-ordered-CPU-supervisor'
         and result['platform'] == 'pixel' and not result.get('error'), 'supervisor scope/incomplete run')
    for name in result['raw_hashes']:
        need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'raw path escapes scope')
    build = native.authority(run, result)
    need(result['s220_supervisor_sha256'] == digest(run/'s220-supervisor.py') ==
         digest(ROOT/'tests/device/s220-pixel-supervisor.py') and
         result['supervisor_runner_sha256'] == digest(ROOT/'tests/device/s242-pixel-supervisor.py') and
         result['placement_runner_sha256'] == digest(ROOT/'tests/device/s220-worker-placement.py'), 'supervisor source identity')
    before = (run/'preferences-before.xml').read_text()
    if before.lstrip().startswith('<?xml'):
        element = ET.fromstring(before).find("string[@name='workerCpuIds']")
        original = '1,2' if element is None else element.text
    else:
        need('No such file or directory' in before, 'original preferences could not be read safely')
        original = '1,2'
    need(result['original_effective_selection'] == original, 'original choice not preserved')
    records = result['generations']
    need([r['label'] for r in records] == ['forward', 'saved', 'reverse', 'restore'] and
         len({r['pid'] for r in records}) == 4 and all(r['generation'] > 0 for r in records) and
         all(a['generation'] < b['generation'] for a, b in zip(records, records[1:])), 'clean restart generation/PID census')
    need(result['endpoint_cleanup'] and all(e['process_absent'] for e in result['endpoint_cleanup']), 'endpoint helper residue')
    endpoints = '\n'.join(p.read_text() for p in run.glob('endpoint-final-*.txt'))
    expected = [('1,3', [1, 3]), (None, [1, 3]), ('3,1', [3, 1]), (original, list(map(int, original.split(','))))]
    reports = []
    stage = props((Path(result['build']).parent/'stage/product-stage.properties').read_text())
    for record, (requested, mapping) in zip(records, expected):
        folder = run/record['label']; generation = str(record['generation'])
        need(record['requested_worker_cpus'] == requested and record['worker_cpus'] == mapping, 'requested versus saved selection')
        config = (folder/'startup.conf').read_text()
        sequences = re.findall(r'\bcpu\s*\{\s*main-core\s+0\s+workers\s+2\s+ordered-workers\s+([0-9,]+)\s*\}', config)
        need(sequences == [','.join(map(str, mapping))] and len(re.findall(r'\bcpu\s*\{', config)) == 1, 'service did not generate ordered native config')
        saved = ET.fromstring((folder/'preferences.xml').read_text()).find("string[@name='workerCpuIds']")
        need(saved is not None and saved.text == sequences[0], 'successful selection not persisted in order')
        guard = props((folder/'guard.properties').read_text())
        need(guard['generation'] == generation and guard['worker_cpu_ids'] == sequences[0]
             and guard['worker_core_config_match'] == guard['placement_fixed_before_start'] == 'true'
             and guard['vpp_worker_count'] == guard['product_graph_worker_count'] == '2'
             and guard['vpp_main_core'] == '0' and guard['vpp_worker0_thread_index'] == '1'
             and guard['vpp_worker1_thread_index'] == '2' and
             [int(guard['vpp_worker0_core']), int(guard['vpp_worker1_core'])] == mapping and
             int(guard['product_graph_hash_seed']) == 0x6f776e65722d3137, 'actual native placement/fixed owner seed differs')
        need(guard['dynamic_worker_change'] == guard['runtime_resize'] == guard['runtime_reshard'] == 'false', 'live layout change claim')
        tids = placement.affinity(folder, 'initial', [0, *mapping], record['pid'])
        need(placement.affinity(folder, 'active', [0, *mapping], record['pid']) == tids, 'same-generation OS threads changed')
        running = props((folder/'running.properties').read_text())
        need(running['state'] == 'running' and running['protectionRunning'] == 'true' and
             not running['errorCode'] and running['profile'] == 'root' and running['generation'] == generation and
             running['artifact'] == stage['artifactId'] and running['version'] == stage['vppRevision'], 'running app/artifact/generation identity')
        owner = props((folder/'owner.properties').read_text())
        process = props((folder/'process-owner.properties').read_text())
        need(owner['generation'] == generation and owner['profile'] == 'root' and
             process['SAKAMOTO_PRODUCT_GENERATION'] == generation and process['SAKAMOTO_VPP_OWNER_TOKEN'] == owner['token'] and
             process['SAKAMOTO_RUNTIME_PROFILE'] == 'root' and
             process['SAKAMOTO_VPP_RUNTIME_DIR'].replace('/data/data/', '/data/user/0/', 1) ==
             owner['runtimePath'].replace('/data/data/', '/data/user/0/', 1), 'actual process not the durable owner')
        log = (folder/'vpp.log').read_text(); service = (folder/'service.log').read_text()
        need(record['process_absent'] and record['termination'] == 'JNI_DRAIN_THEN_APP_STOP' and
             record['native_log_source'] == 'RuntimeService-stop-archive' and 'source=GRAPH_INJECTED' not in log, 'normal app stop not proven')
        lanes = rows((folder/'initial.txt').read_text(), 'root.lane ')
        native.worker_layout((folder/'trace.txt').read_text(), (folder/'initial-fds.txt').read_text(), lanes)
        lanes = {e['lane']: e for e in lanes}
        captures, sends, consumes = rows(log, 's231 ', 'nfq_payload'), rows(log, 's242 ', 'verdict_syscall'), rows(log, 's204 ', 'completion_consume')
        cap, operations = {native.identity(e): e for e in captures}, {native.identity(e): e for e in sends}
        need(cap and len(cap) == len(captures) == len(sends) == len(operations) == len(consumes) and
             set(cap) == set(operations) == {native.identity(e) for e in consumes}, 'native capture/completion census or duplicate')
        returned = [e for e in rows(log, 's203 ', 'buffer_free') if e['source'] == 'NFQ_CAPTURED']
        need(Counter((e['thread'], e['buffer'], e['obligation']) for e in returned) ==
             Counter((e['thread'], e['buffer'], e['token']) for e in consumes), 'ordinary buffer not freed exactly once')
        decoded = {}
        for key, capture in cap.items():
            lane = lanes[capture['lane']]; send = operations[key]
            need(capture['generation'] == generation and all(capture[k] == lane[k] for k in ('thread', 'queue')) and
                 all(send[k] == lane[k] for k in ('generation', 'thread', 'queue', 'fd')) and
                 int(send['result']) >= 0 and send['errno'] == '0', 'native operation redirected or failed')
            try: facts = native.packet(capture['raw'])
            except AssertionError: continue  # Production INPUT may see unrelated device protocols.
            if facts['sport'] == 40642 or facts['dport'] == 40642: decoded[key] = facts
        native.cases(folder, record, cap, operations, decoded, endpoints)
        need({(e['lane'], e['owner_path']) for e in record['seeds']} ==
             {(lane, path) for lane in range(4) for path in ('local', 'remote')}, 'missing real app-owned dual-stack lane/owner coverage')
        assignments = placement.allrows(log, 's207 ')
        for key, facts in decoded.items():
            expected_owner = placement.assigned(facts)
            found = [e for e in assignments if e['stage'] == 'policy' and int(e['token']) == key[2]]
            need(len(found) == 1 and all(str(found[0][k]) == str(v) for k, v in expected_owner.items()) and
                 int(found[0]['thread']) == expected_owner['owner']+1, 'supervisor packet owner differs from CPU-independent oracle')
        zero = rows(log, 's242 ', 'stop_native_zero')
        need(len(zero) == 1 and zero[0]['generation'] == generation and all(zero[0][k] == '0' for k in
             ('ready_mask', 'graph_enabled', 'graph_accepting', 'pending', 'buffers', 'obligations', 'handoffs', 'completion_frames')), 'service native stop residue')
        retired, closed = rows(log, 's242 ', 'lane_retire'), rows(log, 's242 ', 'lane_closed')
        need([e['lane'] for e in closed] == ['3', '2', '1', '0'] and len(retired) == 4 and all(e['fd'] == '-1'
             and all(e[k] == '0' for k in ('pending', 'allocated', 'loans', 'listener', 'socket')) for e in closed), 'service lane cleanup order/residue')
        for e in retired:
            count = sum(s['lane'] == e['lane'] for s in sends)
            need(int(e['verdicts']) == int(e['settlements']) == int(e['returns']) == count, 'native trace truncated or retirement conservation failed')
        claims = [line for line in service.splitlines() if 's242 native_root_drain=true' in line
                  and re.search(r'\bgeneration='+generation+r'\b', line)]
        need(len(claims) == 1 and 'result=1 ' in claims[0] and
             int(re.search(r'elapsed_ms=(\d+)', claims[0])[1]) <= 3000, 'JNI drain did not complete in its bounded budget')
        stopped = props((folder/'stopped.properties').read_text())
        need(stopped['state'] == 'stopped' and stopped['mayBeActive'] == 'false' and stopped['pid'] == '-1'
             and not stopped['errorCode'] and props((folder/'cleanup.properties').read_text())['productRootNfqueueResidueClean'] == 'true', 'app stopped state or hook cleanup false')
        native.queue_state(folder, 'app-closed', 'pixel', set())
        need(native.clean_hooks((folder/'hooks-after.txt').read_text()) == native.clean_hooks((run/'hooks-before.txt').read_text()), 'production hook residue')
        if record['label'] == 'forward':
            for code in ('invalid_worker_cpu_ids', 'worker_placement_requires_restart'):
                errors = re.findall(r'^(\d+) .* error='+code+r'$', (folder/(code+'.log')).read_text(), re.M)
                need(any(int(stamp)*1000000 >= result['started_ns'] for stamp in errors), 'current request rejection missing')
                state = props((folder/(code+'.properties')).read_text())
                need(state['generation'] == generation and placement.affinity(folder, code, [0, *mapping], record['pid']) == tids,
                     'rejected request changed generation/OS placement')
                recovered = props((folder/(code+'-running.properties')).read_text())
                need(recovered['generation'] == generation and recovered['state'] == 'running' and
                     recovered['protectionRunning'] == 'true', 'rejected request stopped protection')
        reports.append(dict(case=record['label'], generation=record['generation'], worker_cpus=mapping,
            native_captures=len(cap), endpoint_packets=len(decoded), os_tids=tids, jni_stop_zero=True))
    final = props((run/'app-after.properties').read_text())
    need(final['state'] == 'stopped' and final['mayBeActive'] == 'false' and not final['errorCode'], 'final app not stopped')
    need(native.clean_hooks((run/'hooks-before.txt').read_text()) == native.clean_hooks((run/'hooks-after.txt').read_text()), 'final hook residue')
    addresses = lambda name: set(re.findall(r'inet6\s+(\S+)', (run/name).read_text()))
    need(addresses('addresses-before.txt') == addresses('addresses-after.txt'), 'endpoint address residue')
    return dict(status='PASS', scope=result['scope'], source_sha256=build['source_sha256'],
        result_sha256=digest(run/'result.json'), runs=reports, restored_selection=original,
        verifier_files={name: digest(ROOT/name) for name in ('tests/device/verify-s220-supervisor.py',
            'tests/device/verify-s220-worker-placement.py', 'tests/device/verify-s242-root-lifecycle.py', 'tests/device/s207-owner-oracle.py')},
        legacy_s187_labels_not_used=['owner_mapping', 'owner_mapping_seed', 'flow_pool_capacity', 'worker_cache_capacity'],
        readiness_expansion=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('run', type=Path); parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try: answer = verify(args.run.resolve())
    except (AssertionError, ValueError, KeyError, OSError, ET.ParseError) as error: answer = dict(status='HOLD', error=repr(error))
    if args.output: args.output.write_text(json.dumps(answer, indent=2)+'\n')
    print(json.dumps(answer, indent=2))
    if answer['status'] != 'PASS': raise SystemExit(1)
