#!/usr/bin/env python3
"""Reject independently falsified T08 witnesses; never mutate real evidence."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
import tempfile

spec = importlib.util.spec_from_file_location('t08_verify', Path(__file__).with_name('verify_t08_placement.py'))
verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)
parser = argparse.ArgumentParser(); parser.add_argument('directory', type=Path); parser.add_argument('--output')
args = parser.parse_args()
verifier.verify(args.directory)
rejected = []
faults = ['process', 'artifact', 'runtime_generation', 'winner', 'rank', 'mode', 'actual_action',
          'ct_fact', 'flow_direction', 'missing_observation', 'flow_identity', 'observation_count',
          'source_expression', 'query_winner', 'query_hits', 'endpoint', 'completion', 'cleanup',
          'placement', 'platform_witness', 'early_flow_touch', 'early_flow_query', 'early_timer_deadline']
for fault in faults:
    with tempfile.TemporaryDirectory(prefix='t08-negative-') as temporary:
        target = Path(temporary)/'run'
        shutil.copytree(args.directory, target, ignore=shutil.ignore_patterns('configuration', '*.png', '*.xml'))
        path = target/'result.json'; run = json.loads(path.read_text()); pixel = 'serial' in run
        trace = target/('root-stop.log' if pixel else 'first-vpp.log')
        text = trace.read_text()
        tokens=verifier.claimed_probe_tokens(text,run)
        def claimed(line):
            token=re.search(r'\btoken=(\d+)',line)
            return token and token.group(1) in tokens
        if fault == 'process':
            run['process_absent'] = False
        elif fault == 'artifact':
            run['build_sha256'] = '0'*64
        elif fault == 'runtime_generation':
            if pixel: run['lifetimes'][0]['generation'] += 1
            else: run['generation'] += 1
        elif fault in ('winner', 'rank', 'mode', 'actual_action', 'ct_fact', 'flow_direction'):
            line = next(line for line in text.splitlines() if line.startswith('s209 event=l4 ') and claimed(line) and 'actual_action=2 ' in line)
            key, value = {'winner': ('rule', 999), 'rank': ('rank', 9), 'mode': ('mode', 1),
                          'actual_action': ('actual_action', 1), 'ct_fact': ('ct_state', 1),
                          'flow_direction': ('flow_dir', 0)}[fault]
            altered = re.sub(r'\b'+key+r'=\d+', key+'='+str(value), line)
            assert altered != line
            text = text.replace(line, altered, 1)
        elif fault in ('missing_observation', 'observation_count'):
            line = next(line for line in text.splitlines() if line.startswith('s208 event=observe ') and claimed(line))
            altered = '' if fault == 'missing_observation' else re.sub(r'\bpackets=\d+', 'packets=999', line)
            text = text.replace(line, altered, 1)
        elif fault == 'flow_identity':
            line = next(line for line in text.splitlines() if line.startswith('s222 event=tcp_update ') and claimed(line))
            text = text.replace(line, re.sub(r'\bincarnation=\d+', 'incarnation=999', line), 1)
        elif fault == 'source_expression':
            source = target/run['configurations'][0]['source']; raw = bytearray(source.read_bytes())
            retained = struct.unpack_from('<I', raw, 20)[0]
            raw[24+8*retained+116+1] = 3
            source.write_bytes(raw)
        elif fault in ('query_winner', 'query_hits'):
            query = target/(run['cases'][0]['query'] if pixel else 'final-query.txt')
            key = ('winnerVersion' if pixel else 'query.winner_version') if fault == 'query_winner' else ('logicalHits' if pixel else 'query.logical_hits')
            value = '0' if fault == 'query_winner' else '999999'
            query.write_text('\n'.join(key+'='+value if line.startswith(key+'=') else line
                                       for line in query.read_text().splitlines())+'\n')
        elif fault == 'endpoint':
            endpoint = target/'endpoint.jsonl'; lines = endpoint.read_text().splitlines()
            index = next(i for i, line in enumerate(lines) if json.loads(line)['kind'] == 'tcp_recv')
            del lines[index]; endpoint.write_text('\n'.join(lines)+'\n')
        elif fault == 'completion':
            line = next(line for line in text.splitlines() if line.startswith('s242 event=verdict_syscall ') and claimed(line) and 'verdict=0 ' in line)
            text = text.replace(line, line.replace('verdict=0 ', 'verdict=1 '), 1)
        elif fault == 'cleanup':
            line = next(line for line in text.splitlines() if line.startswith('s242 event=stop_native_zero '))
            text = text.replace(line, line.replace('pending=0 ', 'pending=1 '), 1)
        elif fault == 'placement':
            lines = text.splitlines()
            index = next(i for i, line in enumerate(lines) if line.startswith('s209 event=l4 ') and claimed(line))
            line = lines.pop(index)
            index = next(i for i, line in enumerate(lines) if line.startswith('s208 event=observe ') and claimed(line))
            lines.insert(index, line); text = '\n'.join(lines)+'\n'
        elif fault in ('early_flow_query','early_timer_deadline'):
            query=target/('root-early-drop-blocked-flow.txt' if pixel else 'tcp-early-drop-blocked-flow.txt')
            field='last_seen' if fault=='early_flow_query' else 'deadline_us'
            query.write_text(re.sub(field+r'=\d+',field+'=999999999',query.read_text()))
        elif fault == 'early_flow_touch':
            match=next(line for line in text.splitlines() if line.startswith('s209 event=l4 ') and claimed(line) and 'actual_action=2 ' in line and 'position=1 ' in line)
            token=re.search(r'\btoken=(\d+)',match)[1]
            flow=next(line for line in text.splitlines() if line.startswith('s208 event=observe ') and claimed(line))
            flow=re.sub(r'\btoken=\d+','token='+token,flow)
            text+='\n'+flow+'\n'
        elif pixel:
            installed = target/'installed-native.txt'
            installed.write_text('0'*64+installed.read_text()[64:])
        else:
            publication = target/'race-session-publication.json'; value = json.loads(publication.read_text())
            value['completed_ns'] = 2**63; publication.write_text(json.dumps(value))
        path.write_text(json.dumps(run)); trace.write_text(text)
        try:
            verifier.verify(target)
        except (AssertionError, KeyError, ValueError, OSError, IndexError, StopIteration, struct.error):
            rejected.append(fault)
        else:
            raise AssertionError('falsified witness accepted: '+fault)
result = dict(status='PASS', platform='pixel' if pixel else 'linux', rejected=rejected,
              verifier_sha256=verifier.digest(verifier.__file__))
if args.output: Path(args.output).write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result, indent=2))
