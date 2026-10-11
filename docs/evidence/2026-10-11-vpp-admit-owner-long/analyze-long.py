#!/usr/bin/env python3
"""Recompute the longer-window delivery comparisons from retained raw data."""
import argparse
import csv
import importlib.util
import json
from pathlib import Path
import statistics
import tarfile

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('quick', ROOT / 'tests/benchmark/pixel_quick.py')
quick = importlib.util.module_from_spec(spec)
spec.loader.exec_module(quick)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True, help='new output folder outside the frozen evidence')
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=False)
run = OUT / 'run-warmed'

def read_raw(cell, name):
    with tarfile.open(OUT / 'raw.tar.gz', 'r:gz') as archive:
        stream = archive.extractfile(str(Path('run-warmed') / cell / name))
        if stream is None: raise RuntimeError('missing raw record')
        return stream.read().decode()
raw = json.loads((run / 'result.json').read_text())
assert raw['status'] == 'COMPLETE' and len(raw['cases']) == 8 and not raw['errors'], raw['errors']
comparisons = {}
raw_rates = []
for case in raw['cases']:
    cell = run / case['cell']
    before, after = (read_raw(case['cell'], name) for name in ('before-cli.txt', 'after-cli.txt'))
    for field in ('node_calls', 'node_vectors', 'node_clocks', 'primary_calls', 'primary_packets', 'transferred', 'quads'):
        total = lambda text: sum(int(v.get(field, 0)) for v in quick.rows(text, 'admit.experiment.thread '))
        assert total(after) - total(before) == case['mechanism'][field], (case['cell'], field)
    tails = lambda text: sum(int(v['tail']) for v in quick.rows(text, 'admit.experiment.queue '))
    assert tails(after) - tails(before) == case['mechanism']['physical_queue_publications']
    cpu = quick.monitor_summary(read_raw(case['cell'], 'cpu.jsonl'), case['client'])
    assert cpu == case['cpu'], case['cell']
    quick.validate_capture_window(case['profile'], case['client'], before, after)
    failures = lambda text: sum(int(v['owner_failures']) for v in quick.rows(text, 'primary.status '))
    assert failures(after) == failures(before), case['cell']
    assert case['score']['flow_capacity_misses'] == 0
    case['flow_stack_delta'] = {k: sum(int(v.get(k, 0)) for v in quick.rows(after, 'flow_stack.status ')) -
                                     sum(int(v.get(k, 0)) for v in quick.rows(before, 'flow_stack.status '))
                               for k in ('admissions', 'rejected', 'sent', 'received', 'outputs', 'output_rejected')}
    def battery(name):
        data = dict(line.strip().split(':', 1) for line in read_raw(case['cell'], name).splitlines() if ':' in line)
        return float(data['temperature']) / 10 if 'temperature' in data else None
    case['battery_temperature_c'] = {'before': battery('battery-before.txt'), 'after': battery('battery-after.txt')}
    samples = [json.loads(line) for line in read_raw(case['cell'], 'peer-samples.jsonl').splitlines()]
    first = samples[0]['host_monotonic_ns']
    rates = []
    for a, b in zip(samples, samples[1:]):
        start, end = ((v['host_monotonic_ns'] - first) / 1e9 for v in (a, b))
        seconds = (b['host_monotonic_ns'] - a['host_monotonic_ns']) / 1e9
        rate = (b['peer']['udp_received_bytes'] - a['peer']['udp_received_bytes']) * 8 / seconds / 1e6
        values = {'profile': case['profile'], 'mode': case['mode'], 'index': case['index'], 'start_seconds': start,
                  'end_seconds': end, 'delivered_mbps': rate}
        raw_rates.append(values)
        if start >= 3 and end <= 28: rates.append(rate)
    assert len(rates) >= 20, case['cell']
    case['peer_steady_samples'] = {'count': len(rates), 'mean_mbps': statistics.mean(rates),
                                   'median_mbps': statistics.median(rates), 'min_mbps': min(rates), 'max_mbps': max(rates)}

for profile in ('root', 'vpn'):
    cells = [c for c in raw['cases'] if c['profile'] == profile]
    assert [c['mode'] for c in cells] == ['baseline', 'batch', 'batch', 'baseline']
    aggregate = {}
    for mode in ('baseline', 'batch'):
        group = [c for c in cells if c['mode'] == mode]
        seconds = sum(c['score']['elapsed_seconds'] for c in group)
        delivered = sum(c['peer']['udp_received_bytes'] for c in group)
        cpu = sum(c['score']['vpp_cpu_seconds_estimated_window'] for c in group)
        admitted = sum(c['mechanism']['node_vectors'] for c in group)
        rejected = sum(c['mechanism']['graph_primary_rejected'] for c in group)
        datagrams = sum(c['mechanism']['root_datagrams'] for c in group)
        bypass = sum(c['mechanism']['root_unadmitted_accepts'] for c in group)
        aggregate[mode] = {'seconds': seconds, 'delivered_bytes': delivered, 'vpp_cpu_seconds': cpu,
                            'delivered_mbps': delivered * 8 / seconds / 1e6,
                            'cpu_seconds_per_delivered_gib': cpu / (delivered / 2**30),
                            'admitted_pps': admitted / seconds, 'rejection_share': rejected / admitted,
                            'admit_clocks_per_vector': sum(c['mechanism']['node_clocks'] for c in group) / admitted,
                            'cpu_seconds_per_admitted_packet': cpu / admitted,
                            'remote_share': sum(c['mechanism']['primary_remote_eligible'] for c in group) / admitted,
                            'root_bypass_share': bypass / datagrams if datagrams else None,
                            'peer_cpu_percent_one_core_max': max(c['peer']['cpu_percent_one_core'] for c in group)}
    pairs = []
    for a, b in ((cells[0], cells[1]), (cells[3], cells[2])):
        pairs.append({'baseline_index': a['index'], 'batch_index': b['index'],
                      'delivered_mbps_change_percent': (b['score']['delivered_mbps'] / a['score']['delivered_mbps'] - 1) * 100,
                      'cpu_per_delivered_gib_change_percent': (b['score']['cpu_seconds_per_delivered_gib'] / a['score']['cpu_seconds_per_delivered_gib'] - 1) * 100})
    a, b = (aggregate[k] for k in ('baseline', 'batch'))
    changes = {k + '_change_percent': (b[k] / a[k] - 1) * 100 for k in
               ('delivered_mbps', 'cpu_seconds_per_delivered_gib', 'admitted_pps', 'admit_clocks_per_vector', 'cpu_seconds_per_admitted_packet')}
    changes['remote_share_difference_pp'] = abs(b['remote_share'] - a['remote_share']) * 100
    changes['rejection_share_increase_pp'] = (b['rejection_share'] - a['rejection_share']) * 100
    changes['root_bypass_share_increase_pp'] = (b['root_bypass_share'] - a['root_bypass_share']) * 100 if profile == 'root' else None
    comparability = changes['remote_share_difference_pp'] <= 5 and changes['rejection_share_increase_pp'] <= 3
    if profile == 'root': comparability = comparability and changes['root_bypass_share_increase_pp'] <= 3
    positive = all(p['delivered_mbps_change_percent'] >= 5 for p in pairs) and changes['delivered_mbps_change_percent'] >= 10 and changes['cpu_seconds_per_delivered_gib_change_percent'] <= -5 and comparability
    comparisons[profile] = {'aggregate': aggregate, 'pairs': pairs, 'changes': changes,
                             'screening_positive': positive, 'comparability': bool(comparability),
                             'cells': [{'cell': c['cell'], 'score': c['score'], 'mechanism': c['mechanism'],
                                        'flow_stack_delta': c['flow_stack_delta'], 'battery_temperature_c': c['battery_temperature_c'],
                                        'peer_steady_samples': c['peer_steady_samples']} for c in cells]}
result = {'status': 'COMPLETE', 'elapsed_seconds': raw['elapsed_seconds'], 'comparisons': comparisons,
          'raw_counter_cpu_capture_replay': 'PASS', 'limits': 'Two 30s windows per condition; full CPU utilization does not determine efficacy. Host receive samples are host-clock intervals, not precisely aligned phone receive windows.'}
(args.output / 'comparison.json').write_text(json.dumps(result, indent=2) + '\n')
with (args.output / 'peer-rates.csv').open('w') as stream:
    writer = csv.DictWriter(stream, fieldnames=raw_rates[0].keys(), lineterminator='\n')
    writer.writeheader()
    writer.writerows(raw_rates)
print(json.dumps({p: {'aggregate': v['aggregate'], 'pairs': v['pairs'], 'changes': v['changes'], 'screening_positive': v['screening_positive']} for p, v in comparisons.items()}, indent=2))
