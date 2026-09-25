#!/usr/bin/env python3
"""Summarize retained raw measurements without dropping failed runs."""
import argparse
import csv
import json
import statistics
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('evidence', type=Path)
p.add_argument('out', type=Path)
args = p.parse_args()
rows = []
for platform, path in [('linux', 'host-b-runs'), ('android-arm64', 'android-c-runs-2')]:
    index = json.loads((args.evidence / path / 'index.json').read_text())
    for workload in sorted({r['workload'] for r in index['runs']}):
        for candidate in ('datrie', 'rax', 'vpp'):
            runs = [r for r in index['runs'] if r['workload'] == workload and r['candidate'] == candidate]
            valid = [r['measurement'] for r in runs if r.get('returncode') == 0]
            row = {'platform': platform, 'workload': workload, 'candidate': candidate,
                   'runs': len(runs), 'successful': len(valid)}
            if valid:
                metrics = {
                    'build_ms': [m['build_ns'] / 1e6 for m in valid],
                    'replacement_build_ms': [m['replacement_build_ns'] / 1e6 for m in valid],
                    'batch_ns_per_query': [m['batch_ns'] / m['batch_queries'] for m in valid],
                    'p50_ns': [m['p50_ns'] for m in valid],
                    'p95_ns': [m['p95_ns'] for m in valid],
                    'p99_ns': [m['p99_ns'] for m in valid],
                    'baseline_rss_mib': [m['baseline_rss_kib'] / 1024 for m in valid],
                    'input_rss_mib': [m['input_rss_kib'] / 1024 for m in valid],
                    'built_delta_mib': [(m['built_rss_kib'] - m['input_rss_kib']) / 1024 for m in valid],
                    'replacement_delta_mib': [(m['replacement_rss_kib'] - m['input_rss_kib']) / 1024 for m in valid],
                    'resident_delta_mib': [(m['resident_rss_kib'] - m['input_rss_kib']) / 1024 for m in valid],
                    'resident_total_mib': [m['resident_rss_kib'] / 1024 for m in valid],
                    'peak_total_mib': [m['peak_rss_kib'] / 1024 for m in valid],
                    'structure_bytes': [m['structure_bytes'] for m in valid],
                }
                for name, values in metrics.items():
                    row[name + '_median'] = round(statistics.median(values), 3)
                    row[name + '_min'] = round(min(values), 3)
                    row[name + '_max'] = round(max(values), 3)
            rows.append(row)
with args.out.open('w', newline='') as output:
    writer = csv.DictWriter(output, fieldnames=list(rows[0]), lineterminator='\n')
    writer.writeheader(); writer.writerows(rows)
print(len(rows), 'summary rows')
