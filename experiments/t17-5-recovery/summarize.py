#!/usr/bin/env python3
"""Export full normal-run measurements; report medians separately."""
import argparse
import csv
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('evidence', type=Path)
    parser.add_argument('out', type=Path)
    args = parser.parse_args()
    rows = []
    for platform, directory in [('host', 'host-d-runs'), ('android-arm64', 'android-e-runs')]:
        data = json.loads((args.evidence / directory / 'index.json').read_text())
        verification = json.loads((args.evidence / directory / 'verification.json').read_text())
        assert verification['passed']
        for record in data['runs']:
            if record['mode'] == 'cost':
                rows.append({'platform': platform, 'workload': record['workload'],
                             'repeat': record['repeat'], **record['measurement']})
    with args.out.open('w', newline='') as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


if __name__ == '__main__':
    main()
