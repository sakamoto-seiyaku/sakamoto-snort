#!/usr/bin/env python3
"""Attribute real TCP no-progress rounds and session wall time from CLI snapshots."""
import argparse
import json
from pathlib import Path

import pixel_quick as quick


def delta(before, after, prefix, keys, fields):
    old = {tuple(row[k] for k in keys): row for row in quick.rows(before, prefix)}
    result = []
    for row in quick.rows(after, prefix):
        identity = tuple(row[k] for k in keys)
        prior = old.pop(identity)
        values = {k: int(row[k]) - int(prior[k]) for k in fields}
        if any(v < 0 for v in values.values()):
            raise ValueError(f"counter regressed: {prefix} {identity}")
        result.append({**dict(zip(keys, identity)), **values})
    if old:
        raise ValueError(f"snapshot lost rows: {prefix}")
    return result


def analyze(path):
    run = json.loads(path.read_text())
    if run['status'] != 'COMPLETE':
        raise ValueError('complete real-device window required')
    case, = run['cases']
    folder = path.parent / 'vpn-tcp-fixed'
    before, after = [(folder / (label + '-cli.txt')).read_text()
                     for label in ('before', 'after')]
    quick.validate_vpn_window(case['generation'], case['client'], before, after)
    quick.validate_vpn_stop((folder / 'native-stop.txt').read_text(), case['generation'])
    wakes = delta(before, after, 'flow_stack.tcp_wake ', ('owner', 'origin'), ('rounds', 'idle'))
    waits = delta(before, after, 'flow_stack.tcp_wait ', ('owner', 'reason'),
                  ('yields', 'wait_ns', 'ready_ns'))
    receive = delta(before, after, 'flow_stack.tcp_receive ', ('owner',),
                    ('rounds', 'read_calls', 'read_blocked', 'commits', 'bytes'))
    progress = delta(before, after, 'flow_stack.tcp_progress ', ('owner',), ('idle_rounds',))
    polls = delta(before, after, 'flow_stack.scheduler_io ', ('owner',), ('polls', 'events'))
    owners = []
    for owner in ('0', '1'):
        wake = [r for r in wakes if r['owner'] == owner]
        wait = [r for r in waits if r['owner'] == owner]
        rx, = [r for r in receive if r['owner'] == owner]
        p, = [r for r in progress if r['owner'] == owner]
        io, = [r for r in polls if r['owner'] == owner]
        if len(wake) != 8 or len(wait) != 7:
            raise ValueError('incomplete wait/wake vocabulary')
        if sum(r['rounds'] for r in wake) != rx['rounds']:
            raise ValueError('first-wake round accounting does not reconcile')
        if sum(r['idle'] for r in wake) != p['idle_rounds']:
            raise ValueError('first-wake idle accounting does not reconcile')
        if any(r['idle'] > r['rounds'] for r in wake):
            raise ValueError('idle rounds exceed all rounds')
        owners.append(dict(owner=owner, receive=rx, idle_rounds=p['idle_rounds'],
                           first_wake=wake, wait=wait, scheduler_io=io))
    gib = case['client']['bytes'] / 2**30
    return dict(run=str(path), generation=case['generation'], owners=owners,
                mbps=case['score']['delivered_mbps'], endpoint_gib=gib,
                cpu_seconds_per_gib=case['score']['cpu_seconds_per_delivered_gib'],
                polls_per_gib=sum(r['polls'] for r in polls) / gib,
                round_accounting_reconciles=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = dict(schema='vpn-task-waits/v1', windows=[analyze(p) for p in args.run], limits=[
        'Logical wait and ready durations sum session wall intervals; they are not worker CPU or off-CPU time.',
        'Open intervals are folded into each owner-published snapshot. CLI boundaries include setup/tail, unlike exact-window CPU samples.',
        'First wake is the event that changes WAITING to RUNNING; later notifications do not replace its origin.',
        'CONTINUE follows a round returning positive work. A subsequent empty round parks, rather than self-rescheduling without progress.',
        'Wait reasons are exclusive, prioritized memory, upload, inner ACK, upstream, EOF, other; runnable is separate.',
        'Wake origins and wait reasons are separate marginals, not a joint distribution or a per-connection latency trace.',
    ])
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('TCP round accounting reconciles:', len(result['windows']), 'windows')


if __name__ == '__main__':
    main()
