#!/usr/bin/env python3
"""Read retained VPN windows; distinguish work counts from elapsed time."""
import argparse
import hashlib
import json
from pathlib import Path

import pixel_quick


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def counters(before, after, prefix):
    old = {row.get('owner', ''): row for row in pixel_quick.rows(before, prefix)}
    result = {}
    for row in pixel_quick.rows(after, prefix):
        identity = row.get('owner', '')
        prior = old[identity]
        result[identity] = {
            key: int(value) - int(prior[key])
            for key, value in row.items()
            if key != 'owner' and value.isdigit() and prior.get(key, '').isdigit()
        }
    return result


def analyze(directory):
    folder = directory / 'vpn-tcp-fixed'
    result = json.loads((directory / 'result.json').read_text())
    if result['status'] != 'COMPLETE':
        raise ValueError(f'incomplete window: {directory}')
    case, = result['cases']
    pixel_quick.validate_vpn_stop((folder / 'native-stop.txt').read_text(), case['generation'])
    before, after = [(folder / f'{phase}-cli.txt').read_text() for phase in ('before', 'after')]
    tcp = counters(before, after, 'flow_stack.tcp_receive ')
    driver = counters(before, after, 'flow_stack.driver ')
    progress = counters(before, after, 'flow_stack.tcp_progress ')
    timing = counters(before, after, 'flow_stack.step_timing ')
    owners = []
    for owner, receive in tcp.items():
        d, p = driver[owner], progress[owner]
        owners.append(dict(
            owner=owner,
            receive_rounds=receive['rounds'],
            read_calls=receive['read_calls'],
            eagain_fraction=ratio(receive['read_blocked'], receive['read_calls']),
            bytes_per_nonblocked_read=ratio(receive['bytes'], receive['read_calls'] - receive['read_blocked']),
            bytes_per_receive_round=ratio(receive['bytes'], receive['rounds']),
            idle_rounds=p['idle_rounds'],
            ring_full_observations=p['ring_full'],
            sndbuf_full_observations=p['sndbuf_full'],
            pending_to_node_mean_ns=ratio(d['ready_delay_ns'], d['ready_samples']),
            pending_to_node_over_1ms_fraction=ratio(d['ready_over_1ms'], d['ready_samples']),
            step_wall_ns=timing.get(owner, {}).get('ns'),
            step_over_1ms=timing.get(owner, {}).get('over_1ms'),
        ))
    return dict(
        directory=str(directory), generation=case['generation'], owners=owners,
        primary=counters(before, after, 'primary.status ')[''],
        primary_rejection=counters(before, after, 'primary.rejection ').get(''),
        capture_io=counters(before, after, 'tun.capture_io ').get(''),
        capture_profile=pixel_quick.rows(after, 'tun.capture_io '),
        input_sha256={name: hashlib.sha256((folder / name).read_bytes()).hexdigest()
                      for name in ('before-cli.txt', 'after-cli.txt', 'native-stop.txt')},
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('windows', nargs='+', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = dict(
        schema='vpn-progress/v1', windows=[analyze(path) for path in args.windows],
        limits=[
            'CLI intervals include setup/background and are not tuple-filtered.',
            'ready_delay spans any pending schedule request to node entry, including input-triggered requests; it is not socket-ready latency.',
            'Round and capacity counters are entry observations, not fractions of wall time.',
            'Nonblocked reads may include EOF; bytes/read is a descriptive ratio, not a packet-size distribution.',
            'On-CPU profiles do not attribute off-CPU waiting or establish a throughput ceiling.',
        ],
    )
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(args.output)


if __name__ == '__main__':
    main()
