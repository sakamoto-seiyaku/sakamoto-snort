#!/usr/bin/env python3
"""Offline regression for current public DNS stream selection in retained wire."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import traceback


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--label', default='n3-v4-public')
    parser.add_argument('--expected-port', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--runner', type=Path,
                        default=Path(__file__).parents[1] / 'device/s314-dns-milestone.py')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('milestone', args.runner)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    plan_path = args.run / (args.label + '-plan.json')
    client_path = args.run / (args.label + '-client.json')
    wire_path = args.run / (args.label + '-underlay.jsonl')
    inputs = {str(path): digest(path) for path in (plan_path, client_path, wire_path)}
    plan, client = json.loads(plan_path.read_text()), json.loads(client_path.read_text())
    wire = [json.loads(line) for line in wire_path.read_text().splitlines() if line.startswith('{')]
    requests, replies = plan['dnsTcpQueries'], [row['replyHex'] for row in client['dnsExchanges']]
    address, source = plan['endpoint'], args.expected_port
    receipt = dict(status='FAIL', runner_sha256=digest(args.runner), test_sha256=digest(Path(__file__)),
                   raw_inputs=inputs, expected_port=source, checks=[])

    def selected(row):
        return row.get('kind') == 'tcp' and (
            (row['destination'] == address and row['destination_port'] == 53 and row['source_port'] == source)
            or (row['source'] == address and row['source_port'] == 53 and row['destination_port'] == source))

    def accepts(name, packets):
        assert runner.public_source_port(packets, address, requests, replies) == source
        receipt['checks'].append(dict(name=name, status='PASS'))

    def rejects(name, packets, expected_replies=replies):
        rejected = False
        try:
            runner.public_source_port(packets, address, requests, expected_replies)
        except AssertionError:
            rejected = True
        assert rejected, name + ' was accepted'
        receipt['checks'].append(dict(name=name, status='REJECTED'))

    try:
        accepts('current-stream-with-historical-payload-port', wire)
        current = [row for row in wire if selected(row)]
        accepts('identical-retransmissions', wire + copy.deepcopy(current))
        foreign = copy.deepcopy(current)
        for row in foreign:
            if row['destination'] == address and row['destination_port'] == 53:
                row['destination'] = '192.0.2.53'
            else:
                row['source'] = '192.0.2.53'
            row['sequence'] ^= 0x80000000
        accepts('same-port-foreign-resolver-isolated-both-directions', wire + foreign)
        ambiguous = copy.deepcopy(current)
        for row in ambiguous:
            row['source_port' if row['destination'] == address else 'destination_port'] = 59999
        rejects('two-current-request-streams', wire + ambiguous)
        rejects('only-historical-stream-remains', [row for row in wire if not selected(row)])
        rejects('current-stream-without-handshake', [row for row in wire if not (selected(row) and row['flags'] & 2)])
        wrong_replies = list(replies)
        wrong_replies[0] = wrong_replies[0][:-2] + ('00' if wrong_replies[0][-2:] != '00' else '01')
        rejects('reply-does-not-match-app', wire, wrong_replies)
        assert all(digest(Path(path)) == value for path, value in inputs.items())
        receipt['status'] = 'PASS_CURRENT_STREAM_SELECTION_AND_NEGATIVE_GUARDS'
    except BaseException:
        receipt['error'] = traceback.format_exc()
        raise
    finally:
        args.output.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(dict(status=receipt['status'], checks=len(receipt['checks']))))


if __name__ == '__main__':
    main()
