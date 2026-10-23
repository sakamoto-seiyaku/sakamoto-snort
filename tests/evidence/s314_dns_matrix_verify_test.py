#!/usr/bin/env python3
"""Check immutable S314 raw evidence and reject forged packet-coverage facts.

Run with the retained eight-group VPN TCP Unknown run, its acceptance plan and
an output receipt. Mutations live in temporary symlink views; raw files are
never changed. This is an offline verifier regression, not a Device replay.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import traceback


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--verifier', type=Path,
                        default=Path(__file__).with_name('s314_dns_matrix_verify.py'))
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('matrix_verifier', args.verifier)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    args.run = args.run.resolve()
    receipt = dict(status='FAIL', verifier_sha256=digest(args.verifier),
                   test_sha256=digest(Path(__file__)), plan_sha256=digest(args.plan),
                   raw_source=str(args.run), negative_checks=[])
    raw_hashes = {path.name: digest(path) for path in args.run.iterdir() if path.is_file()}
    try:
        qualified = verifier.qualify(args.plan, [args.run])
        assert len(qualified['groups']) == 8
        generic = [group for group in qualified['groups'] if group['independent_generic_drop']]
        assert len(generic) == 4 and all(group['messages'] == 2 for group in generic)
        result = json.loads((args.run / 'result.json').read_text())
        case = next(case for case in result['cases'] if case['kind'] == 'unknown-generic-drop')
        observation_name = case['label'] + '-observation.json'
        observation = json.loads((args.run / observation_name).read_text())
        records = observation['consumer']['persistent']['dns']['recent']
        key = next(key for key, value in records.items()
                   if value['record']['generation'] == case['generation']
                   and value['record']['source_port'] == case['source_port']
                   and value['record']['coverage'] == 11
                   and value['record']['incarnation'] == 0)
        original = records[key]['record']
        variants = [
            ('forged-complete-message', dict(coverage=1)),
            ('forged-question', dict(id=1234, name='qname.test', qtype=1, qclass=1)),
            ('forged-message-ordinal', dict(message_sequence=1)),
            ('forged-response', dict(stage=2, direction=1, packet_direction=1)),
            ('forged-caller', dict(caller=1, availability=13)),
            ('forged-domain', dict(domain_available=True, domain_lists=1)),
            ('forged-correlation', dict(correlation=1, query_token=1)),
            ('stale-query-policy', dict(query_policy_generation=case['generation'] - 1,
                                       query_policy_revision=1, query_policy_hash=1, query_winner=1)),
            ('forged-query-incarnation', dict(query_incarnation=1)),
            ('forged-session', dict(transport_session=1, underlay_epoch=1)),
            ('forged-flow-slot', dict(slot=0)),
            ('forged-flow-incarnation', dict(incarnation=1)),
            ('coordinated-forged-flow', dict(incarnation=1, slot=0)),
            ('forged-response-code', dict(rcode=3)),
            ('missing-origin-token', dict(token=0)),
            ('wrong-current-packet-uid', dict(packet_uid=2001)),
            ('missing-current-packet-uid', dict(packet_uid=4294967295, packet_availability=4)),
            ('wrong-current-fact-uid', dict(uid=2001)),
            ('wrong-current-winner', dict(winner=0)),
            ('stale-current-policy', dict(policy_revision=original['policy_revision'] - 1)),
            ('wrong-current-snapshot', dict(policy_hash=original['policy_hash'] ^ 1)),
        ]
        for name, changes in variants:
            with tempfile.TemporaryDirectory(prefix='s314-verifier-') as temporary:
                view = Path(temporary)
                for source in args.run.iterdir():
                    (view / source.name).symlink_to(source, target_is_directory=source.is_dir())
                descriptor = dict(result, cases=[case])
                (view / 'result.json').unlink()
                (view / 'result.json').write_text(json.dumps(descriptor))
                forged = json.loads(json.dumps(observation))
                forged['consumer']['persistent']['dns']['recent'][key]['record'].update(changes)
                (view / observation_name).unlink()
                (view / observation_name).write_text(json.dumps(forged))
                rejected = False
                try:
                    verifier.qualify(args.plan, [view])
                except AssertionError:
                    rejected = True
                assert rejected, name + ' was accepted'
                receipt['negative_checks'].append(dict(name=name, status='REJECTED'))
        assert raw_hashes == {path.name: digest(path) for path in args.run.iterdir() if path.is_file()}
        receipt.update(status='PASS_IMMUTABLE_RAW_AND_FORGED_FACT_REJECTION',
                       positive_groups=8, generic_groups=4, raw_hashes=raw_hashes)
    except BaseException:
        receipt['error'] = traceback.format_exc()
        raise
    finally:
        args.output.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(dict(status=receipt['status'], positive_groups=8,
                          negative_checks=len(receipt['negative_checks']))))


if __name__ == '__main__':
    main()
