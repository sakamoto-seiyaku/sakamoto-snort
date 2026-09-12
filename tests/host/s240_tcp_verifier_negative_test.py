#!/usr/bin/env python3
"""Mutate copies of the actual TCP evidence; each boundary must reject them."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--ovs', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('tcp240', ROOT / 'tests/device/verify-s240-tcp.py')
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    assert verifier.verify(args.build, args.run, args.ovs)['status'] == 'PASS'
    path = 'normal/native-stop.log'
    original = (args.run / path).read_text()
    mutations = []

    def replace(name, pattern, replacement):
        changed, count = re.subn(pattern, replacement, original, count=1, flags=re.M)
        assert count == 1 and changed != original, 'mutation failed: ' + name
        mutations.append((name, path, changed))

    replace('wrong-owner-thread', r'(s237 event=output[^\n]*? thread=)2\b', r'\g<1>1')
    replace('wrong-pbuf-owner', r'(s237 event=pbuf_free[^\n]*? owner=)1\b', r'\g<1>0')
    replace('missing-native-free', r'^s203 event=buffer_free[^\n]*\n', '')
    replace('duplicate-native-free', r'(^s203 event=buffer_free[^\n]*\n)', r'\1\1')
    replace('missing-return-credit', r'^s239 event=return_credit_released[^\n]*\n', '')
    replace('credit-before-native-free', r'(s239 event=return_credit_released[^\n]*? after_native_free=)1', r'\g<1>0')
    replace('tcp-metadata-clobbered', r'(s216 stage=terminal[^\n]*? protocol=6[^\n]*? tcp_seq=)(\d+)',
            lambda m: m[1] + str((int(m[2]) + 1) & 0xffffffff))
    replace('wrong-ovs-window', r'(s222 event=tcp_update[^\n]*? orig_maxwin=)\d+', r'\g<1>0')
    replace('missing-tcp-update', r'^s222 event=tcp_update[^\n]*\n', '')
    replace('cross-generation', r'(s237 event=input_copy[^\n]*? generation=)\d+', r'\g<1>1')
    replace('forged-return-uid', r'(s237 event=return_copy[^\n]*? uid=)\d+', r'\g<1>0')
    replace('forged-return-epoch', r'(s237 event=return_copy[^\n]*? availability=5[^\n]*? epoch=)\d+', r'\g<1>0')
    replace('transport-replacement', r'(s237 event=output[^\n]*? session=)\d+', r'\g<1>9999')
    replace('unsettled-owner', r'(s237 event=owner_stopped[^\n]*? sessions=)0', r'\g<1>1')
    replace('wrong-protected-fd', r'(s237 event=session_closing[^\n]*? result=)\d+', r'\g<1>9999')
    replace('drop-wrote-to-tun', r'(s213 event=completion[^\n]*? policy_drop=1[^\n]*? transport_outcome=)NOT_ATTEMPTED',
            r'\g<1>TUN_WRITE_SUCCEEDED')
    replace('echo-connect-forged-reset', r'(s237 event=tcp_connect_ready[^\n]*? result=)0\b', r'\g<1>104')
    # Corrupt both raw witnesses, so matching capture/admit alone cannot pass.
    first = next(e for e in verifier.records(original) if e.get('stage') == 'admit'
                 and e['_prefix'] == 's216' and e.get('protocol') == '6')
    bad_raw = first['raw'][:-2] + ('00' if first['raw'][-2:] != '00' else '01')
    changed = original.replace('raw=' + first['raw'], 'raw=' + bad_raw)
    assert changed != original
    mutations.append(('consistent-raw-corruption-checksum', path, changed))
    broker_path = 'normal/broker.log'
    broker = (args.run / broker_path).read_text()
    generation = json.loads((args.run / 'result.json').read_text())['runs'][0]['generation']
    changed, count = re.subn(r'(s237 broker generation=' + str(generation) + r'[^\n]*? flags=)7',
                            r'\g<1>3', broker, count=1)
    assert count == 1
    mutations.append(('broker-did-not-bind', broker_path, changed))
    endpoint = (args.run / 'endpoint.log').read_text()
    changed, count = re.subn(r'^(event=read[^\n]*? raw=)[0-9a-f]{2}', r'\g<1>00', endpoint, count=1, flags=re.M)
    assert count == 1
    mutations.append(('kernel-peer-byte-mismatch', 'endpoint.log', changed))
    changed, count = re.subn(r'^event=server_reset connection=(\d+)$',
                            r'event=close connection=\1 received=0 sent=0', endpoint, count=1, flags=re.M)
    assert count == 1
    mutations.append(('missing-actual-peer-reset', 'endpoint.log', changed))
    report_path = 'normal/fin.json'
    report = json.loads((args.run / report_path).read_text())
    report['flows'][0]['echoes'] = 0
    mutations.append(('false-app-report', report_path, json.dumps(report)))
    rejected = []
    for name, relative, changed in mutations:
        with tempfile.TemporaryDirectory(prefix='s240-negative-') as temporary:
            directory = Path(temporary)
            target = Path(relative)

            def copy_level(source, destination, parts):
                for child in source.iterdir():
                    out = destination / child.name
                    if child.name != parts[0]:
                        out.symlink_to(child.resolve(), target_is_directory=child.is_dir())
                    elif len(parts) > 1:
                        out.mkdir()
                        copy_level(child, out, parts[1:])
                    else:
                        out.write_text(changed)

            copy_level(args.run, directory, target.parts)
            try:
                verifier.verify(args.build, directory, args.ovs)
            except AssertionError:
                rejected.append(name)
            else:
                raise AssertionError('accepted corruption: ' + name)
        print('PASS rejected ' + name, flush=True)
    print(json.dumps(dict(status='PASS', rejected=rejected, cases=len(rejected)), indent=2))


if __name__ == '__main__':
    main()
