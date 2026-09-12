#!/usr/bin/env python3
"""Mutation tests against an immutable, successful S237 echo recording.

Tests verify_run only: historical recordings are not current-build acceptance.
The production CLI must still call verify_build, including current-source closure.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--run', type=Path, required=True)
    args = parser.parse_args()
    path = Path(__file__).resolve().parents[1] / 'device/verify-s237.py'
    spec = importlib.util.spec_from_file_location('verifier', path)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    build = json.loads(args.build.read_text())
    verifier.verify_run(args.build, build, args.run)
    trace = (args.run / 'native-stop.log').read_text().splitlines()
    first = lambda prefix: next(i for i, line in enumerate(trace) if line.startswith(prefix))
    copy = first('s237 event=return_copy ')
    admission = first('s216 stage=admit source=FLOW_STACK_RETURN ')
    policy = first('s216 stage=policy source=FLOW_STACK_RETURN ')
    terminal = first('s216 stage=terminal source=FLOW_STACK_RETURN ')
    completion = first('s213 event=completion source=FLOW_STACK_RETURN ')
    token = verifier.fields(trace[copy])['token']
    free = next(i for i, line in enumerate(trace)
                if line.startswith('s203 event=buffer_free ')
                and verifier.fields(line)['obligation'] == token)
    mutants = {}
    for name, index in [('missing-copy', copy), ('missing-completion', completion),
                        ('missing-buffer-free', free),
                        ('missing-pbuf-free', first('s237 event=pbuf_free '))]:
        mutants[name] = trace[:index] + trace[index + 1:]
    for name, left, right in [('terminal-before-policy', policy, terminal),
                               ('completion-before-terminal', terminal, completion),
                               ('free-before-completion', completion, free)]:
        changed = trace.copy()
        changed[left], changed[right] = changed[right], changed[left]
        mutants[name] = changed
    changed = trace.copy()
    changed.insert(copy, trace[copy])
    mutants['duplicate-copy'] = changed
    for key in ['thread', 'tls', 'generation']:
        changed = trace.copy()
        changed[copy] = re.sub(r'\b' + key + r'=\d+', key + '=999', changed[copy])
        mutants['wrong-' + key] = changed
    for label, index in [('admission', admission), ('policy', policy), ('terminal', terminal)]:
        for key in ['uid', 'availability', 'context', 'provenance', 'generation']:
            changed = trace.copy()
            changed[index] = re.sub(r'\b' + key + r'=\d+', key + '=999', changed[index])
            mutants[label + '-wrong-' + key] = changed
    failures = []
    with tempfile.TemporaryDirectory(prefix='s237-verifier-negative-') as temporary:
        directory = Path(temporary) / 'recording'
        shutil.copytree(args.run, directory)
        for name, changed in mutants.items():
            (directory / 'native-stop.log').write_text('\n'.join(changed) + '\n')
            try:
                verifier.verify_run(args.build, build, directory)
            except (AssertionError, KeyError, ValueError):
                print('REJECTED', name)
            else:
                failures.append(name)
                print('WRONGLY ACCEPTED', name)
        (directory / 'native-stop.log').write_text('\n'.join(trace) + '\n')
        after = (args.run / 'after.txt').read_text()
        for key in ['calls', 'bytes']:
            name = 'forged-copy-' + key
            changed = re.sub(r'(flow_stack\.copies [^\n]*\b' + key + r'=)\d+',
                             r'\g<1>999999', after)
            assert changed != after
            (directory / 'after.txt').write_text(changed)
            try:
                verifier.verify_run(args.build, build, directory)
            except AssertionError:
                print('REJECTED', name)
            else:
                failures.append(name)
                print('WRONGLY ACCEPTED', name)
    assert not failures, failures
    print('PASS: baseline accepted; all', len(mutants) + 2, 'mutations rejected')


if __name__ == '__main__':
    main()
