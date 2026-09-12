#!/usr/bin/env python3
"""Corrupt independent copies of a passing S241 matrix; every mutation must fail."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('v241', ROOT / 'tests/device/verify-s241-capacity.py')
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--build', type=Path, required=True)
    p.add_argument('--run', type=Path, required=True)
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    baseline = v.verify(args.build, args.run)
    run = json.loads((args.run / 'result.json').read_text())

    def card(case):
        return next(c for c in run['runs'] if c['case'] == case)

    def trace_path(directory, case):
        return directory / card(case)['label'] / 'native-stop.log'

    def line_change(directory, case, predicate, transform):
        path = trace_path(directory, case)
        lines = path.read_text().splitlines()
        index = next(i for i, line in enumerate(lines) if predicate(line))
        replacement = transform(lines[index])
        lines[index:index + 1] = replacement
        path.write_text('\n'.join(lines) + '\n')

    def field(name, value):
        return lambda line: [re.sub(r'\b' + name + r'=[^\s]+', name + '=' + str(value), line)]

    def event(prefix):
        return lambda line: line.startswith(prefix)

    def mutate_result(directory):
        path = directory / 'result.json'
        data = json.loads(path.read_text())
        data['runs'][0]['probes'].pop()
        path.write_text(json.dumps(data))

    def mutate_app(directory):
        path = directory / card('session-capacity')['label'] / 'pressure.json'
        data = json.loads(path.read_text())
        index = 1 if card('session-capacity')['protocol'] == 'tcp' else 0
        data['flows'][index]['echoes'] = 1
        path.write_text(json.dumps(data))

    def mutate_health(directory):
        path = directory / card('session-capacity')['label'] / 'before-stop.txt'
        text = path.read_text()
        text, count = re.subn(r'(flow_stack.health owner=0 [^\n]*\bfailures=)[0-9]+', r'\g<1>0', text, count=1)
        assert count == 1
        path.write_text(text)

    def mutate_raw(directory):
        path = trace_path(directory, 'session-capacity')
        text = path.read_text()
        rows = v.records(text)
        first = next(e for e in rows if e['_prefix'] == 's216' and e.get('stage') == 'admit' and e.get('protocol') in ('6', '17'))
        raw = bytearray.fromhex(first['raw'])
        raw[-1] ^= 1
        assert text.count('raw=' + first['raw']) >= 2
        path.write_text(text.replace('raw=' + first['raw'], 'raw=' + raw.hex()))

    def graph_before_callback(directory):
        path = trace_path(directory, 'session-capacity')
        lines = path.read_text().splitlines()
        index = next(i for i, line in enumerate(lines) if line.startswith('s237 event=output '))
        output = lines[index]
        thread = re.search(r'\bthread=(\d+)', output).group(1)
        copy = next(line for line in reversed(lines[:index]) if line.startswith('s237 event=return_copy ') and f'thread={thread} ' in line)
        token = re.search(r'\btoken=(\d+)', copy).group(1)
        lines.pop(index)
        index = next(i for i, line in enumerate(lines) if line.startswith('s216 stage=admit ') and f'token={token} ' in line)
        lines.insert(index + 1, output)
        path.write_text('\n'.join(lines) + '\n')

    mutations = [
        ('missing-new-flow-recovery', mutate_result),
        ('false-app-echo', mutate_app),
        ('hidden-health-failure', mutate_health),
        ('corrupted-correlated-wire', mutate_raw),
        ('recursive-return-graph', graph_before_callback),
    ]
    definitions = [
        ('wrong-owner', 'session-capacity', 's237 event=input_copy ',
            lambda line: field('owner', 1 - int(re.search(r'\bowner=(\d+)', line).group(1)))(line)),
        ('wrong-callback-tls', 'session-capacity', 's237 event=input_copy ', field('tls', 99)),
        ('missing-native-free', 'session-capacity', 's203 event=buffer_free ', lambda line: []),
        ('duplicate-native-free', 'session-capacity', 's203 event=buffer_free ', lambda line: [line, line]),
        ('duplicate-completion', 'session-capacity', 's213 event=completion ', lambda line: [line, line]),
        ('wrong-pbuf-owner', 'session-capacity', 's237 event=pbuf_free ', field('owner', 9)),
        ('missing-pbuf-free', 'session-capacity', 's237 event=pbuf_free ', lambda line: []),
        ('missing-return-credit', 'session-capacity', 's239 event=return_credit_released ', lambda line: []),
        ('credit-before-native-free', 'session-capacity', 's239 event=return_credit_released ', field('after_native_free', 0)),
        ('mixed-generation', 'session-capacity', 's237 event=input_copy ', field('generation', 1)),
        ('forged-input-uid', 'session-capacity', 's216 stage=admit source=TUN_CAPTURED ', field('uid', 1)),
        ('changed-transport-session', 'session-capacity', 's237 event=output ', field('session', 999)),
        ('unreleased-pcb', 'session-capacity', 's237 event=pcbs_reclaimed ', field('bytes', 1)),
        ('unclosed-socket', 'session-capacity', 's237 event=owner_stopped ', field('sockets_closed', 0)),
        ('live-owner-at-stop', 'session-capacity', 's237 event=owner_stopped ', field('sessions', 1)),
        ('missing-failure-event', 'session-capacity', 's237 event=transport_failure ', lambda line: []),
        ('wrong-resource-failure-class', 'session-capacity', 's237 event=transport_failure ', field('kind', 3)),
        ('missing-input-handoff', 'session-capacity', 's237 event=input_copy ', lambda line: []),
        ('forged-return-epoch', 'session-capacity', 's237 event=return_copy ', field('epoch', 999)),
    ]
    for name, case, prefix, transform in definitions:
        mutations.append((name, lambda d, c=case, p=prefix, t=transform: line_change(d, c, event(p), t)))
    mutations.extend([
        ('bypass-forged-policy-allow', lambda d: line_change(d, 'flow-capacity',
            lambda l: l.startswith('s213 event=completion ') and 'intent=3 ' in l, field('policy_verdict', 'ALLOW'))),
        ('policy-drop-forwarded', lambda d: line_change(d, 'drop',
            lambda l: l.startswith('s213 event=completion ') and 'policy_drop=1 ' in l, field('transport_outcome', 'ADMITTED'))),
        ('failed-transport-as-policy-drop', lambda d: line_change(d, 'session-capacity',
            lambda l: l.startswith('s213 event=completion ') and 'transport_outcome=INPUT_REJECTED' in l,
            field('policy_verdict', 'DROP'))),
        ('protect-failure-as-success', lambda d: line_change(d, 'protect',
            lambda l: l.startswith('s237 event=broker_reply ') and 'success=0 ' in l, field('success', 1))),
        ('network-failure-as-refusal', lambda d: line_change(d, 'unreachable',
            event('s237 event=transport_failure '), field('kind', v.FAULTS.index('CONNECT_REFUSED')))),
    ])
    if any(c['protocol'] == 'tcp' for c in run['runs']):
        mutations.extend([
            ('live-output-forged-stateless', lambda d: line_change(d, 'session-capacity',
                event('s237 event=output '), field('session', 0))),
            ('stateless-rst-forged-session', lambda d: line_change(d, 'socket-capacity',
                lambda l: l.startswith('s237 event=output ') and 'session=0 ' in l,
                field('session', 999))),
        ])
    if all(c.get('completion_slots') == 2 for c in run['runs']):
        def remove_pressure(directory):
            path = trace_path(directory, 'drop')
            path.write_text('\n'.join(l for l in path.read_text().splitlines()
                                      if not l.startswith('s210 event=completion_deferred ')) + '\n')
        mutations = [('missing-actual-completion-pressure', remove_pressure)]
        for name, prefix, transform in (
            ('retained-drop-forged-allow', 's210 event=completion_deferred ', field('intent', 1)),
            ('wrong-retained-buffer', 's210 event=completion_deferred ', field('buffer', 0)),
            ('duplicate-retained-carrier', 's210 event=completion_deferred ', lambda line: [line, line]),
            ('wrong-completion-owner', 's205 event=completion_return_retry ', field('target_thread', 2)),
            ('missing-native-settlement', 's213 event=completion ', lambda line: []),
            ('missing-native-free', 's203 event=buffer_free ', lambda line: []),
        ):
            mutations.append((name, lambda d, p=prefix, t=transform: line_change(d, 'drop', event(p), t)))
    rejected = []
    with tempfile.TemporaryDirectory(prefix='s241-negative-') as temporary:
        for index, (name, mutate) in enumerate(mutations):
            directory = Path(temporary) / str(index)
            shutil.copytree(args.run, directory)
            mutate(directory)
            try:
                v.verify(args.build, directory)
            except (AssertionError, KeyError, ValueError, OSError) as error:
                rejected.append(dict(name=name, reason=str(error)))
            else:
                raise AssertionError('corrupted evidence passed: ' + name)
            shutil.rmtree(directory)
    result = dict(status='PASS', rejected=len(rejected), cases=rejected,
        baseline_verifier_sha256=baseline['verifier_sha256'], suite_sha256=v.tcp.digest(__file__))
    text = json.dumps(result, indent=2)
    if args.output: args.output.write_text(text + '\n')
    print(text)


if __name__ == '__main__':
    main()
