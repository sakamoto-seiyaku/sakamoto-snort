#!/usr/bin/env python3
"""The S298 verifier must reject broken bytes, identity, and progress evidence."""
import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('run', type=Path)
a = p.parse_args()
source = a.run.resolve()
verifier = Path(__file__).with_name('verify_s298_vpn_return.py')
assert (source / 'flood.txt').is_file(), 'use an S298 sustained-ingress run'

def reject(name, mutate):
    with tempfile.TemporaryDirectory(prefix='s298-negative-') as temporary:
        target = Path(temporary)
        for item in source.iterdir():
            (target / item.name).symlink_to(item)
        mutate(target)
        tested = subprocess.run([sys.executable, str(verifier), str(target)],
                                capture_output=True, text=True)
        assert tested.returncode != 0, name + ' was accepted'
        print(name + ': rejected')

def change_log(target, replacement):
    path = target / 'vpp.log'
    path.unlink()
    before = (source / 'vpp.log').read_text()
    after = replacement(before)
    assert after != before
    path.write_text(after)

def first_write(before, edit):
    lines = before.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.startswith('s298 event=write_wire '):
            lines[index] = edit(line)
            break
    else:
        raise AssertionError('missing write witness')
    return ''.join(lines)

reject('wrong-return-buffer', lambda target: change_log(target,
    lambda text: first_write(text, lambda line: re.sub(r'buffer=\d+', 'buffer=9999999', line, count=1))))
reject('wrong-return-bytes', lambda target: change_log(target,
    lambda text: first_write(text, lambda line: line.replace('raw=45', 'raw=46', 1))))
reject('missing-write', lambda target: change_log(target,
    lambda text: first_write(text, lambda line: '')))

def disjoint_flood(target):
    path = target / 'flood.txt'
    path.unlink()
    text = (source / 'flood.txt').read_text()
    ended = re.search(r'ended_ns=(\d+)', text).group(1)
    path.write_text(re.sub(r'started_ns=\d+', 'started_ns=' + ended, text))

reject('no-concurrent-ingress', disjoint_flood)
