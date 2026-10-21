#!/usr/bin/env python3
"""Validate Java/DEX cache contents while the caller holds its build-cache lock."""
import argparse
import hashlib
import json
from pathlib import Path
import sys


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(cache, sources, pipeline):
    inputs = {str(path.relative_to(sources)): digest(path)
              for path in sorted(sources.rglob('*.java')) if path.is_file()}
    classes = [path for path in sorted((cache / 'classes').rglob('*')) if path.is_file()]
    dex = sorted((cache / 'dex').glob('*'))
    if not inputs or not classes or dex != [cache / 'dex/classes.dex'] or not dex[0].is_file():
        raise ValueError('incomplete Java/DEX compilation outputs')
    return {'schema': 'sakamoto-apk-bytecode-cache/v1', 'pipeline': digest(pipeline),
            'sources': inputs,
            'outputs': {str(path.relative_to(cache)): digest(path) for path in [*classes, *dex]}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('check', 'record'))
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--sources', type=Path, required=True)
    parser.add_argument('--pipeline', type=Path, required=True)
    args = parser.parse_args()
    state_file = args.cache / 'bytecode-state.json'
    try:
        state = snapshot(args.cache, args.sources, args.pipeline)
        if args.operation == 'check':
            return 0 if json.loads(state_file.read_text()) == state else 1
        temporary = state_file.with_suffix('.tmp')
        temporary.write_text(json.dumps(state, sort_keys=True) + '\n')
        temporary.replace(state_file)
        return 0
    except (OSError, ValueError) as error:
        if args.operation == 'record':
            print('APK bytecode cache: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
