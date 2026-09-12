#!/usr/bin/env python3
"""Package pinned dependency licenses and file-specific copyright notices."""
import argparse
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'third_party/hev'
spec = importlib.util.spec_from_file_location('vendor', ROOT / 'tools/product/vendor-hev.py')
vendor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vendor)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((BASE / 'upstream-manifest.json').read_text())
    assert vendor.inventory(BASE / 'upstream') == manifest['upstream_files'], 'modified upstream export'
    sections = ['Sakamoto pinned HEV dependency notices\n'
                'The Product includes a modified HEV/lwIP fork. Original notices follow.\n'
                'Source and revision inventory: third_party/hev/upstream-manifest.json\n']
    for name in ['LICENSE', 'src/core/LICENSE', 'third-part/hev-task-system/LICENSE',
                 'third-part/lwip/LICENSE', 'third-part/yaml/License']:
        sections.append(f'=== {name} ===\n' + (BASE / 'upstream' / name).read_text())
    notices = {}
    for path in sorted((BASE / 'upstream').rglob('*')):
        if not path.is_file() or path.suffix not in {'.c', '.h', '.s', '.S'}:
            continue
        for comment in re.findall(r'/\*.*?\*/', path.read_text(errors='strict'), re.S):
            if 'copyright' in comment.lower():
                notices.setdefault(comment, []).append(str(path.relative_to(BASE / 'upstream')))
    for notice, paths in notices.items():
        sections.append('=== File-specific notice: ' + ', '.join(paths) + ' ===\n' + notice)
    args.output.write_text('\n\n'.join(sections) + '\n', encoding='utf-8')

if __name__ == '__main__':
    main()
