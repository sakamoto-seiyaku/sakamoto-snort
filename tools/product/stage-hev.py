#!/usr/bin/env python3
"""Verify the offline HEV export and stage reviewed fork patches by content hash."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('vendor', ROOT/'tools/product/vendor-hev.py')
vendor = importlib.util.module_from_spec(spec); spec.loader.exec_module(vendor)
BASE = ROOT/'third_party/hev'
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--output-root', type=Path, required=True)
    a = parser.parse_args()
    upstream = json.loads((BASE/'upstream-manifest.json').read_text())
    files = vendor.inventory(BASE/'upstream')
    assert files == upstream['upstream_files'], 'HEV upstream export was modified'
    assert hashlib.sha256(vendor.encode(files)).hexdigest() == upstream['upstream_tree_sha256']
    assert digest(ROOT/'tools/product/vendor-hev.py') == upstream['export_tool_sha256']
    series = json.loads((BASE/'patches/series.json').read_text())
    inputs = {str(p.relative_to(ROOT)):digest(p) for p in BASE.rglob('*') if p.is_file()}
    for name in ('tools/product/vendor-hev.py', 'tools/product/stage-hev.py'):
        inputs[name] = digest(ROOT/name)
    identity = hashlib.sha256(vendor.encode(inputs)).hexdigest()
    stage = a.output_root.resolve()/identity
    marker = stage/'stage.json'
    if marker.exists():
        prior = json.loads(marker.read_text())
        assert prior['inputs'] == inputs and prior['files'] == vendor.inventory(stage/'source'), 'staged HEV source changed'
    else:
        stage.mkdir(parents=True, exist_ok=False)
        source = stage/'source'
        shutil.copytree(BASE/'upstream', source, symlinks=True)
        for patch in series:
            path = (BASE/'patches'/patch['file']).resolve()
            assert path.is_relative_to((BASE/'patches').resolve())
            # patch is repository-authored; restrict every target to the staged tree.
            for line in path.read_text().splitlines():
                if line.startswith(('--- ', '+++ ')):
                    target = line.split()[1]
                    assert target == '/dev/null' or (target.startswith(('a/', 'b/'))
                        and '..' not in Path(target).parts and not Path(target[2:]).is_absolute())
            subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1',
                '-d', str(source), '-i', str(path)], check=True, stdout=subprocess.PIPE)
        shutil.copytree(BASE/'product', source/'sakamoto', symlinks=True)
        staged_files = vendor.inventory(source)
        data = dict(schema='sakamoto-hev-fork/v1', inputs=inputs, files=staged_files,
            upstream_tree_sha256=upstream['upstream_tree_sha256'], input_sha256=identity,
            source_sha256=hashlib.sha256(vendor.encode(staged_files)).hexdigest())
        marker.write_text(json.dumps(data, indent=2)+'\n')
    print(stage/'source')

if __name__ == '__main__': main()
