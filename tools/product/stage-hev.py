#!/usr/bin/env python3
"""Verify the offline HEV export and stage reviewed fork patches by content hash."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import os

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('vendor', ROOT/'tools/product/vendor-hev.py')
vendor = importlib.util.module_from_spec(spec); spec.loader.exec_module(vendor)
BASE = ROOT/'third_party/hev'
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def compile_source(snapshot, destination):
    """Reuse compiler paths while retaining the independently verified snapshot."""
    destination = destination.absolute()
    assert destination.parent == snapshot.parents[2], 'compile inputs must share the owned staging parent'
    assert destination.is_relative_to(ROOT/'build-output'), 'compile inputs must stay in Product build-output'
    for path in (destination, *destination.parents):
        assert not path.is_symlink(), 'compile input path contains a symlink'
    marker = destination/'compile-source.json'
    source = destination/'source'
    metadata = json.loads((snapshot.parent/'stage.json').read_text())
    wanted = metadata['files']
    if destination.exists():
        assert marker.is_file() and not marker.is_symlink(), 'refuse unowned compile inputs'
        prior = json.loads(marker.read_text())
        assert prior['schema'] == 'sakamoto-hev-compile/v1' and prior['checkout'] == str(ROOT)
        assert prior['files'] == vendor.inventory(source), 'owned compile input changed outside staging'
    else:
        destination.mkdir(parents=True, exist_ok=False)
        source.mkdir()
        prior = {'files': {}}
    previous = prior['files']
    for name in sorted(previous.keys()-wanted.keys(), reverse=True):
        (source/name).unlink()
    for name, identity in wanted.items():
        if previous.get(name) == identity:
            continue
        path = source/name
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name+'.sakamoto-stage-tmp')
        assert not temporary.exists() and not temporary.is_symlink()
        if identity['kind'] == 'symlink':
            temporary.symlink_to(identity['target'])
        else:
            # Changed bytes get a current mtime; copy2 could preserve an old
            # snapshot timestamp and hide this change from Ninja.
            shutil.copyfile(snapshot/name, temporary)
            shutil.copymode(snapshot/name, temporary)
        os.replace(temporary, path)
    assert vendor.inventory(source) == wanted, 'compiler input publication differs from frozen source'
    publication = dict(schema='sakamoto-hev-compile/v1', checkout=str(ROOT),
        snapshot=str(snapshot), snapshot_manifest_sha256=digest(snapshot.parent/'stage.json'), files=wanted)
    encoded = json.dumps(publication, indent=2)+'\n'
    if not marker.exists() or marker.read_text() != encoded:
        temporary = marker.with_suffix('.tmp')
        assert not temporary.is_symlink()
        temporary.write_text(encoded)
        os.replace(temporary, marker)
    return source

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--output-root', type=Path, required=True)
    parser.add_argument('--compile-root', type=Path)
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
    print(compile_source(stage/'source', a.compile_root) if a.compile_root else stage/'source')

if __name__ == '__main__': main()
