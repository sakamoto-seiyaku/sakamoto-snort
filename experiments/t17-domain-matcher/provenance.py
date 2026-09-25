#!/usr/bin/env python3
"""Verify consumed upstream bytes against immutable archives; bind VPP stage."""
import argparse
import hashlib
import json
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DAT = '665edc5ec1639a81df004d4f92f07a73d5b96aba'
RAX = '05a9c29c62538519d870d6512978f80ac58a758f'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def closure(upstream, build, android):
    result = {'schema': 't17-source-closure-v1', 'files': {}, 'archives': {}}
    pins = {item['name']: item for item in json.loads(Path(__file__).with_name('sources.json').read_text())}
    specifications = [('libdatrie', DAT, 'datrie'), ('valkey', RAX, 'src')]
    for project, revision, folder in specifications:
        archive = upstream / (project + '.tar.gz')
        assert pins[project]['revision'] == revision, 'source revision mismatch'
        assert sha(archive.read_bytes()) == pins[project]['archive_sha256'], 'pinned archive digest mismatch'
        result['archives'][project] = {'revision': revision, 'sha256': sha(archive.read_bytes()),
                                     'url': f'https://codeload.github.com/{"tlwg/libdatrie" if project == "libdatrie" else "valkey-io/valkey"}/tar.gz/{revision}'}
        source = upstream / (project + '-' + revision) / folder
        paths = sorted(source.glob('*.[ch]')) if project == 'libdatrie' else [source / 'rax.c', source / 'rax.h']
        with tarfile.open(archive) as contents:
            for path in paths:
                name = str(path.relative_to(upstream))
                expected = contents.extractfile(name).read()
                assert path.read_bytes() == expected, 'extracted upstream differs: ' + name
                result['files'][str(path.resolve())] = sha(expected)
                if project == 'valkey':
                    copied = build / path.name
                    assert copied.read_bytes() == expected, 'compiled rax copy differs'
                    result['files'][str(copied.resolve())] = sha(expected)
    stage = ROOT / 'build-output/s220-20260913'
    if android:
        prefix = stage / 'android-stage-b'
        lib = prefix / 'lib/libvppinfra.so'
        manifest = prefix / 'android-vpp-stage.properties'
    else:
        prefix = stage / 'host-stage-b/source/build-root/install-vpp-native/vpp'
        lib = prefix / 'lib/x86_64-linux-gnu/libvppinfra.so'
        manifest = stage / 'host-stage-b/host-vpp-stage.properties'
    for path in sorted((prefix / 'include/vppinfra').rglob('*')) + [lib, manifest]:
        if path.is_file():
            result['files'][str(path.resolve())] = sha(path.read_bytes())
    result['closure_sha256'] = sha(json.dumps(result['files'], sort_keys=True).encode())
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('upstream', type=Path)
    p.add_argument('build', type=Path)
    p.add_argument('--android', action='store_true')
    args = p.parse_args()
    print(json.dumps(closure(args.upstream, args.build, args.android), indent=2))
