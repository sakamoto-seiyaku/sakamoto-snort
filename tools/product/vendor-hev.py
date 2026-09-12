#!/usr/bin/env python3
"""Export audited, exact upstream Git objects; never copy a patched fixture tree.

This is an explicit dependency-maintenance operation, not a build-time fetch.
The destination must not exist. Ordinary Product builds consume offline vendor
files and the separately reviewed Product fork patches.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[2]
REPOSITORIES = [
    ('', 'heiher/hev-socks5-tunnel', '3911f79434d9a27c3ae4e6e07df5cefe2c3d5c70',
     ['LICENSE', 'README.md', '.gitmodules', 'Android.mk', 'Application.mk',
      'Makefile', 'build.mk', 'include', 'src', 'conf']),
    ('src/core', 'heiher/hev-socks5-core', 'ee0f24505d344f14b14624fa2249e6ccfaed138b',
     ['LICENSE', 'README.md', 'include', 'src']),
    ('third-part/hev-task-system', 'heiher/hev-task-system', 'b1afa0e21fb4ed5a69560e78e54baf0efdebe171',
     ['LICENSE', 'README.md', 'Android.mk', 'Application.mk', 'Makefile',
      'build.mk', 'configs.mk', 'include', 'src']),
    ('third-part/lwip', 'heiher/lwip', '8c69dfbe537835d5f2a5fd8c08c859f667b108ea',
     ['LICENSE', 'README.md', 'Android.mk', 'Application.mk', 'Makefile', 'build.mk', 'src']),
    ('third-part/yaml', 'heiher/yaml', 'efa36117a8646d26d12b58e05bac472d7854a70d',
     ['License', 'README.md', 'Android.mk', 'Application.mk', 'Makefile',
      'build.mk', 'configs.mk', 'include', 'src']),
]

def git(checkout, *arguments):
    return subprocess.check_output(['git', '-C', str(checkout), *arguments])

def inventory(root):
    files = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            target = str(path.readlink())
            if not path.resolve().is_relative_to(root.resolve()):
                raise ValueError('vendor symlink escapes source root: '+str(path))
            files[str(path.relative_to(root))] = dict(kind='symlink', target=target)
        elif path.is_file():
            files[str(path.relative_to(root))] = dict(kind='file',
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(), size=path.stat().st_size)
    return files

def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--checkout', type=Path, required=True)
    p.add_argument('--destination', type=Path, default=ROOT/'third_party/hev')
    a = p.parse_args(); a.checkout = a.checkout.resolve(); a.destination = a.destination.resolve()
    assert not a.destination.exists(), 'destination must be new; never overwrite a fork'
    repositories = []
    archives = []
    for relative, repository, revision, paths in REPOSITORIES:
        checkout = a.checkout/relative
        assert git(checkout, 'rev-parse', 'HEAD').decode().strip() == revision
        assert not git(checkout, 'status', '--porcelain'), 'patched/untracked fixture rejected: '+relative
        url = git(checkout, 'remote', 'get-url', 'origin').decode().strip()
        assert url.removesuffix('.git') == 'https://github.com/'+repository
        if relative:
            link = git(a.checkout, 'ls-tree', 'HEAD', relative).decode().split()
            assert link[:3] == ['160000', 'commit', revision], relative
        archive = git(checkout, 'archive', '--format=tar', revision, '--', *paths)
        archives.append((relative, archive))
        repositories.append(dict(path=relative, upstream=url, revision=revision,
            tree=git(checkout, 'rev-parse', revision+'^{tree}').decode().strip(),
            selected_paths=paths, archive_sha256=hashlib.sha256(archive).hexdigest()))
    upstream = a.destination/'upstream'; upstream.mkdir(parents=True)
    for relative, archive in archives:
        destination = upstream/relative; destination.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as members:
            members.extractall(destination, filter='data')
    files = inventory(upstream)
    manifest = dict(schema='sakamoto-hev-upstream/v1', repositories=repositories,
        upstream_files=files, upstream_tree_sha256=hashlib.sha256(encode(files)).hexdigest(),
        export_tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    (a.destination/'upstream-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(json.dumps(dict(files=len(files), upstream_tree_sha256=manifest['upstream_tree_sha256']), indent=2))

if __name__ == '__main__': main()
