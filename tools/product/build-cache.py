#!/usr/bin/env python3
"""Prepare an owned compilation cache, independent of distribution paths."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

SCHEMA = 'sakamoto-product-build-cache/v1'
FLAGS = ('CC', 'CXX', 'AR', 'CFLAGS', 'CXXFLAGS', 'LDFLAGS', 'RUSTC', 'RUSTC_WRAPPER',
         'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS')


def real_directory(path):
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise ValueError('cache path must be a real directory: ' + str(path))
    path.mkdir(exist_ok=True)
    if path.stat().st_uid != os.getuid():
        raise ValueError('cache directory is owned by another user: ' + str(path))


def owned_file(path, content):
    try:
        with path.open('xb') as stream:
            stream.write(content)
    except FileExistsError:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError('cache metadata is not an owned regular file: ' + str(path))
        if path.read_bytes() != content:
            raise ValueError('cache metadata mismatch: ' + str(path))


def prepare(repo_root, namespace, destination, fields, files):
    repo_root = repo_root.resolve(strict=True)
    build_output = repo_root / 'build-output'
    real_directory(build_output)
    raw = Path(os.environ.get('SAKAMOTO_PRODUCT_BUILD_CACHE_DIR', str(build_output / 'product-build-cache')))
    if not raw.is_absolute() or '..' in raw.parts:
        raise ValueError('build cache must be an absolute path below this checkout build-output')
    try:
        relative = raw.relative_to(build_output)
    except ValueError:
        raise ValueError('build cache must stay below ' + str(build_output)) from None
    if not relative.parts:
        raise ValueError('build-output itself cannot be the compilation cache')
    # Check the lexical path before resolve: a symlink must never be hidden by
    # canonicalization, including a link in an intermediate directory.
    current = build_output
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError('build cache path contains a symlink: ' + str(current))
    destination = destination.resolve()
    if raw == destination or raw in destination.parents or destination in raw.parents:
        raise ValueError('compilation cache and distribution must not overlap')
    inputs = {}
    for field in fields:
        key, separator, value = field.partition('=')
        if not separator or not key or key in inputs:
            raise ValueError('cache inputs need unique name=value fields')
        inputs[key] = value
    for field in files:
        key, separator, name = field.partition('=')
        if not separator or not key or key in inputs:
            raise ValueError('cache file inputs need unique name=path fields')
        path = Path(name).resolve(strict=True)
        inputs[key] = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    identity = {'schema': SCHEMA, 'checkout': str(repo_root), 'namespace': namespace,
                'inputs': inputs, 'compiler_environment': {key: os.environ.get(key, '') for key in FLAGS}}
    encoded = (json.dumps(identity, sort_keys=True, separators=(',', ':')) + '\n').encode()
    key = hashlib.sha256(encoded).hexdigest()
    # Serialize initial ownership/metadata publication as well as the later
    # shell compilation lock, including two simultaneous first builds.
    fd = os.open(build_output / '.product-build-cache-init.lock',
                 os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+') as initialization_lock:
        info = os.fstat(initialization_lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError('cache initialization lock is not owned')
        fcntl.flock(initialization_lock, fcntl.LOCK_EX)
        return initialize(raw, relative, build_output, namespace, key, encoded)


def initialize(raw, relative, build_output, namespace, key, encoded):
    for index, _ in enumerate(relative.parts):
        parent = build_output.joinpath(*relative.parts[:index + 1])
        # Parents may already contain other owned caches; only the chosen leaf
        # needs the cache marker and may not adopt unrelated existing contents.
        if parent == raw and parent.exists() and not (parent / '.sakamoto-product-build-cache').exists():
            if any(parent.iterdir()):
                raise ValueError('refusing to adopt an unowned build cache: ' + str(parent))
        real_directory(parent)
    owned_file(raw / '.sakamoto-product-build-cache', (SCHEMA + '\n').encode())
    profile = raw / namespace
    real_directory(profile)
    cache = profile / key
    real_directory(cache)
    owned_file(cache / 'build-inputs.json', encoded)
    lock = cache / '.build.lock'
    if lock.exists() or lock.is_symlink():
        info = lock.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError('cache lock is not an owned regular file')
    return cache


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, required=True)
    parser.add_argument('--namespace', choices=('android', 'host', 'apk'), required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--input', action='append', default=[])
    parser.add_argument('--file', action='append', default=[])
    args = parser.parse_args()
    try:
        print(prepare(args.repo_root, args.namespace, args.destination, args.input, args.file))
    except (ValueError, OSError) as error:
        print('Product build cache: ' + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
