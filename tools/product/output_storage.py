#!/usr/bin/env python3
"""Share sealed publication files without linking to mutable compiler outputs."""
import argparse
import contextlib
import fcntl
import hashlib
import os
from pathlib import Path
import shutil
import stat
import tempfile


MARKER = '.sakamoto-product-published'


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def atomic_link(source, destination):
    """Replacement must never overwrite an inode shared by earlier witnesses."""
    destination = Path(destination)
    fd, temporary = tempfile.mkstemp(prefix='.publish-', dir=destination.parent)
    os.close(fd)
    os.unlink(temporary)
    try:
        os.link(source, temporary)
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)


@contextlib.contextmanager
def publication_store(build_output):
    build_output = Path(build_output).resolve(strict=True)
    store = build_output / 'product-published'
    if store.is_symlink():
        raise ValueError('publication store must not be a symlink')
    with (build_output / '.product-published.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if store.exists() and not (store / MARKER).is_file() and any(store.iterdir()):
            raise ValueError('refusing to adopt a nonempty publication directory')
        store.mkdir(exist_ok=True)
        if store.stat().st_uid != os.getuid():
            raise ValueError('publication store is not owned')
        marker = store / MARKER
        if not marker.exists():
            marker.write_text('sakamoto-product-published/v1\n')
        elif marker.is_symlink() or marker.read_text() != 'sakamoto-product-published/v1\n':
            raise ValueError('publication ownership marker mismatch')
        yield store


def publish_tree(directory, build_output):
    directory, build_output = Path(directory).absolute(), Path(build_output).resolve(strict=True)
    relative = directory.relative_to(build_output)
    if not relative.parts or relative.parts[0] in ('product-build-cache', 'product-published'):
        raise ValueError('publish a distribution, not the compilation cache or store')
    current = build_output
    for part in relative.parts:
        current /= part
        if part == '..' or current.is_symlink():
            raise ValueError('publication directory contains a symlink or parent traversal')
        if (current / '.sakamoto-product-build-cache').exists():
            raise ValueError('cannot seal a compilation cache')
    if not directory.is_dir():
        raise ValueError('publication directory does not exist')
    count = 0
    with publication_store(build_output) as store:
        for base, directories, files in os.walk(directory, followlinks=False):
            if any((Path(base) / name).is_symlink() for name in directories):
                raise ValueError('publication contains a linked directory')
            for name in files:
                path = Path(base) / name
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    path.resolve(strict=True).relative_to(directory)
                    continue
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                    raise ValueError('publication is not an owned regular file: ' + str(path))
                mode = stat.S_IMODE(info.st_mode) & ~0o222
                content = digest(path)
                sealed = store / (content + '-' + format(mode, 'o'))
                if not sealed.exists():
                    fd, temporary = tempfile.mkstemp(prefix='.seal-', dir=store)
                    os.close(fd)
                    try:
                        shutil.copyfile(path, temporary)
                        os.chmod(temporary, mode)
                        if digest(temporary) != content:
                            raise ValueError('publication source changed during copy')
                        os.replace(temporary, sealed)
                    finally:
                        Path(temporary).unlink(missing_ok=True)
                else:
                    saved = sealed.lstat()
                    if (not stat.S_ISREG(saved.st_mode) or saved.st_uid != os.getuid()
                            or stat.S_IMODE(saved.st_mode) != mode or digest(sealed) != content):
                        raise ValueError('sealed publication changed: ' + str(sealed))
                if not os.path.samefile(path, sealed):
                    atomic_link(sealed, path)
                count += 1
    return count


def prune_store(build_output):
    """Only canonical files with no remaining publication aliases are garbage."""
    released = 0
    if not (Path(build_output) / 'product-published').exists():
        return released
    with publication_store(build_output) as store:
        for path in store.iterdir():
            if path.name == MARKER:
                continue
            info = path.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1:
                released += info.st_blocks * 512
                path.unlink()
    return released


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    build_output = Path(__file__).resolve().parents[2] / 'build-output'
    print('publishedFiles=' + str(publish_tree(args.directory, build_output)))


if __name__ == '__main__':
    main()
