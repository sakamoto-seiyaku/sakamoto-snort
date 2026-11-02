#!/usr/bin/env python3
"""Retain compact historical results and recoverable sources; reclaim old output.

Preview is the default. --finished selects a verified, settled task directory;
--before selects historical top-level outputs. --keep protects exact inputs.
"""
import argparse
import collections
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import time
import zipfile

from output_storage import prune_store

SOURCE_SUFFIXES = {'.c', '.h', '.cc', '.cpp', '.hpp', '.rs', '.java', '.py', '.sh',
                   '.ps1', '.toml', '.lock', '.cmake', '.patch', '.diff', '.api',
                   '.inc', '.mk', '.gradle', '.kt', '.yml', '.yaml'}
SOURCE_NAMES = {'CMakeLists.txt', 'Makefile', 'Cargo.lock', 'Cargo.toml'}
GENERATED = {'.git', '__pycache__', 'CMakeFiles', 'cargo-target', 'target',
             'node_modules', 'build-root', 'build-output', '.ccache'}
PAYLOAD_KEYS = {'stdout', 'stderr', 'stdout_base64', 'stderr_base64', 'raw',
                'raw_text', 'raw_hex', 'request_hex', 'reply_hex', 'wire_hex',
                'query_hex', 'response_hex', 'packet_hex', 'recent', 'messages'}
RECORD_NAME = re.compile(r'(?:^|[-_])(result|verification|summary|manifest|protocol|receipt)(?:[-_.]|$)')


def write_json(path, value):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.retain-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def compact(value, depth=0):
    """Keep conclusions and scalar measurements, not repeated raw payloads."""
    if isinstance(value, str):
        return value if len(value) <= 1024 else {'prefix': value[:512], 'original_characters': len(value)}
    if isinstance(value, dict):
        if depth >= 6:
            return {k: compact(v, depth + 1) for k, v in value.items()
                    if not isinstance(v, (list, dict)) and k not in PAYLOAD_KEYS}
        return {k: ({'omitted_items': len(v)} if isinstance(v, (dict, list, str)) else None)
                if k in PAYLOAD_KEYS else compact(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        if depth >= 6:
            return {'omitted_items': len(value)}
        return [compact(v, depth + 1) for v in value]
    return value


def inside(path, parent):
    return path == parent or parent in path.parents


def protected_path(path, keep):
    return path in keep or any(parent in keep for parent in path.parents)


def cache_inputs(build_output):
    """Keep cache dependencies at their existing absolute paths."""
    keep = {build_output / 'product-build-cache', build_output / 'product-published',
            build_output / 'storage-retained', build_output / '.product-build-cache-init.lock',
            build_output / '.product-published.lock'}
    for name in ('host-tests', 'host-tests-asan', 'host-hev-tests',
                 'device-fixture-cache', 'benchmark-tool-cache'):
        if (build_output / name).is_dir():
            keep.add(build_output / name)
    for root in build_output.iterdir():
        if root.name.endswith('.lock') and root.is_file() and not root.is_symlink():
            keep.add(root)
        if root.is_dir() and not root.is_symlink() and (root / '.sakamoto-product-build-cache').is_file():
            keep.add(root)
    def retain(value):
        if isinstance(value, str) and value.startswith(str(build_output) + '/'):
            path = Path(value)
            if path.exists() and not path.is_symlink():
                keep.add(path)
        elif isinstance(value, dict):
            for item in value.values():
                retain(item)
        elif isinstance(value, list):
            for item in value:
                retain(item)
    caches = [p for p in keep if p.is_dir() and (p / '.sakamoto-product-build-cache').is_file()]
    for cache in caches:
        for base, dirs, files in os.walk(cache):
            for name in files:
                path = Path(base) / name
                if name == 'build-inputs.json':
                    retain(json.loads(path.read_text()).get('inputs', {}))
                elif name == 'CMakeCache.txt':
                    for line in path.read_text(errors='replace').splitlines():
                        if not line.startswith(('#', '//')) and '=' in line:
                            for value in line.split('=', 1)[1].split(';'):
                                retain(value)
    return {path for path in keep if not any(parent in keep for parent in path.parents)}


def source_file(relative, bundle=False):
    path = PurePosixPath(relative)
    if any(p in GENERATED for p in path.parts[:-1]):
        return False
    witness = bundle or any(p == 'source' or p.startswith(('source-snapshot', 'source_snapshot'))
                            for p in path.parts[:-1])
    compiled = path.suffix in {'.o', '.a', '.so', '.apk', '.class', '.dex', '.rlib', '.rmeta'}
    return (path.suffix in SOURCE_SUFFIXES or path.name in SOURCE_NAMES
            or (witness and not compiled and '.so.' not in path.name))


def inventory(root, keep, cutoff=None):
    """The same snapshot is rechecked before each removal."""
    files, skipped = [], collections.Counter()
    if protected_path(root, keep):
        return files, collections.Counter(protected_paths=1)
    stack = [root]
    while stack:
        path = stack.pop()
        if path in keep:
            skipped['protected_paths'] += 1
            continue
        try:
            info = path.lstat()
        except FileNotFoundError:
            skipped['already_absent'] += 1
            continue
        # Tests can create packet/log files as nobody. Removing those needs
        # ownership of their writable parent, not ownership of the payload.
        foreign_file = (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)) and (
            path.parent.stat().st_uid == os.getuid() and os.access(path.parent, os.W_OK | os.X_OK))
        if info.st_uid != os.getuid() and not foreign_file:
            skipped['other_owner'] += 1
            continue
        if stat.S_ISDIR(info.st_mode):
            stack.extend(path.iterdir())
        elif stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            if cutoff is not None and info.st_mtime >= cutoff:
                skipped['newer_files'] += 1
            else:
                files.append((path, info))
        else:
            skipped['special_files'] += 1
    return files, skipped


def source_object(data, objects):
    key = hashlib.sha256(data).hexdigest()
    target = objects / key
    try:
        with target.open('xb') as stream:
            stream.write(data)
        target.chmod(0o444)
    except FileExistsError:
        if target.is_symlink() or target.stat().st_size != len(data):
            raise ValueError('retained source object is invalid: ' + str(target))
    return key


def retain_sources(path, relative, info, objects, stream):
    def save(name, data, mode):
        key = source_object(data, objects)
        stream.write(json.dumps({'path': name, 'object': key, 'mode': mode}) + '\n')
    if source_file(relative):
        if path.is_symlink():
            stream.write(json.dumps({'path': relative, 'link': os.readlink(path)}) + '\n')
        else:
            save(relative, path.read_bytes(), stat.S_IMODE(info.st_mode))
    elif path.suffix == '.zip':
        # Source bundles are frequent copies of the same dirty checkout. Save
        # source members by content, not another copy of the compressed bundle.
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                name = PurePosixPath(member.filename)
                if name.is_absolute() or '..' in name.parts:
                    raise ValueError('unsafe source bundle member: ' + member.filename)
                if not member.is_dir() and source_file(member.filename, bundle='source' in path.name):
                    save(relative + '.sources/' + member.filename, archive.read(member),
                         stat.S_IMODE(member.external_attr >> 16) or 0o644)


def retain_record(path, relative, stream):
    if path.suffix == '.json' and (RECORD_NAME.search(path.name)
                                  or path.name in ('build.json', 'source.json')
                                  or path.name.startswith(('prebuild-source', 'current-source',
                                                           'source-closure', 'frozen-tools'))):
        try:
            value = json.loads(path.read_bytes())
        except (ValueError, UnicodeError) as error:
            # Some historical Windows results include CMD diagnostics before
            # their JSON. Preserve the diagnostic text without inventing PASS.
            with path.open('rb') as data:
                text = data.read(65536)
            value = {'unparsed_result': text.decode(errors='replace'),
                     'original_bytes': path.stat().st_size, 'parse_error': str(error)}
        stream.write(json.dumps({'path': relative, 'record': compact(value)}, ensure_ascii=False) + '\n')
    elif path.suffix == '.log' and any(word in path.name for word in ('build', 'first', 'repeat', 'cold', 'warm', 'test')):
        with path.open('rb') as data:
            head = data.read(4096)
            data.seek(max(len(head), path.stat().st_size - 16384))
            tail = data.read()
        stream.write(json.dumps({'path': relative, 'original_bytes': path.stat().st_size,
                                'head': head.decode(errors='replace'), 'tail': tail.decode(errors='replace')}) + '\n')


def restore_sources(archive, destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    with (archive / 'sources.jsonl').open() as stream:
        for line in stream:
            item = json.loads(line)
            relative = PurePosixPath(item['path'])
            if relative.is_absolute() or '..' in relative.parts:
                raise ValueError('unsafe retained source path')
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if any(parent.is_symlink() for parent in target.parents if inside(parent, destination)):
                raise ValueError('source restore cannot traverse a symlink')
            if 'link' in item:
                target.symlink_to(item['link'])
            else:
                data = (archive.parent / 'source-objects' / item['object']).read_bytes()
                if hashlib.sha256(data).hexdigest() != item['object']:
                    raise ValueError('retained source content changed')
                target.write_bytes(data)
                target.chmod(item['mode'])


def cleanup_group(root, build_output, keep, cutoff, apply=False, archive_root=None):
    files, skipped = inventory(root, keep, cutoff)
    unique = {}
    for path, info in files:
        unique[(info.st_dev, info.st_ino)] = info.st_blocks * 512
    result = {'root': str(root), 'selected_files': len(files),
              'selected_inode_allocated_bytes': sum(unique.values()), 'skipped': dict(skipped)}
    if not apply or not files:
        return result
    relative_root = root.relative_to(build_output)
    archive = archive_root / ('--'.join(relative_root.parts) or 'root-files')
    archive.mkdir(exist_ok=True)
    previous = json.loads((archive / 'cleanup.json').read_text()) if (archive / 'cleanup.json').exists() else {}
    objects = archive_root / 'source-objects'
    objects.mkdir(exist_ok=True)
    removed, errors = 0, []
    # Write archive indexes before removing their corresponding source.
    with (archive / 'sources.jsonl').open('a') as sources, (archive / 'records.jsonl').open('a') as records:
        repositories = set()
        for path, _ in files:
            relative = path.relative_to(root) if root.is_dir() else Path(path.name)
            if '.git' in relative.parts:
                index = relative.parts.index('.git')
                repositories.add(root.joinpath(*relative.parts[:index]))
        for repository in sorted(repositories):
            revision = subprocess.run(['git', '-C', str(repository), 'rev-parse', 'HEAD'],
                                      capture_output=True, text=True)
            if revision.returncode:
                raise ValueError('cannot preserve historical Git revision: ' + str(repository))
            diff = subprocess.run(['git', '-C', str(repository), 'diff', '--binary', 'HEAD'],
                                  capture_output=True, check=True)
            records.write(json.dumps({'path': str(repository.relative_to(root)),
                                      'commit': revision.stdout.strip(),
                                      'dirty_diff_object': source_object(diff.stdout, objects)}) + '\n')
        records.flush()
        for path, before in files:
            try:
                now = path.lstat()
                if (now.st_dev, now.st_ino, now.st_size, now.st_mtime_ns) != (
                        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
                    raise ValueError('file changed since selection')
                relative = str(path.relative_to(root)) if root.is_dir() else path.name
                if stat.S_ISREG(now.st_mode) or stat.S_ISLNK(now.st_mode):
                    retain_sources(path, relative, now, objects, sources)
                    if stat.S_ISREG(now.st_mode):
                        retain_record(path, relative, records)
                sources.flush()
                records.flush()
                try:
                    path.unlink()
                except PermissionError:
                    parent = path.parent.stat()
                    if parent.st_uid != os.getuid() or parent.st_mode & stat.S_IWUSR:
                        raise
                    # Sealed historical directories can be read-only too.
                    # Change the owned directory, never a shared file inode.
                    path.parent.chmod(stat.S_IMODE(parent.st_mode) | stat.S_IWUSR)
                    path.unlink()
                removed += 1
            except (OSError, ValueError, zipfile.BadZipFile) as error:
                errors.append({'path': str(path), 'reason': str(error)})
    if root.is_dir():
        for base, dirs, _ in os.walk(root, topdown=False, followlinks=False):
            path = Path(base)
            if any(inside(path, protected) or inside(protected, path) for protected in keep):
                continue
            try:
                path.rmdir()
            except OSError:
                pass
    result.update(removed_files=previous.get('removed_files', 0) + removed,
                  removed_this_pass=removed, errors=errors, prior_errors=previous.get('errors', []),
                  source_index=str(archive / 'sources.jsonl'),
                  records=str(archive / 'records.jsonl'), raw_retained=bool(errors),
                  offline_reverification_available=False)
    write_json(archive / 'cleanup.json', result)
    return result


def allocated(path):
    result = subprocess.run(['du', '-sx', '-B1', str(path)], check=True, text=True, capture_output=True)
    return int(result.stdout.split()[0])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--before', type=datetime.date.fromisoformat)
    parser.add_argument('--finished', action='store_true', help='task verification and lifecycle cleanup have finished')
    parser.add_argument('--keep', action='append', default=[], type=Path)
    parser.add_argument('--keep-raw', action='store_true')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--restore-source', type=Path)
    parser.add_argument('--destination', type=Path)
    args = parser.parse_args()
    if args.restore_source:
        if not args.destination:
            parser.error('--restore-source requires --destination')
        restore_sources(args.restore_source, args.destination)
        return
    build_output = Path(__file__).resolve().parents[2] / 'build-output'
    root = (args.root or build_output).absolute()
    if root.is_symlink() or root.resolve() != root or not inside(root, build_output):
        parser.error('cleanup root must be a real directory below this checkout build-output')
    if not args.before and not (args.finished and root != build_output):
        parser.error('use --before for historical output or --finished for a settled task directory')
    keep = cache_inputs(build_output)
    for path in args.keep:
        path = path.absolute()
        if not inside(path, build_output) or path.is_symlink():
            parser.error('--keep must name an owned input below build-output')
        keep.add(path)
    cutoff = time.mktime(args.before.timetuple()) if args.before else None
    roots = list(root.iterdir()) if root == build_output else [root]
    roots = [p for p in roots if not any(inside(p, protected) for protected in keep)
             and (cutoff is None or p.lstat().st_mtime < cutoff)]
    report = {'mode': 'apply' if args.apply else 'preview', 'keep_raw': args.keep_raw,
              'protected_paths': sorted(map(str, keep)), 'groups': []}
    if args.keep_raw:
        print(json.dumps(report, indent=2))
        return
    before_bytes = allocated(build_output)
    archive_root = build_output / 'storage-retained'
    if args.apply:
        archive_root.mkdir(exist_ok=True)
        if archive_root.is_symlink():
            parser.error('retained output must not be a symlink')
    for group in sorted(roots):
        result = cleanup_group(group, build_output, keep, cutoff, args.apply, archive_root)
        report['groups'].append(result)
        if args.apply and result.get('removed_files') and (
                result['selected_inode_allocated_bytes'] >= 128 * 1024 * 1024 or result.get('errors')):
            print(json.dumps({k: result[k] for k in ('root', 'removed_files', 'errors')}), flush=True)
    if args.apply:
        report['unreferenced_publication_bytes_removed'] = prune_store(build_output)
    report.update(before_allocated_bytes=before_bytes, after_allocated_bytes=allocated(build_output))
    report['allocated_bytes_released'] = report['before_allocated_bytes'] - report['after_allocated_bytes']
    if args.apply:
        write_json(archive_root / 'latest-cleanup.json', report)
    print(json.dumps(report if not args.apply else {k: v for k, v in report.items() if k != 'groups'}, indent=2))
    return int(any(group.get('errors') for group in report['groups']))


if __name__ == '__main__':
    raise SystemExit(main())
