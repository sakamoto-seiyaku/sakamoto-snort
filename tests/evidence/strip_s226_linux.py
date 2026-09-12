#!/usr/bin/env python3
"""Derive a debug-stripped Linux artifact; prove every SHF_ALLOC byte unchanged.

The pinned VPP ELF-symbol reader copies debug sections at startup. Debug data
is not a runtime memory requirement. Keep the original build and its full
symbols, and bind a separate artifact, source closure, strip tool and audit.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def allocated_sections(path):
    data = Path(path).read_bytes()
    if data[:4] != b'\x7fELF': return None
    assert data[4:6] == b'\x02\x01', 'requires ELF64 little-endian'
    offset = struct.unpack_from('<Q', data, 40)[0]
    size, count, strings_index = struct.unpack_from('<HHH', data, 58)
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, offset+i*size) for i in range(count)]
    strings_section = sections[strings_index]
    strings = data[strings_section[4]:strings_section[4]+strings_section[5]]
    result = {}
    for name, kind, flags, address, start, length, *_ in sections:
        if not flags & 2: continue  # SHF_ALLOC, including zero-filled NOBITS.
        label = strings[name:].split(b'\0', 1)[0].decode()
        assert label not in result
        result[label] = dict(kind=kind, flags=flags, address=address, length=length,
            sha256=None if kind == 8 else hashlib.sha256(data[start:start+length]).hexdigest())
    assert result and '.text' in result
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--artifact', type=Path, required=True)
    args = parser.parse_args()
    original = args.build.resolve()
    output, artifact = args.output.resolve(), args.artifact.resolve()
    before = json.loads(original.read_text())
    assert not output.exists() and not artifact.exists()
    output.mkdir(parents=True)
    strip = Path(shutil.which('strip')).resolve()
    source_artifact = Path(before['artifact'])
    for name, expected in before['artifact_hashes'].items():
        assert digest(source_artifact/name) == expected
    shutil.copytree(source_artifact, artifact, symlinks=True,
                    ignore=shutil.ignore_patterns('plugin-build'))
    shutil.copytree(original.parent/'source', output/'source')
    shutil.copy2(original.parent/'dirty.diff', output/'dirty.diff')
    # Retain the auxiliary control client referenced by the original witness.
    shutil.copytree(original.parent/'control', output/'control')
    audit = []
    for path in sorted(artifact.rglob('*')):
        if not path.is_file() or path.is_symlink(): continue
        relative = path.relative_to(artifact).as_posix()
        sections = allocated_sections(path)
        if sections is None: continue
        old_hash, old_size = digest(path), path.stat().st_size
        subprocess.run([str(strip), '--strip-debug', str(path)], check=True)
        assert sections == allocated_sections(path), 'runtime sections changed: '+relative
        audit.append(dict(path=relative, before_sha256=old_hash, after_sha256=digest(path),
                          before_bytes=old_size, after_bytes=path.stat().st_size,
                          allocated_sections=sections))
    assert audit
    (output/'strip-audit.json').write_text(json.dumps(audit, indent=2)+'\n')
    result = copy.deepcopy(before)
    result.update(completed_ns=time.time_ns(), artifact=str(artifact),
        artifact_hashes={str(p.relative_to(artifact)): digest(p) for p in artifact.rglob('*') if p.is_file()},
        policy_client=str(output/'control/s230-policy'),
        debug_strip=dict(original_build=str(original), original_build_sha256=digest(original),
            strip_path=str(strip), strip_sha256=digest(strip), audit_sha256=digest(output/'strip-audit.json'),
            script_sha256=digest(__file__), operation='--strip-debug', all_allocated_sections_unchanged=True))
    relative = 'tests/evidence/strip_s226_linux.py'
    target = output/'source'/relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(__file__, target)
    result['build_inputs'][relative] = digest(__file__)
    (output/'build.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(dict(source_sha256=result['source_sha256'], stripped_elfs=len(audit),
                         artifact=str(artifact), runtime_sections_unchanged=True), indent=2))


if __name__ == '__main__':
    main()
