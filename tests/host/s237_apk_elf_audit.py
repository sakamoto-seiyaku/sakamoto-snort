#!/usr/bin/env python3
"""Check hardening on the actual APK's arm64 ELF payload, not build flags."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    args = parser.parse_args()
    build = json.loads(args.build.read_text())
    apk_path = Path(build['apk'])
    assert hashlib.sha256(apk_path.read_bytes()).hexdigest() == build['apk_sha256']
    results = []
    with zipfile.ZipFile(apk_path) as apk, tempfile.TemporaryDirectory(prefix='s237-elf-') as temporary:
        entries = [name for name in apk.namelist()
                   if name.startswith('lib/arm64-v8a/') and name.endswith('.so')]
        assert {Path(name).name for name in entries} == set(build['native_sha256'])
        for name in entries:
            data = apk.read(name)
            basename = Path(name).name
            assert hashlib.sha256(data).hexdigest() == build['native_sha256'][basename]
            path = Path(temporary) / basename
            path.write_bytes(data)
            headers = subprocess.check_output(['readelf', '-lW', str(path)], text=True)
            dynamic = subprocess.check_output(['readelf', '-dW', str(path)], text=True)
            assert 'GNU_RELRO' in headers, basename + ': no RELRO'
            stack = [line for line in headers.splitlines() if 'GNU_STACK' in line]
            assert len(stack) == 1 and all('E' not in flag for flag in stack[0].split()[6:-1]), basename + ': executable stack'
            assert re.search(r'\b(BIND_NOW|NOW)\b', dynamic), basename + ': no immediate binding'
            assert 'TEXTREL' not in dynamic, basename + ': text relocations'
            results.append(dict(library=basename, relro=True, bind_now=True,
                                non_executable_stack=True, no_text_relocations=True))
    print(json.dumps(dict(status='PASS', apk_sha256=build['apk_sha256'], libraries=results), indent=2))


if __name__ == '__main__':
    main()
