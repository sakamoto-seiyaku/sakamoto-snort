#!/usr/bin/env python3
"""Build real APKs twice, verify Java/DEX reuse and native payload preservation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--stage', required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    stage = args.stage.resolve(strict=True)
    env = dict(os.environ, SAKAMOTO_ANDROID_PRODUCT_STAGE_DIR=str(stage),
               SAKAMOTO_ANDROID_VERSION_STATE_FILE=str(out / 'version-code'))
    report = {'status': 'INCOMPLETE', 'records': []}
    try:
        first_cache = first_files = first_dex = None
        for label in ('first', 'repeat'):
            env['SAKAMOTO_ANDROID_APK_OUTPUT_DIR'] = str(out / label)
            log = out / (label + '.log')
            start = time.monotonic()
            with log.open('w') as stream:
                result = subprocess.run(['bash', str(ROOT / 'app/android-runtime/scripts/build-debug-apk.sh'),
                                         '--apk-only'], cwd=ROOT, env=env,
                                        stdout=stream, stderr=subprocess.STDOUT)
            assert result.returncode == 0, 'APK build failed: ' + str(log)
            raw = log.read_text()
            matches = re.findall(r'^buildCache=(.+)$', raw, re.M)
            assert len(matches) == 1, 'missing cache identity'
            cache = Path(matches[0])
            compiled = {str(p.relative_to(cache)): [p.stat().st_size, p.stat().st_mtime_ns]
                        for p in cache.rglob('*') if p.is_file() and p.suffix in ('.class', '.dex')}
            assert compiled, 'no retained Java/DEX outputs'
            apk = out / label / 'sakamoto-runtime-debug.apk'
            with zipfile.ZipFile(apk) as archive:
                dex = sha(archive.read('classes.dex'))
                for native in (stage / 'lib/arm64-v8a').iterdir():
                    assert sha(archive.read('lib/arm64-v8a/' + native.name)) == sha(native.read_bytes()), native.name
                assert not any('LambdaMetafactory' in n for n in archive.namelist()), 'compiler support was packaged'
            record = {'label': label, 'elapsed_seconds': time.monotonic() - start,
                      'cache': str(cache), 'compiled_file_count': len(compiled), 'dex_sha256': dex,
                      'bytecode_compilations': int('bytecodeCompile=javac+d8' in raw),
                      'apk_sha256': sha(apk.read_bytes())}
            report['records'].append(record)
            if label == 'first':
                first_cache, first_files, first_dex = cache, compiled, dex
            else:
                assert cache == first_cache, 'output path affected compilation cache'
                assert record['bytecode_compilations'] == 0, 'repeat invoked javac/D8'
                assert compiled == first_files, 'repeat replaced/touched bytecode outputs'
                assert dex == first_dex, 'DEX changed with identical sources'
        report['status'] = 'PASS'
    except (AssertionError, OSError, ValueError, zipfile.BadZipFile) as error:
        report['error'] = str(error)
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
