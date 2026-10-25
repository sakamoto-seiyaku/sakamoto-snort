#!/usr/bin/env python3
"""Run the real native builder twice; require output-independent warm reuse."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


def compiled_files(cache):
    return {str(p.relative_to(cache)): dict(bytes=p.stat().st_size, mtime_ns=p.stat().st_mtime_ns,
                                               sha256=hashlib.sha256(p.read_bytes()).hexdigest())
            for p in cache.rglob('*') if p.is_file() and
            p.suffix in ('.o', '.a', '.rlib', '.rmeta', '.so')}


def native_files(stage):
    result = {}
    for path in sorted((stage / 'lib/arm64-v8a').iterdir()):
        result[path.name] = ('link:' + os.readlink(path) if path.is_symlink()
                             else hashlib.sha256(path.read_bytes()).hexdigest())
    return result


def observed_build(command, env, stream, clock_path):
    """Retain clock anomalies alongside the actual artifact reuse assertions."""
    samples = []
    with subprocess.Popen(command, cwd=ROOT, env=env,
                          stdout=stream, stderr=subprocess.STDOUT) as child:
        while True:
            samples.append(dict(realtime_ns=time.time_ns(), monotonic_ns=time.monotonic_ns()))
            if child.poll() is not None:
                break
            time.sleep(0.02)
    backwards = [dict(previous=a, current=b) for a, b in zip(samples, samples[1:])
                 if b['realtime_ns'] < a['realtime_ns'] or b['monotonic_ns'] < a['monotonic_ns']]
    clock_path.write_text(json.dumps(dict(samples=samples, backwards=backwards), indent=2) + '\n')
    return child.returncode, len(backwards)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, SAKAMOTO_ANDROID_VERSION_STATE_FILE=str(out / 'version-code'))
    records = []
    report = {'scope': 'Real Android native compilation reuse, not device/performance acceptance',
              'status': 'INCOMPLETE', 'records': records}
    try:
        first_artifacts = first_compiled = first_cache = None
        for label in ('first', 'repeat'):
            stage = out / ('stage-' + label)
            env['SAKAMOTO_ANDROID_PRODUCT_STAGE_DIR'] = str(stage)
            start = time.monotonic()
            log = out / (label + '.log')
            clock_path = out / ('clock-' + label + '.json')
            with log.open('w') as stream:
                returncode, clock_backwards = observed_build(
                    ['bash', str(ROOT / 'app/android-runtime/scripts/build-debug-apk.sh'), '--stage-only'],
                    env, stream, clock_path)
            raw = log.read_text()
            if returncode:
                raise RuntimeError(label + ' build failed; see ' + str(log))
            matches = re.findall(r'^buildCache=(.+)$', raw, re.M)
            if len(matches) != 1:
                raise RuntimeError('missing unambiguous build cache identity')
            cache = Path(matches[0])
            artifacts, compiled = native_files(stage), compiled_files(cache)
            compiled_path = out / ('compiled-files-' + label + '.json')
            compiled_path.write_text(json.dumps(compiled, indent=2) + '\n')
            if not compiled:
                raise RuntimeError('no real compiled artifacts were retained')
            record = dict(label=label, elapsed_seconds=time.monotonic() - start,
                          cache=str(cache), compiled_file_count=len(compiled),
                          compiled_files=str(compiled_path),
                          compiled_files_sha256=hashlib.sha256(compiled_path.read_bytes()).hexdigest(),
                          clock_evidence=str(clock_path),
                          clock_evidence_sha256=hashlib.sha256(clock_path.read_bytes()).hexdigest(),
                          clock_backwards_count=clock_backwards,
                          rust_compilations=len(re.findall(r'^\s*Compiling ', raw, re.M)),
                          ninja_build_actions=len(re.findall(r'^\[\d+/\d+\] (?:Building|Linking|Generating) ', raw, re.M)),
                          native_sha256=artifacts)
            records.append(record)
            if label == 'first':
                first_cache, first_compiled, first_artifacts = cache, compiled, artifacts
            else:
                assert cache == first_cache, 'distribution directory affected the cache identity'
                assert not record['rust_compilations'], 'warm build recompiled Rust crates'
                assert not record['ninja_build_actions'], 'warm build rebuilt native objects'
                assert compiled == first_compiled, 'warm build replaced/touched compiled artifacts'
                assert artifacts == first_artifacts, 'same inputs produced different native payload'
        report['status'] = 'PASS'
    except (AssertionError, OSError, RuntimeError) as error:
        report['error'] = str(error)
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report.get(key) for key in ('status', 'error', 'records')}, indent=2))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
