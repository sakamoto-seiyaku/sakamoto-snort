#!/usr/bin/env python3
"""Build-cache isolation, output-independent reuse and writer serialization."""
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'tools/product/build-cache.py'
SHELL = ROOT / 'tools/product/build-cache.sh'


class BuildCacheTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix='product-build-cache-')
        self.repo = Path(self.folder.name) / 'repo'
        (self.repo / 'build-output').mkdir(parents=True)
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(('SAKAMOTO_PRODUCT_BUILD_CACHE', 'CARGO_TARGET_DIR'))}

    def tearDown(self):
        self.folder.cleanup()

    def prepare(self, destination='first-stage', namespace='android', toolchain='ndk29', check=True):
        return subprocess.run(['python3', str(HELPER), '--repo-root', str(self.repo),
                               '--namespace', namespace, '--destination', str(self.repo / destination),
                               '--input', 'toolchain=' + toolchain, '--input', 'abi=arm64-v8a'],
                              text=True, capture_output=True, env=self.env, check=check)

    def test_reuse_survives_new_distribution_and_keeps_intermediates(self):
        first = Path(self.prepare().stdout.strip())
        obj = first / 'product-plugin-build' / 'kept.o'
        obj.parent.mkdir()
        obj.write_bytes(b'compiled once')
        before = obj.stat().st_mtime_ns
        second = Path(self.prepare(destination='another-stage').stdout.strip())
        self.assertEqual(first, second)
        self.assertEqual(obj.read_bytes(), b'compiled once')
        self.assertEqual(obj.stat().st_mtime_ns, before)

    def test_toolchain_target_and_compiler_flags_are_isolated(self):
        original = self.prepare().stdout.strip()
        self.assertNotEqual(original, self.prepare(toolchain='ndk30').stdout.strip())
        self.assertNotEqual(original, self.prepare(namespace='host').stdout.strip())
        self.assertNotEqual(original, self.prepare(namespace='apk').stdout.strip())
        self.assertNotEqual(original, self.prepare(namespace='android-vpp').stdout.strip())
        self.env['CFLAGS'] = '-DANOTHER_BUILD=1'
        self.assertNotEqual(original, self.prepare().stdout.strip())

    def test_cache_cannot_escape_or_overlap_distribution(self):
        outside = Path(self.folder.name) / 'outside'
        self.env['SAKAMOTO_PRODUCT_BUILD_CACHE_DIR'] = str(outside)
        self.assertNotEqual(self.prepare(check=False).returncode, 0)
        self.assertFalse(outside.exists())
        cache = self.repo / 'build-output' / 'product-build-cache'
        self.env['SAKAMOTO_PRODUCT_BUILD_CACHE_DIR'] = str(cache)
        self.assertNotEqual(self.prepare(destination='build-output', check=False).returncode, 0)
        self.assertFalse(cache.exists())

    def test_symlinks_and_unowned_directories_are_rejected(self):
        cache = self.repo / 'build-output' / 'product-build-cache'
        outside = Path(self.folder.name) / 'outside'
        outside.mkdir()
        cache.symlink_to(outside, target_is_directory=True)
        self.assertNotEqual(self.prepare(check=False).returncode, 0)
        self.assertEqual(list(outside.iterdir()), [])
        cache.unlink()
        cache.mkdir()
        (cache / 'unrelated').write_text('keep')
        self.assertNotEqual(self.prepare(check=False).returncode, 0)
        self.assertEqual((cache / 'unrelated').read_text(), 'keep')

    def test_writers_for_the_same_compilation_cache_serialize(self):
        signal = self.repo / 'locked'
        body = ('source "$1"; repo_root="$2"; '
                'product_open_build_cache android "$3" --input toolchain=ndk29 --input abi=arm64-v8a; '
                'printf ready > "$4"; sleep "$5"')
        args = ['bash', '-eu', '-c', body, 'cache-test', str(SHELL), str(self.repo),
                str(self.repo / 'distribution'), str(signal)]
        first = subprocess.Popen([*args, '0.7'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        try:
            deadline = time.monotonic() + 5
            while not signal.exists() and first.poll() is None and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue(signal.exists(), first.communicate() if first.poll() is not None else 'no lock')
            start = time.monotonic()
            second = subprocess.run([*args, '0'], capture_output=True, env=self.env, check=True)
            self.assertGreater(time.monotonic() - start, .4)
            first.communicate(timeout=5)
            self.assertEqual(first.returncode, 0)
        finally:
            if first.poll() is None:
                first.terminate()
                first.communicate()

    def test_real_ninja_reuses_objects_and_invalidates_options_or_headers(self):
        source = self.repo / 'tiny'
        source.mkdir()
        (source / 'CMakeLists.txt').write_text('''cmake_minimum_required(VERSION 3.18)
project(cache_test C)
add_library(example STATIC example.c)
target_compile_definitions(example PRIVATE VALUE=${VALUE})
''')
        (source / 'value.h').write_text('#define HEADER_VALUE 1\n')
        (source / 'example.c').write_text('#include "value.h"\nint value(void){return VALUE+HEADER_VALUE;}\n')
        cache = Path(self.prepare().stdout.strip()) / 'tiny-build'
        body = ('source "$1"; product_configure_cached "$3" '
                '-S "$2" -B "$3" -G Ninja "-DVALUE=$4"; cmake --build "$3"')
        args = ['bash', '-eu', '-c', body, 'configure-test', str(SHELL), str(source), str(cache)]
        subprocess.run([*args, '1'], capture_output=True, check=True, env=self.env)
        obj = next(cache.rglob('example.c.o'))
        before = obj.stat().st_mtime_ns
        repeat = subprocess.run([*args, '1'], capture_output=True, check=True, env=self.env)
        self.assertIn(b'buildConfigure=reuse', repeat.stdout)
        self.assertEqual(before, obj.stat().st_mtime_ns)
        subprocess.run([*args, '2'], capture_output=True, check=True, env=self.env)
        self.assertNotEqual(before, obj.stat().st_mtime_ns)
        before = obj.stat().st_mtime_ns
        (source / 'value.h').write_text('#define HEADER_VALUE 2\n')
        subprocess.run([*args, '2'], capture_output=True, check=True, env=self.env)
        self.assertNotEqual(before, obj.stat().st_mtime_ns)
        # Manual cache edits cannot silently replace the caller's configuration.
        subprocess.run(['cmake', '-S', str(source), '-B', str(cache), '-DVALUE=999'],
                       capture_output=True, check=True, env=self.env)
        reset = subprocess.run([*args, '2'], capture_output=True, check=True, env=self.env)
        self.assertNotIn(b'buildConfigure=reuse', reset.stdout)
        self.assertIn('VALUE:UNINITIALIZED=2', (cache / 'CMakeCache.txt').read_text())

    def test_bytecode_reuse_rejects_changed_sources_pipeline_or_outputs(self):
        cache = Path(self.prepare(namespace='apk').stdout.strip()) / 'bytecode'
        sources = self.repo / 'java'
        sources.mkdir()
        java = sources / 'Example.java'
        java.write_text('class Example {}')
        pipeline = self.repo / 'pipeline.sh'
        pipeline.write_text('javac && d8')
        (cache / 'classes').mkdir(parents=True)
        (cache / 'classes/Example.class').write_bytes(b'class output')
        (cache / 'dex').mkdir()
        dex = cache / 'dex/classes.dex'
        dex.write_bytes(b'dex output')
        args = ['python3', str(ROOT / 'tools/product/apk-bytecode-cache.py'),
                '--cache', str(cache), '--sources', str(sources), '--pipeline', str(pipeline)]
        subprocess.run([*args, 'record'], check=True)
        self.assertEqual(subprocess.run([*args, 'check']).returncode, 0)
        for path, content in ((java, b'class Example { int changed; }'),
                              (pipeline, b'new compiler arguments'), (dex, b'corrupted')):
            original = path.read_bytes()
            path.write_bytes(content)
            self.assertNotEqual(subprocess.run([*args, 'check']).returncode, 0)
            path.write_bytes(original)
        dex.unlink()
        self.assertNotEqual(subprocess.run([*args, 'check']).returncode, 0)


if __name__ == '__main__':
    unittest.main()
