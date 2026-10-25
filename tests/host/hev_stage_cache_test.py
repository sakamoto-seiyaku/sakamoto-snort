#!/usr/bin/env python3
"""Stable HEV compiler inputs retain unchanged files and reject unowned edits."""
import importlib.util
import json
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('stage_hev', ROOT/'tools/product/stage-hev.py')
stage = importlib.util.module_from_spec(spec); spec.loader.exec_module(stage)


def snapshot(root, version, glue):
    source = root/'staged'/version/'source'
    source.mkdir(parents=True)
    (source/'glue.c').write_text(glue)
    (source/'upstream.c').write_text('unchanged dependency\n')
    (source/'include.h').symlink_to('upstream.c')
    (source.parent/'stage.json').write_text(json.dumps({'files': stage.vendor.inventory(source)}))
    return source


def fingerprints(root):
    return {str(p.relative_to(root)): (p.lstat().st_ino, p.lstat().st_mtime_ns)
            for p in root.iterdir()}


with tempfile.TemporaryDirectory(prefix='hev-stage-cache-', dir=ROOT/'build-output/host-tests') as directory:
    root = Path(directory)
    first = snapshot(root, 'first', 'first glue\n')
    destination = root/'compile-inputs'
    compiler = stage.compile_source(first, destination)
    before = fingerprints(compiler)
    second = snapshot(root, 'second', 'changed glue\n')
    assert stage.compile_source(second, destination) == compiler
    after = fingerprints(compiler)
    assert before['upstream.c'] == after['upstream.c']
    assert before['include.h'] == after['include.h']
    assert before['glue.c'] != after['glue.c']
    assert (compiler/'glue.c').read_text() == 'changed glue\n'
    third = snapshot(root, 'third', 'changed glue\n')
    stage.compile_source(third, destination)
    assert fingerprints(compiler) == after
    assert (first/'glue.c').read_text() == 'first glue\n'  # Frozen publication was preserved.
    (compiler/'glue.c').write_text('unowned change\n')
    try:
        stage.compile_source(third, destination)
    except AssertionError as error:
        assert 'changed outside staging' in str(error)
    else:
        raise AssertionError('modified compiler inputs were silently trusted')
    unsafe = root/'unowned'; unsafe.mkdir(); (unsafe/'keep').write_text('preserve\n')
    try:
        stage.compile_source(third, unsafe)
    except AssertionError as error:
        assert 'unowned' in str(error)
    else:
        raise AssertionError('unowned nonempty directory was overwritten')
    assert (unsafe/'keep').read_text() == 'preserve\n'
    linked = root/'linked'; linked.symlink_to(unsafe, target_is_directory=True)
    try:
        stage.compile_source(third, linked)
    except AssertionError as error:
        assert 'symlink' in str(error)
    else:
        raise AssertionError('symlink compiler root was accepted')
print('HEV stable source paths: glue-only update, zero unchanged-file replacement, immutable snapshots and ownership guards PASS')
