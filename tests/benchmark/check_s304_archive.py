#!/usr/bin/env python3
"""Protect an existing S304 evidence index against a repeat collection."""
from pathlib import Path
import tempfile

import s304_archive

with tempfile.TemporaryDirectory(prefix='s304-index-retention-') as directory:
    target = Path(directory)
    index = target / s304_archive.INDEX_NAME
    index.write_text('original evidence identity\n')
    try:
        s304_archive.create(target)
    except RuntimeError as error:
        assert 'must not be replaced' in str(error)
    else:
        raise AssertionError('archive creator replaced an existing evidence index')
    assert index.read_text() == 'original evidence identity\n'
    assert sorted(target.iterdir()) == [index]

print('S304 existing evidence index retention: PASS')
