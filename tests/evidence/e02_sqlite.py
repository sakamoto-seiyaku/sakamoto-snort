#!/usr/bin/env python3
"""Offline collection of a closed E02 SQLite store, not a Product query path."""
import json
import sqlite3
from pathlib import Path


def closed_state(database):
    database = Path(database)
    wal = Path(str(database) + '-wal')
    assert not wal.exists() or wal.stat().st_size == 0, 'unsettled SQLite WAL'
    with sqlite3.connect(database.resolve().as_uri() + '?mode=ro&immutable=1', uri=True) as db:
        assert db.execute('PRAGMA quick_check').fetchone() == ('ok',)
        rows = db.execute('SELECT kind,key,value FROM observation').fetchall()
    state = {'baselines': {}, 'recent': {}, 'minutes': {}}
    metadata = None
    for kind, key, raw in rows:
        value = json.loads(raw)
        if kind == 0:
            assert key == '' and metadata is None
            metadata = value
        else:
            state[{1: 'baselines', 2: 'recent', 3: 'minutes'}[kind]][key] = value
    assert metadata is not None
    state.update(metadata)
    return state


def footprint(database, legacy=None):
    database = Path(database)
    files = [database, *(Path(str(database) + suffix) for suffix in ('-wal', '-shm', '-journal'))]
    if legacy is not None:
        legacy = Path(legacy)
        files += [legacy, legacy.with_suffix('.pending'), legacy.with_suffix('.lock')]
    sizes = {path.name: path.stat().st_size for path in files if path.is_file()}
    return {'files': sizes, 'total_bytes': sum(sizes.values())}
