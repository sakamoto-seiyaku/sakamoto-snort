#!/usr/bin/env python3
"""Reuse only the existing experimental build/packaging tooling."""
from pathlib import Path
import importlib.util
import shutil

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("s247_builder", HERE.parent / "s245-s246/build.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
builder.HERE = HERE
builder.WORK = HERE.parent / "work/s247"
builder.OUT = builder.WORK / "build"
builder.STAGE = builder.WORK / "stage"
original_run = builder.run


def run(args, name, cwd=None, env=None):
    if name == "apk":
        env = dict(env, APK_VERSION_NAME="s247-20260907", APK_VERSION_CODE="247001")
    return original_run(args, name, cwd, env)


builder.run = run
if __name__ == "__main__":
    builder.main()
    # The input recipe is also sealed, so replay does not depend on a mutable
    # S245/S246 helper remaining unchanged after this run.
    for archive in (builder.WORK / "artifacts").iterdir():
        if not (archive / "s245-s246-recipes").exists():
            shutil.copytree(HERE.parent / "s245-s246", archive / "s245-s246-recipes")
