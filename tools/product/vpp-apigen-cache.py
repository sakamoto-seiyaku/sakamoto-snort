#!/usr/bin/env python3
"""Keep the official API generator's no-import depfile valid for Ninja."""
from pathlib import Path
import subprocess
import sys


def main():
    generator, *args = sys.argv[1:]
    result = subprocess.run([generator, *args])
    if result.returncode or '-MF' not in args:
        return result.returncode
    # The pinned generator omits the main input from its depfile. With no
    # imports this becomes an empty dependency list; CMake drops the transformed
    # depfile and Ninja consequently regenerates/recompiles on every build.
    # Retain imported dependencies and include the actual main input as well.
    depfile = Path(args[args.index('-MF') + 1])
    source = args[args.index('--input') + 1]
    escaped = source.replace('\\', '\\\\').replace('$', '$$').replace(' ', '\\ ').replace('#', '\\#')
    content = depfile.read_text().rstrip()
    if content.endswith('\\'):
        content += '\n  ' + escaped + '\n'
    else:
        content += ' ' + escaped + '\n'
    depfile.write_text(content)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
