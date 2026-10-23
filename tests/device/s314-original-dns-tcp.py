#!/usr/bin/env python3
"""S314 original TCP DNS qualification through the shared Root/VPN runner."""
import importlib.util
from pathlib import Path

path = Path(__file__).with_name('s313-root-dns-tcp.py')
spec = importlib.util.spec_from_file_location('original_dns_tcp', path)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

if __name__ == '__main__':
    raise SystemExit(runner.main(task='SAKAMOTO-314'))
