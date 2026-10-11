#!/usr/bin/env python3
"""A busy endpoint must not qualify a window with no native packet progress."""
import pixel_quick as quick

client = {'case': 'tcp-new', 'bytes': 284352, 'packets': 0, 'completed': 11848,
          'input_unique_udp_tuples': 0}
before = ('root.receive generation=1827 lane=0 datagrams=203048\n'
          'flow.protocol protocol=tcp creates=26\n')
quiet = before
live = ('root.receive generation=1827 lane=0 datagrams=203150\n'
        'flow.protocol protocol=tcp creates=35\n')

try:
    quick.validate_capture_window('root', client, before, quiet)
except RuntimeError as error:
    assert 'capture' in str(error)
else:
    raise AssertionError('Root bypass-only endpoint traffic was accepted')

quick.validate_capture_window('root', client, before, live)
try:
    quick.validate_capture_window('root', client, before, live.replace('1827', '1828'))
except RuntimeError:
    pass
else:
    raise AssertionError('A replaced generation qualified a measurement window')

try:
    quick.validate_capture_window('vpn', client, before, quiet)
except RuntimeError as error:
    assert 'Flow' in str(error)
else:
    raise AssertionError('Successful new connections without any Flow creates were accepted')

print('capture-window regression checks: PASS')
