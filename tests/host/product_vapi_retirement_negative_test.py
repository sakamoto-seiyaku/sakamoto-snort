#!/usr/bin/env python3
"""Ensure each missing post-dispatch fence turns the real bridge contract red."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / 'src/product/native/sakamoto_product_vapi.c').read_text()
fences = [
    ('network', 'if (rv != VAPI_OK || !call.called) session->connected = 0;', 0, 'retired'),
    ('root_stop', 'if (rv != VAPI_OK || !call.called) session->connected = 0;', 1, 'retired'),
    ('status', 'if (rv != VAPI_OK || !call.callback_called) session->connected = 0;', 0, 'retired'),
    ('scalar_policy', 'if (rv != VAPI_OK || !call.callback_called) session->connected = 0;', 1, 'retired'),
    ('bundle_policy', 'if (rv != VAPI_OK || !call.callback_called) session->connected = 0;', 2, 'retired'),
    ('network_unsent', 'release_unsent_request (session, rv, call.called, message);', 0, 'not reclaimed'),
    ('root_stop_unsent', 'release_unsent_request (session, rv, call.called, message);', 1, 'not reclaimed'),
    ('status_unsent', 'release_unsent_request (session, rv, call.callback_called, message);', 0, 'not reclaimed'),
    ('scalar_unsent', 'release_unsent_request (session, rv, call.callback_called, message);', 1, 'not reclaimed'),
    ('bundle_unsent', 'release_unsent_request (session, rv, call.callback_called, message);', 2, 'not reclaimed'),
]
for label, fence, occurrence, diagnostic in fences:
    with tempfile.TemporaryDirectory(prefix='s243-vapi-negative-') as work:
        start = 0
        for _ in range(occurrence + 1):
            offset = source.index(fence, start)
            start = offset + len(fence)
        modified = source[:offset] + '/* missing retirement fence */' + source[start:]
        bridge = Path(work) / 'bridge.c'
        bridge.write_text(modified)
        run = subprocess.run(['bash', str(ROOT / 'tests/host/product_vapi_callback_contract.sh')],
                             env=dict(os.environ, SAKAMOTO_VAPI_BRIDGE_TEST_SOURCE=str(bridge)),
                             capture_output=True, text=True, timeout=20)
        assert run.returncode != 0, label + ' missing fence passed'
        assert diagnostic in run.stderr, label + ': wrong failure: ' + run.stderr
        print(label + ' missing fence: rejected')
print('VAPI retirement mutation checks: PASS')
