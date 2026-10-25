#!/usr/bin/env python3
"""Exercise the shared Device pre-query contract against independent CLI states."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('dns_device_ready', ROOT/'tests/device/s315-root-dns-proxy.py')
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)


class Clock:
    def __init__(self):
        self.value = -6

    def monotonic(self):
        self.value += 6
        return self.value

    def sleep(self, _):
        pass


def check(profile, changes=None, *, enabled=True, accepted=True, networks=None):
    # These literals describe the producer's public states, independently of
    # the consumer predicate. Historical error does not negate a current idle
    # route; authorization failure is an explicit current state instead.
    row = dict(owner='0', generation='77', profile='2' if profile == 'vpn' else '1',
               enabled='1', route_ready='1', udp_state='authorized', socket_ready='1',
               authorized_udp='1', stopping='0', network_revision='5', route_revision='9',
               upstream='192.0.2.53', port='53054', proxy_bytes='580280', error='0')
    row.update(changes or {})
    device = object.__new__(shared.Device)
    rows = [dict(row, owner=str(i), network_revision=str(network))
            for i, network in enumerate(networks)] if networks else [row]
    device.generation, device.owners, device.profile = 77, len(rows), profile
    device.selected_dns = dict(endpoint=('192.0.2.53', 53054), route_revision=9,
                               active_revision=9)
    device.cli = lambda *_: '\n'.join('dns.proxy ' + ' '.join(f'{key}={value}' for key, value in item.items()) for item in rows)
    shared.time = Clock()
    try:
        result = device.proxy_ready('readiness-contract', enabled)
    except AssertionError:
        assert not accepted, (profile, changes)
    else:
        assert accepted and result == rows, (profile, changes, result)


for profile in ('root', 'vpn'):
    check(profile)
    check(profile, networks=(5, 5, 5))
    check(profile, networks=(5, 4, 5), accepted=False)
    # The producer clears preparation for a uniformly stale owner snapshot.
    check(profile, dict(route_ready='0'), networks=(4, 4, 4), accepted=False)
    check(profile, dict(udp_state='idle', socket_ready='0', authorized_udp='0'), networks=(5, 5, 5))
    check(profile, dict(udp_state='idle', socket_ready='0', authorized_udp='0', error='17'))
    check(profile, dict(enabled='0', udp_state='disabled', socket_ready='0',
                        authorized_udp='0', error='17'), enabled=False)
    for state in ('authorizing', 'failed', 'unavailable', 'stopped'):
        check(profile, dict(route_ready='0', udp_state=state, socket_ready='0',
                            authorized_udp='0'), accepted=False)
    for changes in (dict(generation='76'), dict(owner='1'), dict(route_revision='8'),
                    dict(network_revision='0'), dict(stopping='1'), dict(upstream='192.0.2.54'),
                    dict(port='53'), dict(profile='1' if profile == 'vpn' else '2'),
                    dict(udp_state='idle', proxy_bytes='0', socket_ready='0', authorized_udp='0'),
                    dict(udp_state='idle', authorized_udp='0'),
                    dict(udp_state='failed', route_ready='1', socket_ready='0', authorized_udp='0')):
        check(profile, changes, accepted=False)

print('shared Root/VPN pre-query route/current authorization/idle/error/context contract: PASS')
