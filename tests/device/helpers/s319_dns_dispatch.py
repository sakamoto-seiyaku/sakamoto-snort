"""Qualify logical DNS dispatches separately from one allowed UDP retry.

This reads sequential ordinary-App experiments. A retry needs complete peer,
physical-wire and native-clock evidence; a missing peer receipt is never inferred.
"""
import ipaddress


def _address(value):
    return str(ipaddress.ip_address(value))


def peer_observation_gap(first, second):
    # Preserve the producer's own clock and units; these observations are not
    # exact send times and clocks from different backends cannot be mixed.
    for field, result in (('received_mono_ms', 'peer_observation_gap_ms'),
                          ('host_monotonic_ns', 'peer_observation_gap_ns')):
        if field in first or field in second:
            assert field in first and field in second
            assert isinstance(first[field], int) and isinstance(second[field], int)
            gap = second[field] - first[field]
            assert gap >= 0, 'peer observation clock moved backwards'
            return {result: gap, 'peer_observation_clock': field}
    raise AssertionError('peer observation clock missing')


def qualify_udp_dispatches(query, received, wire, records, *, expected_port=53053):
    groups = {}
    for row in received:
        assert row['kind'] == 'received' and row['protocol'] == 'udp'
        assert row['resolver'][1] == expected_port
        request = bytes.fromhex(row['request_hex'])
        assert request[2:] == query[2:]
        groups.setdefault(request.hex(), []).append(row)
    relevant = [row for row in wire if row.get('kind') == 'udp'
                and row['destination_port'] in {53053, 53054, expected_port}
                and bytes.fromhex(row['payload_hex'])[2:] == query[2:]]
    assert all(row['destination_port'] == expected_port for row in relevant), 'target Question escaped to another test port'
    assert all(row['payload_hex'] in groups for row in relevant), 'wire dispatch without a peer receipt'
    retries = []
    for request, rows in groups.items():
        assert 1 <= len(rows) <= 2, 'more than one UDP retry'
        first = rows[0]
        assert all(row['resolver'] == first['resolver'] and row['peer'] == first['peer'] for row in rows)
        outgoing = [row for row in relevant if row['payload_hex'] == request]
        assert outgoing, 'peer receipt lacks physical sender evidence'
        assert all(_address(row['source']) == _address(first['peer'][0])
                   and row['source_port'] == first['peer'][1]
                   and _address(row['destination']) == _address(first['resolver'][0])
                   and row['destination_port'] == first['resolver'][1] for row in outgoing)
        if len(rows) == 2:
            assert rows[1]['request'] > first['request']
            peer_gap = peer_observation_gap(first, rows[1])
            clocks = [row['mono_ns'] for row in outgoing]
            assert all(row['timestamp_scope'] == 'userspace_after_recv' for row in outgoing)
            assert len(clocks) >= 2 and clocks == sorted(clocks)
            gap = max(clocks) - min(clocks)
            # Both are observation clocks. The core timer starts at native
            # admission, before first-send work or authorization queues, while
            # a collector may be descheduled after recv. Neither gap measures
            # the timer or exact send times, in either direction. Do not apply
            # a tolerance to turn an observation gap into a native duration.
            # Do not guess a retry's App identity when multiple fresh logical
            # resolutions share this Question in the sampled interval.
            resolved = [row for row in records if row['stage'] == 2 and row['name_index'] == 0
                        and row['proxy_flags'] & 4 and not row['proxy_flags'] & 16]
            assert len(resolved) == 1, 'retry has ambiguous native resolution identity'
            final = resolved[0]
            initial = [row for row in records if row['stage'] == 1 and row['token'] == final['token']
                       and row['request_attempt'] == final['request_attempt']]
            delivered = [row for row in records if row['stage'] == 4 and row['token'] == final['token']
                         and row['request_attempt'] == final['request_attempt']]
            assert len(initial) == 1 and final['upstream_session'] > 0
            assert len(delivered) == 1
            identity = ('generation', 'owner', 'incarnation', 'transport_session', 'request_attempt',
                        'token', 'id', 'source_port', 'protocol', 'network_revision', 'route_revision')
            assert all(initial[0][key] == final[key] == delivered[0][key] for key in identity)
            assert final['upstream_session'] == delivered[0]['upstream_session']
            assert final['proxy_flags'] == delivered[0]['proxy_flags']
            elapsed = final['mono_us'] - initial[0]['mono_us']
            assert 1_500_000 <= elapsed < 3_000_000
            assert delivered[0]['mono_us'] >= final['mono_us']
            retries.append(dict(request_hex=request, **peer_gap,
                                sender_observation_gap_ns=gap, exact_send_times_unobserved=True,
                                native_elapsed_us=elapsed, request_attempt=final['request_attempt'],
                                token=final['token'], upstream_session=final['upstream_session']))
    return dict(logical_dispatches=len(groups), received_datagrams=len(received), bounded_retries=retries)
