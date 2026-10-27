"""Strict independent qualification of closed normal DNS history, including
its existing 4096-row retention bound. This never writes the Product store.
"""
import json

DNS_RETAINED_LIMIT = 4096


def qualify_history(before_meta, before_rows, after_meta, after_rows):
    assert after_meta['dns_rejected'] == before_meta['dns_rejected'], 'new normal DNS rows were rejected'
    accepted = after_meta['dns_accepted'] - before_meta['dns_accepted']
    evicted = after_meta['dns_evicted'] - before_meta['dns_evicted']
    assert accepted >= 0 and evicted >= 0
    assert len(before_rows) <= DNS_RETAINED_LIMIT and len(after_rows) <= DNS_RETAINED_LIMIT
    surviving = set(before_rows) & set(after_rows)
    for key in surviving:
        assert before_rows[key] == after_rows[key], ('surviving old raw record or receipt changed', key)
    removed = set(before_rows) - set(after_rows)
    added = set(after_rows) - set(before_rows)
    # Each cohort is smaller than the normal retention limit. Every newly
    # accepted row must remain available for its own whole-record readback.
    assert accepted == len(added), 'a newly accepted row is absent from this closed cohort'
    assert evicted == len(removed), 'eviction count does not match retired old rows'
    assert len(before_rows) + accepted - evicted == len(after_rows)
    expected_evictions = max(0, len(before_rows) + accepted - DNS_RETAINED_LIMIT)
    assert evicted == expected_evictions, 'retirement is not explained by the known row capacity'
    cutoff = None
    boot_id = None
    if removed:
        assert len(after_rows) == DNS_RETAINED_LIMIT
        clocks = {}
        for key, value in dict(before_rows, **{key: after_rows[key] for key in added}).items():
            clock = json.loads(value).get('received_clock')
            assert clock and isinstance(clock.get('boot_id'), str) and clock['boot_id']
            assert isinstance(clock.get('uptime_us'), int) and clock['uptime_us'] >= 0
            clocks[key] = clock
        identities = {clock['boot_id'] for clock in clocks.values()}
        assert len(identities) == 1, 'mixed or unavailable receipt clocks do not prove an exact oldest order'
        boot_id = next(iter(identities))
        # The existing store chooses the oldest receipt first, then the lower
        # canonical key for equal receipts. Independently sort the actual raw
        # input set and verify the exact removed prefix, not only its count.
        ordered = sorted(clocks, key=lambda key: (clocks[key]['uptime_us'], key))
        assert removed == set(ordered[:evicted]), 'a newer row retired while older evidence survived'
        cutoff = clocks[ordered[evicted - 1]]['uptime_us']
    return dict(status='PASS_EXACT_NORMAL_DNS_HISTORY', before_rows=len(before_rows), after_rows=len(after_rows),
                retained_limit=DNS_RETAINED_LIMIT, new_rows=accepted, retired_old_rows=evicted,
                surviving_old_raw_and_clock_exact=len(surviving), removed_keys=sorted(removed),
                oldest_receipt_boot_id=boot_id, oldest_retired_cutoff_uptime_us=cutoff,
                no_new_row_lost=True, no_new_dns_rejection=True)
