"""Complete source requests for real TLS/QUIC domain-list integration.

This is only a request builder. Expectations come from the independent saved-
source/label oracle, never this helper or a production compiled index.
"""

def adapt(lines, variant='full'):
    assert variant in ('full', 'without-exact')
    result = list(lines)
    # List 0 exact AND list 1 descendant AND current packet destination port.
    # The reverse packet can have another same-action logical winner.
    expression = bytes([17, 0, 17, 1, 1, 12]) + (40600).to_bytes(2, 'little') + (40700).to_bytes(2, 'little') + bytes([1])
    first = result[0].split(); first[16:] = [expression.hex()]; result[0] = ' '.join(first)
    # Shorter parent-list membership remains a competing candidate even when
    # the exact list also matches. Unavailable NOT cannot become true.
    second = result[1].split(); second[16:] = [bytes([17, 0, 3, 17, 2, 2]).hex()]; result[1] = ' '.join(second)
    entries = ['lists 3',
               'domain 1 descendants example.test', 'domain 1 descendants example',
               'domain 2 descendants test', 'domain 2 descendants example']
    if variant == 'full':
        entries += ['domain 0 exact EXAMPLE.test.', 'domain 0 exact xn--bcher-kva.example']
    return entries + result
