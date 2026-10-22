"""Independent DNS wire fixtures for the S312 resolver peer; no Product codec."""
import ipaddress
import struct


def name(value):
    return b''.join(bytes([len(label)]) + label.encode('ascii')
                    for label in value.rstrip('.').split('.') if label) + b'\0'


def question(identifier, value='qname.test', qtype=1, *, edns=False):
    header = struct.pack('!6H', identifier, 0x0110 if edns else 0x0100, 1, 0, 0, int(edns))
    wire = header + name(value) + struct.pack('!HH', qtype, 1)
    if edns:
        wire += b'\0' + struct.pack('!HHIH', 41, 1232, 0x8000, 7) + struct.pack('!HH', 65001, 3) + b'\0\xffZ'
    return wire


def rr(owner, kind, data, ttl=60):
    return name(owner) + struct.pack('!HHIH', kind, 1, ttl, len(data)) + data


def decode_question(wire):
    at, labels = 12, []
    while wire[at]:
        size = wire[at]; at += 1
        labels.append(wire[at:at + size].decode('ascii')); at += size
    at += 1
    return '.'.join(labels), int.from_bytes(wire[at:at + 2], 'big'), at + 4


def answer(query, variant='alias', *, aliases=1):
    qname, qtype, end = decode_question(query)
    records, additional, names = [], [], [qname]
    if variant in ('alias', 'loop', 'long', 'overflow'):
        count = aliases if variant in ('long', 'overflow') else 1
        previous = qname
        for index in range(count):
            target = 'alias.test' if index == count - 1 else f'chain{index}.test'
            records.append(rr(previous, 5, name(target)))
            names.append(target); previous = target
        if variant == 'loop':
            records.append(rr(previous, 5, name(qname)))
        target = previous
    else:
        target = qname
    if qtype == 1:
        records.append(rr(target, 1, ipaddress.ip_address('192.0.2.44').packed))
    elif qtype == 28:
        records.append(rr(target, 28, ipaddress.ip_address('2001:db8::44').packed))
    elif qtype == 16:
        records.append(rr(target, 16, b'\x07s312-ok'))
    elif qtype == 15:
        records.append(rr(target, 15, b'\0\x0a' + name('blocked.test')))
    elif qtype == 33:
        records.append(rr(target, 33, struct.pack('!3H', 0, 0, 443) + name('blocked.test')))
    elif qtype == 65:
        records.append(rr(target, 65, b'\0\x01\0' + struct.pack('!HH', 4, 4)
                          + ipaddress.ip_address('192.0.2.66').packed))
    else:
        records.append(rr(target, qtype, b'\xc0\x0c\xff\0Z'))
    if variant == 'unrelated':
        additional.append(rr('unrelated.test', 5, name('alias.test')))
        additional.append(rr('alias.test', 1, ipaddress.ip_address('192.0.2.99').packed))
        records.extend([rr(qname, 15, b'\0\x0a' + name('alias.test')),
                        rr(qname, 33, struct.pack('!3H', 0, 0, 443) + name('alias.test')),
                        rr(qname, 65, b'\0\x01\0' + struct.pack('!HH', 4, 4)
                           + ipaddress.ip_address('192.0.2.99').packed)])
    flags = 0x8180 | (int.from_bytes(query[2:4], 'big') & 0x10)
    if variant == 'tc': flags |= 0x0200
    if variant == 'nxdomain': flags |= 3; records = []
    if int.from_bytes(query[10:12], 'big'):
        additional.append(query[end:])  # Preserve unknown EDNS options verbatim.
    header = query[:2] + struct.pack('!5H', flags, 1, len(records), 0, len(additional))
    result = header + query[12:end] + b''.join(records) + b''.join(additional)
    if variant == 'malformed': result = result[:-1]
    if variant == 'short': result = query[:2] + b'\x81'
    return result, names
