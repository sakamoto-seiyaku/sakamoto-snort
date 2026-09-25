#!/usr/bin/env python3
"""Test-only ordered logical evaluator; never reads compiled rules/indexes.

Logical AST + packet facts produce expectations. The separate encoder supplies
source bytes to the real compiler, and only the public match result is compared.
"""
import ctypes as C
import ipaddress
from pathlib import Path
import random
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
U8, U16, U32, U64 = C.c_uint8, C.c_uint16, C.c_uint32, C.c_uint64

class Rule(C.Structure):
    _fields_ = [('expression_length', U32), ('expression', U8*64), ('rule_id', U64)] + [
        (n, U32) for n in ('uid', 'network_context_id', 'ifindex', 'priority', 'order', 'reason_id')] + [
        (n, U16) for n in ('source_port_first', 'source_port_last', 'destination_port_first', 'destination_port_last')] + [
        (n, U8) for n in ('family', 'protocol', 'direction', 'source_prefix_length', 'destination_prefix_length', 'action', 'mode')] + [
        ('source_address', U8*16), ('destination_address', U8*16)]

class Packet(C.Structure):
    _fields_ = [(n, U32) for n in ('uid', 'network_context_id', 'ifindex')] + [
        (n, U16) for n in ('source_port', 'destination_port')] + [(n, U8) for n in (
        'family', 'protocol', 'direction', 'uid_known', 'direction_known', 'network_context_known', 'ifindex_known', 'ports_available')] + [
        ('source_address', U8*16), ('destination_address', U8*16)]

class Result(C.Structure):
    _fields_ = [(n, U8) for n in ('evaluation', 'stage_verdict', 'action', 'no_match_reason', 'mode', 'actual_action')] + [
        ('rule_id', U64)] + [(n, U32) for n in ('reason_id', 'priority', 'order', 'winner_rank', 'probes', 'probe_limit', 'subject_probes', 'candidate_count')]

# No production opcodes, compiled entries, indexes, masks or caches here.
def logical_truth(expr, facts):
    op, *args = expr
    if op == 'not':
        truth = logical_truth(args[0], facts)
        return None if truth is None else not truth
    if op in ('and', 'or'):
        truths = [logical_truth(arg, facts) for arg in args]
        if op == 'and':
            if False in truths: return False
            return None if None in truths else True
        if True in truths: return True
        return None if None in truths else False
    fact = facts[op]
    if fact is None: return None
    if op in ('src', 'dst'):
        return ipaddress.ip_address(fact) in ipaddress.ip_network(args[0], strict=False)
    if op in ('sport', 'dport'):
        return args[0] <= fact <= args[1]
    return fact == args[0]

def ordered_reference(rules, facts):
    effective = sorted((r for r in rules if facts['uid'] == r['uid']),
                       key=lambda r: (r['priority'], r['order'], r['id']))
    for rank, rule in enumerate(effective, start=1):
        if logical_truth(rule['expr'], facts) is True:
            return dict(rule_id=rule['id'], winner_rank=rank, action=rule['action'],
                        mode=rule['mode'], actual_action=1 if rule['mode'] else rule['action'],
                        reason_id=rule['reason'], priority=rule['priority'], order=rule['order'])
    # The matcher returns NoMatch/NONE; graph completion supplies default ALLOW.
    return dict(rule_id=0, action=0, actual_action=0)

# This request adapter does not participate in reference evaluation.
def encode(expr):
    op, *args = expr
    if op in ('and', 'or', 'not'):
        return b''.join(encode(arg) for arg in args) + bytes([{'and':1, 'or':2, 'not':3}[op]])
    if op in ('family', 'protocol', 'direction'):
        return bytes([{'family':4, 'protocol':5, 'direction':6}[op], args[0]])
    if op in ('network', 'interface'):
        return bytes([7 if op == 'network' else 8])+args[0].to_bytes(4, 'little')
    if op in ('sport', 'dport'):
        return bytes([11 if op == 'sport' else 12])+b''.join(n.to_bytes(2, 'little') for n in args)
    net = ipaddress.ip_network(args[0], strict=False)
    return bytes([9 if op == 'src' else 10, net.version, net.prefixlen])+net.network_address.packed.ljust(16, b'\0')

def packet(facts):
    p = Packet(uid=facts['uid'] or 0, uid_known=facts['uid'] is not None,
               family=facts['family'], protocol=facts['protocol'])
    for key, field in [('direction','direction'), ('network','network_context'), ('interface','ifindex')]:
        setattr(p, field+'_known', facts[key] is not None)
        setattr(p, 'network_context_id' if key == 'network' else field, facts[key] or 0)
    p.ports_available = facts['sport'] is not None and facts['dport'] is not None
    p.source_port, p.destination_port = facts['sport'] or 0, facts['dport'] or 0
    p.source_address[:] = ipaddress.ip_address(facts['src']).packed.ljust(16, b'\0')
    p.destination_address[:] = ipaddress.ip_address(facts['dst']).packed.ljust(16, b'\0')
    return p

def source(rule):
    encoded = encode(rule['expr'])
    r = Rule(expression_length=len(encoded), rule_id=rule['id'], uid=rule['uid'],
             network_context_id=2**32-1, ifindex=2**32-1, priority=rule['priority'], order=rule['order'],
             reason_id=rule['reason'], source_port_last=65535, destination_port_last=65535,
             action=rule['action'], mode=rule['mode'])
    r.expression[:len(encoded)] = encoded
    return r

def logical(expr, identity=10, priority=1, order=0, action=2, mode=0, uid=17):
    return dict(expr=expr, id=identity, priority=priority, order=order, action=action, mode=mode, uid=uid, reason=identity+100)

BASE = dict(uid=17, family=4, protocol=17, direction=3, network=1, interface=9,
            src='192.0.2.1', dst='198.51.100.255', sport=0, dport=65535)

def run(lib):
    count = 0
    def compare(rules, facts, hand_winner=None):
        nonlocal count
        expected = ordered_reference(rules, facts)
        if hand_winner is not None: assert expected['rule_id'] == hand_winner, (rules, facts, expected, hand_winner)
        raw = (Rule*len(rules))(*(source(r) for r in rules))
        # Public compiler owns its opaque output; the test never inspects it.
        view = C.create_string_buffer(128*1024)
        assert lib.product_l4_policy_compile(view, raw, len(rules)) == 0
        result = Result()
        assert lib.product_l4_policy_match(view, C.byref(packet(facts)), C.byref(result)) == 0
        actual = {key: getattr(result, key) for key in expected}
        assert actual == expected, (rules, facts, expected, actual)
        if expected['rule_id']:
            assert result.evaluation == 1 and result.stage_verdict == (expected['actual_action'] == 2)
        else: assert result.evaluation == 0
        count += 1

    # Calibrate every new leaf before generated comparisons. Literal outcomes
    # include both current endpoints, family mismatch, /0, /32, /128, and edges.
    cases = [
        (('family',4), {}, True), (('family',6), {}, False),
        (('protocol',17), {}, True), (('protocol',6), {}, False), (('protocol',1), {'protocol':1}, True),
        (('direction',3), {}, True), (('direction',1), {}, False), (('direction',1), {'direction':None}, None),
        (('network',1), {}, True), (('network',2), {}, False), (('network',1), {'network':None}, None),
        (('interface',9), {}, True), (('interface',10), {}, False), (('interface',9), {'interface':None}, None),
        (('src','192.0.2.0/24'), {}, True), (('src','198.51.100.0/24'), {}, False),
        (('dst','198.51.100.255/32'), {}, True), (('dst','192.0.2.0/24'), {}, False),
        (('src','0.0.0.0/0'), {}, True), (('src','2001:db8::/32'), {}, False),
        (('sport',0,0), {}, True), (('sport',1,65535), {}, False), (('sport',0,65535), {'sport':None,'dport':None}, None),
        (('dport',65535,65535), {}, True), (('dport',0,65534), {}, False), (('dport',0,65535), {'sport':None,'dport':None}, None),
        (('src','2001:db8::/127'), {'family':6,'src':'2001:db8::1','dst':'2001:db8:1::2'}, True),
        (('src','2001:db8::/127'), {'family':6,'src':'2001:db8::2','dst':'2001:db8:1::2'}, False),
        (('dst','2001:db8:1::2/128'), {'family':6,'src':'2001:db8::1','dst':'2001:db8:1::2'}, True),
        (('dst','::/0'), {'family':6,'src':'::1','dst':'2001:db8::'}, True),
    ]
    for expr, changes, truth in cases:
        facts = BASE | changes
        assert logical_truth(expr, facts) is truth
        compare([logical(expr)], facts, 10 if truth is True else 0)
        compare([logical(('not', expr))], facts, 10 if truth is False else 0)
    # Full three-valued truth tables, including false AND unknown then NOT.
    truths = [False, True, None]
    and_expected = [[False,False,False],[False,True,None],[False,None,None]]
    or_expected = [[False,True,None],[True,True,True],[None,True,None]]
    for a in range(3):
        for b in range(3):
            facts = BASE | dict(network=[2,1,None][a], interface=[10,9,None][b])
            for op, table in [('and',and_expected), ('or',or_expected)]:
                expr = (op, ('network',1), ('interface',9))
                assert logical_truth(expr, facts) is table[a][b]
                compare([logical(expr)], facts, 10 if table[a][b] is True else 0)
                compare([logical(('not',expr))], facts, 10 if table[a][b] is False else 0)
    # Same-action competitors ensure action equality cannot hide wrong winners.
    expressions = [('or',('network',1),('dport',65535,65535)),
                   ('not',('interface',9)), ('and',('family',4),('sport',0,0))]
    rules = [logical(e, identity=i+20, priority=1, order=0, mode=i%2) for i,e in enumerate(expressions)]
    compare(list(reversed(rules)), BASE, 20)
    compare(rules, BASE | dict(network=None,dport=5), 22)
    compare(rules, BASE | dict(network=None,dport=5,interface=8), 21)
    compare(rules, BASE | dict(uid=None), 0)
    compare(rules, BASE | dict(uid=19), 0)
    # Deterministic AST generation, independent ordered evaluation, both endpoint
    # orientations and availability values; no compiled plan feeds expectations.
    rng = random.Random(257)
    leaves = [c[0] for c in cases]
    def tree(depth):
        if not depth or rng.randrange(3)==0: return rng.choice(leaves)
        op = rng.choice(['and','or','not'])
        return (op, tree(depth-1)) if op=='not' else (op, tree(depth-1), tree(depth-1))
    for i in range(1200):
        rules = []
        for j in range(4):
            expr = tree(3)
            while len(encode(expr)) > 64: expr = tree(3)
            rules.append(logical(expr, identity=100+j, priority=rng.randrange(3),
                                 order=rng.randrange(3), action=rng.choice([1,2]), mode=rng.randrange(2)))
        facts = BASE | dict(network=rng.choice([1,2,None]), interface=rng.choice([9,10,None]),
                            direction=rng.choice([1,3,None]), sport=rng.choice([0,1,65534,65535]),
                            dport=rng.choice([0,1,65534,65535]), protocol=rng.choice([6,17]))
        if i%3==0: facts.update(family=6,src='2001:db8::1',dst='2001:db8:1::2')
        if i%5==0: facts['src'],facts['dst']=facts['dst'],facts['src']
        if i%7==0: facts.update(sport=None,dport=None)
        compare(rules, facts)
    print(f'T06 independent ordered reference: {count} complete winner comparisons PASS')

if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='sakamoto-t06-') as temporary:
        library = Path(temporary)/'policy.so'
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-shared','-fPIC',
                        str(ROOT/'src/product/vpp/product_l4_policy.c'),'-o',str(library)],check=True)
        lib = C.CDLL(str(library))
        lib.product_l4_policy_compile.argtypes = [C.c_void_p, C.POINTER(Rule), C.c_size_t]
        lib.product_l4_policy_match.argtypes = [C.c_void_p, C.POINTER(Packet), C.POINTER(Result)]
        run(lib)
