"""Declared real-attribute and explicit-fault policy cases."""
def cases(uid, known, ifindex):
    return [
        dict(name='uid-rule',fault=0,mode=1,uid=uid,blocked=known),
        dict(name='missing-uid',fault=1,mode=1,uid=uid,blocked=False),
        dict(name='uid-zero',fault=2,mode=1,uid=0,blocked=True),
        dict(name='ifindex-rule',fault=0,mode=2,uid=uid,blocked=known and bool(ifindex)),
        dict(name='missing-ifindex',fault=3,mode=2,uid=uid,blocked=False),
        dict(name='zero-ifindex',fault=4,mode=2,uid=uid,blocked=False),
        dict(name='opposite-ifindex',fault=5,mode=2,uid=uid,blocked=known and bool(ifindex)),
        dict(name='unknown-hook',fault=6,mode=4,uid=uid,blocked=False),
        dict(name='unknown-context',fault=0,mode=3,uid=uid,blocked=False),
        dict(name='recovery',fault=0,mode=0,uid=uid,blocked=False),
    ]
