#!/usr/bin/env python3
"""S317 directed regression through the existing ordinary S316 VPN entry.

Use the installed current artifact and a 53053-only peer. Existing port53
listeners are independent resources. This adds no Product or VPN test seam.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[2]


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('apk','stage','backup','output'):parser.add_argument('--'+name,type=Path,required=True)
    for name in ('endpoint4','endpoint6'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--owners',choices=('1','3','1,3'),default='1,3')
    parser.add_argument('--trace',action='store_true')
    args=parser.parse_args()
    for name in ('apk','stage','backup','output'):setattr(args,name,getattr(args,name).resolve())
    assert not args.output.exists()
    vpn=module('s317_existing_vpn','tests/device/s316-vpn-dns-proxy.py')
    root_tcp=module('s317_safe_peer','tests/device/s317-root-dns-tcp-proxy.py')
    safe_peers=[]

    class SafePeer(root_tcp.Peer):
        def __init__(self,*values,**options):
            super().__init__(*values,**options);safe_peers.append(self)

    class SafeDevice(vpn.Device):
        def start(self,owners):
            assert len(safe_peers)==1 and [r['ports']for r in safe_peers[0].messages if r.get('kind')=='ready']==[[53053]]
            return super().start(owners)

        def install(self):
            state=vpn.props(self.save('s317-fresh-stopped.properties',self.app('files/runtime-state/snapshot.properties')))
            ledger=vpn.props(self.save('s317-fresh-ledger.properties',self.app('files/product-state/product-core-generation.properties')))
            assert state['state']=='stopped'and state['mayBeActive']=='false'
            assert state['generation']==ledger['generation']
            processes=self.save('s317-fresh-processes.txt',self.root('ps -A -o PID,UID,ARGS'))
            assert not any(len(row:=line.split())>=3 and Path(row[2]).name=='libvpp_runtime.so'for line in processes.splitlines())
            package=self.save('s317-fresh-package.txt',self.adb('shell','dumpsys','package',vpn.PKG))
            code=re.search(r'codePath=(\S+)',package)[1]
            actual=self.save('s317-fresh-apk-sha256.txt',self.adb('shell','sha256sum',code+'/base.apk')).split()[0]
            assert actual==vpn.digest(self.args.apk)
            return super().install()

        def wire_start(self):
            # The existing runner removes these exact owned paths during its
            # lifecycle. Require absence before claiming that ownership.
            paths='/data/local/tmp/s315-wire /data/local/tmp/s315-wire-*.stop /data/local/tmp/s315-wire-*.jsonl /data/local/tmp/s315-stale-return /data/local/tmp/s315-rules.txt'
            self.s317_wire_epoch=getattr(self,'s317_wire_epoch',0)+1
            present=self.save('s317-wire-namespace-before-'+str(self.s317_wire_epoch)+'.txt',
                self.root('for p in '+paths+'; do if [ -e "$p" ]; then echo PRESENT:"$p"; fi; done'))
            assert not present.strip(),'unowned existing witness path: '+present
            return super().wire_start()

    # Reuse the established session, wire, ordinary UI and complete SQLite
    # assertions. Only the independent peer's owned listener set is narrowed.
    vpn.Device=SafeDevice
    vpn.shared.Peer=SafePeer
    closure=[Path(__file__),ROOT/'tests/device/s316-vpn-dns-proxy.py',
        ROOT/'tests/device/s317-root-dns-tcp-proxy.py',ROOT/'tests/device/helpers/s317_dns_peer.ps1',
        ROOT/'tests/device/helpers/s315_dns_peer.ps1']
    hashes={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in closure}
    sys.argv=[str(ROOT/'tests/device/s316-vpn-dns-proxy.py')]
    for name in ('apk','stage','backup','output','endpoint4','endpoint6','owners'):
        sys.argv+=['--'+name,str(getattr(args,name))]
    sys.argv+=['--installed','--matrix','minimal','--peer','windows']
    if args.trace:sys.argv.append('--trace')
    try:vpn.main()
    finally:
        assert hashes=={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in closure}
        if args.output.exists():
            for p in closure:(args.output/('regression-source-'+str(p.relative_to(ROOT)).replace('/','__'))).write_bytes(p.read_bytes())
            (args.output/'s317-directed-regression-qualification.json').write_text(json.dumps(dict(
                scope='S317 current artifact directed regression of existing S316 ordinary VPN UDP behavior',
                reused_entry='tests/device/s316-vpn-dns-proxy.py',owned_peer_ports=[53053],
                original_port53_independent=True,source_sha256=hashes),indent=2)+'\n')


if __name__=='__main__':main()
