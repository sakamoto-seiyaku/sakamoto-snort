#!/usr/bin/env python3
"""Qualify real VPN counter boundaries and preserve a deleted native log inode."""
from pathlib import Path
import subprocess
import tempfile

import pixel_quick as quick


def rejects(operation):
    try:
        operation()
    except RuntimeError:
        return
    raise AssertionError("invalid evidence accepted")


before = ("tun.status generation=42 enabled=1 attached=1 captured=12\n"
          "flow_stack.status generation=42 owner=0 ready=1\n"
          "flow_stack.status generation=42 owner=1 ready=1\n"
          "flow.protocol protocol=tcp creates=3\n")
after = before.replace("captured=12", "captured=40").replace("creates=3", "creates=4")
client = {"case": "tcp-new", "completed": 1}
quick.validate_vpn_window(42, client, before, after)
for bad in (before, after.replace("42", "43"), after.replace("owner=1", "owner=0"),
            after.replace("ready=1", "ready=0"), after.replace("creates=4", "creates=3")):
    rejects(lambda: quick.validate_vpn_window(42, client, before, bad))

owners = [f"s237 event=owner_stopped generation=42 owner={owner} sessions=0 inputs=0 pbufs=0 "
          "sockets_created=10 sockets_closed=10 timer_fd=-1 broker_fd=-1 buffers=0 obligations=0 frames=0\n"
          for owner in range(2)]
stop = "".join(owners) + "s213 event=stop generation=42 pending=0 buffers=0 frames=0 obligations=0 tun_fd=-1\n"
quick.validate_vpn_stop(stop, 42)
for bad in (stop.replace("42", "41"), stop.replace("inputs=0", "inputs=1"),
            stop.replace("sockets_closed=10", "sockets_closed=9"),
            stop.replace(owners[1], ""), stop.replace("tun_fd=-1", "tun_fd=5")):
    rejects(lambda: quick.validate_vpn_stop(bad, 42))

# Execute the collector's actual shell reader. Unlink the log while its writer
# remains open, append the stop records, then read the held inode after exit.
with tempfile.TemporaryDirectory(prefix="vpn-log-reader-") as folder:
    root = Path(folder)
    native = root / "native.log"
    native.write_text("start\n")
    device = quick.Device("unused", root)
    original = "/data/data/" + quick.PACKAGE + "/files/profiles/vpn/vpp/logs/vpp-stdout.log"

    def local_root(command, **kwargs):
        return subprocess.run(command.replace(original, str(native)), shell=True, check=True,
                              text=True, stdout=subprocess.PIPE, timeout=kwargs.get("timeout", 5)).stdout

    device.root = local_root
    destination = str(root / "retained.log")
    device.retain_vpn_log(destination)
    with native.open("a") as writer:
        native.unlink()
        writer.write(stop)
    raw = device.read_retained_vpn_log(destination)
    assert raw == "start\n" + stop
    quick.validate_vpn_stop(raw, 42)

print("VPN generation, progress, native debts and deleted-log retention: PASS")
