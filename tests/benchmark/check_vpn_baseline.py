#!/usr/bin/env python3
"""Qualify real VPN counter boundaries and preserve a deleted native log inode."""
from pathlib import Path
import subprocess
import tempfile

import pixel_quick as quick
import s304_summary


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
three_before = before + "flow_stack.status generation=42 owner=2 ready=1\n"
three_after = after + "flow_stack.status generation=42 owner=2 ready=1\n"
quick.validate_vpn_window(42, client, three_before, three_after, owner_count=3)
rejects(lambda: quick.validate_vpn_window(42, client, before, after, owner_count=3))
for bad in (before, after.replace("42", "43"), after.replace("owner=1", "owner=0"),
            after.replace("ready=1", "ready=0"), after.replace("creates=4", "creates=3")):
    rejects(lambda: quick.validate_vpn_window(42, client, before, bad))

owners = [f"s237 event=owner_stopped generation=42 owner={owner} sessions=0 inputs=0 pbufs=0 "
          "sockets_created=10 sockets_closed=10 timer_fd=-1 broker_fd=-1 buffers=0 obligations=0 frames=0\n"
          for owner in range(2)]
stop = "".join(owners) + "s213 event=stop generation=42 pending=0 buffers=0 frames=0 obligations=0 tun_fd=-1\n"
quick.validate_vpn_stop(stop, 42)
three_stop = stop.replace("s213 event=stop ", owners[0].replace("owner=0", "owner=2") + "s213 event=stop ")
quick.validate_vpn_stop(three_stop, 42, owner_count=3)
rejects(lambda: quick.validate_vpn_stop(stop, 42, owner_count=3))
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

old_layout = [dict(id=i, name=name, lcore=cpu) for i, (name, cpu) in enumerate(
    (("vpp_main", 0), ("vpp_wk_0", 1), ("vpp_wk_1", 2)))]
new_layout = old_layout + [dict(id=3, name="vpp_wk_2", lcore=3)]
quick.validate_vpn_layout(old_layout, [1, 2], None, "")
saved_layout = [dict(id=i, name=name, lcore=cpu) for i, (name, cpu) in enumerate(
    (("vpp_main", 0), ("vpp_wk_0", 2), ("vpp_wk_1", 3)))]
quick.validate_vpn_layout(saved_layout, None, None, "")
topology = ("topology.profile=vpn owner_count=2 vpp_worker_count=3 actual_vpp_workers=3 ready=1\n"
            "topology.tun_io_lane=0 worker=2 thread_index=3 actual_core=3 is_flow_owner=0\n"
            "topology.owner=0 thread_index=1 actual_core=1\n"
            "topology.owner=1 thread_index=2 actual_core=2\n")
quick.validate_vpn_layout(new_layout, [1, 2], 3, topology)
for bad_layout, bad_topology in ((old_layout, topology), (new_layout, topology.replace("is_flow_owner=0", "is_flow_owner=1")),
                                  (new_layout, topology.replace("actual_core=3", "actual_core=2"))):
    rejects(lambda: quick.validate_vpn_layout(bad_layout, [1, 2], 3, bad_topology))
rejects(lambda: s304_summary.counter_delta('primary.rejection credit=0\n',
                                           'unrelated counter=0\n', 'primary.rejection ', 'credit'))
rejects(lambda: s304_summary.counter_delta('primary.rejection credit=0\n',
                                           'primary.rejection enqueue=0\n', 'primary.rejection ', 'credit'))

print("VPN generation, progress, native debts and deleted-log retention: PASS")
