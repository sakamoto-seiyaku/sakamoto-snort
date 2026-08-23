#!/usr/bin/env python3
"""Bounded real OI-5 host fault -> epoch advance -> fresh restart run."""

import os
import subprocess
import time

VPP = "/tmp/s119-vpp-build/bin/vpp"
VPPCTL = "/tmp/s119-vpp-build/bin/vppctl"
ROOT = "/tmp/sakamoto-vpp-nfq-poc"
CONF = os.path.join(ROOT, "s130-oi5-fault.conf")
CLI = os.path.join(ROOT, "s130-oi5-fault-cli.sock")
CONSOLE = os.path.join(ROOT, "s130-oi5-fault-console.log")
HEV = "/tmp/oi1-hev/bin/libhev-socks5-tunnel.so"

os.makedirs(ROOT, exist_ok=True)
with open(CONF, "w", encoding="utf-8") as config:
    config.write(f"""unix {{
  nodaemon
  nobanner
  full-coredump
  runtime-dir {ROOT}/s130-oi5-fault-run
  poll-sleep-usec 1000
  log {ROOT}/s130-oi5-fault-vpp.log
  cli-listen {CLI}
}}
cpu {{ workers 2 }}
api-segment {{ prefix sakamoto-vpp-nfq-poc-s130-fault }}
statseg {{ socket-name {ROOT}/s130-oi5-fault-statseg.sock }}
buffers {{ page-size default }}
plugins {{
  path /tmp/s119-vpp-build/lib/x86_64-linux-gnu/vpp_plugins
  plugin default {{ disable }}
  plugin hev_external_driver_poc_plugin.so {{ enable }}
}}
""")

env = os.environ.copy()
env["LD_LIBRARY_PATH"] = ":".join([
    "/tmp/oi1-hev/bin",
    "/tmp/oi1-hev/third-part/hev-task-system/bin",
    "/tmp/oi1-hev/third-part/lwip/bin",
    "/tmp/oi1-hev/third-part/yaml/bin",
])


def cli(command: str) -> str:
    result = subprocess.run(
        [VPPCTL, "-s", CLI],
        input=(command + "\n").encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    output = result.stdout.decode(errors="replace")
    print(f"{command} => {output}", flush=True)
    return output


with open(CONSOLE, "wb") as log:
    process = subprocess.Popen(
        [VPP, "-c", CONF], env=env, stdout=log, stderr=subprocess.STDOUT
    )
    try:
        for _ in range(150):
            if os.path.exists(CLI):
                if "vpp" in cli("show version").lower():
                    break
            time.sleep(0.1)
        else:
            raise RuntimeError("VPP CLI did not become ready")

        # Generation 1: active UDP timer/no-reply flow, then an explicit
        # bounded FlowStackOwner fault before it can naturally settle.
        cli(f"sakamoto-oi3 run cell no-reply target-thread 1 lib {HEV}")
        cli("sakamoto-oi3 fault")
        time.sleep(1.0)
        cli("show sakamoto-oi3")

        # Generation 2: fresh TCP handshake/payload/FIN on a new underlay
        # epoch, proving the restart is accepted only after generation 1 is
        # inactive and its owner resources have settled.
        cli(f"sakamoto-oi3 run cell tcp4 target-thread 1 lib {HEV}")
        time.sleep(5.0)
        cli("show sakamoto-oi3")
    finally:
        try:
            cli("sakamoto-oi3 stop")
        except Exception:
            pass
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

print(f"console={CONSOLE}")
