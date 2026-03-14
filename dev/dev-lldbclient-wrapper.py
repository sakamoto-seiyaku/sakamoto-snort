#!/usr/bin/env python3

import os
import runpy
import shlex
import subprocess
import sys
import tempfile

import adb
import gdbrunner


_SHELL_OPERATORS = {">", ">>", "<", "<<", "|", "||", "&&", ";"}


def _join_shell_tokens(tokens: list[str]) -> str:
    rendered = []
    for token in tokens:
        if token in _SHELL_OPERATORS:
            rendered.append(token)
        else:
            rendered.append(shlex.quote(token))
    return " ".join(rendered)


def _rewrite_su_command(cmd: list[str]) -> list[str]:
    if len(cmd) >= 3 and cmd[0] == "su" and cmd[1] != "-c":
        inner = _join_shell_tokens(cmd[2:])
        return ["su", "-c", inner]
    return cmd


_original_shell_nocheck = adb.AndroidDevice.shell_nocheck
_original_shell_popen = adb.AndroidDevice.shell_popen
_original_find_file = gdbrunner.find_file
_original_find_binary = gdbrunner.find_binary
_original_start_gdbserver = gdbrunner.start_gdbserver
_original_forward_gdbserver_port = gdbrunner.forward_gdbserver_port


def _patched_shell_nocheck(self, cmd):
    return _original_shell_nocheck(self, _rewrite_su_command(cmd))


def _patched_shell_popen(self, cmd, *args, **kwargs):
    return _original_shell_popen(self, _rewrite_su_command(cmd), *args, **kwargs)


def _open_local_mirror(sysroot: str, executable_path: str):
    if not executable_path.startswith("/data/local/tmp/"):
        return None

    local_path = sysroot + executable_path
    if os.path.isfile(local_path):
        return open(local_path, "rb"), True
    return None


def _patched_find_file(device, executable_path, sysroot, run_as_cmd=None):
    mirrored = _open_local_mirror(sysroot, executable_path)
    if mirrored is not None:
        return mirrored
    return _original_find_file(device, executable_path, sysroot, run_as_cmd)


def _patched_find_binary(device, pid, sysroot, run_as_cmd=None):
    cmd = ["readlink", "-e", "-n", f"/proc/{pid}/exe"]
    if run_as_cmd:
        cmd = run_as_cmd + cmd
    try:
        output, _ = device.shell(cmd)
        mirrored = _open_local_mirror(sysroot, output.strip())
        if mirrored is not None:
            return mirrored
    except Exception:
        pass
    return _original_find_binary(device, pid, sysroot, run_as_cmd)


def _patched_start_gdbserver(
    device,
    gdbserver_local_path,
    gdbserver_remote_path,
    target_pid,
    run_cmd,
    debug_socket,
    port,
    run_as_cmd=[],
    lldb=False,
    chroot="",
    cwd="",
):
    if not lldb or gdbrunner.get_uid(device) == 0:
        return _original_start_gdbserver(
            device,
            gdbserver_local_path,
            gdbserver_remote_path,
            target_pid,
            run_cmd,
            debug_socket,
            port,
            run_as_cmd,
            lldb,
            chroot,
            cwd,
        )

    if chroot:
        if cwd:
            raise ValueError("chroot and cwd cannot be set together")
        run_as_cmd = ["chroot", chroot] + run_as_cmd

    device.shell_nocheck(run_as_cmd + ["rm", debug_socket])

    if gdbserver_local_path is not None:
        try:
            device.push(gdbserver_local_path, chroot + gdbserver_remote_path)
            device.shell(["chmod", "+x", gdbserver_remote_path])
        except subprocess.CalledProcessError as err:
            print("Command failed:")
            print(shlex.join(err.cmd))
            print("Output:")
            print(err.output.decode("utf-8"))
            raise

    gdbserver_cmd = [gdbserver_remote_path, "gdbserver", f"localhost:{port}"]
    if target_pid is not None:
        gdbserver_cmd += ["--attach", str(target_pid)]
    else:
        gdbserver_cmd += ["--"] + run_cmd

    _original_forward_gdbserver_port(device, local=port, remote=f"tcp:{port}")
    gdbserver_cmd = run_as_cmd + gdbserver_cmd

    gdbserver_output_path = os.path.join(tempfile.gettempdir(), "lldb-client.log")
    print(f"Redirecting lldb-server output to {gdbserver_output_path}")
    gdbserver_output = open(gdbserver_output_path, "w")

    if cwd:
        gdbserver_cmd = ["cd", cwd, "&&"] + gdbserver_cmd
    return device.shell_popen(gdbserver_cmd, stdout=gdbserver_output, stderr=gdbserver_output)


adb.AndroidDevice.shell_nocheck = _patched_shell_nocheck
adb.AndroidDevice.shell_popen = _patched_shell_popen
gdbrunner.find_file = _patched_find_file
gdbrunner.find_binary = _patched_find_binary
gdbrunner.start_gdbserver = _patched_start_gdbserver


if len(sys.argv) < 2:
    raise SystemExit("usage: dev-lldbclient-wrapper.py <lldbclient.py> [args...]")

lldbclient_path = sys.argv[1]
sys.argv = [lldbclient_path, *sys.argv[2:]]
runpy.run_path(lldbclient_path, run_name="__main__")
