#!/usr/bin/env python3

import argparse
import json
import os
import pathlib
import signal
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATE_DIR = ROOT / "build-output" / "vscode-debug"
PID_FILE = STATE_DIR / "helper.pid"
KEEPALIVE_PID_FILE = STATE_DIR / "keepalive.pid"
FIFO_FILE = STATE_DIR / "helper.stdin"
MODE_FILE = STATE_DIR / "mode.txt"
WORKSPACE_ROOT_FILE = STATE_DIR / "workspace-root.txt"
SKIP_FIRST_PRERUN_FILE = STATE_DIR / "skip-first-pre-run"

READY_MARKER = "Generated config written to"
DEFAULT_TIMEOUT_SECONDS = 120


def run_command(step: str, command: List[str]) -> None:
    print(step, flush=True)
    print("命令:", " ".join(json.dumps(part) for part in command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def workflow(mode: str, timeout_seconds: int) -> int:
    cleanup(silent=True)

    if mode == "run":
        run_command("[1/3] 增量构建真机二进制...", ["bash", str(ROOT / "dev" / "dev-build.sh")])
        run_command(
            "[2/3] 预部署到真机（不启动守护进程）...",
            ["bash", str(ROOT / "dev" / "dev-deploy.sh"), "--stage-only"],
        )
        print("[3/3] 准备 LLDB run 会话...", flush=True)
        return prepare("run", timeout_seconds)

    print("[1/1] 准备 LLDB attach 会话...", flush=True)
    return prepare("attach", timeout_seconds)


def state_paths(mode: str) -> Dict[str, pathlib.Path]:
    return {
        "log": STATE_DIR / f"{mode}.log",
        "generated_launch": STATE_DIR / f"{mode}-generated-launch.json",
        "init_commands": STATE_DIR / f"{mode}-init.lldb",
        "target_commands": STATE_DIR / f"{mode}-target-create.lldb",
        "process_commands": STATE_DIR / f"{mode}-process-create.lldb",
        "pre_run_commands": STATE_DIR / f"{mode}-pre-run.lldb",
        "pre_terminate_commands": STATE_DIR / f"{mode}-pre-terminate.lldb",
    }


def current_mode() -> Optional[str]:
    if not MODE_FILE.exists():
        return None
    text = MODE_FILE.read_text(encoding="utf-8").strip()
    return text or None


def resolve_workspace_root_hint() -> str:
    env_value = os.environ.get("SNORT_VSCODE_WORKSPACE_ROOT", "").strip()
    if env_value:
        return env_value
    if WORKSPACE_ROOT_FILE.exists():
        file_value = WORKSPACE_ROOT_FILE.read_text(encoding="utf-8").strip()
        if file_value:
            return file_value
    return str(ROOT)


def read_pid(path: pathlib.Path) -> Optional[int]:
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return None
    return int(text)


def process_alive(pid: Optional[int]) -> bool:
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def kill_process_group(pid: Optional[int], sig: int) -> None:
    if pid is None:
        return
    try:
        os.killpg(pid, sig)
    except ProcessLookupError:
        return


def remove_if_exists(path: pathlib.Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def strip_json_comments(text: str) -> str:
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("//")
    )


def load_generated_config(path: pathlib.Path) -> Dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    cleaned = strip_json_comments(raw)
    data = json.loads(cleaned)
    configs = data.get("configurations", [])
    if not configs:
        raise RuntimeError(f"未在 {path} 中找到生成的 CodeLLDB 配置")
    return configs[0]


def write_command_file(path: pathlib.Path, commands: List[str]) -> None:
    lines = [cmd for cmd in commands if cmd]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def render_source_map_commands(config: Dict[str, Any]) -> List[str]:
    source_map = config.get("sourceMap", {})
    if not isinstance(source_map, dict):
        return []

    commands: List[str] = []
    for source_prefix, replacement in source_map.items():
        if not source_prefix or not replacement:
            continue
        commands.append(
            "settings append target.source-map "
            f"{json.dumps(str(source_prefix))} {json.dumps(str(replacement))}"
        )
    return commands


def render_target_reset_commands(config: Dict[str, Any]) -> List[str]:
    commands: List[str] = []
    source_map = config.get("sourceMap", {})
    init_commands = config.get("initCommands", [])

    if isinstance(source_map, dict) and source_map:
        commands.append("settings clear target.source-map")
    if any(
        cmd.startswith("settings append target.exec-search-paths")
        for cmd in init_commands
        if isinstance(cmd, str)
    ):
        commands.append("settings clear target.exec-search-paths")

    return commands


def render_hook_command(mode: str, event: str) -> str:
    command = [
        "python3",
        str(ROOT / "dev" / "dev-vscode-debug-task.py"),
        "hook",
        mode,
        event,
    ]
    return (
        "script import subprocess; subprocess.run("
        + json.dumps(command)
        + ", check=True, cwd="
        + json.dumps(str(ROOT))
        + ")"
    )


def materialize_lldb_command_files(mode: str) -> None:
    paths = state_paths(mode)
    config = load_generated_config(paths["generated_launch"])
    source_map_commands = render_source_map_commands(config)
    target_commands = config.get("targetCreateCommands", [])
    init_commands = list(config.get("initCommands", []))
    process_commands = list(config.get("processCreateCommands", []))

    # Suppress SIGCHLD noise caused by child processes (iptables, etc.).
    # This keeps VS Code sessions stable while still delivering SIGCHLD to the
    # debuggee.
    if mode in {"attach", "run"}:
        process_commands.insert(0, "process handle SIGCHLD -n false -p true -s false")

    if mode == "run":
        init_commands.insert(0, "settings set target.skip-prologue false")
        # VS Code/CodeLLDB typically installs source breakpoints *after* the
        # remote connection is established. We must keep the default SIGSTOP
        # handling (stop at startup), otherwise the debuggee may run past early
        # breakpoints (e.g. main) before VS Code applies them.

    write_command_file(paths["init_commands"], source_map_commands + init_commands)
    write_command_file(paths["target_commands"], target_commands)
    write_command_file(paths["process_commands"], process_commands)

    # NOTE: preRunCommands will run before *every* launch/restart in CodeLLDB.
    # We must not recreate the target here, otherwise VS Code's breakpoints
    # (already installed on the target by the debug adapter) will be lost.
    write_command_file(
        paths["pre_run_commands"],
        [render_hook_command(mode, "pre-run")],
    )

    write_command_file(
        paths["pre_terminate_commands"],
        [render_hook_command(mode, "pre-terminate")],
    )


def tail_log(path: pathlib.Path, lines: int = 40) -> str:
    if not path.exists():
        return "<no log>"
    content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(content[-lines:])


def clear_state_files() -> None:
    remove_if_exists(PID_FILE)
    remove_if_exists(KEEPALIVE_PID_FILE)
    remove_if_exists(MODE_FILE)
    remove_if_exists(WORKSPACE_ROOT_FILE)
    remove_if_exists(FIFO_FILE)
    remove_if_exists(SKIP_FIRST_PRERUN_FILE)
    for path in STATE_DIR.glob("hook-*.status"):
        remove_if_exists(path)


def cleanup(silent: bool = False) -> int:
    pid = read_pid(PID_FILE)
    keepalive_pid = read_pid(KEEPALIVE_PID_FILE)

    if process_alive(pid) and FIFO_FILE.exists():
        try:
            with FIFO_FILE.open("w", encoding="utf-8") as fifo:
                fifo.write("\n")
                fifo.flush()
        except OSError:
            pass

    deadline = time.time() + 5
    while process_alive(pid) and time.time() < deadline:
        time.sleep(0.2)

    if process_alive(pid):
        kill_process_group(pid, signal.SIGTERM)
        time.sleep(0.5)
    if process_alive(pid):
        kill_process_group(pid, signal.SIGKILL)

    if process_alive(keepalive_pid):
        kill_process_group(keepalive_pid, signal.SIGTERM)
        time.sleep(0.2)
    if process_alive(keepalive_pid):
        kill_process_group(keepalive_pid, signal.SIGKILL)

    clear_state_files()

    if not silent:
        print("sucre-snort VS Code debug helper cleaned up")
    return 0


def prepare(mode: str, timeout_seconds: int) -> int:
    cleanup(silent=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    workspace_root_hint = resolve_workspace_root_hint()
    WORKSPACE_ROOT_FILE.write_text(workspace_root_hint + "\n", encoding="utf-8")

    paths = state_paths(mode)
    for path in paths.values():
        remove_if_exists(path)
    remove_if_exists(FIFO_FILE)
    os.mkfifo(FIFO_FILE)

    keepalive = subprocess.Popen(
        ["bash", "-lc", f"exec tail -f /dev/null > {FIFO_FILE}"],
        cwd=ROOT,
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    KEEPALIVE_PID_FILE.write_text(f"{keepalive.pid}\n", encoding="utf-8")

    log_handle = paths["log"].open("w", encoding="utf-8")
    fifo_reader = FIFO_FILE.open("r", encoding="utf-8")
    helper_env = os.environ.copy()
    helper_env["SNORT_VSCODE_WORKSPACE_ROOT"] = workspace_root_hint

    helper = subprocess.Popen(
        [
            "bash",
            str(ROOT / "dev" / "dev-native-debug.sh"),
            f"vscode-helper-{mode}",
            "--launch-file",
            str(paths["generated_launch"]),
        ],
        cwd=ROOT,
        env=helper_env,
        stdin=fifo_reader,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    PID_FILE.write_text(f"{helper.pid}\n", encoding="utf-8")
    MODE_FILE.write_text(mode + "\n", encoding="utf-8")

    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if not process_alive(helper.pid):
            log_handle.flush()
            fifo_reader.close()
            log_handle.close()
            print(tail_log(paths["log"]), file=sys.stderr)
            cleanup(silent=True)
            return 1

        if paths["generated_launch"].exists():
            try:
                materialize_lldb_command_files(mode)
            except (json.JSONDecodeError, RuntimeError):
                pass
            else:
                SKIP_FIRST_PRERUN_FILE.write_text(mode + "\n", encoding="utf-8")
                print(f"sucre-snort VS Code debug helper ready ({mode})")
                print(f"log: {paths['log']}")
                print(f"generated launch: {paths['generated_launch']}")
                print(f"init commands: {paths['init_commands']}")
                return 0
        time.sleep(0.5)

    log_handle.flush()
    fifo_reader.close()
    log_handle.close()
    print(tail_log(paths["log"]), file=sys.stderr)
    cleanup(silent=True)
    return 1


def send_helper_command(action: str, timeout_seconds: int, allow_missing: bool = False) -> int:
    pid = read_pid(PID_FILE)
    if not process_alive(pid) or not FIFO_FILE.exists():
        if allow_missing:
            return 0
        raise RuntimeError("VS Code debug helper 未运行")

    token = f"{int(time.time() * 1000)}-{os.getpid()}"
    ack_path = STATE_DIR / f"hook-{token}.status"
    remove_if_exists(ack_path)

    try:
        with FIFO_FILE.open("w", encoding="utf-8") as fifo:
            fifo.write(f"{action} {token}\n")
            fifo.flush()
    except OSError as exc:
        if allow_missing:
            return 0
        raise RuntimeError(f"无法发送 helper 命令 {action}: {exc}") from exc

    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if ack_path.exists():
            status = ack_path.read_text(encoding="utf-8", errors="replace").strip()
            remove_if_exists(ack_path)
            if status == "ok":
                return 0
            raise RuntimeError(status or f"helper 命令 {action} 返回空状态")
        if not process_alive(pid):
            if allow_missing:
                return 0
            raise RuntimeError(f"helper 在处理 {action} 之前已经退出")
        time.sleep(0.2)

    raise RuntimeError(f"等待 helper 执行 {action} 超时")


def hook(mode: str, event: str, timeout_seconds: int) -> int:
    active_mode = current_mode()
    if active_mode is not None and active_mode != mode:
        print(
            f"当前 helper 模式为 {active_mode}，与请求模式 {mode} 不一致",
            file=sys.stderr,
        )
        return 1

    if event == "pre-run":
        if SKIP_FIRST_PRERUN_FILE.exists():
            remove_if_exists(SKIP_FIRST_PRERUN_FILE)
            print(f"skip initial pre-run hook ({mode})")
            return 0

        if not process_alive(read_pid(PID_FILE)):
            if mode == "run":
                run_command("[restart 1/3] 增量构建真机二进制...", ["bash", str(ROOT / "dev" / "dev-build.sh")])
                run_command(
                    "[restart 2/3] 预部署到真机（不启动守护进程）...",
                    ["bash", str(ROOT / "dev" / "dev-deploy.sh"), "--stage-only"],
                )
            print(f"[restart {'3/3' if mode == 'run' else '1/1'}] 重建 VS Code debug helper 会话...", flush=True)
            result = prepare(mode, timeout_seconds)
            if result == 0:
                remove_if_exists(SKIP_FIRST_PRERUN_FILE)
            return result

        if mode == "run":
            run_command("[restart 1/2] 增量构建真机二进制...", ["bash", str(ROOT / "dev" / "dev-build.sh")])
            run_command(
                "[restart 2/2] 预部署到真机（不启动守护进程）...",
                ["bash", str(ROOT / "dev" / "dev-deploy.sh"), "--stage-only"],
            )

        try:
            return send_helper_command("restart", timeout_seconds)
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    if event == "pre-terminate":
        try:
            return send_helper_command("terminate", timeout_seconds, allow_missing=True)
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    print(f"未知 hook 事件: {event}", file=sys.stderr)
    return 1


def status() -> int:
    pid = read_pid(PID_FILE)
    mode = current_mode() or "<none>"
    print(f"mode: {mode}")
    print(f"helper pid: {pid if pid is not None else '<none>'}")
    print(f"running: {'yes' if process_alive(pid) else 'no'}")
    print(f"workspace-root: {resolve_workspace_root_hint()}")
    print(f"skip-initial-pre-run: {'yes' if SKIP_FIRST_PRERUN_FILE.exists() else 'no'}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage sucre-snort VS Code debug helper")
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("mode", choices=["attach", "run"])
    prepare_parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)

    workflow_parser = subparsers.add_parser("workflow")
    workflow_parser.add_argument("mode", choices=["attach", "run"])
    workflow_parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)

    hook_parser = subparsers.add_parser("hook")
    hook_parser.add_argument("mode", choices=["attach", "run"])
    hook_parser.add_argument("event", choices=["pre-run", "pre-terminate"])
    hook_parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)

    subparsers.add_parser("cleanup")
    subparsers.add_parser("status")

    args = parser.parse_args()

    if args.command == "prepare":
        return prepare(args.mode, args.timeout)
    if args.command == "workflow":
        return workflow(args.mode, args.timeout)
    if args.command == "hook":
        return hook(args.mode, args.event, args.timeout)
    if args.command == "cleanup":
        return cleanup()
    if args.command == "status":
        return status()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
