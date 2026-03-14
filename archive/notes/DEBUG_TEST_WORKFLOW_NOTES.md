# Debug/Test Workflow Notes (sucre-snort)

Date: 2026-03-14

This is a raw “working notes” dump from bringing up a **real-device** debug + test workflow for `sucre-snort` in a **WSL2 + VS Code** environment.
It is intentionally kept under `archive/` and is **not** referenced by the main docs. Use it as a memory jogger when similar issues reappear.

## Context

- Host: VS Code Remote (WSL2), Debian 11
- Debugger: CodeLLDB (`vadimcn.vscode-lldb`) + device-side `arm64-lldb-server gdbserver`
- Build: still uses LineageOS/AOSP build outputs; CMake is a **wrapper entrypoint** (delegated build).
- Target: rooted real device (adb + `su` available)

## Lessons / Gotchas (symptom → cause → fix)

### 1) “Breakpoints don’t hit”, especially at `main`

**Symptom**
- VS Code shows breakpoints set, but the process never stops at `main` (or early startup code).

**Root cause**
- In CodeLLDB, source breakpoints are often installed **after** the `gdb-remote` connection is established.
- If we **ignore the initial SIGSTOP** from `lldb-server gdbserver`, the debuggee may continue running and pass `main` before VS Code has applied breakpoints.

**Fix**
- Keep the default SIGSTOP handling (stop-at-startup).
- It’s OK if the first stop is in the loader/linker (assembly). Just Continue once; breakpoints are already installed by then.

### 2) Tons of SIGCHLD noise (iptables, child processes)

**Symptom**
- Debugger constantly stops on SIGCHLD; stepping becomes painful.

**Fix**
- In the LLDB command sequence:
  - `process handle SIGCHLD -n false -p true -s false`
  - (Pass SIGCHLD to the program, but don’t stop/notify in the debugger.)

### 3) “No symbol info / Source: unknown”, only disassembly

**Symptom**
- Breakpoints show `no symbol info`, stack frames show `unknown`, can only see assembly.

**Root cause**
- Target binary on-device is usually **stripped** (or not the same file LLDB loaded symbols from).
- Some line-table tools (`readelf`, `llvm-dwarfdump`) can also complain about compressed DWARF, even though LLDB can still read it.

**Fix checklist**
- Prefer an **unstripped** host binary (e.g. `build-output/sucre-snort.debug`) and ensure it matches the on-device executable by Build-ID.
- Add AOSP symbols root for shared libs:
  - `target modules search-paths add / $LINEAGE_ROOT/out/target/product/<device>/symbols/`
- Add reasonable `target.exec-search-paths` under `$.../symbols/system/lib64` and `$.../symbols/vendor/lib64` etc.

### 4) Breakpoints show as “pending”

**Symptom**
- Breakpoints exist but have no locations; VS Code never stops.

**Root cause**
- DWARF compile-unit paths are typically `system/sucre-snort/src/...` (or `/b/f/w/system/sucre-snort/...`), while VS Code sets breakpoints using the workspace path.

**Fix**
- Add `sourceMap` mapping those prefixes back to the workspace root:
  - `system/sucre-snort -> <workspaceRoot>`
  - `/b/f/w/system/sucre-snort -> <workspaceRoot>`
- If the workspace is opened via a symlink (e.g. `/home/js/Git/sucre/sucre-snort`), pass the exact VS Code `${workspaceFolder}` down to the backend (so generated `sourceMap` matches what VS Code uses).

### 5) `preRunCommands` can silently delete your breakpoints

**Symptom**
- You can hit breakpoints in a manual LLDB session, but VS Code can’t.

**Root cause**
- CodeLLDB executes `preRunCommands` on every launch/restart.
- If `preRunCommands` does `target create`, `settings clear target.source-map`, etc., it can recreate/reset the target and **wipe VS Code-installed breakpoints**.

**Fix**
- `preRunCommands` must be *hook-only* (lifecycle coordination), not target recreation.
- Target creation belongs in `targetCreateCommands`.

### 6) VS Code “Restart” fails: “no debuggee available, cannot send restart”

**Symptom**
- First F5 works; clicking the Restart button fails with “cannot send restart”.

**Root cause**
- `preTerminateCommands` (which runs on restart) can kill/tear down the debuggee too aggressively, causing the debug session to die before VS Code can issue `restart`.

**Fix**
- Handle restart cleanup in `preRunCommands` (helper does device cleanup + relaunch).
- Rely on `postDebugTask` for Stop cleanup.

### 7) “Residue” from previous sessions (TracerPid, lldb-server leftovers)

**Symptom**
- New sessions hang, attach fails, deploy says process exists but can’t talk to it.

**Fix checklist**
- Kill device-side residues:
  - old `arm64-lldb-server` / `lldb-server` / `gdbserver`
  - leftover port forwarding (`adb forward --remove`)
  - if a process has `TracerPid != 0`, kill the tracer and `kill -CONT` the tracee
- For run-mode, prefer “stage-only deploy” then “run-under-debugger” to avoid starting/kill loops.

## Practical triage commands

- Check helper state:
  - `python3 dev/dev-vscode-debug-task.py status`
- Inspect the generated LLDB command files:
  - `cat build-output/vscode-debug/run-init.lldb`
  - `cat build-output/vscode-debug/run-target-create.lldb`
  - `cat build-output/vscode-debug/run-process-create.lldb`
- Check device-side debugger log:
  - `adb shell su -c 'tail -n 200 /data/local/tmp/lldb-server.log'`

## “Good defaults” we converged on

- Keep startup SIGSTOP (don’t auto-continue).
- Set `target.skip-prologue=false` so breakpoints at function entry behave as expected.
- Always generate + use a Build-ID-matched unstripped symbol binary.
- Keep `preRunCommands` hook-only.
- Treat Restart as “rebuild/redeploy/relaunch” via pre-run hook; Stop cleanup via post-debug task.

