#!/usr/bin/env python3
"""PROTOTYPE — relink only libvlib with an experimental duplicate-CPU fix."""
import hashlib
from pathlib import Path
import shlex
import subprocess


REPO = Path(__file__).resolve().parents[4]
SOURCE = REPO / "build-output/s220-20260913/host-stage-b/source"
BUILD = SOURCE / "build-root/build-vpp-native/vpp"
CACHE = REPO / "build-output/product-build-cache/prototype-tun-io"
LIBRARY = CACHE / "libvlib.so.26.02"
STAMP = CACHE / "patched-vlib.sha256"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build():
    CACHE.mkdir(parents=True, exist_ok=True)
    source = SOURCE / "src/vlib/threads.c"
    identity = hashlib.sha256((sha(source) + sha(Path(__file__))).encode()).hexdigest()
    if LIBRARY.exists() and STAMP.exists() and STAMP.read_text().strip() == identity:
        return False

    text = source.read_text()
    duplicate_check = """      for (u32 i = 0; i < vec_len (ordered_worker_cpus); i++)
        if (ordered_worker_cpus[i] == cpu)
          return clib_error_return (0, "ordered-workers: duplicate CPU %u", cpu);
"""
    if text.count(duplicate_check) != 1:
        raise RuntimeError("pinned duplicate-CPU parser changed")
    text = text.replace(duplicate_check, "")
    marker = "          u32 placement_index = 0;"
    if text.count(marker) != 1:
        raise RuntimeError("pinned ordered-worker launch changed")
    before, after = text.split(marker, 1)
    start = before.rfind("      else\n\t{\n\t  uword c;\n")
    end = after.find("\n\t}\n    }\n  vlib_worker_thread_barrier_sync")
    if start < 0 or end < 0:
        raise RuntimeError("pinned worker launch structure changed")
    replacement = """      else if (tr == ordered_worker_registration)
        {
          /* Prototype: an ordered list has one entry per thread, including
           * repeated CPU IDs. The bitmap still records distinct reserved CPUs. */
          for (u32 i = 0; i < vec_len (ordered_worker_cpus); i++)
            {
              u32 cpu = ordered_worker_cpus[i];
              w = vlib_worker_threads + worker_thread_index++;
              err = vlib_launch_thread_int (vlib_worker_thread_bootstrap_fn,
                                            w, cpu);
              if (err)
                clib_unix_error ("%U, thread %s init on cpu %d failed",
                                 format_clib_error, err, tr->name, cpu);
            }
        }
      else
        {
          uword c;
          clib_bitmap_foreach (c, tr->coremask)
            {
              w = vlib_worker_threads + worker_thread_index++;
              err = vlib_launch_thread_int (vlib_worker_thread_bootstrap_fn,
                                            w, c);
              if (err)
                clib_unix_error ("%U, thread %s init on cpu %d failed",
                                 format_clib_error, err, tr->name, c);
            }
        }"""
    text = before[:start] + replacement + after[end + len("\n\t}"):]
    patched = CACHE / "threads-allow-duplicate.c"
    patched.write_text(text)

    commands = subprocess.check_output(
        ["ninja", "-C", str(BUILD), "-t", "commands", "libvlib.so"],
        text=True).splitlines()
    compile_line = next(line for line in commands if "threads.c.o -c " in line)
    link_line = next(line for line in commands
                     if " -o lib/x86_64-linux-gnu/libvlib.so.26.02 " in line)
    old_prefix = str(REPO / "build-output/s220-20260913/.host-stage-b.building/source")
    compile_args = shlex.split(compile_line.replace(old_prefix, str(SOURCE)))
    compile_args = ["/usr/bin/clang", *compile_args[2:]]  # no global ccache writes
    old_object = "CMakeFiles/vlib/CMakeFiles/vlib_objs.dir/threads.c.o"
    new_object = str(CACHE / "threads-allow-duplicate.c.o")
    for i, arg in enumerate(compile_args):
        if arg == old_object:
            compile_args[i] = new_object
        if arg == "CMakeFiles/vlib/CMakeFiles/vlib_objs.dir/threads.c.o.d":
            compile_args[i] = str(CACHE / "threads-allow-duplicate.c.o.d")
    compile_args[-1] = str(patched)
    subprocess.run(compile_args, cwd=BUILD, check=True)

    link_args = shlex.split(link_line.replace(old_prefix, str(SOURCE)))
    link_args = link_args[2:-2]  # drop shell `: &&` / `&& :` wrappers
    link_args[0] = "/usr/bin/clang"
    for i, arg in enumerate(link_args):
        if arg == old_object:
            link_args[i] = new_object
        if arg == "lib/x86_64-linux-gnu/libvlib.so.26.02":
            link_args[i] = str(LIBRARY)
    subprocess.run(link_args, cwd=BUILD, check=True)
    symlink = CACHE / "libvlib.so"
    if symlink.is_symlink() or symlink.exists():
        symlink.unlink()
    symlink.symlink_to(LIBRARY.name)
    STAMP.write_text(identity + "\n")
    return True


if __name__ == "__main__":
    print("compiled=" + str(int(build())))
    print("libvlib_sha256=" + sha(LIBRARY))
