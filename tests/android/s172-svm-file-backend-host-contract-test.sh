#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
pin_file="$repo_root/src/product/vpp/pinned-vpp-revision.txt"
profile_module="$repo_root/src/product/vpp/android/apply-profile.sh"
pinned_revision="$(tr -d '[:space:]' < "$pin_file")"
source_dir="${SAKAMOTO_S172_VPP_SOURCE_DIR:-/tmp/sakamoto-172-vpp-official.6CoCcd/source-git}"
host_cc="${SAKAMOTO_S172_HOST_CC:-cc}"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/sakamoto-172-svm-host.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

fail() {
  echo "s172 SVM Android file backend host contract: $*" >&2
  exit 1
}

[[ -f "$pin_file" ]] || fail "pinned revision file is missing"
[[ "$pinned_revision" =~ ^[[:xdigit:]]{40}$ ]] || \
  fail "pinned VPP revision is not a 40-character commit"
[[ -x "$profile_module" ]] || fail "Android VPP profile module is missing"
[[ -x "$(command -v "$host_cc")" ]] || fail "host C compiler is missing"

canonical_source_dir="$(realpath -e "$source_dir" 2>/dev/null)" || \
  fail "source directory cannot be canonicalized"
source_dir="$canonical_source_dir"
case "${source_dir,,}" in
  *experiments*|*poc*) fail "POC/experiment source is not permitted" ;;
esac
[[ -d "$source_dir/.git" || -f "$source_dir/.git" ]] || \
  fail "set SAKAMOTO_S172_VPP_SOURCE_DIR to a clean official VPP checkout"
source_head="$(git -C "$source_dir" rev-parse HEAD)"
[[ "$source_head" == "$pinned_revision" ]] || \
  fail "official VPP source is not at the exact pinned revision"
[[ -z "$(git -C "$source_dir" status --porcelain)" ]] || \
  fail "official VPP source must remain clean"

patched_tree="$work_dir/patched-source"
bash "$profile_module" \
  --profile android-api31-arm64 \
  --source-dir "$source_dir" \
  --work-dir "$patched_tree" >"$work_dir/profile.log"

changed_files="$(
  git -C "$patched_tree" diff --name-only
  git -C "$patched_tree" ls-files --others --exclude-standard
  )"
changed_files="$(printf '%s\n' "$changed_files" | LC_ALL=C sort)"
expected_changed_files=$'src/CMakeLists.txt\nsrc/svm/CMakeLists.txt\nsrc/svm/message_queue.c\nsrc/svm/message_queue.h\nsrc/svm/queue.c\nsrc/svm/ssvm.c\nsrc/svm/svm.c\nsrc/svm/svm_android_file.c\nsrc/svm/svm_android_file.h\nsrc/vlib/CMakeLists.txt\nsrc/vlib/threads.c\nsrc/vlibmemory/memclnt_api.c\nsrc/vlibmemory/vlib_api_cli.c\nsrc/vnet/session/session.c\nsrc/vnet/sfdp/timer/timer.h\nsrc/vpp-api/vapi/CMakeLists.txt\nsrc/vpp/vnet/main.c\nsrc/vppinfra/CMakeLists.txt\nsrc/vppinfra/dlmalloc.h\nsrc/vppinfra/linux/mem.c\nsrc/vppinfra/maplog.c\nsrc/vppinfra/mem_intercept.c'
[[ "$changed_files" == "$expected_changed_files" ]] || \
  fail "profile changed files outside the ordered SVM slice: $changed_files"

helper_dir="$patched_tree/src/svm"
[[ -f "$helper_dir/svm_android_file.c" ]] || fail "Android file adapter source is missing"
[[ -f "$helper_dir/svm_android_file.h" ]] || fail "Android file adapter header is missing"

harness="$work_dir/svm_android_file_host.c"
cat >"$harness" <<'EOF'
#include "svm_android_file.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void
check (int condition, const char *message)
{
  if (!condition)
    {
      fprintf (stderr, "host file backend check failed: %s (errno=%d)\n",
               message, errno);
      exit (1);
    }
}

int
main (void)
{
  char base[] = "/tmp/sakamoto-172-svm-file.XXXXXX";
  char expected[PATH_MAX];
  char path[PATH_MAX];
  char link_path[PATH_MAX];
  struct stat st;
  int fd;
  int n;

  unsetenv (SVM_ANDROID_FILE_DIR_ENV);
  errno = 0;
  check (svm_android_file_path (path, sizeof (path), "generation-1",
                                "global_vm") < 0 && errno == ENOENT,
         "missing directory environment fails closed");
  errno = 0;
  check (svm_android_file_open ("generation-1", "global_vm", O_RDWR, 0) < 0 &&
           errno == ENOENT,
         "open without directory environment fails closed");

  check (mkdtemp (base) != NULL, "mkdtemp");
  check (setenv (SVM_ANDROID_FILE_DIR_ENV, base, 1) == 0, "setenv");
  n = snprintf (expected, sizeof (expected), "%s/generation-1-global_vm",
                base);
  check (n > 0 && (size_t) n < sizeof (expected), "expected path");
  check (svm_android_file_path (path, sizeof (path), "/generation-1",
                                "/global_vm") == 0 &&
           strcmp (path, expected) == 0,
         "generation path mapping");

  fd = svm_android_file_open ("generation-1", "global_vm",
                              O_RDWR | O_CREAT | O_EXCL, 0600);
  check (fd >= 0, "exclusive create");
  check (fstat (fd, &st) == 0 && S_ISREG (st.st_mode) &&
           (st.st_mode & 0777) == 0600,
         "regular file has private mode");
  check ((fcntl (fd, F_GETFD) & FD_CLOEXEC) != 0, "close-on-exec");
  check (close (fd) == 0, "close created file");

  errno = 0;
  check (svm_android_file_open ("generation-1", "global_vm",
                                O_RDWR | O_CREAT | O_EXCL, 0600) < 0 &&
           errno == EEXIST,
         "exclusive create rejects an existing generation");
  fd = svm_android_file_open ("generation-1", "global_vm", O_RDWR, 0);
  check (fd >= 0, "open existing generation");
  check (close (fd) == 0, "close existing file");

  n = snprintf (link_path, sizeof (link_path), "%s/generation-1-link", base);
  check (n > 0 && (size_t) n < sizeof (link_path), "symlink path");
  check (symlink ("global_vm", link_path) == 0, "create symlink probe");
  errno = 0;
  check (svm_android_file_open ("generation-1", "link", O_RDONLY, 0) < 0 &&
           errno == ELOOP,
         "symlink is not followed");
  check (unlink (link_path) == 0, "remove symlink probe");

  errno = 0;
  check (svm_android_file_path (path, sizeof (path), "generation/1",
                                "global_vm") < 0 && errno == EINVAL,
         "namespace traversal is rejected");
  errno = 0;
  check (svm_android_file_path (path, sizeof (path), "generation-1",
                                "global/vm") < 0 && errno == EINVAL,
         "region traversal is rejected");
  errno = 0;
  check (svm_android_file_path (path, sizeof (path), "generation-1", "..") < 0 &&
           errno == EINVAL,
         "dot-dot region is rejected");

  check (svm_android_file_unlink ("generation-1", "global_vm") == 0,
         "unlink generation file");
  errno = 0;
  check (lstat (expected, &st) < 0 && errno == ENOENT,
         "unlinked generation is gone");
  errno = 0;
  check (svm_android_file_unlink ("generation-1", "global_vm") < 0 &&
           errno == ENOENT,
         "second unlink reports missing generation");
  check (rmdir (base) == 0, "remove generation directory");
  puts ("HOST GREEN: generation-private regular-file backend contract PASS");
  return 0;
}
EOF

binary="$work_dir/svm_android_file_host"
if ! "$host_cc" -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror \
  -I"$helper_dir" "$helper_dir/svm_android_file.c" "$harness" \
  -o "$binary" >"$work_dir/compile.log" 2>&1; then
  sed -n '1,160p' "$work_dir/compile.log" >&2
  fail "host adapter compilation failed"
fi
if ! "$binary"; then
  fail "host adapter behavior contract failed"
fi

[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$source_head" ]] || \
  fail "host contract modified the input checkout revision"
[[ -z "$(git -C "$source_dir" status --porcelain)" ]] || \
  fail "host contract modified the input checkout"
echo "HOST NOTE: this validates the adapter seam only; it is not Android runtime evidence"
echo "s172 SVM Android file backend host contract: PASS"
