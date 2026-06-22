#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
VPP_DIR="${VPP_DIR:-$VPP_WORK_ROOT/vpp}"
VPP_SRC_DIR="${VPP_SRC_DIR:-$VPP_DIR/src}"

if [ ! -f "$VPP_SRC_DIR/CMakeLists.txt" ]; then
  echo "VPP source CMakeLists.txt not found: $VPP_SRC_DIR/CMakeLists.txt" >&2
  exit 1
fi

if [ ! -w "$VPP_SRC_DIR/CMakeLists.txt" ] && [ "${INSIDE_VPP_NFQ_CONTAINER:-0}" != "1" ]; then
  exec "$SCRIPT_DIR/run-container.sh" env INSIDE_VPP_NFQ_CONTAINER=1 ./scripts/apply-vpp-android-overlay.sh
fi

if [ ! -w "$VPP_SRC_DIR/CMakeLists.txt" ]; then
  echo "VPP source CMakeLists.txt is not writable: $VPP_SRC_DIR/CMakeLists.txt" >&2
  exit 1
fi

perl -0pi -e 's@##############################################################################\n# cross compiling\n##############################################################################\n.*?##############################################################################\n# build config@##############################################################################\n# cross compiling\n##############################################################################\n\nif(CMAKE_CROSSCOMPILING)\n  if (\${CMAKE_SYSTEM_NAME} MATCHES "Linux")\n    set(COMPILER_SUFFIX "linux-gnu")\n  elseif (\${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")\n    set(COMPILER_SUFFIX "freebsd")\n  elseif (\${CMAKE_SYSTEM_NAME} MATCHES "Android")\n    set(COMPILER_SUFFIX "")\n  endif()\n\n  if (COMPILER_SUFFIX)\n    set(CMAKE_IGNORE_PATH\n      /usr/lib/\${CMAKE_HOST_SYSTEM_PROCESSOR}-\${COMPILER_SUFFIX}/\n      /usr/lib/\${CMAKE_HOST_SYSTEM_PROCESSOR}-\${COMPILER_SUFFIX}/lib/\n    )\n    set(CMAKE_C_COMPILER_TARGET \${CMAKE_SYSTEM_PROCESSOR}-\${COMPILER_SUFFIX})\n  endif()\nendif()\n\n##############################################################################\n# build config@s' "$VPP_SRC_DIR/CMakeLists.txt"

perl -0pi -e 's/elseif\([^\n]*MATCHES "Linux\|FreeBSD(?:\|Android)?"\)/elseif(\${CMAKE_SYSTEM_NAME} MATCHES "Linux|FreeBSD|Android")/' "$VPP_SRC_DIR/CMakeLists.txt"

if [ -f "$VPP_SRC_DIR/plugins/nfqueue_poc/CMakeLists.txt" ]; then
  perl -0pi -e 's/SUPPORTED_OS_LIST\s+Linux(?:\s+Android)*/SUPPORTED_OS_LIST Linux Android/' "$VPP_SRC_DIR/plugins/nfqueue_poc/CMakeLists.txt"
fi

if [ -f "$VPP_SRC_DIR/svm/message_queue.h" ]; then
  perl -0pi -e 's@\n#ifdef __ANDROID__\n#define SAKAMOTO_ANDROID_PTHREAD_MUTEX_CONSISTENT_SHIM 1\nstatic inline int\npthread_mutex_consistent \(pthread_mutex_t \*mutex\)\n\{\n  \(void\) mutex;\n  return 0;\n\}\n#endif@@' "$VPP_SRC_DIR/svm/message_queue.h"
fi

if [ -f "$VPP_SRC_DIR/svm/queue.h" ] &&
  ! grep -q "SAKAMOTO_ANDROID_SVM_ROBUST_MUTEX_SHIM" "$VPP_SRC_DIR/svm/queue.h"; then
  perl -0pi -e 's@#include <pthread.h>@#include <pthread.h>\n\n#ifdef __ANDROID__\n#define SAKAMOTO_ANDROID_SVM_ROBUST_MUTEX_SHIM 1\n#ifndef PTHREAD_MUTEX_ROBUST\n#define PTHREAD_MUTEX_ROBUST 0\nstatic inline int\npthread_mutexattr_setrobust (pthread_mutexattr_t *attr, int robust)\n{\n  (void) attr;\n  (void) robust;\n  return 0;\n}\nstatic inline int\npthread_mutex_consistent (pthread_mutex_t *mutex)\n{\n  (void) mutex;\n  return 0;\n}\n#endif\n#endif@' "$VPP_SRC_DIR/svm/queue.h"
fi

if [ -f "$VPP_SRC_DIR/vppinfra/dlmalloc.h" ] &&
  ! grep -q "SAKAMOTO_ANDROID_DLMALLINFO_SHIM" "$VPP_SRC_DIR/vppinfra/dlmalloc.h"; then
  perl -0pi -e 's@#ifndef STRUCT_MALLINFO_DECLARED@#ifdef __ANDROID__\n#define SAKAMOTO_ANDROID_DLMALLINFO_SHIM 1\n#undef STRUCT_MALLINFO_DECLARED\n#endif\n#ifndef STRUCT_MALLINFO_DECLARED@' "$VPP_SRC_DIR/vppinfra/dlmalloc.h"
fi

if [ -f "$VPP_SRC_DIR/vppinfra/CMakeLists.txt" ] &&
  ! grep -q "SAKAMOTO_ANDROID_VPPINFRA_LINUX_SRCS" "$VPP_SRC_DIR/vppinfra/CMakeLists.txt"; then
  perl -0pi -e 's@elseif\("\$\{CMAKE_SYSTEM_NAME\}" STREQUAL "FreeBSD"\)@elseif("\${CMAKE_SYSTEM_NAME}" STREQUAL "Android")\n  # SAKAMOTO_ANDROID_VPPINFRA_LINUX_SRCS\n  list(APPEND VPPINFRA_SRCS\n    elf_clib.c\n    linux/mem.c\n    linux/sysfs.c\n    linux/netns.c\n   )\nelseif("\${CMAKE_SYSTEM_NAME}" STREQUAL "FreeBSD")@' "$VPP_SRC_DIR/vppinfra/CMakeLists.txt"
else
  perl -0pi -e 's@elseif\("" STREQUAL "Android"\)@elseif("\${CMAKE_SYSTEM_NAME}" STREQUAL "Android")@g; s@elseif\("" STREQUAL "FreeBSD"\)@elseif("\${CMAKE_SYSTEM_NAME}" STREQUAL "FreeBSD")@g' "$VPP_SRC_DIR/vppinfra/CMakeLists.txt"
fi

if [ -f "$VPP_SRC_DIR/vppinfra/unix.h" ] &&
  ! grep -q "SAKAMOTO_ANDROID_PTHREAD_AFFINITY_SHIM" "$VPP_SRC_DIR/vppinfra/unix.h"; then
  perl -0pi -e 's@#include <vppinfra/error.h>@#include <vppinfra/error.h>\n\n#ifdef __ANDROID__\n#define SAKAMOTO_ANDROID_PTHREAD_AFFINITY_SHIM 1\n#include <pthread.h>\n#include <sched.h>\nstatic inline int\npthread_setaffinity_np (pthread_t thread, size_t cpusetsize,\n\t\t\tconst void *cpuset)\n{\n  (void) thread;\n  (void) cpusetsize;\n  (void) cpuset;\n  return 0;\n}\n#endif@' "$VPP_SRC_DIR/vppinfra/unix.h"
else
  perl -0pi -e 's@const cpu_set_t \*cpuset@const void *cpuset@g' "$VPP_SRC_DIR/vppinfra/unix.h"
fi

if [ -f "$VPP_SRC_DIR/vppinfra/clib.h" ] &&
  ! grep -q "SAKAMOTO_ANDROID_BZERO_SHIM" "$VPP_SRC_DIR/vppinfra/clib.h"; then
  perl -0pi -e 's@#include <stdalign.h>@#include <stdalign.h>\n#ifdef __ANDROID__\n#define SAKAMOTO_ANDROID_BZERO_SHIM 1\n#include <string.h>\n#ifndef bzero\n#define bzero(p, n) memset ((p), 0, (n))\n#endif\n#endif@' "$VPP_SRC_DIR/vppinfra/clib.h"
fi

if [ -f "$VPP_SRC_DIR/vppinfra/maplog.c" ] &&
  ! grep -q "SAKAMOTO_ANDROID_MAPLOG_OPEN_MODE_FIX" "$VPP_SRC_DIR/vppinfra/maplog.c"; then
  perl -0pi -e 's@#include <vppinfra/maplog.h>@#include <vppinfra/maplog.h>\n\n#ifdef __ANDROID__\n#define SAKAMOTO_ANDROID_MAPLOG_OPEN_MODE_FIX 1\n#endif@' "$VPP_SRC_DIR/vppinfra/maplog.c"
  perl -0pi -e 's@open \(\(char \*\) mm->header_filename, O_RDWR, 0600\)@open ((char *) mm->header_filename, O_RDWR)@g; s@open \(\(char \*\) header_filename, O_RDONLY, 0600\)@open ((char *) header_filename, O_RDONLY)@g; s@open \(\(char \*\) this_filename, O_RDONLY, 0600\)@open ((char *) this_filename, O_RDONLY)@g' "$VPP_SRC_DIR/vppinfra/maplog.c"
fi

if [ -f "$VPP_SRC_DIR/vlib/CMakeLists.txt" ] &&
  ! grep -q "SAKAMOTO_ANDROID_VLIB_LINUX_SRCS" "$VPP_SRC_DIR/vlib/CMakeLists.txt"; then
  perl -0pi -e 's@elseif\("\$\{CMAKE_SYSTEM_NAME\}" STREQUAL "FreeBSD"\)@elseif("\${CMAKE_SYSTEM_NAME}" STREQUAL "Android")\nset(PLATFORM_SOURCES\n  # SAKAMOTO_ANDROID_VLIB_LINUX_SRCS\n  linux/pci.c\n  linux/vfio.c\n  linux/vmbus.c\n)\n\nset(PLATFORM_HEADERS\n  linux/vfio.h\n)\nelseif("\${CMAKE_SYSTEM_NAME}" STREQUAL "FreeBSD")@' "$VPP_SRC_DIR/vlib/CMakeLists.txt"
else
  perl -0pi -e 's@elseif\("" STREQUAL "Android"\)@elseif("\${CMAKE_SYSTEM_NAME}" STREQUAL "Android")@g; s@elseif\("" STREQUAL "FreeBSD"\)@elseif("\${CMAKE_SYSTEM_NAME}" STREQUAL "FreeBSD")@g' "$VPP_SRC_DIR/vlib/CMakeLists.txt"
fi

if [ -f "$VPP_SRC_DIR/vlib/CMakeLists.txt" ] &&
  ! grep -q "SAKAMOTO_ANDROID_VLIB_PROCESS_STACK" "$VPP_SRC_DIR/vlib/CMakeLists.txt"; then
  perl -0pi -e 's@if \(CMAKE_BUILD_TYPE_UC STREQUAL "DEBUG"\)\n  set\(_ss 16\)\nelse\(\)\n  set\(_ss 15\)\nendif\(\)@if ("\${CMAKE_SYSTEM_NAME}" STREQUAL "Android")\n  # SAKAMOTO_ANDROID_VLIB_PROCESS_STACK\n  set(_ss 18)\nelseif (CMAKE_BUILD_TYPE_UC STREQUAL "DEBUG")\n  set(_ss 16)\nelse()\n  set(_ss 15)\nendif()@' "$VPP_SRC_DIR/vlib/CMakeLists.txt"
else
  perl -0pi -e 's@if \("" STREQUAL "Android"\)@if("\${CMAKE_SYSTEM_NAME}" STREQUAL "Android")@g' "$VPP_SRC_DIR/vlib/CMakeLists.txt"
fi

if [ -f "$VPP_SRC_DIR/vppinfra/linux/mem.c" ] &&
  ! grep -q "SAKAMOTO_ANDROID_NUMA_SYSCALL_SHIM" "$VPP_SRC_DIR/vppinfra/linux/mem.c"; then
  perl -0pi -e 's@#include <linux/memfd.h>@#include <linux/memfd.h>\n\n#ifdef __ANDROID__\n#define SAKAMOTO_ANDROID_NUMA_SYSCALL_SHIM 1\n#endif@' "$VPP_SRC_DIR/vppinfra/linux/mem.c"
  perl -0pi -e 's@  /\* numa nodes \*/\n  if \(syscall \(__NR_get_mempolicy, &mode, &nodemask, maxnode, va, flags\) == 0\)\n    mm->numa_node_bitmap = nodemask;@  /* numa nodes */\n#ifdef __ANDROID__\n  mm->numa_node_bitmap = 1;\n#else\n  if (syscall (__NR_get_mempolicy, &mode, &nodemask, maxnode, va, flags) == 0)\n    mm->numa_node_bitmap = nodemask;\n#endif@' "$VPP_SRC_DIR/vppinfra/linux/mem.c"
  perl -0pi -e 's@  if \(syscall \(__NR_move_pages, 0, n_pages, ptr, 0, status, 0\) != 0\)@#ifdef __ANDROID__\n  stats->unknown = n_pages;\n  goto done;\n#endif\n\n  if (syscall (__NR_move_pages, 0, n_pages, ptr, 0, status, 0) != 0)@' "$VPP_SRC_DIR/vppinfra/linux/mem.c"
  perl -0pi -e 's@  /\* no numa support \*/@#ifdef __ANDROID__\n  if (numa_node)\n    {\n      vec_reset_length (mm->error);\n      mm->error = clib_error_return (mm->error, "%s: numa not supported",\n                                     (char *) __func__);\n      return CLIB_MEM_ERROR;\n    }\n  return 0;\n#endif\n\n  /* no numa support */@' "$VPP_SRC_DIR/vppinfra/linux/mem.c"
  perl -0pi -e 's@  if \(syscall \(__NR_set_mempolicy, MPOL_DEFAULT, 0, 0\)\)@#ifdef __ANDROID__\n  return 0;\n#endif\n\n  if (syscall (__NR_set_mempolicy, MPOL_DEFAULT, 0, 0))@' "$VPP_SRC_DIR/vppinfra/linux/mem.c"
fi
if [ -f "$VPP_SRC_DIR/vppinfra/linux/mem.c" ] &&
  grep -q "SAKAMOTO_ANDROID_NUMA_SYSCALL_SHIM" "$VPP_SRC_DIR/vppinfra/linux/mem.c" &&
  ! grep -q "SAKAMOTO_ANDROID_NUMA_UNUSED_RELEASE_FIX" "$VPP_SRC_DIR/vppinfra/linux/mem.c"; then
  perl -0pi -e 's@#define SAKAMOTO_ANDROID_NUMA_SYSCALL_SHIM 1@#define SAKAMOTO_ANDROID_NUMA_SYSCALL_SHIM 1\n#define SAKAMOTO_ANDROID_NUMA_UNUSED_RELEASE_FIX 1@' "$VPP_SRC_DIR/vppinfra/linux/mem.c"
  perl -0pi -e 's@#ifdef __ANDROID__\n  mm->numa_node_bitmap = 1;@#ifdef __ANDROID__\n  (void) nodemask;\n  (void) maxnode;\n  (void) flags;\n  (void) va;\n  (void) mode;\n  mm->numa_node_bitmap = 1;@' "$VPP_SRC_DIR/vppinfra/linux/mem.c"
fi

if [ -f "$VPP_SRC_DIR/vppinfra/mem_intercept.c" ] &&
  ! grep -q "SAKAMOTO_ANDROID_MALLOC_USABLE_SIZE_SHIM" "$VPP_SRC_DIR/vppinfra/mem_intercept.c"; then
  perl -0pi -e 's@__clib_export size_t\nmalloc_usable_size \(void \*p\)\n\{\n@#ifdef __ANDROID__\n#define SAKAMOTO_ANDROID_MALLOC_USABLE_SIZE_SHIM 1\ntypedef const void *sakamoto_android_malloc_usable_size_arg_t;\n#else\ntypedef void *sakamoto_android_malloc_usable_size_arg_t;\n#endif\n\n__clib_export size_t\nmalloc_usable_size (sakamoto_android_malloc_usable_size_arg_t p)\n{\n@' "$VPP_SRC_DIR/vppinfra/mem_intercept.c"
  perl -0pi -e 's@static size_t \(\*__malloc_usable_size\) \(void \*\) = 0;@static size_t (*__malloc_usable_size) (sakamoto_android_malloc_usable_size_arg_t) = 0;@' "$VPP_SRC_DIR/vppinfra/mem_intercept.c"
  perl -0pi -e 's@return clib_mem_size \(p\);@return clib_mem_size ((void *) p);@' "$VPP_SRC_DIR/vppinfra/mem_intercept.c"
fi

if [ -f "$VPP_SRC_DIR/svm/svm_common.h" ] &&
  ! grep -q "SAKAMOTO_ANDROID_SHM_OPEN_FILE_BACKEND" "$VPP_SRC_DIR/svm/svm_common.h"; then
  perl -0pi -e 's@#include <vppinfra/types.h>@#include <vppinfra/types.h>\n\n#ifdef __ANDROID__\n#define SAKAMOTO_ANDROID_SHM_OPEN_FILE_BACKEND 1\n#include <errno.h>\n#include <fcntl.h>\n#include <stdio.h>\n#include <sys/stat.h>\n#include <unistd.h>\n\n#define SAKAMOTO_ANDROID_SHM_DIR "/data/local/tmp/vpp-shm"\n\nstatic inline int\nsakamoto_android_shm_path (const char *name, char *path, size_t path_len)\n{\n  char clean[256];\n  const char *p = name;\n  size_t i = 0;\n\n  if (!p || !p[0])\n    {\n      errno = EINVAL;\n      return -1;\n    }\n  while (*p == 47)\n    p++;\n  for (; *p && i + 1 < sizeof (clean); p++)\n    clean[i++] = (*p == 47) ? 95 : *p;\n  if (*p || i == 0)\n    {\n      errno = *p ? ENAMETOOLONG : EINVAL;\n      return -1;\n    }\n  clean[i] = 0;\n\n  if (mkdir (SAKAMOTO_ANDROID_SHM_DIR, 0777) < 0 && errno != EEXIST)\n    return -1;\n  if (snprintf (path, path_len, "%s/%s", SAKAMOTO_ANDROID_SHM_DIR, clean) >=\n      (int) path_len)\n    {\n      errno = ENAMETOOLONG;\n      return -1;\n    }\n  return 0;\n}\n\nstatic inline int\nsakamoto_android_shm_open (const char *name, int oflag, mode_t mode)\n{\n  char path[512];\n  if (sakamoto_android_shm_path (name, path, sizeof (path)) < 0)\n    return -1;\n  return open (path, oflag, mode);\n}\n\nstatic inline int\nsakamoto_android_shm_unlink (const char *name)\n{\n  char path[512];\n  if (sakamoto_android_shm_path (name, path, sizeof (path)) < 0)\n    return -1;\n  return unlink (path);\n}\n\n#define shm_open sakamoto_android_shm_open\n#define shm_unlink sakamoto_android_shm_unlink\n#endif@' "$VPP_SRC_DIR/svm/svm_common.h"
fi
if [ -f "$VPP_SRC_DIR/svm/svm_common.h" ] &&
  grep -q "SAKAMOTO_ANDROID_SHM_OPEN_FILE_BACKEND" "$VPP_SRC_DIR/svm/svm_common.h"; then
  if ! grep -q "#include <stdlib.h>" "$VPP_SRC_DIR/svm/svm_common.h"; then
    perl -0pi -e 's@#include <stdio.h>@#include <stdio.h>\n#include <stdlib.h>@' "$VPP_SRC_DIR/svm/svm_common.h"
  fi
  if ! grep -q "SAKAMOTO_ANDROID_DEFAULT_SHM_DIR" "$VPP_SRC_DIR/svm/svm_common.h"; then
    perl -0pi -e 's@#define SAKAMOTO_ANDROID_SHM_DIR "/data/local/tmp/vpp-shm"\n@#define SAKAMOTO_ANDROID_DEFAULT_SHM_DIR "/data/local/tmp/vpp-shm"\n\nstatic inline const char *\nsakamoto_android_shm_dir (void)\n{\n  const char *dir = getenv ("SAKAMOTO_ANDROID_SHM_DIR");\n  return (dir && dir[0]) ? dir : SAKAMOTO_ANDROID_DEFAULT_SHM_DIR;\n}\n@' "$VPP_SRC_DIR/svm/svm_common.h"
  fi
  perl -0pi -e 's@mkdir \(SAKAMOTO_ANDROID_SHM_DIR, 0777\)@mkdir (sakamoto_android_shm_dir (), 0777)@g; s@"%s/%s", SAKAMOTO_ANDROID_SHM_DIR, clean@"%s/%s", sakamoto_android_shm_dir (), clean@g' "$VPP_SRC_DIR/svm/svm_common.h"
fi

if [ -f "$VPP_SRC_DIR/svm/svm.c" ] &&
  ! grep -q "SAKAMOTO_ANDROID_SVM_OPEN_MODE_FIX" "$VPP_SRC_DIR/svm/svm.c"; then
  perl -0pi -e 's@#include <vppinfra/clib.h>@#include <vppinfra/clib.h>\n\n#ifdef __ANDROID__\n#define SAKAMOTO_ANDROID_SVM_OPEN_MODE_FIX 1\n#endif@' "$VPP_SRC_DIR/svm/svm.c"
  perl -0pi -e 's@open \(a->backing_file, O_RDWR, 0777\)@open (a->backing_file, O_RDWR)@g' "$VPP_SRC_DIR/svm/svm.c"
fi

if [ -f "$VPP_SRC_DIR/svm/CMakeLists.txt" ] &&
  ! grep -q "SAKAMOTO_ANDROID_SVM_PLATFORM_LIBS" "$VPP_SRC_DIR/svm/CMakeLists.txt"; then
  perl -0pi -e 's@##############################################################################\n# svm shared library@##############################################################################\n# svm shared library\n##############################################################################\nif("\${CMAKE_SYSTEM_NAME}" STREQUAL "Android")\n  # SAKAMOTO_ANDROID_SVM_PLATFORM_LIBS\n  set(SAKAMOTO_ANDROID_SVM_LIBS vppinfra)\n  set(SAKAMOTO_ANDROID_SVMDB_LIBS svm vppinfra)\nelse()\n  set(SAKAMOTO_ANDROID_SVM_LIBS vppinfra rt pthread)\n  set(SAKAMOTO_ANDROID_SVMDB_LIBS svm vppinfra rt pthread)\nendif()\n\n##############################################################################\n# svm shared library@' "$VPP_SRC_DIR/svm/CMakeLists.txt"
  perl -0pi -e 's@LINK_LIBRARIES vppinfra rt pthread@LINK_LIBRARIES \${SAKAMOTO_ANDROID_SVM_LIBS}@' "$VPP_SRC_DIR/svm/CMakeLists.txt"
  perl -0pi -e 's@LINK_LIBRARIES svm vppinfra rt pthread@LINK_LIBRARIES \${SAKAMOTO_ANDROID_SVMDB_LIBS}@' "$VPP_SRC_DIR/svm/CMakeLists.txt"
else
  perl -0pi -e 's@if\("" STREQUAL "Android"\)@if("\${CMAKE_SYSTEM_NAME}" STREQUAL "Android")@g' "$VPP_SRC_DIR/svm/CMakeLists.txt"
fi

for f in "$VPP_SRC_DIR/vlibmemory/memclnt_api.c" \
  "$VPP_SRC_DIR/vlibmemory/vlib_api_cli.c"; do
  if [ -f "$f" ] &&
    ! grep -q "SAKAMOTO_ANDROID_STRINGS_INDEX_DECL" "$f"; then
    perl -0pi -e 's@#include <fcntl.h>@#include <fcntl.h>\n#ifdef __ANDROID__\n#define SAKAMOTO_ANDROID_STRINGS_INDEX_DECL 1\n#include <string.h>\n#define index(s, c) strchr ((s), (c))\n#endif@' "$f"
  elif [ -f "$f" ]; then
    perl -0pi -e 's@#include <strings.h>\n#endif@#include <string.h>\n#define index(s, c) strchr ((s), (c))\n#endif@' "$f"
  fi
done

if [ -f "$VPP_SRC_DIR/vnet/sfdp/timer/timer.h" ] &&
  ! grep -q "SAKAMOTO_ANDROID_SFDP_UNUSED_FIELD_FIX" "$VPP_SRC_DIR/vnet/sfdp/timer/timer.h"; then
  perl -0pi -e 's@#include <vnet/sfdp/sfdp.h>@#include <vnet/sfdp/sfdp.h>\n\n#ifdef __ANDROID__\n#define SAKAMOTO_ANDROID_SFDP_UNUSED_FIELD_FIX 1\n#endif@' "$VPP_SRC_DIR/vnet/sfdp/timer/timer.h"
  perl -0pi -e 's@u32 __unused;@u32 unused;@g' "$VPP_SRC_DIR/vnet/sfdp/timer/timer.h"
fi

echo "Applied Android CMake overlay to $VPP_SRC_DIR"
