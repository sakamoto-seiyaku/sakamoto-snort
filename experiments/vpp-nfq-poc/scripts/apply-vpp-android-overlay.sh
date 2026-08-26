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
  perl -0pi -e 's@#include <vppinfra/error.h>@#include <vppinfra/error.h>\n\n#ifdef __ANDROID__\n#define SAKAMOTO_ANDROID_PTHREAD_AFFINITY_SHIM 1\n#include <errno.h>\n#include <pthread.h>\n#include <sys/syscall.h>\n#include <unistd.h>\nstatic inline int\npthread_setaffinity_np (pthread_t thread, size_t cpusetsize,\n\t\t\tconst void *cpuset)\n{\n  pid_t tid = pthread_gettid_np (thread);\n  if (tid < 0)\n    return ESRCH;\n  if (syscall (SYS_sched_setaffinity, tid, cpusetsize, cpuset) == 0)\n    return 0;\n  return errno ? errno : EINVAL;\n}\n#endif@' "$VPP_SRC_DIR/vppinfra/unix.h"
else
  perl -0pi -e 's@const cpu_set_t \*cpuset@const void *cpuset@g' "$VPP_SRC_DIR/vppinfra/unix.h"
fi
if [ -f "$VPP_SRC_DIR/vppinfra/unix.h" ] &&
  grep -q "SAKAMOTO_ANDROID_PTHREAD_AFFINITY_SHIM" "$VPP_SRC_DIR/vppinfra/unix.h" &&
  ! grep -q "sched_setaffinity (tid" "$VPP_SRC_DIR/vppinfra/unix.h"; then
  perl -0pi -e 's@#define SAKAMOTO_ANDROID_PTHREAD_AFFINITY_SHIM 1\n#include <pthread.h>@#define SAKAMOTO_ANDROID_PTHREAD_AFFINITY_SHIM 1\n#include <errno.h>\n#include <pthread.h>@' "$VPP_SRC_DIR/vppinfra/unix.h"
  perl -0pi -e 's@static inline int\npthread_setaffinity_np \(pthread_t thread, size_t cpusetsize,\n\t\t\tconst void \*cpuset\)\n\{\n  \(void\) thread;\n  \(void\) cpusetsize;\n  \(void\) cpuset;\n  return 0;\n\}@static inline int\npthread_setaffinity_np (pthread_t thread, size_t cpusetsize,\n\t\t\tconst void *cpuset)\n{\n  pid_t tid = pthread_gettid_np (thread);\n  if (tid < 0)\n    return ESRCH;\n  if (sched_setaffinity (tid, cpusetsize, (const cpu_set_t *) cpuset) == 0)\n    return 0;\n  return errno ? errno : EINVAL;\n}@' "$VPP_SRC_DIR/vppinfra/unix.h"
fi
if [ -f "$VPP_SRC_DIR/vppinfra/unix.h" ] &&
  grep -q "sched_setaffinity (tid" "$VPP_SRC_DIR/vppinfra/unix.h"; then
  perl -0pi -e 's@#include <sched.h>@#include <sys/syscall.h>\n#include <unistd.h>@' "$VPP_SRC_DIR/vppinfra/unix.h"
  perl -0pi -e 's@sched_setaffinity \(tid, cpusetsize, \(const cpu_set_t \*\) cpuset\)@syscall (SYS_sched_setaffinity, tid, cpusetsize, cpuset)@' "$VPP_SRC_DIR/vppinfra/unix.h"
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

if [ -f "$VPP_SRC_DIR/vnet/CMakeLists.txt" ] &&
  ! grep -q "option(SAKAMOTO_VPP_NO_IPSEC" "$VPP_SRC_DIR/vnet/CMakeLists.txt"; then
  perl -0pi -e 's@(option\(VPP_IP_FIB_MTRIE_16 "[^"]+" ON\)\n)@$1\noption(SAKAMOTO_VPP_NO_IPSEC "Build without libvnet IPsec sources and feature registrations." OFF)\nif(SAKAMOTO_VPP_NO_IPSEC)\n  add_definitions(-DSAKAMOTO_VPP_NO_IPSEC=1)\nendif()\n@' "$VPP_SRC_DIR/vnet/CMakeLists.txt"
fi
if [ -f "$VPP_SRC_DIR/vnet/CMakeLists.txt" ] &&
  ! grep -q "if(NOT SAKAMOTO_VPP_NO_IPSEC)" "$VPP_SRC_DIR/vnet/CMakeLists.txt"; then
  perl -0pi -e 's@(##############################################################################\n# Layer 3 protocol: IPSec\n##############################################################################\n)(.*?)(\n##############################################################################\n# Layer 4 protocol: tcp\n##############################################################################)@$1if(NOT SAKAMOTO_VPP_NO_IPSEC)\n$2endif()\n$3@s' "$VPP_SRC_DIR/vnet/CMakeLists.txt"
fi
if [ -f "$VPP_SRC_DIR/vnet/CMakeLists.txt" ] &&
  ! grep -q "SAKAMOTO_VNET_VAT_TEST_SOURCES" "$VPP_SRC_DIR/vnet/CMakeLists.txt"; then
  perl -0pi -e 's@add_vat_test_library\(vnet\n  interface_test\.c\n  ip/ip_test\.c\n  arp/arp_test\.c\n  ip6-nd/ip6_nd_test\.c\n  session/session_test\.c\n  l2/l2_test\.c\n  ipsec/ipsec_test\.c\n\)@set(SAKAMOTO_VNET_VAT_TEST_SOURCES\n  interface_test.c\n  ip/ip_test.c\n  arp/arp_test.c\n  ip6-nd/ip6_nd_test.c\n  session/session_test.c\n  l2/l2_test.c\n)\nif(NOT SAKAMOTO_VPP_NO_IPSEC)\n  list(APPEND SAKAMOTO_VNET_VAT_TEST_SOURCES ipsec/ipsec_test.c)\nendif()\n\nadd_vat_test_library(vnet\n  \${SAKAMOTO_VNET_VAT_TEST_SOURCES}\n)@' "$VPP_SRC_DIR/vnet/CMakeLists.txt"
fi
if [ -f "$VPP_SRC_DIR/vnet/CMakeLists.txt" ] &&
  grep -q "SAKAMOTO_VNET_VAT_TEST_SOURCES" "$VPP_SRC_DIR/vnet/CMakeLists.txt" &&
  ! grep -q '\${SAKAMOTO_VNET_VAT_TEST_SOURCES}' "$VPP_SRC_DIR/vnet/CMakeLists.txt"; then
  perl -0pi -e 's@add_vat_test_library\(vnet\n\s*\n\)@add_vat_test_library(vnet\n  \${SAKAMOTO_VNET_VAT_TEST_SOURCES}\n)@' "$VPP_SRC_DIR/vnet/CMakeLists.txt"
fi

if [ -f "$VPP_SRC_DIR/vnet/ip/ip4_forward.c" ] &&
  ! grep -q "SAKAMOTO_VPP_NO_IPSEC" "$VPP_SRC_DIR/vnet/ip/ip4_forward.c"; then
  perl -0pi -e 's@  \.runs_before = VNET_FEATURES \("ipsec4-input-feature"\),@#ifdef SAKAMOTO_VPP_NO_IPSEC\n  .runs_before = VNET_FEATURES ("vpath-input-ip4"),\n#else\n  .runs_before = VNET_FEATURES ("ipsec4-input-feature"),\n#endif@' "$VPP_SRC_DIR/vnet/ip/ip4_forward.c"
  perl -0pi -e 's@(VNET_FEATURE_INIT \(ip4_ipsec, static\) =\n\{\n  \.arc_name = "ip4-unicast",\n  \.node_name = "ipsec4-input-feature",\n  \.runs_before = VNET_FEATURES \("vpath-input-ip4"\),\n\};)@#ifndef SAKAMOTO_VPP_NO_IPSEC\n$1\n#endif@' "$VPP_SRC_DIR/vnet/ip/ip4_forward.c"
  perl -0pi -e 's@  \.runs_before = VNET_FEATURES \("ipsec4-output-feature"\),@#ifdef SAKAMOTO_VPP_NO_IPSEC\n  .runs_before = VNET_FEATURES ("interface-output"),\n#else\n  .runs_before = VNET_FEATURES ("ipsec4-output-feature"),\n#endif@' "$VPP_SRC_DIR/vnet/ip/ip4_forward.c"
  perl -0pi -e 's@(VNET_FEATURE_INIT \(ip4_ipsec_output, static\) =\n\{\n  \.arc_name = "ip4-output",\n  \.node_name = "ipsec4-output-feature",\n  \.runs_before = VNET_FEATURES \("interface-output"\),\n\};)@#ifndef SAKAMOTO_VPP_NO_IPSEC\n$1\n#endif@' "$VPP_SRC_DIR/vnet/ip/ip4_forward.c"
fi

if [ -f "$VPP_SRC_DIR/vnet/ip/ip6_forward.c" ] &&
  ! grep -q "SAKAMOTO_VPP_NO_IPSEC" "$VPP_SRC_DIR/vnet/ip/ip6_forward.c"; then
  perl -0pi -e 's@  \.runs_before = VNET_FEATURES \("ipsec6-input-feature"\),@#ifdef SAKAMOTO_VPP_NO_IPSEC\n  .runs_before = VNET_FEATURES ("l2tp-decap"),\n#else\n  .runs_before = VNET_FEATURES ("ipsec6-input-feature"),\n#endif@' "$VPP_SRC_DIR/vnet/ip/ip6_forward.c"
  perl -0pi -e 's@(VNET_FEATURE_INIT \(ip6_ipsec, static\) =\n\{\n  \.arc_name = "ip6-unicast",\n  \.node_name = "ipsec6-input-feature",\n  \.runs_before = VNET_FEATURES \("l2tp-decap"\),\n\};)@#ifndef SAKAMOTO_VPP_NO_IPSEC\n$1\n#endif@' "$VPP_SRC_DIR/vnet/ip/ip6_forward.c"
  perl -0pi -e 's@  \.runs_before = VNET_FEATURES \("ipsec6-output-feature"\),@#ifdef SAKAMOTO_VPP_NO_IPSEC\n  .runs_before = VNET_FEATURES ("interface-output"),\n#else\n  .runs_before = VNET_FEATURES ("ipsec6-output-feature"),\n#endif@' "$VPP_SRC_DIR/vnet/ip/ip6_forward.c"
  perl -0pi -e 's@(VNET_FEATURE_INIT \(ip6_ipsec_output, static\) = \{\n  \.arc_name = "ip6-output",\n  \.node_name = "ipsec6-output-feature",\n  \.runs_before = VNET_FEATURES \("interface-output"\),\n\};)@#ifndef SAKAMOTO_VPP_NO_IPSEC\n$1\n#endif@' "$VPP_SRC_DIR/vnet/ip/ip6_forward.c"
fi

if [ -f "$VPP_SRC_DIR/vnet/interface_output.c" ] &&
  ! grep -q "SAKAMOTO_VPP_NO_IPSEC" "$VPP_SRC_DIR/vnet/interface_output.c"; then
  perl -0pi -e 's@(VNET_FEATURE_INIT \(ipsec_if_tx, static\) = \{\n  \.arc_name = "interface-output",\n  \.node_name = "ipsec-if-output",\n  \.runs_before = VNET_FEATURES \("interface-output-arc-end"\),\n\};)@#ifndef SAKAMOTO_VPP_NO_IPSEC\n$1\n#endif@' "$VPP_SRC_DIR/vnet/interface_output.c"
fi

if [ -f "$VPP_SRC_DIR/vnet/gso/node.c" ] &&
  ! grep -q "SAKAMOTO_VPP_NO_IPSEC" "$VPP_SRC_DIR/vnet/gso/node.c"; then
  perl -0pi -e 's@  \.runs_before = VNET_FEATURES \("ipsec4-output-feature"\),@#ifdef SAKAMOTO_VPP_NO_IPSEC\n  .runs_before = VNET_FEATURES ("interface-output"),\n#else\n  .runs_before = VNET_FEATURES ("ipsec4-output-feature"),\n#endif@' "$VPP_SRC_DIR/vnet/gso/node.c"
  perl -0pi -e 's@  \.runs_before = VNET_FEATURES \("ipsec6-output-feature"\),@#ifdef SAKAMOTO_VPP_NO_IPSEC\n  .runs_before = VNET_FEATURES ("interface-output"),\n#else\n  .runs_before = VNET_FEATURES ("ipsec6-output-feature"),\n#endif@' "$VPP_SRC_DIR/vnet/gso/node.c"
fi

if [ -f "$VPP_SRC_DIR/vnet/ip/reass/ip4_full_reass.c" ] &&
  ! grep -q "SAKAMOTO_VPP_NO_IPSEC" "$VPP_SRC_DIR/vnet/ip/reass/ip4_full_reass.c"; then
  perl -0pi -e 's@  \.runs_before = VNET_FEATURES \("ip4-lookup", "ipsec4-input-feature",\n\t\t\t\t"ip4-sv-reassembly-feature"\),@#ifdef SAKAMOTO_VPP_NO_IPSEC\n  .runs_before = VNET_FEATURES ("ip4-lookup", "ip4-sv-reassembly-feature"),\n#else\n  .runs_before = VNET_FEATURES ("ip4-lookup", "ipsec4-input-feature",\n\t\t\t\t"ip4-sv-reassembly-feature"),\n#endif@' "$VPP_SRC_DIR/vnet/ip/reass/ip4_full_reass.c"
fi

if [ -f "$VPP_SRC_DIR/vnet/ip/reass/ip6_full_reass.c" ] &&
  ! grep -q "SAKAMOTO_VPP_NO_IPSEC" "$VPP_SRC_DIR/vnet/ip/reass/ip6_full_reass.c"; then
  perl -0pi -e 's@    \.runs_before = VNET_FEATURES \("ip6-lookup",\n                                  "ipsec6-input-feature"\),@#ifdef SAKAMOTO_VPP_NO_IPSEC\n    .runs_before = VNET_FEATURES ("ip6-lookup"),\n#else\n    .runs_before = VNET_FEATURES ("ip6-lookup",\n                                  "ipsec6-input-feature"),\n#endif@' "$VPP_SRC_DIR/vnet/ip/reass/ip6_full_reass.c"
fi

if [ -f "$VPP_SRC_DIR/CMakeLists.txt" ] &&
  ! grep -q "option(SAKAMOTO_VPP_ANDROID_IDLE_PROFILE" "$VPP_SRC_DIR/CMakeLists.txt"; then
  perl -0pi -e 's@(option\(VPP_ENABLE_TRAJECTORY_TRACE "Build vpp with trajectory tracing enabled" OFF\)\nif\(VPP_ENABLE_TRAJECTORY_TRACE\)\n  add_compile_definitions\(VLIB_BUFFER_TRACE_TRAJECTORY=1\)\nendif\(\)\n)@$1\noption(SAKAMOTO_VPP_ANDROID_IDLE_PROFILE "Enable Sakamoto Android minimal idle runtime profile." OFF)\nif(SAKAMOTO_VPP_ANDROID_IDLE_PROFILE)\n  add_compile_definitions(SAKAMOTO_VPP_ANDROID_IDLE_PROFILE=1)\nendif()\n@' "$VPP_SRC_DIR/CMakeLists.txt"
fi

python3 - "$VPP_SRC_DIR" <<'PY'
from pathlib import Path
import sys

src = Path(sys.argv[1])


def replace_once(rel, old, new):
    path = src / rel
    if not path.exists():
        return
    text = path.read_text()
    if new in text:
        return
    if old not in text:
        raise SystemExit(f"pattern not found in {rel}")
    path.write_text(text.replace(old, new, 1))


replace_once(
    "vpp-api/vapi/CMakeLists.txt",
    "add_vpp_library(vapiclient\n",
    "if(\"${CMAKE_SYSTEM_NAME}\" STREQUAL \"Android\")\n"
    "  # Android bionic exports pthread/rt symbols from libc.\n"
    "  set(SAKAMOTO_ANDROID_VAPI_PLATFORM_LIBS m)\n"
    "else()\n"
    "  set(SAKAMOTO_ANDROID_VAPI_PLATFORM_LIBS pthread m rt)\n"
    "endif()\n\n"
    "add_vpp_library(vapiclient\n",
)

replace_once(
    "vpp-api/vapi/CMakeLists.txt",
    "  LINK_LIBRARIES vppinfra vlibmemoryclient svm pthread m rt",
    "  LINK_LIBRARIES vppinfra vlibmemoryclient svm ${SAKAMOTO_ANDROID_VAPI_PLATFORM_LIBS}",
)

replace_once(
    "vlib/file.c",
    "clib_file_main_t file_main;\n",
    "clib_file_main_t file_main;\n\n"
    "#ifdef SAKAMOTO_VPP_ANDROID_IDLE_PROFILE\n"
    "#define SAKAMOTO_ANDROID_IDLE_DIAG_MAX_THREADS 256\n"
    "typedef struct\n"
    "{\n"
    "  u64 poll_calls;\n"
    "  u64 skip_total;\n"
    "  u64 skip_vectors;\n"
    "  u64 skip_polling_inputs;\n"
    "  u64 skip_api_queue;\n"
    "  u64 skip_barrier_recent;\n"
    "  u64 barrier_wait_epoll;\n"
    "  u64 interrupt_pending_epoll;\n"
    "  u64 sleep_enter;\n"
    "  u64 epoll_waits;\n"
    "  u64 epoll_ready;\n"
    "  u64 epoll_zero;\n"
    "  u64 epoll_error;\n"
    "  u64 epoll_ready_events;\n"
    "  u32 last_reason;\n"
    "  u32 last_timeout_ms;\n"
    "  u32 last_ticks;\n"
    "  u32 last_polling_inputs;\n"
    "  u32 last_vectors;\n"
    "} sakamoto_android_idle_diag_t;\n\n"
    "static sakamoto_android_idle_diag_t\n"
    "  sakamoto_android_idle_diags[SAKAMOTO_ANDROID_IDLE_DIAG_MAX_THREADS];\n\n"
    "static_always_inline sakamoto_android_idle_diag_t *\n"
    "sakamoto_android_idle_diag_get (vlib_main_t *vm)\n"
    "{\n"
    "  if (vm->thread_index >= SAKAMOTO_ANDROID_IDLE_DIAG_MAX_THREADS)\n"
    "    return 0;\n"
    "  return &sakamoto_android_idle_diags[vm->thread_index];\n"
    "}\n\n"
    "static clib_error_t *\n"
    "show_sakamoto_android_idle_diag_fn (vlib_main_t *vm,\n"
    "\t\t\t\t       unformat_input_t *input,\n"
    "\t\t\t\t       vlib_cli_command_t *cmd)\n"
    "{\n"
    "  u32 n_threads = vlib_get_n_threads ();\n"
    "  vlib_cli_output (vm,\n"
    "\t\t   \"thread name poll_calls skip_total skip_vectors skip_polling_inputs \"\n"
    "\t\t   \"skip_api_queue skip_barrier_recent barrier_wait_epoll \"\n"
    "\t\t   \"interrupt_pending_epoll sleep_enter epoll_waits epoll_ready \"\n"
    "\t\t   \"epoll_zero epoll_error epoll_ready_events last_reason \"\n"
    "\t\t   \"last_timeout_ms last_ticks last_polling_inputs last_vectors\");\n"
    "  for (u32 i = 0; i < n_threads &&\n"
    "\t\t  i < SAKAMOTO_ANDROID_IDLE_DIAG_MAX_THREADS;\n"
    "\t       i++)\n"
    "    {\n"
    "      sakamoto_android_idle_diag_t *d = &sakamoto_android_idle_diags[i];\n"
    "      vlib_cli_output (vm,\n"
    "\t\t       \"%u %s %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu \"\n"
    "\t\t       \"%llu %llu %llu %llu %u %u %u %u %u\",\n"
    "\t\t       i, i == 0 ? \"main\" : \"worker\",\n"
    "\t\t       d->poll_calls, d->skip_total, d->skip_vectors,\n"
    "\t\t       d->skip_polling_inputs, d->skip_api_queue,\n"
    "\t\t       d->skip_barrier_recent, d->barrier_wait_epoll,\n"
    "\t\t       d->interrupt_pending_epoll, d->sleep_enter, d->epoll_waits,\n"
    "\t\t       d->epoll_ready, d->epoll_zero, d->epoll_error,\n"
    "\t\t       d->epoll_ready_events, d->last_reason,\n"
    "\t\t       d->last_timeout_ms, d->last_ticks,\n"
    "\t\t       d->last_polling_inputs, d->last_vectors);\n"
    "    }\n"
    "  return 0;\n"
    "}\n\n"
    "VLIB_CLI_COMMAND (show_sakamoto_android_idle_diag_command, static) = {\n"
    "  .path = \"show sakamoto android-idle\",\n"
    "  .short_help = \"show sakamoto android-idle\",\n"
    "  .function = show_sakamoto_android_idle_diag_fn,\n"
    "};\n"
    "#endif\n",
)


replace_once(
    "vlib/tw_funcs.h",
    "#define VLIB_TW_TICKS_PER_SECOND 1e5 /* 10 us */",
    "#ifdef SAKAMOTO_VPP_ANDROID_IDLE_PROFILE\n"
    "#define VLIB_TW_TICKS_PER_SECOND 1e3 /* 1 ms */\n"
    "#else\n"
    "#define VLIB_TW_TICKS_PER_SECOND 1e5 /* 10 us */\n"
    "#endif",
)

replace_once(
    "vlib/file.c",
    "  int timeout_ms = 0, max_timeout_ms = 10;\n  u32 ticks;",
    "#ifdef SAKAMOTO_VPP_ANDROID_IDLE_PROFILE\n"
    "  int timeout_ms = 0, max_timeout_ms = 1000;\n"
    "#else\n"
    "  int timeout_ms = 0, max_timeout_ms = 10;\n"
    "#endif\n"
    "  u32 ticks;\n"
    "#ifdef SAKAMOTO_VPP_ANDROID_IDLE_PROFILE\n"
    "  sakamoto_android_idle_diag_t *sakamoto_diag =\n"
    "    sakamoto_android_idle_diag_get (vm);\n"
    "  u32 sakamoto_last_vectors = vlib_last_vectors_per_main_loop (vm);\n"
    "  if (sakamoto_diag)\n"
    "    {\n"
    "      sakamoto_diag->poll_calls++;\n"
    "      sakamoto_diag->last_vectors = sakamoto_last_vectors;\n"
    "      sakamoto_diag->last_polling_inputs =\n"
    "\tnm->input_node_counts_by_state[VLIB_NODE_STATE_POLLING];\n"
    "    }\n"
    "#endif",
)

replace_once(
    "vlib/file.c",
    "  /* at least one node is polling */\n"
    "  if (nm->input_node_counts_by_state[VLIB_NODE_STATE_POLLING])\n"
    "    goto skip_loops;\n",
    "  /* at least one node is polling */\n"
    "#ifdef SAKAMOTO_VPP_ANDROID_IDLE_PROFILE\n"
    "  /* SAKAMOTO_ANDROID_WORKER_IDLE_IGNORES_CLONED_POLLING_INPUTS\n"
    "   * Android VPN workers receive owner work through frame queues and\n"
    "   * eventfd-backed file wakeups.  A VPP worker clone still inherits many\n"
    "   * default POLLING input nodes even when none of them has work; treating\n"
    "   * that clone-time count as busy keeps idle workers in a tight loop. */\n"
    "  if (is_main && nm->input_node_counts_by_state[VLIB_NODE_STATE_POLLING])\n"
    "    {\n"
    "      if (sakamoto_diag)\n"
    "\t{\n"
    "\t  sakamoto_diag->skip_polling_inputs++;\n"
    "\t  sakamoto_diag->last_reason = 2;\n"
    "\t}\n"
    "      goto skip_loops;\n"
    "    }\n"
    "#else\n"
    "  if (nm->input_node_counts_by_state[VLIB_NODE_STATE_POLLING])\n"
    "    goto skip_loops;\n"
    "#endif\n",
)

replace_once(
    "vlib/file.c",
    "  if (vlib_last_vectors_per_main_loop (vm) >= 2)\n"
    "    goto skip_loops;\n",
    "#ifdef SAKAMOTO_VPP_ANDROID_IDLE_PROFILE\n"
    "  if (sakamoto_last_vectors >= 2)\n"
    "    {\n"
    "      if (sakamoto_diag)\n"
    "\t{\n"
    "\t  sakamoto_diag->skip_vectors++;\n"
    "\t  sakamoto_diag->last_reason = 1;\n"
    "\t}\n"
    "      goto skip_loops;\n"
    "    }\n"
    "#else\n"
    "  if (vlib_last_vectors_per_main_loop (vm) >= 2)\n"
    "    goto skip_loops;\n"
    "#endif\n",
)

replace_once(
    "vlib/file.c",
    "  if (is_main && vm->api_queue_nonempty)\n"
    "    goto skip_loops;\n",
    "#ifdef SAKAMOTO_VPP_ANDROID_IDLE_PROFILE\n"
    "  if (is_main && vm->api_queue_nonempty)\n"
    "    {\n"
    "      if (sakamoto_diag)\n"
    "\t{\n"
    "\t  sakamoto_diag->skip_api_queue++;\n"
    "\t  sakamoto_diag->last_reason = 3;\n"
    "\t}\n"
    "      goto skip_loops;\n"
    "    }\n"
    "#else\n"
    "  if (is_main && vm->api_queue_nonempty)\n"
    "    goto skip_loops;\n"
    "#endif\n",
)

replace_once(
    "vlib/file.c",
    "      if (*vlib_worker_threads->wait_at_barrier)\n"
    "\tgoto epoll;\n"
    "\n"
    "      if (vlib_get_first_main ()->time_last_barrier_release + 0.5 >=\n"
    "\t  vlib_time_now (vm))\n"
    "\tgoto skip_loops;\n",
    "      if (*vlib_worker_threads->wait_at_barrier)\n"
    "\t{\n"
    "#ifdef SAKAMOTO_VPP_ANDROID_IDLE_PROFILE\n"
    "\t  if (sakamoto_diag)\n"
    "\t    {\n"
    "\t      sakamoto_diag->barrier_wait_epoll++;\n"
    "\t      sakamoto_diag->last_reason = 5;\n"
    "\t    }\n"
    "#endif\n"
    "\t  goto epoll;\n"
    "\t}\n"
    "\n"
    "      if (vlib_get_first_main ()->time_last_barrier_release + 0.5 >=\n"
    "\t  vlib_time_now (vm))\n"
    "\t{\n"
    "#ifdef SAKAMOTO_VPP_ANDROID_IDLE_PROFILE\n"
    "\t  if (sakamoto_diag)\n"
    "\t    {\n"
    "\t      sakamoto_diag->skip_barrier_recent++;\n"
    "\t      sakamoto_diag->last_reason = 4;\n"
    "\t    }\n"
    "#endif\n"
    "\t  goto skip_loops;\n"
    "\t}\n",
)

replace_once(
    "vlib/file.c",
    "  for (int nt = 0; nt < VLIB_N_NODE_TYPE; nt++)\n"
    "    if (nm->node_interrupts[nt] &&\n"
    "\tclib_interrupt_is_any_pending (nm->node_interrupts[nt]))\n"
    "      goto epoll;\n",
    "  for (int nt = 0; nt < VLIB_N_NODE_TYPE; nt++)\n"
    "    if (nm->node_interrupts[nt] &&\n"
    "\tclib_interrupt_is_any_pending (nm->node_interrupts[nt]))\n"
    "      {\n"
    "#ifdef SAKAMOTO_VPP_ANDROID_IDLE_PROFILE\n"
    "\tif (sakamoto_diag)\n"
    "\t  {\n"
    "\t    sakamoto_diag->interrupt_pending_epoll++;\n"
    "\t    sakamoto_diag->last_reason = 6;\n"
    "\t  }\n"
    "#endif\n"
    "\tgoto epoll;\n"
    "      }\n",
)

replace_once(
    "vlib/file.c",
    "  __atomic_store_n (&vm->thread_sleeps, 1, __ATOMIC_RELAXED);\n",
    "#ifdef SAKAMOTO_VPP_ANDROID_IDLE_PROFILE\n"
    "  if (sakamoto_diag)\n"
    "    {\n"
    "      sakamoto_diag->sleep_enter++;\n"
    "      sakamoto_diag->last_reason = 7;\n"
    "    }\n"
    "#endif\n"
    "  __atomic_store_n (&vm->thread_sleeps, 1, __ATOMIC_RELAXED);\n",
)

replace_once(
    "vlib/file.c",
    "  else\n"
    "    timeout_ms = max_timeout_ms;\n"
    "\n"
    "  goto epoll;\n",
    "  else\n"
    "    timeout_ms = max_timeout_ms;\n"
    "\n"
    "#ifdef SAKAMOTO_VPP_ANDROID_IDLE_PROFILE\n"
    "  if (sakamoto_diag)\n"
    "    {\n"
    "      sakamoto_diag->last_ticks = ticks;\n"
    "      sakamoto_diag->last_timeout_ms = (u32) timeout_ms;\n"
    "    }\n"
    "#endif\n"
    "\n"
    "  goto epoll;\n",
)

replace_once(
    "vlib/file.c",
    "skip_loops:\n"
    "  /* Don't come back for a respectable number of dispatch cycles */\n",
    "skip_loops:\n"
    "#ifdef SAKAMOTO_VPP_ANDROID_IDLE_PROFILE\n"
    "  if (sakamoto_diag)\n"
    "    sakamoto_diag->skip_total++;\n"
    "#endif\n"
    "  /* Don't come back for a respectable number of dispatch cycles */\n",
)

replace_once(
    "vlib/file.c",
    "  n_fds_ready = epoll_wait (vm->epoll_fd, epoll_events,\n"
    "\t\t\t    ARRAY_LEN (epoll_events), timeout_ms);\n"
    "\n"
    "  __atomic_store_n (&vm->thread_sleeps, 0, __ATOMIC_RELAXED);\n",
    "  n_fds_ready = epoll_wait (vm->epoll_fd, epoll_events,\n"
    "\t\t\t    ARRAY_LEN (epoll_events), timeout_ms);\n"
    "\n"
    "#ifdef SAKAMOTO_VPP_ANDROID_IDLE_PROFILE\n"
    "  if (sakamoto_diag)\n"
    "    {\n"
    "      sakamoto_diag->epoll_waits++;\n"
    "      if (n_fds_ready < 0)\n"
    "\tsakamoto_diag->epoll_error++;\n"
    "      else if (n_fds_ready == 0)\n"
    "\tsakamoto_diag->epoll_zero++;\n"
    "      else\n"
    "\t{\n"
    "\t  sakamoto_diag->epoll_ready++;\n"
    "\t  sakamoto_diag->epoll_ready_events += n_fds_ready;\n"
    "\t}\n"
    "    }\n"
    "#endif\n"
    "\n"
    "  __atomic_store_n (&vm->thread_sleeps, 0, __ATOMIC_RELAXED);\n",
)

idle_wait_block = """
#ifdef SAKAMOTO_VPP_ANDROID_IDLE_PROFILE
  uword *sakamoto_idle_event_data = 0;
  while (1)
    {
      vlib_process_wait_for_event (vm);
      while (vlib_process_get_events (vm, &sakamoto_idle_event_data) != ~0)
        vec_reset_length (sakamoto_idle_event_data);
    }
#endif
"""

for rel in (
    "vnet/ip/reass/ip4_full_reass.c",
    "vnet/ip/reass/ip6_full_reass.c",
    "vnet/ip/reass/ip4_sv_reass.c",
    "vnet/ip/reass/ip6_sv_reass.c",
):
    replace_once(
        rel,
        "  uword event_type, *event_data = 0;\n",
        "  uword event_type, *event_data = 0;\n" + idle_wait_block,
    )

for rel in ("vnet/ip6-nd/ip6_mld.c", "vnet/ip6-nd/ip6_ra.c"):
    replace_once(
        rel,
        "  /* init code here */\n\n  while (1)\n",
        "  /* init code here */\n" + idle_wait_block + "\n  while (1)\n",
    )

replace_once(
    "vnet/fib/fib_walk.c",
    "    sleep_time = fib_walk_sleep_duration[FIB_WALK_SHORT_SLEEP];\n\n    while (1)\n",
    "    sleep_time = fib_walk_sleep_duration[FIB_WALK_SHORT_SLEEP];\n"
    + idle_wait_block
    + "\n    while (1)\n",
)

replace_once(
    "vlib/stats/collector.c",
    "  sm->directory_vector[STAT_COUNTER_BOOTTIME].value = unix_time_now ();\n\n  while (1)\n",
    "  sm->directory_vector[STAT_COUNTER_BOOTTIME].value = unix_time_now ();\n"
    + idle_wait_block
    + "\n  while (1)\n",
)

replace_once(
    "plugins/tun_poc/tun_poc.c",
    "static u8\n"
    "tun_poc_a25_stage (tun_poc_main_t *tm)\n"
    "{\n"
    "  const char *stage = tun_poc_ledger_stage (tm);\n"
    "  return (tm && tm->strict_owner_pending) || strncmp (stage, \"A2-5\", 4) == 0;\n"
    "}\n",
    "static const char *\n"
    "tun_poc_ledger_cell (void)\n"
    "{\n"
    "  const char *cell = getenv (\"SAKAMOTO_A2_STAGE_CELL\");\n"
    "  return cell && cell[0] ? cell : \"unknown\";\n"
    "}\n\n"
    "static u8\n"
    "tun_poc_a25_stage (tun_poc_main_t *tm)\n"
    "{\n"
    "  const char *stage = tun_poc_ledger_stage (tm);\n"
    "  return (tm && tm->strict_owner_pending) || strncmp (stage, \"A2-5\", 4) == 0;\n"
    "}\n",
)

replace_once(
    "plugins/tun_poc/tun_poc.c",
    "  char query[256];\n"
    "  char response[64];\n"
    "  struct pollfd pfd = { 0 };\n"
    "  int query_len;\n"
    "  int uid;\n"
    "  ssize_t rv;",
    "  char stage_id[128];\n"
    "  char query[512];\n"
    "  char response[64];\n"
    "  struct pollfd pfd = { 0 };\n"
    "  const char *stage;\n"
    "  const char *cell;\n"
    "  u64 request_id;\n"
    "  int query_len;\n"
    "  int uid;\n"
    "  ssize_t rv;",
)

replace_once(
    "plugins/tun_poc/tun_poc.c",
    "  query_len = snprintf (query, sizeof (query),\n"
    "\t\t\t\"resolve ip%u proto %u %s %u %s %u\\n\",\n"
    "\t\t\ttm->last_tuple_ip_version, tm->last_tuple_protocol, src,\n"
    "\t\t\ttm->last_tuple_src_port, dst,\n"
    "\t\t\ttm->last_tuple_dst_port);\n"
    "  if (query_len <= 0 || query_len >= (int) sizeof (query))\n"
    "    {\n"
    "\t  tm->resolver_errors++;\n"
    "\t  return -1;\n"
    "    }\n\n"
    "  tm->resolver_queries++;\n",
    "  /* Capture correlation at request creation.  The resolver is asynchronous;\n"
    "   * sampling the mutable stage in its completion thread can attribute a\n"
    "   * delayed lookup to the next stage. */\n"
    "  stage = tun_poc_ledger_stage (tm);\n"
    "  snprintf (stage_id, sizeof (stage_id), \"%s\", stage);\n"
    "  cell = tun_poc_ledger_cell ();\n"
    "  request_id = ++tm->resolver_queries;\n"
    "  query_len = snprintf (query, sizeof (query),\n"
    "\t\t\t\"resolve ip%u proto %u %s %u %s %u cell %s stage %s \"\n"
    "\t\t\t\"request %llu\\n\",\n"
    "\t\t\ttm->last_tuple_ip_version, tm->last_tuple_protocol, src,\n"
    "\t\t\ttm->last_tuple_src_port, dst,\n"
    "\t\t\ttm->last_tuple_dst_port, cell, stage_id,\n"
    "\t\t\t(unsigned long long) request_id);\n"
    "  if (query_len <= 0 || query_len >= (int) sizeof (query))\n"
    "    {\n"
    "\t  tm->resolver_errors++;\n"
    "\t  return -1;\n"
    "    }\n",
)
PY

echo "Applied Android CMake overlay to $VPP_SRC_DIR"
