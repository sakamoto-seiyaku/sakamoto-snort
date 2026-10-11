#!/usr/bin/env python3
"""Exercise the actual Root error callback at its SO_ERROR/receive seam."""
from pathlib import Path
import resource
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'src/product/vpp/product_root_nfqueue_adapter.c').read_text()
begin = source.index('static clib_error_t *\nproduct_root_nfqueue_error_ready (')
end = source.index('\nstatic void\nproduct_root_nfqueue_reset_lane', begin)
callback = source[begin:end]
prefix = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>
typedef struct { int code; } clib_error_t;
typedef struct { uint64_t generation; int draining; } product_root_nfqueue_lane_t;
typedef struct { uint64_t generation; } product_root_nfqueue_main_t;
typedef struct { uintptr_t private_data; unsigned file_descriptor; } clib_file_t;
#define uword_to_pointer(value, type) ((type)(uintptr_t)(value))
static product_root_nfqueue_main_t product_root_nfqueue_main = { 7 };
static int socket_error, reads, classified, congested;
static clib_file_t *expected_file;
static clib_error_t fatal = { EIO };
static int test_getsockopt(int fd, int level, int option, void *value, socklen_t *length) {
  assert(fd == 27 && level == SOL_SOCKET && option == SO_ERROR);
  assert(*length == sizeof(int));
  *(int *)value = socket_error;
  socket_error = 0; /* SO_ERROR consumption does not acknowledge Netlink congestion. */
  return 0;
}
#define getsockopt test_getsockopt
clib_error_t *product_root_nfqueue_read_ready(clib_file_t *file) {
  assert(file == expected_file);
  reads++;
  congested = 0; /* Bounded receive also acknowledges an empty congested queue. */
  return 0;
}
static clib_error_t *product_root_nfqueue_handle_socket_error(
  product_root_nfqueue_main_t *nm, product_root_nfqueue_lane_t *lane, int error) {
  assert(nm == &product_root_nfqueue_main && lane->generation == nm->generation);
  classified++;
  return error == ENOBUFS || error == EAGAIN || error == EINTR ? 0 : &fatal;
}
'''
test = r'''
int main(void) {
  product_root_nfqueue_lane_t lane = { 7, 0 };
  clib_file_t file = { (uintptr_t)&lane, 27 };
  expected_file = &file;
  socket_error = ENOBUFS; congested = 1;
  assert(product_root_nfqueue_error_ready(&file) == 0);
  assert(reads == 1 && classified == 1 && socket_error == 0 && congested == 0);
  socket_error = EIO;
  assert(product_root_nfqueue_error_ready(&file) == &fatal);
  assert(reads == 1 && classified == 2);
  socket_error = 0;
  assert(product_root_nfqueue_error_ready(&file) == &fatal);
  assert(reads == 1 && classified == 3);
  lane.draining = 1; socket_error = ENOBUFS;
  assert(product_root_nfqueue_error_ready(&file) == 0);
  assert(reads == 1 && classified == 3 && socket_error == ENOBUFS);
  lane.draining = 0; lane.generation = 6;
  assert(product_root_nfqueue_error_ready(&file) == 0);
  assert(reads == 1 && classified == 3 && socket_error == ENOBUFS);
  return 0;
}
'''
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
with tempfile.TemporaryDirectory(prefix='sakamoto-root-error-') as temporary:
    directory = Path(temporary)
    c = directory / 'callback.c'
    c.write_text(prefix + callback + test)
    binary = directory / 'callback'
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(c), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('Root SO_ERROR/receive-progress seam: PASS')
