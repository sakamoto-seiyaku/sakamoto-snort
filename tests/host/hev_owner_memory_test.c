/* SPDX-License-Identifier: MIT */
#include "hev-lwip-context.h"
#include "lwip/init.h"
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

unsigned int lwip_port_rand(void) { return 1234; }

int main(void)
{
  hev_lwip_context_t a, b;
  hev_lwip_context_init(&a);
  hev_lwip_context_init(&b);
  hev_lwip_context_bind(&a);
  lwip_init();
  unsigned char *bytes = hev_lwip_calloc(8, 3);
  assert(bytes && (uintptr_t)bytes % _Alignof(max_align_t) == 0);
  for (unsigned i = 0; i < 24; ++i) assert(bytes[i] == 0);
  assert(a.heap_live == 1 && a.heap_bytes == 24);
  assert(!hev_lwip_malloc(SIZE_MAX));
  assert(!hev_lwip_calloc(SIZE_MAX, 2));
  assert(a.heap_allocations == 1);
  struct pbuf *pool = pbuf_alloc(PBUF_RAW, 5000, PBUF_POOL);
  struct pbuf *ram = pbuf_alloc(PBUF_RAW, 10, PBUF_RAM);
  struct pbuf *ref = pbuf_alloc_reference(bytes, 24, PBUF_REF);
  struct udp_pcb *pcb = udp_new();
  assert(pool && ram && ref && pcb);
  assert(a.pbuf_live[HEV_LWIP_PBUF_POOL] == 3);
  assert(a.pbuf_live[HEV_LWIP_PBUF_RAM] == 1);
  assert(a.pbuf_live[HEV_LWIP_PBUF_REF] == 1);
  assert(a.heap_live == 7 && a.heap_bytes > 5000);
  hev_lwip_context_bind(&b);
  void *other = hev_lwip_malloc(7);
  assert(other && b.heap_live == 1 && b.heap_bytes == 7);
  pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    struct rlimit limit = {0, 0};
    (void)setrlimit(RLIMIT_CORE, &limit);
    hev_lwip_free(bytes); /* belongs to a; deterministic fatal misuse */
    _exit(99);
  }
  int status;
  assert(waitpid(child, &status, 0) == child);
  assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
  assert(b.heap_live == 1 && b.heap_bytes == 7);
  hev_lwip_free(other);
  hev_lwip_context_bind(&a);
  pbuf_free(pool); pbuf_free(ram); pbuf_free(ref); udp_remove(pcb);
  assert(a.heap_live == 1 && a.heap_bytes == 24);
  hev_lwip_free(bytes);
  assert(!a.heap_live && !a.heap_bytes && !a.pbufs);
  assert(a.heap_allocations == a.heap_frees);
  assert(!b.heap_live && !b.heap_bytes && b.heap_allocations == b.heap_frees);
  hev_lwip_context_bind(NULL);
  hev_lwip_free(NULL);
  return 0;
}
