/* Supervisor lifecycle acceptance client. No packet data or VPP buffer ABI. */
#define _POSIX_C_SOURCE 200809L
#include "sakamoto_product_core_ffi.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value)) exit(2);
  return (uint64_t)value.tv_sec * 1000000000 + value.tv_nsec;
}
static sakamoto_product_bytes_t bytes(const char *text) {
  return (sakamoto_product_bytes_t){(const uint8_t *)text, (uint32_t)strlen(text)};
}
static void status_line(const char *phase, uint32_t code, const sakamoto_product_status_t *s) {
  printf("status phase=%s code=%u generation=%llu adapter=%u enabled=%u accepting=%u buffers=%llu obligations=%llu handoffs=%llu verdicts=%llu succeeded=%llu failed=%llu identity=%s artifact=%s mono_ns=%llu\n",
    phase, code, (unsigned long long)s->generation, s->adapter_available,
    s->product_graph_enabled, s->product_graph_accepting,
    (unsigned long long)s->product_graph_buffer_debt,
    (unsigned long long)s->product_graph_obligation_debt,
    (unsigned long long)s->product_graph_handoff_debt,
    (unsigned long long)s->root_nfqueue_verdict_attempts,
    (unsigned long long)s->root_nfqueue_verdict_succeeded,
    (unsigned long long)s->root_nfqueue_verdict_failed_definite,
    s->api_identity, s->artifact_id, (unsigned long long)now_ns());
}
int main(int argc, char **argv) {
  if (argc == 2 && !strcmp(argv[1], "clock")) {
    printf("clock mono_ns=%llu\n", (unsigned long long)now_ns());
    return 0;
  }
  /* query socket generation | stop socket generation expected-generation budget-ms [gate] */
  if ((argc != 4 || strcmp(argv[1], "query"))
      && ((argc != 6 && argc != 7) || strcmp(argv[1], "stop"))) return 2;
  setvbuf(stdout, NULL, _IOLBF, 0);
  uint64_t generation = strtoull(argv[3], NULL, 10);
  uint64_t expected = argc >= 6 ? strtoull(argv[4], NULL, 10) : generation;
  unsigned budget = argc >= 6 ? strtoul(argv[5], NULL, 10) : 0;
  if (!generation || !expected || budget > 5000) return 2;
  sakamoto_product_core_handle_t *handle = NULL;
  sakamoto_product_status_t status = {0};
  uint32_t code = sakamoto_product_core_connect(bytes(argv[2]), generation, &handle, &status);
  status_line("connect", code, &status);
  if (code) return (int)code;
  if (argc == 7) {
    printf("stop_ready generation=%llu mono_ns=%llu\n", (unsigned long long)generation,
           (unsigned long long)now_ns());
    uint64_t deadline = now_ns()+20000000000ULL;
    while (access(argv[6], F_OK)) {
      if (errno != ENOENT || now_ns() >= deadline) return 1;
      struct timespec pause = {0, 1000000};
      nanosleep(&pause, NULL);
    }
  }
  uint32_t stopped = 0;
  uint64_t started = now_ns();
  if (argc >= 6) {
    unsigned step = 0;
    do {
      uint64_t before = now_ns();
      code = sakamoto_product_core_stop_root(handle, expected, &stopped);
      printf("stop_step generation=%llu expected=%llu step=%u code=%u stopped=%u begin_ns=%llu end_ns=%llu\n",
        (unsigned long long)generation, (unsigned long long)expected, step++, code, stopped,
        (unsigned long long)before, (unsigned long long)now_ns());
      if (code || stopped || now_ns() - started >= (uint64_t)budget * 1000000) break;
      struct timespec pause = {0, 10000000};
      nanosleep(&pause, NULL);
    } while (1);
    if (!code && stopped) {
      code = sakamoto_product_core_query(handle, generation, &status);
      status_line("stopped", code, &status);
    }
  }
  uint32_t disconnected = sakamoto_product_core_disconnect(handle);
  uint32_t destroyed = sakamoto_product_core_destroy(handle);
  printf("client_close disconnected=%u destroyed=%u stopped=%u elapsed_ns=%llu\n",
    disconnected, destroyed, stopped, (unsigned long long)(now_ns() - started));
  return code ? (int)code : (disconnected || destroyed ? 1 : (argc >= 6 && !stopped));
}
