/* SPDX-License-Identifier: Apache-2.0 */
/* Same-process public VAPI/observation lifecycle; no mocked allocator. */
#include "sakamoto_product_observation.h"
#include "sakamoto_product_abi.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vapi/vapi.h>
#include <vppinfra/mem.h>

typedef struct {
  void *heap;
  unsigned allocations, failures;
} result_t;

static const char *api_socket;
static sakamoto_product_session_t *session;
static unsigned lifecycle;
static const char *observation_path;

static void *
product_client (void *argument)
{
  result_t *result = argument;
  sakamoto_product_status_t status;
  if (!session) {
    sakamoto_product_bytes_t path = {(const uint8_t *) api_socket, strlen(api_socket)};
    if (sakamoto_product_session_connect(path, 314001, &session, &status)) {
      ++result->failures;
      return NULL;
    }
  }
  result->heap = clib_mem_get_heap();
  sakamoto_product_rule_config_request_t *request = calloc(1, sizeof(*request));
  sakamoto_product_rule_config_status_t *config = calloc(1, sizeof(*config));
  if (!request || !config) exit(2);
  request->schema = 1;
  request->operation = SAKAMOTO_RULE_CONFIG_QUERY;
  for (unsigned i = 0; i < 32; ++i)
    if (sakamoto_product_session_rule_config(session, 314001, request, config)
        || config->count != 0) ++result->failures;
  free(request);
  free(config);
  if (lifecycle++) {
    if (sakamoto_product_session_destroy(session)) ++result->failures;
    session = NULL;
  }
  printf("product_lifecycle=%u failures=%u\n", lifecycle, result->failures);
  fflush(stdout);
  return NULL;
}

static void *
vapi_client (void *argument)
{
  result_t *result = argument;
  vapi_ctx_t context = NULL;
  if (vapi_ctx_alloc (&context) != VAPI_OK) {
    ++result->failures;
    return NULL;
  }
  result->heap = clib_mem_get_heap ();
  for (unsigned index = 0; index < result->allocations; ++index) {
    /* A typed RuleConfig receive allocates VPP vectors. Probe available
     * capacity with the fallible allocator instead of deliberately aborting. */
    void *allocation = clib_mem_alloc_or_null (2U * 1024U * 1024U);
    if (!allocation) ++result->failures;
    else clib_mem_free (allocation);
  }
  vapi_ctx_free (context);
  return NULL;
}

static void *
observation_client (void *argument)
{
  result_t *result = argument;
  product_observation_transport_t *transport =
    product_observation_connect_for_owners (
      observation_path ? observation_path : "/nonexistent/s314-observation.sock", 77, 2);
  if (observation_path && transport) {
    product_observation_record_t record;
    product_observation_status_t status;
    product_observation_transport_status (transport, &status);
    int received = 0;
    for (unsigned i = 0; i < 200 && !received; ++i) {
      received = product_observation_receive (transport, 0, &record, sizeof(record));
      if (!received) usleep (10000);
    }
    if (received != 1 || record.generation != 77 || record.incarnation != 1
        || record.sequence != 1 || record.packets[0] != 1
        || status.owners != 2) ++result->failures;
    printf ("normal_observation_records=%d failures=%u\n", received, result->failures);
    product_observation_transport_destroy (transport);
  } else if (transport || observation_path) {
    product_observation_transport_destroy (transport);
    ++result->failures;
  }
  result->heap = clib_mem_get_heap ();
  return NULL;
}

static void
run_thread (void *(*operation) (void *), result_t *result)
{
  pthread_t thread;
  if (pthread_create (&thread, NULL, operation, result) || pthread_join (thread, NULL)) {
    fputs ("pthread lifecycle failed\n", stderr);
    exit (2);
  }
}

int
main (int argc, char **argv)
{
  if (argc < 2 || argc > 4) return 2;
  if (argc >= 3) api_socket = argv[2];
  if (argc == 4) observation_path = argv[3];
  result_t first = {.allocations = 32}, observer = {0}, next = {.allocations = 32};
  int observer_first = !strcmp (argv[1], "observer-first");
  int with_observer = strcmp (argv[1], "vapi-only") != 0;
  if (observer_first) run_thread (observation_client, &observer);
  run_thread (api_socket ? product_client : vapi_client, &first);
  void *process_heap = clib_mem_main.main_heap;
  if (with_observer && !observer_first) run_thread (observation_client, &observer);
  run_thread (api_socket ? product_client : vapi_client, &next);
  /* An ordinary new lifecycle connects, queries configuration and destroys
   * its own context after the preceding lifecycle/observer have stopped. */
  if (observation_path) run_thread (product_client, &next);
  int preserved = process_heap == clib_mem_main.main_heap;
  int inherited = first.heap == next.heap && next.heap == clib_mem_main.main_heap;
  int shared = !with_observer || observer.heap == clib_mem_main.main_heap;
  printf ("mode=%s preserved=%d inherited=%d consumer_shared=%d "
          "first_allocation_failures=%u next_allocation_failures=%u observer_failures=%u\n",
          argv[1], preserved, inherited, shared, first.failures, next.failures, observer.failures);
  return !preserved || !inherited || !shared || first.failures || next.failures || observer.failures;
}
