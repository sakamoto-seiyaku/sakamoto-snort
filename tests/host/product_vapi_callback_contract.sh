#!/usr/bin/env bash
set -euo pipefail

# Real generated VAPI headers/runtime are unavailable in this Host checkout.
# Compile the production bridge against a tiny API-shaped stub and exercise
# the one failure real VAPI cannot currently cover: vapi_product_core_status()
# returns VAPI_OK but never invokes the callback. The bridge must not turn that
# into a successful status.

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
stub_dir="$(mktemp -d /tmp/sakamoto-vapi-callback-contract.XXXXXX)"
cleanup() {
  rm -rf -- "$stub_dir"
}
trap cleanup EXIT
mkdir -p "$stub_dir/vapi"

cat > "$stub_dir/vapi/vapi_stub.h" <<'EOF'
#ifndef SAKAMOTO_TEST_VAPI_STUB_H
#define SAKAMOTO_TEST_VAPI_STUB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef void *vapi_ctx_t;
typedef unsigned int vapi_msg_id_t;
typedef int vapi_error_e;
typedef struct {
  uint32_t retval;
  uint32_t abi_version;
  uint32_t api_version;
  uint64_t generation;
  uint8_t core_ready;
  uint8_t adapter_available;
  uint8_t protection_running;
  uint8_t artifact_id[96];
  uint8_t api_identity[96];
  uint8_t vpp_revision[48];
} vapi_payload_product_core_status_reply;
typedef struct {
  struct {
    uint32_t client_index;
    uint32_t context;
    uint16_t _vl_msg_id;
  } header;
} vapi_msg_product_core_status;
typedef vapi_error_e (*vapi_product_core_status_callback_t)(
  vapi_ctx_t, void *, vapi_error_e, bool,
  vapi_payload_product_core_status_reply *);

#define VAPI_OK 0
#define VAPI_EINVAL 22
#define VAPI_MODE_BLOCKING 1
#define DEFINE_VAPI_MSG_IDS_MEMCLNT_API_JSON \
  vapi_msg_id_t vapi_msg_id_memclnt;
#define DEFINE_VAPI_MSG_IDS_VLIB_API_JSON \
  vapi_msg_id_t vapi_msg_id_vlib;
#define DEFINE_VAPI_MSG_IDS_PRODUCT_CORE_API_JSON \
  vapi_msg_id_t vapi_msg_id_product_core_status; \
  vapi_msg_id_t vapi_msg_id_product_core_status_reply;

extern vapi_msg_id_t vapi_msg_id_product_core_status;
extern vapi_msg_id_t vapi_msg_id_product_core_status_reply;

vapi_error_e vapi_ctx_alloc(vapi_ctx_t *);
void vapi_ctx_free(vapi_ctx_t);
bool vapi_is_msg_available(vapi_ctx_t, vapi_msg_id_t);
vapi_error_e vapi_connect_ex(vapi_ctx_t, const char *, const char *, int, int,
                             int, bool, bool);
void vapi_disconnect(vapi_ctx_t);
vapi_msg_product_core_status *vapi_alloc_product_core_status(vapi_ctx_t);
vapi_error_e vapi_product_core_status(
  vapi_ctx_t, vapi_msg_product_core_status *,
  vapi_product_core_status_callback_t, void *);

extern int sakamoto_test_request_available;
extern int sakamoto_test_reply_available;
extern int sakamoto_test_send_calls;
extern int sakamoto_test_send_invalid_id_calls;
extern int sakamoto_test_omit_callback;

#endif
EOF
for header in memclnt.api.vapi.h vapi.h vlib.api.vapi.h product_core.api.vapi.h; do
  printf '%s\n' '#include "vapi_stub.h"' > "$stub_dir/vapi/$header"
done

cat > "$stub_dir/vapi_stub.c" <<'EOF'
#include "vapi/vapi_stub.h"
#include <stdlib.h>

int sakamoto_test_request_available = 1;
int sakamoto_test_reply_available = 1;
int sakamoto_test_send_calls = 0;
int sakamoto_test_send_invalid_id_calls = 0;
int sakamoto_test_omit_callback = 0;

vapi_error_e
vapi_ctx_alloc (vapi_ctx_t *context)
{
  *context = (vapi_ctx_t) (uintptr_t) 1U;
  vapi_msg_id_product_core_status = 100U;
  vapi_msg_id_product_core_status_reply = 101U;
  return VAPI_OK;
}

void
vapi_ctx_free (vapi_ctx_t context)
{
  (void) context;
}

bool
vapi_is_msg_available (vapi_ctx_t context, vapi_msg_id_t type)
{
  (void) context;
  if (type == vapi_msg_id_product_core_status)
    return sakamoto_test_request_available != 0;
  if (type == vapi_msg_id_product_core_status_reply)
    return sakamoto_test_reply_available != 0;
  return false;
}

vapi_error_e
vapi_connect_ex (vapi_ctx_t context, const char *name, const char *socket,
                 int retries, int timeout, int mode, bool do_pthread,
                 bool do_auto_handle)
{
  (void) context;
  (void) name;
  (void) socket;
  (void) retries;
  (void) timeout;
  (void) mode;
  (void) do_pthread;
  (void) do_auto_handle;
  return VAPI_OK;
}

void
vapi_disconnect (vapi_ctx_t context)
{
  (void) context;
}

vapi_msg_product_core_status *
vapi_alloc_product_core_status (vapi_ctx_t context)
{
  (void) context;
  vapi_msg_product_core_status *message =
    calloc (1U, sizeof (vapi_msg_product_core_status));
  if (message != NULL)
    message->header._vl_msg_id =
      sakamoto_test_request_available ? 7U : UINT16_MAX;
  return message;
}

vapi_error_e
vapi_product_core_status (vapi_ctx_t context,
                          vapi_msg_product_core_status *message,
                          vapi_product_core_status_callback_t callback,
                          void *callback_context)
{
  (void) context;
  ++sakamoto_test_send_calls;
  if (message->header._vl_msg_id == UINT16_MAX)
    ++sakamoto_test_send_invalid_id_calls;
  if (sakamoto_test_omit_callback)
    return VAPI_OK;
  vapi_payload_product_core_status_reply reply = {0};
  reply.generation = 77U;
  reply.core_ready = 1U;
  reply.artifact_id[0] = 'a';
  reply.api_identity[0] = 'b';
  reply.vpp_revision[0] = 'c';
  callback (context, callback_context, VAPI_OK, true, &reply);
  return VAPI_OK;
}
EOF

cat > "$stub_dir/harness.c" <<'EOF'
#include "sakamoto_product_abi.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern int sakamoto_test_request_available;
extern int sakamoto_test_reply_available;
extern int sakamoto_test_send_calls;
extern int sakamoto_test_send_invalid_id_calls;
extern int sakamoto_test_omit_callback;

int
main (void)
{
  const char socket_path[] = "/tmp/unused-vapi-callback-contract.sock";
  sakamoto_product_bytes_t path = {
    .data = (const uint8_t *) socket_path,
    .length = (uint32_t) (sizeof (socket_path) - 1U),
  };
  sakamoto_product_session_t *session = NULL;
  sakamoto_product_status_t status;

  sakamoto_test_request_available = 0;
  sakamoto_test_reply_available = 1;
  uint32_t code = sakamoto_product_session_connect (path, 77U, &session,
                                                    &status);
  if (code != SAKAMOTO_PRODUCT_API_UNAVAILABLE
      || status.status_code != SAKAMOTO_PRODUCT_API_UNAVAILABLE
      || session != NULL || sakamoto_test_send_calls != 0
      || sakamoto_test_send_invalid_id_calls != 0)
    {
      fprintf (stderr, "missing VAPI request must not allocate/send\n");
      return 1;
    }

  sakamoto_test_request_available = 1;
  sakamoto_test_reply_available = 0;
  code = sakamoto_product_session_connect (path, 77U, &session, &status);
  if (code != SAKAMOTO_PRODUCT_API_UNAVAILABLE
      || status.status_code != SAKAMOTO_PRODUCT_API_UNAVAILABLE
      || session != NULL || sakamoto_test_send_calls != 0
      || sakamoto_test_send_invalid_id_calls != 0)
    {
      fprintf (stderr, "missing VAPI reply must not allocate/send\n");
      return 1;
    }

  sakamoto_test_request_available = 1;
  sakamoto_test_reply_available = 1;
  code = sakamoto_product_session_connect (path, 77U, &session, &status);
  if (code != SAKAMOTO_PRODUCT_OK || session == NULL
      || sakamoto_test_send_calls != 1
      || sakamoto_test_send_invalid_id_calls != 0)
    {
      fprintf (stderr, "available VAPI messages did not use the normal path\n");
      return 1;
    }
  sakamoto_product_session_destroy (session);
  session = NULL;

  sakamoto_test_omit_callback = 1;
  code = sakamoto_product_session_connect (path, 77U, &session, &status);
  if (code != SAKAMOTO_PRODUCT_QUERY_FAILED
      || status.status_code != SAKAMOTO_PRODUCT_QUERY_FAILED
      || strstr (status.error_detail, "callback was not invoked") == NULL
      || session != NULL)
    {
      fprintf (stderr, "callback omission was not reported as QUERY_FAILED\n");
      return 1;
    }
  return 0;
}
EOF

cc -std=c11 -Wall -Wextra -Werror -pthread \
  -I"$repo_root/src/product/include" -I"$stub_dir" \
  "$repo_root/src/product/native/sakamoto_product_vapi.c" \
  "$stub_dir/vapi_stub.c" "$stub_dir/harness.c" \
  -o "$stub_dir/callback-contract"
"$stub_dir/callback-contract"
echo "sakamoto production VAPI callback contract: PASS"
