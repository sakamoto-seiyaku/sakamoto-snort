/* SPDX-License-Identifier: Apache-2.0 */

#include "sakamoto_product_abi.h"
#include "product_wire.h"
#include "sakamoto_product_status.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef SAKAMOTO_PRODUCT_HOST_FIXTURE
#error "The fixture transport is Host-test-only; production must compile sakamoto_product_vapi.c"
#endif

#define SAKAMOTO_PRODUCT_SOCKET_TIMEOUT_MS 2000
#define SAKAMOTO_PRODUCT_SOCKET_PATH_MAX 108

struct sakamoto_product_session {
  int fd;
  uint64_t generation;
  int connected;
  pthread_mutex_t mutex;
};

_Static_assert (offsetof (sakamoto_product_status_t, generation) == 16U,
                "product status generation offset is part of the ABI");
_Static_assert (offsetof (sakamoto_product_status_t, artifact_id) == 52U,
                "product status identity offset is part of the ABI");
_Static_assert (sizeof (sakamoto_product_status_t) == 424U,
                "product status size is part of the ABI");

static int
wait_fd (int fd, short events)
{
  struct pollfd poll_fd = {.fd = fd, .events = events, .revents = 0};
  int result;
  do
    {
      result = poll (&poll_fd, 1U, SAKAMOTO_PRODUCT_SOCKET_TIMEOUT_MS);
    }
  while (result < 0 && errno == EINTR);
  if (result <= 0)
    return result;
  if ((poll_fd.revents & POLLNVAL) != 0
      || (poll_fd.revents & POLLERR) != 0
      || ((events & POLLIN) == 0 && (poll_fd.revents & POLLHUP) != 0)
      || ((events & POLLIN) != 0 && (poll_fd.revents & POLLIN) == 0
          && (poll_fd.revents & POLLHUP) != 0))
    return -1;
  return 1;
}

static int
write_all (int fd, const void *buffer, size_t length)
{
  const unsigned char *cursor = (const unsigned char *) buffer;
  while (length != 0U)
    {
      if (wait_fd (fd, POLLOUT) <= 0)
        return -1;
      ssize_t written = write (fd, cursor, length);
      if (written < 0 && errno == EINTR)
        continue;
      if (written <= 0)
        return -1;
      cursor += (size_t) written;
      length -= (size_t) written;
    }
  return 0;
}

static int
read_all (int fd, void *buffer, size_t length)
{
  unsigned char *cursor = (unsigned char *) buffer;
  while (length != 0U)
    {
      if (wait_fd (fd, POLLIN) <= 0)
        return -1;
      ssize_t read_count = read (fd, cursor, length);
      if (read_count < 0 && errno == EINTR)
        continue;
      if (read_count <= 0)
        return -1;
      cursor += (size_t) read_count;
      length -= (size_t) read_count;
    }
  return 0;
}

static uint32_t
map_transport_error (void)
{
  if (errno == ETIMEDOUT)
    return SAKAMOTO_PRODUCT_QUERY_FAILED;
  return SAKAMOTO_PRODUCT_CONNECT_FAILED;
}

static uint32_t
copy_response (const sakamoto_product_wire_response_t *response,
               uint64_t expected_generation,
               sakamoto_product_status_t *status)
{
  if (response->magic != SAKAMOTO_PRODUCT_WIRE_MAGIC
      || response->version != SAKAMOTO_PRODUCT_WIRE_VERSION)
    {
      sakamoto_product_status_error (status, SAKAMOTO_PRODUCT_PROTOCOL_MISMATCH,
                                      "VAPI response identity mismatch");
      return SAKAMOTO_PRODUCT_PROTOCOL_MISMATCH;
    }
  status->status_code = response->status_code;
  status->generation = response->generation;
  status->core_ready =
    (response->flags & SAKAMOTO_PRODUCT_WIRE_CORE_READY) != 0U;
  status->adapter_available =
    (response->flags & SAKAMOTO_PRODUCT_WIRE_ADAPTER_AVAILABLE) != 0U;
  status->protection_running =
    (response->flags & SAKAMOTO_PRODUCT_WIRE_PROTECTION_RUNNING) != 0U;
  status->plugin_loaded =
    (response->flags & SAKAMOTO_PRODUCT_WIRE_PLUGIN_LOADED) != 0U;
  status->vapi_handle_live =
    (response->flags & SAKAMOTO_PRODUCT_WIRE_VAPI_HANDLE_LIVE) != 0U;
  status->generation_live =
    (response->flags & SAKAMOTO_PRODUCT_WIRE_GENERATION_LIVE) != 0U;
  sakamoto_product_status_copy_text (status->artifact_id,
                                     sizeof (status->artifact_id),
                                     response->artifact_id,
                                     sizeof (response->artifact_id));
  sakamoto_product_status_copy_text (status->api_identity,
                                     sizeof (status->api_identity),
                                     response->api_identity,
                                     sizeof (response->api_identity));
  sakamoto_product_status_copy_text (status->vpp_revision,
                                     sizeof (status->vpp_revision),
                                     response->vpp_revision,
                                     sizeof (response->vpp_revision));
  sakamoto_product_status_copy_text (status->error_detail,
                                     sizeof (status->error_detail),
                                     response->error_detail,
                                     sizeof (response->error_detail));
  if (response->generation != expected_generation)
    {
      sakamoto_product_status_error (
        status, SAKAMOTO_PRODUCT_STALE_HANDLE,
        "VAPI generation does not match the active generation");
      return SAKAMOTO_PRODUCT_STALE_HANDLE;
    }
  return status->status_code;
}

static uint32_t
exchange (sakamoto_product_session_t *session, uint16_t operation,
          sakamoto_product_status_t *status)
{
  sakamoto_product_wire_request_t request = {
    .magic = SAKAMOTO_PRODUCT_WIRE_MAGIC,
    .version = SAKAMOTO_PRODUCT_WIRE_VERSION,
    .operation = operation,
    .generation = session->generation,
  };
  sakamoto_product_wire_response_t response;
  if (write_all (session->fd, &request, sizeof (request)) != 0
      || read_all (session->fd, &response, sizeof (response)) != 0)
    {
      sakamoto_product_status_error (status, map_transport_error (),
                                     "VAPI transport failed");
      return status->status_code;
    }
  return copy_response (&response, session->generation, status);
}

uint32_t
sakamoto_product_abi_version (void)
{
  return SAKAMOTO_PRODUCT_ABI_VERSION;
}

uint32_t
sakamoto_product_api_version (void)
{
  return SAKAMOTO_PRODUCT_API_VERSION;
}

uint32_t
sakamoto_product_session_connect (sakamoto_product_bytes_t api_socket,
                                   uint64_t expected_generation,
                                   sakamoto_product_session_t **out_session,
                                   sakamoto_product_status_t *out_status)
{
  if (out_session != NULL)
    *out_session = NULL;
  sakamoto_product_status_reset (out_status, expected_generation);
  if (out_session == NULL || out_status == NULL || api_socket.data == NULL
      || api_socket.length == 0U || api_socket.length >= SAKAMOTO_PRODUCT_SOCKET_PATH_MAX
      || expected_generation == 0U)
    {
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_INVALID_ARGUMENT,
        "socket path and non-zero generation are required");
      return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
    }
  for (uint32_t index = 0U; index < api_socket.length; ++index)
    if (api_socket.data[index] == 0U)
      {
        sakamoto_product_status_error (
          out_status, SAKAMOTO_PRODUCT_INVALID_ARGUMENT,
          "socket path contains an embedded NUL");
        return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
      }
  struct sockaddr_un address;
  memset (&address, 0, sizeof (address));
  address.sun_family = AF_UNIX;
  memcpy (address.sun_path, api_socket.data, api_socket.length);
  address.sun_path[api_socket.length] = '\0';

  int fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    {
      sakamoto_product_status_error (out_status,
                                     SAKAMOTO_PRODUCT_CONNECT_FAILED,
                                     "cannot create VAPI socket");
      return SAKAMOTO_PRODUCT_CONNECT_FAILED;
    }
  if (connect (fd, (const struct sockaddr *) &address, sizeof (address)) != 0)
    {
      close (fd);
      sakamoto_product_status_error (out_status,
                                     SAKAMOTO_PRODUCT_CONNECT_FAILED,
                                     "cannot connect to VAPI socket");
      return SAKAMOTO_PRODUCT_CONNECT_FAILED;
    }
  sakamoto_product_session_t *session = calloc (1U, sizeof (*session));
  if (session == NULL)
    {
      close (fd);
      sakamoto_product_status_error (out_status,
                                     SAKAMOTO_PRODUCT_ALLOCATION_FAILED,
                                     "cannot allocate VAPI session");
      return SAKAMOTO_PRODUCT_ALLOCATION_FAILED;
    }
  session->fd = fd;
  session->generation = expected_generation;
  session->connected = 1;
  if (pthread_mutex_init (&session->mutex, NULL) != 0)
    {
      close (fd);
      free (session);
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_ALLOCATION_FAILED,
        "cannot initialize VAPI session lock");
      return SAKAMOTO_PRODUCT_ALLOCATION_FAILED;
    }
  uint32_t code = exchange (session, SAKAMOTO_PRODUCT_WIRE_OP_CONNECT,
                            out_status);
  if (code != SAKAMOTO_PRODUCT_OK)
    {
      pthread_mutex_destroy (&session->mutex);
      close (fd);
      free (session);
      return code;
    }
  *out_session = session;
  return SAKAMOTO_PRODUCT_OK;
}

uint32_t
sakamoto_product_session_query (sakamoto_product_session_t *session,
                                 uint64_t expected_generation,
                                 sakamoto_product_status_t *out_status)
{
  sakamoto_product_status_reset (out_status, expected_generation);
  if (session == NULL || out_status == NULL || expected_generation == 0U)
    {
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_INVALID_ARGUMENT,
        "session and non-zero generation are required");
      return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
    }
  if (pthread_mutex_lock (&session->mutex) != 0)
    {
      sakamoto_product_status_error (out_status,
                                     SAKAMOTO_PRODUCT_INTERNAL_ERROR,
                                     "cannot lock VAPI session");
      return SAKAMOTO_PRODUCT_INTERNAL_ERROR;
    }
  uint32_t code;
  if (!session->connected || expected_generation != session->generation)
    {
      sakamoto_product_status_reset (out_status, session->generation);
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_STALE_HANDLE,
        "session is retired or belongs to another generation");
      code = SAKAMOTO_PRODUCT_STALE_HANDLE;
    }
  else
    {
      code = exchange (session, SAKAMOTO_PRODUCT_WIRE_OP_QUERY, out_status);
    }
  (void) pthread_mutex_unlock (&session->mutex);
  return code;
}

uint32_t
sakamoto_product_session_disconnect (sakamoto_product_session_t *session)
{
  if (session == NULL)
    return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (pthread_mutex_lock (&session->mutex) != 0)
    return SAKAMOTO_PRODUCT_INTERNAL_ERROR;
  if (!session->connected)
    {
      (void) pthread_mutex_unlock (&session->mutex);
      return SAKAMOTO_PRODUCT_OK;
    }
  session->connected = 0;
  int fd = session->fd;
  session->fd = -1;
  (void) shutdown (fd, SHUT_RDWR);
  (void) close (fd);
  (void) pthread_mutex_unlock (&session->mutex);
  return SAKAMOTO_PRODUCT_OK;
}

uint32_t
sakamoto_product_session_destroy (sakamoto_product_session_t *session)
{
  if (session == NULL)
    return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  uint32_t code = sakamoto_product_session_disconnect (session);
  if (code != SAKAMOTO_PRODUCT_OK)
    return code;
  (void) pthread_mutex_destroy (&session->mutex);
  free (session);
  return SAKAMOTO_PRODUCT_OK;
}
