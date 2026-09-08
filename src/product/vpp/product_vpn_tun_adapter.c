/* SPDX-License-Identifier: Apache-2.0 */
/* One native TUN lane. No transport stack, socket egress or packet re-parser. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "product_vpn_tun_adapter.h"
#include "product_packet_graph.h"
#include <vlib/file.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define TUN_PENDING 128
#define TUN_CONTROL_SLOTS 4
#define TUN_CONTROL_MAGIC 0x53323133U
#define TUN_CONTROL_ATTACH 1U
#define TUN_CONTROL_STOP 2U

typedef struct { u64 token; u32 buffer; u8 active; } tun_pending_t;
typedef struct { u32 file; int fd; } tun_control_t;
static struct {
  vlib_main_t *vm;
  u64 generation, next_token, captured, submitted, completed;
  u64 policy_drops, runtime_drops, transport_unavailable, errors, rejected;
  u64 pregraph_returns, local, remote;
  u32 pending, test_uid, tun_file, listener_file;
  int tun_fd, listener_fd;
  u8 enabled, draining;
  char path[sizeof (((struct sockaddr_un *)0)->sun_path)];
  tun_pending_t obligations[TUN_PENDING];
  tun_control_t controls[TUN_CONTROL_SLOTS];
} tun = { .tun_fd = -1, .listener_fd = -1,
          .tun_file = ~0U, .listener_file = ~0U };

int product_vpn_tun_validation_enabled (void) {
  const char *profile = getenv ("SAKAMOTO_RUNTIME_PROFILE");
  const char *validation = getenv ("SAKAMOTO_PRODUCT_VPN_GRAPH_VALIDATION");
  return profile && !strcmp (profile, "vpn") && validation && !strcmp (validation, "1");
}
u64 product_vpn_tun_attached (void) { return tun.tun_fd >= 0; }
u64 product_vpn_tun_captured (void) { return tun.captured; }

static void tun_complete (vlib_main_t *vm, u32 bi,
                          const product_packet_completion_frame_t *frame, void *opaque) {
  (void) opaque;
  const product_adapter_obligation_t *o = &frame->obligation;
  tun_pending_t *pending = &tun.obligations[o->token % TUN_PENDING];
  if (o->kind != PRODUCT_ADAPTER_OBLIGATION_VPN_TUN
      || o->queue_generation != tun.generation || o->origin_lane != 0
      || o->origin_worker != 0 || vm->thread_index != vlib_get_worker_thread_index (0)
      || !pending->active || pending->token != o->token || pending->buffer != bi) {
    tun.rejected++;
    return;
  }
  pending->active = 0;
  tun.pending--;
  tun.completed++;
  if (frame->producer_thread == vm->thread_index) tun.local++; else tun.remote++;
  int policy_drop = frame->terminal_intent == PRODUCT_PACKET_INTENT_DROP_RUNTIME
    && (frame->runtime_drop_reason == PRODUCT_PACKET_DROP_POLICY_GATE
        || frame->runtime_drop_reason == PRODUCT_PACKET_DROP_POLICY_L4);
  if (policy_drop) tun.policy_drops++;
  else if (frame->terminal_intent == PRODUCT_PACKET_INTENT_DROP_RUNTIME) tun.runtime_drops++;
  else tun.transport_unavailable++;
  /* The shared origin consumer frees the VPP buffer after this callback. No
   * TUN write is a valid completion for an outbound TUN-origin packet. */
  if (frame->flags & PRODUCT_COMPLETION_TRACE)
    fprintf (stderr, "s213 event=completion source=TUN_CAPTURED generation=%llu token=%llu buffer=%u thread=%u producer=%u intent=%u drop_reason=%u policy_drop=%u transport_unavailable=%u pending=%u tun_writes=0 nfq_verdicts=0 flow_stack_admissions=0\n",
      (unsigned long long) tun.generation, (unsigned long long) o->token, bi,
      vm->thread_index, frame->producer_thread, frame->terminal_intent,
      frame->runtime_drop_reason, policy_drop,
      frame->terminal_intent != PRODUCT_PACKET_INTENT_DROP_RUNTIME, tun.pending);
}

static clib_error_t *tun_read_ready (clib_file_t *file) {
  vlib_main_t *vm = vlib_get_main ();
  if (vm->thread_index != vlib_get_worker_thread_index (0)
      || file->file_descriptor != (u32) tun.tun_fd) return clib_error_return (0, "TUN lane mismatch");
  if (tun.draining) return 0;
  for (u32 budget = 0; budget < 64 && tun.pending < TUN_PENDING; ++budget) {
    u64 token = tun.next_token + 1;
    if (!token) { tun.draining = 1; tun.errors++; return 0; }
    tun_pending_t *pending = &tun.obligations[token % TUN_PENDING];
    if (pending->active) return 0;
    u32 bi;
    if (vlib_buffer_alloc (vm, &bi, 1) != 1) return 0;
    vlib_buffer_t *buffer = vlib_get_buffer (vm, bi);
    vlib_buffer_reset (buffer);
    clib_memset (buffer->opaque, 0, sizeof (buffer->opaque));
    clib_memset (buffer->opaque2, 0, sizeof (buffer->opaque2));
    u32 capacity = vlib_buffer_get_default_data_size (vm);
    u8 *data = vlib_buffer_get_current (buffer);
    ssize_t length = read (tun.tun_fd, data, capacity);
    if (length <= 0) {
      int error = errno;
      vlib_buffer_free (vm, &bi, 1);
      if (length < 0 && (error == EAGAIN || error == EWOULDBLOCK || error == EINTR)) return 0;
      tun.errors++; tun.draining = 1; return 0;
    }
    tun.captured++;
    if ((u32) length >= capacity) {
      /* A full read buffer cannot establish absence of TUN truncation. */
      tun.pregraph_returns++; tun.transport_unavailable++;
      vlib_buffer_free (vm, &bi, 1); continue;
    }
    buffer->current_length = (u16) length;
    tun.next_token = token;
    *pending = (tun_pending_t){ .token = token, .buffer = bi, .active = 1 };
    tun.pending++;
    product_platform_packet_facts_t platform = {
      .uid = tun.test_uid, .availability = PRODUCT_PLATFORM_UID_KNOWN,
      .direction = PRODUCT_PACKET_DIRECTION_OUTPUT,
      .provenance = PRODUCT_PACKET_PROVENANCE_VPN_TUN,
    };
    product_adapter_obligation_t obligation = {
      .token = token, .queue_generation = tun.generation,
      .kind = PRODUCT_ADAPTER_OBLIGATION_VPN_TUN, .origin_worker = 0, .origin_lane = 0,
    };
    if (tun.captured <= product_packet_graph_trace_limit ()) {
      flockfile (stderr);
      fprintf (stderr, "s213 event=capture source=TUN_CAPTURED generation=%llu token=%llu buffer=%u thread=%u tls=%u lane=0 bytes=%zd uid_source=CONTROLLED_TEST_PROVIDER uid=%u raw=",
        (unsigned long long) tun.generation, (unsigned long long) token, bi,
        vm->thread_index, vlib_get_thread_index (), length, tun.test_uid);
      for (ssize_t i = 0; i < length; ++i) fprintf (stderr, "%02x", data[i]);
      fprintf (stderr, "\n"); funlockfile (stderr);
    }
    if (!product_packet_graph_submit_external (vm, bi, &platform, &obligation, 0)) {
      pending->active = 0; tun.pending--; tun.pregraph_returns++;
      tun.transport_unavailable++;
      vlib_buffer_free (vm, &bi, 1);
    } else tun.submitted++;
  }
  return 0;
}

static int tun_attach (int fd, u32 uid) {
  struct ifreq interface;
  clib_memset (&interface, 0, sizeof (interface));
  if (tun.tun_fd >= 0 || tun.draining || uid == UINT32_MAX
      || ioctl (fd, TUNGETIFF, &interface) < 0
      || !(interface.ifr_flags & IFF_TUN) || !(interface.ifr_flags & IFF_NO_PI)) return 0;
  int flags = fcntl (fd, F_GETFL);
  if (flags < 0 || fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0
      || fcntl (fd, F_SETFD, FD_CLOEXEC) < 0) return 0;
  tun.test_uid = uid;
  tun.tun_fd = fd;
  clib_file_t file = {0};
  file.read_function = tun_read_ready;
  file.polling_thread_index = vlib_get_worker_thread_index (0);
  file.file_descriptor = fd;
  file.description = format (0, "sakamoto-product-tun%c", 0);
  tun.tun_file = clib_file_add (&file_main, &file);
  fprintf (stderr, "s213 event=attach generation=%llu fd=%d interface=%s origin_thread=%u uid_source=CONTROLLED_TEST_PROVIDER uid=%u direct_egress_ready=0\n",
    (unsigned long long) tun.generation, fd, interface.ifr_name,
    vlib_get_worker_thread_index (0), uid);
  return 1;
}

static int tun_stop (void) {
  tun.draining = 1;
  product_packet_graph_quiesce_reassembly (tun.vm);
  if (tun.pending || product_packet_graph_buffer_debt ()
      || product_packet_graph_obligation_debt ()
      || product_packet_graph_completion_frame_debt ()) return 1;
  if (tun.tun_file != ~0U) clib_file_del_by_index (&file_main, tun.tun_file);
  tun.tun_file = ~0U; tun.tun_fd = -1;
  product_packet_graph_stop_external (tun.vm);
  product_packet_graph_register_external_completion (0, 0);
  fprintf (stderr, "s213 event=stop generation=%llu pending=0 buffers=0 frames=0 obligations=0 tun_fd=-1 captured=%llu completed=%llu pregraph_returns=%llu\n",
    (unsigned long long) tun.generation, (unsigned long long) tun.captured,
    (unsigned long long) tun.completed, (unsigned long long) tun.pregraph_returns);
  return 0;
}

static clib_error_t *tun_control_read (clib_file_t *file) {
  tun_control_t *client = uword_to_pointer (file->private_data, tun_control_t *);
  u8 payload[20];
  union { struct cmsghdr align; u8 bytes[CMSG_SPACE (4 * sizeof (int))]; } control = {0};
  struct iovec iov = { .iov_base = payload, .iov_len = sizeof (payload) };
  struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
    .msg_control = control.bytes, .msg_controllen = sizeof (control.bytes) };
  ssize_t length = recvmsg (client->fd, &msg, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
  if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
  int fds[4], n_fds = 0;
  if (length >= 0) for (struct cmsghdr *c = CMSG_FIRSTHDR (&msg); c; c = CMSG_NXTHDR (&msg, c)) {
    if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS || c->cmsg_len < CMSG_LEN (0)) continue;
    size_t count = (c->cmsg_len - CMSG_LEN (0)) / sizeof (int);
    for (size_t i = 0; i < count; ++i) {
      int fd; memcpy (&fd, (u8 *) CMSG_DATA (c) + i * sizeof (fd), sizeof (fd));
      if (n_fds < 4) fds[n_fds++] = fd; else close (fd);
    }
  }
  u32 magic = 0, command = 0, uid = 0; u64 generation = 0;
  if (length == sizeof (payload)) {
    memcpy (&magic, payload, 4); memcpy (&command, payload + 4, 4);
    memcpy (&generation, payload + 8, 8); memcpy (&uid, payload + 16, 4);
    magic = ntohl (magic); command = ntohl (command); uid = ntohl (uid);
    generation = clib_net_to_host_u64 (generation);
  }
  u32 result = 2;
  if (length == sizeof (payload) && !(msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))
      && magic == TUN_CONTROL_MAGIC && generation == tun.generation) {
    vlib_worker_thread_barrier_sync (tun.vm);
    if (command == TUN_CONTROL_ATTACH && n_fds == 1 && tun_attach (fds[0], uid)) {
      fds[0] = -1; result = 0;
    } else if (command == TUN_CONTROL_STOP && n_fds == 0) result = tun_stop ();
    vlib_worker_thread_barrier_release (tun.vm);
  }
  for (int i = 0; i < n_fds; ++i) if (fds[i] >= 0) close (fds[i]);
  u32 reply = htonl (result);
  (void) send (client->fd, &reply, sizeof (reply), MSG_DONTWAIT | MSG_NOSIGNAL);
  clib_file_del_by_index (&file_main, client->file);
  client->file = ~0U; client->fd = -1;
  return 0;
}

static clib_error_t *tun_control_accept (clib_file_t *file) {
  for (u32 budget = 0; budget < TUN_CONTROL_SLOTS; ++budget) {
    int fd = accept4 (file->file_descriptor, 0, 0, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) return 0;
    struct ucred peer; socklen_t size = sizeof (peer);
    if (getsockopt (fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) < 0 || peer.uid != geteuid ()) {
      close (fd); continue;
    }
    tun_control_t *client = 0;
    for (u32 i = 0; i < TUN_CONTROL_SLOTS; ++i) if (tun.controls[i].fd < 0) { client = &tun.controls[i]; break; }
    if (!client) { close (fd); continue; }
    client->fd = fd;
    clib_file_t entry = {0};
    entry.read_function = tun_control_read;
    entry.polling_thread_index = 0;
    entry.file_descriptor = fd;
    entry.private_data = pointer_to_uword (client);
    entry.description = format (0, "sakamoto-tun-control-client%c", 0);
    client->file = clib_file_add (&file_main, &entry);
  }
  return 0;
}

int product_vpn_tun_start (vlib_main_t *vm, u64 generation) {
  const char *runtime = getenv ("SAKAMOTO_VPP_RUNTIME_DIR");
  if (!product_vpn_tun_validation_enabled () || !runtime || tun.enabled || !generation) return 0;
  int n = snprintf (tun.path, sizeof (tun.path), "%s/tun-control.sock", runtime);
  if (n <= 0 || (size_t) n >= sizeof (tun.path)) return 0;
  int fd = socket (AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) return 0;
  struct sockaddr_un address = { .sun_family = AF_UNIX };
  memcpy (address.sun_path, tun.path, n + 1);
  if (bind (fd, (struct sockaddr *) &address, sizeof (address)) < 0 || listen (fd, 4) < 0) {
    close (fd); return 0;
  }
  if (!product_packet_graph_start_external (vm, generation)) {
    close (fd); unlink (tun.path); return 0;
  }
  tun.vm = vm; tun.generation = generation; tun.enabled = 1; tun.listener_fd = fd;
  for (u32 i = 0; i < TUN_CONTROL_SLOTS; ++i) tun.controls[i] = (tun_control_t){ .file = ~0U, .fd = -1 };
  product_packet_graph_register_external_completion (tun_complete, 0);
  clib_file_t entry = {0};
  entry.read_function = tun_control_accept;
  entry.polling_thread_index = 0; entry.file_descriptor = fd;
  entry.description = format (0, "sakamoto-tun-control%c", 0);
  tun.listener_file = clib_file_add (&file_main, &entry);
  return 1;
}

static clib_error_t *tun_status (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *command) {
  (void) input; (void) command;
  vlib_cli_output (vm, "tun.status generation=%llu enabled=%u attached=%u fd=%d origin_thread=%u draining=%u captured=%llu submitted=%llu completed=%llu pending=%u policy_drops=%llu runtime_drops=%llu transport_unavailable=%llu pregraph_returns=%llu errors=%llu rejected=%llu local=%llu remote=%llu frames=%llu buffers=%llu obligations=%llu tun_writes=0 nfq_verdicts=0 flow_stack_admissions=0 direct_egress_ready=0",
    (unsigned long long) tun.generation, tun.enabled, tun.tun_fd >= 0, tun.tun_fd,
    vlib_get_worker_thread_index (0), tun.draining,
    (unsigned long long) tun.captured, (unsigned long long) tun.submitted,
    (unsigned long long) tun.completed, tun.pending,
    (unsigned long long) tun.policy_drops, (unsigned long long) tun.runtime_drops,
    (unsigned long long) tun.transport_unavailable, (unsigned long long) tun.pregraph_returns,
    (unsigned long long) tun.errors, (unsigned long long) tun.rejected,
    (unsigned long long) tun.local, (unsigned long long) tun.remote,
    (unsigned long long) product_packet_graph_completion_frame_debt (),
    (unsigned long long) product_packet_graph_buffer_debt (),
    (unsigned long long) product_packet_graph_obligation_debt ());
  return 0;
}
VLIB_CLI_COMMAND (product_tun_status_command, static) = {
  .path = "show product tun", .function = tun_status,
};

static clib_error_t *tun_stop_cli (vlib_main_t *vm, unformat_input_t *input,
                                  vlib_cli_command_t *command) {
  (void) input; (void) command;
  if (!tun.enabled) return clib_error_return (0, "TUN validation is inactive");
  int result = tun_stop ();
  vlib_cli_output (vm, "tun.stop result=%d pending=%u fd=%d", result, tun.pending, tun.tun_fd);
  return 0;
}
VLIB_CLI_COMMAND (product_tun_stop_command, static) = {
  .path = "product tun stop", .function = tun_stop_cli,
};

static clib_error_t *tun_exit (vlib_main_t *vm) {
  (void) vm;
  if (!tun.enabled) return 0;
  if (tun.tun_file != ~0U) clib_file_del_by_index (&file_main, tun.tun_file);
  if (tun.listener_file != ~0U) clib_file_del_by_index (&file_main, tun.listener_file);
  for (u32 i = 0; i < TUN_CONTROL_SLOTS; ++i)
    if (tun.controls[i].file != ~0U) clib_file_del_by_index (&file_main, tun.controls[i].file);
  unlink (tun.path);
  return 0;
}
VLIB_MAIN_LOOP_EXIT_FUNCTION (tun_exit);
