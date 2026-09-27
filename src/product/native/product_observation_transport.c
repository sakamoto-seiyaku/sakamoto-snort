/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "sakamoto_product_observation.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wempty-body"
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#ifdef __clang__
/* Pinned VPP's BITS(_vec_find(0)->grow_elts) is an unevaluated sizeof. */
#pragma clang diagnostic ignored "-Wnull-pointer-arithmetic"
#endif
#include <svm/message_queue.h>
#include <vppinfra/mem.h>
#pragma GCC diagnostic pop

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__ || __SIZEOF_POINTER__ != 8
#error "observation supports the product little-endian 64-bit targets"
#endif
#define OBS_MAGIC UINT64_C (0x3153424f50504b53)
#define OBS_HEADER 4096
#define OBS_SLOTS 256
#define LOAD(p) __atomic_load_n ((p), __ATOMIC_ACQUIRE)
#define ADD(p, n) __atomic_fetch_add ((p), (n), __ATOMIC_RELAXED)

typedef struct {
  uint64_t magic, generation, mapping_bytes, queue_bytes;
  uint32_t version, flow_capacity, connected, reserved;
  product_observation_channel_status_t channels[PRODUCT_OBSERVATION_CHANNELS];
  uint64_t ring_consumed[PRODUCT_OBSERVATION_CHANNELS][2];
} observation_shared_t;
_Static_assert (sizeof (observation_shared_t) <= OBS_HEADER, "shared header bound");
typedef struct {
  uint64_t magic, generation, mapping_bytes, queue_bytes;
  uint32_t version, flow_capacity, header_bytes, channels;
} observation_hello_t;

struct product_observation_transport {
  observation_shared_t *shared;
  size_t length;
  int memfd, socket, interrupt, consumer;
  int event[PRODUCT_OBSERVATION_CHANNELS];
  svm_msg_q_t queue[PRODUCT_OBSERVATION_CHANNELS];
  unsigned attached;
  uint64_t ring_published[PRODUCT_OBSERVATION_CHANNELS][2];
};

static svm_msg_q_ring_cfg_t rings[] = {
  { .nitems = OBS_SLOTS, .elsize = 432 },
  { .nitems = OBS_SLOTS, .elsize = 448 },
};
static svm_msg_q_cfg_t config = {
  .q_nitems = OBS_SLOTS * 2, .n_rings = 2, .ring_cfgs = rings,
};
static size_t queue_bytes (void) {
  return (svm_msg_q_size_to_alloc (&config) + 63) & ~(size_t) 63;
}
static void *queue_base (product_observation_transport_t *t, unsigned channel) {
  return (uint8_t *) t->shared + OBS_HEADER + channel * queue_bytes ();
}
static product_observation_transport_t *allocate_handle (void) {
  product_observation_transport_t *t = calloc (1, sizeof (*t));
  if (!t) return NULL;
  t->memfd = t->socket = t->interrupt = -1;
  for (unsigned i = 0; i < PRODUCT_OBSERVATION_CHANNELS; i++) t->event[i] = -1;
  return t;
}
static int allocate_descriptors (product_observation_transport_t *t) {
  t->length = OBS_HEADER + PRODUCT_OBSERVATION_CHANNELS * queue_bytes ();
  t->memfd = syscall (SYS_memfd_create, "sakamoto-observation", MFD_CLOEXEC | MFD_ALLOW_SEALING);
  if (t->memfd < 0 || ftruncate (t->memfd, t->length)) return 0;
  for (unsigned i = 0; i < PRODUCT_OBSERVATION_CHANNELS; i++) {
    t->event[i] = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (t->event[i] < 0) return 0;
  }
  return !fcntl (t->memfd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
}
static void attach (product_observation_transport_t *t) {
  for (unsigned i = 0; i < PRODUCT_OBSERVATION_CHANNELS; i++) {
    svm_msg_q_attach (&t->queue[i], queue_base (t, i));
    /* The pinned primitive supports -2 as event mode with signals disabled.
     * We own the ordered notification latch, and never wait in svm_msg_q. */
    svm_msg_q_set_eventfd (&t->queue[i], -2);
    t->attached++;
  }
}
void product_observation_transport_destroy (product_observation_transport_t *t) {
  if (!t) return;
  for (unsigned i = 0; i < t->attached; i++) {
    t->queue[i].q.evtfd = -1;
    svm_msg_q_cleanup (&t->queue[i]);
  }
  if (t->shared) munmap (t->shared, t->length);
  for (unsigned i = 0; i < PRODUCT_OBSERVATION_CHANNELS; i++)
    if (t->event[i] >= 0) close (t->event[i]);
  if (t->memfd >= 0) close (t->memfd);
  if (t->interrupt >= 0) close (t->interrupt);
  /* Close the connection last: server may now declare consumer detached. */
  if (t->socket >= 0) close (t->socket);
  free (t);
}
product_observation_transport_t *product_observation_transport_create (
  uint64_t generation, uint32_t flow_capacity) {
  if (!generation || !flow_capacity || flow_capacity > 65536) return NULL;
  product_observation_transport_t *t = allocate_handle ();
  if (!t) return NULL;
  if (!allocate_descriptors (t)) goto fail;
  void *mapped = mmap (NULL, t->length, PROT_READ | PROT_WRITE, MAP_SHARED, t->memfd, 0);
  if (mapped == MAP_FAILED) goto fail;
  t->shared = mapped;
  *t->shared = (observation_shared_t) { .magic = OBS_MAGIC, .generation = generation,
    .mapping_bytes = t->length, .queue_bytes = queue_bytes (),
    .version = PRODUCT_OBSERVATION_VERSION, .flow_capacity = flow_capacity };
  for (unsigned i = 0; i < PRODUCT_OBSERVATION_CHANNELS; i++) {
    svm_msg_q_init (queue_base (t, i), &config);
  }
  attach (t);
  return t;
fail:
  product_observation_transport_destroy (t);
  return NULL;
}

int product_observation_publish (product_observation_transport_t *t, unsigned channel,
                                 const void *data, uint32_t length) {
  if (!t || t->consumer || channel >= PRODUCT_OBSERVATION_CHANNELS) return -1;
  product_observation_channel_status_t *s = &t->shared->channels[channel];
  ADD (&s->attempted, 1);
  if (!data || length < 4 || length > PRODUCT_OBSERVATION_MAX_RECORD) {
    ADD (&s->oversize, 1); return -1;
  }
  svm_msg_q_t *mq = &t->queue[channel];
  if (LOAD (&s->published) - LOAD (&s->consumed) >= config.q_nitems) {
    ADD (&s->full, 1); return 0;
  }
  unsigned ring;
  for (ring = 0; ring < 2; ring++)
    if (length <= rings[ring].elsize
        && t->ring_published[channel][ring]
             - LOAD (&t->shared->ring_consumed[channel][ring]) < rings[ring].nitems) break;
  if (ring == 2) { ADD (&s->full, 1); return 0; }
  svm_msg_q_msg_t msg = svm_msg_q_alloc_msg_w_ring (mq, ring);
  memcpy (svm_msg_q_msg_data (mq, &msg), data, length);
  /* Exactly one owner produces this queue. Release consumption watermarks
   * below cover the pinned primitive's relaxed free/dequeue operations. The
   * producer acquires both watermarks BEFORE any descriptor/payload reuse. */
  svm_msg_q_add_raw (mq, &msg);
  t->ring_published[channel][ring]++;
  __atomic_fetch_add (&s->published, 1, __ATOMIC_RELEASE);
  if (!__atomic_exchange_n (&s->pending, 1, __ATOMIC_SEQ_CST)) {
    uint64_t one = 1;
    ssize_t n;
    do n = write (t->event[channel], &one, sizeof (one)); while (n < 0 && errno == EINTR);
    if (n == sizeof (one)) ADD (&s->notifications, 1);
    else if (errno != EAGAIN) ADD (&s->notify_errors, 1);
  }
  return 1;
}
void product_observation_account (product_observation_transport_t *t, unsigned owner,
                                  unsigned outcome, uint32_t bytes) {
  if (!t || owner >= PRODUCT_OBSERVATION_OWNERS || outcome >= 3) return;
  product_observation_channel_status_t *s = &t->shared->channels[owner * 2];
  ADD (&s->basic_packets[outcome], 1);
  ADD (&s->basic_bytes[outcome], bytes);
}
void product_observation_connected (product_observation_transport_t *t, int connected) {
  if (t) __atomic_store_n (&t->shared->connected, !!connected, __ATOMIC_RELEASE);
}
void product_observation_transport_status (product_observation_transport_t *t,
                                           product_observation_status_t *out) {
  memset (out, 0, sizeof (*out));
  if (!t) return;
  out->generation = t->shared->generation;
  out->mapping_bytes = t->length;
  out->version = PRODUCT_OBSERVATION_VERSION;
  out->owners = PRODUCT_OBSERVATION_OWNERS;
  out->flow_capacity = t->shared->flow_capacity;
  out->connected = LOAD (&t->shared->connected);
  for (unsigned i = 0; i < PRODUCT_OBSERVATION_CHANNELS; i++) {
    product_observation_channel_status_t *dst = &out->channels[i];
    product_observation_channel_status_t *src = &t->shared->channels[i];
    /* Status is a per-counter sample, not a transaction across running owners. */
#define SAMPLE(field) dst->field = LOAD (&src->field)
    SAMPLE (attempted); SAMPLE (published); SAMPLE (full); SAMPLE (oversize);
    SAMPLE (consumed); SAMPLE (notify_errors); SAMPLE (pending); SAMPLE (notifications);
#undef SAMPLE
    for (unsigned j = 0; j < 3; j++) {
      dst->basic_packets[j] = LOAD (&src->basic_packets[j]);
      dst->basic_bytes[j] = LOAD (&src->basic_bytes[j]);
    }
    dst->occupancy = LOAD (&t->queue[i].q.shr->cursize);
    dst->capacity = config.q_nitems;
  }
}

int product_observation_offer (product_observation_transport_t *t, int fd) {
  observation_hello_t request = {0};
  product_observation_transport_t *proposal = allocate_handle ();
  if (!proposal) return -1;
  union { struct cmsghdr alignment;
    char bytes[CMSG_SPACE (sizeof (int) * (1 + PRODUCT_OBSERVATION_CHANNELS))]; } control = {0};
  struct iovec iov = { &request, sizeof (request) };
  struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
    .msg_control = control.bytes, .msg_controllen = sizeof (control.bytes) };
  ssize_t received = recvmsg (fd, &msg, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
  /* Failed recvmsg leaves msg_controllen unchanged. Never traverse its zero
   * headers: bionic's CMSG_NXTHDR may then fail to advance. */
  if (received < 0) {
    int retry = errno == EAGAIN || errno == EINTR;
    product_observation_transport_destroy (proposal);
    return retry ? 1 : -1;
  }
  unsigned count = 0;
  for (struct cmsghdr *c = CMSG_FIRSTHDR (&msg); c; c = CMSG_NXTHDR (&msg, c)) {
    if (c->cmsg_len < CMSG_LEN (0)) goto fail;
    if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) continue;
    unsigned n = (c->cmsg_len - CMSG_LEN (0)) / sizeof (int);
    int *fds = (int *) CMSG_DATA (c);
    for (unsigned i = 0; i < n; i++, count++) {
      if (count == 0) proposal->memfd = fds[i];
      else if (count <= PRODUCT_OBSERVATION_CHANNELS) proposal->event[count - 1] = fds[i];
      else close (fds[i]);
    }
  }
  if (received != sizeof (request) || msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)
      || count != 1 + PRODUCT_OBSERVATION_CHANNELS || request.magic != OBS_MAGIC
      || request.generation != t->shared->generation || request.version != PRODUCT_OBSERVATION_VERSION
      || request.header_bytes != OBS_HEADER || request.channels != PRODUCT_OBSERVATION_CHANNELS
      || request.queue_bytes != queue_bytes () || request.mapping_bytes != t->length) goto fail;
  struct stat st;
  int seals = fcntl (proposal->memfd, F_GET_SEALS);
  if (fstat (proposal->memfd, &st) || st.st_size != (off_t) t->length
      || seals < 0 || (seals & (F_SEAL_GROW | F_SEAL_SHRINK)) != (F_SEAL_GROW | F_SEAL_SHRINK)) goto fail;
  for (unsigned i = 0; i < PRODUCT_OBSERVATION_CHANNELS; i++)
    if (fcntl (proposal->event[i], F_SETFL, O_NONBLOCK)) goto fail;
  proposal->length = t->length;
  void *mapped = mmap (NULL, t->length, PROT_READ | PROT_WRITE, MAP_SHARED, proposal->memfd, 0);
  if (mapped == MAP_FAILED) goto fail;
  proposal->shared = mapped;
  /* First and only consumer claim. Caller quiesces the producers, so copy
   * their pre-connection records/counters without a gap or pointer relocation.
   * APK-created memfd/eventfds retain the application's Android access label;
   * no root-created tmpfs FD must be received by the application. */
  memcpy (proposal->shared, t->shared, t->length);
  for (unsigned i = 0; i < t->attached; i++) {
    t->queue[i].q.evtfd = -1;
    svm_msg_q_cleanup (&t->queue[i]);
  }
  t->attached = 0;
  munmap (t->shared, t->length); close (t->memfd);
  t->shared = proposal->shared; proposal->shared = NULL;
  t->memfd = proposal->memfd; proposal->memfd = -1;
  for (unsigned i = 0; i < PRODUCT_OBSERVATION_CHANNELS; i++) {
    close (t->event[i]); t->event[i] = proposal->event[i]; proposal->event[i] = -1;
  }
  attach (t);
  product_observation_transport_destroy (proposal);
  observation_hello_t reply = { .magic = OBS_MAGIC, .generation = t->shared->generation,
    .mapping_bytes = t->length, .queue_bytes = queue_bytes (),
    .version = PRODUCT_OBSERVATION_VERSION, .flow_capacity = t->shared->flow_capacity,
    .header_bytes = OBS_HEADER, .channels = PRODUCT_OBSERVATION_CHANNELS };
  return send (fd, &reply, sizeof (reply), MSG_NOSIGNAL | MSG_DONTWAIT) == sizeof (reply) ? 0 : -1;
fail:
  product_observation_transport_destroy (proposal);
  return -1;
}

/* Only the Rust ingestion thread uses VPP allocations in its process. */
static pthread_once_t consumer_heap_once = PTHREAD_ONCE_INIT;
static void *consumer_heap;
static void init_consumer_heap (void) { consumer_heap = clib_mem_init (NULL, 1024 * 1024); }
product_observation_transport_t *product_observation_connect (
  const char *path, uint64_t generation) {
  if (!path || strlen (path) >= sizeof (((struct sockaddr_un *) 0)->sun_path)) return NULL;
  pthread_once (&consumer_heap_once, init_consumer_heap);
  if (!consumer_heap) return NULL;
  clib_mem_set_heap (consumer_heap);
  product_observation_transport_t *t = allocate_handle ();
  if (!t) return NULL;
  t->consumer = 1;
  if (!allocate_descriptors (t)) goto fail;
  t->socket = socket (AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  if (t->socket < 0) goto fail;
  struct timeval timeout = { .tv_sec = 2 };
  if (setsockopt (t->socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof (timeout))
      || setsockopt (t->socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof (timeout))) goto fail;
  struct sockaddr_un address = { .sun_family = AF_UNIX };
  memcpy (address.sun_path, path, strlen (path) + 1);
  if (connect (t->socket, (struct sockaddr *) &address, sizeof (address))) goto fail;
  struct ucred server;
  socklen_t server_length = sizeof (server);
  if (getsockopt (t->socket, SOL_SOCKET, SO_PEERCRED, &server, &server_length)
      || server_length != sizeof (server) || (server.uid != geteuid () && server.uid != 0)) goto fail;
  observation_hello_t hello = { .magic = OBS_MAGIC, .generation = generation,
    .version = PRODUCT_OBSERVATION_VERSION, .mapping_bytes = t->length,
    .queue_bytes = queue_bytes (), .header_bytes = OBS_HEADER, .channels = PRODUCT_OBSERVATION_CHANNELS };
  union { struct cmsghdr alignment;
    char bytes[CMSG_SPACE (sizeof (int) * (1 + PRODUCT_OBSERVATION_CHANNELS))]; } control = {0};
  struct iovec iov = { &hello, sizeof (hello) };
  struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
    .msg_control = control.bytes, .msg_controllen = sizeof (control.bytes) };
  int fds[1 + PRODUCT_OBSERVATION_CHANNELS]; fds[0] = t->memfd;
  for (unsigned i = 0; i < PRODUCT_OBSERVATION_CHANNELS; i++) fds[i+1] = t->event[i];
  struct cmsghdr *cmsg = CMSG_FIRSTHDR (&msg);
  cmsg->cmsg_level = SOL_SOCKET; cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN (sizeof (fds)); memcpy (CMSG_DATA (cmsg), fds, sizeof (fds));
  if (sendmsg (t->socket, &msg, MSG_NOSIGNAL) != sizeof (hello)) goto fail;
  ssize_t received = recv (t->socket, &hello, sizeof (hello), MSG_TRUNC);
  if (received != sizeof (hello) || hello.magic != OBS_MAGIC
      || hello.generation != generation || hello.version != PRODUCT_OBSERVATION_VERSION
      || hello.header_bytes != OBS_HEADER || hello.channels != PRODUCT_OBSERVATION_CHANNELS
      || hello.queue_bytes != queue_bytes () || !hello.flow_capacity || hello.flow_capacity > 65536
      || hello.mapping_bytes != OBS_HEADER + PRODUCT_OBSERVATION_CHANNELS * queue_bytes ()) goto fail;
  void *mapped = mmap (NULL, t->length, PROT_READ | PROT_WRITE, MAP_SHARED, t->memfd, 0);
  if (mapped == MAP_FAILED) goto fail;
  t->shared = mapped;
  if (t->shared->magic != OBS_MAGIC || t->shared->generation != generation
      || t->shared->mapping_bytes != t->length || t->shared->queue_bytes != queue_bytes ()
      || t->shared->version != PRODUCT_OBSERVATION_VERSION
      || t->shared->flow_capacity != hello.flow_capacity) goto fail;
  /* Validate layout before the pinned attach function follows any offsets. */
  for (unsigned i = 0; i < PRODUCT_OBSERVATION_CHANNELS; i++) {
    svm_msg_q_shared_t *q = queue_base (t, i);
    if (q->n_rings != 2 || q->q->maxsize != config.q_nitems
        || q->q->elsize != sizeof (svm_msg_q_msg_t)) goto fail;
    uint8_t *p = (uint8_t *) q->q + sizeof (*q->q) + config.q_nitems * sizeof (svm_msg_q_msg_t);
    for (unsigned r = 0; r < 2; r++) {
      svm_msg_q_ring_shared_t *ring = (void *) p;
      if (ring->nitems != rings[r].nitems || ring->elsize != rings[r].elsize) goto fail;
      p += sizeof (*ring) + rings[r].nitems * rings[r].elsize;
    }
    if (fcntl (t->event[i], F_SETFL, O_NONBLOCK)) goto fail;
  }
  t->interrupt = eventfd (0, EFD_CLOEXEC | EFD_NONBLOCK);
  if (t->interrupt < 0) goto fail;
  attach (t);
  return t;
fail:
  product_observation_transport_destroy (t);
  return NULL;
}

int product_observation_receive (product_observation_transport_t *t, unsigned channel,
                                 product_observation_record_t *record) {
  if (!t || !t->consumer || channel >= PRODUCT_OBSERVATION_CHANNELS || !record) return -1;
  svm_msg_q_t *mq = &t->queue[channel];
  if (!LOAD (&mq->q.shr->cursize)) return 0;
  svm_msg_q_msg_t msg;
  svm_msg_q_sub_raw (mq, &msg);
  if (msg.ring_index >= 2 || msg.elt_index >= OBS_SLOTS) return -1;
  const product_observation_record_t *source = svm_msg_q_msg_data (mq, &msg);
  uint16_t length = source->length;
  int valid = length >= 4 && length <= sizeof (*record) && length <= rings[msg.ring_index].elsize;
  memset (record, 0, sizeof (*record));
  if (valid) memcpy (record, source, length);
  svm_msg_q_free_msg (mq, &msg);
  __atomic_fetch_add (&t->shared->ring_consumed[channel][msg.ring_index], 1, __ATOMIC_RELEASE);
  __atomic_fetch_add (&t->shared->channels[channel].consumed, 1, __ATOMIC_RELEASE);
  return valid ? 1 : -1;
}
static void drain (int fd) {
  uint64_t value;
  ssize_t n;
  do n = read (fd, &value, sizeof (value)); while (n < 0 && errno == EINTR);
}
int product_observation_wait (product_observation_transport_t *t, int timeout_ms) {
  if (!t || !t->consumer) return -1;
  struct pollfd fds[PRODUCT_OBSERVATION_CHANNELS + 2];
  for (unsigned i = 0; i < PRODUCT_OBSERVATION_CHANNELS; i++) {
    drain (t->event[i]);
    __atomic_exchange_n (&t->shared->channels[i].pending, 0, __ATOMIC_SEQ_CST);
    if (LOAD (&t->queue[i].q.shr->cursize)) return 1;
    fds[i] = (struct pollfd) { .fd = t->event[i], .events = POLLIN };
  }
  fds[PRODUCT_OBSERVATION_CHANNELS] = (struct pollfd) { .fd = t->socket, .events = POLLIN };
  fds[PRODUCT_OBSERVATION_CHANNELS + 1] = (struct pollfd) { .fd = t->interrupt, .events = POLLIN };
  int rv;
  do rv = poll (fds, PRODUCT_OBSERVATION_CHANNELS + 2, timeout_ms); while (rv < 0 && errno == EINTR);
  if (fds[PRODUCT_OBSERVATION_CHANNELS].revents) return -1;
  if (fds[PRODUCT_OBSERVATION_CHANNELS + 1].revents) drain (t->interrupt);
  return rv;
}
int product_observation_interrupt_fd (product_observation_transport_t *t) {
  return t ? fcntl (t->interrupt, F_DUPFD_CLOEXEC, 0) : -1;
}
void product_observation_interrupt (int fd) {
  uint64_t one = 1;
  if (fd >= 0) (void) write (fd, &one, sizeof (one));
}
void product_observation_close_fd (int fd) { if (fd >= 0) close (fd); }
