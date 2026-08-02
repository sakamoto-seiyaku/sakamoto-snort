/* SPDX-License-Identifier: Apache-2.0 */

/* Throwaway P3 correctness probe. A remote owner never touches an NFQUEUE
 * handle: it returns a descriptor to the origin lane, which owns the verdict. */

#define _GNU_SOURCE

#include <vlib/vlib.h>
#include <vlib/file.h>
#include <vlib/threads.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <sched.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#define P3_LANES 2
#define P3_OWNERS 2
#define P3_POOL_MAX 128
#define P3_RING_CAP 256
#define P3_PREFIX 256
#define P3_DRAIN_BUDGET 64
#define P3_HASH_SEED 0x1234ULL
#define P3_MARKER_MAGIC 0x4e465142u

typedef enum { P3_FREE, P3_INGRESS, P3_OWNER, P3_COMPLETION } p3_state_t;
typedef enum { P3_MODE_LOCAL, P3_MODE_RETURN, P3_MODE_SHARED } p3_mode_t;

typedef struct {
  u64 id[P3_RING_CAP];
  u32 head;
  u32 tail;
} p3_ring_t;

typedef struct {
  u32 generation;
  u32 packet_id;
  u16 prefix_len;
  u8 origin;
  u8 owner;
  u8 state;
  u8 decision;
  u8 verdict_done;
  u8 prefix[P3_PREFIX];
} p3_desc_t;

typedef struct p3_main p3_main_t;

typedef struct {
  p3_main_t *pm;
  struct nfq_handle *handle;
  struct nfq_q_handle *queue;
  u32 file_index;
  u32 completion_file_index;
  u16 queue_num;
  u8 index;
  int fd;
  int completion_fd;
  u32 free_stack[P3_POOL_MAX];
  u32 free_count;
  u64 seen, local, remote, overload, owner_done, completion_done;
  u64 verdict_attempts, verdict_success, verdict_errors;
  u64 missing_id, malformed, recv_errors, handle_errors, enobufs;
  u64 callback_tid, callback_cpu, callback_thread_mismatch;
  u64 qh_mismatch, verdict_thread_mismatch;
  u64 completion_wake_attempts, completion_wake_writes, completion_wake_errors;
  u64 stale_generation, duplicate_terminal;
  clib_spinlock_t io_gate;
  u64 shared_try, shared_hit, shared_miss, shared_fallback;
  u64 lane_gate_defer;
  u8 completion_pending;
} p3_lane_t;

typedef struct {
  p3_main_t *pm;
  u8 index;
  int event_fd;
  u32 file_index;
  u64 processed, completion_push_errors, wake_attempts, wake_writes, wake_errors;
  u64 callback_thread_mismatch;
  u8 pending;
} p3_owner_t;

struct p3_main {
  u8 enabled;
  u8 accepting;
  u8 pool_size;
  u8 mode;
  u16 base_queue;
  p3_lane_t lane[P3_LANES];
  p3_owner_t owner[P3_OWNERS];
  p3_ring_t ingress[P3_LANES][P3_OWNERS];
  p3_ring_t completion[P3_OWNERS][P3_LANES];
  p3_desc_t desc[P3_LANES][P3_POOL_MAX];
  u8 inject_stale;
  u8 inject_duplicate;
  u8 stale_injected;
  u8 duplicate_injected;
  u32 route_flow[P3_LANES][P3_OWNERS];
};

static p3_main_t p3_main;

static const char *
p3_mode_name (u8 mode)
{
  if (mode == P3_MODE_LOCAL) return "queue-local";
  if (mode == P3_MODE_SHARED) return "canonical-shared-trylock";
  return "canonical-return";
}

static_always_inline u8
p3_ring_push (p3_ring_t *r, u64 id)
{
  u32 tail = __atomic_load_n (&r->tail, __ATOMIC_RELAXED);
  u32 next = (tail + 1) % P3_RING_CAP;
  if (next == __atomic_load_n (&r->head, __ATOMIC_ACQUIRE))
    return 0;
  r->id[tail] = id;
  __atomic_store_n (&r->tail, next, __ATOMIC_RELEASE);
  return 1;
}

static_always_inline u8
p3_ring_pop (p3_ring_t *r, u64 *id)
{
  u32 head = __atomic_load_n (&r->head, __ATOMIC_RELAXED);
  if (head == __atomic_load_n (&r->tail, __ATOMIC_ACQUIRE))
    return 0;
  *id = r->id[head];
  __atomic_store_n (&r->head, (head + 1) % P3_RING_CAP, __ATOMIC_RELEASE);
  return 1;
}

static_always_inline u8
p3_ring_peek (p3_ring_t *r, u64 *id)
{
  u32 head = __atomic_load_n (&r->head, __ATOMIC_RELAXED);
  if (head == __atomic_load_n (&r->tail, __ATOMIC_ACQUIRE))
    return 0;
  *id = r->id[head];
  return 1;
}

static_always_inline u8
p3_ring_empty (p3_ring_t *r)
{
  return __atomic_load_n (&r->head, __ATOMIC_ACQUIRE) ==
    __atomic_load_n (&r->tail, __ATOMIC_ACQUIRE);
}

static void
p3_notify (int fd, u8 *pending, u64 *attempts, u64 *writes, u64 *errors)
{
  u64 one = 1;
  __atomic_fetch_add (attempts, 1, __ATOMIC_RELAXED);
  if (__atomic_exchange_n (pending, 1, __ATOMIC_ACQ_REL) == 0)
    {
      if (write (fd, &one, sizeof (one)) == sizeof (one))
	__atomic_fetch_add (writes, 1, __ATOMIC_RELAXED);
      else
	{
	  __atomic_fetch_add (errors, 1, __ATOMIC_RELAXED);
	  __atomic_store_n (pending, 0, __ATOMIC_RELEASE);
	}
    }
}

static u64
p3_hash (const u8 *src, const u8 *dst, u16 src_port, u16 dst_port, u8 proto)
{
  u8 left[16] = { 0 }, right[16] = { 0 }, key[39], *p = key;
  const u8 *a = src, *b = dst;
  u16 ap = src_port, bp = dst_port;
  u64 h = 14695981039346656037ULL ^ P3_HASH_SEED;
  if (memcmp (a, b, 4) > 0 || (memcmp (a, b, 4) == 0 && ap > bp))
    { a = dst; b = src; ap = dst_port; bp = src_port; }
  clib_memcpy (left, a, 4); clib_memcpy (right, b, 4);
  *p++ = proto; *p++ = 0; clib_memcpy (p, left, 16); p += 16;
  *p++ = 0; clib_memcpy (p, right, 16); p += 16;
  *p++ = ap >> 8; *p++ = ap; *p++ = bp >> 8; *p++ = bp;
  for (u32 i = 0; i < sizeof (key); i++) { h ^= key[i]; h *= 1099511628211ULL; }
  return h;
}

static u8
p3_owner_for (struct nfq_data *nfa, u8 *prefix, u16 *prefix_len, u32 *flow_id)
{
  unsigned char *payload = 0;
  int length = nfq_get_payload (nfa, &payload);
  u32 ihl;
  if (length < 28 || !payload || (payload[0] >> 4) != 4 || payload[9] != IPPROTO_UDP)
    return 0xff;
  ihl = (payload[0] & 15) * 4;
  if (ihl < 20 || length < (int) ihl + 8)
    return 0xff;
  if (flow_id)
    {
      *flow_id = ~0;
      if (length >= (int) ihl + 24)
	{
	  u32 magic, id;
	  clib_memcpy (&magic, payload + ihl + 8, sizeof (magic));
	  clib_memcpy (&id, payload + ihl + 16, sizeof (id));
	  if (clib_net_to_host_u32 (magic) == P3_MARKER_MAGIC)
	    *flow_id = clib_net_to_host_u32 (id);
	}
    }
  *prefix_len = clib_min ((u32) length, (u32) P3_PREFIX);
  if (prefix)
    clib_memcpy (prefix, payload, *prefix_len);
  return (u8) (p3_hash (payload + 12, payload + 16,
                         clib_net_to_host_u16 (*(u16 *) (payload + ihl)),
                         clib_net_to_host_u16 (*(u16 *) (payload + ihl + 2)),
                         payload[9]) % P3_OWNERS);
}

static u8
p3_verdict (p3_lane_t *lane, u32 id, u32 verdict, u8 allow_remote)
{
  if (!allow_remote && vlib_get_thread_index () != 1 + lane->index)
    lane->verdict_thread_mismatch++;
  lane->verdict_attempts++;
  if (nfq_set_verdict (lane->queue, id, verdict, 0, 0) < 0)
    {
      lane->verdict_errors++;
      return 0;
    }
  else
    lane->verdict_success++;
  return 1;
}

static clib_error_t *p3_completion_ready (clib_file_t *f);

static clib_error_t *
p3_owner_ready (clib_file_t *f)
{
  p3_owner_t *owner = (p3_owner_t *) f->private_data;
  p3_main_t *pm = owner->pm;
  u64 value;
  u32 budget = P3_DRAIN_BUDGET;
  if (vlib_get_thread_index () != 1 + owner->index)
    owner->callback_thread_mismatch++;
  while (read (owner->event_fd, &value, sizeof (value)) == sizeof (value)) ;
  for (u32 origin = 0; origin < P3_LANES; origin++)
    {
      u64 token;
      while (budget && p3_ring_pop (&pm->ingress[origin][owner->index], &token))
	{
	  budget--;
	  u32 id = (u32) token;
	  u32 generation = token >> 32;
	  p3_desc_t *d;
	  if (id >= pm->pool_size)
	    { owner->completion_push_errors++; continue; }
	  d = &pm->desc[origin][id];
	  if (d->generation != generation ||
	      d->state != P3_OWNER || d->owner != owner->index)
	    { owner->completion_push_errors++; continue; }
	  d->decision = NF_ACCEPT;
	  d->verdict_done = 0;
	  if (pm->mode == P3_MODE_SHARED)
	    {
	      __atomic_fetch_add (&pm->lane[origin].shared_try, 1,
				  __ATOMIC_RELAXED);
	      if (clib_spinlock_trylock (&pm->lane[origin].io_gate))
		{
		  if (p3_verdict (&pm->lane[origin], d->packet_id,
				  d->decision, 1))
		    d->verdict_done = 1;
		  clib_spinlock_unlock (&pm->lane[origin].io_gate);
		  __atomic_fetch_add (&pm->lane[origin].shared_hit, 1,
				      __ATOMIC_RELAXED);
		}
	      else
		{
		  __atomic_fetch_add (&pm->lane[origin].shared_miss, 1,
				      __ATOMIC_RELAXED);
		  __atomic_fetch_add (&pm->lane[origin].shared_fallback, 1,
				      __ATOMIC_RELAXED);
		}
	    }
	  d->state = P3_COMPLETION;
	  owner->processed++;
	  if (!p3_ring_push (&pm->completion[owner->index][origin], token))
	    { owner->completion_push_errors++; ASSERT (0); continue; }
	  if (pm->inject_stale &&
	      __atomic_exchange_n (&pm->stale_injected, 1, __ATOMIC_ACQ_REL) == 0)
	    {
	      if (!p3_ring_push (&pm->completion[owner->index][origin],
				 token + (1ULL << 32)))
		owner->completion_push_errors++;
	    }
	  if (pm->inject_duplicate &&
	      __atomic_exchange_n (&pm->duplicate_injected, 1,
				   __ATOMIC_ACQ_REL) == 0)
	    {
	      if (!p3_ring_push (&pm->completion[owner->index][origin], token))
		owner->completion_push_errors++;
	    }
	  pm->lane[origin].owner_done++;
	  p3_notify (pm->lane[origin].completion_fd,
		     &pm->lane[origin].completion_pending,
		     &pm->lane[origin].completion_wake_attempts,
		     &pm->lane[origin].completion_wake_writes,
		     &pm->lane[origin].completion_wake_errors);
	}
      if (!budget)
	break;
    }
  __atomic_store_n (&owner->pending, 0, __ATOMIC_RELEASE);
  __atomic_thread_fence (__ATOMIC_ACQUIRE);
  for (u32 origin = 0; origin < P3_LANES; origin++)
    if (!p3_ring_empty (&pm->ingress[origin][owner->index]))
      {
	p3_notify (owner->event_fd, &owner->pending, &owner->wake_attempts,
		   &owner->wake_writes, &owner->wake_errors);
	break;
      }
  return 0;
}

static clib_error_t *
p3_completion_ready (clib_file_t *f)
{
  p3_lane_t *lane = (p3_lane_t *) f->private_data;
  p3_main_t *pm = lane->pm;
  u64 value;
  u8 deferred = 0;
  u32 budget = P3_DRAIN_BUDGET;
  if (vlib_get_thread_index () != 1 + lane->index)
    lane->callback_thread_mismatch++;
  while (read (lane->completion_fd, &value, sizeof (value)) == sizeof (value)) ;
  for (u32 owner = 0; owner < P3_OWNERS; owner++)
    {
      u64 token;
      while (budget && p3_ring_peek (&pm->completion[owner][lane->index], &token))
	{
	  u32 id = (u32) token;
	  u32 generation = token >> 32;
	  p3_desc_t *d;
	  if (id >= pm->pool_size)
	    {
	      u8 popped = p3_ring_pop (&pm->completion[owner][lane->index],
				       &token);
	      ASSERT (popped); if (!popped) break;
	      budget--; lane->stale_generation++; continue;
	    }
	  d = &pm->desc[lane->index][id];
	  if (pm->mode == P3_MODE_SHARED && !d->verdict_done &&
	      d->generation == generation && d->state == P3_COMPLETION &&
	      !clib_spinlock_trylock (&lane->io_gate))
	    { lane->lane_gate_defer++; deferred = 1; break; }
	  {
	    u8 popped = p3_ring_pop (&pm->completion[owner][lane->index],
				     &token);
	    ASSERT (popped); if (!popped) break;
	  }
	  budget--;
	  if (d->generation != generation)
	    { lane->stale_generation++; continue; }
	  if (d->state != P3_COMPLETION || d->origin != lane->index ||
	      d->owner != owner)
	    { lane->duplicate_terminal++; continue; }
	  if (d->verdict_done || p3_verdict (lane, d->packet_id, d->decision, 0))
	    {
	      d->state = P3_FREE;
	      ASSERT (lane->free_count < pm->pool_size);
	      lane->free_stack[lane->free_count++] = id;
	      lane->completion_done++;
	    }
	  if (pm->mode == P3_MODE_SHARED && !d->verdict_done)
	    clib_spinlock_unlock (&lane->io_gate);
	}
      if (deferred)
	break;
      if (!budget)
	break;
    }
  __atomic_store_n (&lane->completion_pending, 0, __ATOMIC_RELEASE);
  if (deferred)
    {
      p3_notify (lane->completion_fd, &lane->completion_pending,
		 &lane->completion_wake_attempts, &lane->completion_wake_writes,
		 &lane->completion_wake_errors);
      return 0;
    }
  __atomic_thread_fence (__ATOMIC_ACQUIRE);
  for (u32 owner = 0; owner < P3_OWNERS; owner++)
    if (!p3_ring_empty (&pm->completion[owner][lane->index]))
      {
	p3_notify (lane->completion_fd, &lane->completion_pending,
		   &lane->completion_wake_attempts, &lane->completion_wake_writes,
		   &lane->completion_wake_errors);
	break;
      }
  return 0;
}

static int
p3_packet_cb (struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
  p3_lane_t *lane = data;
  p3_main_t *pm = lane->pm;
  struct nfqnl_msg_packet_hdr *header;
  u32 packet_id, slot;
  u16 prefix_len = 0;
  u32 flow_id = ~0;
  u8 owner;
  (void) qh; (void) nfmsg;
  lane->seen++;
  if (qh != lane->queue)
    lane->qh_mismatch++;
  header = nfq_get_msg_packet_hdr (nfa);
  if (!header) { lane->missing_id++; return 0; }
  packet_id = clib_net_to_host_u32 (header->packet_id);
  owner = p3_owner_for (nfa, 0, &prefix_len, &flow_id);
  if (owner == 0xff) { lane->malformed++; p3_verdict (lane, packet_id, NF_DROP, 0); return 0; }
  if (!__atomic_load_n (&pm->accepting, __ATOMIC_ACQUIRE))
    { lane->overload++; p3_verdict (lane, packet_id, NF_DROP, 0); return 0; }
  if (flow_id != ~0 && pm->route_flow[lane->index][owner] == ~0)
    pm->route_flow[lane->index][owner] = flow_id;
  if (pm->mode == P3_MODE_LOCAL)
    { lane->local++; p3_verdict (lane, packet_id, NF_ACCEPT, 0); return 0; }
  if (owner == lane->index)
    { lane->local++; p3_verdict (lane, packet_id, NF_ACCEPT, 0); return 0; }
  if (lane->free_count == 0)
    { lane->overload++; p3_verdict (lane, packet_id, NF_DROP, 0); return 0; }
  slot = lane->free_stack[--lane->free_count];
  {
    p3_desc_t *d = &pm->desc[lane->index][slot];
    ASSERT (d->state == P3_FREE);
    d->generation++;
    if (d->generation == 0)
      d->generation++;
    d->packet_id = packet_id; d->origin = lane->index; d->owner = owner;
    d->prefix_len = prefix_len; d->state = P3_OWNER; d->decision = NF_DROP;
    d->verdict_done = 0;
    (void) p3_owner_for (nfa, d->prefix, &d->prefix_len, 0);
  }
  if (!p3_ring_push (&pm->ingress[lane->index][owner],
		     ((u64) pm->desc[lane->index][slot].generation << 32) | slot))
    { pm->desc[lane->index][slot].state = P3_FREE; lane->free_stack[lane->free_count++] = slot; lane->overload++; p3_verdict (lane, packet_id, NF_DROP, 0); return 0; }
  lane->remote++;
  p3_notify (pm->owner[owner].event_fd, &pm->owner[owner].pending,
             &pm->owner[owner].wake_attempts, &pm->owner[owner].wake_writes,
             &pm->owner[owner].wake_errors);
  return 0;
}

static clib_error_t *
p3_lane_ready (clib_file_t *f)
{
  p3_lane_t *lane = (p3_lane_t *) f->private_data;
  u8 buffer[65536];
  u8 locked = 0;
  lane->callback_tid = syscall (SYS_gettid);
  lane->callback_cpu = sched_getcpu ();
  if (vlib_get_thread_index () != 1 + lane->index) lane->callback_thread_mismatch++;
  if (lane->pm->mode == P3_MODE_SHARED)
    {
      if (!clib_spinlock_trylock (&lane->io_gate))
	{ lane->lane_gate_defer++; return 0; }
      locked = 1;
    }
  for (u32 n = 0; n < P3_DRAIN_BUDGET; n++)
    {
      int rv = recv (lane->fd, buffer, sizeof (buffer), MSG_DONTWAIT);
      if (rv >= 0) { if (nfq_handle_packet (lane->handle, (char *) buffer, rv) < 0) lane->handle_errors++; continue; }
      if (errno == EAGAIN || errno == EWOULDBLOCK) break;
      if (errno == EINTR) continue;
      if (errno == ENOBUFS) { lane->enobufs++; break; }
      lane->recv_errors++;
      if (locked) clib_spinlock_unlock (&lane->io_gate);
      return clib_error_return_unix (0, "p3 recv");
    }
  if (locked) clib_spinlock_unlock (&lane->io_gate);
  return 0;
}

static void
p3_cleanup (vlib_main_t *vm, p3_main_t *pm)
{
  vlib_worker_thread_barrier_sync (vm);
  for (u32 i = 0; i < P3_LANES; i++)
    {
      p3_lane_t *l = &pm->lane[i];
      if (l->file_index != ~0)
	clib_file_del_by_index (&file_main, l->file_index);
      if (l->completion_file_index != ~0)
	clib_file_del_by_index (&file_main, l->completion_file_index);
      if (l->queue)
	nfq_destroy_queue (l->queue);
      if (l->handle)
	nfq_close (l->handle);
      if (l->completion_fd >= 0)
	close (l->completion_fd);
      clib_spinlock_free (&l->io_gate);
      l->file_index = l->completion_file_index = ~0;
      l->handle = 0; l->queue = 0; l->fd = -1; l->completion_fd = -1;
    }
  for (u32 i = 0; i < P3_OWNERS; i++)
    {
      p3_owner_t *o = &pm->owner[i];
      if (o->file_index != ~0)
	clib_file_del_by_index (&file_main, o->file_index);
      if (o->event_fd >= 0)
	close (o->event_fd);
      o->file_index = ~0; o->event_fd = -1;
    }
  pm->enabled = 0;
  vlib_worker_thread_barrier_release (vm);
}

static clib_error_t *p3_stop (vlib_main_t *vm);

static clib_error_t *
p3_start (vlib_main_t *vm, u16 base_queue, u32 pool, u8 mode, u8 inject_stale,
	  u8 inject_duplicate)
{
  p3_main_t *pm = &p3_main;
  if (pm->enabled) return clib_error_return (0, "p3 already enabled");
  if (vlib_num_workers () < P3_OWNERS || pool == 0 || pool > P3_POOL_MAX)
    return clib_error_return (0, "p3 needs two workers and pool 1..%u", P3_POOL_MAX);
  clib_memset (pm, 0, sizeof (*pm)); pm->pool_size = pool; pm->base_queue = base_queue;
  for (u32 i = 0; i < P3_OWNERS; i++)
    { pm->owner[i].event_fd = -1; pm->owner[i].file_index = ~0; }
  for (u32 i = 0; i < P3_LANES; i++)
    {
      pm->lane[i].fd = pm->lane[i].completion_fd = -1;
      pm->lane[i].file_index = pm->lane[i].completion_file_index = ~0;
      clib_spinlock_init (&pm->lane[i].io_gate);
    }
  pm->mode = mode; pm->inject_stale = inject_stale; pm->inject_duplicate = inject_duplicate;
  for (u32 lane = 0; lane < P3_LANES; lane++)
    for (u32 owner = 0; owner < P3_OWNERS; owner++)
      pm->route_flow[lane][owner] = ~0;
  for (u32 i = 0; i < P3_OWNERS; i++)
    {
      p3_owner_t *o = &pm->owner[i]; clib_file_t file = { 0 };
      o->pm = pm; o->index = i; o->event_fd = eventfd (0, EFD_NONBLOCK); o->file_index = ~0;
      if (o->event_fd < 0) goto fail;
      file.read_function = p3_owner_ready; file.file_descriptor = o->event_fd;
      file.private_data = (uword) o; file.polling_thread_index = 1 + i; file.dont_close = 1;
      file.description = format (0, "nfqueue-handoff-poc owner %u", i);
      o->file_index = clib_file_add (&file_main, &file);
      if (o->file_index == ~0)
	goto fail;
    }
  for (u32 i = 0; i < P3_LANES; i++)
    {
      p3_lane_t *l = &pm->lane[i]; clib_file_t file = { 0 }; int flags;
      l->pm = pm; l->index = i; l->queue_num = base_queue + i; l->file_index = l->completion_file_index = ~0; l->fd = -1;
      for (u32 s = 0; s < pool; s++) l->free_stack[s] = s;
      l->free_count = pool; l->completion_fd = eventfd (0, EFD_NONBLOCK);
      if (l->completion_fd < 0) goto fail;
      file.read_function = p3_completion_ready; file.file_descriptor = l->completion_fd; file.private_data = (uword) l;
      file.polling_thread_index = 1 + i; file.dont_close = 1; file.description = format (0, "nfqueue-handoff-poc completion %u", i);
      l->completion_file_index = clib_file_add (&file_main, &file);
      if (l->completion_file_index == ~0)
	goto fail;
      l->handle = nfq_open (); if (!l->handle || nfq_bind_pf (l->handle, AF_INET) < 0) goto fail;
      l->queue = nfq_create_queue (l->handle, l->queue_num, p3_packet_cb, l); if (!l->queue) goto fail;
      if (nfq_set_mode (l->queue, NFQNL_COPY_PACKET, P3_PREFIX) < 0 || nfq_set_queue_maxlen (l->queue, 4096) < 0) goto fail;
      l->fd = nfq_fd (l->handle); flags = fcntl (l->fd, F_GETFL, 0);
      if (flags < 0 || fcntl (l->fd, F_SETFL, flags | O_NONBLOCK) < 0) goto fail;
      clib_memset (&file, 0, sizeof (file)); file.read_function = p3_lane_ready; file.file_descriptor = l->fd; file.private_data = (uword) l;
      file.polling_thread_index = 1 + i; file.dont_close = 1; file.description = format (0, "nfqueue-handoff-poc lane %u", i);
      l->file_index = clib_file_add (&file_main, &file);
      if (l->file_index == ~0)
	goto fail;
    }
  pm->accepting = 1; pm->enabled = 1; return 0;
fail:
  p3_cleanup (vm, pm); return clib_error_return_unix (0, "p3 start");
}

static clib_error_t *
p3_stop (vlib_main_t *vm)
{
  p3_main_t *pm = &p3_main;
  if (!pm->enabled) return 0;
  __atomic_store_n (&pm->accepting, 0, __ATOMIC_RELEASE);
  vlib_worker_thread_barrier_sync (vm);
  for (u32 i = 0; i < P3_LANES; i++)
    if (pm->lane[i].free_count != pm->pool_size)
      {
	vlib_worker_thread_barrier_release (vm);
	return clib_error_return (0, "p3 outstanding descriptors");
      }
  for (u32 lane = 0; lane < P3_LANES; lane++)
    for (u32 owner = 0; owner < P3_OWNERS; owner++)
      if (!p3_ring_empty (&pm->ingress[lane][owner]) ||
	  !p3_ring_empty (&pm->completion[owner][lane]))
	{
	  vlib_worker_thread_barrier_release (vm);
	  return clib_error_return (0, "p3 rings not drained");
	}
  vlib_worker_thread_barrier_release (vm);
  p3_cleanup (vm, pm); return 0;
}

static clib_error_t *
p3_start_cli (vlib_main_t *vm, unformat_input_t *in, vlib_cli_command_t *cmd)
{
  u32 queue = 70, pool = P3_POOL_MAX; u8 mode = P3_MODE_RETURN; (void) cmd;
  u8 inject_stale = 0, inject_duplicate = 0;
  while (unformat_check_input (in) != UNFORMAT_END_OF_INPUT)
    { if (unformat (in, "queue %u", &queue)) ; else if (unformat (in, "pool %u", &pool)) ;
      else if (unformat (in, "inject stale")) inject_stale = 1;
      else if (unformat (in, "inject duplicate")) inject_duplicate = 1;
      else if (unformat (in, "mode queue-local")) mode = P3_MODE_LOCAL;
      else if (unformat (in, "mode canonical-return")) mode = P3_MODE_RETURN;
      else if (unformat (in, "mode canonical-shared-trylock")) mode = P3_MODE_SHARED;
      else return clib_error_return (0, "unknown input"); }
  return p3_start (vm, (u16) queue, pool, mode, inject_stale, inject_duplicate);
}
VLIB_CLI_COMMAND (p3_start_cmd, static) = { .path = "nfqueue-handoff-poc start", .short_help = "nfqueue-handoff-poc start [queue <n>] [pool <1..128>] [mode queue-local|canonical-return|canonical-shared-trylock] [inject stale] [inject duplicate]", .function = p3_start_cli };

static clib_error_t *
p3_stop_cli (vlib_main_t *vm, unformat_input_t *in, vlib_cli_command_t *cmd)
{ (void) in; (void) cmd; return p3_stop (vm); }
VLIB_CLI_COMMAND (p3_stop_cmd, static) = { .path = "nfqueue-handoff-poc stop", .short_help = "nfqueue-handoff-poc stop", .function = p3_stop_cli };

static clib_error_t *
p3_show_cli (vlib_main_t *vm, unformat_input_t *in, vlib_cli_command_t *cmd)
{
  p3_main_t *pm = &p3_main; u64 outstanding = 0; (void) in; (void) cmd;
  if (!pm->enabled) { vlib_cli_output (vm, "p3 enabled 0"); return 0; }
  vlib_worker_thread_barrier_sync (vm);
  for (u32 i = 0; i < P3_LANES; i++) { p3_lane_t *l = &pm->lane[i]; outstanding += pm->pool_size - l->free_count; vlib_cli_output (vm, "p3 lane %u queue %u seen %llu local %llu remote %llu overload %llu owner-done %llu completion-done %llu verdict-attempts %llu verdict-success %llu verdict-errors %llu free %u stale-generation %llu duplicate-terminal %llu tid %llu cpu %lld thread-mismatches %llu qh-mismatches %llu verdict-thread-mismatches %llu wake-attempts %llu wake-writes %llu wake-errors %llu shared-try %llu shared-hit %llu shared-miss %llu shared-fallback %llu lane-gate-defer %llu", i, l->queue_num, l->seen, l->local, l->remote, l->overload, l->owner_done, l->completion_done, l->verdict_attempts, l->verdict_success, l->verdict_errors, l->free_count, l->stale_generation, l->duplicate_terminal, l->callback_tid, (long long) l->callback_cpu, l->callback_thread_mismatch, l->qh_mismatch, l->verdict_thread_mismatch, l->completion_wake_attempts, l->completion_wake_writes, l->completion_wake_errors, l->shared_try, l->shared_hit, l->shared_miss, l->shared_fallback, l->lane_gate_defer); }
  for (u32 i = 0; i < P3_OWNERS; i++) { p3_owner_t *o = &pm->owner[i]; vlib_cli_output (vm, "p3 owner %u processed %llu completion-push-errors %llu wake-attempts %llu wake-writes %llu wake-errors %llu thread-mismatches %llu", i, o->processed, o->completion_push_errors, o->wake_attempts, o->wake_writes, o->wake_errors, o->callback_thread_mismatch); }
  vlib_cli_output (vm, "p3 oracle lane0-owner0 %u lane0-owner1 %u lane1-owner0 %u lane1-owner1 %u", pm->route_flow[0][0], pm->route_flow[0][1], pm->route_flow[1][0], pm->route_flow[1][1]);
  vlib_cli_output (vm, "p3 enabled 1 accepting %u mode %s pool %u outstanding %llu hash-seed %llu injected-stale %u injected-duplicate %u", pm->accepting, p3_mode_name (pm->mode), pm->pool_size, outstanding, P3_HASH_SEED, pm->stale_injected, pm->duplicate_injected);
  vlib_worker_thread_barrier_release (vm); return 0;
}
VLIB_CLI_COMMAND (p3_show_cmd, static) = { .path = "show nfqueue-handoff-poc", .short_help = "show nfqueue-handoff-poc", .function = p3_show_cli };
