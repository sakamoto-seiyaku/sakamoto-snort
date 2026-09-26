#include "minimal_ring.h"
#include <string.h>

typedef struct { uint32_t length, reserved; } record_header;
_Static_assert(sizeof(record_header)==8, "record header layout");
_Static_assert(sizeof(_Atomic uint64_t)==8, "position layout");
_Static_assert(offsetof(minimal_ring,data)==128, "separate position cache lines");
_Static_assert(sizeof(minimal_ring)==T20_RING_CAPACITY+128, "shared footprint");
_Static_assert((T20_RING_CAPACITY & (T20_RING_CAPACITY-1))==0, "power-of-two capacity");

int minimal_ring_init(minimal_ring *q)
{
  if (!atomic_is_lock_free(&q->head) || !atomic_is_lock_free(&q->tail)) return -1;
  atomic_init(&q->head,0);
  atomic_init(&q->tail,0);
  return 0;
}

int minimal_ring_write(minimal_ring *q,const void *data,size_t length)
{
  if (!data || !length || length>T20_RING_MAX_RECORD) return -1;
  uint64_t tail=atomic_load_explicit(&q->tail,memory_order_relaxed);
  uint64_t head=atomic_load_explicit(&q->head,memory_order_acquire);
  uint64_t used=tail-head; /* Unsigned modular difference also covers counter wrap. */
  if (used>T20_RING_CAPACITY || (head|tail)&7) return -1;
  size_t bytes=(sizeof(record_header)+length+7)&~(size_t)7;
  size_t offset=(size_t)(tail & (T20_RING_CAPACITY-1));
  size_t remaining=T20_RING_CAPACITY-offset;
  size_t padding=remaining<bytes?remaining:0;
  if (bytes+padding>T20_RING_CAPACITY-used) return 1;

  if (padding) {
    record_header marker={0,0};
    memcpy(q->data+offset,&marker,sizeof(marker));
    offset=0;
  }
  record_header header={(uint32_t)length,0};
  memcpy(q->data+offset,&header,sizeof(header));
  memcpy(q->data+offset+sizeof(header),data,length);
  /* No reader can inspect the header/payload until this publication. */
  atomic_store_explicit(&q->tail,tail+padding+bytes,memory_order_release);
  return 0;
}

int minimal_ring_read(minimal_ring *q,size_t limit,minimal_record_fn fn,
                      void *arg,size_t *count)
{
  *count=0;
  uint64_t head=atomic_load_explicit(&q->head,memory_order_relaxed);
  uint64_t tail=atomic_load_explicit(&q->tail,memory_order_acquire);
  uint64_t available=tail-head;
  if (available>T20_RING_CAPACITY || (head|tail)&7) return -1;
  size_t n=0;
  while (available && n<limit) {
    size_t offset=(size_t)(head & (T20_RING_CAPACITY-1));
    size_t remaining=T20_RING_CAPACITY-offset;
    record_header header;
    if (available<sizeof(header)) return -1;
    memcpy(&header,q->data+offset,sizeof(header));
    if (header.reserved || header.length>T20_RING_MAX_RECORD) return -1;
    if (!header.length) {
      if (available<=remaining || remaining>=sizeof(header)+T20_RING_MAX_RECORD) return -1;
      head+=remaining;available-=remaining;
      continue;
    }
    size_t bytes=(sizeof(header)+header.length+7)&~(size_t)7;
    if (bytes>available || bytes>remaining) return -1;
    fn(q->data+offset+sizeof(header),header.length,arg);
    head+=bytes;available-=bytes;n++;
  }
  /* A producer acquire of this head may reuse all completed callback bytes. */
  atomic_store_explicit(&q->head,head,memory_order_release);
  *count=n;
  return 0;
}
