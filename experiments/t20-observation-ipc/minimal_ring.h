#ifndef T20_MINIMAL_RING_H
#define T20_MINIMAL_RING_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

/* Experimental shared layout. Both endpoints use this exact C implementation. */
#define T20_RING_CAPACITY 262144u
#define T20_RING_MAX_RECORD 2048u
typedef struct {
  _Alignas(64) _Atomic uint64_t head;
  _Alignas(64) _Atomic uint64_t tail;
  _Alignas(64) uint8_t data[T20_RING_CAPACITY];
} minimal_ring;

typedef void (*minimal_record_fn)(const uint8_t *, size_t, void *);
int minimal_ring_init(minimal_ring *);
/* 0 admitted, 1 full, -1 invalid input/state. A failed write changes no bytes. */
int minimal_ring_write(minimal_ring *, const void *, size_t);
/* The callback borrow ends before the head is released. -1 means corrupt state. */
int minimal_ring_read(minimal_ring *, size_t, minimal_record_fn, void *, size_t *);

#endif
