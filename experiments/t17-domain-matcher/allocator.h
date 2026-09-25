#ifndef T17_ALLOCATOR_H
#define T17_ALLOCATOR_H
#include <malloc.h>
#include <stdlib.h>
#define rax_malloc malloc
#define rax_realloc realloc
#define rax_free free
#define rax_ptr_alloc_size malloc_usable_size
#endif
