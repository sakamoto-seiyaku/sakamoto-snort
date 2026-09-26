#ifndef T17_5_ALLOCATOR_H
#define T17_5_ALLOCATOR_H
#include <stddef.h>
void *recovery_alloc(size_t size);
void *recovery_realloc(void *pointer, size_t size);
void recovery_free(void *pointer);
size_t recovery_size(void *pointer);
#define rax_malloc recovery_alloc
#define rax_realloc recovery_realloc
#define rax_free recovery_free
#define rax_ptr_alloc_size recovery_size
#endif
