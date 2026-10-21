#!/usr/bin/env python3
"""Execute the pinned VPP pool allocator against real guarded ordinary pages.

Only map/vector/platform plumbing is replaced. Allocation geometry and pool
initialization come verbatim from VPP plus the Product core patch.
"""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PATCH = ROOT / 'src/product/vpp/patches/core/0007-vlib-virtual-buffer-pool.patch'


def function(source, name):
    marker = '\n' + name + ' ('
    start = source.index(marker)
    start = source.rfind('\n\n', 0, start) + 2
    end = source.index('\n}\n', start) + 3
    return source[start:end]


STUBS = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uintptr_t uword;
typedef unsigned clib_mem_page_sz_t;
enum { CLIB_MEM_PAGE_SZ_UNKNOWN=255, CLIB_MEM_PAGE_SZ_DEFAULT=0 };
#define VLIB_BUFFER_ALIGN TEST_BUFFER_ALIGN
#define CLIB_CACHE_LINE_BYTES TEST_BUFFER_ALIGN
#define CLIB_LOG2_CACHE_LINE_BYTES (TEST_BUFFER_ALIGN == 128 ? 7 : 6)
#define VLIB_BUFFER_DEFAULT_BUFFERS_PER_NUMA 16384
#define VLIB_BUFFER_DEFAULT_BUFFERS_PER_NUMA_UNPRIV 8192
#define ASSERT assert
#define always_inline static inline
#define PREDICT_FALSE(x) __builtin_expect(!!(x),0)
#define pointer_to_uword(p) ((uword)(p))
#define round_pow2(n,a) (((n)+(a)-1)&~((uword)(a)-1))
#define pow2_mask(n) (((uword)1<<(n))-1)
#define vec_free(p) free(p)
typedef struct { u8 buffer_pool_index, ref_count; } vlib_buffer_template_t;
typedef struct { vlib_buffer_template_t template; u8 padding[254]; u8 data[]; } vlib_buffer_t;
_Static_assert(sizeof(vlib_buffer_t)==256, "real Product header size");
typedef struct {
  uword start, size;
  u32 index, physmem_map_index, data_size, numa_node, log2_page_size;
  u32 alloc_size, *buffers, n_avail, n_buffers;
  vlib_buffer_template_t buffer_template;
  void *threads, *lock;
  u8 *name;
} vlib_buffer_pool_t;
typedef struct {
  uword buffer_mem_start, buffer_mem_size;
  vlib_buffer_pool_t *buffer_pools;
  u32 default_buffers_per_numa, buffers_per_numa[32];
  u16 ext_hdr_size;
  u32 default_data_size;
  unsigned virtual_only;
} vlib_buffer_main_t;
typedef struct vlib_main_t { vlib_buffer_main_t *buffer_main; } vlib_main_t;
typedef struct { void *base; u32 n_pages, log2_page_size, numa_node; } vlib_physmem_map_t;
typedef struct { char message[256]; } clib_error_t;
static vlib_physmem_map_t map;
static u32 pools;
static unsigned map_calls;
static void *mapping;
static size_t mapping_size;
#define vec_len(p) pools
#define vec_add2_aligned(v,p,n,a) do { \
  assert(!(v)); (v)=calloc(1,sizeof(*(v))); assert(v); \
  (p)=(v); ++pools; \
} while(0)
#define vec_validate_aligned(p,n,a) do { (p)=calloc(1,128); assert(p); } while(0)
static void clib_spinlock_init(void *lock) { (void)lock; }
static void *clib_mem_alloc_aligned(size_t n,size_t a) {
  void *p=0; assert(!posix_memalign(&p,a,n)); return p;
}
static void clib_panic(const char *s,...) { fprintf(stderr,"%s\n",s); abort(); }
static uword clib_mem_page_bytes(clib_mem_page_sz_t n) {
  return n==CLIB_MEM_PAGE_SZ_DEFAULT ? 4096 : (uword)1<<n;
}
static unsigned min_log2(uword n) { return 63-__builtin_clzll(n); }
static unsigned vlib_get_n_threads(void) { return 3; }
static u32 vlib_buffer_get_default_data_size(vlib_main_t *vm) {
  return vm->buffer_main->default_data_size;
}
static vlib_physmem_map_t *vlib_physmem_get_map(vlib_main_t *vm,u32 i) {
  (void)vm; assert(i==0); return &map;
}
static u32 vlib_get_buffer_index(vlib_main_t *vm,vlib_buffer_t *b) {
  uword offset=(uword)b-vm->buffer_main->buffer_mem_start;
  assert(!(offset%CLIB_CACHE_LINE_BYTES));
  return offset>>CLIB_LOG2_CACHE_LINE_BYTES;
}
static vlib_buffer_t *vlib_get_buffer(vlib_main_t *vm,u32 i) {
  return (void *)(vm->buffer_main->buffer_mem_start+((uword)i<<CLIB_LOG2_CACHE_LINE_BYTES));
}
static uword vlib_physmem_get_pa(vlib_main_t *vm,void *data) {
  (void)vm; return (uword)data;
}
static u8 *format(void *unused,const char *fmt,...) {
  (void)unused; (void)fmt; return (u8 *)strdup("test-pool");
}
static u8 *va_format(void *unused,const char *fmt,va_list *args) {
  (void)args; return format(unused,fmt);
}
static clib_error_t *clib_error_return(void *unused,const char *fmt,...) {
  (void)unused; clib_error_t *e=calloc(1,sizeof(*e)); assert(e);
  snprintf(e->message,sizeof(e->message),"%s",fmt); return e;
}
static clib_error_t *vlib_physmem_shared_map_create(vlib_main_t *vm,char *name,
  uword size,u32 page,u32 numa,u32 *index) {
  (void)vm; (void)name; assert(page==12); assert(!(size%4096));
  ++map_calls;
  mapping_size=size+8192;
  mapping=mmap(0,mapping_size,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  assert(mapping!=MAP_FAILED);
  map=(vlib_physmem_map_t){(u8 *)mapping+4096,size/4096,12,numa};
  assert(!mprotect(map.base,size,PROT_READ|PROT_WRITE)); *index=0; return 0;
}
'''

TEST = r'''
static void check(u32 data,u32 count,int virtual_only) {
  vlib_buffer_main_t bm={.default_buffers_per_numa=count,
    .default_data_size=data,.virtual_only=virtual_only};
  memset(bm.buffers_per_numa,255,sizeof(bm.buffers_per_numa));
  vlib_main_t vm={&bm}; u32 index=~0;
  clib_error_t *e=vlib_buffer_main_init_numa_alloc(&vm,0,&index,
    CLIB_MEM_PAGE_SZ_DEFAULT,1);
  if(e) { fprintf(stderr,"allocation failed data=%u virtual=%d: %s\n",
                  data,virtual_only,e->message); free(e); exit(1); }
  assert(index==0 && map.log2_page_size==12);
  u8 pool=vlib_buffer_pool_create(&vm,data,index,"test"); assert(pool==0);
  vlib_buffer_pool_t *bp=bm.buffer_pools;
  assert(bp->n_buffers==count || !virtual_only);
  if(virtual_only) assert(map.n_pages*4096ULL<=(uword)(count+3)*bp->alloc_size+4096);
  unsigned crossings=0;
  for(u32 i=0;i<bp->n_buffers;++i) {
    u32 bi=bp->buffers[i]; assert(bi);
    vlib_buffer_t *b=vlib_get_buffer(&vm,bi);
    assert(b->template.buffer_pool_index==pool && b->template.ref_count==1);
    uword start=(uword)b, end=start+sizeof(*b)+data;
    assert(start>=(uword)map.base && end<=(uword)map.base+(uword)map.n_pages*4096);
    if(i) assert(start>=(uword)vlib_get_buffer(&vm,bp->buffers[i-1])+bp->alloc_size);
    if(start/4096!=(end-1)/4096) ++crossings;
    /* Keep all buffers live: detect overlap and overwrite, not only geometry. */
    memset((u8 *)b+sizeof(*b),(u8)i,data);
  }
  for(u32 i=0;i<bp->n_buffers;++i) {
    u8 *p=(u8 *)vlib_get_buffer(&vm,bp->buffers[i])+sizeof(vlib_buffer_t);
    for(u32 j=0;j<data;++j) assert(p[j]==(u8)i);
  }
  if(data>4096) assert(crossings==bp->n_buffers);
  if(!virtual_only) assert(!crossings);
  printf("data=%u requested=%u actual=%u stride=%u pages=%u crossing=%u virtual=%d PASS\n",
    data,count,bp->n_buffers,bp->alloc_size,map.n_pages,crossings,virtual_only);
  free(bp->buffers); free(bp->threads); free(bp->name); free(bm.buffer_pools);
  assert(!munmap(mapping,mapping_size)); pools=0;
}
int main(void) {
  struct rlimit limit={0,0}; assert(!setrlimit(RLIMIT_CORE,&limit));
  assert(sysconf(_SC_PAGESIZE)==4096);
  check(2048,512,0);
  check(3072,512,0);
  check(10240,2048,1);
  check(10240,512,1);
  check(3072,512,1);
  /* Oversized data remains invalid unless explicitly virtual-only. */
  vlib_buffer_main_t bm={.default_buffers_per_numa=512,.default_data_size=10240};
  memset(bm.buffers_per_numa,255,sizeof(bm.buffers_per_numa));
  vlib_main_t vm={&bm}; u32 index=~0; unsigned calls=map_calls;
  clib_error_t *e=vlib_buffer_main_init_numa_alloc(&vm,0,&index,CLIB_MEM_PAGE_SZ_DEFAULT,1);
  assert(e && map_calls==calls); free(e);
  bm.virtual_only=1; bm.default_data_size=65536;
  e=vlib_buffer_main_init_numa_alloc(&vm,0,&index,CLIB_MEM_PAGE_SZ_DEFAULT,1);
  assert(e && map_calls==calls); free(e);
  /* The public DMA accessor must fail in release builds as well. */
  pid_t child=fork(); assert(child>=0);
  if(!child) { vlib_buffer_t b={0}; (void)vlib_buffer_get_pa(&vm,&b); _exit(0); }
  int status=0; assert(waitpid(child,&status,0)==child);
  assert(WIFSIGNALED(status) && WTERMSIG(status)==SIGABRT);
  puts("explicit virtual-only boundary PASS");
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path,
                        default=Path(os.environ.get('VPP_SOURCE_DIR', ROOT / 'build-output/pinned-vpp-clean')))
    parser.add_argument('--baseline', action='store_true')
    args = parser.parse_args()
    if not (args.source_dir / 'src/vlib/buffer.c').exists():
        parser.error('supply the clean pinned VPP source with --source-dir or VPP_SOURCE_DIR')
    with tempfile.TemporaryDirectory(prefix='vpp-virtual-buffer-test-') as folder:
        tmp = Path(folder)
        for name in ('buffer.c', 'buffer.h', 'buffer_funcs.h'):
            out = tmp / 'src/vlib' / name
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes((args.source_dir / 'src/vlib' / name).read_bytes())
        if not args.baseline:
            subprocess.run(['git', 'apply', '--whitespace=error', str(PATCH)], cwd=tmp, check=True)
        text = (tmp / 'src/vlib/buffer.c').read_text()
        names = ['vlib_buffer_alloc_size']
        if '\nvlib_buffer_configured_count (' in text:
            names.append('vlib_buffer_configured_count')
        names.extend(('vlib_buffer_pool_create', 'vlib_buffer_main_init_numa_alloc'))
        physical = function((tmp / 'src/vlib/buffer_funcs.h').read_text(), 'vlib_buffer_get_pa')
        source = STUBS + '\n'.join(function(text, name) for name in names) + physical + TEST
        (tmp / 'test.c').write_text(source)
        for align in (64, 128):
            binary = tmp / ('test-' + str(align))
            subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra',
                            '-Werror', '-Wno-unused-function', '-Wno-sign-compare',
                            '-fsanitize=undefined',
                            '-DTEST_BUFFER_ALIGN=' + str(align), str(tmp / 'test.c'),
                            '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    main()
