/* Explicit controlled snapshot publication for the Linux fragment test. */
#define _POSIX_C_SOURCE 200809L
#include "sakamoto_product_core_ffi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
static sakamoto_product_bytes_t bytes(const char *s) {return (sakamoto_product_bytes_t){(const uint8_t *)s,(uint32_t)strlen(s)};}
int main(int argc,char **argv) {
 if(argc!=5)return 2;
 uint64_t generation=strtoull(argv[2],0,10);
 sakamoto_product_core_handle_t *handle=0;sakamoto_product_status_t status={0};
 uint32_t rc=sakamoto_product_core_connect(bytes(argv[1]),generation,&handle,&status);
 if(rc)return (int)rc;
 struct timespec now;clock_gettime(CLOCK_MONOTONIC,&now);
 sakamoto_product_network_snapshot_t snapshot={0};
 snapshot.revision=strtoull(argv[3],0,10);snapshot.event_elapsed_ns=(uint64_t)now.tv_sec*1000000000+now.tv_nsec;
 snapshot.count=1;snapshot.entries[0].linux_ifindex=31;snapshot.entries[0].context=(uint32_t)strtoul(argv[4],0,10);
 rc=sakamoto_product_core_publish_network(handle,generation,&snapshot);
 printf("network rc=%u generation=%llu revision=%llu context=%u source=CONTROLLED_TEST_PROVIDER\n",rc,(unsigned long long)generation,(unsigned long long)snapshot.revision,snapshot.entries[0].context);
 sakamoto_product_core_disconnect(handle);sakamoto_product_core_destroy(handle);return (int)rc;
}
