/* SPDX-License-Identifier: Apache-2.0 */
/* Real TLS/socket IO below the existing source-linked Adapter fixture. The
 * host's SO_MARK and raw return are controlled platform dependencies. */
#include <poll.h>
int __real_setsockopt(int,int,int,const void *,socklen_t);
int __wrap_setsockopt(int fd,int level,int option,const void *value,socklen_t length)
{
 if(level==SOL_SOCKET&&option==SO_MARK)return 0;
 return __real_setsockopt(fd,level,option,value,length);
}
static void tls_view_tick(void)
{
 struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));
 now_us=(u64)t.tv_sec*1000000+t.tv_nsec/1000;
}
static void tls_view_replacement(void)
{
 const char *port=getenv("SAKAMOTO_TEST_DOT_PORT");assert(port);
 assert(!product_l4_policy_compile(&bank.view,NULL,0));
 tls_view_tick();initialize(322,4);
 for(unsigned cycle=0;cycle<12;++cycle) {
  bank.dns=(product_dns_proxy_route_t){.enabled=1,.family=4,.port=atoi(port),
   .address={127,0,0,1},.endpoint_count=1,.route_count=1,.routes={{.count=1}},
   .endpoints={{.transport=PRODUCT_DNS_PROXY_DOT,.family=4,.port=atoi(port),.address={127,0,0,1}}}};
  strcpy((char *)bank.dns.endpoints[0].identity,cycle%2?"127.0.0.1":"dot.test");
  ++bank.dns_revision;snapshot.identity.revision=bank.dns_revision;
  root_dns_sync(&root_dns_owners[0],now_us);
  assert(root_dns_owner_current(&root_dns_owners[0],bank.dns_revision,network.revision));
  reset_terminal();consume();
  u64 deadline=now_us+3000000;
  clib_file_t old_file=watched;
  while(!pending()&&now_us<deadline) {
   clib_file_t file=watched;
   struct pollfd fd={.fd=file.file_descriptor,.events=POLLIN|POLLOUT};
   assert(poll(&fd,1,5)>=0);tls_view_tick();
   if(fd.revents&POLLIN)root_dns_file_read(&file);
   if(fd.revents&POLLOUT)root_dns_file_write(&file);
   product_root_dns_adapter_expire(&worker,now_us);
  }
  assert(pending());
  assert(records[record_count-1].tls_state==PRODUCT_DNS_TLS_AUTHENTICATED);
  finish(0,0);
  assert(!product_dns_proxy_resources(root_dns_owners[0].proxy).active);
  assert(!product_root_dns_io_status(root_dns_owners[0].io).tls_connections);
  ++bank.dns_revision;snapshot.identity.revision=bank.dns_revision;
  root_dns_sync(&root_dns_owners[0],now_us);
  assert(root_dns_owners[0].generation==322&&root_dns_owner_current(&root_dns_owners[0],bank.dns_revision,network.revision));
  root_dns_file_read(&old_file);root_dns_file_write(&old_file);
  assert(!product_root_dns_io_status(root_dns_owners[0].io).sockets);
  assert(!product_dns_proxy_resources(root_dns_owners[0].proxy).active&&!pending()&&!watches);
 }
 close_owner();assert(raw_created==raw_closed);
 puts("Actual authenticated TLS -> root_dns_sync replacement -> stale file event -> bounded clean closure PASS");
}
