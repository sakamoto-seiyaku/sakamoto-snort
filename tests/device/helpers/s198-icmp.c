/* Controlled kernel endpoint; packets reach the real TUN, never a graph injector. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <linux/capability.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
static void fail(const char *message) { perror(message); exit(1); }
static unsigned checksum(const unsigned char *p, unsigned size) {
  unsigned sum=0;
  for (unsigned i=0;i<size;i+=2) sum+=((unsigned)p[i]<<8)+(i+1<size?p[i+1]:0);
  while (sum>>16) sum=(sum&65535)+(sum>>16);
  return (~sum)&65535;
}
int main(int argc,char **argv) {
  if(argc!=6)return 2;
  uid_t uid=(uid_t)strtoul(argv[1],0,10);int family=atoi(argv[2]);
  if(family!=4&&family!=6)return 2;
  if (getuid()!=uid) {
    if(prctl(PR_SET_KEEPCAPS,1L,0L,0L,0L)||setgid(uid)||setuid(uid))fail("endpoint uid");
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct caps[2]={{0}};
    caps[0].permitted=caps[0].effective=1U<<CAP_NET_RAW;
    if(syscall(SYS_capset,&header,caps))fail("endpoint capset");
  }
  int fd=socket(family==4?AF_INET:AF_INET6,SOCK_RAW,family==4?IPPROTO_ICMP:IPPROTO_ICMPV6);
  if(fd<0)fail("icmp socket");
  struct sockaddr_storage source={0},destination={0};socklen_t length;
  if(family==4) {
    struct sockaddr_in *s=(void*)&source,*d=(void*)&destination;
    s->sin_family=d->sin_family=AF_INET;
    inet_pton(AF_INET,"10.111.0.2",&s->sin_addr);inet_pton(AF_INET,"198.18.198.1",&d->sin_addr);length=sizeof(*s);
  } else {
    struct sockaddr_in6 *s=(void*)&source,*d=(void*)&destination;
    s->sin6_family=d->sin6_family=AF_INET6;
    inet_pton(AF_INET6,"fd00:111:111::2",&s->sin6_addr);inet_pton(AF_INET6,"fd00:198::1",&d->sin6_addr);length=sizeof(*s);
  }
  if(bind(fd,(void*)&source,length)||connect(fd,(void*)&destination,length))fail("icmp route");
  size_t nonce=strlen(argv[5]);if(nonce>120)return 2;
  unsigned id=(unsigned)strtoul(argv[3],0,10),seq=(unsigned)strtoul(argv[4],0,10);
  unsigned char packet[128]={0};packet[0]=family==4?8:128;
  packet[4]=id>>8;packet[5]=id;packet[6]=seq>>8;packet[7]=seq;memcpy(packet+8,argv[5],nonce);
  if(family==4){unsigned sum=checksum(packet,nonce+8);packet[2]=sum>>8;packet[3]=sum;}
  if(send(fd,packet,nonce+8,0)!=(ssize_t)(nonce+8))fail("icmp send");
  printf("icmp_endpoint uid=%u family=%d id=%u sequence=%u bytes=%zu nonce=%s\n",(unsigned)getuid(),family,id,seq,nonce+8,argv[5]);
  close(fd);return 0;
}
