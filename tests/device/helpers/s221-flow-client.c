/* Independent kernel endpoint for S221; contains no Product packet logic. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <linux/capability.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static void fail(const char *what) { perror(what); exit(1); }
static unsigned checksum(const unsigned char *bytes, unsigned length) {
  unsigned sum=0;
  for(unsigned i=0;i<length;i+=2)sum+=((unsigned)bytes[i]<<8)+(i+1<length?bytes[i+1]:0);
  while(sum>>16)sum=(sum&65535)+(sum>>16);
  return (~sum)&65535;
}

int main(int argc,char **argv) {
  /* uid family tcp|udp|icmp destination local-port-or-id count nonce [timeout-ms] */
  if(argc!=8&&argc!=9)return 2;
  uid_t uid=(uid_t)strtoul(argv[1],NULL,10);
  unsigned family=(unsigned)atoi(argv[2]),number=(unsigned)atoi(argv[5]);
  unsigned count=(unsigned)atoi(argv[6]);
  unsigned timeout_ms=argc==9?(unsigned)strtoul(argv[8],NULL,10):2000;
  int tcp=!strcmp(argv[3],"tcp"),icmp=!strcmp(argv[3],"icmp");
  if((family!=4&&family!=6)||!number||number>65535||!count||count>8
     ||(!tcp&&!icmp&&strcmp(argv[3],"udp"))||strlen(argv[7])>128
     ||!timeout_ms||timeout_ms>60000)return 2;
  if(getuid()!=uid) {
    if(prctl(PR_SET_KEEPCAPS,1L,0L,0L,0L)||setgid(uid)||setuid(uid))fail("uid");
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct caps[2]={{0}};
    caps[0].effective=caps[0].permitted=icmp?1U<<CAP_NET_RAW:0;
    if(syscall(SYS_capset,&header,caps))fail("capset");
  }
  int af=family==4?AF_INET:AF_INET6;
  int fd=socket(af,icmp?SOCK_RAW:tcp?SOCK_STREAM:SOCK_DGRAM,
                icmp?(family==4?IPPROTO_ICMP:IPPROTO_ICMPV6):0);
  if(fd<0)fail("socket");
  struct timeval timeout={timeout_ms/1000,(timeout_ms%1000)*1000};int one=1;
  if(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof timeout)
     ||setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof timeout))fail("timeout");
  if(!icmp&&setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one))fail("reuseaddr");
  struct sockaddr_storage source={0},destination={0};socklen_t length;
  if(family==4) {
    struct sockaddr_in *s=(void*)&source,*d=(void*)&destination;
    s->sin_family=d->sin_family=af;s->sin_port=icmp?0:htons(number);d->sin_port=icmp?0:htons(40621);
    if(inet_pton(af,"127.0.0.1",&s->sin_addr)!=1||inet_pton(af,argv[4],&d->sin_addr)!=1)return 2;
    length=sizeof *s;
  } else {
    struct sockaddr_in6 *s=(void*)&source,*d=(void*)&destination;
    s->sin6_family=d->sin6_family=af;s->sin6_port=icmp?0:htons(number);d->sin6_port=icmp?0:htons(40621);
    if(inet_pton(af,"::1",&s->sin6_addr)!=1||inet_pton(af,argv[4],&d->sin6_addr)!=1)return 2;
    length=sizeof *s;
  }
  if(bind(fd,(void*)&source,length)||connect(fd,(void*)&destination,length))fail("route/connect");
  for(unsigned sequence=1;sequence<=count;sequence++) {
    unsigned char request[256]={0},response[1024];
    unsigned offset=icmp?8:0;
    int written=snprintf((char*)request+offset,sizeof request-offset,"%s-%u",argv[7],sequence);
    if(written<0||(unsigned)written>=sizeof request-offset)return 2;
    unsigned bytes=offset+(unsigned)written;
    if(icmp) {
      request[0]=family==4?8:128;request[4]=number>>8;request[5]=number;
      request[6]=sequence>>8;request[7]=sequence;
      if(family==4){unsigned sum=checksum(request,bytes);request[2]=sum>>8;request[3]=sum;}
    }
    if(send(fd,request,bytes,0)!=(ssize_t)bytes)fail("send");
    unsigned got=0;int matched=0;
    /* Raw sockets can also expose unrelated messages; bound that search. */
    for(unsigned tries=0;tries<32&&!matched;tries++) {
      ssize_t n=recv(fd,response+got,sizeof response-got,0);
      if(n<=0)fail("recv");
      if(tcp) {
        got+=(unsigned)n;
        if(got<bytes)continue;
        matched=got==bytes&&!memcmp(request,response,bytes);
        break;
      }
      if(!icmp){matched=(unsigned)n==bytes&&!memcmp(request,response,bytes);break;}
      unsigned ip=family==4?(response[0]&15)*4:0;
      if((unsigned)n<ip+8)continue;
      matched=response[ip]==(family==4?0:129)&&response[ip+1]==0
        &&response[ip+4]==request[4]&&response[ip+5]==request[5]
        &&response[ip+6]==request[6]&&response[ip+7]==request[7]
        &&(unsigned)n==ip+bytes&&!memcmp(response+ip+8,request+8,bytes-8);
    }
    if(!matched){fprintf(stderr,"echo mismatch\n");return 1;}
    printf("endpoint uid=%u family=%u protocol=%s number=%u sequence=%u nonce=%s-%u received=1\n",
           (unsigned)getuid(),family,argv[3],number,sequence,argv[7],sequence);
  }
  close(fd);return 0;
}
