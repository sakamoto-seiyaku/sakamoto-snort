/* Bounded real shell-UID mDNS transport fixture; never a Product resolver. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int nibble(char c)
{return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:-1;}
int main(int argc,char **argv)
{
  if(argc!=3||getuid()!=2000)return 2;
  unsigned port=strtoul(argv[1],NULL,10);size_t length=strlen(argv[2]);
  if(port<1024||port>65535||length<24||length>1024||length%2)return 2;
  uint8_t query[512],reply[2048];length/=2;
  for(size_t i=0;i<length;++i){int a=nibble(argv[2][i*2]),b=nibble(argv[2][i*2+1]);if(a<0||b<0)return 2;query[i]=a*16+b;}
  int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0),error=fd<0?errno:0;
  struct sockaddr_in local={.sin_family=AF_INET,.sin_port=htons(port)},remote={.sin_family=AF_INET,.sin_port=htons(5353)};
  inet_pton(AF_INET,"224.0.0.251",&remote.sin_addr);unsigned char ttl=255;
  ssize_t received=-1;struct sockaddr_in sender;socklen_t sender_length=sizeof(sender);
  if(!error&&setsockopt(fd,IPPROTO_IP,IP_MULTICAST_TTL,&ttl,sizeof(ttl)))error=errno;
  if(!error&&bind(fd,(void *)&local,sizeof(local)))error=errno;
  struct timespec started,finished;clock_gettime(CLOCK_MONOTONIC,&started);
  if(!error&&sendto(fd,query,length,0,(void *)&remote,sizeof(remote))!=(ssize_t)length)error=errno;
  if(!error){struct pollfd ready={.fd=fd,.events=POLLIN};int available=poll(&ready,1,3000);
    if(available==1)received=recvfrom(fd,reply,sizeof(reply),0,(void *)&sender,&sender_length);
    else error=available==0?ETIMEDOUT:errno;}
  clock_gettime(CLOCK_MONOTONIC,&finished);if(fd>=0)close(fd);
  printf("{\"uid\":%u,\"source_port\":%u,\"destination\":\"224.0.0.251\",\"destination_port\":5353,\"error\":%d,\"started_mono_ns\":%llu,\"completed_mono_ns\":%llu,\"query_hex\":\"",
    (unsigned)getuid(),port,error,(unsigned long long)started.tv_sec*1000000000ULL+started.tv_nsec,
    (unsigned long long)finished.tv_sec*1000000000ULL+finished.tv_nsec);
  for(size_t i=0;i<length;++i)printf("%02x",query[i]);printf("\",\"reply_hex\":\"");
  if(received>0)for(ssize_t i=0;i<received;++i)printf("%02x",reply[i]);printf("\"}\n");
  return error?1:0;
}
