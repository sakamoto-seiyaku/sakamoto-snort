/* Bounded real shell-UID multicast client with an explicit network scope. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int nibble(char c)
{return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:-1;}
static uint64_t now(void)
{struct timespec value;if(clock_gettime(CLOCK_MONOTONIC,&value))_exit(3);return(uint64_t)value.tv_sec*1000000000+value.tv_nsec;}
int main(int argc,char **argv)
{
  if(argc!=5||getuid()!=2000)return 2;
  unsigned family=strtoul(argv[1],NULL,10),port=strtoul(argv[2],NULL,10);
  if((family!=4&&family!=6)||port<1024||port>65535)return 2;
  unsigned interface=strcmp(argv[3],"-")?if_nametoindex(argv[3]):0;
  if(strcmp(argv[3],"-")&&(!interface||(strncmp(argv[3],"wlan",4)&&strncmp(argv[3],"tun",3))))return 2;
  size_t length=strlen(argv[4]);if(length<24||length>1024||length%2)return 2;length/=2;
  uint8_t query[512],reply[2048];
  for(size_t i=0;i<length;++i){int a=nibble(argv[4][i*2]),b=nibble(argv[4][i*2+1]);if(a<0||b<0)return 2;query[i]=a*16+b;}
  alarm(6);int fd=socket(family==4?AF_INET:AF_INET6,SOCK_DGRAM|SOCK_CLOEXEC,0),error=fd<0?errno:0;
  int reuse=1,hops=255;
  struct sockaddr_storage remote={0},local={0},sender={0};socklen_t size,sender_size=sizeof(sender);
  const char *destination=family==4?"224.0.0.251":"ff02::fb";
  if(!error&&setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse)))error=errno;
  if(family==4){
    struct sockaddr_in *to=(void *)&remote,*from=(void *)&local;
    to->sin_family=from->sin_family=AF_INET;to->sin_port=htons(5353);from->sin_port=htons(port);
    inet_pton(AF_INET,destination,&to->sin_addr);size=sizeof(*to);
    unsigned char ttl=255;struct ip_mreqn membership={.imr_multiaddr=to->sin_addr,.imr_ifindex=(int)interface};
    if(!error&&setsockopt(fd,IPPROTO_IP,IP_MULTICAST_TTL,&ttl,sizeof(ttl)))error=errno;
    if(!error&&interface&&setsockopt(fd,IPPROTO_IP,IP_MULTICAST_IF,&membership,sizeof(membership)))error=errno;
    if(!error&&bind(fd,(void *)&local,size))error=errno;
    if(!error&&port==5353&&setsockopt(fd,IPPROTO_IP,IP_ADD_MEMBERSHIP,&membership,sizeof(membership)))error=errno;
  }else{
    struct sockaddr_in6 *to=(void *)&remote,*from=(void *)&local;
    to->sin6_family=from->sin6_family=AF_INET6;to->sin6_port=htons(5353);from->sin6_port=htons(port);to->sin6_scope_id=interface;
    inet_pton(AF_INET6,destination,&to->sin6_addr);size=sizeof(*to);
    struct ipv6_mreq membership={.ipv6mr_multiaddr=to->sin6_addr,.ipv6mr_interface=interface};
    if(!error&&setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&reuse,sizeof(reuse)))error=errno;
    if(!error&&setsockopt(fd,IPPROTO_IPV6,IPV6_MULTICAST_HOPS,&hops,sizeof(hops)))error=errno;
    if(!error&&interface&&setsockopt(fd,IPPROTO_IPV6,IPV6_MULTICAST_IF,&interface,sizeof(interface)))error=errno;
    if(!error&&bind(fd,(void *)&local,size))error=errno;
    if(!error&&port==5353&&setsockopt(fd,IPPROTO_IPV6,IPV6_JOIN_GROUP,&membership,sizeof(membership)))error=errno;
  }
  uint64_t started=now(),deadline=started+3000000000ULL;ssize_t received=-1;unsigned ignored=0;
  if(!error&&sendto(fd,query,length,0,(void *)&remote,size)!=(ssize_t)length)error=errno;
  while(!error){
    uint64_t current=now();if(current>=deadline)break;
    struct pollfd ready={.fd=fd,.events=POLLIN};int timeout=(int)((deadline-current+999999)/1000000);
    int available=poll(&ready,1,timeout>0?timeout:1);
    if(available<0){if(errno==EINTR)continue;error=errno;break;}
    if(!available)break;
    sender_size=sizeof(sender);received=recvfrom(fd,reply,sizeof(reply),0,(void *)&sender,&sender_size);
    if(received>=12&&reply[0]==query[0]&&reply[1]==query[1]&&(reply[2]&0x80))break;
    received=-1;if(++ignored==128){error=EOVERFLOW;break;}
  }
  if(!error&&received<0)error=ETIMEDOUT;
  uint64_t completed=now();if(fd>=0)close(fd);
  printf("{\"uid\":%u,\"family\":%u,\"source_port\":%u,\"interface\":\"%s\",\"interface_index\":%u,\"destination\":\"%s\",\"destination_port\":5353,\"error\":%d,\"ignored\":%u,\"started_mono_ns\":%llu,\"completed_mono_ns\":%llu,\"query_hex\":\"",
    (unsigned)getuid(),family,port,argv[3],interface,destination,error,ignored,(unsigned long long)started,(unsigned long long)completed);
  for(size_t i=0;i<length;++i)printf("%02x",query[i]);printf("\",\"reply_hex\":\"");
  if(received>0)for(ssize_t i=0;i<received;++i)printf("%02x",reply[i]);printf("\"}\n");
  return error?1:0;
}
