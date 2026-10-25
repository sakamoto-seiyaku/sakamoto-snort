/* Read-only bounded wlan0/lo DNS wire witness. No Product calls or injection. */
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static unsigned u16 (const unsigned char *p) { return p[0] * 256U + p[1]; }
int main (int argc, char **argv) {
  if (argc < 5 || argc > 9 || getuid () != 0 ||
      (strcmp (argv[1], "wlan0") && strcmp (argv[1], "lo") &&
       (strncmp (argv[1], "tun", 3) || !argv[1][3] || strspn (argv[1] + 3, "0123456789") != strlen (argv[1] + 3))) ||
      strncmp (argv[2], "/data/local/tmp/s317-wire-", 26)) return 2;
  unsigned char addresses[6][16] = {{0}}; int families[6];
  for (int i = 3; i < argc; ++i) {
    families[i-3] = strchr (argv[i], ':') ? AF_INET6 : AF_INET;
    if (inet_pton (families[i-3], argv[i], addresses[i-3]) != 1) return 2;
  }
  int fd = socket (AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons (ETH_P_ALL));
  struct sockaddr_ll link = {.sll_family=AF_PACKET,.sll_protocol=htons(ETH_P_ALL),
    .sll_ifindex=(int)if_nametoindex(argv[1])};
  if (fd < 0 || !link.sll_ifindex || bind (fd, (void *)&link, sizeof(link))) { perror("wire bind");return 1; }
  setvbuf (stdout, NULL, _IOLBF, 0);
  printf ("{\"kind\":\"ready\",\"interface\":\"%s\"}\n", argv[1]);
  struct timespec began, now; if (clock_gettime(CLOCK_MONOTONIC,&began)) return 1;
  unsigned matched=0;size_t retained=0;const char *reason="requested";
  while (access(argv[2],F_OK)) {
    if (clock_gettime(CLOCK_MONOTONIC,&now)) {perror("wire clock");return 1;}
    if (now.tv_sec-began.tv_sec>=1200) {reason="deadline";break;}
    struct pollfd pending={.fd=fd,.events=POLLIN};int ready=poll(&pending,1,200);
    if (ready<0&&errno==EINTR)continue;
    if(ready<0){perror("wire poll");return 1;}if(!ready)continue;
    unsigned char packet[65536];struct sockaddr_ll from={0};socklen_t from_size=sizeof(from);
    ssize_t count=recvfrom(fd,packet,sizeof(packet),0,(void*)&from,&from_size);
    if(count<0){if(errno==EINTR)continue;perror("wire recv");return 1;}
    if(clock_gettime(CLOCK_MONOTONIC,&now)){perror("wire received clock");return 1;}
    size_t size=(size_t)count,header,total;unsigned protocol,family,fragmented=0;
    const unsigned char *source,*destination;
    if(size>=20&&(packet[0]>>4)==4){
      family=AF_INET;header=(packet[0]&15U)*4U;total=u16(packet+2);protocol=packet[9];
      unsigned fragment=u16(packet+6);
      if(header<20||(fragment&0x1fff)||total<header+8||total>size)continue;
      fragmented=!!(fragment&0x2000);
      source=packet+12;destination=packet+16;
    }else if(size>=48&&(packet[0]>>4)==6){
      family=AF_INET6;header=40;total=40U+u16(packet+4);protocol=packet[6];
      if(total<48||total>size)continue;
      source=packet+8;destination=packet+24;
    }else continue;
    if(protocol!=6&&protocol!=17)continue;
    unsigned sport=u16(packet+header),dport=u16(packet+header+2);
    if(sport!=53&&dport!=53&&sport!=53053&&dport!=53053&&
       !(sport>=15353&&sport<15415)&&!(dport>=15353&&dport<15415))continue;
    unsigned selected=0;
    for(int i=3;i<argc;++i)if(families[i-3]==(int)family&&
      (!memcmp(source,addresses[i-3],family==AF_INET?4:16)||!memcmp(destination,addresses[i-3],family==AF_INET?4:16)))selected=1;
    if(!selected)continue;
    if(protocol==6&&total<header+20)continue;
    size_t transport=protocol==17?8:(packet[header+12]>>4)*4U;
    if(protocol==6&&(transport<20||transport>total-header))continue;
    unsigned udp_length=protocol==17?u16(packet+header+4):0;
    if(protocol==17&&(udp_length<8||(!fragmented&&udp_length>total-header)))continue;
    size_t payload=protocol==17?(fragmented?total-header-8:udp_length-8):total-header-transport;
    if(payload>16*1024*1024-retained){reason="byte_bound";break;}
    if(matched==1024){reason="packet_bound";break;}retained+=payload;++matched;
    char src[INET6_ADDRSTRLEN],dst[INET6_ADDRSTRLEN];
    if(!inet_ntop(family,source,src,sizeof(src))||!inet_ntop(family,destination,dst,sizeof(dst)))return 1;
    printf("{\"kind\":\"%s\",\"interface\":\"%s\",\"source\":\"%s\",\"destination\":\"%s\",\"source_port\":%u,\"destination_port\":%u,\"packet_type\":%u,\"payload_hex\":\"",
      protocol==17?(fragmented?"udp_fragment_first":"udp"):"tcp",argv[1],src,dst,sport,dport,from.sll_pkttype);
    for(size_t i=0;i<payload;++i)printf("%02x",packet[header+transport+i]);
    printf("\",\"packet_hex\":\"");for(size_t i=0;i<total;++i)printf("%02x",packet[i]);
    printf("\",\"mono_ns\":%llu,\"timestamp_scope\":\"userspace_after_recv\"",(unsigned long long)now.tv_sec*1000000000+(unsigned long long)now.tv_nsec);
    if(protocol==6)printf(",\"sequence\":%u,\"flags\":%u",((unsigned)packet[header+4]<<24)|((unsigned)packet[header+5]<<16)|((unsigned)packet[header+6]<<8)|packet[header+7],packet[header+13]);
    else printf(",\"udp_length\":%u,\"fragmented\":%s",udp_length,fragmented?"true":"false");
    puts("}");
  }
  struct {unsigned packets,dropped;} stats={0};socklen_t stats_size=sizeof(stats);
  int stats_ok=!getsockopt(fd,SOL_PACKET,PACKET_STATISTICS,&stats,&stats_size)&&stats_size==sizeof(stats);
  close(fd);printf("{\"kind\":\"stopped\",\"reason\":\"%s\",\"matched\":%u,\"payload_bytes\":%zu,\"stats_ok\":%s,\"socket_packets\":%u,\"socket_drops\":%u}\n",
    reason,matched,retained,stats_ok?"true":"false",stats.packets,stats.dropped);return 0;
}
