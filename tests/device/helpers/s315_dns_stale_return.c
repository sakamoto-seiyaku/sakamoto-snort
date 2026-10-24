/* Controlled Root IPv6 raw-return confinement probe; no Product calls. */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static uint32_t add(uint32_t sum,const uint8_t *data,size_t length) {
  while(length>=2){sum+=(uint32_t)data[0]*256U+data[1];data+=2;length-=2;}
  if(length)sum+=(uint32_t)data[0]*256U;
  while(sum>>16)sum=(sum&65535U)+(sum>>16);
  return sum;
}
static uint16_t checksum(const uint8_t *packet) {
  uint32_t sum=0;sum=add(sum,packet+8,32);
  const uint8_t pseudo[8]={0,0,0,20,0,0,0,17};sum=add(sum,pseudo,sizeof(pseudo));
  sum=add(sum,packet+40,20);uint16_t value=(uint16_t)~sum;
  return value?value:65535U;
}
int main(int argc,char **argv) {
  if(argc!=3||getuid()!=0)return 2;
  uint8_t packet[60]={0};packet[0]=0x60;packet[4]=0;packet[5]=20;packet[6]=17;packet[7]=1;
  if(inet_pton(AF_INET6,argv[1],packet+8)!=1||inet_pton(AF_INET6,argv[2],packet+24)!=1)return 2;
  packet[40]=0;packet[41]=53;packet[42]=0x9c;packet[43]=0x3f;packet[44]=0;packet[45]=20;
  packet[48]=0x03;packet[49]=0x15;packet[50]=0x81;packet[51]=0x82;
  uint16_t check=checksum(packet);packet[46]=(uint8_t)(check>>8);packet[47]=(uint8_t)check;
  int fd=socket(AF_INET6,SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC,IPPROTO_RAW),enabled=1;
  if(fd<0||setsockopt(fd,SOL_SOCKET,SO_BINDTODEVICE,"lo",3)||
     setsockopt(fd,IPPROTO_IPV6,IPV6_HDRINCL,&enabled,sizeof(enabled))){perror("stale raw setup");return 1;}
  struct sockaddr_in6 route={.sin6_family=AF_INET6,.sin6_addr=IN6ADDR_LOOPBACK_INIT};
  errno=0;ssize_t sent=sendto(fd,packet,sizeof(packet),MSG_DONTWAIT|MSG_NOSIGNAL,(void*)&route,sizeof(route));
  int error=errno;close(fd);
  printf("{\"sent\":%zd,\"expected\":%zu,\"errno\":%d,\"hop_limit\":1}\n",sent,sizeof(packet),error);
  return sent==(ssize_t)sizeof(packet)?0:1;
}
