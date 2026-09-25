/* SPDX-License-Identifier: Apache-2.0
 * Independent test TCP sender. Real kernel endpoint receives every accepted
 * stream. Deliberate segment ordering/duplication is external to Product. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/capability.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int fd;
static uint32_t local_address,remote_address,base=UINT32_MAX-100,acknowledgement;
static uint16_t local_port,remote_port=40641;
static uint64_t now_ms(void) {
  struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))exit(2);
  return (uint64_t)t.tv_sec*1000+(unsigned)t.tv_nsec/1000000;
}
static void fail(const char *message) {perror(message);exit(1);}
static void word(unsigned char *p,unsigned v) {p[0]=(unsigned char)(v>>8);p[1]=(unsigned char)v;}
static void dword(unsigned char *p,uint32_t v) {word(p,v>>16);word(p+2,v);}
static unsigned read_word(const unsigned char *p) {return (unsigned)p[0]*256+p[1];}
static uint32_t read_dword(const unsigned char *p) {return (uint32_t)read_word(p)*65536+read_word(p+2);}
static unsigned checksum(const unsigned char *p,unsigned n) {
  unsigned sum=0;for(unsigned i=0;i<n;i+=2)sum+=(unsigned)p[i]*256+(i+1<n?p[i+1]:0);
  while(sum>>16)sum=(sum&65535)+(sum>>16);
  return (~sum)&65535;
}
static void send_segment(uint32_t sequence,unsigned flags,const unsigned char *data,unsigned length) {
  unsigned char packet[1600]={0},pseudo[1600]={0};
  if(length>1400) {errno=EINVAL;fail("segment size");}
  packet[0]=0x45;word(packet+2,40+length);packet[8]=64;packet[9]=6;
  memcpy(packet+12,&local_address,4);memcpy(packet+16,&remote_address,4);
  word(packet+20,local_port);word(packet+22,remote_port);
  dword(packet+24,sequence);dword(packet+28,acknowledgement);
  packet[32]=0x50;packet[33]=(unsigned char)flags;word(packet+34,65535);
  if(length)memcpy(packet+40,data,length);
  memcpy(pseudo,packet+12,8);pseudo[9]=6;word(pseudo+10,20+length);
  memcpy(pseudo+12,packet+20,20+length);word(packet+36,checksum(pseudo,32+length));
  word(packet+10,checksum(packet,20));
  struct sockaddr_in destination={.sin_family=AF_INET,.sin_addr.s_addr=remote_address};
  if(sendto(fd,packet,40+length,0,(void *)&destination,sizeof destination)!=(ssize_t)(40+length))fail("sendto");
  printf("{\"kind\":\"sent\",\"ms\":%llu,\"sequence\":%u,\"flags\":%u,\"length\":%u}\n",
    (unsigned long long)now_ms(),sequence,flags,length);fflush(stdout);
}
static void receive(unsigned handshake,uint32_t end_sequence) {
  uint64_t deadline=now_ms()+10000;
  while(now_ms()<deadline) {
    struct pollfd wait={.fd=fd,.events=POLLIN};if(poll(&wait,1,100)<0)fail("poll");
    if(!(wait.revents&POLLIN))continue;
    unsigned char packet[65536];ssize_t n=recv(fd,packet,sizeof packet,0);if(n<0)fail("recv");
    if(n<40 || packet[9]!=6 || memcmp(packet+12,&remote_address,4)
       || memcmp(packet+16,&local_address,4))continue;
    unsigned ip=(packet[0]&15)*4;if(ip<20 || (unsigned)n<ip+20)continue;
    const unsigned char *tcp=packet+ip;
    if(read_word(tcp)!=remote_port || read_word(tcp+2)!=local_port)continue;
    unsigned header=(tcp[12]>>4)*4,total=read_word(packet+2);
    if(header<20 || total<ip+header || total>(unsigned)n)continue;
    if(tcp[13]&4) {errno=ECONNRESET;fail("endpoint RST");}
    if(handshake && (tcp[13]&18)==18 && read_dword(tcp+8)==base) {
      acknowledgement=read_dword(tcp+4)+1;send_segment(base,16,NULL,0);return;
    }
    if(!handshake && total>ip+header && tcp[header]=='A') {
      acknowledgement=read_dword(tcp+4)+(total-ip-header);
      send_segment(end_sequence,16,NULL,0);
      puts("{\"kind\":\"endpoint_receipt\",\"value\":65}");fflush(stdout);return;
    }
  }
  errno=ETIMEDOUT;fail(handshake?"SYNACK deadline":"endpoint receipt deadline");
}
static void gate(const char *path,const char *phase) {
  char name[1024];if(snprintf(name,sizeof name,"%s.%s",path,phase)>=(int)sizeof name)exit(2);
  FILE *f=fopen(name,"w");if(!f)fail("gate report");fprintf(f,"%llu\n",(unsigned long long)now_ms());fclose(f);
  printf("{\"kind\":\"%s\",\"ms\":%llu}\n",phase,(unsigned long long)now_ms());fflush(stdout);
  if(snprintf(name,sizeof name,"%s.release-%s",path,phase)>=(int)sizeof name)exit(2);
  uint64_t deadline=now_ms()+30000;
  while(access(name,F_OK)) {if(now_ms()>deadline){errno=ETIMEDOUT;fail("gate deadline");}usleep(10000);}
}
static void send_bytes(const unsigned char *wire,unsigned first,unsigned last) {
  while(first<last) {unsigned n=last-first;if(n>1300)n=1300;send_segment(base+first,24,wire+first,n);first+=n;usleep(20000);}
}
int main(int argc,char **argv) {
  if(argc!=7)return 2;
  uid_t uid=(uid_t)strtoul(argv[1],NULL,10);local_port=(uint16_t)strtoul(argv[3],NULL,10);
  if(local_port<1024 || inet_pton(AF_INET,argv[2],&remote_address)!=1)return 2;
  unsigned char wire[4097];FILE *input=fopen(argv[5],"rb");if(!input)fail("fixture");
  unsigned size=(unsigned)fread(wire,1,sizeof wire,input);fclose(input);if(size<50)return 2;
  if(prctl(PR_SET_KEEPCAPS,1,0,0,0)||setgid(uid)||setuid(uid))fail("test uid");
  struct __user_cap_header_struct h={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};
  struct __user_cap_data_struct caps[2]={{.effective=1U<<CAP_NET_RAW,.permitted=1U<<CAP_NET_RAW},{0}};
  if(syscall(SYS_capset,&h,caps))fail("CAP_NET_RAW");
  int route=socket(AF_INET,SOCK_DGRAM,0);if(route<0)fail("route socket");
  struct sockaddr_in remote={.sin_family=AF_INET,.sin_port=htons(remote_port),.sin_addr.s_addr=remote_address};
  if(connect(route,(void *)&remote,sizeof remote))fail("route connect");
  struct sockaddr_in local;socklen_t address_size=sizeof local;
  if(getsockname(route,(void *)&local,&address_size))fail("route address");
  local_address=local.sin_addr.s_addr;close(route);
  fd=socket(AF_INET,SOCK_RAW,IPPROTO_TCP);if(fd<0)fail("raw TCP socket");int yes=1;
  if(setsockopt(fd,IPPROTO_IP,IP_HDRINCL,&yes,sizeof yes))fail("IP_HDRINCL");
  send_segment(base-1,2,NULL,0);receive(1,0);
  const char *mode=argv[4];
  if(!strcmp(mode,"reorder")) {
    send_bytes(wire,20,40);send_bytes(wire,20,40);send_bytes(wire,40,size);
    gate(argv[6],"prefix_ready");send_bytes(wire,0,20);
  } else if(!strcmp(mode,"sparse")) {
    for(unsigned i=0;i<16;++i)send_segment(base+1+2*i,24,wire+1+2*i,1);
    gate(argv[6],"prefix_ready");send_segment(base+33,24,wire+33,1);send_bytes(wire,0,size);
  } else if(!strcmp(mode,"span")) {
    send_bytes(wire,0,20);gate(argv[6],"prefix_ready");
    send_segment(base+4096,24,wire,1);send_bytes(wire,20,size);
  } else if(!strcmp(mode,"bytes")) {
    if(size!=4096)return 2;
    send_bytes(wire,0,4090);
    gate(argv[6],"prefix_ready");send_bytes(wire,4090,size);
  } else if(!strcmp(mode,"packets")) {
    for(unsigned i=0;i<19;++i)send_segment(base+20,24,wire+20,1);
    gate(argv[6],"prefix_ready");send_segment(base+20,24,wire+20,1);send_bytes(wire,0,size);
  } else return 2;
  receive(0,base+size);gate(argv[6],"complete");send_segment(base+size,17,NULL,0);close(fd);return 0;
}
