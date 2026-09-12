/* Independent kernel TCP endpoints and bounded raw TCP fault injector.
 * No Product parser, owner selector or tracker implementation is linked. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static void fail(const char *name) {perror(name);exit(1);}
static uint64_t milliseconds(void) {struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))fail("clock");return t.tv_sec*1000ULL+t.tv_nsec/1000000;}
static void put16(unsigned char *p,unsigned value) {p[0]=value>>8;p[1]=value;}
static void put32(unsigned char *p,uint32_t value) {p[0]=value>>24;p[1]=value>>16;p[2]=value>>8;p[3]=value;}
static unsigned sum(const unsigned char *p,unsigned length,unsigned total) {
 for(unsigned i=0;i<length;i+=2)total+=((unsigned)p[i]<<8)+(i+1<length?p[i+1]:0);
 return total;
}
static unsigned finish(unsigned total) {while(total>>16)total=(total&65535)+(total>>16);return (~total)&65535;}
static socklen_t address(struct sockaddr_storage *storage,unsigned family,const char *text,unsigned port) {
 memset(storage,0,sizeof *storage);
 if(family==4) {struct sockaddr_in *a=(void*)storage;a->sin_family=AF_INET;a->sin_port=htons(port);
  if(inet_pton(AF_INET,text,&a->sin_addr)!=1)exit(2);
  return sizeof *a;}
 struct sockaddr_in6 *a=(void*)storage;a->sin6_family=AF_INET6;a->sin6_port=htons(port);
 if(inet_pton(AF_INET6,text,&a->sin6_addr)!=1)exit(2);
 return sizeof *a;
}
static void server(int argc,char **argv) {
 struct pollfd fds[64];unsigned family[64],count=0;
 for(int i=3;i<argc;++i) {
  unsigned version=strchr(argv[i],':')?6:4;int fd=socket(version==4?AF_INET:AF_INET6,SOCK_STREAM,0),one=1;
  if(fd<0)fail("server socket");
  if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one))fail("reuseaddr");
  if(version==6&&setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&one,sizeof one))fail("v6only");
  struct sockaddr_storage a;socklen_t length=address(&a,version,argv[i],atoi(argv[2]));
  if(bind(fd,(void*)&a,length)||listen(fd,16))fail("listen");
  fds[count]=(struct pollfd){fd,POLLIN,0};family[count++]=version;
  printf("listen family=%u address=%s port=%s fd=%d\n",version,argv[i],argv[2],fd);
 }
 unsigned listeners=count;
 for(;;) {
  if(poll(fds,count,-1)<0) {if(errno==EINTR)continue;fail("poll");}
  for(unsigned i=0;i<count;++i) if(fds[i].revents&(POLLIN|POLLHUP|POLLERR)) {
   if(i<listeners) {int fd=accept(fds[i].fd,NULL,NULL);if(fd<0)fail("accept");
    if(count==64) {close(fd);continue;}
    fds[count]=(struct pollfd){fd,POLLIN,0};family[count++]=family[i];continue;}
   unsigned char bytes[2048];ssize_t n=recv(fds[i].fd,bytes,sizeof bytes,0);
   if(n<=0) {if(n<0&&errno!=ECONNRESET)fail("server recv");
    printf("close family=%u fd=%d reset=%u\n",family[i],fds[i].fd,n<0);
    close(fds[i].fd);--count;fds[i]=fds[count];family[i]=family[count];--i;continue;}
   size_t written=0;while(written<(size_t)n) {ssize_t r=send(fds[i].fd,bytes+written,n-written,MSG_NOSIGNAL);
    if(r<0&&errno==EINTR)continue;
    if(r<=0)fail("server send");
    written+=r;}
   printf("echo family=%u fd=%d bytes=%zd data=",family[i],fds[i].fd,n);
   for(ssize_t k=0;k<n;++k)printf("%02x",bytes[k]);
   putchar('\n');
  }
 }
}
static void client(char **argv) {
 unsigned family=atoi(argv[2]),sport=atoi(argv[4]),dport=atoi(argv[6]);
 int fd=socket(family==4?AF_INET:AF_INET6,SOCK_STREAM,0),one=1;
 if(fd<0)fail("client socket");
 struct timeval timeout={10,0};
 if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one)
    ||setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof timeout)
    ||setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof timeout))fail("client options");
 struct sockaddr_storage src,dst;socklen_t n=address(&src,family,argv[3],sport);
 address(&dst,family,argv[5],dport);
 if(bind(fd,(void*)&src,n))fail("client bind");
 if(connect(fd,(void*)&dst,n)) {
  if(!strcmp(argv[7],"refused")&&errno==ECONNREFUSED) {printf("refused family=%u source=%u nonce=%s\n",family,sport,argv[8]);close(fd);return;}
  fail("connect");
 }
 if(!strcmp(argv[7],"refused")) {fprintf(stderr,"unexpected accepted connect\n");exit(1);}
 printf("connected family=%u source=%u destination=%u nonce=%s mono_ms=%llu\n",family,sport,dport,argv[8],(unsigned long long)milliseconds());
 if(strcmp(argv[9],"-")) {
  uint64_t deadline=milliseconds()+20000;
  while(access(argv[9],F_OK)) {if(errno!=ENOENT)fail("gate");if(milliseconds()>=deadline) {fprintf(stderr,"gate deadline\n");exit(1);}usleep(10000);}
 }
 for(unsigned i=0;i<3;++i) {
  unsigned char request[256],reply[256];int length=snprintf((char*)request,sizeof request,"%s:%u",argv[8],i);
  size_t sent=0,got=0;
  while(sent<(size_t)length) {ssize_t r=send(fd,request+sent,length-sent,MSG_NOSIGNAL);if(r<0&&errno==EINTR)continue;if(r<=0)fail("send");sent+=r;}
  while(got<(size_t)length) {ssize_t r=recv(fd,reply+got,length-got,0);if(r<0&&errno==EINTR)continue;if(r<=0)fail("recv");got+=r;}
  if(memcmp(request,reply,length)) {fprintf(stderr,"echo mismatch\n");exit(1);}
  printf("received family=%u source=%u nonce=%s:%u bytes=%d\n",family,sport,argv[8],i,length);
 }
 if(!strcmp(argv[7],"rst")) {struct linger linger={1,0};if(setsockopt(fd,SOL_SOCKET,SO_LINGER,&linger,sizeof linger))fail("linger");}
 close(fd);printf("client_closed source=%u mode=%s\n",sport,argv[7]);
}
static void raw(char **argv) {
 unsigned family=atoi(argv[2]),length=atoi(argv[11]),ip=family==4?20:40;
 if(length>256)exit(2);
 unsigned char bytes[316]={0},*tcp=bytes+ip;
 if(family==4) {bytes[0]=0x45;put16(bytes+2,ip+20+length);put16(bytes+4,222);bytes[8]=64;bytes[9]=6;
  if(inet_pton(AF_INET,argv[3],bytes+12)!=1||inet_pton(AF_INET,argv[5],bytes+16)!=1)exit(2);
  put16(bytes+10,finish(sum(bytes,20,0)));
 } else {bytes[0]=0x60;put16(bytes+4,20+length);bytes[6]=6;bytes[7]=64;
  if(inet_pton(AF_INET6,argv[3],bytes+8)!=1||inet_pton(AF_INET6,argv[5],bytes+24)!=1)exit(2);}
 put16(tcp,atoi(argv[4]));put16(tcp+2,atoi(argv[6]));put32(tcp+4,strtoul(argv[8],NULL,0));
 put32(tcp+8,strtoul(argv[9],NULL,0));tcp[12]=0x50;tcp[13]=strtoul(argv[7],NULL,0);put16(tcp+14,atoi(argv[10]));
 for(unsigned i=0;i<length;++i)tcp[20+i]='X';
 unsigned pseudo=sum(bytes+(family==4?12:8),family==4?8:32,6+20+length);
 put16(tcp+16,finish(sum(tcp,20+length,pseudo)));
 int fd=socket(family==4?AF_INET:AF_INET6,SOCK_RAW,IPPROTO_RAW),one=1;
 if(fd<0)fail("raw socket");
 if(setsockopt(fd,family==4?IPPROTO_IP:IPPROTO_IPV6,family==4?IP_HDRINCL:IPV6_HDRINCL,&one,sizeof one))fail("headerincl");
 struct sockaddr_storage dst;socklen_t n=address(&dst,family,argv[5],0);
 if(sendto(fd,bytes,ip+20+length,0,(void*)&dst,n)!=(ssize_t)(ip+20+length))fail("raw send");
 printf("raw family=%u source=%s destination=%s flags=%s seq=%s ack=%s payload=%u\n",family,argv[4],argv[6],argv[7],argv[8],argv[9],length);
 close(fd);
}
int main(int argc,char **argv) {
 setvbuf(stdout,NULL,_IOLBF,0);
 if(argc>=7&&(!strcmp(argv[1],"client")||!strcmp(argv[1],"raw"))) {
  if((atoi(argv[2])!=4&&atoi(argv[2])!=6)||atoi(argv[4])<1||atoi(argv[4])>65535
     ||atoi(argv[6])<1||atoi(argv[6])>65535)return 2;
 }
 if(argc==10&&!strcmp(argv[1],"client") && (strlen(argv[8])>128 ||
    (strcmp(argv[7],"fin")&&strcmp(argv[7],"rst")&&strcmp(argv[7],"refused"))))return 2;
 if(argc>=4&&argc<=8&&!strcmp(argv[1],"server")) {server(argc,argv);return 0;}
 if(argc==10&&!strcmp(argv[1],"client")) {client(argv);return 0;}
 if(argc==12&&!strcmp(argv[1],"raw")) {raw(argv);return 0;}
 fprintf(stderr,"server port addresses... | client family src port dst port fin|rst|refused nonce gate|- | raw family src port dst port flags seq ack win payload\n");return 2;
}
