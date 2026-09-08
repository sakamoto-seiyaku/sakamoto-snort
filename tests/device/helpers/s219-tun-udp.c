/* Real kernel UDP fragmentation under the scoped VPN app UID; no graph/TUN writer. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
static void fail(const char *s){perror(s);exit(1);}
int main(int argc,char **argv){
 if(argc!=5)return 2;
 unsigned uid=(unsigned)strtoul(argv[1],0,10),family=(unsigned)strtoul(argv[2],0,10),port=(unsigned)strtoul(argv[3],0,10);
 const char *nonce=argv[4];size_t nonce_length=strlen(nonce);
 if((family!=4&&family!=6)||port<1024||port>65535||nonce_length>120)return 2;
 if(setgid(uid)||setuid(uid)||getuid()!=uid)fail("test endpoint UID");
 int fd=socket(family==4?AF_INET:AF_INET6,SOCK_DGRAM,0),discovery=IP_PMTUDISC_DONT;
 if(fd<0)fail("socket");
 if(setsockopt(fd,family==4?IPPROTO_IP:IPPROTO_IPV6,family==4?IP_MTU_DISCOVER:IPV6_MTU_DISCOVER,&discovery,sizeof discovery))fail("allow kernel fragmentation");
 struct timeval timeout={0,400000};if(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof timeout))fail("timeout");
 struct sockaddr_storage src={0},dst={0};socklen_t size;
 if(family==4){
  struct sockaddr_in *s=(void*)&src,*d=(void*)&dst;s->sin_family=d->sin_family=AF_INET;s->sin_port=htons(port);d->sin_port=htons(40633);
  inet_pton(AF_INET,"10.111.0.2",&s->sin_addr);inet_pton(AF_INET,"198.18.213.1",&d->sin_addr);size=sizeof *s;
 }else{
  struct sockaddr_in6 *s=(void*)&src,*d=(void*)&dst;s->sin6_family=d->sin6_family=AF_INET6;s->sin6_port=htons(port);d->sin6_port=htons(40633);
  inet_pton(AF_INET6,"fd00:111:111::2",&s->sin6_addr);inet_pton(AF_INET6,"fd00:198::1",&d->sin6_addr);size=sizeof *s;
 }
 if(bind(fd,(void*)&src,size)||connect(fd,(void*)&dst,size))fail("bind/connect");
 unsigned char payload[1800];for(unsigned i=0;i<sizeof payload;i++)payload[i]=(unsigned char)(i%251);memcpy(payload,nonce,nonce_length);
 if(send(fd,payload,sizeof payload,0)!=sizeof payload)fail("kernel UDP send");
 unsigned char reply[256];ssize_t received=recv(fd,reply,sizeof reply,0);int error=errno;close(fd);
 if(received>=0||(error!=EAGAIN&&error!=EWOULDBLOCK)){errno=error;fail("expected DROP timeout");}
 printf("probe uid=%u family=%u source_port=%u destination_port=40633 bytes=1800 outcome=timeout source=KERNEL_UDP nonce=%s\n",getuid(),family,port,nonce);return 0;
}
