/* Independent test endpoint; no packet-domain implementation. */
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
  struct pollfd fds[32]; int count=0;
  setvbuf(stdout, NULL, _IOLBF, 0);
  if(argc<3 || argc>34) return 2;
  int port=atoi(argv[1]);
  for(int i=2;i<argc;i++) {
    int family=strchr(argv[i], ':') ? AF_INET6 : AF_INET;
    int fd=socket(family, SOCK_DGRAM, 0), one=1;
    if(fd<0) {perror("socket"); return 3;}
    setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_storage ss={0}; socklen_t len;
    if(family==AF_INET6) {
      setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&one,sizeof one);
      struct sockaddr_in6 *a=(void*)&ss; a->sin6_family=family;
      a->sin6_port=htons(port);inet_pton(family,argv[i],&a->sin6_addr);len=sizeof *a;
    } else {
      struct sockaddr_in *a=(void*)&ss;a->sin_family=family;
      a->sin_port=htons(port);inet_pton(family,argv[i],&a->sin_addr);len=sizeof *a;
    }
    if(bind(fd,(void*)&ss,len)<0) {perror("bind");return 4;}
    fds[count++]=(struct pollfd){fd,POLLIN,0};
    printf("listen address=%s port=%d fd=%d\n",argv[i],port,fd);
  }
  while(poll(fds,count,-1)>0) for(int i=0;i<count;i++) if(fds[i].revents&POLLIN) {
    char b[2048];struct sockaddr_storage peer; socklen_t len=sizeof peer;
    ssize_t n=recvfrom(fds[i].fd,b,sizeof b,0,(void*)&peer,&len);
    if(n<0)return 5;
    ssize_t sent=sendto(fds[i].fd,b,n,0,(void*)&peer,len);
    printf("echo address=%s bytes=%zd sent=%zd nonce=%.*s\n",argv[i+2],n,sent,(int)n,b);
  }
  return 0;
}
