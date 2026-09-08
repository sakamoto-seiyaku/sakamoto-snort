/* Controlled loopback UDP endpoint; no product packet processing. */
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  struct sockaddr_in a = {.sin_family=AF_INET, .sin_port=htons(atoi(argv[1])),
                         .sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
  if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof(a))) return 3;
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("ready port=%s\n", argv[1]);
  time_t deadline = time(NULL) + 90;
  while (time(NULL) < deadline) {
    struct pollfd p = {.fd=fd, .events=POLLIN};
    if (poll(&p, 1, 500) <= 0) continue;
    char data[2048]; struct sockaddr_in peer; socklen_t len=sizeof(peer);
    ssize_t n = recvfrom(fd, data, sizeof(data), 0, (struct sockaddr *)&peer, &len);
    if (n <= 0) break;
    ssize_t sent=sendto(fd,data,n,0,(struct sockaddr *)&peer,len);
    printf("receive peer_port=%u bytes=%zd sent=%zd payload=%.*s\n",ntohs(peer.sin_port),n,sent,(int)n,data);
  }
  close(fd); return 0;
}
