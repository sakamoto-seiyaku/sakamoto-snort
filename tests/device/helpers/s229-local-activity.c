/* Bounded local UDP activity for native lane scheduling during diagnostics. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    unsigned uid = (unsigned) strtoul(argv[1], NULL, 10);
    if (setgid(uid) || setuid(uid) || getuid() != uid) return 3;
    int sockets[8];
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons(40638)};
    if (inet_pton(AF_INET, "127.0.0.1", &peer.sin_addr) != 1) return 4;
    for (unsigned i = 0; i < 8; ++i) {
        sockets[i] = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        if (sockets[i] < 0) return 5;
    }
    printf("activity source=KERNEL_UDP uid=%u destination=127.0.0.1..8:40638 rounds=100 sockets=8\n", uid);
    fflush(stdout);
    unsigned sent = 0;
    for (unsigned round = 0; round < 100; ++round) {
        for (unsigned i = 0; i < 8; ++i) {
            peer.sin_addr.s_addr = htonl(0x7f000001U + i);
            char payload[64];
            int n = snprintf(payload, sizeof payload, "s229-local-activity-%u-%u", round, i);
            if (sendto(sockets[i], payload, (size_t) n, 0,
                       (struct sockaddr *) &peer, sizeof peer) != n) return 6;
            ++sent;
        }
        usleep(20000);
    }
    for (unsigned i = 0; i < 8; ++i) close(sockets[i]);
    printf("activity complete sent=%u\n", sent);
    return 0;
}
