/* Own one real kernel queue to induce a partial Product startup rejection.
 * Optional copy-mode configuration supports the independent kernel close
 * probe. No received-packet parser, verdict or forwarding implementation. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 3 && (argc != 4 || strcmp(argv[3], "copy"))) return 2;
  unsigned queue = strtoul(argv[1], NULL, 10), family = strtoul(argv[2], NULL, 10);
  if (queue > 65535 || (family != 4 && family != 6)) return 2;
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
  struct sockaddr_nl local = {.nl_family = AF_NETLINK}, kernel = {.nl_family = AF_NETLINK};
  if (fd < 0 || bind(fd, (void *)&local, sizeof(local))) {perror("queue socket");return 1;}
  struct {
    struct nlmsghdr header;
    struct nfgenmsg generic;
    struct nlattr attribute;
    struct nfqnl_msg_config_cmd command;
  } request = {0};
  request.header.nlmsg_len = sizeof(request);
  request.header.nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG;
  request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  request.header.nlmsg_seq = 242;
  request.generic.res_id = htons(queue);
  request.attribute.nla_type = NFQA_CFG_CMD;
  request.attribute.nla_len = sizeof(request.attribute) + sizeof(request.command);
  request.command.command = NFQNL_CFG_CMD_BIND;
  request.command.pf = htons(family == 4 ? AF_INET : AF_INET6);
  if (sendto(fd, &request, sizeof(request), 0, (void *)&kernel, sizeof(kernel)) != (ssize_t)sizeof(request)) {
    perror("queue bind send");return 1;
  }
  unsigned char response[4096];
  ssize_t length = recv(fd, response, sizeof(response), 0);
  struct nlmsghdr *header = (void *)response;
  if (length < (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr)) || header->nlmsg_type != NLMSG_ERROR) return 1;
  struct nlmsgerr *error = NLMSG_DATA(header);
  printf("queue_bound queue=%u family=%u fd=%d pid=%ld ack=%d\n", queue, family, fd, (long)getpid(), error->error);
  fflush(stdout);
  if (error->error) return 1;
  if (argc == 4) {
    struct {
      struct nlmsghdr header;
      struct nfgenmsg generic;
      struct nlattr attribute;
      struct nfqnl_msg_config_params parameters;
      unsigned char padding[3];
    } copy = {0};
    copy.header = request.header;
    copy.header.nlmsg_len = sizeof(copy);
    copy.header.nlmsg_seq++;
    copy.generic = request.generic;
    copy.attribute.nla_type = NFQA_CFG_PARAMS;
    copy.attribute.nla_len = sizeof(copy.attribute) + sizeof(copy.parameters);
    copy.parameters.copy_range = htonl(128);
    copy.parameters.copy_mode = NFQNL_COPY_PACKET;
    if (sendto(fd, &copy, sizeof(copy), 0, (void *)&kernel, sizeof(kernel)) != (ssize_t)sizeof(copy)) return 1;
    length = recv(fd, response, sizeof(response), 0);
    if (length < (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr)) || header->nlmsg_type != NLMSG_ERROR) return 1;
    printf("queue_copy queue=%u ack=%d\n", queue, error->error);
    fflush(stdout);
    if (error->error) return 1;
  }
  for (;;) pause();
}
