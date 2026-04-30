#pragma once

#include <stdint.h>
#include <sys/socket.h>
#include <linux/netfilter/nfnetlink_queue.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nlattr;
struct nlmsghdr;

void nfq_nlmsg_cfg_put_cmd(struct nlmsghdr *nlh, uint16_t pf, uint8_t cmd);
void nfq_nlmsg_cfg_put_params(struct nlmsghdr *nlh, uint8_t mode, int range);
void nfq_nlmsg_cfg_put_qmaxlen(struct nlmsghdr *nlh, uint32_t qmaxlen);

void nfq_nlmsg_verdict_put(struct nlmsghdr *nlh, int id, int verdict);
void nfq_nlmsg_verdict_put_mark(struct nlmsghdr *nlh, uint32_t mark);
void nfq_nlmsg_verdict_put_pkt(struct nlmsghdr *nlh, const void *pkt, uint32_t pktlen);

int nfq_nlmsg_parse(const struct nlmsghdr *nlh, struct nlattr **attr);
struct nlmsghdr *nfq_nlmsg_put(char *buf, int type, uint32_t queue_num);

#ifdef __cplusplus
}
#endif
