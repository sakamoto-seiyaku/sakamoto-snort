#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

enum verdict_mode {
  MODE_ACCEPT_ALL,
  MODE_DROP_ALL,
  MODE_DROP_RATIO,
};

struct config {
  uint16_t queue_num;
  enum verdict_mode mode;
  unsigned drop_ratio;
  unsigned print_every;
  uint64_t max_packets;
  bool unbind_existing;
};

struct counters {
  uint64_t seen;
  uint64_t accepted;
  uint64_t dropped;
  uint64_t missing_id;
  uint64_t uid_known;
  uint64_t gid_known;
  uint64_t timestamp_known;
  uint64_t payload_known;
};

struct app_state {
  struct config cfg;
  struct counters counters;
};

static volatile sig_atomic_t stop_requested;

static void on_signal(int signo) {
  (void)signo;
  stop_requested = 1;
}

static void usage(const char *argv0) {
  fprintf(stderr,
          "usage: %s [--queue N] [--mode accept-all|drop-all|drop-ratio=N] "
          "[--print-every N] [--max-packets N] [--unbind-existing]\n",
          argv0);
}

static uint64_t parse_u64(const char *text, const char *name) {
  char *end = NULL;
  errno = 0;
  unsigned long long value = strtoull(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0') {
    fprintf(stderr, "invalid %s: %s\n", name, text);
    exit(2);
  }
  return (uint64_t)value;
}

static void parse_mode(struct config *cfg, const char *mode) {
  if (strcmp(mode, "accept-all") == 0) {
    cfg->mode = MODE_ACCEPT_ALL;
    cfg->drop_ratio = 0;
    return;
  }
  if (strcmp(mode, "drop-all") == 0) {
    cfg->mode = MODE_DROP_ALL;
    cfg->drop_ratio = 100;
    return;
  }
  const char *prefix = "drop-ratio=";
  size_t prefix_len = strlen(prefix);
  if (strncmp(mode, prefix, prefix_len) == 0) {
    uint64_t ratio = parse_u64(mode + prefix_len, "drop ratio");
    if (ratio > 100) {
      fprintf(stderr, "drop ratio must be 0..100\n");
      exit(2);
    }
    cfg->mode = MODE_DROP_RATIO;
    cfg->drop_ratio = (unsigned)ratio;
    return;
  }

  fprintf(stderr, "invalid mode: %s\n", mode);
  exit(2);
}

static struct config parse_args(int argc, char **argv) {
  struct config cfg = {
      .queue_num = 42,
      .mode = MODE_ACCEPT_ALL,
      .drop_ratio = 0,
      .print_every = 10,
      .max_packets = 0,
      .unbind_existing = false,
  };

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--queue") == 0 && i + 1 < argc) {
      uint64_t value = parse_u64(argv[++i], "queue");
      if (value > 65535) {
        fprintf(stderr, "queue must be 0..65535\n");
        exit(2);
      }
      cfg.queue_num = (uint16_t)value;
    } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
      parse_mode(&cfg, argv[++i]);
    } else if (strcmp(argv[i], "--print-every") == 0 && i + 1 < argc) {
      cfg.print_every = (unsigned)parse_u64(argv[++i], "print-every");
    } else if (strcmp(argv[i], "--max-packets") == 0 && i + 1 < argc) {
      cfg.max_packets = parse_u64(argv[++i], "max-packets");
    } else if (strcmp(argv[i], "--unbind-existing") == 0) {
      cfg.unbind_existing = true;
    } else if (strcmp(argv[i], "--help") == 0) {
      usage(argv[0]);
      exit(0);
    } else {
      usage(argv[0]);
      exit(2);
    }
  }

  return cfg;
}

static const char *verdict_name(uint32_t verdict) {
  return verdict == NF_ACCEPT ? "ACCEPT" : "DROP";
}

static uint32_t choose_verdict(struct app_state *state) {
  switch (state->cfg.mode) {
  case MODE_ACCEPT_ALL:
    return NF_ACCEPT;
  case MODE_DROP_ALL:
    return NF_DROP;
  case MODE_DROP_RATIO:
    if (state->cfg.drop_ratio == 0) {
      return NF_ACCEPT;
    }
    if (state->cfg.drop_ratio >= 100) {
      return NF_DROP;
    }
    return ((state->counters.seen * state->cfg.drop_ratio) % 100) <
                   state->cfg.drop_ratio
               ? NF_DROP
               : NF_ACCEPT;
  }
  return NF_DROP;
}

static void print_summary(const struct app_state *state) {
  const struct counters *c = &state->counters;
  printf("summary seen=%llu accept=%llu drop=%llu missing_id=%llu "
         "payload=%llu uid=%llu gid=%llu timestamp=%llu\n",
         (unsigned long long)c->seen, (unsigned long long)c->accepted,
         (unsigned long long)c->dropped, (unsigned long long)c->missing_id,
         (unsigned long long)c->payload_known, (unsigned long long)c->uid_known,
         (unsigned long long)c->gid_known,
         (unsigned long long)c->timestamp_known);
  fflush(stdout);
}

static int on_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                     struct nfq_data *nfa, void *data) {
  (void)nfmsg;
  struct app_state *state = data;
  struct counters *c = &state->counters;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);

  c->seen++;

  uint32_t id = 0;
  bool has_id = false;
  uint8_t hook = 0;
  uint16_t hw_protocol = 0;
  if (ph != NULL) {
    id = ntohl(ph->packet_id);
    hook = ph->hook;
    hw_protocol = ntohs(ph->hw_protocol);
    has_id = true;
  } else {
    c->missing_id++;
  }

  unsigned char *payload = NULL;
  int payload_len = nfq_get_payload(nfa, &payload);
  if (payload_len >= 0) {
    c->payload_known++;
  }

  uint32_t uid = 0;
  bool uid_known = nfq_get_uid(nfa, &uid) != 0;
  if (uid_known) {
    c->uid_known++;
  }

  uint32_t gid = 0;
  bool gid_known = nfq_get_gid(nfa, &gid) != 0;
  if (gid_known) {
    c->gid_known++;
  }

  struct timeval timestamp;
  bool timestamp_known = nfq_get_timestamp(nfa, &timestamp) == 0;
  if (timestamp_known) {
    c->timestamp_known++;
  }

  uint32_t indev = nfq_get_indev(nfa);
  uint32_t outdev = nfq_get_outdev(nfa);
  uint32_t physindev = nfq_get_physindev(nfa);
  uint32_t physoutdev = nfq_get_physoutdev(nfa);
  uint32_t mark = nfq_get_nfmark(nfa);

  uint32_t verdict = choose_verdict(state);
  if (verdict == NF_ACCEPT) {
    c->accepted++;
  } else {
    c->dropped++;
  }

  printf("packet n=%llu id=%s%u hook=%u hwproto=0x%04x payload_len=%d "
         "mark=%u indev=%u outdev=%u physindev=%u physoutdev=%u "
         "uid=%s%u gid=%s%u timestamp=%s verdict=%s\n",
         (unsigned long long)c->seen, has_id ? "" : "missing:", id, hook,
         hw_protocol, payload_len, mark, indev, outdev, physindev, physoutdev,
         uid_known ? "" : "unknown:", uid, gid_known ? "" : "unknown:", gid,
         timestamp_known ? "known" : "unknown", verdict_name(verdict));

  if (state->cfg.print_every != 0 && c->seen % state->cfg.print_every == 0) {
    print_summary(state);
  }

  if (!has_id) {
    return 0;
  }

  return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

static int configure_queue(struct nfq_q_handle *qh) {
  if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    perror("nfq_set_mode NFQNL_COPY_PACKET");
    return -1;
  }

  if (nfq_set_queue_maxlen(qh, 4096) < 0) {
    perror("nfq_set_queue_maxlen");
    return -1;
  }

#ifdef NFQA_CFG_F_UID_GID
  if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID) < 0) {
    fprintf(stderr, "warning: kernel did not enable UID/GID attrs\n");
  }
#endif

  return 0;
}

int main(int argc, char **argv) {
  struct app_state state = {
      .cfg = parse_args(argc, argv),
      .counters = {0},
  };

  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);

  struct nfq_handle *h = nfq_open();
  if (h == NULL) {
    perror("nfq_open");
    return 1;
  }

  if (state.cfg.unbind_existing) {
    (void)nfq_unbind_pf(h, AF_INET);
  }

  if (nfq_bind_pf(h, AF_INET) < 0) {
    perror("nfq_bind_pf AF_INET");
    nfq_close(h);
    return 1;
  }

  struct nfq_q_handle *qh =
      nfq_create_queue(h, state.cfg.queue_num, on_packet, &state);
  if (qh == NULL) {
    perror("nfq_create_queue");
    nfq_close(h);
    return 1;
  }

  if (configure_queue(qh) < 0) {
    nfq_destroy_queue(qh);
    nfq_close(h);
    return 1;
  }

  int fd = nfq_fd(h);
  printf("nfq-smoke queue=%u fd=%d mode=%d drop_ratio=%u\n",
         state.cfg.queue_num, fd, state.cfg.mode, state.cfg.drop_ratio);
  fflush(stdout);

  char buf[65536] __attribute__((aligned));
  while (!stop_requested) {
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };

    int ready = poll(&pfd, 1, 1000);
    if (ready < 0) {
      if (errno == EINTR) {
        continue;
      }
      perror("poll");
      break;
    }
    if (ready == 0) {
      continue;
    }

    int rv = recv(fd, buf, sizeof(buf), 0);
    if (rv >= 0) {
      if (nfq_handle_packet(h, buf, rv) < 0) {
        perror("nfq_handle_packet");
      }
    } else if (errno == ENOBUFS) {
      fprintf(stderr, "warning: netlink ENOBUFS, packets lost before verdict\n");
    } else if (errno != EINTR) {
      perror("recv");
      break;
    }

    if (state.cfg.max_packets != 0 &&
        state.counters.seen >= state.cfg.max_packets) {
      break;
    }
  }

  print_summary(&state);
  nfq_destroy_queue(qh);
  nfq_close(h);
  return 0;
}
