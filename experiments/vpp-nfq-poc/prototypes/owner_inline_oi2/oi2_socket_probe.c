/* SPDX-License-Identifier: Apache-2.0 */

/*
 * OI-2 real Unix-socket contract probe.
 *
 * It is deliberately a host-side executable, not product code.  The owner
 * thread creates sockets and submits an opaque request plus one SCM_RIGHTS
 * duplicate through a nonblocking channel.  A separate broker thread binds,
 * applies a deterministic protect decision, closes its duplicate, and sends
 * a completion.  The owner keeps ticking a graph sentinel while completions
 * are delayed.  The Android JNI broker will reuse the same wire contract.
 */

#define _GNU_SOURCE
#include "oi2_broker_contract.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

enum {
    OI2_ACTION_SUCCESS = 0,
    OI2_ACTION_BIND_FAILURE = 1,
    OI2_ACTION_PROTECT_FAILURE = 2,
};

typedef struct oi2_socket_record {
    oi2_broker_request_t request;
    int fd;
    int original_close_count;
    int connect_count;
    int first_send_count;
    int outcome;
} oi2_socket_record_t;

typedef struct oi2_probe {
    int request_pair[2];
    int completion_pair[2];
    pthread_t broker_thread;
    bool broker_started;
    bool broker_running;
    atomic_bool broker_stop_requested;
    bool broker_available;
    bool stop;
    unsigned delay_ms;
    int action[2][2];
    unsigned accepted;
    unsigned queue_rejects;
    unsigned unavailable_rejects;
    unsigned stale;
    unsigned duplicate;
    unsigned wrong_owner;
    unsigned wrong_epoch;
    unsigned broker_duplicate_closes;
    unsigned bind_calls;
    unsigned protect_calls;
    unsigned owner_ticks;
    unsigned sentinel_ticks;
    unsigned early_connects;
    unsigned late_completions;
    uint64_t generation;
    uint64_t epoch;
    unsigned owner_queue_limit;
    unsigned owner_inflight;
    uint32_t owner;
    uint32_t shard;
    uint64_t next_token;
    char order[256];
    unsigned order_count;
    oi2_socket_record_t records[OI2_BROKER_QUEUE_CAPACITY + 8];
    unsigned record_count;
} oi2_probe_t;

static uint64_t now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static const char *family_name(uint32_t family) {
    return family == OI2_FAMILY_IPV4 ? "ipv4" : "ipv6";
}

static const char *kind_name(uint32_t kind) {
    return kind == OI2_KIND_TCP ? "tcp" : "udp";
}

static void close_original(oi2_socket_record_t *record) {
    if (record->original_close_count == 0) {
        close(record->fd);
        record->original_close_count = 1;
    }
}

static int recv_request(int fd, oi2_broker_request_t *request, int *received_fd) {
    char payload[sizeof(*request)];
    char control[CMSG_SPACE(sizeof(int))];
    struct iovec iov = { .iov_base = payload, .iov_len = sizeof(payload) };
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    ssize_t count = recvmsg(fd, &msg, MSG_DONTWAIT);
    if (count < 0)
        return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
    if ((size_t)count != sizeof(*request))
        return -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET ||
        cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len < CMSG_LEN(sizeof(int)))
        return -1;
    memcpy(request, payload, sizeof(*request));
    memcpy(received_fd, CMSG_DATA(cmsg), sizeof(int));
    return 1;
}

static int send_completion(int fd, const oi2_broker_completion_t *completion) {
    ssize_t count = send(fd, completion, sizeof(*completion), MSG_NOSIGNAL);
    return count == (ssize_t)sizeof(*completion) ? 0 : -1;
}

static int bind_socket(int fd, uint32_t family) {
    if (family == OI2_FAMILY_IPV4) {
        struct sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_ANY);
        return bind(fd, (struct sockaddr *)&address, sizeof(address));
    }
    struct sockaddr_in6 address6;
    memset(&address6, 0, sizeof(address6));
    address6.sin6_family = AF_INET6;
    address6.sin6_addr = in6addr_any;
    return bind(fd, (struct sockaddr *)&address6, sizeof(address6));
}

static void *broker_main(void *opaque) {
    oi2_probe_t *probe = opaque;
    probe->broker_running = true;
    while (!atomic_load_explicit(&probe->broker_stop_requested,
                                 memory_order_acquire)) {
        struct pollfd pollfd = { .fd = probe->request_pair[1], .events = POLLIN };
        int ready = poll(&pollfd, 1, 10);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0)
            continue;
        oi2_broker_request_t request;
        int duplicate_fd = -1;
        int result = recv_request(probe->request_pair[1], &request, &duplicate_fd);
        if (result <= 0) {
            if (result < 0)
                break;
            continue;
        }
        if (request.abi_version != OI2_BROKER_ABI_VERSION || duplicate_fd < 0) {
            close(duplicate_fd);
            probe->broker_duplicate_closes++;
            continue;
        }
        probe->bind_calls++;
        if (probe->order_count + 3 < sizeof(probe->order)) {
            probe->order[probe->order_count++] = 'B';
            probe->order[probe->order_count++] = 'P';
            probe->order[probe->order_count++] = 'C';
            probe->order[probe->order_count] = '\0';
        }
        int action = probe->action[request.family == OI2_FAMILY_IPV6][request.kind == OI2_KIND_UDP];
        int operation_result = OI2_RESULT_SUCCESS;
        if (!probe->broker_available) {
            operation_result = OI2_RESULT_BROKER_UNAVAILABLE;
        } else if (action == OI2_ACTION_BIND_FAILURE || bind_socket(duplicate_fd, request.family) < 0) {
            operation_result = OI2_RESULT_BIND_FAILURE;
        } else {
            probe->protect_calls++;
            if (action == OI2_ACTION_PROTECT_FAILURE)
                operation_result = OI2_RESULT_PROTECT_FAILURE;
        }
        if (probe->delay_ms != 0)
            usleep((useconds_t)probe->delay_ms * 1000u);
        close(duplicate_fd);
        probe->broker_duplicate_closes++;
        oi2_broker_completion_t completion = {
            .abi_version = OI2_BROKER_ABI_VERSION,
            .result = (uint32_t)operation_result,
            .fault_reason = (uint32_t)operation_result,
            .owner = request.owner,
            .shard = request.shard,
            .token = request.token,
            .generation = request.generation,
            .underlay_epoch = request.underlay_epoch,
        };
        if (send_completion(probe->completion_pair[1], &completion) != 0)
            break;
    }
    probe->broker_running = false;
    return NULL;
}

static int send_request(oi2_probe_t *probe, oi2_socket_record_t *record) {
    char control[CMSG_SPACE(sizeof(int))];
    char payload[sizeof(record->request)];
    struct iovec iov = { .iov_base = payload, .iov_len = sizeof(payload) };
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    memcpy(payload, &record->request, sizeof(record->request));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(record->fd));
    memcpy(CMSG_DATA(cmsg), &record->fd, sizeof(record->fd));
    ssize_t count = sendmsg(probe->request_pair[0], &msg,
                            MSG_DONTWAIT | MSG_NOSIGNAL);
    if (count == (ssize_t)sizeof(record->request)) {
        probe->accepted++;
        probe->owner_inflight++;
        return 0;
    }
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        probe->queue_rejects++;
        close_original(record);
        return 1;
    }
    probe->unavailable_rejects++;
    close_original(record);
    return -1;
}

static oi2_socket_record_t *find_record(oi2_probe_t *probe, uint64_t token) {
    for (unsigned i = 0; i < probe->record_count; ++i)
        if (probe->records[i].request.token == token)
            return &probe->records[i];
    return NULL;
}

static void consume_completion(oi2_probe_t *probe,
                               const oi2_broker_completion_t *completion) {
    oi2_socket_record_t *record = find_record(probe, completion->token);
    if (!record || completion->generation != probe->generation) {
        probe->stale++;
        probe->late_completions++;
        return;
    }
    if (completion->owner != probe->owner || completion->shard != probe->shard) {
        probe->wrong_owner++;
        close_original(record);
        return;
    }
    if (completion->underlay_epoch != probe->epoch) {
        probe->wrong_epoch++;
        close_original(record);
        return;
    }
    if (record->outcome != 0) {
        probe->duplicate++;
        return;
    }
    if (probe->owner_inflight > 0)
        probe->owner_inflight--;
    if (completion->result == OI2_RESULT_SUCCESS) {
        record->connect_count++;
        record->first_send_count++;
        record->outcome = OI2_RESULT_SUCCESS;
    } else {
        record->outcome = (int)completion->result;
        close_original(record);
    }
}

static void owner_tick(oi2_probe_t *probe) {
    probe->owner_ticks++;
    probe->sentinel_ticks++;
    for (;;) {
        oi2_broker_completion_t completion;
        ssize_t count = recv(probe->completion_pair[0], &completion,
                             sizeof(completion), MSG_DONTWAIT);
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
        if (count != (ssize_t)sizeof(completion))
            break;
        consume_completion(probe, &completion);
    }
}

static int create_socket(uint32_t family, uint32_t kind) {
    int domain = family == OI2_FAMILY_IPV4 ? AF_INET : AF_INET6;
    int type = kind == OI2_KIND_TCP ? SOCK_STREAM : SOCK_DGRAM;
    return socket(domain, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
}

static int start_broker(oi2_probe_t *probe) {
    atomic_store_explicit(&probe->broker_stop_requested, false,
                          memory_order_release);
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, probe->request_pair) != 0)
        return -1;
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, probe->completion_pair) != 0)
        return -1;
    if (set_nonblocking(probe->request_pair[0]) != 0)
        return -1;
    if (set_nonblocking(probe->completion_pair[0]) != 0)
        return -1;
    if (pthread_create(&probe->broker_thread, NULL, broker_main, probe) != 0)
        return -1;
    probe->broker_started = true;
    return 0;
}

static void stop_broker(oi2_probe_t *probe) {
    atomic_store_explicit(&probe->broker_stop_requested, true,
                          memory_order_release);
    if (probe->broker_started)
        pthread_join(probe->broker_thread, NULL);
    shutdown(probe->request_pair[0], SHUT_RDWR);
    shutdown(probe->request_pair[1], SHUT_RDWR);
    shutdown(probe->completion_pair[0], SHUT_RDWR);
    shutdown(probe->completion_pair[1], SHUT_RDWR);
    close(probe->request_pair[0]);
    close(probe->request_pair[1]);
    close(probe->completion_pair[0]);
    close(probe->completion_pair[1]);
}

static void init_probe(oi2_probe_t *probe) {
    memset(probe, 0, sizeof(*probe));
    atomic_init(&probe->broker_stop_requested, false);
    probe->broker_available = true;
    probe->generation = 1;
    probe->epoch = 17;
    probe->owner = 1;
    probe->shard = 3;
    probe->next_token = 1;
    probe->owner_queue_limit = OI2_BROKER_QUEUE_CAPACITY;
}

static int submit_socket(oi2_probe_t *probe, uint32_t family, uint32_t kind,
                         int action) {
    if (probe->record_count >= sizeof(probe->records) / sizeof(probe->records[0]))
        return -1;
    int fd = create_socket(family, kind);
    if (fd < 0) {
        fprintf(stderr, "socket family=%u kind=%u failed errno=%d %s\n",
                family, kind, errno, strerror(errno));
        return -1;
    }
    oi2_socket_record_t *record = &probe->records[probe->record_count++];
    memset(record, 0, sizeof(*record));
    record->fd = fd;
    record->request.abi_version = OI2_BROKER_ABI_VERSION;
    record->request.family = family;
    record->request.kind = kind;
    record->request.owner = probe->owner;
    record->request.shard = probe->shard;
    record->request.token = probe->next_token++;
    record->request.generation = probe->generation;
    record->request.underlay_epoch = probe->epoch;
    probe->action[family == OI2_FAMILY_IPV6][kind == OI2_KIND_UDP] = action;
    if (probe->owner_inflight >= probe->owner_queue_limit) {
        probe->queue_rejects++;
        close_original(record);
        return 1;
    }
    return send_request(probe, record);
}

static void stop_pending(oi2_probe_t *probe) {
    probe->generation++;
    for (unsigned i = 0; i < probe->record_count; ++i) {
        if (probe->records[i].outcome == 0)
            close_original(&probe->records[i]);
    }
}

static void print_summary(const char *name, const oi2_probe_t *probe) {
    printf("cell=%s accepted=%u queue-rejects=%u unavailable=%u "
           "bind=%u protect=%u stale=%u duplicate=%u wrong-owner=%u "
           "wrong-epoch=%u owner-ticks=%u sentinel-ticks=%u late=%u "
           "duplicate-fd-closes=%u order=%s\n",
           name, probe->accepted, probe->queue_rejects,
           probe->unavailable_rejects, probe->bind_calls, probe->protect_calls,
           probe->stale, probe->duplicate, probe->wrong_owner,
           probe->wrong_epoch, probe->owner_ticks, probe->sentinel_ticks,
           probe->late_completions, probe->broker_duplicate_closes,
           probe->order);
    for (unsigned i = 0; i < probe->record_count; ++i) {
        const oi2_socket_record_t *record = &probe->records[i];
        printf("  token=%llu %s/%s original-close=%d connect=%d first-send=%d outcome=%d\n",
               (unsigned long long)record->request.token,
               family_name(record->request.family), kind_name(record->request.kind),
               record->original_close_count, record->connect_count,
               record->first_send_count, record->outcome);
    }
}

static int run_success_cells(void) {
    oi2_probe_t probe;
    init_probe(&probe);
    if (start_broker(&probe) != 0)
        return 1;
    submit_socket(&probe, OI2_FAMILY_IPV4, OI2_KIND_TCP, OI2_ACTION_SUCCESS);
    submit_socket(&probe, OI2_FAMILY_IPV4, OI2_KIND_UDP, OI2_ACTION_SUCCESS);
    submit_socket(&probe, OI2_FAMILY_IPV6, OI2_KIND_TCP, OI2_ACTION_SUCCESS);
    submit_socket(&probe, OI2_FAMILY_IPV6, OI2_KIND_UDP, OI2_ACTION_SUCCESS);
    for (unsigned i = 0; i < 120; ++i) {
        owner_tick(&probe);
        usleep(1000);
    }
    for (unsigned i = 0; i < probe.record_count; ++i)
        close_original(&probe.records[i]);
    print_summary("families", &probe);
    stop_broker(&probe);
    return 0;
}

static int run_delay_stop_cell(void) {
    oi2_probe_t probe;
    init_probe(&probe);
    probe.delay_ms = 25;
    if (start_broker(&probe) != 0)
        return 1;
    submit_socket(&probe, OI2_FAMILY_IPV4, OI2_KIND_TCP, OI2_ACTION_SUCCESS);
    uint64_t started = now_ms();
    while (now_ms() - started < 8) {
        owner_tick(&probe);
        usleep(1000);
    }
    stop_pending(&probe);
    /* Let the already accepted request complete after the owner generation
     * has advanced; this is the late-completion rejection cell. */
    usleep(40000);
    for (unsigned i = 0; i < 35; ++i) {
        owner_tick(&probe);
        usleep(1000);
    }
    print_summary("delayed-stop", &probe);
    stop_broker(&probe);
    return probe.sentinel_ticks < 4 || probe.late_completions == 0;
}

static int run_failure_cells(void) {
    oi2_probe_t probe;
    init_probe(&probe);
    if (start_broker(&probe) != 0)
        return 1;
    submit_socket(&probe, OI2_FAMILY_IPV4, OI2_KIND_TCP, OI2_ACTION_BIND_FAILURE);
    submit_socket(&probe, OI2_FAMILY_IPV6, OI2_KIND_UDP, OI2_ACTION_PROTECT_FAILURE);
    for (unsigned i = 0; i < 120; ++i) {
        owner_tick(&probe);
        usleep(1000);
    }
    print_summary("forced-failures", &probe);
    stop_broker(&probe);
    return 0;
}

static int run_unavailable_queue_cells(void) {
    oi2_probe_t unavailable;
    init_probe(&unavailable);
    if (start_broker(&unavailable) != 0)
        return 1;
    stop_broker(&unavailable);
    unavailable.broker_available = false;
    submit_socket(&unavailable, OI2_FAMILY_IPV4, OI2_KIND_TCP, OI2_ACTION_SUCCESS);
    print_summary("broker-unavailable", &unavailable);

    oi2_probe_t full;
    init_probe(&full);
    full.owner_queue_limit = 2;
    if (start_broker(&full) != 0)
        return 1;
    for (unsigned i = 0; i < 4; ++i)
        submit_socket(&full, i & 1 ? OI2_FAMILY_IPV6 : OI2_FAMILY_IPV4,
                      i & 1 ? OI2_KIND_UDP : OI2_KIND_TCP, OI2_ACTION_SUCCESS);
    for (unsigned i = 0; i < 120; ++i) {
        owner_tick(&full);
        usleep(1000);
    }
    for (unsigned i = 0; i < full.record_count; ++i)
        close_original(&full.records[i]);
    print_summary("queue-full", &full);
    stop_broker(&full);
    return unavailable.unavailable_rejects != 1 || full.queue_rejects != 2;
}

static int run_completion_tripwire_cell(void) {
    oi2_probe_t probe;
    init_probe(&probe);
    if (start_broker(&probe) != 0)
        return 1;
    submit_socket(&probe, OI2_FAMILY_IPV4, OI2_KIND_TCP, OI2_ACTION_SUCCESS);
    for (unsigned i = 0; i < 80 && probe.records[0].outcome == 0; ++i) {
        owner_tick(&probe);
        usleep(1000);
    }
    oi2_broker_completion_t completion = {
        .abi_version = OI2_BROKER_ABI_VERSION,
        .result = OI2_RESULT_SUCCESS,
        .owner = probe.owner,
        .shard = probe.shard,
        .token = probe.records[0].request.token,
        .generation = probe.generation,
        .underlay_epoch = probe.epoch,
    };
    consume_completion(&probe, &completion);
    completion.owner++;
    consume_completion(&probe, &completion);
    completion.owner = probe.owner;
    completion.underlay_epoch++;
    consume_completion(&probe, &completion);
    completion.underlay_epoch = probe.epoch;
    completion.generation--;
    consume_completion(&probe, &completion);
    close_original(&probe.records[0]);
    print_summary("completion-tripwires", &probe);
    stop_broker(&probe);
    return probe.duplicate != 1 || probe.wrong_owner != 1 ||
           probe.wrong_epoch != 1 || probe.stale != 1;
}

int main(void) {
    int rc = 0;
    rc |= run_success_cells();
    rc |= run_failure_cells();
    rc |= run_delay_stop_cell();
    rc |= run_unavailable_queue_cells();
    rc |= run_completion_tripwire_cell();
    if (rc != 0)
        fprintf(stderr, "OI2 socket probe failed\n");
    else
        puts("oi2_socket_probe=PASS");
    return rc;
}
