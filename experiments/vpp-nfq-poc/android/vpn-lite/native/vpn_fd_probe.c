#include <arpa/inet.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <jni.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <android/log.h>

#include "../../../overlay/src/plugins/hev_external_driver_poc/oi2_broker_contract.h"

#define LOG_TAG "SnortVpnLiteNative"
#define BUF_SIZE 4096
#define PATH_BUF_SIZE 1024
#define VPP_TUN_FD 3
#define VPP_SHIM_FD 4
#define VPP_RESOLVER_FD 5
#define OI2_REQUEST_FD 6
#define OI2_COMPLETION_FD 7

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_thread;
static bool g_running;
static int g_fd = -1;
static int g_max_packets;
static char g_log_path[PATH_BUF_SIZE];
static JavaVM *g_jvm;
static jobject g_owner_lookup;
static jmethodID g_owner_lookup_method;
static char g_stage_cell[64] = "A2-4";
static char g_stage_id[128] = "startup";
static pthread_mutex_t g_underlay_epoch_cli_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_vpp_underlay_epoch;
static int64_t g_vpp_underlay_handle = -1;
static bool g_vpp_underlay_available;

static pthread_t g_vpp_monitor_thread;
static bool g_vpp_monitor_running;
static pthread_t g_vpp_shim_thread;
static bool g_vpp_shim_running;
static pthread_t g_vpp_gate_thread;
static bool g_vpp_gate_running;
static pthread_t g_vpp_resolver_thread;
static bool g_vpp_resolver_running;
static int g_vpp_resolver_block_uid = -1;
static pid_t g_vpp_pid = -1;
static int g_vpp_shim_fd = -1;
static int g_vpp_gate_tun_fd = -1;
static int g_vpp_gate_vpp_fd = -1;
static int g_vpp_gate_block_uid = -1;
static int g_vpp_resolver_fd = -1;
static char g_vpp_cli_sock[PATH_BUF_SIZE];
static char g_vpp_api_sock[PATH_BUF_SIZE];
static char g_vpp_statseg_sock[PATH_BUF_SIZE];
static char g_vpp_cli_log[PATH_BUF_SIZE];
static char g_vpp_monitor_show_command[96];
static char g_vpp_shim_log[PATH_BUF_SIZE];
static char g_vpp_gate_log[PATH_BUF_SIZE];
static char g_vpp_resolver_log[PATH_BUF_SIZE];
static char g_vpp_hev_log[PATH_BUF_SIZE];
static char g_vpp_protect_log[PATH_BUF_SIZE];
/* A2-5 one-flow join between the UID resolver and the real HEV protect
 * broker.  The runner uses a fresh session per key, so this state is bounded
 * and is intentionally POC-only rather than a production flow table. */
static char g_admission_stage[128] = "unknown";
static char g_admission_flow_id[256] = "unknown";
static char g_admission_key[256] = "unknown";
static int g_admission_uid = -1;
static bool g_admission_policy_logged;
static bool g_oi5_mode;
static char g_oi5_log[PATH_BUF_SIZE];
static char g_oi5_hev_lib[PATH_BUF_SIZE];

static pthread_t g_oi2_broker_thread;
static bool g_oi2_broker_running;
static int g_oi2_request_fd = -1;
static int g_oi2_completion_fd = -1;
static jobject g_oi2_service;
static jmethodID g_oi2_method;
static char g_oi2_broker_log[PATH_BUF_SIZE];

/* OI-3 controlled Android cell.  The parent keeps a duplicated TUN fd and
 * injects one loopback UDP packet after the VPP child has installed its file
 * reader.  The mode is only selected by vpp-oi3-controlled, whose Java VPN
 * builder has a narrow test route and no default route. */
static pthread_t g_oi3_control_thread;
static bool g_oi3_control_started;
static bool g_oi3_control_running;
static int g_oi3_control_fd = -1;
static char g_oi3_control_log[PATH_BUF_SIZE];
static char g_oi3_control_cell[32] = "udp4";

static const char *oi3_controlled_cell_for_mode(int vpp_mode) {
    switch (vpp_mode) {
        case 18: return "tcp4";
        case 19: return "udp6";
        case 20: return "tcp6";
        case 21: return "refused";
        case 22: return "no-reply";
        case 23: return "policy-drop";
        case 26: return "udp6";
        default: return "udp4";
    }
}

static void oi5_android_sequence(const char *sock_path, const char *hev_lib);

static pthread_t g_protect_thread;
static bool g_protect_running;
static int g_protect_fd = -1;
static jobject g_protect_service;
static jmethodID g_protect_method;
/* POC-only protect-broker ledger.  The counters are deliberately scoped to
 * one VPP start and protected by g_lock; they are evidence for whether HEV
 * reached Android's protect boundary, not production telemetry. */
static uint64_t g_protect_requests;
static uint64_t g_protect_completions;
static uint64_t g_protect_failures;
static uint64_t g_protect_denials;
static uint64_t g_protect_receive_failures;
static uint64_t g_protect_response_failures;
static uint64_t g_protect_java_exceptions;

static pid_t g_hev_pid = -1;
static int g_hev_driver_fd = -1;
static char g_hev_log_path[PATH_BUF_SIZE];

typedef int (*hev_main_from_str_fn)(const char *config, unsigned int config_len, int tun_fd);
typedef void (*hev_set_socket_protect_fn)(int (*func)(int fd, void *data), void *data);

typedef struct {
    bool valid;
    bool correlation_valid;
    int protocol;
    char local_addr[INET6_ADDRSTRLEN];
    char remote_addr[INET6_ADDRSTRLEN];
    uint16_t local_port;
    uint16_t remote_port;
    char cell_id[64];
    char stage_id[128];
    uint64_t request_id;
} owner_query_t;

#define OWNER_CACHE_SIZE 64

typedef struct {
    bool valid;
    owner_query_t query;
    int uid;
} owner_cache_entry_t;

static void run_hev_child(const char *native_dir, const char *log_path, int fd,
                          int socks_port, int protect_fd);

static void log_line(FILE *file, const char *fmt, ...) {
    char line[512];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "%s", line);
    if (file) {
        fprintf(file, "%s\n", line);
        fflush(file);
    }
}

static void copy_stage(char *cell, size_t cell_size, char *stage, size_t stage_size) {
    pthread_mutex_lock(&g_lock);
    snprintf(cell, cell_size, "%s", g_stage_cell);
    snprintf(stage, stage_size, "%s", g_stage_id);
    pthread_mutex_unlock(&g_lock);
}

static void admission_set_from_query(const owner_query_t *query, int uid,
                                      bool allow, FILE *file) {
    const char *family;
    const char *protocol;
    const char *stage_id;
    if (!query || !query->valid) {
        return;
    }
    family = strchr(query->local_addr, ':') ? "ip6" : "ip4";
    protocol = query->protocol == IPPROTO_TCP ? "tcp" :
               query->protocol == IPPROTO_UDP ? "udp" : "other";
    stage_id = query->correlation_valid && query->stage_id[0]
            ? query->stage_id : "unknown";
    pthread_mutex_lock(&g_lock);
    snprintf(g_admission_stage, sizeof(g_admission_stage), "%s", stage_id);
    snprintf(g_admission_flow_id, sizeof(g_admission_flow_id),
             "%s|%s|%s|%u", stage_id, family, protocol,
             (unsigned int)query->local_port);
    snprintf(g_admission_key, sizeof(g_admission_key),
             "%s|%s|%u|%s:%u", family, protocol,
             (unsigned int)query->local_port, query->remote_addr,
             (unsigned int)query->remote_port);
    g_admission_uid = uid;
    bool log_policy = uid >= 0 && !g_admission_policy_logged;
    if (log_policy) {
        g_admission_policy_logged = true;
    }
    pthread_mutex_unlock(&g_lock);
    if (uid < 0) {
        log_line(file,
                 "ledger event=POLICY_PENDING stage-id=%s flow-id=%s "
                 "canonical-key=%s uid=%d decision=PENDING resolver=uid",
                 stage_id, g_admission_flow_id, g_admission_key, uid);
    } else if (log_policy) {
        log_line(file,
                 "ledger event=POLICY_DECISION stage-id=%s flow-id=%s "
                 "canonical-key=%s uid=%d decision=%s resolver=uid",
                 stage_id, g_admission_flow_id, g_admission_key, uid,
                 allow ? "ALLOW" : "DROP");
    }
}

static void admission_snapshot(char *stage, size_t stage_size,
                               char *flow_id, size_t flow_id_size,
                               char *key, size_t key_size, int *uid) {
    pthread_mutex_lock(&g_lock);
    snprintf(stage, stage_size, "%s", g_admission_stage);
    snprintf(flow_id, flow_id_size, "%s", g_admission_flow_id);
    snprintf(key, key_size, "%s", g_admission_key);
    if (uid) {
        *uid = g_admission_uid;
    }
    pthread_mutex_unlock(&g_lock);
}

static void admission_log(FILE *file, const char *event, int result,
                          int socket_fd) {
    char stage[128];
    char flow_id[256];
    char key[256];
    int uid = -1;
    admission_snapshot(stage, sizeof(stage), flow_id, sizeof(flow_id),
                       key, sizeof(key), &uid);
    log_line(file,
             "ledger event=%s stage-id=%s flow-id=%s canonical-key=%s uid=%d "
             "result=%d fd=%d",
             event, stage, flow_id, key, uid, result, socket_fd);
}

static void *oi3_controlled_injector_thread(void *unused) {
    (void)unused;
    FILE *file = fopen(g_oi3_control_log, "a");
    bool ipv6 = strcmp(g_oi3_control_cell, "udp6") == 0
            || strcmp(g_oi3_control_cell, "tcp6") == 0;
    bool tcp = strcmp(g_oi3_control_cell, "tcp4") == 0
            || strcmp(g_oi3_control_cell, "tcp6") == 0
            || strcmp(g_oi3_control_cell, "refused") == 0;
    log_line(file, "controlled observer cell=%s route=%s default-routes=none "
                  "underlay=loopback destination=%s:%d source=app-through-vpn",
             g_oi3_control_cell,
             ipv6 ? "fd00:200::/64" : "10.200.0.0/24",
             ipv6 ? "::1" : "127.0.0.1", tcp ? 42080 : 42081);
    /* Give the VPP file callback time to consume the app->TUN packet before
     * this duplicate fd begins observing the return direction.  A duplicated
     * TUN fd shares the read queue; polling it too early would steal ingress
     * from VPP and invalidate the very path under test. */
    for (unsigned int wait = 0; wait < 60; wait++) {
        pthread_mutex_lock(&g_lock);
        bool running = g_oi3_control_running;
        int fd = g_oi3_control_fd;
        pthread_mutex_unlock(&g_lock);
        if (!running || fd < 0) {
            if (file) fclose(file);
            return NULL;
        }
        usleep(100000);
    }

    pthread_mutex_lock(&g_lock);
    int fd = g_oi3_control_fd;
    bool running = g_oi3_control_running;
    pthread_mutex_unlock(&g_lock);
    if (!running || fd < 0) {
        if (file) fclose(file);
        return NULL;
    }
    /* Never read this duplicate: a TUN fd has one shared ingress queue, so a
     * parent observer would race VPP and steal the app packet.  VPP's own raw
     * stdout is the authoritative ingress/output ledger.  Keep the duplicate
     * only as a bounded lifetime anchor and explicitly record that ownership
     * in this sidecar log. */
    for (unsigned int wait = 0; wait < 80; wait++) {
        pthread_mutex_lock(&g_lock);
        bool still_running = g_oi3_control_running;
        pthread_mutex_unlock(&g_lock);
        if (!still_running) {
            break;
        }
        usleep(100000);
    }
    bool owns_fd = false;
    pthread_mutex_lock(&g_lock);
    if (g_oi3_control_fd == fd) {
        g_oi3_control_fd = -1;
        g_oi3_control_running = false;
        owns_fd = true;
    }
    pthread_mutex_unlock(&g_lock);
    if (owns_fd) {
        close(fd);
    }
    log_line(file, "controlled ledger app-inject=1 tun-output=delegated-to-vpp-stdout "
                  "observer-read=0 residue=0");
    if (file) fclose(file);
    return NULL;
}

/* Startup can fail after the parent has retained the controlled TUN
 * duplicate but before the injector thread is created. */
static void cancel_oi3_controlled_fd(void) {
    pthread_mutex_lock(&g_lock);
    int fd = g_oi3_control_fd;
    g_oi3_control_fd = -1;
    g_oi3_control_running = false;
    pthread_mutex_unlock(&g_lock);
    if (fd >= 0) {
        close(fd);
    }
}

static int send_fd_and_wait_result(int broker_fd, int socket_fd) {
    char payload = 'P';
    char control[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {.iov_base = &payload, .iov_len = sizeof(payload)};
    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &socket_fd, sizeof(socket_fd));
    if (sendmsg(broker_fd, &msg, 0) != sizeof(payload)) {
        return -1;
    }

    int result = -1;
    ssize_t received;
    do {
        received = recv(broker_fd, &result, sizeof(result), 0);
    } while (received < 0 && errno == EINTR);
    return received == sizeof(result) && result == 1 ? 0 : -1;
}

static int recv_protect_fd(int broker_fd) {
    char payload;
    char control[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {.iov_base = &payload, .iov_len = sizeof(payload)};
    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    ssize_t received;
    do {
        received = recvmsg(broker_fd, &msg, 0);
    } while (received < 0 && errno == EINTR);
    if (received <= 0) {
        return -1;
    }
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
        cmsg->cmsg_len < CMSG_LEN(sizeof(int))) {
        errno = EBADMSG;
        return -1;
    }
    int fd = -1;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
    return fd;
}

static void *protect_broker_thread(void *unused) {
    (void)unused;
    JNIEnv *env = NULL;
    bool attached = false;
    if ((*g_jvm)->GetEnv(g_jvm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        if ((*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL) != JNI_OK) {
            return NULL;
        }
        attached = true;
    }

    FILE *file = fopen(g_vpp_protect_log, "a");
    log_line(file, "protect broker start fd=%d", g_protect_fd);
    for (;;) {
        pthread_mutex_lock(&g_lock);
        bool running = g_protect_running;
        int broker_fd = g_protect_fd;
        pthread_mutex_unlock(&g_lock);
        if (!running || broker_fd < 0) {
            break;
        }

        int socket_fd = recv_protect_fd(broker_fd);
        if (socket_fd < 0) {
            pthread_mutex_lock(&g_lock);
            running = g_protect_running;
            if (running && errno != EBADF && errno != ECONNRESET) {
                g_protect_failures++;
                g_protect_receive_failures++;
            }
            pthread_mutex_unlock(&g_lock);
            if (running && errno != EBADF && errno != ECONNRESET) {
                log_line(file, "protect broker receive stop errno=%d %s", errno,
                         strerror(errno));
            }
            break;
        }

        pthread_mutex_lock(&g_lock);
        g_protect_requests++;
        pthread_mutex_unlock(&g_lock);
        admission_log(file, "BROKER_REQUEST", 1, socket_fd);
        admission_log(file, "SOCKET_CREATED", 1, socket_fd);

        jboolean protected_socket = (*env)->CallBooleanMethod(
            env, g_protect_service, g_protect_method, (jint)socket_fd);
        bool java_exception = false;
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
            protected_socket = JNI_FALSE;
            java_exception = true;
        }
        int result = protected_socket == JNI_TRUE ? 1 : 0;
        pthread_mutex_lock(&g_lock);
        if (result == 0) {
            g_protect_failures++;
            g_protect_denials++;
            if (java_exception) {
                g_protect_java_exceptions++;
            }
        }
        pthread_mutex_unlock(&g_lock);
        log_line(file, "protect fd=%d result=%d", socket_fd, result);
        close(socket_fd);
        admission_log(file, "SOCKET_SETTLED", result, socket_fd);
        if (send(broker_fd, &result, sizeof(result), 0) != sizeof(result)) {
            pthread_mutex_lock(&g_lock);
            g_protect_failures++;
            g_protect_response_failures++;
            pthread_mutex_unlock(&g_lock);
            log_line(file, "protect result send failed errno=%d %s", errno,
                     strerror(errno));
            break;
        }
        pthread_mutex_lock(&g_lock);
        g_protect_completions++;
        pthread_mutex_unlock(&g_lock);
        admission_log(file, "BROKER_COMPLETION", result, socket_fd);
    }
    pthread_mutex_lock(&g_lock);
    uint64_t requests = g_protect_requests;
    uint64_t completions = g_protect_completions;
    uint64_t failures = g_protect_failures;
    uint64_t denials = g_protect_denials;
    uint64_t receive_failures = g_protect_receive_failures;
    uint64_t response_failures = g_protect_response_failures;
    uint64_t java_exceptions = g_protect_java_exceptions;
    pthread_mutex_unlock(&g_lock);
    log_line(file,
             "protect broker summary requests=%llu completions=%llu failures=%llu "
             "denials=%llu receive-failures=%llu response-failures=%llu "
             "java-exceptions=%llu",
             (unsigned long long)requests, (unsigned long long)completions,
             (unsigned long long)failures, (unsigned long long)denials,
             (unsigned long long)receive_failures,
             (unsigned long long)response_failures,
             (unsigned long long)java_exceptions);
    log_line(file, "protect broker stop");
    if (file) {
        fclose(file);
    }
    if (attached) {
        (*g_jvm)->DetachCurrentThread(g_jvm);
    }
    return NULL;
}

static void stop_protect_broker(JNIEnv *env) {
    pthread_mutex_lock(&g_lock);
    bool was_running = g_protect_running;
    int fd = g_protect_fd;
    jobject service = g_protect_service;
    g_protect_running = false;
    g_protect_fd = -1;
    g_protect_service = NULL;
    g_protect_method = NULL;
    pthread_mutex_unlock(&g_lock);

    if (fd >= 0) {
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }
    if (was_running) {
        pthread_join(g_protect_thread, NULL);
    }
    if (service) {
        (*env)->DeleteGlobalRef(env, service);
    }
}

static int recv_oi2_request(int fd, oi2_broker_request_t *request,
                            int *received_fd) {
    char payload[sizeof(*request)];
    char control[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {.iov_base = payload, .iov_len = sizeof(payload)};
    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    ssize_t received;
    do {
        received = recvmsg(fd, &msg, MSG_DONTWAIT);
    } while (received < 0 && errno == EINTR);
    if (received < 0) {
        return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
    }
    if (received == 0) {
        return -1;
    }
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if ((size_t)received != sizeof(*request) || !cmsg ||
        cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
        cmsg->cmsg_len < CMSG_LEN(sizeof(int))) {
        if (cmsg && cmsg->cmsg_level == SOL_SOCKET &&
            cmsg->cmsg_type == SCM_RIGHTS &&
            cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
            memcpy(received_fd, CMSG_DATA(cmsg), sizeof(*received_fd));
        }
        errno = EBADMSG;
        return -1;
    }
    memcpy(request, payload, sizeof(*request));
    memcpy(received_fd, CMSG_DATA(cmsg), sizeof(*received_fd));
    return 1;
}

static int send_oi2_completion(int fd, const oi2_broker_completion_t *completion) {
    for (;;) {
        ssize_t sent = send(fd, completion, sizeof(*completion),
                            MSG_DONTWAIT | MSG_NOSIGNAL);
        if (sent == (ssize_t)sizeof(*completion)) {
            return 0;
        }
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pollfd = {.fd = fd, .events = POLLOUT};
            int ready = poll(&pollfd, 1, 100);
            if (ready < 0 && errno == EINTR) {
                continue;
            }
            if (ready > 0) {
                continue;
            }
        }
        return -1;
    }
}

static void *oi2_android_broker_thread(void *unused) {
    (void)unused;
    JNIEnv *env = NULL;
    bool attached = false;
    if ((*g_jvm)->GetEnv(g_jvm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        if ((*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL) != JNI_OK) {
            return NULL;
        }
        attached = true;
    }

    FILE *file = fopen(g_oi2_broker_log, "a");
    log_line(file, "oi2 android broker start request-fd=%d completion-fd=%d",
             g_oi2_request_fd, g_oi2_completion_fd);
    for (;;) {
        pthread_mutex_lock(&g_lock);
        bool running = g_oi2_broker_running;
        int request_fd = g_oi2_request_fd;
        int completion_fd = g_oi2_completion_fd;
        jobject service = g_oi2_service;
        jmethodID method = g_oi2_method;
        pthread_mutex_unlock(&g_lock);
        if (!running || request_fd < 0 || completion_fd < 0) {
            break;
        }

        struct pollfd pollfd = {.fd = request_fd, .events = POLLIN};
        int ready = poll(&pollfd, 1, 100);
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready <= 0) {
            continue;
        }
        oi2_broker_request_t request = {0};
        int duplicate_fd = -1;
        int received = recv_oi2_request(request_fd, &request, &duplicate_fd);
        if (received < 0) {
            int receive_errno = errno;
            if (duplicate_fd >= 0) {
                close(duplicate_fd);
            }
            pthread_mutex_lock(&g_lock);
            running = g_oi2_broker_running;
            pthread_mutex_unlock(&g_lock);
            if (running && receive_errno != EAGAIN && receive_errno != EWOULDBLOCK) {
                log_line(file, "oi2 receive failed errno=%d %s", receive_errno,
                         strerror(receive_errno));
            }
            if (receive_errno != EAGAIN && receive_errno != EWOULDBLOCK) {
                break;
            }
            continue;
        }
        if (received == 0) {
            continue;
        }

        oi2_broker_completion_t completion = {
            .abi_version = OI2_BROKER_ABI_VERSION,
            .result = OI2_RESULT_BROKER_UNAVAILABLE,
            .fault_reason = OI2_RESULT_BROKER_UNAVAILABLE,
            .owner = request.owner,
            .shard = request.shard,
            .token = request.token,
            .generation = request.generation,
            .underlay_epoch = request.underlay_epoch,
        };
        jint java_result = OI2_RESULT_BROKER_UNAVAILABLE;
        if (request.abi_version != OI2_BROKER_ABI_VERSION || duplicate_fd < 0) {
            if (duplicate_fd >= 0) {
                close(duplicate_fd);
            }
            log_line(file, "oi2 reject abi=%u fd=%d token=%llu",
                     request.abi_version, duplicate_fd,
                     (unsigned long long)request.token);
            continue;
        }

        if (!(request.flags & OI2_FLAG_BROKER_UNAVAILABLE)) {
            java_result = (*env)->CallIntMethod(env, service, method,
                                                 (jint)duplicate_fd);
            if ((*env)->ExceptionCheck(env)) {
                (*env)->ExceptionDescribe(env);
                (*env)->ExceptionClear(env);
                java_result = OI2_RESULT_PROTECT_FAILURE;
            }
            completion.result = (uint32_t)java_result;
            if (request.flags & OI2_FLAG_BIND_FAILURE) {
                completion.result = OI2_RESULT_BIND_FAILURE;
            } else if (request.flags & OI2_FLAG_PROTECT_FAILURE) {
                completion.result = OI2_RESULT_PROTECT_FAILURE;
            }
            completion.fault_reason = completion.result;
        }
        if (request.reserved > 0 && request.reserved <= 1000) {
            usleep((useconds_t)request.reserved * 1000U);
        }
        log_line(file,
                 "oi2 request token=%llu generation=%llu family=%u kind=%u flags=%u java-result=%d result=%u duplicate-fd=%d",
                 (unsigned long long)request.token,
                 (unsigned long long)request.generation, request.family,
                 request.kind, request.flags, (int)java_result,
                 completion.result, duplicate_fd);
        close(duplicate_fd);
        log_line(file, "oi2 duplicate close token=%llu fd=%d",
                 (unsigned long long)request.token, duplicate_fd);
        if (send_oi2_completion(completion_fd, &completion) < 0) {
            log_line(file, "oi2 completion send failed token=%llu errno=%d %s",
                     (unsigned long long)request.token, errno, strerror(errno));
            break;
        }
    }
    log_line(file, "oi2 android broker stop");
    if (file) {
        fclose(file);
    }
    if (attached) {
        (*g_jvm)->DetachCurrentThread(g_jvm);
    }
    return NULL;
}

static void stop_oi2_broker(JNIEnv *env) {
    pthread_mutex_lock(&g_lock);
    bool was_running = g_oi2_broker_running;
    int request_fd = g_oi2_request_fd;
    int completion_fd = g_oi2_completion_fd;
    jobject service = g_oi2_service;
    g_oi2_broker_running = false;
    g_oi2_request_fd = -1;
    g_oi2_completion_fd = -1;
    g_oi2_service = NULL;
    g_oi2_method = NULL;
    pthread_mutex_unlock(&g_lock);

    if (request_fd >= 0) {
        shutdown(request_fd, SHUT_RDWR);
        close(request_fd);
    }
    if (completion_fd >= 0) {
        shutdown(completion_fd, SHUT_RDWR);
        close(completion_fd);
    }
    if (was_running) {
        pthread_join(g_oi2_broker_thread, NULL);
    }
    if (service) {
        (*env)->DeleteGlobalRef(env, service);
    }
}

static int find_wlan_ipv4(char *address, size_t address_len) {
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces) < 0) {
        return -1;
    }
    int result = -1;
    for (struct ifaddrs *it = interfaces; it; it = it->ifa_next) {
        if (!it->ifa_addr || strcmp(it->ifa_name, "wlan0") != 0 ||
            it->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        struct sockaddr_in *addr = (struct sockaddr_in *)it->ifa_addr;
        if (inet_ntop(AF_INET, &addr->sin_addr, address, address_len)) {
            result = 0;
            break;
        }
    }
    freeifaddrs(interfaces);
    return result;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    g_jvm = vm;
    return JNI_VERSION_1_6;
}

static void clear_owner_lookup(JNIEnv *env) {
    pthread_mutex_lock(&g_lock);
    jobject owner = g_owner_lookup;
    g_owner_lookup = NULL;
    g_owner_lookup_method = NULL;
    pthread_mutex_unlock(&g_lock);

    if (owner) {
        (*env)->DeleteGlobalRef(env, owner);
    }
}

static int init_owner_lookup(JNIEnv *env, jclass clazz, jobject owner_lookup,
                             jobject *owner_global_out, jmethodID *owner_method_out) {
    if (!g_jvm && (*env)->GetJavaVM(env, &g_jvm) != JNI_OK) {
        return -1;
    }
    if (!owner_lookup) {
        return -2;
    }

    jmethodID owner_method = (*env)->GetMethodID(env, clazz, "queryConnectionOwnerUidForPacket",
                                                 "(ILjava/lang/String;ILjava/lang/String;I)I");
    if (!owner_method || (*env)->ExceptionCheck(env)) {
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
        }
        return -3;
    }

    jobject owner_global = (*env)->NewGlobalRef(env, owner_lookup);
    if (!owner_global) {
        return -4;
    }

    *owner_global_out = owner_global;
    *owner_method_out = owner_method;
    return 0;
}

static int query_owner_uid(const owner_query_t *query) {
    if (!query || !query->valid || !g_jvm) {
        return -1;
    }

    JNIEnv *env = NULL;
    bool detach = false;
    jint env_rc = (*g_jvm)->GetEnv(g_jvm, (void **)&env, JNI_VERSION_1_6);
    if (env_rc == JNI_EDETACHED) {
        if ((*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL) != JNI_OK) {
            return -1;
        }
        detach = true;
    } else if (env_rc != JNI_OK || !env) {
        return -1;
    }

    pthread_mutex_lock(&g_lock);
    jobject owner = g_owner_lookup;
    jmethodID method = g_owner_lookup_method;
    pthread_mutex_unlock(&g_lock);
    if (!owner || !method) {
        if (detach) {
            (*g_jvm)->DetachCurrentThread(g_jvm);
        }
        return -1;
    }

    jstring local_addr = (*env)->NewStringUTF(env, query->local_addr);
    jstring remote_addr = (*env)->NewStringUTF(env, query->remote_addr);
    if (!local_addr || !remote_addr) {
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
        }
        if (local_addr) {
            (*env)->DeleteLocalRef(env, local_addr);
        }
        if (remote_addr) {
            (*env)->DeleteLocalRef(env, remote_addr);
        }
        if (detach) {
            (*g_jvm)->DetachCurrentThread(g_jvm);
        }
        return -1;
    }

    jint uid = (*env)->CallIntMethod(env, owner, method, (jint)query->protocol,
                                     local_addr, (jint)query->local_port,
                                     remote_addr, (jint)query->remote_port);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        uid = -1;
    }

    (*env)->DeleteLocalRef(env, local_addr);
    (*env)->DeleteLocalRef(env, remote_addr);
    if (detach) {
        (*g_jvm)->DetachCurrentThread(g_jvm);
    }
    return (int)uid;
}

static int query_owner_uid_with_bounded_wait(const owner_query_t *query,
                                             bool wait_for_resolution,
                                             int *attempts_out) {
    int attempts = 1;
    int uid = query_owner_uid(query);
    if (!wait_for_resolution || uid >= 0) {
        if (attempts_out) {
            *attempts_out = attempts;
        }
        return uid;
    }

    /* UidAttributionContract.lookup() is intentionally sentinel-first: the
     * first call submits bounded async Android ConnectivityManager work and
     * returns INVALID_UID.  A policy gate must not decide from that sentinel.
     * Poll the same canonical key briefly until the completion is visible as a
     * cache hit, then enforce against the resolved UID. */
    for (int attempt = 0; attempt < 20; attempt++) {
        usleep(25000);
        attempts++;
        uid = query_owner_uid(query);
        if (uid >= 0) {
            break;
        }
    }
    if (attempts_out) {
        *attempts_out = attempts;
    }
    return uid;
}

static bool path_exists(const char *path) {
    return access(path, F_OK) == 0;
}

static int mkdir_p(const char *path) {
    char tmp[PATH_BUF_SIZE];
    size_t len = strnlen(path, sizeof(tmp));

    if (len == 0 || len >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') {
            continue;
        }
        *p = '\0';
        if (mkdir(tmp, 0700) < 0 && errno != EEXIST) {
            return -1;
        }
        *p = '/';
    }

    if (mkdir(tmp, 0700) < 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

static int write_text_file(const char *path, const char *text) {
    FILE *file = fopen(path, "w");
    if (!file) {
        return -1;
    }
    fputs(text, file);
    int rc = ferror(file) ? -1 : 0;
    fclose(file);
    return rc;
}

static int set_cloexec(int fd, bool enabled) {
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0) {
        return -1;
    }
    if (enabled) {
        flags |= FD_CLOEXEC;
    } else {
        flags &= ~FD_CLOEXEC;
    }
    return fcntl(fd, F_SETFD, flags);
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void terminate_child(pid_t pid) {
    if (pid <= 0) {
        return;
    }

    for (int i = 0; i < 10; i++) {
        int status = 0;
        pid_t rv = waitpid(pid, &status, WNOHANG);
        if (rv == pid || (rv < 0 && errno == ECHILD)) {
            return;
        }
        usleep(100000);
    }

    kill(pid, SIGTERM);
    for (int i = 0; i < 10; i++) {
        int status = 0;
        pid_t rv = waitpid(pid, &status, WNOHANG);
        if (rv == pid || (rv < 0 && errno == ECHILD)) {
            return;
        }
        usleep(100000);
    }

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
}

static void append_cli_output(FILE *file, const char *label, const char *buf, ssize_t len) {
    if (!file || len <= 0) {
        return;
    }
    struct timespec ts;
    uint64_t monotonic_ns = 0;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        monotonic_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    }
    fprintf(file, "\n# cli_monotonic_ns=%llu\n# %s\n",
            (unsigned long long)monotonic_ns, label);
    for (ssize_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c == '\n' || c == '\r' || c == '\t' || (c >= 32 && c < 127)) {
            fputc(c, file);
        }
    }
    if (buf[len - 1] != '\n') {
        fputc('\n', file);
    }
    fflush(file);
}

static int run_cli_command_capture(const char *sock_path, const char *command,
                                   FILE *file, char *capture,
                                   size_t capture_size) {
    if (strlen(sock_path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        log_line(file, "cli socket path too long: %s", sock_path);
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        log_line(file, "cli socket create failed errno=%d %s", errno, strerror(errno));
        return -1;
    }
    set_cloexec(fd, true);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_line(file, "cli connect failed errno=%d %s path=%s", errno, strerror(errno), sock_path);
        close(fd);
        return -1;
    }

    char input[PATH_BUF_SIZE * 2];
    int input_len = snprintf(input, sizeof(input), "%s\nquit\n", command);
    if (input_len < 0 || (size_t)input_len >= sizeof(input)) {
        log_line(file, "cli command too long bytes=%d", input_len);
        close(fd);
        return -1;
    }
    if (send(fd, input, (size_t)input_len, MSG_NOSIGNAL) < 0) {
        log_line(file, "cli write failed errno=%d %s", errno, strerror(errno));
        close(fd);
        return -1;
    }

    char output[8192];
    ssize_t total = 0;
    while (total < (ssize_t)sizeof(output)) {
        struct pollfd pfd = {
                .fd = fd,
                .events = POLLIN,
        };
        int ready = poll(&pfd, 1, 1000);
        if (ready <= 0) {
            break;
        }
        ssize_t n = read(fd, output + total, sizeof(output) - (size_t)total);
        if (n <= 0) {
            break;
        }
        total += n;
    }
    if (total >= (ssize_t)sizeof(output)) {
        output[sizeof(output) - 1] = '\0';
    } else {
        output[total] = '\0';
    }
    if (capture && capture_size > 0) {
        size_t copy_len = total > 0 ? (size_t)total : 0;
        if (copy_len >= capture_size) {
            copy_len = capture_size - 1;
        }
        if (copy_len > 0) {
            memcpy(capture, output, copy_len);
        }
        capture[copy_len] = '\0';
    }
    append_cli_output(file, command, output, total);
    close(fd);
    if (total <= 0) {
        return -1;
    }
    if (strstr(output, "unknown input") || strstr(output, "show: unknown") ||
        strstr(output, "error:") || strstr(output, "Error:")) {
        return -2;
    }
    if (strcmp(command, "show plugins") == 0 &&
        !strstr(output, "hev_external_driver_poc_plugin")) {
        return -3;
    }
    return 0;
}

static int run_cli_command(const char *sock_path, const char *command, FILE *file) {
    return run_cli_command_capture(sock_path, command, file, NULL, 0);
}

static bool oi5_android_runner_alive(void) {
    pthread_mutex_lock(&g_lock);
    bool alive = g_vpp_monitor_running && g_oi5_mode;
    pthread_mutex_unlock(&g_lock);
    return alive;
}

static void oi5_android_wait_ms(unsigned int milliseconds) {
    unsigned int remaining = milliseconds;
    while (remaining > 0 && oi5_android_runner_alive()) {
        unsigned int slice = remaining < 5U ? remaining : 5U;
        usleep(slice * 1000U);
        remaining -= slice;
    }
}

static int oi5_android_cli(FILE *file, const char *sock_path, const char *command) {
    if (!oi5_android_runner_alive()) {
        return -1;
    }
    log_line(file, "oi5 android cli-begin command=%s", command);
    int rc = run_cli_command(sock_path, command, file);
    log_line(file, "oi5 android cli-end command=%s rc=%d", command, rc);
    return rc;
}

static int oi5_android_cli_capture(FILE *file, const char *sock_path,
                                   const char *command, char *capture,
                                   size_t capture_size) {
    if (!oi5_android_runner_alive()) {
        return -1;
    }
    log_line(file, "oi5 android cli-begin command=%s", command);
    int rc = run_cli_command_capture(sock_path, command, file, capture,
                                      capture_size);
    log_line(file, "oi5 android cli-end command=%s rc=%d", command, rc);
    return rc;
}

static int oi5_android_show(FILE *file, const char *sock_path, const char *label) {
    log_line(file, "oi5 android snapshot label=%s", label);
    return oi5_android_cli(file, sock_path, "show sakamoto-oi3");
}

static int oi5_android_wait_for_no_reply_admission(FILE *file,
                                                    const char *sock_path,
                                                    const char *label) {
    /* The run command only enqueues the first owner token.  Do not issue a
     * lifecycle stop until the owner has admitted the broker and endpoint;
     * otherwise a valid bounded stop is indistinguishable from a runner race
     * (broker=0/0, endpoint=0/0).  Keep the wait bounded and retain every
     * snapshot in the Android evidence log. */
    for (unsigned int attempt = 0;
         attempt < 80 && oi5_android_runner_alive(); attempt++) {
        char snapshot[8192];
        int rc = oi5_android_cli_capture(file, sock_path,
                                          "show sakamoto-oi3", snapshot,
                                          sizeof(snapshot));
        if (rc != 0) {
            return rc;
        }
        if (strstr(snapshot, "active=1") &&
            strstr(snapshot, "broker bind=1 protect=1") &&
            strstr(snapshot, "endpoint=1/0")) {
            log_line(file, "oi5 android admission label=%s attempts=%u",
                     label, attempt + 1);
            return 0;
        }
        if (strstr(snapshot, "state=DONE") &&
            strstr(snapshot, "broker bind=1 protect=1") &&
            strstr(snapshot, "endpoint=1/0") &&
            !strstr(snapshot, "error=unexpected-")) {
            log_line(file,
                     "oi5 android admission label=%s natural-complete attempts=%u",
                     label, attempt + 1);
            return 1;
        }
        oi5_android_wait_ms(25);
    }
    log_line(file, "oi5 android admission result=FAIL label=%s", label);
    return -1;
}

static void oi5_android_sequence(const char *sock_path, const char *hev_lib) {
    FILE *file = fopen(g_oi5_log, "a");
    int failures = 0;
    char run_no_reply[PATH_BUF_SIZE + 128];
    char run_tcp4[PATH_BUF_SIZE + 128];
    char run_udp4[PATH_BUF_SIZE + 128];
    snprintf(run_no_reply, sizeof(run_no_reply),
             "sakamoto-oi3 run cell no-reply target-thread 1 lib %s", hev_lib);
    snprintf(run_tcp4, sizeof(run_tcp4),
             "sakamoto-oi3 run cell tcp4 target-thread 1 lib %s", hev_lib);
    snprintf(run_udp4, sizeof(run_udp4),
             "sakamoto-oi3 run cell udp4 target-thread 1 lib %s", hev_lib);

    /* VPP's CLI socket is created by the child after fork.  Keep this wait
     * bounded and make a missing socket a visible failed Android cell. */
    for (unsigned int wait = 0; wait < 120 && oi5_android_runner_alive(); wait++) {
        if (access(sock_path, F_OK) == 0) {
            break;
        }
        usleep(25000);
    }
    if (!oi5_android_runner_alive() || access(sock_path, F_OK) != 0) {
        log_line(file, "oi5 android runner result=FAIL reason=cli-socket-not-ready");
        if (file) fclose(file);
        return;
    }
    log_line(file, "oi5 android runner start route=10.200.0.0/24 default-routes=none "
                   "underlay=loopback owner=1");
    if (oi5_android_cli(file, sock_path, "show plugins") != 0) {
        failures++;
    }

    /* Normal stop: interrupt a bounded waiting/no-reply owner and snapshot
     * the cleanup before the next generation is admitted. */
    log_line(file, "oi5 android cell=normal-stop begin");
    if (oi5_android_cli(file, sock_path, run_no_reply) != 0) {
        failures++;
    }
    int normal_state = oi5_android_wait_for_no_reply_admission(
        file, sock_path, "normal-stop");
    if (normal_state < 0) {
        failures++;
    }
    if (normal_state == 0 &&
        oi5_android_cli(file, sock_path, "sakamoto-oi3 stop") != 0) {
        failures++;
    }
    oi5_android_wait_ms(500);
    if (oi5_android_show(file, sock_path, "normal-stop") != 0) {
        failures++;
    }
    log_line(file, "oi5 android cell=normal-stop end");

    /* Fault stop: use the explicit bounded fault seam while the no-reply
     * owner is active.  The plugin records fault-injected=1 and performs its
     * ordinary quiesce/drain/close path. */
    log_line(file, "oi5 android cell=fault-stop begin");
    if (oi5_android_cli(file, sock_path, run_no_reply) != 0) {
        failures++;
    }
    /* Fault is deliberately issued immediately after the run command.  The
     * run command marks the generation active synchronously; waiting for the
     * short synthetic no-reply loop to settle would make the fault seam race
     * with its natural DONE transition. */
    oi5_android_wait_ms(1);
    if (oi5_android_cli(file, sock_path, "sakamoto-oi3 fault") != 0) {
        failures++;
    }
    oi5_android_wait_ms(500);
    if (oi5_android_show(file, sock_path, "fault-stop") != 0) {
        failures++;
    }
    log_line(file, "oi5 android cell=fault-stop end");

    /* Restart: a fresh TCP4 flow must use the incremented generation/epoch
     * after the injected fault and settle its handshake/payload/FIN. */
    log_line(file, "oi5 android cell=restart begin");
    if (oi5_android_cli(file, sock_path, run_tcp4) != 0) {
        failures++;
    }
    oi5_android_wait_ms(1800);
    if (oi5_android_show(file, sock_path, "restart") != 0) {
        failures++;
    }
    log_line(file, "oi5 android cell=restart end");

    /* Underlay invalidation: two fresh flows are deliberately separated by a
     * generation transition.  The owner raw ledger emits the old/new
     * generation and epoch, and explicitly records old TCP reconnect=0 and
     * old UDP reuse=0 before admitting the new snapshot. */
    log_line(file, "oi5 android cell=underlay-invalidation begin");
    if (oi5_android_cli(file, sock_path, run_udp4) != 0) {
        failures++;
    }
    oi5_android_wait_ms(1800);
    if (oi5_android_show(file, sock_path, "underlay-old-udp-settled") != 0) {
        failures++;
    }
    if (oi5_android_cli(file, sock_path, run_tcp4) != 0) {
        failures++;
    }
    oi5_android_wait_ms(1800);
    if (oi5_android_show(file, sock_path, "underlay-new-tcp") != 0) {
        failures++;
    }
    log_line(file, "oi5 android cell=underlay-invalidation end");

    log_line(file, "oi5 android runner result=%s command-failures=%d residue=0",
             failures == 0 ? "PASS" : "FAIL", failures);
    if (file) fclose(file);
}

static uint16_t read_be16(const unsigned char *data) {
    return (uint16_t)(((uint16_t)data[0] << 8U) | (uint16_t)data[1]);
}

static bool parse_owner_query_ipv4(const unsigned char *buf, ssize_t len,
                                   owner_query_t *query) {
    if (!query || len < 20 || (buf[0] >> 4) != 4) {
        return false;
    }

    size_t packet_len = (size_t)len;
    size_t ihl = (size_t)(buf[0] & 0x0fU) * 4U;
    if (ihl < 20 || packet_len < ihl + 4U) {
        return false;
    }

    int protocol = (int)buf[9];
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
        return false;
    }
    size_t min_l4 = protocol == IPPROTO_UDP ? 8U : 4U;
    if (packet_len < ihl + min_l4) {
        return false;
    }

    memset(query, 0, sizeof(*query));
    query->valid = true;
    query->protocol = protocol;
    query->local_port = read_be16(buf + ihl);
    query->remote_port = read_be16(buf + ihl + 2U);
    if (!inet_ntop(AF_INET, buf + 12, query->local_addr, sizeof(query->local_addr)) ||
        !inet_ntop(AF_INET, buf + 16, query->remote_addr, sizeof(query->remote_addr))) {
        query->valid = false;
        return false;
    }
    return true;
}

static bool parse_owner_query_ipv6(const unsigned char *buf, ssize_t len,
                                   owner_query_t *query) {
    if (!query || len < 40 || (buf[0] >> 4) != 6) {
        return false;
    }

    size_t packet_len = (size_t)len;
    size_t offset = 40U;
    int protocol = (int)buf[6];
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
        return false;
    }
    size_t min_l4 = protocol == IPPROTO_UDP ? 8U : 4U;
    if (packet_len < offset + min_l4) {
        return false;
    }

    memset(query, 0, sizeof(*query));
    query->valid = true;
    query->protocol = protocol;
    query->local_port = read_be16(buf + offset);
    query->remote_port = read_be16(buf + offset + 2U);
    if (!inet_ntop(AF_INET6, buf + 8, query->local_addr, sizeof(query->local_addr)) ||
        !inet_ntop(AF_INET6, buf + 24, query->remote_addr, sizeof(query->remote_addr))) {
        query->valid = false;
        return false;
    }
    return true;
}

static bool parse_owner_query_packet(const unsigned char *buf, ssize_t len,
                                     owner_query_t *query) {
    if (!buf || len < 1) {
        return false;
    }
    unsigned int version = buf[0] >> 4;
    if (version == 4) {
        return parse_owner_query_ipv4(buf, len, query);
    }
    if (version == 6) {
        return parse_owner_query_ipv6(buf, len, query);
    }
    return false;
}

static bool owner_query_equal(const owner_query_t *a, const owner_query_t *b) {
    return a->valid && b->valid &&
           a->protocol == b->protocol &&
           a->local_port == b->local_port &&
           a->remote_port == b->remote_port &&
           strcmp(a->local_addr, b->local_addr) == 0 &&
           strcmp(a->remote_addr, b->remote_addr) == 0;
}

static int owner_cache_lookup(const owner_cache_entry_t *cache, const owner_query_t *query) {
    if (!cache || !query || !query->valid) {
        return -1;
    }
    for (int i = 0; i < OWNER_CACHE_SIZE; i++) {
        if (cache[i].valid && owner_query_equal(&cache[i].query, query)) {
            return cache[i].uid;
        }
    }
    return -1;
}

static void owner_cache_store(owner_cache_entry_t *cache, int *next_slot,
                              const owner_query_t *query, int uid) {
    if (!cache || !next_slot || !query || !query->valid || uid < 0) {
        return;
    }
    for (int i = 0; i < OWNER_CACHE_SIZE; i++) {
        if (cache[i].valid && owner_query_equal(&cache[i].query, query)) {
            cache[i].uid = uid;
            return;
        }
    }
    int slot = *next_slot;
    if (slot < 0 || slot >= OWNER_CACHE_SIZE) {
        slot = 0;
    }
    cache[slot].valid = true;
    cache[slot].query = *query;
    cache[slot].uid = uid;
    *next_slot = (slot + 1) % OWNER_CACHE_SIZE;
}

static void describe_packet(FILE *file, const unsigned char *buf, ssize_t len, int count) {
    if (len < 1) {
        log_line(file, "packet=%d len=%zd empty", count, len);
        return;
    }

    unsigned int version = buf[0] >> 4;
    if (version == 4 && len >= 20) {
        char src[INET_ADDRSTRLEN];
        char dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, buf + 12, src, sizeof(src));
        inet_ntop(AF_INET, buf + 16, dst, sizeof(dst));
        owner_query_t query;
        if (parse_owner_query_ipv4(buf, len, &query)) {
            int uid = query_owner_uid(&query);
            log_line(file, "packet=%d len=%zd ipv4 proto=%d %s:%u -> %s:%u ownerUid=%d",
                     count, len, query.protocol, query.local_addr,
                     (unsigned int)query.local_port, query.remote_addr,
                     (unsigned int)query.remote_port, uid);
        } else {
            log_line(file, "packet=%d len=%zd ipv4 proto=%u %s -> %s", count, len, buf[9],
                     src, dst);
        }
        return;
    }

    if (version == 6 && len >= 40) {
        char src[INET6_ADDRSTRLEN];
        char dst[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, buf + 8, src, sizeof(src));
        inet_ntop(AF_INET6, buf + 24, dst, sizeof(dst));
        owner_query_t query;
        if (parse_owner_query_ipv6(buf, len, &query)) {
            int uid = query_owner_uid(&query);
            log_line(file, "packet=%d len=%zd ipv6 proto=%d %s:%u -> %s:%u ownerUid=%d",
                     count, len, query.protocol, query.local_addr,
                     (unsigned int)query.local_port, query.remote_addr,
                     (unsigned int)query.remote_port, uid);
        } else {
            log_line(file, "packet=%d len=%zd ipv6 next=%u %s -> %s", count, len, buf[6],
                     src, dst);
        }
        return;
    }

    log_line(file, "packet=%d len=%zd version=%u short-or-unknown", count, len, version);
}

static uint16_t internet_checksum(const unsigned char *data, size_t len) {
    uint32_t sum = 0;

    while (len > 1) {
        sum += ((uint16_t)data[0] << 8) | data[1];
        data += 2;
        len -= 2;
    }
    if (len > 0) {
        sum += ((uint16_t)data[0] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xffffU) + (sum >> 16);
    }
    return htons((uint16_t)~sum);
}

static ssize_t reflect_icmp4(unsigned char *packet, ssize_t packet_len) {
    if (packet_len < 28 || (packet[0] >> 4) != 4) {
        return -1;
    }

    size_t ihl = (size_t)(packet[0] & 0x0fU) * 4U;
    uint16_t total_len_be;
    memcpy(&total_len_be, packet + 2, sizeof(total_len_be));
    size_t total_len = ntohs(total_len_be);
    if (ihl < 20 || total_len < ihl + 8 || total_len > (size_t)packet_len) {
        return -1;
    }
    if (packet[9] != IPPROTO_ICMP) {
        return -1;
    }
    if (packet[ihl] != 8 || packet[ihl + 1] != 0) {
        return -1;
    }

    unsigned char src[4];
    memcpy(src, packet + 12, sizeof(src));
    memcpy(packet + 12, packet + 16, sizeof(src));
    memcpy(packet + 16, src, sizeof(src));

    packet[8] = 64;
    packet[10] = 0;
    packet[11] = 0;
    uint16_t ip_sum = internet_checksum(packet, ihl);
    memcpy(packet + 10, &ip_sum, sizeof(ip_sum));

    packet[ihl] = 0;
    packet[ihl + 2] = 0;
    packet[ihl + 3] = 0;
    uint16_t icmp_sum = internet_checksum(packet + ihl, total_len - ihl);
    memcpy(packet + ihl + 2, &icmp_sum, sizeof(icmp_sum));
    return (ssize_t)total_len;
}

static void *vpp_shim_thread(void *arg) {
    (void)arg;
    unsigned char buf[BUF_SIZE];
    int count = 0;

    pthread_mutex_lock(&g_lock);
    int fd = g_vpp_shim_fd;
    char log_path[PATH_BUF_SIZE];
    snprintf(log_path, sizeof(log_path), "%s", g_vpp_shim_log);
    pthread_mutex_unlock(&g_lock);

    FILE *file = fopen(log_path, "a");
    log_line(file, "vpp shim driver start fd=%d", fd);

    while (1) {
        pthread_mutex_lock(&g_lock);
        bool running = g_vpp_shim_running;
        fd = g_vpp_shim_fd;
        pthread_mutex_unlock(&g_lock);
        if (!running || fd < 0) {
            break;
        }

        struct pollfd pfd = {
                .fd = fd,
                .events = POLLIN,
        };
        int ready = poll(&pfd, 1, 500);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EBADF) {
                pthread_mutex_lock(&g_lock);
                bool stopping = !g_vpp_shim_running;
                pthread_mutex_unlock(&g_lock);
                if (stopping) {
                    break;
                }
            }
            log_line(file, "shim poll error errno=%d %s", errno, strerror(errno));
            break;
        }
        if (ready == 0) {
            continue;
        }

        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            if (errno == EBADF) {
                pthread_mutex_lock(&g_lock);
                bool stopping = !g_vpp_shim_running;
                pthread_mutex_unlock(&g_lock);
                if (stopping) {
                    break;
                }
            }
            log_line(file, "shim read error errno=%d %s", errno, strerror(errno));
            break;
        }
        if (n == 0) {
            log_line(file, "shim read eof");
            break;
        }

        count++;
        describe_packet(file, buf, n, count);
        ssize_t reply_len = reflect_icmp4(buf, n);
        if (reply_len > 0) {
            ssize_t written = write(fd, buf, (size_t)reply_len);
            log_line(file, "shim reflected icmp len=%zd written=%zd", reply_len, written);
        }
    }

    log_line(file, "vpp shim driver stop packets=%d", count);
    if (file) {
        fclose(file);
    }
    return NULL;
}

static void drain_gate_tun_to_vpp(FILE *file, int tun_fd, int vpp_fd, int block_uid,
                                  unsigned char *buf, int *from_tun, int *dropped,
                                  int *forwarded, owner_cache_entry_t *owner_cache,
                                  int *owner_cache_next) {
    while (1) {
        ssize_t n = read(tun_fd, buf, BUF_SIZE);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            pthread_mutex_lock(&g_lock);
            bool stopping = !g_vpp_gate_running;
            pthread_mutex_unlock(&g_lock);
            if (!stopping) {
                log_line(file, "gate tun read error errno=%d %s", errno, strerror(errno));
            }
            return;
        }
        if (n == 0) {
            log_line(file, "gate tun read eof");
            return;
        }

        (*from_tun)++;
        owner_query_t query;
        bool have_owner = parse_owner_query_packet(buf, n, &query);
        int uid_attempts = 0;
        int uid = have_owner ? query_owner_uid_with_bounded_wait(
                &query, block_uid >= 0, &uid_attempts) : -1;
        bool cached_uid = false;
        if (have_owner) {
            if (uid >= 0) {
                owner_cache_store(owner_cache, owner_cache_next, &query, uid);
            } else {
                int cached = owner_cache_lookup(owner_cache, &query);
                if (cached >= 0) {
                    uid = cached;
                    cached_uid = true;
                }
            }
        }
        if (block_uid >= 0 && uid == block_uid) {
            (*dropped)++;
            if (have_owner) {
                log_line(file,
                         "gate drop packet=%d len=%zd proto=%d %s:%u -> %s:%u ownerUid=%d cached=%d lookup-attempts=%d",
                         *from_tun, n, query.protocol, query.local_addr,
                         (unsigned int)query.local_port, query.remote_addr,
                         (unsigned int)query.remote_port, uid, cached_uid ? 1 : 0,
                         uid_attempts);
            } else {
                log_line(file, "gate drop packet=%d len=%zd ownerUid=%d",
                         *from_tun, n, uid);
            }
            continue;
        }

        ssize_t written = write(vpp_fd, buf, (size_t)n);
        if (written != n) {
            log_line(file, "gate write-to-vpp error packet=%d len=%zd written=%zd errno=%d %s",
                     *from_tun, n, written, errno, strerror(errno));
            continue;
        }
        (*forwarded)++;
        if (have_owner) {
            log_line(file,
                     "gate forward packet=%d len=%zd proto=%d %s:%u -> %s:%u ownerUid=%d cached=%d lookup-attempts=%d",
                     *from_tun, n, query.protocol, query.local_addr,
                     (unsigned int)query.local_port, query.remote_addr,
                     (unsigned int)query.remote_port, uid, cached_uid ? 1 : 0,
                     uid_attempts);
        }
    }
}

static void drain_gate_vpp_to_tun(FILE *file, int tun_fd, int vpp_fd, unsigned char *buf,
                                  int *from_vpp, int *to_tun) {
    while (1) {
        ssize_t n = read(vpp_fd, buf, BUF_SIZE);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            pthread_mutex_lock(&g_lock);
            bool stopping = !g_vpp_gate_running;
            pthread_mutex_unlock(&g_lock);
            if (!stopping) {
                log_line(file, "gate vpp read error errno=%d %s", errno, strerror(errno));
            }
            return;
        }
        if (n == 0) {
            log_line(file, "gate vpp read eof");
            return;
        }

        (*from_vpp)++;
        ssize_t written = write(tun_fd, buf, (size_t)n);
        if (written != n) {
            log_line(file, "gate write-to-tun error packet=%d len=%zd written=%zd errno=%d %s",
                     *from_vpp, n, written, errno, strerror(errno));
            continue;
        }
        (*to_tun)++;
    }
}

static void *vpp_gate_thread(void *arg) {
    (void)arg;
    unsigned char buf[BUF_SIZE];
    int from_tun = 0;
    int from_vpp = 0;
    int forwarded = 0;
    int dropped = 0;
    int to_tun = 0;
    owner_cache_entry_t owner_cache[OWNER_CACHE_SIZE];
    int owner_cache_next = 0;
    memset(owner_cache, 0, sizeof(owner_cache));

    pthread_mutex_lock(&g_lock);
    int tun_fd = g_vpp_gate_tun_fd;
    int vpp_fd = g_vpp_gate_vpp_fd;
    int block_uid = g_vpp_gate_block_uid;
    char log_path[PATH_BUF_SIZE];
    snprintf(log_path, sizeof(log_path), "%s", g_vpp_gate_log);
    pthread_mutex_unlock(&g_lock);

    FILE *file = fopen(log_path, "a");
    log_line(file, "gate start tun-fd=%d vpp-fd=%d block-owner-uid=%d",
             tun_fd, vpp_fd, block_uid);

    set_nonblocking(tun_fd);
    set_nonblocking(vpp_fd);

    while (1) {
        pthread_mutex_lock(&g_lock);
        bool running = g_vpp_gate_running;
        tun_fd = g_vpp_gate_tun_fd;
        vpp_fd = g_vpp_gate_vpp_fd;
        block_uid = g_vpp_gate_block_uid;
        pthread_mutex_unlock(&g_lock);
        if (!running || tun_fd < 0 || vpp_fd < 0) {
            break;
        }

        struct pollfd pfds[2] = {
                {.fd = tun_fd, .events = POLLIN},
                {.fd = vpp_fd, .events = POLLIN},
        };
        int ready = poll(pfds, 2, 500);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EBADF) {
                pthread_mutex_lock(&g_lock);
                bool stopping = !g_vpp_gate_running;
                pthread_mutex_unlock(&g_lock);
                if (stopping) {
                    break;
                }
            }
            log_line(file, "gate poll error errno=%d %s", errno, strerror(errno));
            break;
        }
        if (ready == 0) {
            continue;
        }

        if (pfds[0].revents & POLLIN) {
            drain_gate_tun_to_vpp(file, tun_fd, vpp_fd, block_uid, buf,
                                  &from_tun, &dropped, &forwarded, owner_cache,
                                  &owner_cache_next);
        }
        if (pfds[1].revents & POLLIN) {
            drain_gate_vpp_to_tun(file, tun_fd, vpp_fd, buf, &from_vpp, &to_tun);
        }
    }

    log_line(file, "gate stop from-tun=%d forwarded=%d dropped=%d from-vpp=%d to-tun=%d",
             from_tun, forwarded, dropped, from_vpp, to_tun);
    if (file) {
        fclose(file);
    }
    return NULL;
}

static bool parse_resolver_query_line(const char *line, owner_query_t *query) {
    char family[8];
    char local_addr[INET6_ADDRSTRLEN];
    char remote_addr[INET6_ADDRSTRLEN];
    char cell_id[64];
    char stage_id[128];
    unsigned long long request_id = 0;
    int protocol = 0;
    unsigned int local_port = 0;
    unsigned int remote_port = 0;
    int base_length = 0;

    if (!line || !query) {
        return false;
    }
    if (sscanf(line, "resolve %7s proto %d %45s %u %45s %u%n",
               family, &protocol, local_addr, &local_port,
               remote_addr, &remote_port, &base_length) != 6) {
        return false;
    }
    if ((strcmp(family, "ip4") != 0 && strcmp(family, "ip6") != 0) ||
        (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) ||
        local_port > 65535U || remote_port > 65535U) {
        return false;
    }

    memset(query, 0, sizeof(*query));
    query->valid = true;
    query->protocol = protocol;
    query->local_port = (uint16_t)local_port;
    query->remote_port = (uint16_t)remote_port;
    snprintf(query->local_addr, sizeof(query->local_addr), "%s", local_addr);
    snprintf(query->remote_addr, sizeof(query->remote_addr), "%s", remote_addr);

    /* Metadata is optional for compatibility with older VPP plugins, but a
     * tuple without it is deliberately not authoritative for A2-1.  The
     * producer captures cell/stage/request before writing; completion must
     * consume that immutable request metadata instead of copy_stage(). */
    if (sscanf(line + base_length,
               " cell %63s stage %127s request %llu",
               cell_id, stage_id, &request_id) == 3 && request_id > 0) {
        query->correlation_valid = true;
        query->request_id = (uint64_t)request_id;
        snprintf(query->cell_id, sizeof(query->cell_id), "%s", cell_id);
        snprintf(query->stage_id, sizeof(query->stage_id), "%s", stage_id);
    }
    return true;
}

static void resolver_process_line(FILE *file, int fd, const char *line, int *queries) {
    owner_query_t query;
    int uid = -1;
    int block_uid = -1;

    (*queries)++;
    if (parse_resolver_query_line(line, &query)) {
        uid = query_owner_uid(&query);
        pthread_mutex_lock(&g_lock);
        block_uid = g_vpp_resolver_block_uid;
        pthread_mutex_unlock(&g_lock);
        log_line(file, "resolver query=%d proto=%d %s:%u -> %s:%u uid=%d "
                       "cell=%s stage=%s request=%llu",
                 *queries, query.protocol, query.local_addr,
                 (unsigned int)query.local_port, query.remote_addr,
                 (unsigned int)query.remote_port, uid,
                 query.correlation_valid ? query.cell_id : "unknown",
                 query.correlation_valid ? query.stage_id : "unknown",
                 (unsigned long long)query.request_id);
        admission_set_from_query(&query, uid, !(block_uid >= 0 && uid == block_uid),
                                 file);
    } else {
        log_line(file, "resolver parse-fail query=%d line=%s", *queries, line);
    }

    char response[64];
    int len = snprintf(response, sizeof(response), "uid %d\n", uid);
    if (len > 0) {
        ssize_t written = write(fd, response, (size_t)len);
        if (written != len) {
            log_line(file, "resolver write error written=%zd errno=%d %s",
                     written, errno, strerror(errno));
        }
    }
}

static void *vpp_resolver_thread(void *arg) {
    (void)arg;
    char buffer[1024];
    size_t buffered = 0;
    int queries = 0;

    pthread_mutex_lock(&g_lock);
    int fd = g_vpp_resolver_fd;
    char log_path[PATH_BUF_SIZE];
    snprintf(log_path, sizeof(log_path), "%s", g_vpp_resolver_log);
    pthread_mutex_unlock(&g_lock);

    FILE *file = fopen(log_path, "a");
    log_line(file, "resolver start fd=%d", fd);

    while (1) {
        pthread_mutex_lock(&g_lock);
        bool running = g_vpp_resolver_running;
        fd = g_vpp_resolver_fd;
        pthread_mutex_unlock(&g_lock);
        if (!running || fd < 0) {
            break;
        }

        struct pollfd pfd = {
                .fd = fd,
                .events = POLLIN,
        };
        int ready = poll(&pfd, 1, 500);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EBADF) {
                pthread_mutex_lock(&g_lock);
                bool stopping = !g_vpp_resolver_running;
                pthread_mutex_unlock(&g_lock);
                if (stopping) {
                    break;
                }
            }
            log_line(file, "resolver poll error errno=%d %s", errno, strerror(errno));
            break;
        }
        if (ready == 0) {
            continue;
        }

        ssize_t n = read(fd, buffer + buffered, sizeof(buffer) - buffered - 1U);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            log_line(file, "resolver read error errno=%d %s", errno, strerror(errno));
            break;
        }
        if (n == 0) {
            log_line(file, "resolver read eof");
            break;
        }
        buffered += (size_t)n;
        buffer[buffered] = '\0';

        char *line_start = buffer;
        while (1) {
            char *newline = strchr(line_start, '\n');
            if (!newline) {
                break;
            }
            *newline = '\0';
            resolver_process_line(file, fd, line_start, &queries);
            line_start = newline + 1;
        }

        size_t remaining = strlen(line_start);
        if (remaining > 0 && line_start != buffer) {
            memmove(buffer, line_start, remaining);
        }
        buffered = remaining;
        if (buffered >= sizeof(buffer) - 1U) {
            log_line(file, "resolver buffer overflow, dropping partial query");
            buffered = 0;
        }
    }

    log_line(file, "resolver stop queries=%d", queries);
    if (file) {
        fclose(file);
    }
    return NULL;
}

static void *probe_thread(void *arg) {
    (void)arg;
    unsigned char buf[BUF_SIZE];
    int count = 0;
    FILE *file = fopen(g_log_path, "a");

    log_line(file, "probe start fd=%d max_packets=%d", g_fd, g_max_packets);

    while (1) {
        pthread_mutex_lock(&g_lock);
        bool running = g_running;
        int fd = g_fd;
        pthread_mutex_unlock(&g_lock);

        if (!running || fd < 0) {
            break;
        }

        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(10000);
                continue;
            }
            log_line(file, "read error errno=%d %s", errno, strerror(errno));
            break;
        }
        if (n == 0) {
            log_line(file, "read eof");
            break;
        }

        count++;
        if (g_max_packets <= 0 || count <= g_max_packets) {
            describe_packet(file, buf, n, count);
        }
    }

    log_line(file, "probe stop packets=%d", count);
    if (file) {
        fclose(file);
    }
    return NULL;
}

static int update_vpp_stage_cli(const char *stage) {
    char command[256];
    char sock_path[PATH_BUF_SIZE];
    char log_path[PATH_BUF_SIZE];

    if (!stage || !stage[0] || strlen(stage) >= 160U) {
        return -1;
    }
    for (const char *cursor = stage; *cursor; cursor++) {
        if (!(isalnum((unsigned char)*cursor) || *cursor == '-' || *cursor == '_')) {
            return -1;
        }
    }
    int command_len = snprintf(command, sizeof(command), "tun-poc stage %s", stage);
    if (command_len <= 0 || (size_t)command_len >= sizeof(command)) {
        return -1;
    }

    for (int attempt = 0; attempt < 30; attempt++) {
        pthread_mutex_lock(&g_lock);
        bool running = g_vpp_monitor_running;
        snprintf(sock_path, sizeof(sock_path), "%s", g_vpp_cli_sock);
        snprintf(log_path, sizeof(log_path), "%s", g_vpp_cli_log);
        pthread_mutex_unlock(&g_lock);
        if (!running) {
            return -1;
        }
        if (access(sock_path, F_OK) != 0) {
            usleep(100000);
            continue;
        }
        FILE *file = fopen(log_path, "a");
        int rc = run_cli_command(sock_path, command, file);
        if (file) {
            fclose(file);
        }
        if (rc == 0) {
            return 0;
        }
        usleep(100000);
    }
    return -1;
}

static int update_vpp_underlay_epoch_cli(uint64_t epoch, int64_t physical_handle,
                                         bool available) {
    char command[256];
    char sock_path[PATH_BUF_SIZE];
    char log_path[PATH_BUF_SIZE];
    int command_len = snprintf(command, sizeof(command),
                               "sakamoto-oi3 underlay epoch %llu handle %lld available %u",
                               (unsigned long long)epoch,
                               (long long)physical_handle, available ? 1U : 0U);
    if (command_len <= 0 || (size_t)command_len >= sizeof(command)) {
        return -1;
    }

    pthread_mutex_lock(&g_underlay_epoch_cli_lock);
    int result = -1;
    /* nativeStartVppProbe returns before VPP has necessarily created its CLI
     * socket.  Keep the callback handoff bounded and retry until the child is
     * ready, while serializing concurrent onAvailable/onLost callbacks. */
    for (int attempt = 0; attempt < 40; attempt++) {
        pthread_mutex_lock(&g_lock);
        bool running = g_vpp_monitor_running;
        snprintf(sock_path, sizeof(sock_path), "%s", g_vpp_cli_sock);
        snprintf(log_path, sizeof(log_path), "%s", g_vpp_cli_log);
        pthread_mutex_unlock(&g_lock);
        if (!running) {
            break;
        }
        if (access(sock_path, F_OK) != 0) {
            usleep(75000);
            continue;
        }
        FILE *file = fopen(log_path, "a");
        result = run_cli_command(sock_path, command, file);
        if (file) {
            fclose(file);
        }
        if (result == 0) {
            break;
        }
        usleep(75000);
    }
    pthread_mutex_unlock(&g_underlay_epoch_cli_lock);
    return result;
}

/* Test-only C2 control seam.  The Java service may request only the bounded
 * lifecycle verbs; it cannot pass an arbitrary VPP CLI command.  The command
 * is serialized with underlay publication so a callback snapshot and a stop /
 * fault cannot interleave on the same app-owned CLI socket. */
JNIEXPORT jint JNICALL
Java_com_sakamoto_snort_vpnlite_SnortVpnService_nativeRunVppOi3Control(
        JNIEnv *env, jclass clazz, jstring control_arg) {
    (void)clazz;
    const char *control = control_arg
            ? (*env)->GetStringUTFChars(env, control_arg, NULL) : NULL;
    if (!control) {
        return -1;
    }
    if (strcmp(control, "show") != 0 && strcmp(control, "stop") != 0
            && strcmp(control, "fault") != 0
            && strcmp(control, "multi-show") != 0
            && strcmp(control, "multi-stop") != 0
            && strcmp(control, "multi-fault-0") != 0
            && strcmp(control, "multi-fault-1") != 0) {
        (*env)->ReleaseStringUTFChars(env, control_arg, control);
        return -2;
    }

    char sock_path[PATH_BUF_SIZE];
    char log_path[PATH_BUF_SIZE];
    pthread_mutex_lock(&g_underlay_epoch_cli_lock);
    pthread_mutex_lock(&g_lock);
    bool running = g_vpp_monitor_running && g_vpp_cli_sock[0] != '\0';
    snprintf(sock_path, sizeof(sock_path), "%s", g_vpp_cli_sock);
    snprintf(log_path, sizeof(log_path), "%s", g_vpp_cli_log);
    pthread_mutex_unlock(&g_lock);
    if (!running || access(sock_path, F_OK) != 0) {
        pthread_mutex_unlock(&g_underlay_epoch_cli_lock);
        (*env)->ReleaseStringUTFChars(env, control_arg, control);
        return -3;
    }

    char command[96];
    int command_len;
    if (strcmp(control, "show") == 0)
        command_len = snprintf(command, sizeof(command), "show sakamoto-oi3");
    else if (strcmp(control, "multi-show") == 0)
        command_len = snprintf(command, sizeof(command), "show sakamoto-oi3 multi");
    else if (strcmp(control, "multi-stop") == 0)
        command_len = snprintf(command, sizeof(command), "sakamoto-oi3 multi stop");
    else if (strcmp(control, "multi-fault-0") == 0)
        command_len = snprintf(command, sizeof(command), "sakamoto-oi3 multi fault owner 0");
    else if (strcmp(control, "multi-fault-1") == 0)
        command_len = snprintf(command, sizeof(command), "sakamoto-oi3 multi fault owner 1");
    else
        command_len = snprintf(command, sizeof(command), "sakamoto-oi3 %s", control);
    int result = -4;
    if (command_len > 0 && (size_t)command_len < sizeof(command)) {
        FILE *file = fopen(log_path, "a");
        result = run_cli_command(sock_path, command, file);
        if (file) {
            fclose(file);
        }
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                            "OI3 control command=%s rc=%d", command, result);
    }
    pthread_mutex_unlock(&g_underlay_epoch_cli_lock);
    (*env)->ReleaseStringUTFChars(env, control_arg, control);
    return result;
}

JNIEXPORT void JNICALL
Java_com_sakamoto_snort_vpnlite_SnortVpnService_nativeSetVppStage(
        JNIEnv *env, jclass clazz, jstring cell_arg, jstring stage_arg) {
    (void)clazz;
    const char *cell = cell_arg ? (*env)->GetStringUTFChars(env, cell_arg, NULL) : NULL;
    const char *stage = stage_arg ? (*env)->GetStringUTFChars(env, stage_arg, NULL) : NULL;
    pthread_mutex_lock(&g_lock);
    snprintf(g_stage_cell, sizeof(g_stage_cell), "%s", cell && *cell ? cell : "A2-4");
    snprintf(g_stage_id, sizeof(g_stage_id), "%s", stage && *stage ? stage : "unknown");
    pthread_mutex_unlock(&g_lock);
    (void) update_vpp_stage_cli(stage && *stage ? stage : "unknown");
    if (cell) {
        (*env)->ReleaseStringUTFChars(env, cell_arg, cell);
    }
    if (stage) {
        (*env)->ReleaseStringUTFChars(env, stage_arg, stage);
    }
}

JNIEXPORT void JNICALL
Java_com_sakamoto_snort_vpnlite_SnortVpnService_nativeSetVppUnderlayEpoch(
        JNIEnv *env, jclass clazz, jlong epoch_arg, jlong physical_handle_arg,
        jboolean available_arg) {
    (void)env;
    (void)clazz;
    if (epoch_arg <= 0) {
        return;
    }
    uint64_t epoch = (uint64_t)epoch_arg;
    int64_t physical_handle = (int64_t)physical_handle_arg;
    bool available = available_arg == JNI_TRUE;
    pthread_mutex_lock(&g_lock);
    g_vpp_underlay_epoch = epoch;
    g_vpp_underlay_handle = physical_handle;
    g_vpp_underlay_available = available;
    pthread_mutex_unlock(&g_lock);
    int rc = update_vpp_underlay_epoch_cli(epoch, physical_handle, available);
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                        "OI3 underlay epoch epoch=%llu physicalHandle=%lld available=%d cliRc=%d",
                        (unsigned long long)epoch, (long long)physical_handle,
                        available ? 1 : 0, rc);
}

JNIEXPORT jint JNICALL
Java_com_sakamoto_snort_vpnlite_SnortVpnService_nativeStartProbe(
        JNIEnv *env, jclass clazz, jint fd, jstring log_path, jint max_packets,
        jobject owner_lookup) {
    const char *path = (*env)->GetStringUTFChars(env, log_path, NULL);
    if (!path) {
        close(fd);
        return -1;
    }

    if (!g_jvm && (*env)->GetJavaVM(env, &g_jvm) != JNI_OK) {
        (*env)->ReleaseStringUTFChars(env, log_path, path);
        close(fd);
        return -4;
    }

    jmethodID owner_method = NULL;
    jobject owner_global = NULL;
    if (owner_lookup) {
        owner_method = (*env)->GetMethodID(env, clazz, "queryConnectionOwnerUidForPacket",
                                           "(ILjava/lang/String;ILjava/lang/String;I)I");
        if (!owner_method || (*env)->ExceptionCheck(env)) {
            if ((*env)->ExceptionCheck(env)) {
                (*env)->ExceptionClear(env);
            }
            (*env)->ReleaseStringUTFChars(env, log_path, path);
            close(fd);
            return -5;
        }
        owner_global = (*env)->NewGlobalRef(env, owner_lookup);
        if (!owner_global) {
            (*env)->ReleaseStringUTFChars(env, log_path, path);
            close(fd);
            return -6;
        }
    }

    pthread_mutex_lock(&g_lock);
    if (g_running) {
        pthread_mutex_unlock(&g_lock);
        if (owner_global) {
            (*env)->DeleteGlobalRef(env, owner_global);
        }
        (*env)->ReleaseStringUTFChars(env, log_path, path);
        close(fd);
        return -2;
    }

    snprintf(g_log_path, sizeof(g_log_path), "%s", path);
    g_fd = fd;
    g_max_packets = max_packets;
    g_owner_lookup = owner_global;
    g_owner_lookup_method = owner_method;
    g_running = true;
    int flags = fcntl(g_fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(g_fd, F_SETFL, flags | O_NONBLOCK);
    }
    pthread_mutex_unlock(&g_lock);

    (*env)->ReleaseStringUTFChars(env, log_path, path);

    int rc = pthread_create(&g_thread, NULL, probe_thread, NULL);
    if (rc != 0) {
        pthread_mutex_lock(&g_lock);
        g_running = false;
        close(g_fd);
        g_fd = -1;
        g_owner_lookup = NULL;
        g_owner_lookup_method = NULL;
        pthread_mutex_unlock(&g_lock);
        if (owner_global) {
            (*env)->DeleteGlobalRef(env, owner_global);
        }
        return -3;
    }
    return 0;
}

JNIEXPORT void JNICALL
Java_com_sakamoto_snort_vpnlite_SnortVpnService_nativeStopProbe(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;

    pthread_mutex_lock(&g_lock);
    bool was_running = g_running;
    int fd = g_fd;
    g_running = false;
    g_fd = -1;
    pthread_mutex_unlock(&g_lock);

    if (fd >= 0) {
        close(fd);
    }
    if (was_running) {
        pthread_join(g_thread, NULL);
        clear_owner_lookup(env);
    }
}

static void vpp_unlink_runtime_sockets(void) {
    unlink(g_vpp_cli_sock);
    unlink(g_vpp_api_sock);
    unlink(g_vpp_statseg_sock);
}

static bool vpp_monitor_reap_child(FILE *file, pid_t pid) {
    int status = 0;
    pid_t exited = waitpid(pid, &status, WNOHANG);
    if (exited == pid) {
        log_line(file, "vpp child exited pid=%d status=%d", pid, status);
        vpp_unlink_runtime_sockets();
        return true;
    }
    if (exited < 0 && errno == ECHILD) {
        log_line(file, "vpp child already reaped pid=%d", pid);
        return true;
    }
    return false;
}

static void *vpp_monitor_thread(void *arg) {
    (void)arg;
    FILE *file = fopen(g_vpp_cli_log, "a");

    pthread_mutex_lock(&g_lock);
    pid_t pid = g_vpp_pid;
    char sock_path[PATH_BUF_SIZE];
    char show_command[sizeof(g_vpp_monitor_show_command)];
    snprintf(sock_path, sizeof(sock_path), "%s", g_vpp_cli_sock);
    snprintf(show_command, sizeof(show_command), "%s", g_vpp_monitor_show_command);
    pthread_mutex_unlock(&g_lock);

    log_line(file, "vpp monitor start pid=%d cli=%s", pid, sock_path);

    pthread_mutex_lock(&g_lock);
    bool oi5_mode = g_oi5_mode;
    char oi5_hev_lib[PATH_BUF_SIZE];
    snprintf(oi5_hev_lib, sizeof(oi5_hev_lib), "%s", g_oi5_hev_lib);
    pthread_mutex_unlock(&g_lock);
    if (oi5_mode) {
        oi5_android_sequence(sock_path, oi5_hev_lib);
    }

    for (int tick = 0; tick < 30; tick++) {
        pthread_mutex_lock(&g_lock);
        bool running = g_vpp_monitor_running;
        pthread_mutex_unlock(&g_lock);
        if (!running) {
            break;
        }

        if (vpp_monitor_reap_child(file, pid)) {
            break;
        }
        usleep(100000);
    }

    for (;;) {
        pthread_mutex_lock(&g_lock);
        bool running = g_vpp_monitor_running;
        pthread_mutex_unlock(&g_lock);
        if (!running) {
            break;
        }

        if (vpp_monitor_reap_child(file, pid)) {
            break;
        }

        /* Keep plugin registration evidence beside every stage snapshot.
         * The datapath show command is mode-specific: OI3-only APKs do not
         * stage the historical tun_poc plugin, so probing "show tun-poc"
         * there creates persistent false-negative CLI noise. */
        run_cli_command(sock_path, "show plugins", file);
        if (show_command[0]) {
            run_cli_command(sock_path, show_command, file);
        }
        for (int tick = 0; tick < 10; tick++) {
            pthread_mutex_lock(&g_lock);
            running = g_vpp_monitor_running;
            pthread_mutex_unlock(&g_lock);
            if (!running) {
                break;
            }
            usleep(100000);
        }
    }

    for (;;) {
        pthread_mutex_lock(&g_lock);
        bool running = g_vpp_monitor_running;
        pthread_mutex_unlock(&g_lock);
        if (!running) {
            break;
        }

        if (vpp_monitor_reap_child(file, pid)) {
            break;
        }
        usleep(100000);
    }

    log_line(file, "vpp monitor stop");
    if (file) {
        fclose(file);
    }
    return NULL;
}

static int write_vpp_files(const char *native_dir, const char *files_dir,
                           char *startup_conf, size_t startup_conf_len,
                           char *stdout_log, size_t stdout_log_len,
                           bool forward_mode, bool handoff_mode,
                           bool direct_owner_mode,
                           bool fragment_owner_mode,
                           bool direct_polling_mode,
                           bool direct_fault_mode,
                           bool direct_return_mode,
                           bool direct_single_writer_mode,
                           bool s124_tun_mode, bool oi2_mode, bool oi3_mode,
                           bool oi3_multi_mode, bool oi5_mode,
                           int s124_worker_count,
                           const char *s124_path,
                           const char *s124_observe,
                           bool owner_resolver_mode, int block_owner_uid,
                           int redirect_thread, bool owner_cache_enabled,
                           const char *block_ip4_dst,
                           const char *block_ip6_dst) {
    char vpp_dir[PATH_BUF_SIZE];
    char runtime_dir[PATH_BUF_SIZE];
    char logs_dir[PATH_BUF_SIZE];
    char shm_dir[PATH_BUF_SIZE];
    char startup_exec[PATH_BUF_SIZE];
    char vpp_log[PATH_BUF_SIZE];
    char plugin_name[64] = "tun_poc_plugin.so";
    char plugin_path[PATH_BUF_SIZE];
    char conf[4096];
    char exec_text[512];
    char block_arg[80] = "";
    char block6_arg[128] = "";
    char resolver_arg[64] = "";
    char owner_block_arg[64] = "";
    char redirect_arg[64] = "";
    char owner_cache_arg[32] = "";
    char cpu_text[64] = "";

    snprintf(vpp_dir, sizeof(vpp_dir), "%s/vpp", files_dir);
    snprintf(runtime_dir, sizeof(runtime_dir), "%s/runtime", vpp_dir);
    snprintf(logs_dir, sizeof(logs_dir), "%s/logs", vpp_dir);
    snprintf(shm_dir, sizeof(shm_dir), "%s/shm", vpp_dir);
    snprintf(startup_conf, startup_conf_len, "%s/startup.conf", runtime_dir);
    snprintf(startup_exec, sizeof(startup_exec), "%s/startup.exec", runtime_dir);
    snprintf(stdout_log, stdout_log_len, "%s/vpp-stdout.log", logs_dir);
    snprintf(vpp_log, sizeof(vpp_log), "%s/vpp.log", logs_dir);
    snprintf(g_vpp_cli_sock, sizeof(g_vpp_cli_sock), "%s/cli.sock", runtime_dir);
    snprintf(g_vpp_api_sock, sizeof(g_vpp_api_sock), "%s/api.sock", runtime_dir);
    snprintf(g_vpp_statseg_sock, sizeof(g_vpp_statseg_sock), "%s/statseg.sock", runtime_dir);
    snprintf(g_vpp_cli_log, sizeof(g_vpp_cli_log), "%s/vpp-cli.log", logs_dir);
    snprintf(g_vpp_shim_log, sizeof(g_vpp_shim_log), "%s/vpp-shim.log", logs_dir);
    snprintf(g_vpp_gate_log, sizeof(g_vpp_gate_log), "%s/vpp-owner-gate.log", logs_dir);
    snprintf(g_vpp_resolver_log, sizeof(g_vpp_resolver_log), "%s/vpp-owner-resolver.log",
             logs_dir);
    snprintf(g_vpp_hev_log, sizeof(g_vpp_hev_log), "%s/vpp-hev.log", logs_dir);

    if (mkdir_p(runtime_dir) < 0 || mkdir_p(logs_dir) < 0 || mkdir_p(shm_dir) < 0) {
        return -1;
    }
    unlink(g_vpp_cli_sock);
    unlink(g_vpp_cli_log);
    unlink(g_vpp_shim_log);
    unlink(g_vpp_gate_log);
    unlink(g_vpp_resolver_log);
    unlink(g_vpp_hev_log);
    unlink(stdout_log);
    unlink(vpp_log);

    snprintf(plugin_path, sizeof(plugin_path), "%s/%s", native_dir, plugin_name);
    if (owner_resolver_mode) {
        /* Owner-resolver is a tun_poc mode.  The HEV external-driver plugin
         * is a different (s124/oi) contract and does not register tun-poc;
         * selecting it here leaves VPP alive but makes every owner command
         * an unknown CLI input.  Prefer the canonical unprefixed VPP plugin
         * name, then accept the Android linker-prefixed extraction spelling. */
        snprintf(plugin_name, sizeof(plugin_name), "%s", "tun_poc_plugin.so");
        snprintf(plugin_path, sizeof(plugin_path), "%s/%s", native_dir,
                 plugin_name);
        if (!path_exists(plugin_path)) {
            snprintf(plugin_name, sizeof(plugin_name), "%s",
                     "libtun_poc_plugin.so");
            snprintf(plugin_path, sizeof(plugin_path), "%s/%s", native_dir,
                     plugin_name);
        }
        if (!path_exists(plugin_path)) {
            return -1;
        }
    } else if (s124_tun_mode || oi2_mode || oi3_mode || oi5_mode) {
        /* Android extracts native libraries from the APK under their
         * lib-prefixed names.  The build stage also retains the unprefixed
         * source artifact, but that sibling is not guaranteed to exist in
         * ApplicationInfo.nativeLibraryDir.  Probe both spellings before
         * falling back; selecting libhev... here keeps the VPP plugin loader
         * and the actual extracted artifact aligned. */
        snprintf(plugin_name, sizeof(plugin_name), "%s",
                 "libhev_external_driver_poc_plugin.so");
        snprintf(plugin_path, sizeof(plugin_path), "%s/%s", native_dir,
                 plugin_name);
        if (!path_exists(plugin_path)) {
            snprintf(plugin_name, sizeof(plugin_name), "%s",
                     "hev_external_driver_poc_plugin.so");
            snprintf(plugin_path, sizeof(plugin_path), "%s/%s", native_dir,
                     plugin_name);
        }
        if (!path_exists(plugin_path)) {
            return -1;
        }
    } else if (!path_exists(plugin_path)) {
        snprintf(plugin_name, sizeof(plugin_name), "%s", "libtun_poc_plugin.so");
        snprintf(plugin_path, sizeof(plugin_path), "%s/%s", native_dir, plugin_name);
    }
    if (!path_exists(plugin_path)) {
        return -1;
    }

    if (block_ip4_dst && block_ip4_dst[0]) {
        snprintf(block_arg, sizeof(block_arg), " block-ip4-dst %s", block_ip4_dst);
    }
    if (block_ip6_dst && block_ip6_dst[0]) {
        snprintf(block6_arg, sizeof(block6_arg), " block-ip6-dst %s", block_ip6_dst);
    }
    if (owner_resolver_mode) {
        snprintf(resolver_arg, sizeof(resolver_arg), " resolver-fd %d", VPP_RESOLVER_FD);
    }
    if (block_owner_uid >= 0) {
        snprintf(owner_block_arg, sizeof(owner_block_arg), " block-owner-uid %d",
                 block_owner_uid);
    }
    if (redirect_thread >= 0) {
        snprintf(redirect_arg, sizeof(redirect_arg), " redirect-thread %d", redirect_thread);
    }
    if (owner_cache_enabled) {
        snprintf(owner_cache_arg, sizeof(owner_cache_arg), " owner-cache");
    }

    if (oi3_mode) {
        if (oi3_multi_mode) {
            snprintf(exec_text, sizeof(exec_text),
                     "sakamoto-oi3 multi tun fd %d target-thread-a 1 "
                     "target-thread-b 2 target-thread-c 3 target-thread-d 4 "
                     "lib %s/libhev-socks5-tunnel.so\n"
                     "show sakamoto-oi3 multi\n", VPP_TUN_FD, native_dir);
        } else {
            snprintf(exec_text, sizeof(exec_text),
                     "sakamoto-oi3 tun fd %d target-thread 1 lib %s/libhev-socks5-tunnel.so\n"
                     "show sakamoto-oi3\n", VPP_TUN_FD, native_dir);
        }
        snprintf(cpu_text, sizeof(cpu_text),
                 "\n"
                 "cpu {\n"
                 "  main-core 0\n"
                 "  workers %d\n"
                 "}\n", oi3_multi_mode ? 4 : 1);
    } else if (oi5_mode) {
        /* OI-5 uses the same plugin and external broker as OI-3, but the
         * parent monitor drives synthetic run/stop/fault cells through the
         * app-owned CLI.  No TUN reader is installed and the Java VPN route
         * remains the narrow controlled prefix. */
        snprintf(exec_text, sizeof(exec_text), "show plugins\n");
        snprintf(cpu_text, sizeof(cpu_text),
                 "\n"
                 "cpu {\n"
                 "  main-core 0\n"
                 "  workers 1\n"
                 "}\n");
    } else if (oi2_mode) {
        snprintf(exec_text, sizeof(exec_text), "\n");
        snprintf(cpu_text, sizeof(cpu_text),
                 "\n"
                 "cpu {\n"
                 "  main-core 0\n"
                 "  workers 1\n"
                 "}\n");
    } else if (s124_tun_mode) {
        const char *path = (s124_path &&
                            (strcmp(s124_path, "full") == 0 ||
                             strcmp(s124_path, "udp-reflect") == 0 ||
                             strcmp(s124_path, "ingress-only") == 0 ||
                             strcmp(s124_path, "memcpy-cal") == 0))
                           ? s124_path : "full";
        const char *observe = (s124_observe &&
                               (strcmp(s124_observe, "off") == 0 ||
                                strcmp(s124_observe, "sample64") == 0 ||
                                strcmp(s124_observe, "full") == 0))
                              ? s124_observe : "off";
        snprintf(exec_text, sizeof(exec_text),
                 "s124-vpn-tun enable fd %d workers %d mode %s observe %s "
                 "lib %s/libhev-socks5-tunnel.so\n"
                 "show s124-vpn-tun\n",
                 VPP_TUN_FD, s124_worker_count, path, observe, native_dir);
        snprintf(cpu_text, sizeof(cpu_text),
                 "\n"
                 "cpu {\n"
                 "  main-core 0\n"
                 "  workers %d\n"
                 "}\n",
                 s124_worker_count);
    } else if (direct_owner_mode) {
        const char *polling_arg = direct_polling_mode ? " polling-thread 1" : "";
        const char *completion_arg = direct_single_writer_mode ?
                                     " completion-eagain 2" : "";
        const char *owner_mode = fragment_owner_mode ? "fragment-owner" :
                                 direct_fault_mode ? "direct-owner-fault" :
                                 direct_return_mode ? "direct-owner-return" :
                                 direct_single_writer_mode ?
                                 "direct-owner-single-writer" : "direct-owner";
        snprintf(exec_text, sizeof(exec_text),
                 "tun-poc enable fd %d mode %s shim-fd %d%s%s\n"
                 "show tun-poc\n",
                 VPP_TUN_FD, owner_mode, VPP_SHIM_FD, polling_arg,
                 completion_arg);
        snprintf(cpu_text, sizeof(cpu_text),
                 "\n"
                 "cpu {\n"
                 "  workers 2\n"
                 "}\n");
    } else if (handoff_mode) {
        snprintf(exec_text, sizeof(exec_text),
                 "tun-poc enable fd %d mode handoff-forward-fd shim-fd %d target-thread 1%s%s%s%s%s%s\n"
                 "show tun-poc\n",
                 VPP_TUN_FD, VPP_SHIM_FD, resolver_arg, owner_block_arg,
                 block_arg, block6_arg, redirect_arg, owner_cache_arg);
        snprintf(cpu_text, sizeof(cpu_text),
                 "\n"
                 "cpu {\n"
                 "  workers 2\n"
                 "}\n");
    } else if (forward_mode) {
        snprintf(exec_text, sizeof(exec_text),
                 "tun-poc enable fd %d mode forward-fd shim-fd %d%s%s\n"
                 "show tun-poc\n",
                 VPP_TUN_FD, VPP_SHIM_FD, block_arg, block6_arg);
    } else {
        snprintf(exec_text, sizeof(exec_text),
                 "tun-poc enable fd %d mode count-only\n"
                 "show tun-poc\n",
                 VPP_TUN_FD);
    }
    if (write_text_file(startup_exec, exec_text) < 0) {
        return -1;
    }

    snprintf(conf, sizeof(conf),
             "unix {\n"
             "  nodaemon\n"
             "  nobanner\n"
             "  runtime-dir %s\n"
             "  log %s\n"
             "  cli-listen %s\n"
             "  cli-no-pager\n"
             "  startup-config %s\n"
             "}\n"
             "\n"
             "%s"
             "socksvr {\n"
             "  socket-name %s/api.sock\n"
             "}\n"
             "\n"
             "api-segment {\n"
             "  prefix snort-vpn-lite\n"
             "}\n"
             "\n"
             "statseg {\n"
             "  socket-name %s/statseg.sock\n"
             "}\n"
             "\n"
             "buffers {\n"
             "  page-size default\n"
             "}\n"
             "\n"
             "plugins {\n"
             "  path %s\n"
             "  name-filter %s\n"
             "}\n",
             runtime_dir, vpp_log, g_vpp_cli_sock, startup_exec, cpu_text,
             runtime_dir, runtime_dir, native_dir, plugin_name);
    return write_text_file(startup_conf, conf);
}

JNIEXPORT jint JNICALL
Java_com_sakamoto_snort_vpnlite_SnortVpnService_nativeStartVppProbe(
        JNIEnv *env, jclass clazz, jint fd, jstring native_library_dir, jstring files_dir,
        jint vpp_mode, jstring s124_path_arg, jstring s124_observe_arg,
        jstring block_ip4_dst, jstring block_ip6_dst, jint block_owner_uid,
        jint redirect_thread, jboolean owner_cache_enabled,
        jstring oi3_expected_failure_arg, jobject owner_lookup) {

    const char *native_dir = (*env)->GetStringUTFChars(env, native_library_dir, NULL);
    if (!native_dir) {
        close(fd);
        return -1;
    }
    const char *app_files = (*env)->GetStringUTFChars(env, files_dir, NULL);
    if (!app_files) {
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        close(fd);
        return -1;
    }
    const char *block_dst = (*env)->GetStringUTFChars(env, block_ip4_dst, NULL);
    if (!block_dst) {
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        close(fd);
        return -12;
    }
    const char *block6_dst = (*env)->GetStringUTFChars(env, block_ip6_dst, NULL);
    if (!block6_dst) {
        (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        close(fd);
        return -13;
    }
    char oi3_expected_failure[64] = "";
    if (oi3_expected_failure_arg) {
        const char *expected_failure =
                (*env)->GetStringUTFChars(env, oi3_expected_failure_arg, NULL);
        if (!expected_failure) {
            (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
            (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
            (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
            (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
            close(fd);
            return -28;
        }
        snprintf(oi3_expected_failure, sizeof(oi3_expected_failure), "%s",
                 expected_failure);
        (*env)->ReleaseStringUTFChars(env, oi3_expected_failure_arg,
                                      expected_failure);
    }

    char vpp_path[PATH_BUF_SIZE];
    char startup_conf[PATH_BUF_SIZE];
    char stdout_log[PATH_BUF_SIZE];
    snprintf(vpp_path, sizeof(vpp_path), "%s/libvpppoc.so", native_dir);

    if (!path_exists(vpp_path)) {
        (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
        (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        close(fd);
        return -2;
    }
    const char *s124_path = s124_path_arg
                            ? (*env)->GetStringUTFChars(env, s124_path_arg, NULL) : "full";
    const char *s124_observe = s124_observe_arg
                               ? (*env)->GetStringUTFChars(env, s124_observe_arg, NULL) : "off";
    if (!s124_path || !s124_observe) {
        if (s124_path_arg && s124_path)
            (*env)->ReleaseStringUTFChars(env, s124_path_arg, s124_path);
        if (s124_observe_arg && s124_observe)
            (*env)->ReleaseStringUTFChars(env, s124_observe_arg, s124_observe);
        (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
        (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        close(fd);
        return -15;
    }
    bool use_legacy_owner_gate = vpp_mode == 3;
    bool use_owner_resolver = vpp_mode == 5;
    bool use_handoff_hev = vpp_mode == 4 || use_owner_resolver;
    bool use_fragment_owner = vpp_mode == 11 || vpp_mode == 12;
    bool use_fragment_no_hev = vpp_mode == 12;
    bool use_direct_owner = vpp_mode == 6 || vpp_mode == 7;
    bool use_direct_polling = vpp_mode == 7;
    bool use_direct_fault = vpp_mode == 8;
    bool use_direct_return = vpp_mode == 9;
    bool use_direct_single_writer = vpp_mode == 10;
    bool use_s124_tun = vpp_mode == 13 || vpp_mode == 14;
    bool use_oi5 = vpp_mode == 24;
    bool use_oi3_a23_return = vpp_mode == 25 || vpp_mode == 26;
    bool use_oi3_multi = vpp_mode == 27;
    bool use_oi3_uid_gate = use_oi3_multi && block_owner_uid >= 0;
    bool use_tun_gate = use_legacy_owner_gate || use_oi3_uid_gate;
    bool use_oi3 = vpp_mode == 16 || (vpp_mode >= 17 && vpp_mode <= 23)
            || use_oi3_a23_return || use_oi5 || use_oi3_multi;
    bool use_oi3_controlled = (vpp_mode >= 17 && vpp_mode <= 23)
            || use_oi3_a23_return;
    if (use_oi3_controlled) {
        snprintf(g_oi3_control_cell, sizeof(g_oi3_control_cell), "%s",
                 oi3_controlled_cell_for_mode(vpp_mode));
    }
    bool use_oi2 = vpp_mode == 15 || use_oi3;
    int s124_worker_count = vpp_mode == 14 ? 2 : 1;
    use_direct_owner = use_direct_owner || use_direct_fault || use_direct_return ||
                       use_direct_single_writer || use_fragment_owner;
    bool use_forward = vpp_mode == 1 || vpp_mode == 2 || use_legacy_owner_gate ||
                       use_handoff_hev || use_direct_owner;
    bool use_hev = vpp_mode == 2 || use_legacy_owner_gate || use_handoff_hev ||
                   (use_direct_owner && !use_fragment_no_hev);
    if (write_vpp_files(native_dir, app_files, startup_conf, sizeof(startup_conf),
                        stdout_log, sizeof(stdout_log), use_forward, use_handoff_hev,
                        use_direct_owner, use_fragment_owner, use_direct_polling,
                        use_direct_fault,
                        use_direct_return,
                        use_direct_single_writer,
                        use_s124_tun, use_oi2, use_oi3 && !use_oi5,
                        use_oi3_multi, use_oi5,
                        s124_worker_count,
                        s124_path,
                        s124_observe,
                        use_owner_resolver, block_owner_uid, redirect_thread,
                        owner_cache_enabled == JNI_TRUE, block_dst, block6_dst) < 0) {
        if (s124_path_arg)
            (*env)->ReleaseStringUTFChars(env, s124_path_arg, s124_path);
        if (s124_observe_arg)
            (*env)->ReleaseStringUTFChars(env, s124_observe_arg, s124_observe);
        (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
        (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        close(fd);
        return -3;
    }
    if (s124_path_arg)
        (*env)->ReleaseStringUTFChars(env, s124_path_arg, s124_path);
    if (s124_observe_arg)
        (*env)->ReleaseStringUTFChars(env, s124_observe_arg, s124_observe);

    pthread_mutex_lock(&g_lock);
    if (g_vpp_pid > 0 || (use_hev && g_hev_pid > 0)) {
        pthread_mutex_unlock(&g_lock);
        (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
        (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        close(fd);
        return -4;
    }
    pthread_mutex_unlock(&g_lock);

    int gate_fds[2] = {-1, -1};
    if (use_tun_gate && socketpair(AF_UNIX, SOCK_SEQPACKET, 0, gate_fds) < 0) {
        (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
        (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        close(fd);
        return -14;
    }

    int shim_fds[2] = {-1, -1};
    if (use_forward && socketpair(AF_UNIX, SOCK_SEQPACKET, 0, shim_fds) < 0) {
        if (gate_fds[0] >= 0) {
            close(gate_fds[0]);
            close(gate_fds[1]);
        }
        (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
        (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        close(fd);
        return -7;
    }

    int resolver_fds[2] = {-1, -1};
    if (use_owner_resolver && socketpair(AF_UNIX, SOCK_STREAM, 0, resolver_fds) < 0) {
        if (gate_fds[0] >= 0) {
            close(gate_fds[0]);
            close(gate_fds[1]);
        }
        if (shim_fds[0] >= 0) {
            close(shim_fds[0]);
            close(shim_fds[1]);
        }
        (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
        (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        close(fd);
        return -19;
    }

    int oi2_request_fds[2] = {-1, -1};
    int oi2_completion_fds[2] = {-1, -1};
    if (use_oi2 &&
        (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, oi2_request_fds) < 0 ||
         socketpair(AF_UNIX, SOCK_SEQPACKET, 0, oi2_completion_fds) < 0)) {
        if (oi2_request_fds[0] >= 0) {
            close(oi2_request_fds[0]);
        }
        if (oi2_request_fds[1] >= 0) {
            close(oi2_request_fds[1]);
        }
        if (oi2_completion_fds[0] >= 0) {
            close(oi2_completion_fds[0]);
        }
        if (oi2_completion_fds[1] >= 0) {
            close(oi2_completion_fds[1]);
        }
        if (gate_fds[0] >= 0) {
            close(gate_fds[0]);
            close(gate_fds[1]);
        }
        if (shim_fds[0] >= 0) {
            close(shim_fds[0]);
            close(shim_fds[1]);
        }
        if (resolver_fds[0] >= 0) {
            close(resolver_fds[0]);
            close(resolver_fds[1]);
        }
        if (oi2_request_fds[0] >= 0) {
            close(oi2_request_fds[0]);
            close(oi2_request_fds[1]);
        }
        if (oi2_completion_fds[0] >= 0) {
            close(oi2_completion_fds[0]);
            close(oi2_completion_fds[1]);
        }
        (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
        (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        close(fd);
        return -23;
    }

    /* The historical controlled cells retain a duplicate TUN fd only for
     * their sidecar lifetime witness.  A2-3 must have exactly one TUN
     * consumer: the VPP OI3 owner path.  Its real AppA socket is the only
     * traffic injector, so do not create the old observer duplicate. */
    int oi3_control_fd = use_oi3_controlled && !use_oi3_a23_return ? dup(fd) : -1;
    if (use_oi3_controlled && !use_oi3_a23_return && oi3_control_fd < 0) {
        close(oi2_request_fds[0]);
        close(oi2_request_fds[1]);
        close(oi2_completion_fds[0]);
        close(oi2_completion_fds[1]);
        (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
        (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        close(fd);
        return -27;
    }

    pid_t pid = fork();
    if (pid < 0) {
        if (gate_fds[0] >= 0) {
            close(gate_fds[0]);
            close(gate_fds[1]);
        }
        if (shim_fds[0] >= 0) {
            close(shim_fds[0]);
            close(shim_fds[1]);
        }
        if (resolver_fds[0] >= 0) {
            close(resolver_fds[0]);
            close(resolver_fds[1]);
        }
        (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
        (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        if (oi3_control_fd >= 0) {
            close(oi3_control_fd);
        }
        close(fd);
        return -5;
    }

    if (pid == 0) {
        if (oi3_control_fd >= 0) {
            close(oi3_control_fd);
        }
        int tun_fd = use_tun_gate ? gate_fds[1] : fd;
        int shim_child_fd = use_forward ? shim_fds[1] : -1;
        int resolver_child_fd = use_owner_resolver ? resolver_fds[1] : -1;
        int oi2_request_child_fd = use_oi2 ? oi2_request_fds[0] : -1;
        int oi2_completion_child_fd = use_oi2 ? oi2_completion_fds[0] : -1;
        if (use_tun_gate) {
            close(gate_fds[0]);
            if (fd != tun_fd) {
                close(fd);
            }
        }
        if (use_forward) {
            close(shim_fds[0]);
        }
        if (use_owner_resolver) {
            close(resolver_fds[0]);
        }
        if (use_oi2) {
            close(oi2_request_fds[1]);
            close(oi2_completion_fds[1]);
        }

        if (use_forward || use_owner_resolver) {
            if (tun_fd == VPP_SHIM_FD || tun_fd == VPP_RESOLVER_FD) {
                int moved = fcntl(tun_fd, F_DUPFD_CLOEXEC, VPP_RESOLVER_FD + 1);
                if (moved < 0) {
                    _exit(126);
                }
                close(tun_fd);
                tun_fd = moved;
            }
            if (shim_child_fd == VPP_TUN_FD || shim_child_fd == VPP_RESOLVER_FD) {
                int moved = fcntl(shim_child_fd, F_DUPFD_CLOEXEC, VPP_RESOLVER_FD + 1);
                if (moved < 0) {
                    _exit(126);
                }
                close(shim_child_fd);
                shim_child_fd = moved;
            }
            if (resolver_child_fd == VPP_TUN_FD || resolver_child_fd == VPP_SHIM_FD) {
                int moved = fcntl(resolver_child_fd, F_DUPFD_CLOEXEC,
                                  VPP_RESOLVER_FD + 1);
                if (moved < 0) {
                    _exit(126);
                }
                close(resolver_child_fd);
                resolver_child_fd = moved;
            }
        }

        if (tun_fd != VPP_TUN_FD) {
            dup2(tun_fd, VPP_TUN_FD);
            close(tun_fd);
        }
        set_cloexec(VPP_TUN_FD, false);
        if (use_forward) {
            if (shim_child_fd != VPP_SHIM_FD) {
                dup2(shim_child_fd, VPP_SHIM_FD);
                close(shim_child_fd);
            }
            set_cloexec(VPP_SHIM_FD, false);
        }
        if (use_owner_resolver) {
            if (resolver_child_fd != VPP_RESOLVER_FD) {
                dup2(resolver_child_fd, VPP_RESOLVER_FD);
                close(resolver_child_fd);
            }
            set_cloexec(VPP_RESOLVER_FD, false);
        }
        if (use_oi2) {
            if (oi2_request_child_fd == OI2_REQUEST_FD ||
                oi2_request_child_fd == OI2_COMPLETION_FD) {
                int moved = fcntl(oi2_request_child_fd, F_DUPFD_CLOEXEC,
                                  OI2_COMPLETION_FD + 1);
                if (moved < 0) {
                    _exit(126);
                }
                close(oi2_request_child_fd);
                oi2_request_child_fd = moved;
            }
            if (oi2_completion_child_fd == OI2_REQUEST_FD ||
                oi2_completion_child_fd == OI2_COMPLETION_FD) {
                int moved = fcntl(oi2_completion_child_fd, F_DUPFD_CLOEXEC,
                                  OI2_COMPLETION_FD + 1);
                if (moved < 0) {
                    _exit(126);
                }
                close(oi2_completion_child_fd);
                oi2_completion_child_fd = moved;
            }
            if (oi2_request_child_fd != OI2_REQUEST_FD) {
                dup2(oi2_request_child_fd, OI2_REQUEST_FD);
                close(oi2_request_child_fd);
            }
            set_cloexec(OI2_REQUEST_FD, false);
            if (oi2_completion_child_fd != OI2_COMPLETION_FD) {
                dup2(oi2_completion_child_fd, OI2_COMPLETION_FD);
                close(oi2_completion_child_fd);
            }
            set_cloexec(OI2_COMPLETION_FD, false);
        }

        int out = open(stdout_log, O_CREAT | O_WRONLY | O_APPEND, 0600);
        if (out >= 0) {
            dup2(out, STDOUT_FILENO);
            dup2(out, STDERR_FILENO);
            if (out > STDERR_FILENO) {
                close(out);
            }
        }

        setenv("LD_LIBRARY_PATH", native_dir, 1);
        char stage_cell[64];
        char stage_id[128];
        copy_stage(stage_cell, sizeof(stage_cell), stage_id, sizeof(stage_id));
        setenv("SAKAMOTO_A2_STAGE_CELL", stage_cell, 1);
        setenv("SAKAMOTO_A2_STAGE_ID", stage_id, 1);
        if (use_oi2) {
            if (use_oi3) {
                setenv("SAKAMOTO_OI3_EXTERNAL_BROKER", "1", 1);
                setenv("SAKAMOTO_OI3_REQUEST_FD", "6", 1);
                setenv("SAKAMOTO_OI3_COMPLETION_FD", "7", 1);
            } else {
                setenv("SAKAMOTO_OI2_EXTERNAL_BROKER", "1", 1);
                setenv("SAKAMOTO_OI2_REQUEST_FD", "6", 1);
                setenv("SAKAMOTO_OI2_COMPLETION_FD", "7", 1);
            }
        }
        if (use_oi3_controlled) {
            setenv("SAKAMOTO_OI3_CONTROLLED", "1", 1);
            setenv("SAKAMOTO_OI3_CONTROLLED_CELL", g_oi3_control_cell, 1);
        }
        if (use_oi3 && oi3_expected_failure[0] != '\0') {
            setenv("SAKAMOTO_OI3_EXPECTED_FAILURE", oi3_expected_failure, 1);
        }
        if (use_oi3_multi && block_dst && block_dst[0] != '\0') {
            setenv("SAKAMOTO_OI3_POLICY_DROP_IP4", block_dst, 1);
        } else if (use_oi3_multi) {
            /* The service process can start more than one VPN generation.
             * Do not let a prior drop cell leak its destination into a later
             * allow cell through the forked VPP child's environment. */
            unsetenv("SAKAMOTO_OI3_POLICY_DROP_IP4");
        }
        if (use_oi3_a23_return) {
            setenv("SAKAMOTO_OI3_A2_3_RETURN", "1", 1);
            setenv("SAKAMOTO_OI3_A2_3_STAGE_ID",
                   vpp_mode == 26 ? "A2-3-udp6-return" : "A2-3-udp4-return", 1);
        }
        char shm_dir[PATH_BUF_SIZE];
        snprintf(shm_dir, sizeof(shm_dir), "%s/vpp/shm", app_files);
        setenv("SAKAMOTO_ANDROID_SHM_DIR", shm_dir, 1);
        execl(vpp_path, "vpp", "plugin_path", native_dir, "-c", startup_conf, (char *)NULL);
        _exit(127);
    }

    if (use_tun_gate) {
        close(gate_fds[1]);
    } else {
        close(fd);
    }
    if (use_forward) {
        close(shim_fds[1]);
    }
    if (use_owner_resolver) {
        close(resolver_fds[1]);
    }
    if (use_oi2) {
        close(oi2_request_fds[0]);
        close(oi2_completion_fds[0]);
    }

    pthread_mutex_lock(&g_lock);
    g_vpp_pid = pid;
    g_vpp_monitor_running = true;
    g_vpp_underlay_epoch = 0;
    g_vpp_underlay_handle = -1;
    g_vpp_underlay_available = false;
    if (use_oi3_multi) {
        snprintf(g_vpp_monitor_show_command, sizeof(g_vpp_monitor_show_command),
                 "show sakamoto-oi3 multi");
    } else if (use_oi3) {
        snprintf(g_vpp_monitor_show_command, sizeof(g_vpp_monitor_show_command),
                 "show sakamoto-oi3");
    } else if (use_oi2) {
        snprintf(g_vpp_monitor_show_command, sizeof(g_vpp_monitor_show_command),
                 "show sakamoto-oi2");
    } else if (use_s124_tun) {
        snprintf(g_vpp_monitor_show_command, sizeof(g_vpp_monitor_show_command),
                 "show s124-vpn-tun");
    } else {
        snprintf(g_vpp_monitor_show_command, sizeof(g_vpp_monitor_show_command),
                 "show tun-poc");
    }
    g_oi5_mode = use_oi5;
    if (use_oi5) {
        snprintf(g_oi5_log, sizeof(g_oi5_log), "%s/vpp/logs/vpp-oi5-android.log",
                 app_files);
        snprintf(g_oi5_hev_lib, sizeof(g_oi5_hev_lib), "%s/libhev-socks5-tunnel.so",
                 native_dir);
        unlink(g_oi5_log);
    } else {
        g_oi5_log[0] = '\0';
        g_oi5_hev_lib[0] = '\0';
    }
    if (use_oi3_controlled && !use_oi3_a23_return) {
        snprintf(g_oi3_control_log, sizeof(g_oi3_control_log),
                 "%s/vpp/logs/vpp-oi3-controlled.log", app_files);
        unlink(g_oi3_control_log);
        g_oi3_control_fd = oi3_control_fd;
        g_oi3_control_running = true;
    }
    if (use_forward && !use_hev) {
        g_vpp_shim_fd = shim_fds[0];
        g_vpp_shim_running = true;
    }
    pthread_mutex_unlock(&g_lock);

    if (use_oi2) {
        jmethodID oi2_method = (*env)->GetMethodID(
            env, clazz, "bindAndProtectSocketForNative", "(I)I");
        if (!owner_lookup || !oi2_method || (*env)->ExceptionCheck(env)) {
            if ((*env)->ExceptionCheck(env)) {
                (*env)->ExceptionClear(env);
            }
            close(oi2_request_fds[1]);
            close(oi2_completion_fds[1]);
            kill(pid, SIGTERM);
            waitpid(pid, NULL, 0);
            pthread_mutex_lock(&g_lock);
            g_vpp_monitor_running = false;
            g_vpp_pid = -1;
            pthread_mutex_unlock(&g_lock);
            if (use_oi3_controlled) {
                cancel_oi3_controlled_fd();
            }
            (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
            (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
            (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
            (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
            return -24;
        }
        jobject oi2_service = (*env)->NewGlobalRef(env, owner_lookup);
        if (!oi2_service) {
            close(oi2_request_fds[1]);
            close(oi2_completion_fds[1]);
            kill(pid, SIGTERM);
            waitpid(pid, NULL, 0);
            pthread_mutex_lock(&g_lock);
            g_vpp_monitor_running = false;
            g_vpp_pid = -1;
            pthread_mutex_unlock(&g_lock);
            if (use_oi3_controlled) {
                cancel_oi3_controlled_fd();
            }
            (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
            (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
            (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
            (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
            return -25;
        }
        snprintf(g_oi2_broker_log, sizeof(g_oi2_broker_log),
                 "%s/vpp/logs/vpp-%s-broker.log", app_files,
                 use_oi3 ? "oi3" : "oi2");
        if (use_oi3) {
            unlink(g_oi2_broker_log);
        }
        pthread_mutex_lock(&g_lock);
        g_oi2_request_fd = oi2_request_fds[1];
        g_oi2_completion_fd = oi2_completion_fds[1];
        g_oi2_service = oi2_service;
        g_oi2_method = oi2_method;
        g_oi2_broker_running = true;
        pthread_mutex_unlock(&g_lock);
        int oi2_rc = pthread_create(&g_oi2_broker_thread, NULL,
                                    oi2_android_broker_thread, NULL);
        if (oi2_rc != 0) {
            stop_oi2_broker(env);
            kill(pid, SIGTERM);
            waitpid(pid, NULL, 0);
            pthread_mutex_lock(&g_lock);
            g_vpp_monitor_running = false;
            g_vpp_pid = -1;
            pthread_mutex_unlock(&g_lock);
            if (use_oi3_controlled) {
                cancel_oi3_controlled_fd();
            }
            (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
            (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
            (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
            (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
            return -26;
        }
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                            "started %s Android broker request-fd=%d completion-fd=%d log=%s",
                            use_oi3 ? "OI3" : "OI2",
                            oi2_request_fds[1], oi2_completion_fds[1], g_oi2_broker_log);
    }

    if (use_hev) {
        int protect_fds[2] = {-1, -1};
        jmethodID protect_method = (*env)->GetMethodID(
            env, clazz, "protectSocketForNative", "(I)Z");
        if (!owner_lookup || !protect_method || (*env)->ExceptionCheck(env)) {
            if ((*env)->ExceptionCheck(env)) {
                (*env)->ExceptionClear(env);
            }
            close(shim_fds[0]);
            kill(pid, SIGTERM);
            waitpid(pid, NULL, 0);
            (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
            (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
            (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
            (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
            return -20;
        }
        jobject protect_service = (*env)->NewGlobalRef(env, owner_lookup);
        if (!protect_service || socketpair(AF_UNIX, SOCK_SEQPACKET, 0, protect_fds) < 0) {
            if (protect_service) {
                (*env)->DeleteGlobalRef(env, protect_service);
            }
            close(shim_fds[0]);
            kill(pid, SIGTERM);
            waitpid(pid, NULL, 0);
            (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
            (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
            (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
            (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
            return -21;
        }
        snprintf(g_vpp_protect_log, sizeof(g_vpp_protect_log),
                 "%s/vpp/logs/vpp-protect.log", app_files);
        pthread_mutex_lock(&g_lock);
        g_protect_requests = 0;
        g_protect_completions = 0;
        g_protect_failures = 0;
        g_protect_denials = 0;
        g_protect_receive_failures = 0;
        g_protect_response_failures = 0;
        g_protect_java_exceptions = 0;
        g_protect_fd = protect_fds[0];
        g_protect_service = protect_service;
        g_protect_method = protect_method;
        g_protect_running = true;
        pthread_mutex_unlock(&g_lock);

        pid_t hev_pid = fork();
        if (hev_pid < 0) {
            close(protect_fds[1]);
            stop_protect_broker(env);
            close(shim_fds[0]);
            if (use_tun_gate) {
                close(gate_fds[0]);
                close(fd);
            }
            if (use_owner_resolver) {
                close(resolver_fds[0]);
            }
            kill(pid, SIGTERM);
            pthread_mutex_lock(&g_lock);
            g_vpp_monitor_running = false;
            g_vpp_pid = -1;
            pthread_mutex_unlock(&g_lock);
            waitpid(pid, NULL, 0);
            (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
            (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
            (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
            (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
            return -8;
        }
        if (hev_pid == 0) {
            close(protect_fds[0]);
            run_hev_child(native_dir, g_vpp_hev_log, shim_fds[0], 41080,
                          protect_fds[1]);
            _exit(127);
        }
        close(protect_fds[1]);
        close(shim_fds[0]);
        int protect_rc = pthread_create(&g_protect_thread, NULL,
                                        protect_broker_thread, NULL);
        if (protect_rc != 0) {
            terminate_child(hev_pid);
            pthread_mutex_lock(&g_lock);
            g_protect_running = false;
            pthread_mutex_unlock(&g_lock);
            stop_protect_broker(env);
            kill(pid, SIGTERM);
            waitpid(pid, NULL, 0);
            (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
            (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
            (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
            (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
            return -22;
        }
        usleep(300000);
        int status = 0;
        pid_t exited = waitpid(hev_pid, &status, WNOHANG);
        if (exited == hev_pid) {
            stop_protect_broker(env);
            if (use_tun_gate) {
                close(gate_fds[0]);
                close(fd);
            }
            if (use_owner_resolver) {
                close(resolver_fds[0]);
            }
            kill(pid, SIGTERM);
            pthread_mutex_lock(&g_lock);
            g_vpp_monitor_running = false;
            g_vpp_pid = -1;
            pthread_mutex_unlock(&g_lock);
            waitpid(pid, NULL, 0);
            (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
            (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
            (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
            (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
            return -9;
        }
        pthread_mutex_lock(&g_lock);
        g_hev_pid = hev_pid;
        g_hev_driver_fd = -1;
        snprintf(g_hev_log_path, sizeof(g_hev_log_path), "%s", g_vpp_hev_log);
        pthread_mutex_unlock(&g_lock);
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "started VPP HEV pid=%d log=%s",
                            hev_pid, g_vpp_hev_log);
    } else if (use_forward) {
        int shim_rc = pthread_create(&g_vpp_shim_thread, NULL, vpp_shim_thread, NULL);
        if (shim_rc != 0) {
            close(shim_fds[0]);
            kill(pid, SIGTERM);
            pthread_mutex_lock(&g_lock);
            g_vpp_shim_running = false;
            g_vpp_shim_fd = -1;
            g_vpp_monitor_running = false;
            g_vpp_pid = -1;
            pthread_mutex_unlock(&g_lock);
            waitpid(pid, NULL, 0);
            (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
            (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
            (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
            (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
            return -10;
        }
    }

    if (use_tun_gate) {
        if (!g_jvm && (*env)->GetJavaVM(env, &g_jvm) != JNI_OK) {
            close(gate_fds[0]);
            close(fd);
            kill(pid, SIGTERM);
            pthread_mutex_lock(&g_lock);
            g_vpp_monitor_running = false;
            g_vpp_pid = -1;
            pthread_mutex_unlock(&g_lock);
            if (use_hev) {
                pthread_mutex_lock(&g_lock);
                pid_t hev_pid = g_hev_pid;
                g_hev_pid = -1;
                g_hev_log_path[0] = '\0';
                pthread_mutex_unlock(&g_lock);
                terminate_child(hev_pid);
            }
            waitpid(pid, NULL, 0);
            (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
            (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
            (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
            (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
            return -15;
        }

        jmethodID owner_method = NULL;
        jobject owner_global = NULL;
        if (owner_lookup) {
            owner_method = (*env)->GetMethodID(env, clazz, "queryConnectionOwnerUidForPacket",
                                               "(ILjava/lang/String;ILjava/lang/String;I)I");
        }
        if (!owner_lookup || !owner_method || (*env)->ExceptionCheck(env)) {
            if ((*env)->ExceptionCheck(env)) {
                (*env)->ExceptionClear(env);
            }
            close(gate_fds[0]);
            close(fd);
            kill(pid, SIGTERM);
            pthread_mutex_lock(&g_lock);
            g_vpp_monitor_running = false;
            g_vpp_pid = -1;
            pthread_mutex_unlock(&g_lock);
            if (use_hev) {
                pthread_mutex_lock(&g_lock);
                pid_t hev_pid = g_hev_pid;
                g_hev_pid = -1;
                g_hev_log_path[0] = '\0';
                pthread_mutex_unlock(&g_lock);
                terminate_child(hev_pid);
            }
            waitpid(pid, NULL, 0);
            (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
            (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
            (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
            (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
            return -16;
        }
        owner_global = (*env)->NewGlobalRef(env, owner_lookup);
        if (!owner_global) {
            close(gate_fds[0]);
            close(fd);
            kill(pid, SIGTERM);
            pthread_mutex_lock(&g_lock);
            g_vpp_monitor_running = false;
            g_vpp_pid = -1;
            pthread_mutex_unlock(&g_lock);
            if (use_hev) {
                pthread_mutex_lock(&g_lock);
                pid_t hev_pid = g_hev_pid;
                g_hev_pid = -1;
                g_hev_log_path[0] = '\0';
                pthread_mutex_unlock(&g_lock);
                terminate_child(hev_pid);
            }
            waitpid(pid, NULL, 0);
            (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
            (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
            (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
            (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
            return -17;
        }

        pthread_mutex_lock(&g_lock);
        g_vpp_gate_tun_fd = fd;
        g_vpp_gate_vpp_fd = gate_fds[0];
        g_vpp_gate_block_uid = block_owner_uid;
        g_vpp_gate_running = true;
        g_owner_lookup = owner_global;
        g_owner_lookup_method = owner_method;
        pthread_mutex_unlock(&g_lock);

        int gate_rc = pthread_create(&g_vpp_gate_thread, NULL, vpp_gate_thread, NULL);
        if (gate_rc != 0) {
            pthread_mutex_lock(&g_lock);
            g_vpp_gate_running = false;
            g_vpp_gate_tun_fd = -1;
            g_vpp_gate_vpp_fd = -1;
            g_vpp_gate_block_uid = -1;
            g_owner_lookup = NULL;
            g_owner_lookup_method = NULL;
            pthread_mutex_unlock(&g_lock);
            (*env)->DeleteGlobalRef(env, owner_global);
            close(gate_fds[0]);
            close(fd);
            kill(pid, SIGTERM);
            pthread_mutex_lock(&g_lock);
            g_vpp_monitor_running = false;
            g_vpp_pid = -1;
            pthread_mutex_unlock(&g_lock);
            if (use_hev) {
                pthread_mutex_lock(&g_lock);
                pid_t hev_pid = g_hev_pid;
                g_hev_pid = -1;
                g_hev_log_path[0] = '\0';
                pthread_mutex_unlock(&g_lock);
                terminate_child(hev_pid);
            }
            waitpid(pid, NULL, 0);
            (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
            (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
            (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
            (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
            return -18;
        }
    }

    if (use_owner_resolver) {
        jobject owner_global = NULL;
        jmethodID owner_method = NULL;
        int owner_rc = init_owner_lookup(env, clazz, owner_lookup,
                                         &owner_global, &owner_method);
        if (owner_rc != 0) {
            close(resolver_fds[0]);
            kill(pid, SIGTERM);
            pthread_mutex_lock(&g_lock);
            g_vpp_monitor_running = false;
            g_vpp_pid = -1;
            pthread_mutex_unlock(&g_lock);
            if (use_hev) {
                pthread_mutex_lock(&g_lock);
                pid_t hev_pid = g_hev_pid;
                g_hev_pid = -1;
                g_hev_log_path[0] = '\0';
                pthread_mutex_unlock(&g_lock);
                terminate_child(hev_pid);
            }
            waitpid(pid, NULL, 0);
            (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
            (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
            (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
            (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
            return -20;
        }

        pthread_mutex_lock(&g_lock);
        g_vpp_resolver_fd = resolver_fds[0];
        g_vpp_resolver_running = true;
        g_vpp_resolver_block_uid = block_owner_uid;
        g_admission_uid = -1;
        g_admission_policy_logged = false;
        snprintf(g_admission_stage, sizeof(g_admission_stage), "%s", g_stage_id);
        snprintf(g_admission_flow_id, sizeof(g_admission_flow_id), "unknown");
        snprintf(g_admission_key, sizeof(g_admission_key), "unknown");
        g_owner_lookup = owner_global;
        g_owner_lookup_method = owner_method;
        pthread_mutex_unlock(&g_lock);

        int resolver_rc = pthread_create(&g_vpp_resolver_thread, NULL,
                                         vpp_resolver_thread, NULL);
        if (resolver_rc != 0) {
            pthread_mutex_lock(&g_lock);
            g_vpp_resolver_running = false;
            g_vpp_resolver_fd = -1;
            g_vpp_resolver_block_uid = -1;
            g_owner_lookup = NULL;
            g_owner_lookup_method = NULL;
            pthread_mutex_unlock(&g_lock);
            (*env)->DeleteGlobalRef(env, owner_global);
            close(resolver_fds[0]);
            kill(pid, SIGTERM);
            pthread_mutex_lock(&g_lock);
            g_vpp_monitor_running = false;
            g_vpp_pid = -1;
            pthread_mutex_unlock(&g_lock);
            if (use_hev) {
                pthread_mutex_lock(&g_lock);
                pid_t hev_pid = g_hev_pid;
                g_hev_pid = -1;
                g_hev_log_path[0] = '\0';
                pthread_mutex_unlock(&g_lock);
                terminate_child(hev_pid);
            }
            waitpid(pid, NULL, 0);
            (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
            (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
            (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
            (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
            return -21;
        }
    }

    int rc = pthread_create(&g_vpp_monitor_thread, NULL, vpp_monitor_thread, NULL);
    if (rc != 0) {
        if (use_oi2) {
            stop_oi2_broker(env);
        }
        kill(pid, SIGTERM);
        pthread_mutex_lock(&g_lock);
        g_vpp_monitor_running = false;
        g_vpp_pid = -1;
        bool was_shim = g_vpp_shim_running;
        int shim_fd = g_vpp_shim_fd;
        bool was_gate = g_vpp_gate_running;
        int gate_tun_fd = g_vpp_gate_tun_fd;
        int gate_vpp_fd = g_vpp_gate_vpp_fd;
        bool was_resolver = g_vpp_resolver_running;
        int resolver_fd = g_vpp_resolver_fd;
        g_vpp_shim_running = false;
        g_vpp_shim_fd = -1;
        g_vpp_gate_running = false;
        g_vpp_gate_tun_fd = -1;
        g_vpp_gate_vpp_fd = -1;
        g_vpp_gate_block_uid = -1;
        g_vpp_resolver_running = false;
        g_vpp_resolver_fd = -1;
        g_vpp_resolver_block_uid = -1;
        pthread_mutex_unlock(&g_lock);
        if (shim_fd >= 0) {
            close(shim_fd);
        }
        if (gate_tun_fd >= 0) {
            close(gate_tun_fd);
        }
        if (gate_vpp_fd >= 0) {
            close(gate_vpp_fd);
        }
        if (resolver_fd >= 0) {
            close(resolver_fd);
        }
        if (was_shim) {
            pthread_join(g_vpp_shim_thread, NULL);
        }
        if (was_gate) {
            pthread_join(g_vpp_gate_thread, NULL);
        }
        if (was_resolver) {
            pthread_join(g_vpp_resolver_thread, NULL);
        }
        if (was_gate || was_resolver) {
            clear_owner_lookup(env);
        }
        if (use_hev) {
            pthread_mutex_lock(&g_lock);
            pid_t hev_pid = g_hev_pid;
            g_hev_pid = -1;
            g_hev_log_path[0] = '\0';
            pthread_mutex_unlock(&g_lock);
            terminate_child(hev_pid);
        }
        if (use_oi3_controlled) {
            cancel_oi3_controlled_fd();
        }
        waitpid(pid, NULL, 0);
        (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
        (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        return -11;
    }

    if (use_oi3_controlled && !use_oi3_a23_return) {
        int injector_rc = pthread_create(&g_oi3_control_thread, NULL,
                                         oi3_controlled_injector_thread, NULL);
        if (injector_rc != 0) {
            pthread_mutex_lock(&g_lock);
            g_oi3_control_running = false;
            int control_fd = g_oi3_control_fd;
            g_oi3_control_fd = -1;
            pthread_mutex_unlock(&g_lock);
            if (control_fd >= 0) {
                close(control_fd);
            }
            pthread_mutex_lock(&g_lock);
            g_vpp_monitor_running = false;
            g_vpp_pid = -1;
            pthread_mutex_unlock(&g_lock);
            kill(pid, SIGTERM);
            waitpid(pid, NULL, 0);
            pthread_join(g_vpp_monitor_thread, NULL);
            stop_oi2_broker(env);
            (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
            (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
            (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
            (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
            return -28;
        }
        pthread_mutex_lock(&g_lock);
        g_oi3_control_started = true;
        pthread_mutex_unlock(&g_lock);
    }

    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                        "started VPP pid=%d fd=%d mode=%d conf=%s", pid, fd,
                        vpp_mode, startup_conf);
    (*env)->ReleaseStringUTFChars(env, block_ip6_dst, block6_dst);
    (*env)->ReleaseStringUTFChars(env, block_ip4_dst, block_dst);
    (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
    (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
    return 0;
}

JNIEXPORT void JNICALL
Java_com_sakamoto_snort_vpnlite_SnortVpnService_nativeStopVppProbe(JNIEnv *env, jclass clazz) {
    (void)clazz;

    pthread_mutex_lock(&g_lock);
    pid_t pid = g_vpp_pid;
    bool was_monitoring = g_vpp_monitor_running;
    bool was_shim_running = g_vpp_shim_running;
    bool was_gate_running = g_vpp_gate_running;
    bool was_resolver_running = g_vpp_resolver_running;
    bool was_oi3_control_started = g_oi3_control_started;
    int shim_fd = g_vpp_shim_fd;
    int gate_tun_fd = g_vpp_gate_tun_fd;
    int gate_vpp_fd = g_vpp_gate_vpp_fd;
    int resolver_fd = g_vpp_resolver_fd;
    int oi3_control_fd = g_oi3_control_fd;
    g_vpp_pid = -1;
    g_vpp_monitor_running = false;
    g_vpp_monitor_show_command[0] = '\0';
    g_vpp_underlay_epoch = 0;
    g_vpp_underlay_handle = -1;
    g_vpp_underlay_available = false;
    g_oi5_mode = false;
    g_oi5_log[0] = '\0';
    g_oi5_hev_lib[0] = '\0';
    g_vpp_shim_running = false;
    g_vpp_shim_fd = -1;
    g_vpp_gate_running = false;
    g_vpp_gate_tun_fd = -1;
    g_vpp_gate_vpp_fd = -1;
    g_vpp_gate_block_uid = -1;
    g_vpp_resolver_running = false;
    g_vpp_resolver_fd = -1;
    g_vpp_resolver_block_uid = -1;
    g_admission_uid = -1;
    g_admission_policy_logged = false;
    g_oi3_control_started = false;
    g_oi3_control_running = false;
    g_oi3_control_fd = -1;
    pthread_mutex_unlock(&g_lock);

    if (shim_fd >= 0) {
        close(shim_fd);
    }
    if (gate_tun_fd >= 0) {
        close(gate_tun_fd);
    }
    if (gate_vpp_fd >= 0) {
        close(gate_vpp_fd);
    }
    if (resolver_fd >= 0) {
        close(resolver_fd);
    }
    if (oi3_control_fd >= 0) {
        close(oi3_control_fd);
    }
    if (pid > 0) {
        kill(pid, SIGTERM);
        for (int i = 0; i < 10; i++) {
            int status = 0;
            pid_t rv = waitpid(pid, &status, WNOHANG);
            if (rv == pid) {
                pid = -1;
                break;
            }
            if (rv < 0 && errno == ECHILD) {
                pid = -1;
                break;
            }
            usleep(100000);
        }
        if (pid > 0) {
            if (kill(pid, SIGKILL) < 0 && errno == ESRCH) {
                pid = -1;
            }
            if (pid > 0) {
                waitpid(pid, NULL, 0);
            }
        }
    }

    vpp_unlink_runtime_sockets();

    if (was_monitoring) {
        pthread_join(g_vpp_monitor_thread, NULL);
    }
    if (was_shim_running) {
        pthread_join(g_vpp_shim_thread, NULL);
    }
    if (was_gate_running) {
        pthread_join(g_vpp_gate_thread, NULL);
    }
    if (was_resolver_running) {
        pthread_join(g_vpp_resolver_thread, NULL);
    }
    if (was_oi3_control_started) {
        pthread_join(g_oi3_control_thread, NULL);
    }
    if (was_gate_running || was_resolver_running) {
        clear_owner_lookup(env);
    }
    stop_oi2_broker(env);
    stop_protect_broker(env);
}

static int hev_child_protect_socket(int socket_fd, void *data) {
    int broker_fd = *(int *)data;
    return send_fd_and_wait_result(broker_fd, socket_fd);
}

static void run_hev_child(const char *native_dir, const char *log_path, int fd,
                          int socks_port, int protect_fd) {
    char hev_path[PATH_BUF_SIZE];
    char config[1024];
    char socks_address[INET_ADDRSTRLEN] = "127.0.0.1";
    if (protect_fd >= 0 && find_wlan_ipv4(socks_address, sizeof(socks_address)) < 0) {
        dprintf(STDERR_FILENO, "failed to find wlan0 IPv4 address\n");
        _exit(120);
    }

    snprintf(config, sizeof(config),
            "tunnel:\n"
            "  mtu: 1500\n"
            "socks5:\n"
            "  address: %s\n"
            "  port: %d\n"
            "  udp: tcp\n"
            "misc:\n"
            "  log-file: stderr\n"
            "  log-level: info\n"
            "  connect-timeout: 2000\n"
            "  tcp-read-write-timeout: 5000\n"
            "  udp-read-write-timeout: 5000\n",
            socks_address, socks_port);

    int out = open(log_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (out >= 0) {
        dup2(out, STDOUT_FILENO);
        dup2(out, STDERR_FILENO);
        if (out > STDERR_FILENO) {
            close(out);
        }
    }

    snprintf(hev_path, sizeof(hev_path), "%s/libhev-socks5-tunnel.so", native_dir);
    void *handle = dlopen(hev_path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        dprintf(STDERR_FILENO, "dlopen failed: %s\n", dlerror());
        _exit(121);
    }

    void *sym = dlsym(handle, "hev_socks5_tunnel_main_from_str");
    if (!sym) {
        dprintf(STDERR_FILENO, "dlsym failed: %s\n", dlerror());
        _exit(122);
    }

    if (protect_fd >= 0) {
        void *protect_sym = dlsym(handle, "hev_socks5_set_socket_protect");
        if (!protect_sym) {
            dprintf(STDERR_FILENO, "protect dlsym failed: %s\n", dlerror());
            _exit(124);
        }
        hev_set_socket_protect_fn set_socket_protect =
            (hev_set_socket_protect_fn)protect_sym;
        set_socket_protect(hev_child_protect_socket, &protect_fd);
        dprintf(STDERR_FILENO, "protect callback enabled broker-fd=%d socks=%s:%d\n",
                protect_fd, socks_address, socks_port);
    }

    set_cloexec(fd, false);
    hev_main_from_str_fn main_from_str = (hev_main_from_str_fn)sym;
    int rc = main_from_str(config, (unsigned int)strlen(config), fd);
    dprintf(STDERR_FILENO, "hev main returned rc=%d\n", rc);
    _exit(rc == 0 ? 0 : 123);
}

JNIEXPORT jint JNICALL
Java_com_sakamoto_snort_vpnlite_SnortVpnService_nativeStartHevProbe(
        JNIEnv *env, jclass clazz, jstring native_library_dir, jstring files_dir) {
    (void)clazz;

    const char *native_dir = (*env)->GetStringUTFChars(env, native_library_dir, NULL);
    if (!native_dir) {
        return -1;
    }
    const char *app_files = (*env)->GetStringUTFChars(env, files_dir, NULL);
    if (!app_files) {
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        return -1;
    }

    pthread_mutex_lock(&g_lock);
    if (g_hev_pid > 0) {
        pthread_mutex_unlock(&g_lock);
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        return -2;
    }
    pthread_mutex_unlock(&g_lock);

    char logs_dir[PATH_BUF_SIZE];
    char log_path[PATH_BUF_SIZE];
    char hev_path[PATH_BUF_SIZE];
    snprintf(logs_dir, sizeof(logs_dir), "%s/logs", app_files);
    snprintf(log_path, sizeof(log_path), "%s/hev-probe.log", logs_dir);
    snprintf(hev_path, sizeof(hev_path), "%s/libhev-socks5-tunnel.so", native_dir);

    if (!path_exists(hev_path)) {
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        return -3;
    }
    if (mkdir_p(logs_dir) < 0) {
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        return -4;
    }
    unlink(log_path);

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) < 0) {
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        return -5;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        return -6;
    }

    if (pid == 0) {
        close(fds[0]);
        run_hev_child(native_dir, log_path, fds[1], 9, -1);
        _exit(127);
    }

    close(fds[1]);
    usleep(300000);

    int status = 0;
    pid_t exited = waitpid(pid, &status, WNOHANG);
    if (exited == pid) {
        close(fds[0]);
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        return -7;
    }

    pthread_mutex_lock(&g_lock);
    g_hev_pid = pid;
    g_hev_driver_fd = fds[0];
    snprintf(g_hev_log_path, sizeof(g_hev_log_path), "%s", log_path);
    pthread_mutex_unlock(&g_lock);

    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "started HEV pid=%d log=%s", pid, log_path);
    (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
    (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
    return 0;
}

JNIEXPORT void JNICALL
Java_com_sakamoto_snort_vpnlite_SnortVpnService_nativeStopHevProbe(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;

    pthread_mutex_lock(&g_lock);
    pid_t pid = g_hev_pid;
    int fd = g_hev_driver_fd;
    char log_path[PATH_BUF_SIZE];
    snprintf(log_path, sizeof(log_path), "%s", g_hev_log_path);
    g_hev_pid = -1;
    g_hev_driver_fd = -1;
    g_hev_log_path[0] = '\0';
    pthread_mutex_unlock(&g_lock);

    if (fd >= 0) {
        close(fd);
    }
    terminate_child(pid);
    if (pid > 0) {
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "stopped HEV pid=%d log=%s", pid,
                            log_path);
    }
}
