/* SPDX-License-Identifier: Apache-2.0 */

#include <jni.h>

#include <android/log.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define LOG_TAG "SakamotoVpnTransport"
#define PATH_BUF_SIZE 1024
#define HEV_SOCKS_PORT 41080

typedef int (*hev_main_from_str_fn)(const char *config, unsigned int config_len, int tun_fd);
typedef void (*hev_set_socket_protect_fn)(int (*func)(int fd, void *data), void *data);

static JavaVM *g_vm;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_protect_thread;
static bool g_protect_thread_started;
static bool g_running;
static int g_broker_fd = -1;
static pid_t g_hev_pid = -1;
static jobject g_owner;
static jmethodID g_protect_method;
static char g_protect_log[PATH_BUF_SIZE];
static char g_hev_log[PATH_BUF_SIZE];

JNIEXPORT void JNICALL
Java_com_sakamoto_snort_androidruntime_VpnHevTransportSession_nativeStopHevTransport(
    JNIEnv *env, jclass clazz);

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

static int find_wlan_ipv4(char *out, size_t out_len) {
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0) {
        return -1;
    }
    int rc = -1;
    for (struct ifaddrs *it = ifaddr; it != NULL; it = it->ifa_next) {
        if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        if ((it->ifa_flags & IFF_UP) == 0 || strcmp(it->ifa_name, "wlan0") != 0) {
            continue;
        }
        const struct sockaddr_in *addr = (const struct sockaddr_in *)it->ifa_addr;
        if (inet_ntop(AF_INET, &addr->sin_addr, out, out_len) != NULL) {
            rc = 0;
            break;
        }
    }
    freeifaddrs(ifaddr);
    return rc;
}

static int send_fd_and_wait_result(int broker_fd, int socket_fd) {
    char payload = 'P';
    char control[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {.iov_base = &payload, .iov_len = sizeof(payload)};
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &socket_fd, sizeof(socket_fd));
    if (sendmsg(broker_fd, &msg, 0) != (ssize_t)sizeof(payload)) {
        return -1;
    }

    int result = -1;
    ssize_t received;
    do {
        received = recv(broker_fd, &result, sizeof(result), 0);
    } while (received < 0 && errno == EINTR);
    return received == (ssize_t)sizeof(result) && result == 1 ? 0 : -1;
}

static int recv_protect_fd(int broker_fd) {
    char payload;
    char control[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {.iov_base = &payload, .iov_len = sizeof(payload)};
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
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
    if ((*g_vm)->GetEnv(g_vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != JNI_OK) {
            return NULL;
        }
        attached = true;
    }

    FILE *file = fopen(g_protect_log, "a");
    log_line(file, "protect broker start");
    for (;;) {
        pthread_mutex_lock(&g_lock);
        bool running = g_running;
        int broker_fd = g_broker_fd;
        jobject owner = g_owner;
        jmethodID method = g_protect_method;
        pthread_mutex_unlock(&g_lock);
        if (!running || broker_fd < 0 || owner == NULL || method == NULL) {
            break;
        }

        int socket_fd = recv_protect_fd(broker_fd);
        if (socket_fd < 0) {
            pthread_mutex_lock(&g_lock);
            running = g_running;
            pthread_mutex_unlock(&g_lock);
            if (running && errno != EBADF && errno != ECONNRESET) {
                log_line(file, "protect broker receive stop errno=%d %s", errno,
                         strerror(errno));
            }
            break;
        }
        jboolean protected_socket =
            (*env)->CallBooleanMethod(env, owner, method, (jint)socket_fd);
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
            protected_socket = JNI_FALSE;
        }
        int result = protected_socket == JNI_TRUE ? 1 : 0;
        log_line(file, "protect fd=%d result=%d", socket_fd, result);
        close(socket_fd);
        if (send(broker_fd, &result, sizeof(result), 0) != (ssize_t)sizeof(result)) {
            log_line(file, "protect result send failed errno=%d %s", errno, strerror(errno));
            break;
        }
    }
    log_line(file, "protect broker stop");
    if (file) {
        fclose(file);
    }
    if (attached) {
        (*g_vm)->DetachCurrentThread(g_vm);
    }
    return NULL;
}

static int hev_child_protect_socket(int socket_fd, void *data) {
    int broker_fd = *(int *)data;
    return send_fd_and_wait_result(broker_fd, socket_fd);
}

static void run_hev_child(const char *native_dir, const char *log_path, int transport_fd,
                          int protect_fd) {
    char hev_path[PATH_BUF_SIZE];
    char socks_address[INET_ADDRSTRLEN] = "127.0.0.1";
    if (find_wlan_ipv4(socks_address, sizeof(socks_address)) != 0) {
        dprintf(STDERR_FILENO, "failed to find wlan0 IPv4 address\n");
        _exit(120);
    }

    char config[1024];
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
             socks_address, HEV_SOCKS_PORT);

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
    void *main_sym = dlsym(handle, "hev_socks5_tunnel_main_from_str");
    if (!main_sym) {
        dprintf(STDERR_FILENO, "dlsym failed: %s\n", dlerror());
        _exit(122);
    }
    void *protect_sym = dlsym(handle, "hev_socks5_set_socket_protect");
    if (!protect_sym) {
        dprintf(STDERR_FILENO, "protect dlsym failed: %s\n", dlerror());
        _exit(124);
    }
    hev_set_socket_protect_fn set_socket_protect =
        (hev_set_socket_protect_fn)protect_sym;
    set_socket_protect(hev_child_protect_socket, &protect_fd);
    dprintf(STDERR_FILENO, "protect callback enabled broker-fd=%d socks=%s:%d\n",
            protect_fd, socks_address, HEV_SOCKS_PORT);

    hev_main_from_str_fn main_from_str = (hev_main_from_str_fn)main_sym;
    int rc = main_from_str(config, (unsigned int)strlen(config), transport_fd);
    dprintf(STDERR_FILENO, "hev main returned rc=%d\n", rc);
    _exit(rc == 0 ? 0 : 123);
}

static void terminate_child(pid_t pid) {
    if (pid <= 0) {
        return;
    }
    kill(pid, SIGTERM);
    for (int i = 0; i < 15; ++i) {
        int status = 0;
        pid_t exited = waitpid(pid, &status, WNOHANG);
        if (exited == pid) {
            return;
        }
        usleep(100000);
    }
    kill(pid, SIGKILL);
    (void)waitpid(pid, NULL, 0);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    g_vm = vm;
    return JNI_VERSION_1_6;
}

JNIEXPORT jintArray JNICALL
Java_com_sakamoto_snort_androidruntime_VpnHevTransportSession_nativeCreateTransportSocketPair(
    JNIEnv *env, jclass clazz) {
    (void)clazz;
    int fds[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) != 0) {
        fds[0] = -1;
        fds[1] = -1;
    }
    jintArray result = (*env)->NewIntArray(env, 2);
    if (!result) {
        if (fds[0] >= 0) {
            close(fds[0]);
        }
        if (fds[1] >= 0) {
            close(fds[1]);
        }
        return NULL;
    }
    jint values[2] = {(jint)fds[0], (jint)fds[1]};
    (*env)->SetIntArrayRegion(env, result, 0, 2, values);
    return result;
}

JNIEXPORT jint JNICALL
Java_com_sakamoto_snort_androidruntime_VpnHevTransportSession_nativeStartHevTransport(
    JNIEnv *env, jclass clazz, jint transport_fd, jstring native_library_dir, jstring log_dir,
    jobject owner) {
    if (transport_fd < 0 || native_library_dir == NULL || log_dir == NULL || owner == NULL) {
        if (transport_fd >= 0) {
            close((int)transport_fd);
        }
        return -1;
    }

    const char *native_dir = (*env)->GetStringUTFChars(env, native_library_dir, NULL);
    const char *logs = (*env)->GetStringUTFChars(env, log_dir, NULL);
    if (!native_dir || !logs) {
        if (native_dir) {
            (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        }
        if (logs) {
            (*env)->ReleaseStringUTFChars(env, log_dir, logs);
        }
        close((int)transport_fd);
        return -2;
    }
    mkdir(logs, 0700);
    snprintf(g_hev_log, sizeof(g_hev_log), "%s/vpn-hev.log", logs);
    snprintf(g_protect_log, sizeof(g_protect_log), "%s/vpn-hev-protect.log", logs);

    int protect_fds[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, protect_fds) != 0) {
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        (*env)->ReleaseStringUTFChars(env, log_dir, logs);
        close((int)transport_fd);
        return -3;
    }

    jobject owner_ref = (*env)->NewGlobalRef(env, owner);
    jclass owner_class = (*env)->GetObjectClass(env, owner);
    jmethodID protect_method =
        owner_class == NULL ? NULL
                            : (*env)->GetMethodID(env, owner_class, "protectSocketForNative",
                                                  "(I)Z");
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        protect_method = NULL;
    }
    if (!owner_ref || !protect_method) {
        if (owner_ref) {
            (*env)->DeleteGlobalRef(env, owner_ref);
        }
        close(protect_fds[0]);
        close(protect_fds[1]);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        (*env)->ReleaseStringUTFChars(env, log_dir, logs);
        close((int)transport_fd);
        return -4;
    }

    pthread_mutex_lock(&g_lock);
    bool already_running = g_running || g_hev_pid > 0;
    pthread_mutex_unlock(&g_lock);
    if (already_running) {
        (*env)->DeleteGlobalRef(env, owner_ref);
        close(protect_fds[0]);
        close(protect_fds[1]);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        (*env)->ReleaseStringUTFChars(env, log_dir, logs);
        close((int)transport_fd);
        return -5;
    }

    pid_t pid = fork();
    if (pid < 0) {
        (*env)->DeleteGlobalRef(env, owner_ref);
        close(protect_fds[0]);
        close(protect_fds[1]);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        (*env)->ReleaseStringUTFChars(env, log_dir, logs);
        close((int)transport_fd);
        return -6;
    }
    if (pid == 0) {
        close(protect_fds[0]);
        run_hev_child(native_dir, g_hev_log, (int)transport_fd, protect_fds[1]);
        _exit(127);
    }
    close((int)transport_fd);
    close(protect_fds[1]);

    pthread_mutex_lock(&g_lock);
    g_broker_fd = protect_fds[0];
    g_owner = owner_ref;
    g_protect_method = protect_method;
    g_hev_pid = pid;
    g_running = true;
    g_protect_thread_started = false;
    pthread_mutex_unlock(&g_lock);

    int thread_rc = pthread_create(&g_protect_thread, NULL, protect_broker_thread, NULL);
    if (thread_rc != 0) {
        Java_com_sakamoto_snort_androidruntime_VpnHevTransportSession_nativeStopHevTransport(
            env, clazz);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        (*env)->ReleaseStringUTFChars(env, log_dir, logs);
        return -7;
    }
    pthread_mutex_lock(&g_lock);
    g_protect_thread_started = true;
    pthread_mutex_unlock(&g_lock);

    (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
    (*env)->ReleaseStringUTFChars(env, log_dir, logs);
    return 0;
}

JNIEXPORT void JNICALL
Java_com_sakamoto_snort_androidruntime_VpnHevTransportSession_nativeStopHevTransport(
    JNIEnv *env, jclass clazz) {
    (void)clazz;
    pthread_mutex_lock(&g_lock);
    bool thread_started = g_protect_thread_started;
    pthread_t thread = g_protect_thread;
    int broker_fd = g_broker_fd;
    pid_t pid = g_hev_pid;
    jobject owner = g_owner;
    g_running = false;
    g_broker_fd = -1;
    g_hev_pid = -1;
    g_owner = NULL;
    g_protect_method = NULL;
    g_protect_thread_started = false;
    pthread_mutex_unlock(&g_lock);

    if (broker_fd >= 0) {
        shutdown(broker_fd, SHUT_RDWR);
        close(broker_fd);
    }
    if (thread_started) {
        pthread_join(thread, NULL);
    }
    terminate_child(pid);
    if (owner) {
        (*env)->DeleteGlobalRef(env, owner);
    }
}

JNIEXPORT void JNICALL
Java_com_sakamoto_snort_androidruntime_VpnHevTransportSession_nativeCloseFd(
    JNIEnv *env, jclass clazz, jint fd) {
    (void)env;
    (void)clazz;
    if (fd >= 0) {
        close((int)fd);
    }
}
