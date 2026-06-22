#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <android/log.h>

#define LOG_TAG "SnortVpnLiteNative"
#define BUF_SIZE 4096

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_thread;
static bool g_running;
static int g_fd = -1;
static int g_max_packets;
static char g_log_path[512];

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
        log_line(file, "packet=%d len=%zd ipv4 proto=%u %s -> %s", count, len, buf[9], src, dst);
        return;
    }

    if (version == 6 && len >= 40) {
        char src[INET6_ADDRSTRLEN];
        char dst[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, buf + 8, src, sizeof(src));
        inet_ntop(AF_INET6, buf + 24, dst, sizeof(dst));
        log_line(file, "packet=%d len=%zd ipv6 next=%u %s -> %s", count, len, buf[6], src, dst);
        return;
    }

    log_line(file, "packet=%d len=%zd version=%u short-or-unknown", count, len, version);
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

JNIEXPORT jint JNICALL
Java_com_sakamoto_snort_vpnlite_SnortVpnService_nativeStartProbe(
        JNIEnv *env, jclass clazz, jint fd, jstring log_path, jint max_packets) {
    (void)clazz;
    const char *path = (*env)->GetStringUTFChars(env, log_path, NULL);
    if (!path) {
        close(fd);
        return -1;
    }

    pthread_mutex_lock(&g_lock);
    if (g_running) {
        pthread_mutex_unlock(&g_lock);
        (*env)->ReleaseStringUTFChars(env, log_path, path);
        close(fd);
        return -2;
    }

    snprintf(g_log_path, sizeof(g_log_path), "%s", path);
    g_fd = fd;
    g_max_packets = max_packets;
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
        pthread_mutex_unlock(&g_lock);
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
    }
}
