#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
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

#define LOG_TAG "SnortVpnLiteNative"
#define BUF_SIZE 4096
#define PATH_BUF_SIZE 1024
#define VPP_TUN_FD 3

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_thread;
static bool g_running;
static int g_fd = -1;
static int g_max_packets;
static char g_log_path[PATH_BUF_SIZE];

static pthread_t g_vpp_monitor_thread;
static bool g_vpp_monitor_running;
static pid_t g_vpp_pid = -1;
static char g_vpp_cli_sock[PATH_BUF_SIZE];
static char g_vpp_cli_log[PATH_BUF_SIZE];

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

static void append_cli_output(FILE *file, const char *label, const char *buf, ssize_t len) {
    if (!file || len <= 0) {
        return;
    }
    fprintf(file, "\n# %s\n", label);
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

static int run_cli_command(const char *sock_path, const char *command, FILE *file) {
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

    char input[256];
    snprintf(input, sizeof(input), "%s\nquit\n", command);
    if (send(fd, input, strlen(input), MSG_NOSIGNAL) < 0) {
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
    append_cli_output(file, command, output, total);
    close(fd);
    return total > 0 ? 0 : -1;
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

static void *vpp_monitor_thread(void *arg) {
    (void)arg;
    FILE *file = fopen(g_vpp_cli_log, "a");

    pthread_mutex_lock(&g_lock);
    pid_t pid = g_vpp_pid;
    char sock_path[PATH_BUF_SIZE];
    snprintf(sock_path, sizeof(sock_path), "%s", g_vpp_cli_sock);
    pthread_mutex_unlock(&g_lock);

    log_line(file, "vpp monitor start pid=%d cli=%s", pid, sock_path);
    sleep(3);

    for (int i = 0; i < 8; i++) {
        pthread_mutex_lock(&g_lock);
        bool running = g_vpp_monitor_running;
        pthread_mutex_unlock(&g_lock);
        if (!running) {
            break;
        }

        run_cli_command(sock_path, "show tun-poc", file);
        sleep(1);
    }

    log_line(file, "vpp monitor stop");
    if (file) {
        fclose(file);
    }
    return NULL;
}

static int write_vpp_files(const char *native_dir, const char *files_dir,
                           char *startup_conf, size_t startup_conf_len,
                           char *stdout_log, size_t stdout_log_len) {
    char vpp_dir[PATH_BUF_SIZE];
    char runtime_dir[PATH_BUF_SIZE];
    char logs_dir[PATH_BUF_SIZE];
    char shm_dir[PATH_BUF_SIZE];
    char startup_exec[PATH_BUF_SIZE];
    char vpp_log[PATH_BUF_SIZE];
    char plugin_name[64] = "tun_poc_plugin.so";
    char plugin_path[PATH_BUF_SIZE];
    char conf[4096];
    char exec_text[256];

    snprintf(vpp_dir, sizeof(vpp_dir), "%s/vpp", files_dir);
    snprintf(runtime_dir, sizeof(runtime_dir), "%s/runtime", vpp_dir);
    snprintf(logs_dir, sizeof(logs_dir), "%s/logs", vpp_dir);
    snprintf(shm_dir, sizeof(shm_dir), "%s/shm", vpp_dir);
    snprintf(startup_conf, startup_conf_len, "%s/startup.conf", runtime_dir);
    snprintf(startup_exec, sizeof(startup_exec), "%s/startup.exec", runtime_dir);
    snprintf(stdout_log, stdout_log_len, "%s/vpp-stdout.log", logs_dir);
    snprintf(vpp_log, sizeof(vpp_log), "%s/vpp.log", logs_dir);
    snprintf(g_vpp_cli_sock, sizeof(g_vpp_cli_sock), "%s/cli.sock", runtime_dir);
    snprintf(g_vpp_cli_log, sizeof(g_vpp_cli_log), "%s/vpp-cli.log", logs_dir);

    if (mkdir_p(runtime_dir) < 0 || mkdir_p(logs_dir) < 0 || mkdir_p(shm_dir) < 0) {
        return -1;
    }
    unlink(g_vpp_cli_sock);
    unlink(g_vpp_cli_log);
    unlink(stdout_log);
    unlink(vpp_log);

    snprintf(plugin_path, sizeof(plugin_path), "%s/%s", native_dir, plugin_name);
    if (!path_exists(plugin_path)) {
        snprintf(plugin_name, sizeof(plugin_name), "%s", "libtun_poc_plugin.so");
    }

    snprintf(exec_text, sizeof(exec_text),
             "tun-poc enable fd %d mode count-only\n"
             "show tun-poc\n",
             VPP_TUN_FD);
    if (write_text_file(startup_exec, exec_text) < 0) {
        return -1;
    }

    snprintf(conf, sizeof(conf),
             "unix {\n"
             "  nodaemon\n"
             "  nobanner\n"
             "  runtime-dir %s\n"
             "  poll-sleep-usec 1000\n"
             "  log %s\n"
             "  cli-listen %s\n"
             "  startup-config %s\n"
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
             "  plugin default { disable }\n"
             "  plugin %s { enable }\n"
             "}\n",
             runtime_dir, vpp_log, g_vpp_cli_sock, startup_exec, runtime_dir,
             native_dir, plugin_name);
    return write_text_file(startup_conf, conf);
}

JNIEXPORT jint JNICALL
Java_com_sakamoto_snort_vpnlite_SnortVpnService_nativeStartVppProbe(
        JNIEnv *env, jclass clazz, jint fd, jstring native_library_dir, jstring files_dir) {
    (void)clazz;

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

    char vpp_path[PATH_BUF_SIZE];
    char startup_conf[PATH_BUF_SIZE];
    char stdout_log[PATH_BUF_SIZE];
    snprintf(vpp_path, sizeof(vpp_path), "%s/libvpppoc.so", native_dir);

    if (!path_exists(vpp_path)) {
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        close(fd);
        return -2;
    }
    if (write_vpp_files(native_dir, app_files, startup_conf, sizeof(startup_conf),
                        stdout_log, sizeof(stdout_log)) < 0) {
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        close(fd);
        return -3;
    }

    pthread_mutex_lock(&g_lock);
    if (g_vpp_pid > 0) {
        pthread_mutex_unlock(&g_lock);
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        close(fd);
        return -4;
    }
    pthread_mutex_unlock(&g_lock);

    pid_t pid = fork();
    if (pid < 0) {
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        close(fd);
        return -5;
    }

    if (pid == 0) {
        if (fd != VPP_TUN_FD) {
            dup2(fd, VPP_TUN_FD);
            close(fd);
        }
        set_cloexec(VPP_TUN_FD, false);

        int out = open(stdout_log, O_CREAT | O_WRONLY | O_APPEND, 0600);
        if (out >= 0) {
            dup2(out, STDOUT_FILENO);
            dup2(out, STDERR_FILENO);
            if (out > STDERR_FILENO) {
                close(out);
            }
        }

        setenv("LD_LIBRARY_PATH", native_dir, 1);
        char shm_dir[PATH_BUF_SIZE];
        snprintf(shm_dir, sizeof(shm_dir), "%s/vpp/shm", app_files);
        setenv("SAKAMOTO_ANDROID_SHM_DIR", shm_dir, 1);
        execl(vpp_path, "vpp", "plugin_path", native_dir, "-c", startup_conf, (char *)NULL);
        _exit(127);
    }

    close(fd);

    pthread_mutex_lock(&g_lock);
    g_vpp_pid = pid;
    g_vpp_monitor_running = true;
    pthread_mutex_unlock(&g_lock);

    int rc = pthread_create(&g_vpp_monitor_thread, NULL, vpp_monitor_thread, NULL);
    if (rc != 0) {
        kill(pid, SIGTERM);
        pthread_mutex_lock(&g_lock);
        g_vpp_monitor_running = false;
        g_vpp_pid = -1;
        pthread_mutex_unlock(&g_lock);
        waitpid(pid, NULL, 0);
        (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
        (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
        return -6;
    }

    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "started VPP pid=%d fd=%d conf=%s", pid, fd,
                        startup_conf);
    (*env)->ReleaseStringUTFChars(env, files_dir, app_files);
    (*env)->ReleaseStringUTFChars(env, native_library_dir, native_dir);
    return 0;
}

JNIEXPORT void JNICALL
Java_com_sakamoto_snort_vpnlite_SnortVpnService_nativeStopVppProbe(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;

    pthread_mutex_lock(&g_lock);
    pid_t pid = g_vpp_pid;
    bool was_monitoring = g_vpp_monitor_running;
    g_vpp_pid = -1;
    g_vpp_monitor_running = false;
    pthread_mutex_unlock(&g_lock);

    if (pid > 0) {
        kill(pid, SIGTERM);
        for (int i = 0; i < 10; i++) {
            int status = 0;
            pid_t rv = waitpid(pid, &status, WNOHANG);
            if (rv == pid) {
                pid = -1;
                break;
            }
            usleep(100000);
        }
        if (pid > 0) {
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
        }
    }

    if (was_monitoring) {
        pthread_join(g_vpp_monitor_thread, NULL);
    }
}
