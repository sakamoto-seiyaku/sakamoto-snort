/* Explicitly authorized, one-device repair tool; never a Product fallback.
 * Only UID 12632, only stale interface 952, only IIF_MATCH (bit 7).
 */
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int call(int command, union bpf_attr *attr)
{
    int rc = (int)syscall(__NR_bpf, command, attr, sizeof(*attr));
    if (rc < 0) { fprintf(stderr, "bpf command=%d ", command); perror("failed"); }
    return rc;
}

int main(int argc, char **argv)
{
    const char *path = "/sys/fs/bpf/netd_shared/map_netd_uid_owner_map";
    uint32_t uid = 12632;
    struct { uint32_t iif, rule; } before = {0}, after = {0}, check = {0};
    union bpf_attr attr = {0};
    attr.pathname = (uintptr_t)path;
    int fd = call(BPF_OBJ_GET, &attr);
    if (fd < 0) return 1;
    struct bpf_map_info info = {0};
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = fd;
    attr.info.info_len = sizeof(info);
    attr.info.info = (uintptr_t)&info;
    if (call(BPF_OBJ_GET_INFO_BY_FD, &attr) < 0) return 1;
    if (info.key_size != sizeof(uid) || info.value_size != sizeof(before)) return 2;
    printf("map_type=%u map_flags=%u key_size=%u value_size=%u\n", info.type, info.map_flags, info.key_size, info.value_size);
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd; attr.key = (uintptr_t)&uid; attr.value = (uintptr_t)&before;
    if (call(BPF_MAP_LOOKUP_ELEM, &attr) < 0) return 1;
    printf("map_id=%u uid=%u before_iif=%u before_rule=%u\n", info.id, uid, before.iif, before.rule);
    fflush(stdout);
    if (argc == 1) return 0;
    if (argc != 2 || strcmp(argv[1], "--clear-authorized") || before.iif != 952 || !(before.rule & (1U << 7))) return 2;
    after = before; after.iif = 0; after.rule &= ~(1U << 7);
    attr.value = (uintptr_t)&check;
    if (call(BPF_MAP_LOOKUP_ELEM, &attr) < 0 || memcmp(&before, &check, sizeof(before))) return 2;
    attr.value = (uintptr_t)&after; attr.flags = BPF_EXIST;
    if (call(BPF_MAP_UPDATE_ELEM, &attr) < 0) return 1;
    attr.value = (uintptr_t)&check; attr.flags = 0;
    if (call(BPF_MAP_LOOKUP_ELEM, &attr) < 0 || memcmp(&after, &check, sizeof(after))) return 3;
    printf("uid=%u after_iif=%u after_rule=%u preserved_non_iif=1\n", uid, check.iif, check.rule);
    close(fd);
    return 0;
}
