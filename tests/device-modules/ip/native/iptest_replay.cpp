/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr char kMagic[8] = {'I', 'P', 'T', 'R', 'C', 'E', '1', '\0'};
constexpr std::uint32_t kTraceVersion = 1;

struct TraceHeaderRaw {
    char magic[8];
    std::uint32_t version_be;
    std::uint32_t entry_count_be;
    std::uint32_t reserved_be;
} __attribute__((packed));

struct TraceEntryRaw {
    std::uint32_t src_ip_be;
    std::uint32_t dst_ip_be;
    std::uint16_t src_port_be;
    std::uint16_t dst_port_be;
    std::uint32_t conn_bytes_be;
} __attribute__((packed));

static_assert(sizeof(TraceHeaderRaw) == 20, "unexpected TraceHeaderRaw size");
static_assert(sizeof(TraceEntryRaw) == 16, "unexpected TraceEntryRaw size");

struct TraceEntry {
    in_addr src_ip{};
    in_addr dst_ip{};
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::uint32_t conn_bytes = 0;
};

struct Options {
    std::string trace_path;
    std::uint32_t seconds = 5;
    std::uint32_t threads = 1;
    std::uint32_t recv_timeout_ms = 3000;
};

struct Totals {
    std::atomic<std::uint64_t> bytes{0};
    std::atomic<std::uint64_t> connections{0};
    std::atomic<std::uint64_t> failures{0};
};

void usage(const char *prog) {
    std::fprintf(stderr,
                 "Usage: %s --trace <path> [--seconds N] [--threads N] [--recv-timeout-ms N]\n",
                 prog);
}

bool parse_uint32(const char *text, std::uint32_t &out) {
    if (text == nullptr || *text == '\0') {
        return false;
    }
    char *end = nullptr;
    errno = 0;
    const unsigned long value = std::strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value > UINT32_MAX) {
        return false;
    }
    out = static_cast<std::uint32_t>(value);
    return true;
}

bool parse_args(const int argc, char **argv, Options &opt) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--trace" && i + 1 < argc) {
            opt.trace_path = argv[++i];
        } else if (arg == "--seconds" && i + 1 < argc) {
            if (!parse_uint32(argv[++i], opt.seconds) || opt.seconds == 0) {
                return false;
            }
        } else if (arg == "--threads" && i + 1 < argc) {
            if (!parse_uint32(argv[++i], opt.threads) || opt.threads == 0) {
                return false;
            }
        } else if (arg == "--recv-timeout-ms" && i + 1 < argc) {
            if (!parse_uint32(argv[++i], opt.recv_timeout_ms) || opt.recv_timeout_ms == 0) {
                return false;
            }
        } else if (arg == "-h" || arg == "--help") {
            usage(argv[0]);
            std::exit(0);
        } else {
            return false;
        }
    }
    return !opt.trace_path.empty();
}

bool load_trace(const std::string &path, std::vector<TraceEntry> &entries, std::string &error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = "cannot open trace";
        return false;
    }

    TraceHeaderRaw header{};
    in.read(reinterpret_cast<char *>(&header), sizeof(header));
    if (!in) {
        error = "cannot read trace header";
        return false;
    }

    if (std::memcmp(header.magic, kMagic, sizeof(kMagic)) != 0) {
        error = "trace magic mismatch";
        return false;
    }

    const std::uint32_t version = ntohl(header.version_be);
    if (version != kTraceVersion) {
        error = "unsupported trace version";
        return false;
    }

    const std::uint32_t count = ntohl(header.entry_count_be);
    if (count == 0) {
        error = "trace entry count is zero";
        return false;
    }

    entries.resize(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        TraceEntryRaw raw{};
        in.read(reinterpret_cast<char *>(&raw), sizeof(raw));
        if (!in) {
            error = "trace truncated";
            return false;
        }
        TraceEntry entry{};
        entry.src_ip.s_addr = raw.src_ip_be;
        entry.dst_ip.s_addr = raw.dst_ip_be;
        entry.src_port = ntohs(raw.src_port_be);
        entry.dst_port = ntohs(raw.dst_port_be);
        entry.conn_bytes = ntohl(raw.conn_bytes_be);
        if (entry.dst_ip.s_addr == 0 || entry.dst_port == 0 || entry.conn_bytes == 0) {
            error = "trace entry contains zero dst/bytes";
            return false;
        }
        entries[i] = entry;
    }
    return true;
}

bool run_one_connection(const TraceEntry &entry, const std::uint32_t recv_timeout_ms,
                        std::uint64_t &bytes_read) {
    bytes_read = 0;

    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return false;
    }

    timeval tv{};
    tv.tv_sec = static_cast<time_t>(recv_timeout_ms / 1000);
    tv.tv_usec = static_cast<suseconds_t>((recv_timeout_ms % 1000) * 1000);
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr = entry.src_ip;
    local.sin_port = htons(entry.src_port);
    if (entry.src_ip.s_addr != 0 || entry.src_port != 0) {
        if (::bind(fd, reinterpret_cast<const sockaddr *>(&local), sizeof(local)) != 0) {
            ::close(fd);
            return false;
        }
    }

    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_addr = entry.dst_ip;
    remote.sin_port = htons(entry.dst_port);
    if (::connect(fd, reinterpret_cast<const sockaddr *>(&remote), sizeof(remote)) != 0) {
        ::close(fd);
        return false;
    }

    char buffer[4096];
    std::uint32_t remaining = entry.conn_bytes;
    while (remaining > 0) {
        const std::size_t want = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        const ssize_t n = ::recv(fd, buffer, want, 0);
        if (n <= 0) {
            ::close(fd);
            return false;
        }
        bytes_read += static_cast<std::uint64_t>(n);
        remaining -= static_cast<std::uint32_t>(n);
    }

    ::close(fd);
    return true;
}

void worker_loop(const std::vector<TraceEntry> &entries, const Options &opt, const std::uint32_t worker_id,
                 Totals &totals, const std::chrono::steady_clock::time_point deadline) {
    const std::size_t stride = opt.threads;
    std::size_t idx = worker_id % entries.size();

    while (std::chrono::steady_clock::now() < deadline) {
        const TraceEntry &entry = entries[idx];
        std::uint64_t bytes = 0;
        if (run_one_connection(entry, opt.recv_timeout_ms, bytes)) {
            totals.bytes.fetch_add(bytes, std::memory_order_relaxed);
            totals.connections.fetch_add(1, std::memory_order_relaxed);
        } else {
            totals.failures.fetch_add(1, std::memory_order_relaxed);
        }

        idx += stride;
        if (idx >= entries.size()) {
            idx %= entries.size();
        }
    }
}

} // namespace

int main(int argc, char **argv) {
    Options opt{};
    if (!parse_args(argc, argv, opt)) {
        usage(argv[0]);
        return 2;
    }

    std::vector<TraceEntry> entries;
    std::string error;
    if (!load_trace(opt.trace_path, entries, error)) {
        std::fprintf(stderr, "trace load failed: %s (%s)\n", error.c_str(), opt.trace_path.c_str());
        return 1;
    }

    Totals totals{};
    const auto start = std::chrono::steady_clock::now();
    const auto deadline = start + std::chrono::seconds(opt.seconds);

    std::vector<std::thread> workers;
    workers.reserve(opt.threads);
    for (std::uint32_t i = 0; i < opt.threads; ++i) {
        workers.emplace_back(worker_loop, std::cref(entries), std::cref(opt), i, std::ref(totals), deadline);
    }
    for (auto &t : workers) {
        t.join();
    }

    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - start)
                                .count();

    std::printf(
        "IPTEST_REPLAY_RESULT_JSON "
        "{\"bytes\":%" PRIu64 ",\"connections\":%" PRIu64 ",\"failures\":%" PRIu64
        ",\"threads\":%u,\"seconds\":%u,\"elapsed_ms\":%" PRIu64 ",\"trace_entries\":%zu}\n",
        totals.bytes.load(std::memory_order_relaxed),
        totals.connections.load(std::memory_order_relaxed),
        totals.failures.load(std::memory_order_relaxed), opt.threads, opt.seconds,
        static_cast<std::uint64_t>(elapsed_ms), entries.size());

    return 0;
}
