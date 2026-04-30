/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <FlowTelemetry.hpp>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <new>
#include <utility>

namespace {

class UniqueFd {
public:
    UniqueFd() = default;
    explicit UniqueFd(const int fd) : _fd(fd) {}
    ~UniqueFd() { reset(); }

    UniqueFd(const UniqueFd &) = delete;
    UniqueFd &operator=(const UniqueFd &) = delete;

    UniqueFd(UniqueFd &&other) noexcept : _fd(std::exchange(other._fd, -1)) {}
    UniqueFd &operator=(UniqueFd &&other) noexcept {
        if (this != &other) {
            reset(std::exchange(other._fd, -1));
        }
        return *this;
    }

    [[nodiscard]] int get() const noexcept { return _fd; }
    [[nodiscard]] explicit operator bool() const noexcept { return _fd >= 0; }

    int release() noexcept { return std::exchange(_fd, -1); }

    void reset(const int fd = -1) noexcept {
        if (_fd >= 0) {
            ::close(_fd);
        }
        _fd = fd;
    }

private:
    int _fd = -1;
};

class MmapRegion {
public:
    MmapRegion() = default;
    MmapRegion(void *addr, const std::size_t size) : _addr(addr), _size(size) {}
    ~MmapRegion() { reset(); }

    MmapRegion(const MmapRegion &) = delete;
    MmapRegion &operator=(const MmapRegion &) = delete;

    MmapRegion(MmapRegion &&other) noexcept
        : _addr(std::exchange(other._addr, nullptr)), _size(std::exchange(other._size, 0)) {}
    MmapRegion &operator=(MmapRegion &&other) noexcept {
        if (this != &other) {
            reset();
            _addr = std::exchange(other._addr, nullptr);
            _size = std::exchange(other._size, 0);
        }
        return *this;
    }

    [[nodiscard]] void *addr() const noexcept { return _addr; }
    [[nodiscard]] std::size_t size() const noexcept { return _size; }
    [[nodiscard]] explicit operator bool() const noexcept { return _addr != nullptr; }

    void reset() noexcept {
        if (_addr != nullptr && _size != 0) {
            ::munmap(_addr, _size);
        }
        _addr = nullptr;
        _size = 0;
    }

private:
    void *_addr = nullptr;
    std::size_t _size = 0;
};

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001
#endif

int sysMemfdCreate(const char *name) noexcept {
#if defined(SYS_memfd_create)
    return static_cast<int>(::syscall(SYS_memfd_create, name, MFD_CLOEXEC));
#else
    (void)name;
    errno = ENOSYS;
    return -1;
#endif
}

int openTmpUnlinked() noexcept {
    char tmpl[] = "/tmp/sucre-snort-telemetry.XXXXXX";
    const int fd = ::mkstemp(tmpl);
    if (fd < 0) {
        return -1;
    }
    (void)::unlink(tmpl);
    const int flags = ::fcntl(fd, F_GETFD, 0);
    if (flags >= 0) {
        (void)::fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    }
    return fd;
}

} // namespace

struct FlowTelemetry::Session {
    std::uint64_t sessionId = 0;
    Level level = Level::Off;
    Config cfg{};

    UniqueFd memfd;
    MmapRegion region;
    FlowTelemetryRing ring;
};

static std::uint32_t computeSlotCountOrZero(const std::uint64_t ringDataBytes,
                                            const std::uint32_t slotBytes) noexcept {
    if (slotBytes == 0) {
        return 0;
    }
    if (ringDataBytes == 0) {
        return 0;
    }
    if (ringDataBytes % slotBytes != 0) {
        return 0;
    }
    const std::uint64_t count = ringDataBytes / slotBytes;
    if (count == 0 || count > 0xFFFFFFFFull) {
        return 0;
    }
    return static_cast<std::uint32_t>(count);
}

FlowTelemetry::FlowTelemetry() = default;
FlowTelemetry::~FlowTelemetry() { resetAll(); }

std::uint64_t FlowTelemetry::allocateSessionId() noexcept {
    static std::atomic<std::uint64_t> next{1};
    return next.fetch_add(1, std::memory_order_relaxed);
}

bool FlowTelemetry::open(void *ownerKey, const bool canPassFd, const Level level,
                         const std::optional<Config> &overrideCfg, OpenResult &out,
                         std::string &outError) {
    out = OpenResult{};
    outError.clear();

    if (level == Level::Off) {
        close(ownerKey);
        out.actualLevel = Level::Off;
        return true;
    }

    if (!canPassFd) {
        outError = "TELEMETRY.OPEN(level=flow) requires vNext Unix domain socket fd passing";
        return false;
    }

    const Config cfg = overrideCfg.value_or(Config{});
    const std::uint32_t slotCount = computeSlotCountOrZero(cfg.ringDataBytes, cfg.slotBytes);
    if (slotCount == 0) {
        outError = "invalid slotBytes/ringDataBytes: ringDataBytes must be a multiple of slotBytes";
        return false;
    }

    int fd = sysMemfdCreate("sucre-snort-telemetry");
    if (fd < 0) {
        // Host sandboxes may deny memfd_create; fall back to an unlinked tmp file.
        fd = openTmpUnlinked();
        if (fd < 0) {
            outError = std::string("shared memory fd create failed: ") + std::strerror(errno);
            return false;
        }
    }

    UniqueFd memfd(fd);
    if (::ftruncate(memfd.get(), static_cast<off_t>(cfg.ringDataBytes)) != 0) {
        outError = std::string("ftruncate failed: ") + std::strerror(errno);
        return false;
    }

    void *addr = ::mmap(nullptr, static_cast<size_t>(cfg.ringDataBytes),
                        PROT_READ | PROT_WRITE, MAP_SHARED, memfd.get(), 0);
    if (addr == MAP_FAILED) {
        outError = std::string("mmap failed: ") + std::strerror(errno);
        return false;
    }

    MmapRegion region(addr, static_cast<size_t>(cfg.ringDataBytes));

    auto s = std::make_unique<Session>();
    s->sessionId = allocateSessionId();
    s->level = level;
    s->cfg = cfg;
    s->memfd = std::move(memfd);
    s->region = std::move(region);

    {
        FlowTelemetryRing::Config ringCfg{};
        ringCfg.slotBytes = cfg.slotBytes;
        ringCfg.slotCount = slotCount;
        std::span<std::byte> storage(reinterpret_cast<std::byte *>(s->region.addr()),
                                     s->region.size());
        if (!s->ring.init(storage, ringCfg)) {
            outError = "telemetry ring init failed";
            return false;
        }
    }

    // Preempt old session (safe because caller must take mutexListeners unique lock).
    _sessionOwner = std::move(s);
    _session.store(_sessionOwner.get(), std::memory_order_release);
    _ownerKey = ownerKey;

    Session *cur = _sessionOwner.get();
    out.actualLevel = level;
    out.sessionId = cur->sessionId;
    out.abiVersion = 1;
    out.slotBytes = cfg.slotBytes;
    out.slotCount = slotCount;
    out.ringDataBytes = cfg.ringDataBytes;
    out.maxPayloadBytes = cur->ring.maxPayloadBytes();
    out.writeTicketSnapshot = cur->ring.writeTicketSnapshot();
    out.sharedMemoryFd = cur->memfd.get();

    return true;
}

void FlowTelemetry::close(void *ownerKey) noexcept {
    if (_ownerKey != ownerKey) {
        return;
    }
    _session.store(nullptr, std::memory_order_release);
    _sessionOwner.reset();
    _ownerKey = nullptr;
}

void FlowTelemetry::resetAll() noexcept {
    _session.store(nullptr, std::memory_order_release);
    _sessionOwner.reset();
    _ownerKey = nullptr;

    _recordsWritten.store(0, std::memory_order_relaxed);
    _recordsDropped.store(0, std::memory_order_relaxed);
    _lastDropReason.store(FlowTelemetryRing::DropReason::None, std::memory_order_relaxed);
    _lastError.clear();
}

FlowTelemetry::HealthSnapshot FlowTelemetry::healthSnapshot() const {
    HealthSnapshot out{};
    out.recordsWritten = _recordsWritten.load(std::memory_order_relaxed);
    out.recordsDropped = _recordsDropped.load(std::memory_order_relaxed);
    out.lastDropReason = _lastDropReason.load(std::memory_order_relaxed);
    if (!_lastError.empty()) {
        out.lastError = _lastError;
    }

    Session *s = _session.load(std::memory_order_acquire);
    if (!s) {
        out.enabled = false;
        out.consumerPresent = false;
        out.sessionId = 0;
        out.slotBytes = 0;
        out.slotCount = 0;
        return out;
    }

    out.enabled = (s->level == Level::Flow);
    out.consumerPresent = true;
    out.sessionId = s->sessionId;
    out.slotBytes = s->cfg.slotBytes;
    out.slotCount = s->ring.config().slotCount;
    return out;
}

bool FlowTelemetry::hasActiveFlowConsumer() const noexcept {
    Session *s = _session.load(std::memory_order_acquire);
    return s != nullptr && s->level == Level::Flow;
}

FlowTelemetry::HotPath FlowTelemetry::hotPathFlow() const noexcept {
    Session *s = _session.load(std::memory_order_acquire);
    if (!s || s->level != Level::Flow) {
        return HotPath{};
    }
    return HotPath{.session = s, .cfg = &s->cfg};
}

void FlowTelemetry::accountDrop(const FlowTelemetryRing::DropReason reason) noexcept {
    _recordsDropped.fetch_add(1, std::memory_order_relaxed);
    _lastDropReason.store(reason, std::memory_order_relaxed);
}

void FlowTelemetry::setLastError(std::string message) noexcept {
    _lastError = std::move(message);
}

bool FlowTelemetry::exportRecord(const FlowTelemetryAbi::RecordType type,
                                 const std::span<const std::byte> payload) noexcept {
    return exportRecordHot(hotPathFlow(), type, payload);
}

bool FlowTelemetry::exportRecordHot(const HotPath &hot, const FlowTelemetryAbi::RecordType type,
                                    const std::span<const std::byte> payload) noexcept {
    Session *s = hot.session;
    if (!s || s->level != Level::Flow) {
        accountDrop(FlowTelemetryRing::DropReason::ConsumerAbsent);
        return false;
    }

    const auto res = s->ring.tryWrite(type, payload);
    if (!res.wrote) {
        accountDrop(res.dropReason);
        return false;
    }
    _recordsWritten.fetch_add(1, std::memory_order_relaxed);
    return true;
}

void FlowTelemetry::accountResourcePressureDrop() noexcept {
    accountDrop(FlowTelemetryRing::DropReason::ResourcePressure);
}

bool FlowTelemetry::exportSyntheticTestRecord() noexcept {
    const std::array<std::byte, 8> payload{
        std::byte{'S'}, std::byte{'N'}, std::byte{'O'}, std::byte{'R'},
        std::byte{'T'}, std::byte{'T'}, std::byte{'E'}, std::byte{'S'},
    };
    return exportRecord(FlowTelemetryAbi::RecordType::Flow, payload);
}
