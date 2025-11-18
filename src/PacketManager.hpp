/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <AppManager.hpp>
#include <HostManager.hpp>
#include <Packet.hpp>
#include <Streamable.hpp>

#include <atomic>
#include <memory>
#include <mutex>
#include <vector>

class PacketManager : public Streamable<Packet<IPv4>>, Streamable<Packet<IPv6>> {
private:
    enum IfaceBit : uint8_t { NONE = 0, WIFI = 1, DATA = 2, VPN = 4, UNMANAGED = 128 };

    // Hot-path data: snapshot of interface bits.
    // Accessed via atomic_load/store_explicit on the pointer value for portability.
    // Readers only load this pointer and perform bounds-check; no locks or writes on hot path.
    std::shared_ptr<std::vector<uint8_t>> _ifaceSnap;
    // Last refresh timestamp (monotonic ns). Relaxed is fine for best-effort rate limiting.
    std::atomic<long long> _ifaceLastRefreshNs{0};
    // Serialize refresh work; never taken on the hot path except via try_lock.
    std::mutex _ifaceRefreshMutex;
    // Cooldown to rate-limit refresh attempts from the hot path.
    static constexpr long long kIfaceRefreshCooldownNs = 200LL * 1000 * 1000; // 200 ms
    // Optional passive (very low frequency) refresh period.
    static constexpr long long kIfacePassiveRefreshNs = 30LL * 1000 * 1000 * 1000; // 30 s

public:
    PacketManager();

    ~PacketManager();

    PacketManager(const PacketManager &) = delete;

    template <class IP>
    bool make(const Address<IP> &&ip, const App::Uid uid, const bool input, const uint32_t iface,
              const timespec timestamp, const int proto, const uint16_t srcPort,
              const uint16_t dstPort, const uint16_t len);

    void reset();

    void startStream(const SocketIO::Ptr sockio, const bool pretty, const uint32_t horizon,
                     const std::uint32_t minSize);

    void stopStream(const SocketIO::Ptr sockio);

private:
    // Rebuild snapshot from current system state and publish atomically.
    void refreshIfaces();
    // Monotonic clock in nanoseconds.
    static long long monotonicNs();

    uint8_t ifaceBit(const uint32_t iface);

public:
    // Public helpers (not used on hot path) to prime/maintain snapshot.
    // Safe to call from non-critical threads.
    void refreshIfacesPassive();  // low-frequency best-effort refresh
    void refreshIfacesOnce();     // unconditional refresh
};

template <class IP>
bool PacketManager::make(const Address<IP> &&ip, const App::Uid uid, const bool input,
                         const uint32_t iface, const timespec timestamp, const int proto,
                         const uint16_t srcPort, const uint16_t dstPort, const uint16_t len) {
    const auto app = appManager.make(uid);
    const auto host = hostManager.make<IP>(ip);
    auto domain = host->domain();
    const auto validIP = domain != nullptr && domain->validIP();
    if (!validIP) {
        domain = nullptr;
    }
    const auto [blocked, cs] = app->blocked(domain);
    const bool verdict = !(settings.blockIPLeaks() && blocked && validIP) &&
                         (app->blockIface() & ifaceBit(iface)) == 0;

    if (app->tracked()) {
        appManager.updateStats(domain, app, !verdict, cs, input ? Stats::RXP : Stats::TXP, 1);
        appManager.updateStats(domain, app, !verdict, cs, input ? Stats::RXB : Stats::TXB, len);
    }
    Streamable<Packet<IP>>::stream(std::make_shared<Packet<IP>>(
        std::move(ip), host, app, input, iface, timestamp, proto, srcPort, dstPort, len, verdict));

    return verdict;
}

extern PacketManager pktManager;
