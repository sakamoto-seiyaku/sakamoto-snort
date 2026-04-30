/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <net/if.h>

#include <PacketManager.hpp>

#include <fstream>
#include <string>
#include <time.h>

PacketManager::PacketManager() {}

PacketManager::~PacketManager() {}

void PacketManager::reset() {
    Streamable<Packet<IPv4>>::reset();
    Streamable<Packet<IPv6>>::reset();
    _reasonMetrics.reset();
    _ipRules.resetAll();
    _conntrack.reset();
}

void PacketManager::resetCheckpointRuntimeEpoch() {
    Streamable<Packet<IPv4>>::reset();
    Streamable<Packet<IPv6>>::reset();
    _reasonMetrics.reset();
    _conntrack.reset();
}

void PacketManager::startStream(const SocketIO::Ptr sockio, const bool pretty,
                                const uint32_t horizon, const std::uint32_t minSize) {
    Streamable<Packet<IPv4>>::startStream(sockio, pretty, horizon, minSize);
    Streamable<Packet<IPv6>>::startStream(sockio, pretty, horizon, minSize);
}

void PacketManager::stopStream(const SocketIO::Ptr sockio) {
    Streamable<Packet<IPv4>>::stopStream(sockio);
    Streamable<Packet<IPv6>>::stopStream(sockio);
}

// Build a fresh interface classification vector and publish it atomically.
void PacketManager::refreshIfaces() {
    const std::string sysdir = "/sys/class/net/";
    auto ifaces = if_nameindex();
    if (ifaces == nullptr) {
        // Enumeration failed; keep the previous snapshot intact.
        _ifaceLastRefreshNs.store(monotonicNs(), std::memory_order_relaxed);
        return;
    }

    // First pass: find max index to size the vector tightly.
    unsigned int maxIndex = 0;
    for (auto i = ifaces; i && i->if_index != 0 && i->if_name != nullptr; ++i) {
        if (i->if_index > maxIndex) maxIndex = i->if_index;
    }
    auto snap = std::make_shared<std::vector<uint8_t>>(static_cast<size_t>(maxIndex) + 1, NONE);

    // Second pass: classify interfaces.
    for (auto i = ifaces; i && i->if_index != 0 && i->if_name != nullptr; ++i) {
        const unsigned int idx = i->if_index;
        const std::string dir = sysdir + std::string(i->if_name);
        (*snap)[idx] = UNMANAGED; // default when present but not matched below
        uint32_t type = 0;
        if (std::ifstream in(dir + "/type"); in.is_open() && (in >> type)) {
            switch (type) {
            case 1: // ARPHRD_ETHER
                if (std::ifstream(dir + "/wireless").is_open()) {
                    (*snap)[idx] = WIFI;
                }
                break;
            case 512: // ARPHRD_PPP
            case 519: // ARPHRD_RAWIP (or similar cellular types)
                (*snap)[idx] = DATA;
                break;
            case 65534: // ARPHRD_NONE used by TUN/TAP/VPN
                (*snap)[idx] = VPN;
                break;
            default:
                // keep UNMANAGED
                break;
            }
        }
    }
    if_freenameindex(ifaces);

    // Publish the new snapshot with release semantics so readers with acquire
    // loads see a fully constructed vector.
    std::atomic_store_explicit(&_ifaceSnap, std::move(snap), std::memory_order_release);
    _ifaceLastRefreshNs.store(monotonicNs(), std::memory_order_relaxed);
}

long long PacketManager::monotonicNs() {
    timespec ts{0, 0};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<long long>(ts.tv_sec) * 1000LL * 1000LL * 1000LL + ts.tv_nsec;
}

uint8_t PacketManager::ifaceBit(const uint32_t iface) {
    // Hot path: read snapshot pointer atomically; no locks.
    auto snap = std::atomic_load_explicit(&_ifaceSnap, std::memory_order_acquire);
    if (snap && iface < snap->size()) {
        return (*snap)[iface];
    }

    // Unknown/absent: rate-limited best-effort refresh without blocking hot path.
    const auto now = monotonicNs();
    const auto last = _ifaceLastRefreshNs.load(std::memory_order_relaxed);
    if (now - last >= kIfaceRefreshCooldownNs) {
        if (_ifaceRefreshMutex.try_lock()) {
            // Double-check after acquiring the mutex to avoid redundant refreshes.
            const auto last2 = _ifaceLastRefreshNs.load(std::memory_order_relaxed);
            if (now - last2 >= kIfaceRefreshCooldownNs) {
                refreshIfaces();
            }
            _ifaceRefreshMutex.unlock();
        }
    }

    // Try again after a refresh attempt; still return 0 if unknown.
    snap = std::atomic_load_explicit(&_ifaceSnap, std::memory_order_acquire);
    if (snap && iface < snap->size()) {
        return (*snap)[iface];
    }
    return 0;
}

void PacketManager::refreshIfacesPassive() {
    const auto now = monotonicNs();
    const auto last = _ifaceLastRefreshNs.load(std::memory_order_relaxed);
    if (now - last < kIfacePassiveRefreshNs) return;
    if (_ifaceRefreshMutex.try_lock()) {
        const auto last2 = _ifaceLastRefreshNs.load(std::memory_order_relaxed);
        if (now - last2 >= kIfacePassiveRefreshNs) {
            refreshIfaces();
        }
        _ifaceRefreshMutex.unlock();
    }
}

void PacketManager::refreshIfacesOnce() {
    std::lock_guard<std::mutex> g(_ifaceRefreshMutex);
    refreshIfaces();
}

// Bundled translation unit: keep IpRulesEngine coupled to PacketManager for the
// current daemon source-list shape used by host and NDK builds.
#include "Conntrack.cpp"
#include "IpRulesEngine.cpp"
