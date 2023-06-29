/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
 
#pragma once

#include <AppManager.hpp>
#include <HostManager.hpp>
#include <Packet.hpp>
#include <Streamable.hpp>

class PacketManager : public Streamable<Packet<IPv4>>, Streamable<Packet<IPv6>> {
private:
    enum IfaceBit : uint8_t { NONE = 0, WIFI = 1, DATA = 2, VPN = 4, UNMANAGED = 128 };

    std::vector<IfaceBit> _ifaceBits;

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
    void initIfaces();

    uint8_t ifaceBit(const uint32_t iface);
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
