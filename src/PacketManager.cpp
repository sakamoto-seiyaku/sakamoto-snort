/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <net/if.h>

#include <PacketManager.hpp>

PacketManager::PacketManager() {}

PacketManager::~PacketManager() {}

void PacketManager::reset() {
    Streamable<Packet<IPv4>>::reset();
    Streamable<Packet<IPv6>>::reset();
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

void PacketManager::initIfaces() {
    const auto sysdir = std::string("/sys/class/net/");
    auto ifaces = if_nameindex();
    if (ifaces == nullptr) {
        // Failed to enumerate interfaces; leave _ifaceBits as-is
        return;
    }

    for (auto i = ifaces; i && i->if_index != 0 && i->if_name != nullptr; ++i) {
        const std::string dir(sysdir + i->if_name);
        uint32_t type;
        _ifaceBits.resize(std::max(_ifaceBits.size(), static_cast<size_t>(i->if_index + 1)), NONE);
        _ifaceBits[i->if_index] = UNMANAGED;
        if (std::ifstream in(dir + "/type"); in.is_open() && in >> type) {
            switch (type) {
            case 1:
                if (std::ifstream(dir + "/wireless").is_open()) {
                    _ifaceBits[i->if_index] = WIFI;
                }
                break;
            case 512:
            case 519:
                _ifaceBits[i->if_index] = DATA;
                break;
            case 65534:
                _ifaceBits[i->if_index] = VPN;
                break;
            }
        }
    }
    if_freenameindex(ifaces);
}

uint8_t PacketManager::ifaceBit(const uint32_t iface) {
    if (iface >= _ifaceBits.size() || _ifaceBits[iface] == NONE) {
        initIfaces();
    }
    return iface >= _ifaceBits.size() ? 0 : _ifaceBits[iface];
}
