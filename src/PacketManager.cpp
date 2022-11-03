/*
 * Copyright 2019 - 2022, iodé Technologies
 *
 * This file is part of the iode-snort project.
 *
 * iode-snort is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * iode-snort is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with iode-snort. If not, see <https://www.gnu.org/licenses/>.
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

    for (auto i = ifaces; i->if_index != 0 || i->if_name != nullptr; ++i) {
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
