/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <iomanip>
#include <net/if.h>

#include <Packet.hpp>

template <class IP>
Packet<IP>::Packet(const Address<IP> &&ip, const Host::Ptr &host, const App::Ptr &app,
                   const bool input, const uint32_t iface, const timespec timestamp,
                   const int proto, const uint16_t srcPort, const uint16_t dstPort,
                   const uint16_t len, const bool accepted)
    : _ip(std::move(ip))
    , _host(host)
    , _app(app)
    , _iface(iface)
    , _timestamp(timestamp)
    , _proto(proto)
    , _srcPort(srcPort)
    , _dstPort(dstPort)
    , _len(len)
    , _input(input)
    , _accepted(accepted) {}

template <class IP> Packet<IP>::~Packet() {}

template <class IP> void Packet<IP>::save(Saver &saver) {}

template <class IP> typename Packet<IP>::Ptr Packet<IP>::restore(Saver &saver) { return nullptr; }

template <class IP> void Packet<IP>::print(std::ostream &out) const {
    char buffer[IF_NAMESIZE];
    out << "{" << JSF("app") << JSS(_app->name()) << "," << JSF("direction")
        << JSS((_input ? "in" : "out")) << "," << JSF("length") << _len << "," << JSF("interface")
        << JSS((if_indextoname(_iface, buffer) ? buffer : "n/a")) << "," << JSF("protocol")
        << JSS((_proto == IPPROTO_TCP      ? "tcp"
                : _proto == IPPROTO_UDP    ? "udp"
                : _proto == IPPROTO_ICMP   ? "icmp"
                : _proto == IPPROTO_ICMPV6 ? "icmp"
                                           : "n/a"))
        << "," << JSF("timestamp")
        << JSS(_timestamp.tv_sec << "." << std::setfill('0') << std::setw(9) << _timestamp.tv_nsec)
        << "," << JSF(IP::name) << JSS(_ip.str()) << "," << JSF("host")
        << JSS((_host->hasName() ? _host->name().c_str() : "n/a")) << "," << JSF("srcPort")
        << _srcPort << "," << JSF("dstPort") << _dstPort << "," << JSF("accepted") << JSB(_accepted)
        << "}";
}

template class Packet<IPv4>;
template class Packet<IPv6>;
