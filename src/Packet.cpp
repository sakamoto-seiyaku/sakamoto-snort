/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <iomanip>
#include <net/if.h>
#include <type_traits>

#include <Packet.hpp>

template <class IP>
Packet<IP>::Packet(const Address<IP> &srcIp, const Address<IP> &dstIp, const Host::Ptr &host,
                   const App::Ptr &app, const bool input, const uint32_t iface,
                   const timespec timestamp, const int proto, const uint16_t srcPort,
                   const uint16_t dstPort, const uint16_t len, const bool accepted,
                   const PacketReasonId reasonId, const std::optional<uint32_t> ruleId,
                   const std::optional<uint32_t> wouldRuleId)
    : _srcIp(srcIp)
    , _dstIp(dstIp)
    , _host(host)
    , _app(app)
    , _iface(iface)
    , _timestamp(timestamp)
    , _proto(proto)
    , _srcPort(srcPort)
    , _dstPort(dstPort)
    , _len(len)
    , _input(input)
    , _accepted(accepted)
    , _reasonId(reasonId)
    , _ruleId(ruleId)
    , _wouldRuleId(wouldRuleId) {}

template <class IP> Packet<IP>::~Packet() {}

template <class IP> void Packet<IP>::save(Saver &saver) {}

template <class IP> typename Packet<IP>::Ptr Packet<IP>::restore(Saver &saver) { return nullptr; }

template <class IP> void Packet<IP>::print(std::ostream &out) const {
    char buffer[IF_NAMESIZE];
    out << "{" << JSF("app");
    if (const auto appName = _app->nameSnapshot()) {
        out << JSS(*appName);
    } else {
        out << JSS(_app->name());
    }
    out << "," << JSF("uid") << _app->uid() << ","
        << JSF("userId") << _app->userId() << "," << JSF("direction") << JSS((_input ? "in" : "out"))
        << "," << JSF("length") << _len << "," << JSF("interface")
        << JSS((if_indextoname(_iface, buffer) ? buffer : "n/a")) << "," << JSF("protocol")
        << JSS((_proto == IPPROTO_TCP      ? "tcp"
                : _proto == IPPROTO_UDP    ? "udp"
                : _proto == IPPROTO_ICMP   ? "icmp"
                : _proto == IPPROTO_ICMPV6 ? "icmp"
                                           : "n/a"))
        << "," << JSF("timestamp")
        << JSS(_timestamp.tv_sec << "." << std::setfill('0') << std::setw(9) << _timestamp.tv_nsec)
        << "," << JSF("ipVersion")
        << (std::is_same_v<IP, IPv4> ? 4 : 6)
        << "," << JSF("srcIp") << JSS(_srcIp.str()) << "," << JSF("dstIp") << JSS(_dstIp.str())
        << "," << JSF("host")
        << JSS((_host->hasName() ? _host->name().c_str() : "n/a")) << "," << JSF("srcPort")
        << _srcPort << "," << JSF("dstPort") << _dstPort << "," << JSF("accepted") << JSB(_accepted)
        << "," << JSF("reasonId") << JSS(packetReasonIdStr(_reasonId));
    if (_ruleId.has_value()) {
        out << "," << JSF("ruleId") << *_ruleId;
    }
    if (_wouldRuleId.has_value()) {
        out << "," << JSF("wouldRuleId") << *_wouldRuleId << "," << JSF("wouldDrop") << 1;
    }
    out << "}";
}

template class Packet<IPv4>;
template class Packet<IPv6>;
