/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <App.hpp>
#include <Host.hpp>

template <class IP> class Packet {
public:
    using Ptr = std::shared_ptr<Packet>;

private:
    const Address<IP> _ip;
    const Host::Ptr _host;
    const App::Ptr _app;
    const uint32_t _iface;
    const timespec _timestamp;
    const uint16_t _proto;
    const uint16_t _srcPort;
    const uint16_t _dstPort;
    const uint16_t _len; // NFQUEUE/GSO can exceed 14-bit payload lengths; keep full 16-bit value.
    const bool _input;
    const bool _accepted;

public:
    Packet(const Address<IP> &ip, const Host::Ptr &host, const App::Ptr &app, const bool input,
           const uint32_t iface, const timespec timestamp, const int proto, const uint16_t srcPort,
           const uint16_t dstPort, const uint16_t len, const bool accepted);

    ~Packet();

    Packet(const Packet &) = delete;

    bool inHorizon(const uint32_t horizon, const timespec timeRef) const {
        return timeRef.tv_sec - _timestamp.tv_sec < static_cast<std::time_t>(horizon);
    }

    bool expired(const Packet::Ptr req) const {
        return req->_timestamp.tv_sec - _timestamp.tv_sec >
               static_cast<std::time_t>(settings.pktStreamMaxHorizon);
    }

    void save(Saver &saver);

    static Packet::Ptr restore(Saver &saver);

    void print(std::ostream &out) const;
};
