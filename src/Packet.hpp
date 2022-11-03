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
    const uint16_t _len : 14; // MTU max : 32768
    const bool _input : 1;
    const bool _accepted : 1;

public:
    Packet(const Address<IP> &&ip, const Host::Ptr &host, const App::Ptr &app, const bool input,
           const uint32_t iface, const timespec timestamp, const int proto, const uint16_t srcPort,
           const uint16_t dstPort, const uint16_t len, const bool accepted);

    ~Packet();

    Packet(const Packet &) = delete;

    bool inHorizon(const uint32_t horizon, const timespec timeRef) const {
        return timeRef.tv_sec - _timestamp.tv_sec < horizon;
    }

    bool expired(const Packet::Ptr req) const {
        return req->_timestamp.tv_sec - _timestamp.tv_sec > settings.pktStreamMaxHorizon;
    }

    void save(Saver &saver);

    static Packet::Ptr restore(Saver &saver);

    void print(std::ostream &out) const;
};
