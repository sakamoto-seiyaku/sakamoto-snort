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

#include <array>
#include <sys/socket.h>

#include <Saver.hpp>

template <class IP> class Address {
private:
    using Value = std::array<uint8_t, sizeof(typename IP::Addr)>;
    using ReaderFun = std::function<void(uint8_t *, const uint32_t len)>;

    Value _value;

public:
    Address() {}

    Address(const uint8_t *address);

    Address(const ReaderFun &&reader);

    Address(Saver &saver);

    ~Address();

    bool operator==(const Address<IP> &addr) const noexcept { return _value == addr._value; }

    std::size_t hash() const {
        std::size_t result = 5381;
        for (const auto x : _value) {
            result = ((result << 5) + result) ^ x;
        }
        return result;
    }

    void fillSockAddr(sockaddr_storage &sa) const { IP::fillSockAddr(sa, _value.data()); }

    const std::string str() const;

    void save(Saver &saver) const;

    void print(std::ostream &out) const;
};

template <class IP> struct std::hash<Address<IP>> {
    auto operator()(const Address<IP> &addr) const noexcept { return addr.hash(); }
};
