/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
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

    std::size_t hash() const __attribute__((no_sanitize("unsigned-integer-overflow"))) {
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
