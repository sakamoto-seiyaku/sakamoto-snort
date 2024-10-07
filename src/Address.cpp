/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <arpa/inet.h>

#include <IP.hpp>
#include <Address.hpp>

template <class IP> Address<IP>::Address(const uint8_t *address) {
    std::copy_n(address, _value.size(), _value.begin());
}

template <class IP> Address<IP>::Address(const ReaderFun &&reader) {
    reader(_value.data(), sizeof(typename IP::Addr));
}

template <class IP> Address<IP>::Address(Saver &saver) {
    saver.read(_value.data(), sizeof(typename IP::Addr));
}

template <class IP> Address<IP>::~Address() {}

template <class IP> const std::string Address<IP>::str() const {
    char buffer[IP::strLen];
    inet_ntop(IP::family, _value.data(), buffer, IP::strLen);
    return std::string(buffer);
}

template <class IP> void Address<IP>::save(Saver &saver) const {
    saver.write(_value.data(), sizeof(typename IP::Addr));
}

template <class IP> void Address<IP>::print(std::ostream &out) const { out << str(); }

template class Address<IPv4>;
template class Address<IPv6>;
