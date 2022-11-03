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
