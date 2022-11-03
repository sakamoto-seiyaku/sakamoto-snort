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

#include <sstream>

#include <iode-snort.hpp>
#include <SocketIO.hpp>

SocketIO::SocketIO(const int socket)
    : _socket(socket) {}

SocketIO::~SocketIO() {}

bool SocketIO::print(std::stringstream &out, const bool pretty) {
    auto writeSocket = [&](auto &in) {
        const std::string out(in.str());
        if (const uint32_t len = out.size() + 1; len != 1) {
            const std::lock_guard lock(_mutex);
            _open = (write(_socket, out.c_str(), len) == len);
        }
    };
    if (_open) {
        if (pretty) {
            std::stringstream fmt;
            format(out, fmt);
            writeSocket(fmt);
        } else {
            writeSocket(out);
        }
    }
    return _open;
}

void SocketIO::format(std::stringstream &in, std::stringstream &out) {
    std::istream_iterator<char> it(in);
    const std::istream_iterator<char> end;
    std::string indent;
    char c0 = '\0';
    while (it != end) {
        const char c = *it;
        const char c2 = (++it == end ? '\0' : *it);
        switch (c) {
        case ':':
            out << c;
            if (c0 == '\"') {
                out << ' ';
            }
            break;
        case ',':
            out << c;
            if (c2 == '\"') {
                out << "\r\n" << indent;
            }
            break;
        case '{':
            out << c << "\r\n" << (indent += '\t');
            break;
        case '}':
            out << "\r\n" << (indent.pop_back(), indent) << c;
            break;
        default:
            out << c;
        }
        c0 = c;
    }
}
