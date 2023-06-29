/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
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
    in.clear();
    in.seekg(0);
}
