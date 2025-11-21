/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <sstream>
#include <iterator>
#include <errno.h>
#include <ctime>

#include <sucre-snort.hpp>
#include <SocketIO.hpp>

SocketIO::SocketIO(const int socket)
    : _socket(socket) {
    // Initialize lastWrite to "now" so that a freshly created connection that
    // never writes anything will still be considered idle after a single full
    // timeout window.
    _lastWrite.store(std::time(nullptr), std::memory_order_relaxed);
}

SocketIO::~SocketIO() {}

bool SocketIO::print(std::stringstream &out, const bool pretty) {
    // Robust write: handle partial writes and EINTR/EAGAIN; keep semantics of sending a
    // trailing NUL byte as before (size()+1).
    auto writeSocket = [&](auto &in) {
        const std::string outStr(in.str());
        const char *buf = outStr.c_str();
        ssize_t remaining = static_cast<ssize_t>(outStr.size() + 1); // include NUL terminator
        ssize_t written = 0;
        if (remaining == 1) {
            return; // nothing to write
        }
        const std::lock_guard lock(_mutex);
        while (remaining > 0) {
            ssize_t ret = ::write(_socket, buf + written, static_cast<size_t>(remaining));
            if (ret > 0) {
                written += ret;
                remaining -= ret;
            } else if (ret == -1 && (errno == EINTR)) {
                continue; // retry
            } else if (ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // For blocking sockets this shouldn't happen; treat as failure to avoid busy loop
                _open = false;
                break;
            } else {
                _open = false;
                break;
            }
        }
        if (remaining == 0) {
            _open = true;
            _lastWrite.store(std::time(nullptr), std::memory_order_relaxed);
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
    // JSON-ish pretty printer with string-awareness.
    // - Track string/escape state so braces/commas inside strings don't affect indentation
    // - Keep previous CRLF + tab-based indentation semantics
    std::istreambuf_iterator<char> it(in.rdbuf());
    const std::istreambuf_iterator<char> end;
    std::string indent;
    bool inString = false;
    bool escaped = false;

    while (it != end) {
        const char c = *it;

        if (inString) {
            out << c;
            if (escaped) {
                escaped = false; // escape only protects next char
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                inString = false;
            }
            ++it;
            continue;
        }

        // Not inside string: structural formatting
        switch (c) {
        case '"':
            inString = true;
            out << c;
            break;
        case ':':
            out << c << ' ';
            break;
        case ',': {
            out << c;
            // Preserve old behavior: newline+indent only if next is a string start
            const auto next = std::next(it);
            if (next != end && *next == '"') {
                out << "\r\n" << indent;
            }
            break;
        }
        case '{':
        case '[':
            out << c << "\r\n";
            indent.push_back('\t');
            out << indent;
            break;
        case '}':
        case ']':
            if (!indent.empty()) {
                indent.pop_back();
            }
            out << "\r\n" << indent << c;
            break;
        default:
            out << c;
            break;
        }
        ++it;
    }
    in.clear();
    in.seekg(0);
}
