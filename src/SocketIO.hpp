/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <atomic>
#include <ctime>

class SocketIO {
public:
    using Ptr = std::shared_ptr<SocketIO>;

private:
    int _socket;
    bool _open = true;
    std::mutex _mutex;
    std::atomic<std::time_t> _lastWrite{0};

public:
    SocketIO(const int socket);

    ~SocketIO();

    SocketIO(const SocketIO &) = delete;

    bool print(std::stringstream &out, const bool pretty);

    std::time_t lastWrite() const {
        return _lastWrite.load(std::memory_order_relaxed);
    }

    int fd() const { return _socket; }

private:
    static void format(std::stringstream &in, std::stringstream &out);
};
