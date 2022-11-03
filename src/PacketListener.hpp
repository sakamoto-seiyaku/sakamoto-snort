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

#include <libmnl/libmnl.h>

#include <PacketManager.hpp>

template <class IP> class PacketListener {
private:
    uint32_t _inputQueues;
    uint32_t _outputQueues;
    uint32_t _firstQueue;

    thread_local inline static bool _inputTLS;
    thread_local inline static uint32_t _queueTLS;
    thread_local inline static mnl_socket *_socketTLS;

public:
    PacketListener();

    ~PacketListener();

    PacketListener(const PacketListener &) = delete;

    void start();

private:
    void listen(const uint32_t threadId);

    static nlmsghdr *putHeader(char *buffer, const uint32_t type);

    static void sendToSocket(const nlmsghdr *nlh);

    static void sendVerdict(const uint32_t id, const uint32_t verdict);

    static int callback(const nlmsghdr *nlh, void *data);
};
