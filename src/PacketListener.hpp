/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
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
