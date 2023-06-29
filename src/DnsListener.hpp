/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
 
#pragma once

#include <DnsRequest.hpp>
#include <AppManager.hpp>
#include <Streamable.hpp>

class DnsListener : public Streamable<DnsRequest> {
public:
    DnsListener();

    ~DnsListener();

    DnsListener(const DnsListener &) = delete;

    void start();

    void save();

    void restore();

private:
    void server();

    void clientRun(const int socket);

    template <class IP> static void readIP(const int socket, const Domain::Ptr &domain);

    static void clientRead(const int socket, void *data, const uint32_t len, const char *error);

    static void clientWrite(const int socket, const void *data, const uint32_t len,
                            const char *error);
};

extern DnsListener dnsListener;
