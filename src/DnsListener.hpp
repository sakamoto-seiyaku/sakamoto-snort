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
