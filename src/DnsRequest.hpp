/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <App.hpp>

class DnsRequest {
public:
    using Ptr = std::shared_ptr<DnsRequest>;

private:
    App::Ptr _app;
    Domain::Ptr _domain;
    Stats::Color _color;
    bool _blocked;
    timespec _timestamp;

public:
    DnsRequest(const App::Ptr app, const Domain::Ptr domain, const Stats::Color color,
               const bool blocked, const timespec timestamp);

    DnsRequest(const App::Ptr app, const Domain::Ptr domain, const Stats::Color color,
               const bool blocked);

    ~DnsRequest();

    DnsRequest(const DnsRequest &) = delete;

    void print(std::ostream &out) const;

    bool inHorizon(const uint32_t horizon, const timespec timeRef) const;

    bool expired(const DnsRequest::Ptr req) const;

    void save(Saver &saver);

    static DnsRequest::Ptr restore(Saver &saver);
};
