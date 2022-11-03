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
