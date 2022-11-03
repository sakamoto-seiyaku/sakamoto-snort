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

#include <iomanip>

#include <AppManager.hpp>
#include <DnsRequest.hpp>

DnsRequest::DnsRequest(const App::Ptr app, const Domain::Ptr domain, const Stats::Color color,
                       const bool blocked, const timespec timestamp)
    : _app(app)
    , _domain(domain)
    , _color(color)
    , _blocked(blocked)
    , _timestamp(timestamp) {}

DnsRequest::DnsRequest(const App::Ptr app, const Domain::Ptr domain, const Stats::Color color,
                       const bool blocked)
    : _app(app)
    , _domain(domain)
    , _color(color)
    , _blocked(blocked) {
    timespec_get(&_timestamp, TIME_UTC);
}

DnsRequest::~DnsRequest() {}

void DnsRequest::print(std::ostream &out) const {
    out << "{" << JSF("app") << JSS(_app->name()) << "," << JSF("domain") << JSS(_domain->name())
        << "," << JSF("color") << JSS(Stats::colorNames[_color]) << "," << JSF("blocked")
        << JSB(_blocked) << "," << JSF("timestamp")
        << JSS(_timestamp.tv_sec << "." << std::setfill('0') << std::setw(9) << _timestamp.tv_nsec)
        << "}";
}

bool DnsRequest::inHorizon(const uint32_t horizon, const timespec timeRef) const {
    return timeRef.tv_sec - _timestamp.tv_sec < horizon;
}

bool DnsRequest::expired(const DnsRequest::Ptr req) const {
    return req->_timestamp.tv_sec - _timestamp.tv_sec > settings.dnsStreamMaxHorizon;
}

void DnsRequest::save(Saver &saver) {
    saver.write(_app->name());
    saver.write(_domain->name());
    saver.write<Stats::Color>(_color);
    saver.write<bool>(_blocked);
    saver.write<timespec>(_timestamp);
}

DnsRequest::Ptr DnsRequest::restore(Saver &saver) {
    std::string name;
    saver.read(name);
    auto &app = appManager.find(name);
    std::string name2;
    saver.read(name2);
    auto &domain = domManager.find(name2);
    auto cs = saver.read<Stats::Color>();
    auto blocked = saver.read<bool>();
    auto timestamp = saver.read<timespec>();
    if (app != nullptr && domain != nullptr) {
        return std::make_shared<DnsRequest>(app, domain, cs, blocked, timestamp);
    } else {
        return nullptr;
    }
}
