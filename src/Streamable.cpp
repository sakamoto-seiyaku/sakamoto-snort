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

#include <sstream>
#include <vector>

#include <Activity.hpp>
#include <DnsRequest.hpp>
#include <Packet.hpp>
#include <Streamable.hpp>

template <class Item>
Streamable<Item>::Streamable()
    : _saver("") {}

template <class Item>
Streamable<Item>::Streamable(const std::string &filename)
    : _saver(filename) {}

template <class Item> Streamable<Item>::~Streamable() {}

template <class Item> void Streamable<Item>::reset() { _items.clear(); }

template <class Item> void Streamable<Item>::stream(const std::shared_ptr<Item> item) {
    const std::lock_guard lockItems(_mutexItems);
    _items.push_back(item);
    while (_items.front()->expired(item)) {
        _items.pop_front();
    }

    const std::lock_guard lockSockios(_mutexSockios);
    if (!_sockios.empty()) {
        std::vector<SocketIO::Ptr> closed;
        std::stringstream out;
        _items.back()->print(out);
        for (const auto &[sockio, pretty] : _sockios) {
            if (!sockio->print(out, pretty)) {
                closed.push_back(sockio);
            }
        }
        for (const auto &sockio : closed) {
            _sockios.erase(sockio);
        }
    }
}

template <class Item>
void Streamable<Item>::startStream(const SocketIO::Ptr sockio, const bool pretty,
                                   const std::time_t horizon, const std::uint32_t minSize) {
    const std::lock_guard lockItems(_mutexItems);
    timespec now;
    timespec_get(&now, TIME_UTC);
    uint32_t nb = 0;
    for (const auto &item : _items) {
        if (_items.size() - ++nb < minSize || item->inHorizon(horizon, now)) {
            std::stringstream out;
            item->print(out);
            sockio->print(out, pretty);
        }
    }
    const std::lock_guard lockSockios(_mutexSockios);
    _sockios.emplace(sockio, pretty);
}

template <class Item> void Streamable<Item>::stopStream(const SocketIO::Ptr sockio) {
    const std::lock_guard lock(_mutexSockios);
    _sockios.erase(sockio);
}

template <class Item> void Streamable<Item>::save() {
    _saver.save([&] {
        const std::lock_guard lockItems(_mutexItems);
        _saver.write<uint32_t>(_items.size());
        for (const auto &item : _items) {
            item->save(_saver);
        }
    });
}

template <class Item> void Streamable<Item>::restore() {
    _saver.restore([&] {
        const uint32_t nb = _saver.read<uint32_t>();
        for (uint32_t i = 0; i < nb; ++i) {
            if (const auto item = Item::restore(_saver); item != nullptr) {
                stream(item);
            }
        }
    });
}

template class Streamable<Activity>;
template class Streamable<DnsRequest>;
template class Streamable<Packet<IPv4>>;
template class Streamable<Packet<IPv6>>;
