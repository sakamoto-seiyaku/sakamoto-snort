/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

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

template <class Item> void Streamable<Item>::reset() {
    const std::lock_guard<std::shared_mutex> lock(_mutexItems);
    _items.clear();
}

template <class Item> void Streamable<Item>::stream(const std::shared_ptr<Item> item) {
    (void)item;
}

template <class Item>
void Streamable<Item>::startStream(const SocketIO::Ptr sockio, const bool pretty,
                                   const std::time_t horizon, const std::uint32_t minSize) {
    (void)sockio;
    (void)pretty;
    (void)horizon;
    (void)minSize;
}

template <class Item> void Streamable<Item>::stopStream(const SocketIO::Ptr sockio) {
    const std::lock_guard lock(_mutexSockios);
    _sockios.erase(sockio);
}

template <class Item> void Streamable<Item>::save() {
    _saver.save([&] {
        const std::shared_lock<std::shared_mutex> lockItems(_mutexItems);
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
