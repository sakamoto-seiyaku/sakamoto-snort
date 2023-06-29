/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
 
#pragma once

#include <deque>

#include <Saver.hpp>
#include <SocketIO.hpp>

template <class Item> class Streamable {
private:
    Saver _saver;
    std::unordered_map<SocketIO::Ptr, const bool> _sockios;
    std::deque<const std::shared_ptr<Item>> _items;
    std::mutex _mutexItems;
    std::mutex _mutexSockios;

public:
    Streamable();

    Streamable(const std::string &filename);

    virtual ~Streamable();

    void reset();

    void stream(const std::shared_ptr<Item> item);

    void startStream(const SocketIO::Ptr sockio, const bool pretty, const std::time_t horizon,
                     const std::uint32_t minSize);

    void stopStream(const SocketIO::Ptr sockio);

    void save();

    void restore();
};
