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
