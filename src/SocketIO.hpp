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

class SocketIO {
public:
    using Ptr = std::shared_ptr<SocketIO>;

private:
    int _socket;
    bool _open = true;
    std::mutex _mutex;

public:
    SocketIO(const int socket);

    ~SocketIO();

    SocketIO(const SocketIO &) = delete;

    bool print(std::stringstream &out, const bool pretty);

private:
    static void format(std::stringstream &in, std::stringstream &out);
};
