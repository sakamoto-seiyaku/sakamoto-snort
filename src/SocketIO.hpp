/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
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
