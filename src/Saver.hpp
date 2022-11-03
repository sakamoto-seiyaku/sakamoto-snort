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

#include <fstream>
#include <functional>
#include <string>

class RestoreException : public std::exception {};

class Saver {
private:
    using ioFun = std::function<void()>;

    const std::string _filename;
    const std::string _filetmp;

    std::ifstream in;
    std::ofstream out;

public:
    Saver(const std::string &&filename);

    Saver(const std::string &filename);

    ~Saver();

    Saver(const Saver &) = delete;

    void save(ioFun &&saveFun);

    void restore(ioFun &&restoreFun);

    void remove();

    template <class T> T read();

    template <class T> void read(T &data);

    inline void read(std::string &str, const uint32_t min, const uint32_t max);

    inline void readDomName(std::string &str);

    template <class T> void read(void *data, const T len);

    template <class V, class T> void write(const T &&data);

    template <class T> void write(const T &data);

    template <> inline void write(const std::string &str);

    template <class T> void write(const void *data, const T len);
};

template <class T> T Saver::read() {
    T tmp_data;
    read(&tmp_data, sizeof(tmp_data));
    return tmp_data;
}

template <class T> void Saver::read(T &data) { read(data, sizeof(data)); }

void Saver::read(std::string &str, const uint32_t min = 1, const uint32_t max = UINT32_MAX / 2) {
    uint32_t len = read<uint32_t>();
    str.resize(len - 1);
    if (len < min || len > max) {
        throw RestoreException();
    }
    read(str.data(), len);
    if (str.c_str()[len - 1] != 0) {
        throw RestoreException();
    }
}

void Saver::readDomName(std::string &str) { read(str, 3, HOST_NAME_MAX); }

template <class T> void Saver::read(void *data, const T len) {
    in.read(reinterpret_cast<char *>(data), len);
}

template <class V, class T> void Saver::write(const T &&data) {
    V tmp_data = data;
    write(&tmp_data, sizeof(tmp_data));
}

template <class T> void Saver::write(const T &data) { write(&data, sizeof(data)); }

template <> inline void Saver::write(const std::string &str) {
    const uint32_t len = str.size() + 1;
    write<uint32_t>(len);
    write(str.c_str(), len);
}

template <class T> void Saver::write(const void *data, const T len) {
    out.write(reinterpret_cast<const char *>(data), len);
}
