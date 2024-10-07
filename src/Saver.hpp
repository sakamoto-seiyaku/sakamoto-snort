/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
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

    inline void readBlockingListName(std::string &str);

    inline void readGuid(std::string &str);

    inline void readBlockingListUrl(std::string &str);

    inline void readBlockingListType(std::string &str);

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

void Saver::read(std::string &str, const uint32_t min = 1, const uint32_t max = 1000) {
    uint32_t len = read<uint32_t>();
    if (len < min || len > max) {
        throw RestoreException();
    }
    str.resize(len - 1);
    read(str.data(), len);
    if (str.data()[len - 1] != 0) {
        str.clear();
        throw RestoreException();
    }
}

void Saver::readDomName(std::string &str) { read(str, 3, HOST_NAME_MAX); }

void Saver::readGuid(std::string &str) { read(str, 37, 37); }

void Saver::readBlockingListName(std::string &str) { read(str, 1, 50); }

void Saver::readBlockingListUrl(std::string &str) { read(str, 1, 256); }

void Saver::readBlockingListType(std::string &str) { read(str, 6, 6); }

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
