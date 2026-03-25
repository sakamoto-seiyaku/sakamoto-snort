#pragma once

#include <functional>
#include <exception>
#include <string>
#include <utility>

class RestoreException : public std::exception {};

class Saver {
private:
    using ioFun = std::function<void()>;

public:
    Saver(const std::string &&) {}
    Saver(const std::string &) {}
    ~Saver() = default;

    Saver(const Saver &) = delete;
    Saver &operator=(Saver &&) = default;

    void save(ioFun &&saveFun) {
        saveFun();
    }

    void restore(ioFun &&restoreFun) {
        restoreFun();
    }

    void remove() {}

    template <class T>
    T read() {
        return T{};
    }

    template <class T>
    void read(T &) {}

    void read(std::string &str, const uint32_t = 1, const uint32_t = 1000) {
        str.clear();
    }

    void readDomName(std::string &str) { read(str); }

    void readBlockingListName(std::string &str) { read(str); }

    void readGuid(std::string &str) { read(str); }

    void readBlockingListUrl(std::string &str) { read(str); }

    void readBlockingListType(std::string &str) { read(str); }

    template <class T>
    void read(void *, const T) {}

    template <class V, class T>
    void write(const T &&) {}

    template <class T>
    void write(const T &) {}

    template <class T>
    void write(const void *, const T) {}
};
