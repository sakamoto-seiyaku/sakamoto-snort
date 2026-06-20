/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <Saver.hpp>
#include <SnortLog.hpp>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <exception>

namespace {

void closeAndClear(std::ofstream &out) noexcept {
    try {
        if (out.is_open()) {
            out.close();
        }
    } catch (...) {
    }
    out.clear();
}

} // namespace

Saver::Saver(const std::string &&filename)
    : _filename(filename)
    , _filetmp(_filename + ".tmp") {
    in.exceptions(std::ifstream::failbit | std::ifstream::badbit | std::ifstream::eofbit);
    out.exceptions(std::ofstream::failbit | std::ofstream::badbit);
}

Saver::Saver(const std::string &filename)
    : Saver(std::move(filename)) {}

Saver::~Saver() {}

void Saver::save(ioFun &&saveFun) {
    try {
        out.clear();
        out.open(_filetmp.c_str(), std::ios::binary);
        saveFun();
        out.close();
        if (std::rename(_filetmp.c_str(), _filename.c_str()) != 0) {
            const int err = errno;
            LOG(ERROR) << "Saver save rename failed for " << _filename << ": "
                       << std::strerror(err);
            std::remove(_filetmp.c_str());
        }
    } catch (const std::ofstream::failure &e) {
        LOG(ERROR) << "Saver save failed for " << _filename << ": " << e.what();
        closeAndClear(out);
        std::remove(_filetmp.c_str());
    } catch (const std::exception &e) {
        LOG(ERROR) << "Saver save exception for " << _filename << ": " << e.what();
        closeAndClear(out);
        std::remove(_filetmp.c_str());
    } catch (...) {
        LOG(ERROR) << "Saver save exception for " << _filename << ": unknown";
        closeAndClear(out);
        std::remove(_filetmp.c_str());
    }
}

void Saver::restore(ioFun &&restoreFun) {
    try {
        in.open(_filename, std::ios::binary);
        restoreFun();
    } catch (const std::ifstream::failure &_) {
    } catch (const RestoreException &_) {
    }
}

void Saver::remove() { std::remove(_filename.c_str()); }
