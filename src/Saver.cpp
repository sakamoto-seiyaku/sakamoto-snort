/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <Saver.hpp>

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
    const std::string tmp(_filetmp);
    try {
        out.open(_filetmp.c_str(), std::ios::binary);
        saveFun();
        out.close();
        std::rename(_filetmp.c_str(), _filename.c_str());
    } catch (const std::ofstream::failure &_) {
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
