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

#include <Saver.hpp>

Saver::Saver(const std::string &&filename)
    : _filename(filename)
    , _filetmp(_filename + ".tmp") {
    in.exceptions(std::ifstream::failbit | std::ifstream::badbit | std::ifstream::eofbit);
    out.exceptions(std::ifstream::failbit | std::ifstream::badbit);
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
    } catch (std::ofstream::failure _) {
    }
}

void Saver::restore(ioFun &&restoreFun) {
    try {
        in.open(_filename, std::ios::binary);
        restoreFun();
    } catch (std::ifstream::failure _) {
    } catch (RestoreException _) {
    }
}

void Saver::remove() { std::remove(_filename.c_str()); }
