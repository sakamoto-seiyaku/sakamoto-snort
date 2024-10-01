/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <sys/stat.h>

#include <Settings.hpp>

Settings::Settings() { reset(); }

Settings::~Settings() {}

void Settings::start() {
    mkdir(_saveDir.c_str(), 0700);
    mkdir(saveDirPackages.c_str(), 0700);
    mkdir(saveDirSystem.c_str(), 0700);
    mkdir(saveDirSystem.c_str(), 0700);
    mkdir(saveDirDomainLists.c_str(), 0700);
    restore();
}

void Settings::finishFirstStart() { android::base::SetProperty(_firstStartProp, "0"); }

void Settings::save() {
    _saver.save([&] {
        const std::shared_lock_guard lock(_mutexPassword);
        _saver.write<bool>(_blockEnabled);
        _saver.write<uint32_t>(_version);
        _saver.write<uint8_t>(_blockMask);
        _saver.write<uint8_t>(_blockIface);
        _saver.write<uint8_t>(_passState);
        _saver.write(_password);
        _saver.write<bool>(_getBlackIPs);
        _saver.write<bool>(_blockIPLeaks);
        _saver.write<std::time_t>(_maxAgeIP);
    });
}

void Settings::restore() {
    _saver.restore([&] {
        _blockEnabled = _saver.read<bool>();
        _savedVersion = _saver.read<uint32_t>();
        if (_savedVersion == 1) {
            _saver.read<bool>();
        }
        _blockMask = _saver.read<uint8_t>();
        if (_savedVersion < 3) {
            _blockMask += customListBit;
        }
        _blockIface = _saver.read<uint8_t>();
        _passState = _saver.read<uint8_t>();
        std::string password;
        _saver.read(password);
        _password = password;
        _getBlackIPs = _saver.read<bool>();
        _blockIPLeaks = _saver.read<bool>();
        _maxAgeIP = _saver.read<std::time_t>();
    });
}
