/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <BlockingList.hpp>
#include <Saver.hpp>
#include <Stats.hpp>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <iostream>
#include <sstream>
using namespace std;

BlockingList::BlockingList() {}

BlockingList::BlockingList(const string id, const string name, const string url,
                           const Stats::Color color, const uint8_t blockMask,
                           const time_t updatedAt, const bool outdated, const string etag,
                           const bool enabled, const uint32_t domainsCount)
    : _id(id)
    , _name(name)
    , _url(url)
    , _color(color)
    , _blockMask(blockMask)
    , _updatedAt(updatedAt)
    , _outdated(outdated)
    , _etag(etag)
    , _enabled(enabled)
    , _domainsCount(domainsCount) {}

void BlockingList::updateList(const string name, const Stats::Color color, const string url,
                              const uint8_t blockMask, const uint32_t domainsCount,
                              const time_t updatedAt, const string etag, const bool enabled,
                              const bool outdated) {
    _name = name;
    _url = url;
    _color = color;
    _blockMask = blockMask;
    _domainsCount = domainsCount;
    _updatedAt = updatedAt;
    _etag = etag;
    _enabled = enabled;
    _outdated = outdated;
}

void BlockingList::refreshList(const string lastUpdated, const string etag) {
    // Fix 8a: zero-initialize tm and validate parsing before mktime
    struct tm tm{};
    istringstream ss(lastUpdated);
    if (ss >> get_time(&tm, "%Y-%m-%d_%X")) {
        _updatedAt = mktime(&tm);
        _outdated = false;
        _etag = etag;
    }
}

void BlockingList::save(Saver &saver) const {
    saver.write(_id);
    saver.write(_name);
    saver.write(_url);
    saver.write<Stats::Color>(_color);
    saver.write<uint8_t>(_blockMask);
    saver.write(_updatedAt);
    saver.write<bool>(_outdated);
    saver.write(_etag);
    saver.write<bool>(_enabled);
    saver.write<uint32_t>(_domainsCount);
}

void BlockingList::restore(Saver &saver) {
    saver.readGuid(_id);
    saver.readBlockingListName(_name);
    saver.readBlockingListUrl(_url);
    _color = saver.read<Stats::Color>();
    _blockMask = saver.read<uint8_t>();
    _updatedAt = saver.read<time_t>();
    _outdated = saver.read<bool>();
    saver.read(_etag);
    _enabled = saver.read<bool>();
    _domainsCount = saver.read<uint32_t>();
}

string BlockingList::getId() const { return _id; }

string BlockingList::getName() const { return _name; }

string BlockingList::getUrl() const { return _url; }

Stats::Color BlockingList::getColor() const { return _color; }

uint8_t BlockingList::getBlockMask() const { return _blockMask; }

time_t BlockingList::getUpdatedAt() const { return _updatedAt; }

bool BlockingList::isOutdated() const { return _outdated; }

void BlockingList::setIsOutDated() { _outdated = true; }

string BlockingList::getEtag() const { return _etag; }

bool BlockingList::isEnabled() const { return _enabled; }

void BlockingList::enable() { _enabled = true; }

void BlockingList::disable() { _enabled = false; }

uint32_t BlockingList::getDomainsCount() const { return _domainsCount; }

string BlockingList::serialize() const {
    // Fix #11: thread-safe time formatting + correct buffer size (19 + NUL)
    // - Use gmtime_r (POSIX) instead of gmtime (non-thread-safe)
    // - Use fixed format "%Y-%m-%d_%H:%M:%S" (19 chars) and a 20-byte buffer
    // - Respect strftime return value to avoid using uninitialized memory
    time_t date = _updatedAt;
    struct tm tmval{};
    char dateBuffer[20]; // 19 chars + '\0'
    const char *fallback = "1970-01-01_00:00:00"; // safe default
    if (gmtime_r(&date, &tmval) != nullptr) {
        size_t n = strftime(dateBuffer, sizeof(dateBuffer), "%Y-%m-%d_%H:%M:%S", &tmval);
        if (n == 0) {
            // Buffer too small or formatting error; fall back to a fixed string
            std::memcpy(dateBuffer, fallback, sizeof(dateBuffer));
        }
    } else {
        std::memcpy(dateBuffer, fallback, sizeof(dateBuffer));
    }
    string dateStr(dateBuffer);
    string blString = "{\"id\":\"";
    blString += _id;
    blString += "\",\"name\":\"";
    blString += _name;
    blString += "\",\"url\":\"";
    blString += _url;
    blString += "\",\"type\":\"";
    blString += Stats::colorToString(_color);
    blString += "\",\"blockMask\":";
    blString += std::to_string(_blockMask);
    blString += ",\"updatedAt\":\"";
    blString += dateStr;
    blString += "\",\"outdated\":";
    blString += _outdated ? "1" : "0";
    blString += ",\"etag\":\"";
    blString += _etag;
    blString += "\",\"enabled\":";
    blString += _enabled ? "1" : "0";
    blString += ",\"domainsCount\":";
    blString += std::to_string(_domainsCount);
    blString += "}";
    return blString;
}
