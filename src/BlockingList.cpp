#include <BlockingList.hpp>
#include <Saver.hpp>
#include <Stats.hpp>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <sstream>
using namespace std;

BlockingList::BlockingList() {}

BlockingList::BlockingList(const string id, const string name, const string url,
                           const Stats::Color color, const time_t updatedAt, const bool outdated,
                           const string etag, const bool enabled)
    : _id(id)
    , _name(name)
    , _url(url)
    , _color(color)
    , _updatedAt(updatedAt)
    , _outdated(outdated)
    , _etag(etag)
    , _enabled(enabled) {}

void BlockingList::updateList(const string name, const Stats::Color color, const string url) {
    _name = name;
    _url = url;
    _color = color;
}

void BlockingList::refreshList(const string lastUpdated, const string etag) {
    struct std::tm tm;
    std::istringstream ss(lastUpdated);
    ss >> std::get_time(&tm, "%Y-%m-%d_%X"); // or just %T in this case
    _updatedAt = mktime(&tm);
    _outdated = false;
    _etag = etag;
}

void BlockingList::toggleList() { _enabled = !_enabled; }

void BlockingList::save(Saver &saver) const {
    saver.write(_id);
    saver.write(_name);
    saver.write(_url);
    saver.write(Stats::colorToString(_color));
    saver.write(_updatedAt);
    saver.write<bool>(_outdated);
    saver.write(_etag);
    saver.write<bool>(_enabled);
}

void BlockingList::restore(Saver &saver) {
    saver.readGuid(_id);
    saver.readBlockingListName(_name);
    saver.readBlockingListUrl(_url);
    string colorStr = "";
    saver.readBlockingListType(colorStr);
    _color = Stats::colorFromString(colorStr);
    _updatedAt = saver.read<std::time_t>();
    _outdated = saver.read<bool>();
    saver.read(_etag);
    _enabled = saver.read<bool>();
}

string BlockingList::getId() const { return _id; }

string BlockingList::getName() const { return _name; }

string BlockingList::getUrl() const { return _url; }

Stats::Color BlockingList::getColor() const { return _color; }

time_t BlockingList::getUpdatedAt() const { return _updatedAt; }

bool BlockingList::isOutdated() const { return _outdated; }

void BlockingList::setIsOutDated() { _outdated = true; }

string BlockingList::getEtag() const { return _etag; }

bool BlockingList::isEnabled() const { return _enabled; }

std::string BlockingList::serialize() {
    std::time_t date = _updatedAt;
    std::tm *date_tm = std::gmtime(&date);
    char dateBuffer[19];
    std::strftime(dateBuffer, 19, "%Y-%m-%d_%X", date_tm);
    std::string dateStr(dateBuffer, 19);
    string blString = "{\"id\":\"";
    blString += _id;
    blString += "\",\"name\":\"";
    blString += _name;
    blString += "\",\"url\":\"";
    blString += _url;
    blString += "\",\"type\":\"";
    blString += Stats::colorToString(_color);
    blString += "\",\"updatedAt\":\"";
    blString += dateStr;
    blString += "\",\"outdated\":";
    blString += _outdated ? "1" : "0";
    blString += ",\"etag\":\"";
    blString += _etag;
    blString += "\",\"enabled\":";
    blString += _enabled ? "1" : "0";
    blString += "}";
    return blString;
}
