#include <Activity.hpp>

Activity::Activity(App::Ptr app) : _app(app) {
}

Activity::~Activity() {
}

void Activity::print(std::ostream &out) const {
    _app->printAppStats(out, Stats::DAY0, Stats::DNS);
}

bool Activity::inHorizon(const uint32_t horizon, const timespec timeRef) const {
    return true;
}

bool Activity::expired(const Activity::Ptr activity) const {
    return _streamed;
}

void Activity::save(Saver &saver) {
}

Activity::Ptr restore(Saver &saver) {
    return nullptr;
}
