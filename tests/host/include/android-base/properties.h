#pragma once

#include <string>

namespace android::base {

inline bool GetBoolProperty(const std::string &, const bool defaultValue) {
    return defaultValue;
}

inline bool SetProperty(const std::string &, const std::string &) {
    return true;
}

} // namespace android::base
