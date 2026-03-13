#pragma once

namespace android::base {

class TestLogStream {
public:
    template <class T>
    TestLogStream &operator<<(const T &) {
        return *this;
    }
};

} // namespace android::base

#define LOG(severity) ::android::base::TestLogStream()
