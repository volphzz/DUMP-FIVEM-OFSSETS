#pragma once
#include <string>
#include <cstdint>

namespace logger {
    enum Level {
        info = 0,
        success = 1,
        fail = 2,
        warn = 3
    };

    void log(const std::string& message, Level level = info);
    void raw(const std::string& message);
}
