#include "utils.hpp"
#include <windows.h>
#include <iostream>
#include <iomanip>
#include <chrono>

namespace logger {
    void set_console_color(WORD color) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, color);
    }

    void raw(const std::string& message) {
        std::cout << message;
    }

    void log(const std::string& message, Level level) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

        WORD white = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
        WORD bright_white = white | FOREGROUND_INTENSITY;
        WORD cyan_bright = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        WORD green_bright = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        WORD red_bright = FOREGROUND_RED | FOREGROUND_INTENSITY;
        WORD yellow_bright = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;

        std::cout << "  ";

        set_console_color(white);
        std::cout << "[";

        switch (level) {
        case info:
            set_console_color(cyan_bright);
            std::cout << "  INFO  ";
            break;
        case success:
            set_console_color(green_bright);
            std::cout << "   OK   ";
            break;
        case fail:
            set_console_color(red_bright);
            std::cout << "  FAIL  ";
            break;
        case warn:
            set_console_color(yellow_bright);
            std::cout << "  WARN  ";
            break;
        default:
            set_console_color(bright_white);
            std::cout << "   ??   ";
            break;
        }

        set_console_color(white);
        std::cout << "] ";

        set_console_color(bright_white);
        std::cout << message << std::endl;

        set_console_color(white);
    }
}
