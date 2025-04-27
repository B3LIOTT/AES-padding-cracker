#include <iostream>
#include <string>

#include "include/log.h"


namespace Log {
    void print(const std::string& msg) {
        std::cout << WHITE << msg << std::endl;
    }

    void flushPrint(const std::string& msg){
        std::cout << WHITE << '\r' << msg << std::flush;
    }

    void info(const std::string& msg) {
        std::cout << WHITE << "[INFO]-" + msg << std::endl;
    }

    void bingo(const std::string& msg) {
        std::cout << std::endl;
        std::cout << GREEN << "[SUCCESS]-" + msg << std::endl;
        std::cout << std::endl;
    }

    void warning(const std::string& msg) {
        std::cout << ORANGE << "[WARN]-" + msg << std::endl;
    }

    void error(const std::string& msg) {
        std::cout << RED << "[ERROR]-" + msg << std::endl;
    }
}