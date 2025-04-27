#pragma once

#include <iostream>
#include <string>

#define ORANGE "\033[38;5;214m"
#define WHITE "\033[37m"
#define GREEN "\033[32m"
#define RED "\033[31m"


namespace Log {
    void print(const std::string& msg);
    void flushPrint(const std::string& msg);
    void info(const std::string& msg);
    void bingo(const std::string& msg);
    void warning(const std::string& msg); 
    void error(const std::string& msg);
}
