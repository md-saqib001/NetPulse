#pragma once

#include "config.h"
#include <string>

class CLIParser {
public:
    static Config parse(int argc, char* argv[]);
    static void printHelp(const std::string& program_name);
    static bool isValidFlag(const std::string& flag);
};
