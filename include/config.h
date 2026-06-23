#pragma once

#include <string>

struct Config {
    std::string filename;
    int top_n = 10;
    bool verbose = false;
    bool csv_output = false;
    std::string filter_app = "";
    bool help = false;
    bool no_color = false;
};
