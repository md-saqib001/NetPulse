#include "cli_parser.h"
#include <iostream>
#include <algorithm>

bool CLIParser::isValidFlag(const std::string& flag) {
    return flag == "--top" || flag == "--verbose" || flag == "--csv" || 
           flag == "--filter" || flag == "--help" || flag == "-h" ||
           flag == "--no-color";
}

Config CLIParser::parse(int argc, char* argv[]) {
    Config config;

    if (argc < 2) {
        config.help = true;
        return config;
    }

    std::string first_arg = argv[1];
    if (first_arg == "--help" || first_arg == "-h") {
        config.help = true;
        return config;
    }

    config.filename = first_arg;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            config.help = true;
            return config;
        } else if (arg == "--top") {
            if (i + 1 < argc) {
                config.top_n = std::stoi(argv[++i]);
            }
        } else if (arg == "--verbose") {
            config.verbose = true;
        } else if (arg == "--csv") {
            config.csv_output = true;
        } else if (arg == "--filter") {
            if (i + 1 < argc) {
                config.filter_app = argv[++i];
                // Lowercase the filter
                std::transform(config.filter_app.begin(), config.filter_app.end(), config.filter_app.begin(), [](unsigned char c){ return std::tolower(c); });
            }
        } else if (arg == "--no-color") {
            config.no_color = true;
        } else {
            std::cerr << "Warning: Unknown flag " << arg << "\n";
        }
    }

    return config;
}

void CLIParser::printHelp(const std::string& program_name) {
    std::cout << "NetPulse v1.0 — Deep Packet Inspection Engine\n"
              << "Analyzes PCAP files to classify network traffic using \n"
              << "TLS SNI extraction.\n\n"
              << "Usage:\n"
              << "  " << program_name << " <file.pcap> [options]\n\n"
              << "Options:\n"
              << "  --top N        Show top N connections (default: 10)\n"
              << "  --verbose      Print each classified packet in real-time\n"
              << "  --filter APP   Show only traffic matching app name\n"
              << "                 (youtube, instagram, github, netflix, etc.)\n"
              << "  --csv          Output as CSV instead of formatted table\n"
              << "  --no-color     Disable all ANSI color codes\n"
              << "  --help, -h     Show this help message\n\n"
              << "Examples:\n"
              << "  " << program_name << " capture.pcap\n"
              << "  " << program_name << " capture.pcap --filter youtube --top 5\n"
              << "  " << program_name << " capture.pcap --csv > results.csv\n";
}
