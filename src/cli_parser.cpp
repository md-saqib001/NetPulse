#include "cli_parser.h"
#include <iostream>
#include <algorithm>

bool CLIParser::isValidFlag(const std::string& flag) {
    return flag == "--top" || flag == "--verbose" || flag == "--csv" || 
           flag == "--filter" || flag == "--help" || flag == "-h" ||
           flag == "--no-color" || flag == "--demo" ||
           flag == "--verbose-live" || flag == "--json-stream";
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
    
    if (first_arg == "--demo") {
        config.demo = true;
        return config;
    }

    if (first_arg == "--live") {
        config.live_capture = true;
        if (argc >= 3 && !isValidFlag(argv[2])) {
            config.interface_name = argv[2];
        }
    } else {
        config.filename = first_arg;
    }

    int start_idx = config.live_capture ? (config.interface_name.empty() ? 2 : 3) : 2;
    for (int i = start_idx; i < argc; ++i) {
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
        } else if (arg == "--demo") {
            config.demo = true;
            return config;
        } else if (arg == "--verbose-live") {
            config.verbose_live = true;
        } else if (arg == "--json-stream") {
            config.json_stream = true;
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
              << "  " << program_name << " <file.pcap> [options]\n"
              << "  " << program_name << " --live <interface> [options]\n\n"
              << "Options:\n"
              << "  --top N        Show top N connections (default: 10)\n"
              << "  --verbose      Print each classified packet in real-time\n"
              << "  --verbose-live Print newly classified domains once per session\n"
              << "  --json-stream  Print JSON-lines format for newly classified domains\n"
              << "  --filter APP   Show only traffic matching app name\n"
              << "                 (youtube, instagram, github, netflix, etc.)\n"
              << "  --csv          Output as CSV instead of formatted table\n"
              << "  --no-color     Disable all ANSI color codes\n"
              << "  --demo         Show instructions for capturing your own traffic\n"
              << "  --help, -h     Show this help message\n\n"
              << "Examples:\n"
              << "  " << program_name << " capture.pcap\n"
              << "  " << program_name << " --live eth0\n"
              << "  " << program_name << " capture.pcap --filter youtube --top 5\n"
              << "  " << program_name << " capture.pcap --csv > results.csv\n\n"
              << "Architecture:\n"
              << "┌─────────────────────────────────────────────────────────┐\n"
              << "│                    NetPulse Pipeline                    │\n"
              << "├──────────────┬──────────────┬──────────────┬────────────┤\n"
              << "│ PcapReader   │PacketParser  │SNIExtractor  │Classifier  │\n"
              << "│              │              │              │            │\n"
              << "│ Read global  │ Ethernet hdr │ TLS record   │ Domain →   │\n"
              << "│ header       │ (14 bytes)   │ header check │ AppType    │\n"
              << "│              │              │              │            │\n"
              << "│ Read packet  │ IPv4 header  │ Client Hello │ Pattern    │\n"
              << "│ header+data  │ (IHL*4 bytes)│ verification │ matching   │\n"
              << "│              │              │              │            │\n"
              << "│ Handle byte  │ TCP header   │ Walk 5 var-  │ 30+ app    │\n"
              << "│ swapping     │ (DO*4 bytes) │ length fields│ patterns   │\n"
              << "│              │              │              │            │\n"
              << "│ Return       │ Set payload  │ Find SNI ext │ Return     │\n"
              << "│ RawPacket    │ pointer      │ type 0x0000  │ AppType    │\n"
              << "└──────┬───────┴──────┬───────┴──────┬───────┴─────┬──────┘\n"
              << "       │              │              │             │\n"
              << "       └──────────────┴──────────────┴─────────────┘\n"
              << "                              │\n"
              << "                    ┌─────────▼──────────┐\n"
              << "                    │   FlowTable        │\n"
              << "                    │ FiveTuple → Flow   │\n"
              << "                    │ (unordered_map     │\n"
              << "                    │  custom hash)      │\n"
              << "                    └─────────┬──────────┘\n"
              << "                              │\n"
              << "                    ┌─────────▼──────────┐\n"
              << "                    │    Reporter        │\n"
              << "                    │ App breakdown      │\n"
              << "                    │ Category groups    │\n"
              << "                    │ Top connections    │\n"
              << "                    │ Domain list        │\n"
              << "                    │ RFC 6066 footer    │\n"
              << "                    └────────────────────┘\n";
}
