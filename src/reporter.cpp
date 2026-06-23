#include "reporter.h"
#include "classifier.h"
#include "colors.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <algorithm>
#include <map>
#include <cmath>
#include <cctype>

std::string Reporter::formatBytes(uint64_t bytes) const {
    double b = bytes;
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int i = 0;
    while (b >= 1024.0 && i < 4) {
        b /= 1024.0;
        i++;
    }
    std::ostringstream out;
    if (i == 0) {
        out << (uint64_t)b << " " << units[i];
    } else {
        out << std::fixed << std::setprecision(1) << b << " " << units[i];
    }
    return out.str();
}

std::string Reporter::formatCount(uint64_t n) const {
    std::string s = std::to_string(n);
    int insertPosition = s.length() - 3;
    while (insertPosition > 0) {
        s.insert(insertPosition, ",");
        insertPosition -= 3;
    }
    return c(Colors::WHITE + Colors::BOLD, s);
}

double Reporter::pct(uint64_t part, uint64_t total) const {
    if (total == 0) return 0.0;
    return (double)part / total * 100.0;
}

static std::string maskIP(uint32_t ip) {
    uint8_t bytes[4];
    bytes[0] = (ip >> 24) & 0xFF;
    bytes[1] = (ip >> 16) & 0xFF;
    bytes[2] = (ip >> 8) & 0xFF;
    bytes[3] = ip & 0xFF;
    
    std::ostringstream oss;
    oss << (int)bytes[0] << "." << (int)bytes[1] << ".x.x";
    return oss.str();
}

void Reporter::generateCSV(const Config& config,
                           const FlowTable& flows,
                           uint32_t /*total_packets*/,
                           uint64_t /*total_bytes*/) {
    Classifier classifier;
    std::cout << "src_ip,dst_ip,dst_port,protocol,sni,app_name,category,packets,bytes\n";

    for (const auto& [tuple, flow] : flows) {
        std::string app_name = classifier.appName(flow.app_type);
        
        if (!config.filter_app.empty()) {
            std::string lower_app_name = app_name;
            std::transform(lower_app_name.begin(), lower_app_name.end(), lower_app_name.begin(), [](unsigned char c){ return std::tolower(c); });
            if (lower_app_name.find(config.filter_app) == std::string::npos) {
                continue;
            }
        }

        std::string src_ip_str = ipToString(tuple.src_ip);
        std::string dst_ip_str = ipToString(tuple.dst_ip);
        std::string proto_str = tuple.protocol == 6 ? "TCP" : (tuple.protocol == 17 ? "UDP" : std::to_string(tuple.protocol));
        
        std::cout << src_ip_str << ","
                  << dst_ip_str << ","
                  << tuple.dst_port << ","
                  << proto_str << ","
                  << flow.sni << ","
                  << app_name << ","
                  << classifier.category(flow.app_type) << ","
                  << flow.packet_count << ","
                  << flow.byte_count << "\n";
    }
}

void Reporter::generate(const Config& config,
                        const FlowTable& flows,
                        uint32_t total_packets,
                        uint64_t total_bytes) {
    
    Classifier classifier;

    uint32_t classified_flows = 0;
    uint32_t unclassified_flows = 0;
    uint32_t filtered_flows_count = 0;

    struct AppStat {
        std::string name;
        std::string category;
        uint64_t packets = 0;
        uint64_t bytes = 0;
        AppType type;
    };
    std::map<AppType, AppStat> app_stats;

    struct CatStat {
        uint64_t packets = 0;
    };
    std::map<std::string, CatStat> cat_stats;

    struct TopConn {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t dst_port;
        std::string app_name;
        uint64_t packets;
        AppType type;
    };
    std::vector<TopConn> top_https;

    struct UniqueDomain {
        std::string domain;
        std::string app_name;
        AppType type;
    };
    std::vector<UniqueDomain> unique_domains;

    for (const auto& [tuple, flow] : flows) {
        std::string app_name = classifier.appName(flow.app_type);

        if (!config.filter_app.empty()) {
            std::string lower_app_name = app_name;
            std::transform(lower_app_name.begin(), lower_app_name.end(), lower_app_name.begin(), [](unsigned char c){ return std::tolower(c); });
            if (lower_app_name.find(config.filter_app) == std::string::npos) {
                continue;
            }
        }
        
        filtered_flows_count++;

        if (flow.classified) {
            classified_flows++;
        } else {
            unclassified_flows++;
        }

        if (app_stats.find(flow.app_type) == app_stats.end()) {
            app_stats[flow.app_type].name = app_name;
            app_stats[flow.app_type].category = classifier.category(flow.app_type);
            app_stats[flow.app_type].type = flow.app_type;
        }
        app_stats[flow.app_type].packets += flow.packet_count;
        app_stats[flow.app_type].bytes += flow.byte_count;

        std::string cat = classifier.category(flow.app_type);
        cat_stats[cat].packets += flow.packet_count;

        if (tuple.dst_port == 443 || tuple.src_port == 443) {
            uint32_t src = tuple.src_ip;
            uint32_t dst = tuple.dst_ip;
            uint16_t dport = tuple.dst_port;
            if (tuple.src_port == 443) {
                 src = tuple.dst_ip;
                 dst = tuple.src_ip;
                 dport = tuple.src_port;
            }
            top_https.push_back({src, dst, dport, app_name, flow.packet_count, flow.app_type});
        }

        if (!flow.sni.empty()) {
            bool found = false;
            for (const auto& d : unique_domains) {
                if (d.domain == flow.sni) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                unique_domains.push_back({flow.sni, app_name, flow.app_type});
            }
        }
    }

    std::vector<AppStat> sorted_apps;
    for (const auto& [type, stat] : app_stats) {
        sorted_apps.push_back(stat);
    }
    std::sort(sorted_apps.begin(), sorted_apps.end(), 
        [](const auto& a, const auto& b){ 
          return a.packets > b.packets; 
    });

    std::vector<std::pair<std::string, CatStat>> sorted_cats(cat_stats.begin(), cat_stats.end());
    std::sort(sorted_cats.begin(), sorted_cats.end(),
        [](const auto& a, const auto& b){
            return a.second.packets > b.second.packets;
        });

    std::sort(top_https.begin(), top_https.end(),
        [](const auto& a, const auto& b){
            return a.packets > b.packets;
        });

    std::sort(unique_domains.begin(), unique_domains.end(),
        [](const auto& a, const auto& b){
            return a.domain < b.domain;
        });

    std::string border = c(Colors::CYAN + Colors::BOLD, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    std::string title = c(Colors::CYAN + Colors::BOLD, "  NetPulse v1.0 — Deep Packet Inspection Engine");

    std::cout << "\n" << border << "\n" << title << "\n" << border << "\n\n";

    if (!config.filter_app.empty()) {
        std::cout << "  Filter: " << config.filter_app << " (showing " << filtered_flows_count << " of " << flows.size() << " total flows)\n\n";
    }

    auto colorizeApp = [&](const std::string& name, AppType type) {
        if (type == AppType::UNKNOWN) {
            return c(Colors::GRAY, name);
        }
        return c(Colors::GREEN, name);
    };

    auto colorizePct = [&](double pct_val) {
        std::ostringstream out;
        out << std::fixed << std::setprecision(1) << pct_val << "%";
        return c(Colors::YELLOW, out.str());
    };

    std::cout << "  FILE SUMMARY\n";
    std::cout << "  ─────────────────────────────────────────────────\n";
    std::cout << "  File:              " << config.filename << "\n";
    std::cout << "  Total packets:     " << formatCount(total_packets) << "\n";
    std::cout << "  Total flows:       " << formatCount(filtered_flows_count) << "\n";
    std::cout << "  Classified flows:  " << formatCount(classified_flows) << "  (" 
              << colorizePct(pct(classified_flows, filtered_flows_count)) << ")\n";
    std::cout << "  Unclassified:      " << formatCount(unclassified_flows) << "  (" 
              << colorizePct(pct(unclassified_flows, filtered_flows_count)) << ")\n";
    std::cout << "  Total data:        " << formatBytes(total_bytes) << "\n\n";

    std::cout << "  APPLICATION BREAKDOWN\n";
    std::cout << "  ─────────────────────────────────────────────────\n";
    std::cout << "  " << std::left << std::setw(17) << "App" 
              << std::right << std::setw(7) << "Packets" 
              << std::setw(7) << "%" 
              << "      " << std::left << "Category" << "\n";
    for (const auto& app : sorted_apps) {
        std::string cat_display = app.category == "Unknown" ? "—" : app.category;
        
        // Handling width with ANSI codes properly is tricky, since ANSI codes are not visible characters.
        // We output the ANSI codes outside the setw if possible, or build the string.
        std::ostringstream out_pct;
        out_pct << std::fixed << std::setprecision(1) << pct(app.packets, total_packets) << "%";
        
        std::string name_colored = colorizeApp(app.name, app.type);
        // ANSI codes add chars, making setw() behave wrong.
        // Easiest trick: print spaces manually or adjust setw by the color code length.
        // The prompt says "Apply Colors to all output sections". If we just inject c() we break setw alignment if useColors is true.
        int color_len = useColors ? (app.type == AppType::UNKNOWN ? Colors::GRAY.length() : Colors::GREEN.length()) + Colors::RESET.length() : 0;
        
        std::cout << "  " << std::left << std::setw(17 + color_len) << name_colored
                  << std::right << std::setw(7 + (useColors ? Colors::WHITE.length() + Colors::BOLD.length() + Colors::RESET.length() : 0)) << formatCount(app.packets)
                  << std::setw(7 + (useColors ? Colors::YELLOW.length() + Colors::RESET.length() : 0)) << colorizePct(pct(app.packets, total_packets))
                  << "   " << std::left << cat_display << "\n";
    }
    std::cout << "\n";

    std::cout << "  CATEGORY BREAKDOWN\n";
    std::cout << "  ─────────────────────────────────────────────────\n";
    for (const auto& [cat, stat] : sorted_cats) {
        std::cout << "  " << std::left << std::setw(17) << cat
                  << std::right << std::setw(7 + (useColors ? Colors::WHITE.length() + Colors::BOLD.length() + Colors::RESET.length() : 0)) << formatCount(stat.packets)
                  << std::setw(7 + (useColors ? Colors::YELLOW.length() + Colors::RESET.length() : 0)) << colorizePct(pct(stat.packets, total_packets)) << "\n";
    }
    std::cout << "\n";

    std::cout << "  TOP HTTPS CONNECTIONS  (port 443)\n";
    std::cout << "  ─────────────────────────────────────────────────\n";
    std::cout << "  " << std::left << std::setw(20) << "Source IP" 
              << std::setw(18) << "Destination" 
              << std::setw(12) << "App" 
              << "Pkts\n";
    int https_count = 0;
    for (const auto& conn : top_https) {
        if (https_count >= config.top_n) break; // limit to top_n
        std::string src_str = ipToString(conn.src_ip);
        std::string dst_str = maskIP(conn.dst_ip) + ":" + std::to_string(conn.dst_port);
        
        std::string app_name_c = colorizeApp(conn.app_name, conn.type);
        int color_len = useColors ? (conn.type == AppType::UNKNOWN ? Colors::GRAY.length() : Colors::GREEN.length()) + Colors::RESET.length() : 0;

        std::cout << "  " << std::left << std::setw(15) << src_str 
                  << "→  " << std::setw(17) << dst_str 
                  << std::setw(12 + color_len) << app_name_c 
                  << formatCount(conn.packets) << "\n";
        https_count++;
    }
    std::cout << "\n";

    std::cout << "  UNIQUE DOMAINS SEEN\n";
    std::cout << "  ─────────────────────────────────────────────────\n";
    for (const auto& d : unique_domains) {
        std::string domain_c = c(Colors::CYAN, d.domain);
        int color_len = useColors ? Colors::CYAN.length() + Colors::RESET.length() : 0;
        
        std::cout << "  " << std::left << std::setw(29 + color_len) << domain_c 
                  << "[" << colorizeApp(d.app_name, d.type) << "]\n";
    }
    std::cout << "\n";

    std::cout << border << "\n";
    std::cout << c(Colors::CYAN + Colors::BOLD, "  VERIFIED: TLS SNI reveals destination domain\n");
    std::cout << c(Colors::CYAN + Colors::BOLD, "  even on encrypted HTTPS connections (RFC 6066)\n");
    std::cout << border << "\n";
}
