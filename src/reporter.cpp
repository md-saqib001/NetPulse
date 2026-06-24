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
    uint32_t flows_with_domain = 0;
    uint32_t flows_without_domain = 0;
    uint32_t unrecognized_domain_flows = 0;
    uint32_t filtered_flows_count = 0;

    uint32_t tcp_flows = 0;
    uint32_t udp_flows = 0;
    uint32_t other_flows = 0;
    uint64_t tcp_packets = 0;
    uint64_t udp_packets = 0;
    uint64_t other_packets = 0;

    struct AppStat {
        std::string name;
        std::string category;
        uint64_t packets = 0;
        uint64_t bytes = 0;
        AppType type;
    };
    std::map<std::string, AppStat> app_stats;

    struct CatStat {
        uint64_t packets = 0;
    };
    std::map<std::string, CatStat> cat_stats;

    struct TopConn {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t dst_port;
        uint64_t tcp_packets = 0;
        uint64_t udp_packets = 0;
        std::string app_name;
        AppType type;
        std::string sni;
        uint64_t total_packets() const { return tcp_packets + udp_packets; }
    };
    std::vector<TopConn> top_https;
    std::vector<TopConn> top_http;

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

        if (tuple.protocol == 6) {
            tcp_flows++;
            tcp_packets += flow.packet_count;
        } else if (tuple.protocol == 17) {
            udp_flows++;
            udp_packets += flow.packet_count;
        } else {
            other_flows++;
            other_packets += flow.packet_count;
        }

        if (!flow.sni.empty()) {
            flows_with_domain++;
            if (flow.classified) {
                classified_flows++;
            } else {
                unrecognized_domain_flows++;
            }
        } else {
            flows_without_domain++;
        }

        std::string stat_key;
        std::string display_name;
        if (flow.app_type != AppType::UNKNOWN) {
            display_name = app_name;
            stat_key = app_name;
        } else if (!flow.sni.empty()) {
            display_name = "Unrecognized Domain";
            stat_key = "Unrecognized Domain";
        } else {
            display_name = "Unknown (Raw IP)";
            stat_key = "Unknown (Raw IP)";
        }

        if (app_stats.find(stat_key) == app_stats.end()) {
            app_stats[stat_key].name = display_name;
            app_stats[stat_key].category = classifier.category(flow.app_type);
            app_stats[stat_key].type = flow.app_type;
        }
        app_stats[stat_key].packets += flow.packet_count;
        app_stats[stat_key].bytes += flow.byte_count;

        std::string cat = classifier.category(flow.app_type);
        cat_stats[cat].packets += flow.packet_count;

        if (tuple.dst_port == 443 || tuple.src_port == 443 || tuple.dst_port == 80 || tuple.src_port == 80) {
            uint32_t src = tuple.src_ip;
            uint32_t dst = tuple.dst_ip;
            uint16_t dport = tuple.dst_port;
            if (tuple.src_port == 443 || tuple.src_port == 80) {
                 src = tuple.dst_ip;
                 dst = tuple.src_ip;
                 dport = tuple.src_port;
            }
            auto& target_vec = (dport == 443) ? top_https : top_http;
            bool found = false;
            for (auto& conn : target_vec) {
                if (conn.src_ip == src && conn.dst_ip == dst && conn.dst_port == dport && conn.sni == flow.sni) {
                    if (tuple.protocol == 6) conn.tcp_packets += flow.packet_count;
                    else if (tuple.protocol == 17) conn.udp_packets += flow.packet_count;
                    found = true;
                    break;
                }
            }
            if (!found) {
                TopConn new_conn;
                new_conn.src_ip = src;
                new_conn.dst_ip = dst;
                new_conn.dst_port = dport;
                if (tuple.protocol == 6) new_conn.tcp_packets = flow.packet_count;
                else if (tuple.protocol == 17) new_conn.udp_packets = flow.packet_count;
                new_conn.app_name = app_name;
                new_conn.type = flow.app_type;
                new_conn.sni = flow.sni;
                target_vec.push_back(new_conn);
            }
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
            return a.total_packets() > b.total_packets();
        });

    std::sort(top_http.begin(), top_http.end(),
        [](const auto& a, const auto& b){
            return a.total_packets() > b.total_packets();
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
    std::cout << "  Flows with Domain: " << formatCount(flows_with_domain) << "  (" 
              << colorizePct(pct(flows_with_domain, filtered_flows_count)) << ")\n";
    if (flows_with_domain > 0) {
        std::cout << "    ├─ Classified:   " << formatCount(classified_flows) << "  (" 
                  << colorizePct(pct(classified_flows, flows_with_domain)) << ")\n";
        std::cout << "    └─ Unrecognized: " << formatCount(unrecognized_domain_flows) << "  (" 
                  << colorizePct(pct(unrecognized_domain_flows, flows_with_domain)) << ")\n";
    }
    std::cout << "  Flows w/o Domain:  " << formatCount(flows_without_domain) << "  (" 
              << colorizePct(pct(flows_without_domain, filtered_flows_count)) << ")\n";
    std::cout << "  Total data:        " << formatBytes(total_bytes) << "\n\n";

    std::cout << "  PROTOCOL BREAKDOWN\n";
    std::cout << "  ─────────────────────────────────────────────────\n";
    std::cout << "  " << std::left << std::setw(17) << "Protocol" 
              << std::right << std::setw(7) << "Flows" 
              << std::setw(12) << "Packets" << "\n";

    auto printProto = [&](const std::string& name, uint32_t f, uint64_t p) {
        if (f > 0) {
            std::cout << "  " << std::left << std::setw(17) << name
                      << std::right << std::setw(7 + (useColors ? Colors::WHITE.length() + Colors::BOLD.length() + Colors::RESET.length() : 0)) << formatCount(f)
                      << std::setw(12 + (useColors ? Colors::WHITE.length() + Colors::BOLD.length() + Colors::RESET.length() : 0)) << formatCount(p) << "\n";
        }
    };
    printProto("TCP", tcp_flows, tcp_packets);
    printProto("UDP", udp_flows, udp_packets);
    printProto("Other", other_flows, other_packets);
    std::cout << "\n";

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

    if (!top_https.empty()) {
        std::cout << "  TOP HTTPS CONNECTIONS  (port 443)\n";
        std::cout << "  ───────────────────────────────────────────────────────────────────────────────\n";
        std::cout << "  " << std::left << std::setw(18) << "Source IP" 
                  << std::setw(18) << "Destination" 
                  << std::setw(28) << "Domain (SNI)"
                  << std::setw(15) << "App" 
                  << std::right << std::setw(10) << "Total Pkts" 
                  << std::setw(10) << "TCP Pkts" 
                  << std::setw(10) << "UDP Pkts\n";
        int https_count = 0;
        for (const auto& conn : top_https) {
            if (https_count >= config.top_n) break; // limit to top_n
            std::string src_str = ipToString(conn.src_ip);
            std::string dst_str = maskIP(conn.dst_ip) + ":" + std::to_string(conn.dst_port);
            
            std::string app_name_c = colorizeApp(conn.app_name, conn.type);
            int app_color_len = useColors ? (conn.type == AppType::UNKNOWN ? Colors::GRAY.length() : Colors::GREEN.length()) + Colors::RESET.length() : 0;

            std::string sni_display = conn.sni;
            if (sni_display.empty()) sni_display = "-";
            if (sni_display.length() > 25) sni_display = sni_display.substr(0, 22) + "...";
            std::string sni_c = c(Colors::CYAN, sni_display);
            int sni_color_len = useColors ? Colors::CYAN.length() + Colors::RESET.length() : 0;

            int fmt_len = useColors ? Colors::WHITE.length() + Colors::BOLD.length() + Colors::RESET.length() : 0;
            std::string total_str = formatCount(conn.total_packets());
            std::string tcp_str = conn.tcp_packets > 0 ? formatCount(conn.tcp_packets) : "-";
            std::string udp_str = conn.udp_packets > 0 ? formatCount(conn.udp_packets) : "-";

            std::cout << "  " << std::left << std::setw(15) << src_str 
                      << "→  " << std::setw(17) << dst_str 
                      << std::setw(28 + sni_color_len) << sni_c
                      << std::setw(15 + app_color_len) << app_name_c 
                      << std::right 
                      << std::setw(10 + fmt_len) << total_str
                      << std::setw(10 + (conn.tcp_packets > 0 ? fmt_len : 0)) << tcp_str
                      << std::setw(10 + (conn.udp_packets > 0 ? fmt_len : 0)) << udp_str << "\n";
            https_count++;
        }
        std::cout << "\n";
    }

    if (!top_http.empty()) {
        std::cout << "  TOP HTTP CONNECTIONS  (port 80)\n";
        std::cout << "  ───────────────────────────────────────────────────────────────────────────────\n";
        std::cout << "  " << std::left << std::setw(18) << "Source IP" 
                  << std::setw(18) << "Destination" 
                  << std::setw(28) << "Domain (Host)"
                  << std::setw(15) << "App" 
                  << std::right << std::setw(10) << "Total Pkts" 
                  << std::setw(10) << "TCP Pkts" 
                  << std::setw(10) << "UDP Pkts\n";
        int http_count = 0;
        for (const auto& conn : top_http) {
            if (http_count >= config.top_n) break; // limit to top_n
            std::string src_str = ipToString(conn.src_ip);
            std::string dst_str = maskIP(conn.dst_ip) + ":" + std::to_string(conn.dst_port);
            
            std::string app_name_c = colorizeApp(conn.app_name, conn.type);
            int app_color_len = useColors ? (conn.type == AppType::UNKNOWN ? Colors::GRAY.length() : Colors::GREEN.length()) + Colors::RESET.length() : 0;

            std::string sni_display = conn.sni;
            if (sni_display.empty()) sni_display = "-";
            if (sni_display.length() > 25) sni_display = sni_display.substr(0, 22) + "...";
            std::string sni_c = c(Colors::CYAN, sni_display);
            int sni_color_len = useColors ? Colors::CYAN.length() + Colors::RESET.length() : 0;

            int fmt_len = useColors ? Colors::WHITE.length() + Colors::BOLD.length() + Colors::RESET.length() : 0;
            std::string total_str = formatCount(conn.total_packets());
            std::string tcp_str = conn.tcp_packets > 0 ? formatCount(conn.tcp_packets) : "-";
            std::string udp_str = conn.udp_packets > 0 ? formatCount(conn.udp_packets) : "-";

            std::cout << "  " << std::left << std::setw(15) << src_str 
                      << "→  " << std::setw(17) << dst_str 
                      << std::setw(28 + sni_color_len) << sni_c
                      << std::setw(15 + app_color_len) << app_name_c 
                      << std::right 
                      << std::setw(10 + fmt_len) << total_str
                      << std::setw(10 + (conn.tcp_packets > 0 ? fmt_len : 0)) << tcp_str
                      << std::setw(10 + (conn.udp_packets > 0 ? fmt_len : 0)) << udp_str << "\n";
            http_count++;
        }
        std::cout << "\n";
    }

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
