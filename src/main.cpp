#include <iostream>
#include <algorithm>
#include <set>
#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "classifier.h"
#include "types.h"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Usage: ./netpulse <capture.pcap>\n";
        return 1;
    }

    std::string filename = argv[1];
    PcapReader reader;

    if (!reader.open(filename)) {
        std::cerr << "Error: Failed to open PCAP file " << filename << "\n";
        return 1;
    }

    std::cout << "Reading: " << filename << "\n";

    Classifier classifier;
    FlowTable flows;
    RawPacket packet;
    uint32_t total_count = 0;

    while (reader.readNextPacket(packet)) {
        total_count++;

        ParsedPacket parsed;
        if (!PacketParser::parse(packet, parsed)) {
            continue;
        }

        // Build five-tuple from parsed packet fields
        FiveTuple tuple;
        tuple.src_ip   = parsed.src_ip;
        tuple.dst_ip   = parsed.dst_ip;
        tuple.src_port = parsed.src_port;
        tuple.dst_port = parsed.dst_port;
        tuple.protocol = parsed.protocol;

        // Update flow statistics
        Flow& flow = flows[tuple];
        flow.packet_count++;
        flow.byte_count += parsed.payload_len;

        // ── Day 5 & 6: SNI / HTTP Host extraction and Classification ──
        if (parsed.payload_len > 5 && flow.sni.empty())
        {
            // HTTPS — TLS Client Hello on port 443
            if (parsed.dst_port == 443 || parsed.src_port == 443)
            {
                auto sni = SNIExtractor::extractTLS(
                    parsed.payload, parsed.payload_len);
                if (sni.has_value()) {
                    flow.sni        = sni.value();
                    flow.app_type   = classifier.classify(flow.sni);
                    flow.app_name   = classifier.appName(flow.app_type);
                    flow.classified = (flow.app_type != AppType::UNKNOWN);
                    std::cout << "SNI: " << sni.value() << "\n";
                    if (flow.classified) {
                        std::cout << "CLASSIFIED: " << flow.sni << " → " 
                                  << flow.app_name << " [" 
                                  << classifier.category(flow.app_type) << "]\n";
                    }
                }
            }
            // HTTP — plaintext Host header on port 80
            else if (parsed.dst_port == 80 || parsed.src_port == 80)
            {
                if (SNIExtractor::isHTTPRequest(
                        parsed.payload, parsed.payload_len))
                {
                    auto host = SNIExtractor::extractHTTPHost(
                        parsed.payload, parsed.payload_len);
                    if (host.has_value()) {
                        flow.sni        = host.value();
                        flow.app_type   = classifier.classify(flow.sni);
                        flow.app_name   = classifier.appName(flow.app_type);
                        flow.classified = (flow.app_type != AppType::UNKNOWN);
                        std::cout << "HTTP Host: " << host.value() << "\n";
                        if (flow.classified) {
                            std::cout << "CLASSIFIED: " << flow.sni << " → " 
                                  << flow.app_name << " [" 
                                  << classifier.category(flow.app_type) << "]\n";
                        }
                    }
                }
            }
        }
    }

    reader.close();

    // ── Summary statistics ─────────────────────────────────────────────
    uint32_t tcp_flows        = 0;
    uint32_t udp_flows        = 0;
    uint32_t port443          = 0;
    uint32_t port80           = 0;
    uint32_t sni_count        = 0;
    uint32_t classified_count = 0;
    std::set<std::string> unique_domains;

    for (const auto& [key, flow] : flows) {
        if (key.protocol == 6)   tcp_flows++;
        if (key.protocol == 17)  udp_flows++;
        if (key.dst_port == 443) port443++;
        if (key.dst_port == 80)  port80++;

        if (!flow.sni.empty()) {
            sni_count++;
            unique_domains.insert(flow.sni);
            if (flow.classified) {
                classified_count++;
            }
        }
    }

    std::cout << "\n";
    std::cout << "──────────── Summary ────────────\n";
    std::cout << "Total packets:      " << total_count          << "\n";
    std::cout << "Unique flows:       " << flows.size()         << "\n";
    std::cout << "TCP flows:          " << tcp_flows            << "\n";
    std::cout << "UDP flows:          " << udp_flows            << "\n";
    std::cout << "Port 443 flows:     " << port443              << "\n";
    std::cout << "Port 80 flows:      " << port80               << "\n";
    std::cout << "SNI extractions:    " << sni_count            << "\n";
    std::cout << "Classified flows:   " << classified_count << " / " << flows.size() << "\n";
    std::cout << "Unique domains:     " << unique_domains.size()<< "\n";

    if (!unique_domains.empty()) {
        std::cout << "\nDomains found:\n";
        for (const auto& domain : unique_domains) {
            std::cout << "  " << domain << "\n";
        }
    }

    return 0;
}
