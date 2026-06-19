#include <iostream>
#include <algorithm>
#include "pcap_reader.h"
#include "packet_parser.h"
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
        flows[tuple].packet_count++;
        flows[tuple].byte_count += parsed.payload_len;
    }

    reader.close();

    // Count flows by type
    uint32_t tcp_flows  = 0;
    uint32_t udp_flows  = 0;
    uint32_t port443    = 0;
    uint32_t port80     = 0;

    for (const auto& [key, flow] : flows) {
        if (key.protocol == 6)   tcp_flows++;
        if (key.protocol == 17)  udp_flows++;
        if (key.dst_port == 443) port443++;
        if (key.dst_port == 80)  port80++;
    }

    // Print summary
    std::cout << "Total packets:    " << total_count      << "\n";
    std::cout << "Unique flows:     " << flows.size()     << "\n";
    std::cout << "TCP flows:        " << tcp_flows        << "\n";
    std::cout << "UDP flows:        " << udp_flows        << "\n";
    std::cout << "Port 443 flows:   " << port443          << "\n";
    std::cout << "Port 80 flows:    " << port80           << "\n";

    return 0;
}
