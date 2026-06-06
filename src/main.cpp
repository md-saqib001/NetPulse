#include <iostream>
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

    RawPacket packet;
    uint32_t total_count = 0;
    uint32_t ipv4_count = 0;
    uint32_t other_count = 0;
    uint32_t printed_count = 0;

    while (reader.readNextPacket(packet)) {
        total_count++;
        ParsedPacket parsed;
        if (PacketParser::parse(packet, parsed)) {
            ipv4_count++;
            if (printed_count < 10) {
                std::cout << "Packet " << total_count << ": "
                          << ipToString(parsed.src_ip) << " → "
                          << ipToString(parsed.dst_ip) << "  Proto: "
                          << static_cast<int>(parsed.protocol) << "\n";
                printed_count++;
            }
        } else {
            other_count++;
        }
    }

    std::cout << "Total packets:  " << total_count << "\n";
    std::cout << "IPv4 packets:   " << ipv4_count << "\n";
    std::cout << "Other packets:  " << other_count << "\n";

    reader.close();
    return 0;
}
