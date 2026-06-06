#include <iostream>
#include "pcap_reader.h"
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
    while (reader.readNextPacket(packet)) {
        // Read packet data in a loop
    }

    std::cout << "Total packets: " << reader.packetCount() << "\n";

    reader.close();
    std::cout << "File closed successfully.\n";

    return 0;
}
