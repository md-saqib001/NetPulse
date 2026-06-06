#include <iostream>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Usage: ./netpulse <capture.pcap>\n";
        return 1;
    }

    std::cout << "NetPulse v1.0 — Deep Packet Inspection Engine\n";
    std::cout << "File: " << argv[1] << "\n";
    return 0;
}
