#include <iostream>
#include <pcap.h>

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *d;

    std::cout << "NetPulse Live Capture Test" << std::endl;
    std::cout << "Looking for available network interfaces..." << std::endl;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return 1;
    }

    if (alldevs == nullptr) {
        std::cout << "No interfaces found! Make sure you have the required permissions (e.g., sudo / Administrator)." << std::endl;
        return 0;
    }

    int i = 0;
    for (d = alldevs; d != nullptr; d = d->next) {
        std::cout << ++i << ". " << d->name;
        if (d->description) {
            std::cout << " (" << d->description << ")";
        } else {
            std::cout << " (No description available)";
        }
        std::cout << std::endl;
    }

    pcap_freealldevs(alldevs);
    return 0;
}
