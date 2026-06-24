#include "live_capture.h"
#include <iostream>
#include <cstring>

LiveCapture::LiveCapture() : pcap_handle(nullptr) {}

LiveCapture::~LiveCapture() {
    close();
}

bool LiveCapture::open(const std::string& interfaceName) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Explain promiscuous mode: normally a network interface only processes packets
    // addressed TO it; promiscuous mode captures ALL packets on the segment it can
    // see, even ones not addressed to your machine. DPI tools typically need this
    // to inspect all visible network traffic.
    // Privacy/legal note: on a switched network (virtually all modern networks),
    // promiscuous mode mostly only sees YOUR OWN traffic anyway, not your neighbors'
    // - switches don't broadcast everyone's traffic to everyone the way old hubs did.
    int promisc = 1;

    pcap_handle = pcap_open_live(interfaceName.c_str(), 
                                 65535, /* snaplen, max bytes per packet */
                                 promisc, 
                                 1000, /* read timeout in ms */
                                 errbuf);

    if (pcap_handle == nullptr) {
        std::cerr << "Failed to open interface " << interfaceName << " for live capture: " << errbuf << std::endl;
        std::cerr << "Hint: Ensure you have sufficient permissions." << std::endl;
        std::cerr << "On Linux/Mac use 'sudo' or 'setcap cap_net_raw,cap_net_admin=eip ./netpulse'." << std::endl;
        std::cerr << "On Windows run as Administrator." << std::endl;
        return false;
    }

    return true;
}

bool LiveCapture::captureOne(RawPacket& outPacket) {
    if (pcap_handle == nullptr) {
        return false;
    }

    struct pcap_pkthdr* header;
    const u_char* data;

    // Use pcap_next_ex() to get ONE packet (polling style instead of callback style)
    // res will be 1 on success, 0 on timeout, -1 on error, -2 on EOF
    int res = pcap_next_ex(pcap_handle, &header, &data);

    if (res == 1) {
        // Successfully read a packet
        outPacket.header.ts_sec = header->ts.tv_sec;
        outPacket.header.ts_usec = header->ts.tv_usec;
        outPacket.header.incl_len = header->caplen;
        outPacket.header.orig_len = header->len;

        outPacket.data.assign(data, data + header->caplen);
        outPacket.timestamp_us = (uint64_t)header->ts.tv_sec * 1000000ULL + header->ts.tv_usec;

        return true;
    } else if (res == 0) {
        // Timeout occurred (no packet received within the 1000ms read timeout).
        // This is normal and allows the loop to check for exit conditions instead of blocking forever.
        return false;
    } else {
        // Error or EOF (res == -1 or -2)
        if (res == -1) {
            std::cerr << "Error reading packet: " << pcap_geterr(pcap_handle) << std::endl;
        }
        return false;
    }
}

void LiveCapture::close() {
    if (pcap_handle != nullptr) {
        pcap_close(pcap_handle);
        pcap_handle = nullptr;
    }
}

std::string LiveCapture::promptForInterface() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *d;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return "";
    }

    if (alldevs == nullptr) {
        std::cerr << "No interfaces found! Make sure you have the required permissions (e.g., sudo / Administrator)." << std::endl;
        return "";
    }

    std::vector<std::string> interfaceNames;
    std::cout << "\nAvailable Network Interfaces:\n";
    std::cout << "─────────────────────────────────────────────────\n";
    
    int i = 0;
    for (d = alldevs; d != nullptr; d = d->next) {
        interfaceNames.push_back(d->name);
        std::cout << "  [" << ++i << "] " << d->name;
        if (d->description) {
            std::cout << " (" << d->description << ")";
        }
        std::cout << std::endl;
    }
    std::cout << "─────────────────────────────────────────────────\n";
    pcap_freealldevs(alldevs);

    int choice = 0;
    while (true) {
        std::cout << "Select an interface (1-" << interfaceNames.size() << ") [0 to exit]: ";
        std::cin >> choice;
        
        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            continue;
        }

        if (choice == 0) {
            return "";
        }

        if (choice >= 1 && choice <= (int)interfaceNames.size()) {
            return interfaceNames[choice - 1];
        } else {
            std::cout << "Invalid choice. Please try again.\n";
        }
    }
}
