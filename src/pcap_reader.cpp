#include "pcap_reader.h"
#include <iostream>
#include <cstdlib>

bool PcapReader::open(const std::string& filename) {
    file_.open(filename, std::ios::binary);
    if (!file_.is_open()) {
        std::cerr << "Error: cannot open file: " << filename << "\n";
        std::exit(1);
    }

    PcapGlobalHeader global_header;
    file_.read(reinterpret_cast<char*>(&global_header), sizeof(PcapGlobalHeader));
    if (file_.gcount() < static_cast<std::streamsize>(sizeof(PcapGlobalHeader))) {
        // Just empty / less than global header -> graceful exit or handle as empty
        file_.close();
        return false;
    }

    if (global_header.magic_number == 0xa1b2c3d4) {
        byte_swapped_ = false;
    } else if (global_header.magic_number == 0xd4c3b2a1) {
        byte_swapped_ = true;
    } else {
        std::cerr << "Error: not a valid PCAP file (bad magic)\n";
        std::exit(1);
    }

    packet_count_ = 0;
    return true;
}

bool PcapReader::readNextPacket(RawPacket& packet) {
    if (!file_ || !file_.is_open()) {
        return false;
    }

    PcapPacketHeader header;
    file_.read(reinterpret_cast<char*>(&header), sizeof(PcapPacketHeader));
    if (file_.gcount() < static_cast<std::streamsize>(sizeof(PcapPacketHeader))) {
        return false; // graceful end of file or truncated
    }

    if (byte_swapped_) {
        header.ts_sec = swap32(header.ts_sec);
        header.ts_usec = swap32(header.ts_usec);
        header.incl_len = swap32(header.incl_len);
        header.orig_len = swap32(header.orig_len);
    }

    packet.header = header;
    packet.data.resize(header.incl_len);

    if (header.incl_len > 0) {
        file_.read(reinterpret_cast<char*>(packet.data.data()), header.incl_len);
        if (file_.gcount() < static_cast<std::streamsize>(header.incl_len)) {
            return false; // truncated mid-packet
        }
    }

    packet.timestamp_us = static_cast<uint64_t>(header.ts_sec) * 1000000ULL + header.ts_usec;
    packet_count_++;

    return true;
}

void PcapReader::close() {
    if (file_.is_open()) {
        file_.close();
    }
}
