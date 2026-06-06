#pragma once

#include <string>
#include <fstream>
#include "types.h"

class PcapReader {
public:
    PcapReader() = default;
    ~PcapReader() { close(); }

    bool open(const std::string& filename);
    bool readNextPacket(RawPacket& packet);
    void close();

    bool isSwapped() const { return byte_swapped_; }
    uint32_t packetCount() const { return packet_count_; }

private:
    std::ifstream file_;
    bool byte_swapped_ = false;
    uint32_t packet_count_ = 0;
};
