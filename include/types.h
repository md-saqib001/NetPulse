#pragma once

#include <cstdint>
#include <vector>

// Forward declarations for structures to be implemented later
struct ParsedPacket;
struct FiveTuple;
struct Flow;

#pragma pack(push, 1)

struct PcapGlobalHeader {
    uint32_t magic_number;   // Magic number
    uint16_t version_major;  // Major version number
    uint16_t version_minor;  // Minor version number
    int32_t  thiszone;       // GMT to local correction
    uint32_t sigfigs;        // Accuracy of timestamps
    uint32_t snaplen;        // Max length of captured packets, in octets
    uint32_t network;        // Data link type
};

struct PcapPacketHeader {
    uint32_t ts_sec;         // Timestamp seconds
    uint32_t ts_usec;        // Timestamp microseconds
    uint32_t incl_len;       // Number of octets of packet saved in file
    uint32_t orig_len;       // Actual length of packet
};

#pragma pack(pop)

struct RawPacket {
    PcapPacketHeader header;
    std::vector<uint8_t> data;
    uint64_t timestamp_us;
};
