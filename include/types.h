#pragma once

#include <cstdint>
#include <vector>

// Forward declarations for structures to be implemented later
struct ParsedPacket;
struct FiveTuple;
struct Flow;

inline uint32_t swap32(uint32_t val) {
    return ((val & 0x000000FFu) << 24) |
           ((val & 0x0000FF00u) << 8)  |
           ((val & 0x00FF0000u) >> 8)  |
           ((val & 0xFF000000u) >> 24);
}

inline uint16_t swap16(uint16_t val) {
    return ((val & 0x00FFu) << 8) |
           ((val & 0xFF00u) >> 8);
}

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
    PcapPacketHeader header;     // The 16-byte envelope
    std::vector<uint8_t> data;   // The actual payload of size 'incl_len'
    uint64_t timestamp_us;       // A mathematical combination of ts_sec and ts_usec
};
