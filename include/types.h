#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <functional>
#include <unordered_map>
#include "classifier.h"


// ─── Parsed packet produced by PacketParser ─────────────────────────────

struct ParsedPacket {
    uint8_t src_mac[6] = {0};
    uint8_t dst_mac[6] = {0};
    uint16_t ether_type = 0;
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    uint8_t protocol = 0;
    uint8_t ip_header_len = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
    bool has_ip = false;
    bool has_tcp = false;
    bool has_udp = false;
};

// ─── Five-tuple: uniquely identifies a connection / flow ────────────────

struct FiveTuple {
    uint32_t src_ip   = 0;
    uint32_t dst_ip   = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t  protocol = 0;

    bool operator==(const FiveTuple& o) const {
        return src_ip   == o.src_ip   &&
               dst_ip   == o.dst_ip   &&
               src_port == o.src_port &&
               dst_port == o.dst_port &&
               protocol == o.protocol;
    }
};

// ─── Hash functor for FiveTuple (golden-ratio combine) ──────────────────

struct FiveTupleHash {
    size_t operator()(const FiveTuple& t) const {
        size_t h = 0;
        auto combine = [&](auto v) {
            h ^= std::hash<decltype(v)>{}(v)
                 + 0x9e3779b9 + (h << 6) + (h >> 2);
        };
        combine(t.src_ip);
        combine(t.dst_ip);
        combine(t.src_port);
        combine(t.dst_port);
        combine(t.protocol);
        return h;
    }
};

// ─── Flow: tracks state of one connection ───────────────────────────────

struct Flow {
    std::string sni;                // Extracted domain name (empty until found)
    std::string app_name;           // Classified application (empty until found)
    uint32_t    packet_count = 0;   // Incremented per packet
    uint64_t    byte_count   = 0;   // Accumulated payload bytes
    bool        classified   = false; // True once SNI is extracted
    AppType     app_type     = AppType::UNKNOWN;
};

// ─── FlowTable: hash map from FiveTuple → Flow ─────────────────────────

using FlowTable = std::unordered_map<FiveTuple, Flow, FiveTupleHash>;

// ─── Utility ────────────────────────────────────────────────────────────

std::string ipToString(uint32_t ip);

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

// ─── PCAP file structures ───────────────────────────────────────────────

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
