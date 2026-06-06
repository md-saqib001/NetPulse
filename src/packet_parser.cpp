#include "packet_parser.h"
#include <cstring>
#include <string>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

bool PacketParser::parse(const RawPacket& raw, ParsedPacket& out) {
    if (!parseEthernet(raw, out)) {
        return false;
    }
    if (out.ether_type != 0x0800) {
        return false;
    }
    if (!parseIPv4(raw, out)) {
        return false;
    }
    return true;
}

bool PacketParser::parseEthernet(const RawPacket& raw, ParsedPacket& out) {
    if (raw.data.size() < 14) {
        return false;
    }
    std::memcpy(out.dst_mac, raw.data.data(), 6);
    std::memcpy(out.src_mac, raw.data.data() + 6, 6);

    uint16_t raw_ether_type;
    std::memcpy(&raw_ether_type, raw.data.data() + 12, sizeof(uint16_t));
    out.ether_type = ntohs(raw_ether_type);

    return true;
}

bool PacketParser::parseIPv4(const RawPacket& raw, ParsedPacket& out) {
    if (raw.data.size() < 34) { // 14 (Eth) + 20 (min IP header)
        return false;
    }
    const uint8_t* ip_ptr = raw.data.data() + 14;
    size_t ip_available = raw.data.size() - 14;

    uint8_t version = (ip_ptr[0] >> 4) & 0x0F;
    if (version != 4) {
        return false;
    }

    uint8_t ihl = ip_ptr[0] & 0x0F;
    uint8_t ip_header_len = ihl * 4;
    if (ip_available < ip_header_len) {
        return false;
    }

    out.ip_header_len = ip_header_len;
    out.protocol = ip_ptr[9];

    uint32_t raw_src_ip, raw_dst_ip;
    std::memcpy(&raw_src_ip, ip_ptr + 12, sizeof(uint32_t));
    std::memcpy(&raw_dst_ip, ip_ptr + 16, sizeof(uint32_t));

    out.src_ip = ntohl(raw_src_ip);
    out.dst_ip = ntohl(raw_dst_ip);
    out.has_ip = true;

    out.payload = ip_ptr + ip_header_len;
    out.payload_len = ip_available - ip_header_len;

    return true;
}

std::string ipToString(uint32_t ip) {
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string(ip & 0xFF);
}
