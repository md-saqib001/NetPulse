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

    // Dispatch to transport-layer parser based on protocol
    if (out.protocol == 6) {        // TCP
        parseTCP(raw, out);
    } else if (out.protocol == 17) { // UDP
        parseUDP(raw, out);
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

    // Default payload to right after IP header (overridden by TCP/UDP parsers)
    out.payload = ip_ptr + ip_header_len;
    out.payload_len = ip_available - ip_header_len;

    return true;
}

bool PacketParser::parseTCP(const RawPacket& raw, ParsedPacket& out) {
    // TCP header starts after Ethernet (14) + IP header
    size_t tcp_offset = 14 + out.ip_header_len;

    // Need at least 20 bytes for minimum TCP header
    if (raw.data.size() < tcp_offset + 20) {
        return false;
    }

    const uint8_t* tcp_ptr = raw.data.data() + tcp_offset;

    // Read source and destination ports (bytes 0-1, 2-3)
    uint16_t raw_src_port, raw_dst_port;
    std::memcpy(&raw_src_port, tcp_ptr + 0, sizeof(uint16_t));
    std::memcpy(&raw_dst_port, tcp_ptr + 2, sizeof(uint16_t));
    out.src_port = ntohs(raw_src_port);
    out.dst_port = ntohs(raw_dst_port);

    // Data offset: top 4 bits of byte 12 → header length in 32-bit words
    uint8_t data_offset = (tcp_ptr[12] >> 4) & 0x0F;
    uint8_t tcp_header_len = data_offset * 4;

    // Validate that we have enough data for the full TCP header
    if (raw.data.size() < tcp_offset + tcp_header_len) {
        return false;
    }

    // Payload starts after the TCP header
    out.payload = tcp_ptr + tcp_header_len;
    out.payload_len = raw.data.size() - tcp_offset - tcp_header_len;
    out.has_tcp = true;

    return true;
}

bool PacketParser::parseUDP(const RawPacket& raw, ParsedPacket& out) {
    // UDP header starts after Ethernet (14) + IP header
    size_t udp_offset = 14 + out.ip_header_len;

    // UDP header is exactly 8 bytes
    if (raw.data.size() < udp_offset + 8) {
        return false;
    }

    const uint8_t* udp_ptr = raw.data.data() + udp_offset;

    // Read source and destination ports (bytes 0-1, 2-3)
    uint16_t raw_src_port, raw_dst_port;
    std::memcpy(&raw_src_port, udp_ptr + 0, sizeof(uint16_t));
    std::memcpy(&raw_dst_port, udp_ptr + 2, sizeof(uint16_t));
    out.src_port = ntohs(raw_src_port);
    out.dst_port = ntohs(raw_dst_port);

    // Payload starts at byte 8 of UDP header
    out.payload = udp_ptr + 8;
    out.payload_len = raw.data.size() - udp_offset - 8;
    out.has_udp = true;

    return true;
}

std::string ipToString(uint32_t ip) {
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string(ip & 0xFF);
}
