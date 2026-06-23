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

bool PacketParser::parse(const RawPacket& raw, ParsedPacket& out, ParseStats& stats) {
    if (!parseEthernet(raw, out, stats)) {
        return false;
    }
    if (out.ether_type != 0x0800) {
        stats.non_ipv4_skipped++;
        return false;
    }
    if (!parseIPv4(raw, out, stats)) {
        return false;
    }

    // Dispatch to transport-layer parser based on protocol
    if (out.protocol == 6) {        // TCP
        if (!parseTCP(raw, out, stats)) return false;
    } else if (out.protocol == 17) { // UDP
        if (!parseUDP(raw, out, stats)) return false;
    }

    return true;
}

bool PacketParser::parseEthernet(const RawPacket& raw, ParsedPacket& out, ParseStats& stats) {
    if (raw.data.size() < 14) {
        stats.short_packets++;
        out.parse_error = true;
        out.error_reason = "Packet shorter than Ethernet header";
        return false;
    }
    std::memcpy(out.dst_mac, raw.data.data(), 6);
    std::memcpy(out.src_mac, raw.data.data() + 6, 6);

    uint16_t raw_ether_type;
    std::memcpy(&raw_ether_type, raw.data.data() + 12, sizeof(uint16_t));
    out.ether_type = ntohs(raw_ether_type);

    return true;
}

bool PacketParser::parseIPv4(const RawPacket& raw, ParsedPacket& out, ParseStats& stats) {
    if (raw.data.size() < 34) { // 14 (Eth) + 20 (min IP header)
        stats.short_packets++;
        out.parse_error = true;
        out.error_reason = "Packet shorter than IPv4 header";
        return false;
    }
    const uint8_t* ip_ptr = raw.data.data() + 14;
    size_t ip_available = raw.data.size() - 14;

    uint8_t version = (ip_ptr[0] >> 4) & 0x0F;
    if (version != 4) {
        // We shouldn't get here because ether_type == 0x0800 ensures IPv4
        return false;
    }

    uint8_t ihl = ip_ptr[0] & 0x0F;
    if (ihl < 5) {
        stats.parse_errors++;
        out.parse_error = true;
        out.error_reason = "Invalid IPv4 IHL < 5";
        return false;
    }

    uint8_t ip_header_len = ihl * 4;
    if (ip_available < ip_header_len) {
        stats.short_packets++;
        out.parse_error = true;
        out.error_reason = "Packet truncated inside IPv4 header";
        return false;
    }

    uint16_t total_length;
    std::memcpy(&total_length, ip_ptr + 2, sizeof(uint16_t));
    total_length = ntohs(total_length);

    if (total_length > ip_available) {
        stats.short_packets++;
        out.parse_error = true;
        out.error_reason = "IPv4 header claims more bytes than packet has";
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

    // Use total_length as payload bound rather than ip_available
    size_t actual_ip_payload = total_length - ip_header_len;
    out.payload = ip_ptr + ip_header_len;
    out.payload_len = actual_ip_payload;

    return true;
}

bool PacketParser::parseTCP(const RawPacket& raw, ParsedPacket& out, ParseStats& stats) {
    size_t tcp_offset = 14 + out.ip_header_len;

    if (raw.data.size() < tcp_offset + 20) {
        stats.short_packets++;
        out.parse_error = true;
        out.error_reason = "Packet shorter than TCP header";
        return false;
    }

    const uint8_t* tcp_ptr = raw.data.data() + tcp_offset;

    uint16_t raw_src_port, raw_dst_port;
    std::memcpy(&raw_src_port, tcp_ptr + 0, sizeof(uint16_t));
    std::memcpy(&raw_dst_port, tcp_ptr + 2, sizeof(uint16_t));
    out.src_port = ntohs(raw_src_port);
    out.dst_port = ntohs(raw_dst_port);

    uint8_t data_offset = (tcp_ptr[12] >> 4) & 0x0F;
    if (data_offset < 5) {
        stats.parse_errors++;
        out.parse_error = true;
        out.error_reason = "TCP data offset < 5";
        return false;
    }

    uint8_t tcp_header_len = data_offset * 4;

    if (raw.data.size() < tcp_offset + tcp_header_len || out.payload_len < tcp_header_len) {
        stats.short_packets++;
        out.parse_error = true;
        out.error_reason = "Packet truncated inside TCP header";
        return false;
    }

    out.payload = tcp_ptr + tcp_header_len;
    out.payload_len -= tcp_header_len;
    out.has_tcp = true;

    return true;
}

bool PacketParser::parseUDP(const RawPacket& raw, ParsedPacket& out, ParseStats& stats) {
    size_t udp_offset = 14 + out.ip_header_len;

    if (raw.data.size() < udp_offset + 8) {
        stats.short_packets++;
        out.parse_error = true;
        out.error_reason = "Packet shorter than UDP header";
        return false;
    }

    const uint8_t* udp_ptr = raw.data.data() + udp_offset;

    uint16_t raw_src_port, raw_dst_port;
    std::memcpy(&raw_src_port, udp_ptr + 0, sizeof(uint16_t));
    std::memcpy(&raw_dst_port, udp_ptr + 2, sizeof(uint16_t));
    out.src_port = ntohs(raw_src_port);
    out.dst_port = ntohs(raw_dst_port);

    if (out.payload_len < 8) {
        stats.short_packets++;
        out.parse_error = true;
        out.error_reason = "Packet truncated inside UDP header";
        return false;
    }

    out.payload = udp_ptr + 8;
    out.payload_len -= 8;
    out.has_udp = true;

    return true;
}

std::string ipToString(uint32_t ip) {
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string(ip & 0xFF);
}
